/*
 * Copyright (c) 2013-2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define MTEV_CONTROL_REVERSE   0x52455645 /* "REVE" */
#define DEFAULT_MTEV_CONNECTION_TIMEOUT 60000 /* 60 seconds */

#define IFCMD(f, s) if((f)->command && (f)->buff_len == strlen(s) && (f)->buff && !strncmp(static_cast<const char*>((f)->buff), s, strlen(s)))
#define GET_CONF_STR(nctx, key, cn) do { \
  void *vcn; \
  cn = NULL; \
  if(nctx->config && \
     mtev_hash_retrieve(nctx->config, key, strlen(key), &vcn)) { \
     cn = static_cast<const char*>(vcn); \
  } \
} while(0)
#define GET_EXPECTED_CN(nctx, cn) GET_CONF_STR(nctx, "cn", cn)

#include <poll.h>

#include <errno.h>
#include <ctype.h>

#include <cstddef>
#include <cstdint>
#include <mutex>

#include "utils/intrusive/intrusive_ptr.hpp"
#include "mtev_defines.h"
#include "mtev_listener.h"
#include "mtev_conf.h"
#include "mtev_rest.h"
#include "mtev_reverse_socket.h"
#include "mtev_hash.h"
#include "mtev_str.h"
#include "mtev_watchdog.h"
#include "mtev_reverse_socket.h"
#include "mtev_json.h"
#include "libmtev_dtrace.h"

constexpr std::int32_t MAX_CHANNELS = 512;
constexpr std::size_t MAX_FRAME_LEN = 65530;
constexpr std::size_t CMD_BUFF_LEN = 4096;
constexpr std::int32_t AVAILABLE = -1;
constexpr std::int32_t AGING = -2;

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;
static mtev_hash_table reverse_sockets;
static pthread_rwlock_t reverse_sockets_lock;
static pthread_mutex_t reverses_lock;
static mtev_hash_table reverses;

inline eventer_t intrusive_ptr_add_ref(eventer_t p) noexcept {
  eventer_ref(p);
  return p;
}

inline bool intrusive_ptr_release(eventer_t p) noexcept {
  return eventer_deref(p) == mtev_true;
}

using eventer_sp = util::mem::intrusive_ptr<_event>;
using reverse_socket_sp = util::mem::intrusive_ptr<reverse_socket_t>;

static void reverse_frame_free(void *vrf);
static int mtev_reverse_socket_wakeup(eventer_t e, int mask, void *closure, struct timeval *tv);

struct reverse_frame_t final {
  uint16_t channel_id;
  void *buff;            /* payload */
  size_t buff_len;       /* length of frame */
  size_t buff_filled;    /* length of frame populated */
  size_t offset;         /* length of frame already processed */
  int command;
  reverse_frame_t *next;
};

struct channel_t final {
  struct timeval create_time;
  uint64_t in_bytes;
  uint64_t in_frames;
  uint64_t out_bytes;
  uint64_t out_frames;
  int pair[2]; /* pair[0] is under our control... */
               /* pair[1] might be the other side of a socketpair */
  reverse_frame_t *incoming;
  reverse_frame_t *incoming_tail;
};

struct reverse_socket_data_t final {
  int up;
  struct timeval create_time;
  uint64_t in_bytes;
  uint64_t in_frames;
  uint64_t out_bytes;
  uint64_t out_frames;
  eventer_sp e;
  reverse_frame_t *outgoing;
  reverse_frame_t *outgoing_tail;

  /* used to write the next frame */
  char frame_hdr_out[6];
  size_t frame_hdr_written;

  /* used to read the next frame */
  char frame_hdr[6];
  size_t frame_hdr_read;
  reverse_frame_t incoming_inflight;

  channel_t channels[MAX_CHANNELS];
  int last_allocated_channel;
  char *buff;
  size_t buff_len;
  size_t buff_read;
  size_t buff_written;
  union {
    struct sockaddr ip;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
  } tgt;
  int tgt_len;

  /* This are how we're bound */
  char *xbind;
  struct sockaddr_in proxy_ip4;
  eventer_t proxy_ip4_e;
  struct sockaddr_in6 proxy_ip6;
  eventer_t proxy_ip6_e;

  /* If we have one of these, we need to refresh timeouts */
  mtev_connection_ctx_t *nctx;
};

struct reverse_socket final {
public:
  reverse_socket() {
    mtev_gettimeofday(&data.create_time, nullptr);

    for (auto i = decltype(MAX_CHANNELS){0}; i < MAX_CHANNELS; i++) {
      data.channels[i].pair[0] = data.channels[i].pair[1] = AVAILABLE;
    }
  }

  ~reverse_socket() {
    free(id);
  }

public:
  inline reverse_socket *add_ref() {
    ck_pr_inc_32(&refcnt);
    return this;
  }

  inline bool release_ref() {
    if (ck_pr_dec_32_is_zero(&refcnt)) {
      if (data.buff) {
        free(data.buff);
      }

      delete this;
      return true;
    }

    return false;
  }

  void append_in(reverse_frame_t *frame_to_copy) {
    auto rc = this;
    eventer_t e;
    uint16_t id = frame_to_copy->channel_id;
    auto frame = static_cast<reverse_frame_t *>(malloc(sizeof(reverse_frame_t)));
    memcpy(frame, frame_to_copy, sizeof(*frame));

    if (std::unique_lock l{rc->lock}) {
      rc->data.in_bytes += frame->buff_len;
      rc->data.in_frames += 1;
      rc->data.channels[id].in_bytes += frame->buff_len;
      rc->data.channels[id].in_frames += 1;
      if (rc->data.channels[id].incoming_tail) {
        mtevAssert(rc->data.channels[id].incoming);
        rc->data.channels[id].incoming_tail->next = frame;
        rc->data.channels[id].incoming_tail = frame;
      }
      else {
        mtevAssert(!rc->data.channels[id].incoming);
        rc->data.channels[id].incoming = rc->data.channels[id].incoming_tail = frame;
      }
    }

    memset(frame_to_copy, 0, sizeof(*frame_to_copy));
    e = eventer_find_fd(rc->data.channels[id].pair[0]);
    if (!e) {
      mtevL(rc->data.channels[id].pair[0] >= 0 ? nlerr : nldeb,
            "(%s, %d, %s): No event on my side [%d] of the socketpair()\n",
            rc->id,
            id,
            __func__,
            rc->data.channels[id].pair[0]);
    }
    else {
      mtevL(nldeb, "%s(%s,%d) => %s\n", __func__, rc->id, id, eventer_name_for_callback_e(eventer_get_callback(e), e));
      if (!(eventer_get_mask(e) & EVENTER_WRITE))
        eventer_trigger(e, EVENTER_WRITE | EVENTER_READ);
    }
  }

  void pop_out() {
    auto rc = this;
    reverse_frame_t *f = rc->data.outgoing;
    if (rc->data.outgoing == rc->data.outgoing_tail)
      rc->data.outgoing_tail = NULL;
    rc->data.outgoing = rc->data.outgoing->next;
    reverse_frame_free(f);
  }

  void append_out(reverse_frame_t *frame_to_copy) {
    auto rc = this;
    int id;
    auto frame = static_cast<reverse_frame_t *>(malloc(sizeof(reverse_frame_t)));
    eventer_t wakeup_e = NULL;

    memcpy(frame, frame_to_copy, sizeof(*frame));
    std::unique_lock l{rc->lock};
    rc->data.out_bytes += frame->buff_len;
    rc->data.out_frames += 1;
    id = frame->channel_id & 0x7fff;
    rc->data.channels[id].out_bytes += frame->buff_len;
    rc->data.channels[id].out_frames += 1;
    if (rc->data.outgoing_tail) {
      rc->data.outgoing_tail->next = frame;
      rc->data.outgoing_tail = frame;
    }
    else {
      rc->data.outgoing = rc->data.outgoing_tail = frame;
    }
    if (rc->data.e) {
      wakeup_e = eventer_alloc_timer_next_opportunity(mtev_reverse_socket_wakeup, rc->add_ref(), eventer_get_owner(rc->data.e.get()));
    }
    l.unlock();
    if (!wakeup_e) {
      mtevL(nldeb, "%s: No event to trigger for reverse_socket framing\n", __func__);
    }
    else {
      mtevL(nldeb, "%s(%s, %d) => %s\n", __func__, rc->id, id, eventer_name_for_callback_e(eventer_get_callback(wakeup_e), wakeup_e));
      eventer_add(wakeup_e);
    }
  }

  void append_out_no_lock(reverse_frame_t *frame_to_copy) {
    auto rc = this;
    int id;
    auto frame = static_cast<reverse_frame_t *>(malloc(sizeof(reverse_frame_t)));
    eventer_t wakeup_e = NULL;

    memcpy(frame, frame_to_copy, sizeof(*frame));
    rc->data.out_bytes += frame->buff_len;
    rc->data.out_frames += 1;
    id = frame->channel_id & 0x7fff;
    rc->data.channels[id].out_bytes += frame->buff_len;
    rc->data.channels[id].out_frames += 1;
    if (rc->data.outgoing_tail) {
      rc->data.outgoing_tail->next = frame;
      rc->data.outgoing_tail = frame;
    }
    else {
      rc->data.outgoing = rc->data.outgoing_tail = frame;
    }
    if (rc->data.e) {
      wakeup_e = eventer_alloc_timer_next_opportunity(mtev_reverse_socket_wakeup,
                                                      rc->add_ref(), eventer_get_owner(rc->data.e.get()));
    }
    if (!wakeup_e)
      mtevL(nlerr, "(%s, %d, %s): No event to trigger for reverse_socket framing\n",
        rc->id,
        id,
        __func__);
    else {
      mtevL(nldeb, "%s(%s, %d) => %s\n", __func__, rc->id, id, eventer_name_for_callback_e(eventer_get_callback(wakeup_e), wakeup_e));
      eventer_add(wakeup_e);
    }
  }

  void command_out(uint16_t id, const char *command)
  {
    reverse_frame_t frame{};

    frame.channel_id = id | 0x8000;
    mtevL(nldeb, "%s channel:%d '%s'\n", __func__, id, command);
    frame.buff = strdup(command);
    frame.buff_len = frame.buff_filled = strlen(static_cast<const char *>(frame.buff));
    append_out(&frame);
  }

public:
  friend inline reverse_socket_t *intrusive_ptr_add_ref(reverse_socket_t *p) noexcept {
    return p->add_ref();
  }

  friend inline bool intrusive_ptr_release(reverse_socket_t *p) noexcept {
    return p->release_ref();
  }

public:
  static inline void release_ref_no_return(void *vrc) {
    intrusive_ptr_release(static_cast<reverse_socket_t *>(vrc));
  }

public:
  reverse_socket_data_t data{};
  char *id{};
  std::recursive_mutex lock;
  uint32_t refcnt{};
};

MTEV_HOOK_IMPL(mtev_reverse_proxy_changed,
               (const char *id, int family, struct sockaddr *addr, bool up),
               void *, closure,
               (void *closure, const char *id, int family, struct sockaddr *addr, bool up),
               (closure, id, family, addr, up))

static const char *my_reverse_prefix = "mtev/";
static const char *default_cn_required_prefixes[] = { "mtev/", NULL };
static const char **cn_required_prefixes = default_cn_required_prefixes;
struct reverse_access_list {
  mtev_reverse_acl_decider_t allow;
  struct reverse_access_list *next;
};
static struct reverse_access_list *access_list = NULL;

extern "C" void
mtev_reverse_socket_acl(mtev_reverse_acl_decider_t f) {
  struct reverse_access_list *acl = static_cast<struct reverse_access_list *>(calloc(1, sizeof(*acl)));
  acl->next = access_list;
  acl->allow = f;
  access_list = acl;
}

extern "C" mtev_reverse_acl_decision_t
mtev_reverse_socket_denier(const char * /* id */, mtev_acceptor_closure_t * /* ac */) {
  return MTEV_ACL_DENY;
}

static int
mtev_reverse_socket_allowed(const char *id, mtev_acceptor_closure_t *ac) {
  struct reverse_access_list *acl;
  for(acl = access_list; acl; acl = acl->next) {
    switch(acl->allow(id,ac)) {
      case MTEV_ACL_ALLOW: return 1;
      case MTEV_ACL_DENY: return 0;
      default: break;
    }
  }
  /* default allow */
  return 1;
}

static void mtev_connection_initiate_connection(mtev_connection_ctx_t *ctx);
static void mtev_connection_schedule_reattempt(mtev_connection_ctx_t *ctx,
                                               struct timeval *now);

static void reverse_frame_free(void *vrf) {
  auto f = static_cast<reverse_frame_t *>(vrf);
  if(f->buff) free(f->buff);
  free(f);
}

#undef RSACCESS
#define RSACCESS(type, name, elem) \
type mtev_reverse_socket_##name(reverse_socket_t *sock) { \
  return sock->data.elem; \
}
RSACCESS(size_t, in_bytes, in_bytes)
RSACCESS(size_t, out_bytes, out_bytes)
RSACCESS(size_t, in_frames, in_frames)
RSACCESS(size_t, out_frames, out_frames)
RSACCESS(struct timeval, create_time, create_time)
RSACCESS(const char *, xbind, xbind)

extern "C" uint32_t mtev_reverse_socket_nchannels(reverse_socket_t *sock) {
  uint32_t count = 0;
  for(int i=0; i<MAX_CHANNELS; i++) {
    count += sock->data.channels[i].pair[0] >= 0;
  }
  return count;
}

struct channel_closure_t {
  uint16_t channel_id;
  reverse_socket_sp parent;
};

static reverse_socket_sp mtev_reverse_socket_alloc() {
  return reverse_socket_sp{new reverse_socket_t{}};
}

static void mtev_reverse_socket_channel_shutdown(reverse_socket_sp rc, const uint16_t channel_id) {
  eventer_t ce = nullptr;
  reverse_frame_t *saved_incoming = nullptr;

  mtevL(nldeb, "(%s %d %s)\n", rc->id, channel_id, __func__);

  if (std::unique_lock l{rc->lock}) {
    channel_t *const channel = &rc->data.channels[channel_id];

    if (channel->pair[0] >= 0) {
      const int fd = channel->pair[0];

      ce = eventer_find_fd(fd);
      channel->pair[0] = AGING;

      if (!ce) {
        close(fd);
      }
    }

    if (ce) {
      l.unlock();
      eventer_trigger(ce, EVENTER_EXCEPTION);
      l.lock();
    }

    if (channel->pair[0] == AGING) {
      channel->in_bytes = channel->out_bytes = channel->in_frames = channel->out_frames = 0;
      saved_incoming = channel->incoming;
      channel->incoming = NULL;
      channel->incoming_tail = NULL;
      channel->pair[0] = channel->pair[1] = AVAILABLE;
    }
  }

  while (saved_incoming) {
    reverse_frame_t *const f = saved_incoming;

    saved_incoming = saved_incoming->next;
    reverse_frame_free(f);
  }
}

static void
mtev_reverse_socket_shutdown(reverse_socket_sp rc, [[maybe_unused]] eventer_t e) {
  int mask, i;
  std::unique_lock l{rc->lock};

  mtevL(nldeb, "(%s %s)\n", rc->id, __func__);
  free(rc->data.buff);
  rc->data.buff = nullptr;
  rc->data.e = nullptr;
  if (rc->data.xbind) {
    free(rc->data.xbind);

    if (auto e = rc->data.proxy_ip4_e) {
      if (eventer_remove_fde(e)) {
        mtev_reverse_proxy_changed_hook_invoke(rc->id, AF_INET, (struct sockaddr *)&rc->data.proxy_ip4, false);
        eventer_close(e, &mask);
        mtev_watchdog_on_crash_close_remove_fd(eventer_get_fd(e));
        eventer_free(e);
      }
    }

    if (auto e = rc->data.proxy_ip6_e) {
      if (eventer_remove_fde(e)) {
        mtev_reverse_proxy_changed_hook_invoke(rc->id, AF_INET6, (struct sockaddr *)&rc->data.proxy_ip6, false);
        eventer_close(e, &mask);
        mtev_watchdog_on_crash_close_remove_fd(eventer_get_fd(e));
        eventer_free(e);
      }
    }
  }
  if(rc->data.incoming_inflight.buff) free(rc->data.incoming_inflight.buff);
  while(rc->data.outgoing) {
    reverse_frame_t *f = rc->data.outgoing;
    rc->data.outgoing = rc->data.outgoing->next;
    reverse_frame_free(f);
  }
  l.unlock();
  for(i=0;i<MAX_CHANNELS;i++) {
    mtev_reverse_socket_channel_shutdown(rc, i);
  }

  if (const auto id = rc->id) {
    pthread_rwlock_wrlock(&reverse_sockets_lock);
    mtev_hash_delete(&reverse_sockets, id, strlen(id), nullptr, [](void *p) {
      static_cast<reverse_socket_t*>(p)->release_ref();
    });
    pthread_rwlock_unlock(&reverse_sockets_lock);
  }
}

static int
mtev_reverse_socket_channel_handler(eventer_t e, int mask, void *closure,
                                    struct timeval *now) {
  (void)now;
  char buff[MAX_FRAME_LEN];
  auto cct = static_cast<channel_closure_t *>(closure);
  auto parent_rs = cct->parent;
  ssize_t len;
  int write_success = 1, read_success = 1;
  int write_mask = EVENTER_EXCEPTION, read_mask = EVENTER_EXCEPTION;
  mtevAssert(parent_rs);
  mtevAssert(ck_pr_load_32(&parent_rs->refcnt) > 0);
  channel_t *const channel = &parent_rs->data.channels[cct->channel_id];

  mtevL(nldeb, "(%s, %d, %s): \n", parent_rs->id, cct->channel_id, __func__);

  if(parent_rs->data.nctx && parent_rs->data.nctx->wants_permanent_shutdown) {
    mtevL(nldeb, "(%s, %d, %s) [%d,%d]: wants_permanent_shutdown - goto snip\n",
          parent_rs->id, cct->channel_id, __func__,
          channel->pair[0], channel->pair[1]);
    goto snip;
  }
  if(mask & EVENTER_EXCEPTION) {
    mtevL(nldeb, "(%s, %d, %s) [%d,%d]: EVENTER_EXCEPTION - goto snip\n",
          parent_rs->id, cct->channel_id, __func__,
          channel->pair[0], channel->pair[1]);
    goto snip;
  }

  /* this damn-well better be our side of the socketpair */
  if(channel->pair[0] != eventer_get_fd(e)) {
   if(channel->pair[0] >= 0) {
      mtevL(nlerr, "(%s, %d, %s): misaligned events, this is a bug (%d != %d)\n",
            parent_rs->id, cct->channel_id, __func__,
            channel->pair[0], eventer_get_fd(e));
   }
   shutdown:
    mtevL(nldeb, "(%s, %d, %s) [%d,%d]: shutdown\n",
            parent_rs->id, cct->channel_id, __func__,
            channel->pair[0], channel->pair[1]);
    parent_rs->command_out(cct->channel_id, "SHUTDOWN");
   snip:
    mtevL(nldeb, "(%s, %d, %s) [%d,%d]: snip\n",
      parent_rs->id, cct->channel_id, __func__,
      channel->pair[0], channel->pair[1]);

    if (eventer_remove_fde(e)) {
      mtevAssert(ck_pr_load_32(&parent_rs->refcnt) > 0);
      eventer_close(e, &write_mask);

      if (std::unique_lock l{parent_rs->lock}) {
        channel->pair[0] = channel->pair[1] = AGING;
      }

      mtev_reverse_socket_channel_shutdown(parent_rs, cct->channel_id);
    }

    delete cct;
    return 0;
  }

  while(write_success || read_success) {
    std::unique_lock l{parent_rs->lock};

    read_success = write_success = 0;

    /* try to write some stuff */
    while(channel->incoming) {
      reverse_frame_t *f = channel->incoming;
      mtevAssert(f->buff_len == f->buff_filled); /* we only expect full frames here */
      if(f->command) {
        IFCMD(f, "RESET") {
          mtevL(nldeb, "(%s, %d, %s) [%d,%d]: - RESET pair - goto snip\n",
                parent_rs->id, cct->channel_id, __func__,
                channel->pair[0], channel->pair[1]);
          goto snip;
        }
        IFCMD(f, "CLOSE") {
          mtevL(nldeb, "(%s, %d, %s) [%d,%d]: - CLOSE - goto snip\n",
                parent_rs->id, cct->channel_id, __func__,
                channel->pair[0], channel->pair[1]);
          goto snip;
        }
        IFCMD(f, "SHUTDOWN") {
          mtevL(nldeb, "(%s, %d, %s) [%d, %d]: - SHUTDOWN - goto shutdown\n",
                parent_rs->id, cct->channel_id, __func__,
                channel->pair[0], channel->pair[1]);
          goto shutdown;
        }
        mtevL(nldeb, "(%s, %d, %s) [%d, %d]: - unknown command - goto shutdown\n",
              parent_rs->id, cct->channel_id, __func__,
              channel->pair[0], channel->pair[1]);
        goto shutdown;
      }

      if(f->buff_len == 0) {
        mtevL(nldeb, "(%s, %d, %s) [%d, %d]: f->buff len == 0 goto shutdown\n",
              parent_rs->id, cct->channel_id, __func__,
              channel->pair[0], channel->pair[1]);
        goto shutdown;
      }

      len = eventer_write(e, static_cast<const char *>(f->buff) + f->offset,
                          f->buff_filled - f->offset, &write_mask);

      if(len < 0 && errno == EAGAIN) {
        break;
      }

      if(len <= 0) {
        mtevL(nldeb, "(%s, %d, %s) [%d, %d]: failed eventer write %d \"%s\" - goto shutdown\n",
              parent_rs->id, cct->channel_id, __func__,
              channel->pair[0], channel->pair[1],
              errno, strerror(errno));
        goto shutdown;
      }

      if(len > 0) {
        mtevL(nldeb, "(%s, %d, %s) [%d, %d]: reverse_socket_channel %zd\n",
              parent_rs->id, cct->channel_id, __func__,
              channel->pair[0], channel->pair[1], len);
        f->offset += len;
        write_success = 1;
      }

      if (f->offset == f->buff_filled) {
        channel->incoming = channel->incoming->next;
        if (channel->incoming_tail == f) {
          channel->incoming_tail = channel->incoming;
        }

        reverse_frame_free(f);
      }
    }

    /* try to read some stuff */
    len = eventer_read(e, buff, sizeof(buff), &read_mask);

    if(len < 0 && (errno != EINPROGRESS && errno != EAGAIN)) {
      mtevL(nldeb, "(%s, %d, %s) [%d, %d]: failed eventer read %d \"%s\" - goto shutdown\n",
            parent_rs->id, cct->channel_id, __func__,
            channel->pair[0], channel->pair[1],
            errno, strerror(errno));
      goto shutdown;
    }

    if(len == 0) {
      mtevL(nldeb, "(%s, %d, %s) [%d, %d]: failed eventer read %d \"%s\" - goto shutdown\n",
            parent_rs->id, cct->channel_id, __func__,
            channel->pair[0], channel->pair[1],
            errno, strerror(errno));
      goto shutdown;
    }

    if (len > 0) {
      reverse_frame_t frame{};

      mtevL(nldeb, "(%s, %d, %s) [%d, %d]: read %zd on %d\n",
            parent_rs->id, cct->channel_id, __func__,
            channel->pair[0], channel->pair[1],
            len,
            eventer_get_fd(e));
      frame.channel_id = cct->channel_id;
      frame.buff = malloc(len);
      memcpy(frame.buff, buff, len);
      frame.buff_len = frame.buff_filled = len;
      cct->parent->append_out_no_lock(&frame);
      read_success = 1;
    }
  }

  return read_mask | write_mask | EVENTER_EXCEPTION;
}

static int
mtev_reverse_socket_wakeup(eventer_t /*e*/, int /*mask*/, void *closure, timeval * /*tv*/)
{
  reverse_socket_sp rc = static_cast<reverse_socket_t *>(closure);
  eventer_sp e;

  if (std::unique_lock l{rc->lock}) {
    e = rc->data.e;
  }

  if (e) {
    if (eventer_remove_fde(e.get())) {
      eventer_trigger(e.get(), EVENTER_READ|EVENTER_WRITE);
    }
    else {
      mtevL(nldeb, "(%s, %s) : failed to remove fde from eventer object %p\n",
            rc->id, __func__,
            e.get());
    }
  }

  return 0;
}

static int
mtev_support_connection(reverse_socket_sp &rc) {
  int fd, rv;
  fd = socket(rc->data.tgt.ip.sa_family, NE_SOCK_CLOEXEC|SOCK_STREAM, 0);

  if (fd < 0) {
    goto fail;
  }

  /* Make it non-blocking */
  if (eventer_set_fd_nonblocking(fd)) {
    goto fail;
  }

  rv = connect(fd, &rc->data.tgt.ip, rc->data.tgt_len);

  if (rv == -1 && errno != EINPROGRESS) {
    goto fail;
  }

  return fd;
fail:
  mtevL(nldeb, "(%s, %s) : failed to connect %d (%s)\n",
        rc->id, __func__,
        errno, strerror(errno));

  if (fd >= 0) {
    close(fd);
  }

  return -1;
}

static int mtev_reverse_socket_handler(eventer_t e, int mask, reverse_socket_sp rc) {
  uint16_t channel_id = 0;
  int rmask = EVENTER_EXCEPTION;
  int wmask = EVENTER_EXCEPTION;
  int len;
  int success = 0;
  int reads_remaining=500, writes_remaining=500;
  const char *socket_error_string = "protocol error";

  if(rc->data.nctx && rc->data.nctx->wants_permanent_shutdown) {
    socket_error_string = "shutdown requested";
    goto socket_error;
  }
  if(mask & EVENTER_EXCEPTION) {
socket_error:
    mtevL(nldeb, "(%s %s): socket error: %s\n", rc->id, __func__, socket_error_string);
    mtev_reverse_socket_shutdown(rc, e);
    return 0;
  }

 next_frame:
  while(rc->data.frame_hdr_read < sizeof(rc->data.frame_hdr)) {
    len = eventer_read(e, rc->data.frame_hdr + rc->data.frame_hdr_read, sizeof(rc->data.frame_hdr) - rc->data.frame_hdr_read, &rmask);
    if(len < 0 && errno == EAGAIN) {
      mtevL(nldeb, "(%s %s): next frame, got EAGAIN, goto try_writes\n", rc->id, __func__);
      goto try_writes;
    }

    if(len <= 0) {
      mtevL(nldeb, "(%s %s): bad eventer read - len == %d, error %d (%s), goto socket_error\n",
              rc->id, __func__, len, errno, strerror(errno));
      socket_error_string = "data frame eventer_read error";
      goto socket_error;
    }

    rc->data.frame_hdr_read += len;
    success = 1;
  }

  if (rc->data.incoming_inflight.buff_len == 0) {
    uint16_t nchannel_id;
    uint32_t nframelen;

    memcpy(&nchannel_id, rc->data.frame_hdr, sizeof(nchannel_id));
    memcpy(&nframelen, rc->data.frame_hdr + sizeof(nchannel_id), sizeof(nframelen));
    rc->data.incoming_inflight.channel_id = ntohs(nchannel_id);

    if (rc->data.incoming_inflight.channel_id & 0x8000) {
      rc->data.incoming_inflight.channel_id &= 0x7fff;
      rc->data.incoming_inflight.command = 1;
    } else {
      rc->data.incoming_inflight.command = 0;
    }

    channel_id = rc->data.incoming_inflight.channel_id;
    rc->data.incoming_inflight.buff_len = ntohl(nframelen);
    mtevL(nldeb, "(%s %d %s) [%d,%d]: next_frame_in(%s,%zu)\n",
          rc->id, channel_id, __func__,
          rc->data.channels[channel_id].pair[0],
          rc->data.channels[channel_id].pair[1],
          rc->data.incoming_inflight.command ? "!" : "",
          rc->data.incoming_inflight.buff_len);

    if (rc->data.incoming_inflight.buff_len > MAX_FRAME_LEN) {
      mtevL(nldeb, "(%s %d %s) [%d,%d]: oversized frame (%zd > %zd), goto socket_error\n",
            rc->id, channel_id, __func__,
            rc->data.channels[channel_id].pair[0],
            rc->data.channels[channel_id].pair[1],
            rc->data.incoming_inflight.buff_len, MAX_FRAME_LEN);
      socket_error_string = "oversized_frame";
      goto socket_error;
    }

    if (channel_id >= MAX_CHANNELS) {
      mtevL(nldeb, "(%s %s): invalid channel (%d >= %d), goto socket_error\n",
              rc->id, __func__, channel_id, MAX_CHANNELS);
      socket_error_string = "invalid_channel";
      goto socket_error;
    }
  }

  channel_id = rc->data.incoming_inflight.channel_id;

  while (rc->data.incoming_inflight.buff_filled < rc->data.incoming_inflight.buff_len) {
    if (!rc->data.incoming_inflight.buff) {
      rc->data.incoming_inflight.buff = malloc(rc->data.incoming_inflight.buff_len);
    }

    len = eventer_read(e,
            const_cast<char*>(static_cast<const char*>(rc->data.incoming_inflight.buff) + rc->data.incoming_inflight.buff_filled),
            rc->data.incoming_inflight.buff_len - rc->data.incoming_inflight.buff_filled, &rmask);

    if(len < 0 && errno == EAGAIN) {
      mtevL(nldeb, "(%s %s): frame payload read, got EAGAIN, goto try_writes\n", rc->id, __func__);
      goto try_writes;
    }

    if(len <= 0) {
      mtevL(nldeb, "(%s %s): bad eventer frame payload read - len = %d, error %d (%s), goto socket_error\n",
              rc->id, __func__, len, errno, strerror(errno));
      socket_error_string = "buffer eventer_read error";
      goto socket_error;
    }

    mtevL(nldeb, "(%s %d %s) [%d,%d]: frame payload read -> %llu (@%llu/%llu)\n",
          rc->id,  channel_id, __func__,
          rc->data.channels[channel_id].pair[0],
          rc->data.channels[channel_id].pair[1],
          (unsigned long long)len,
          (unsigned long long)rc->data.incoming_inflight.buff_filled,
          (unsigned long long)rc->data.incoming_inflight.buff_len);
    rc->data.incoming_inflight.buff_filled += len;
    success = 1;
  }

  /* we have a complete inbound frame here (w/ data) */
  if (rc->data.incoming_inflight.command) {
    mtevL(nldeb, "(%s %d %s): inbound command channel: '%.*s'\n",
          rc->id,
          channel_id,
          __func__,
          (int)rc->data.incoming_inflight.buff_len, 
          (char *)rc->data.incoming_inflight.buff);
  }

  IFCMD(&rc->data.incoming_inflight, "CONNECT") {
    mtevL(nldeb, "(%s %d %s) [%d, %d] - got connect request\n",
            rc->id, channel_id, __func__,
            rc->data.channels[channel_id].pair[0],
            rc->data.channels[channel_id].pair[1]);

    if(rc->data.channels[channel_id].pair[0] == AVAILABLE) {
      int fd = mtev_support_connection(rc);
      if(fd >= 0) {
        mtevAssert(ck_pr_load_32(&rc->refcnt) > 0);
        auto cct = new channel_closure_t{channel_id, rc};
        eventer_t newe =
          eventer_alloc_fd(mtev_reverse_socket_channel_handler, cct, fd,
                           EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION);
        eventer_add(newe);
        mtev_gettimeofday(&rc->data.channels[channel_id].create_time, NULL);
        rc->data.channels[channel_id].pair[0] = fd;
        memset(&rc->data.incoming_inflight, 0, sizeof(rc->data.incoming_inflight));
        rc->data.frame_hdr_read = 0;
        goto next_frame;
      }
    }
  }

  if (rc->data.channels[channel_id].pair[0] == AVAILABLE) {
    /* but the channel disappeared */
    /* send a reset, but not in response to a reset */
    IFCMD(&rc->data.incoming_inflight, "RESET") { } /* noop */
    else {
      mtevL(nldeb, "(%s %d %s) [%d,%d] - sending reset\n",
              rc->id, channel_id, __func__,
              rc->data.channels[channel_id].pair[0],
              rc->data.channels[channel_id].pair[1]);
      rc->command_out(channel_id, "RESET");
    }
    free(rc->data.incoming_inflight.buff);
    memset(&rc->data.incoming_inflight, 0, sizeof(rc->data.incoming_inflight));
    rc->data.frame_hdr_read = 0;
    goto next_frame;
  }

  rc->append_in(&rc->data.incoming_inflight);
  rc->data.frame_hdr_read = 0;
  if (--reads_remaining) goto next_frame;

 try_writes: {
  std::unique_lock l{rc->lock};

  while (--writes_remaining && rc->data.outgoing) {
    ssize_t len;
    reverse_frame_t *f = rc->data.outgoing;
    while(rc->data.frame_hdr_written < sizeof(rc->data.frame_hdr_out)) {
      uint16_t nchannel_id = htons(f->channel_id);
      uint32_t nframelen = htonl(f->buff_len);
      memcpy(rc->data.frame_hdr_out, &nchannel_id, sizeof(nchannel_id));
      memcpy(rc->data.frame_hdr_out + sizeof(nchannel_id), &nframelen, sizeof(nframelen));
      len = eventer_write(e, rc->data.frame_hdr_out + rc->data.frame_hdr_written,
                          sizeof(rc->data.frame_hdr_out) - rc->data.frame_hdr_written, &wmask);
      if(len < 0 && errno == EAGAIN) {
        mtevL(nldeb, "(%s %d %s): try_writes for frame, got EAGAIN, goto done_for_now\n", rc->id, f->channel_id, __func__);
        goto done_for_now;
      }
      else if(len <= 0) goto socket_error;
      rc->data.frame_hdr_written += len;
      success = 1;
    }
    while(f->offset < f->buff_len) {
      len = eventer_write(e, static_cast<const char*>(f->buff) + f->offset,
                          f->buff_len - f->offset, &wmask);
      if(len < 0 && errno == EAGAIN) {
        mtevL(nldeb, "(%s %d %s): try_writes for buffer, got EAGAIN, goto done_for_now\n", rc->id, f->channel_id, __func__);
        goto done_for_now;
      }
      else if(len <= 0) {
        mtevL(nldeb, "(%s %d %s): try_writes for frame, got %d (%s), len %zd, goto socket_error\n",
                rc->id, f->channel_id, __func__, errno, strerror(errno), len);
        goto socket_error;
      }
      f->offset += len;
      success = 1;
    }

    mtevL(nldeb, "(%s %d %s): frame_out %p/%llu/%llu\n",
          rc->id, f->channel_id, __func__,
          f->buff,
          (unsigned long long)f->offset, 
          (unsigned long long)f->buff_len);
    /* reset for next frame */
    rc->data.frame_hdr_written = 0;
    rc->pop_out();
  }
 }

 done_for_now: 
  if(success && rc->data.nctx) {
    mtevL(nldeb, "(%s %d %s): done_for_now finished, updating timeout\n",
          rc->id, channel_id, __func__);
    mtev_connection_update_timeout(rc->data.nctx);
  }
  else {
    mtevL(nldeb, "(%s %d %s): done_for_now without finishing, will retry later: success %d, nctx %s\n",
          rc->id, channel_id, __func__,
          success, rc->data.nctx ? "not null" : "null");
  }

  if(e != rc->data.e) {
    eventer_set_mask(rc->data.e.get(), rmask|wmask);
    return 0;
  }

  return (reads_remaining && writes_remaining) ?
      rmask|wmask :
      EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION;
}

int mtev_reverse_socket_server_handler(eventer_t e, int mask, void *closure, timeval * /*now*/) {
  auto ac = static_cast<mtev_acceptor_closure_t *>(closure);
  reverse_socket_sp rc = static_cast<reverse_socket_t *>(mtev_acceptor_closure_ctx(ac));
  const auto rv = mtev_reverse_socket_handler(e, mask, rc);

  if(rv == 0) {
    mtev_acceptor_closure_free(ac);

    if (eventer_remove_fde(e)) {
      eventer_close(e, &mask);
    }
  }

  return rv;
}

int mtev_reverse_socket_client_handler(eventer_t e, int mask, void *closure, timeval *now) {
  auto nctx = static_cast<mtev_connection_ctx_t *>(closure);
  reverse_socket_sp rc = static_cast<reverse_socket_t *>(nctx->consumer_ctx);
  const auto rv = mtev_reverse_socket_handler(e, mask, rc);

  if (rv == 0) {
    nctx->close(nctx, e);
    nctx->schedule_reattempt(nctx, now);
  }

  return rv;
}

static char *
extract_xbind(char *in, struct sockaddr_in *in4, struct sockaddr_in6 *in6) {
  char *hdr, *eol, *port;
  hdr = strstr(in, "\r\nX-Bind:");
  if(!hdr) return NULL;
  hdr += strlen("\r\nX-Bind:");
  while(*hdr && isspace(*hdr)) hdr++;
  eol = strstr(hdr, "\r\n");
  if(!eol) return NULL;
  *eol = '\0';

  port = strchr(hdr, ' ');
  if(port) { *port = '\0'; in4->sin_port = in6->sin6_port = htons(atoi(port+1)); }
  if(!strcmp(hdr, "*")) {
    in4->sin_family = AF_INET;
    in4->sin_addr.s_addr = INADDR_ANY;
    in6->sin6_family = AF_INET6;
    memcpy(&in6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
  }
  else {
    if(inet_pton(AF_INET, hdr, &in4->sin_addr) == 1)
      in4->sin_family = AF_INET;
    if(inet_pton(AF_INET6, hdr, &in6->sin6_addr) == 1)
      in6->sin6_family = AF_INET6;
  }
  if(port) { *port = ' '; }
  return strdup(hdr);
}

int
mtev_reverse_socket_proxy_accept(eventer_t e, int mask, void *closure,
                                 struct timeval *now) {
  (void)now;
  int fd;
  socklen_t salen;
  union {
    struct sockaddr in;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
  } remote;
  reverse_socket_sp rc = {static_cast<reverse_socket_t *>(closure), false};

  salen = sizeof(remote);
  fd = eventer_accept(e, &remote.in, &salen, &mask);
  if(fd >= 0) {
    if(eventer_set_fd_nonblocking(fd)) {
      mtevL(nlerr, "%s: eventer_set_fd_nonblocking failed\n", __func__);
      close(fd);
    }
    else {
      if(mtev_reverse_socket_connect(rc->id, fd) < 0) {
        mtevL(nlerr, "%s: mtev_reverse_socket_connect failed\n", __func__);
        close(fd);
      }
    }
  } else {
    mtevL(nlerr, "%s: failed: %s\n", __func__, strerror(errno));
  }
  return EVENTER_READ | EVENTER_EXCEPTION;
}
void
mtev_reverse_socket_proxy_setup(reverse_socket_sp rc) {
  int fd;
  socklen_t salen;
  if(rc->data.proxy_ip4.sin_family == AF_INET) {
    if(-1 == (fd = socket(AF_INET, SOCK_STREAM, 0))) goto bad4;
    if(eventer_set_fd_nonblocking(fd)) goto bad4;
    if(-1 == bind(fd, (struct sockaddr *)&rc->data.proxy_ip4, sizeof(rc->data.proxy_ip4))) goto bad4;
    if(-1 == listen(fd, 5)) goto bad4;
    salen = sizeof(rc->data.proxy_ip4);
    if(getsockname(fd, (struct sockaddr *)&rc->data.proxy_ip4, &salen)) goto bad4;
    mtev_watchdog_on_crash_close_add_fd(fd);
    rc->data.proxy_ip4_e =
      eventer_alloc_fd(mtev_reverse_socket_proxy_accept, rc->add_ref(), fd,
                       EVENTER_READ | EVENTER_EXCEPTION);
    eventer_add(rc->data.proxy_ip4_e);
    mtev_reverse_proxy_changed_hook_invoke(rc->id, AF_INET, (struct sockaddr *)&rc->data.proxy_ip4, true);
    fd = -1;
   bad4:
    if(fd >= 0) close(fd);
  }
  if(rc->data.proxy_ip6.sin6_family == AF_INET6) {
    if(-1 == (fd = socket(AF_INET6, SOCK_STREAM, 0))) goto bad6;
    if(eventer_set_fd_nonblocking(fd)) goto bad6;
    if(-1 == bind(fd, (struct sockaddr *)&rc->data.proxy_ip6, sizeof(rc->data.proxy_ip6))) goto bad6;
    if(-1 == listen(fd, 5)) goto bad6;
    salen = sizeof(rc->data.proxy_ip6);
    if(getsockname(fd, (struct sockaddr *)&rc->data.proxy_ip6, &salen)) goto bad6;
    mtev_watchdog_on_crash_close_add_fd(fd);
    rc->data.proxy_ip6_e =
      eventer_alloc_fd(mtev_reverse_socket_proxy_accept, rc->add_ref(), fd,
                       EVENTER_READ | EVENTER_EXCEPTION);
    eventer_add(rc->data.proxy_ip6_e);
    mtev_reverse_proxy_changed_hook_invoke(rc->id, AF_INET6, (struct sockaddr *)&rc->data.proxy_ip6, true);
    fd = -1;
   bad6:
    if(fd >= 0) close(fd);
  }
}

int
mtev_reverse_socket_acceptor(eventer_t e, int mask, void *closure,
                             struct timeval *now) {
  int newmask = EVENTER_READ | EVENTER_EXCEPTION, rv;
  ssize_t len = 0;
  const char *socket_error_string = "unknown socket error";
  char errbuf[80];
  auto ac = static_cast<mtev_acceptor_closure_t *>(closure);
  reverse_socket_sp rc = static_cast<reverse_socket_t*>(mtev_acceptor_closure_ctx(ac));

  if(mask & EVENTER_EXCEPTION) {
socket_error:
    /* Exceptions cause us to simply snip the connection */
    mtev_reverse_socket_shutdown(rc, e);
    mtev_acceptor_closure_free(ac);

    if (eventer_remove_fde(e)) {
      eventer_close(e, &mask);
      mtevL(nldeb, "%s - reverse_socket error: %s\n", __func__, socket_error_string);
    }

    return 0;
  }

  if(!rc) {
    rc = mtev_reverse_socket_alloc();
    mtev_acceptor_closure_set_ctx(ac, rc->add_ref(), reverse_socket::release_ref_no_return);
    if(!rc->data.buff) rc->data.buff = static_cast<char*>(malloc(CMD_BUFF_LEN));
    /* expect: "REVERSE /<id>\r\n"  ... "REVE" already read */
    /*              [ 5 ][ X][ 2]  */
  }

  const char *remote_cn = mtev_acceptor_closure_remote_cn(ac);

  /* Herein we read one byte at a time to ensure we don't accidentally
   * consume pipelined frames.
   */
  while(!rc->data.up && rc->data.buff_read < CMD_BUFF_LEN) {
    char *crlf;

    len = eventer_read(e, rc->data.buff + rc->data.buff_read, 1, &newmask);
    if(len < 0 && errno == EAGAIN) return newmask | EVENTER_EXCEPTION;
    if(len < 0) {
      socket_error_string = strerror(errno);
      goto socket_error;
    }
    rc->data.buff_read += len;
    crlf = (char *)mtev_memmem(rc->data.buff, rc->data.buff_read, "\r\n\r\n", 4); /* end of request */
    if(crlf) {
      const char **req;
      char *anchor;

      *(crlf + 2) = '\0';
      if(memcmp(rc->data.buff, "RSE /", 5)) {
        socket_error_string = "bad command";
        goto socket_error;
      }
      if(rc->data.buff_read < 8) goto socket_error; /* no room for an <id> */

      /* Find a X-Bind "header" */
      rc->data.xbind = extract_xbind(rc->data.buff, &rc->data.proxy_ip4, &rc->data.proxy_ip6);

      if(NULL == (crlf = (char *)mtev_memmem(rc->data.buff, rc->data.buff_read, "\r\n", 2))) {
        socket_error_string = "no end of line found";
        goto socket_error;
      }
      *crlf = '\0'; /* end of line */
      for(crlf = rc->data.buff+5; *crlf && !isspace(*crlf); crlf++);
      *crlf = '\0'; /* end of line */
      rc->id = strdup(rc->data.buff + 5);
      free(rc->data.buff);
      rc->data.buff = NULL;

      /* Validate the client certs for required connections. */
      for(req = cn_required_prefixes; *req; req++) {
        int reqlen = strlen(*req);
        if(!strncmp(rc->id, *req, reqlen)) {
          if(strcmp(rc->id+reqlen, remote_cn ? remote_cn : "")) {
            mtevL(nldeb, "%s - attempted reverse connection '%s' invalid remote '%s'\n",
                  __func__, rc->id+reqlen, remote_cn ? remote_cn : "");
            goto socket_error;
          }
        }
      }

      switch(mtev_reverse_socket_allowed(rc->id, ac)) {
        case MTEV_ACL_DENY:
          mtevL(nldeb, "%s - attempted reverse connection '%s' from '%s' denied by policy\n",
                  __func__, rc->id, remote_cn ? remote_cn : "");
          goto socket_error;
        default: break;
      }

      /* Like a URL, we'll clip off anything past # */
      anchor = strchr(rc->id, '#');
      if(anchor) *anchor = '\0';
      break;
    }
  }
  if(!rc->id) {
    socket_error_string = "no identifier";
    goto socket_error;
  }

  pthread_rwlock_wrlock(&reverse_sockets_lock);
  rv = mtev_hash_store(&reverse_sockets, rc->id, strlen(rc->id), rc->add_ref());
  pthread_rwlock_unlock(&reverse_sockets_lock);
  if(rv == 0) {
    snprintf(errbuf, sizeof(errbuf), "'%s' id in use", rc->id);
    free(rc->id);
    rc->id = NULL;
    socket_error_string = errbuf;
    goto socket_error;
  }
  else {
    mtevL(nldeb, "%s - reverse_socket to %s\n", __func__, rc->id);
    /* Setup proxies if we've got them */
    mtev_reverse_socket_proxy_setup(rc);
    mtevAssert(e);
    rc->data.e = e;
    eventer_set_callback(e, mtev_reverse_socket_server_handler);
    return eventer_callback(e, EVENTER_READ | EVENTER_WRITE, closure, now);
  }
  return 0;
}

extern "C" int mtev_reverse_socket_connect(const char *id, int existing_fd) {
  const char *op = "";
  int i, fd = -1, chan = -1;
  void *vrc;
  reverse_socket_sp rc;

  pthread_rwlock_rdlock(&reverse_sockets_lock);
  if(mtev_hash_retrieve(&reverse_sockets, id, strlen(id), &vrc)) {
    rc = static_cast<reverse_socket_t*>(vrc);
    for(i=0;i<MAX_CHANNELS;i++) {
      chan = (rc->data.last_allocated_channel + i + 1) % MAX_CHANNELS;
      if(rc->data.channels[chan].pair[0] == AVAILABLE) break;
    }
    if(i<MAX_CHANNELS) {
      reverse_frame_t f{};

      f.channel_id = chan | 0x8000;
      f.buff = strdup("CONNECT");
      f.buff_len = strlen(static_cast<const char*>(f.buff));
      op = "socketpair";
      mtevL(nldeb, "%s - sending connect message (channel id %d, chan %d, id %s, existing_fd %d)\n",
              __func__, f.channel_id, chan, id, existing_fd);
      if(existing_fd >= 0) {
        fd = existing_fd;
        mtevL(nldeb, "%s - setting fd for %s [channel %d] pair[0] from existing_fd - %d\n", __func__, id, chan,
          existing_fd);
        rc->data.channels[chan].pair[0] = fd;
      }
      else if(socketpair(AF_LOCAL, SOCK_STREAM, 0, rc->data.channels[chan].pair) < 0) {
        mtevL(nldeb, "%s - socketpair failed for %s [channel %d] - %d (%s)\n", __func__, id, chan, errno,
          strerror(errno));
        rc->data.channels[chan].pair[0] = rc->data.channels[chan].pair[1] = AVAILABLE;
      }
      else {
        mtevL(nldeb, "%s - set fds for %s [channel %d] from socketpair - [0] = %d, [1] = %d\n",
                __func__, id, chan, rc->data.channels[chan].pair[0], rc->data.channels[chan].pair[1]);
        op = "O_NONBLOCK";
        if(eventer_set_fd_nonblocking(rc->data.channels[chan].pair[0]) ||
           eventer_set_fd_nonblocking(rc->data.channels[chan].pair[1])) {
          close(rc->data.channels[chan].pair[0]);
          close(rc->data.channels[chan].pair[1]);
          mtevL(nldeb, "%s - eventer_set_fd_nonblocking failed for %s [channel %d]\n", __func__, id, chan);
          rc->data.channels[chan].pair[0] = rc->data.channels[chan].pair[1] = AVAILABLE;
        }
        else {
          fd = rc->data.channels[chan].pair[1];
          existing_fd = rc->data.channels[chan].pair[0];
        }
      }
      rc->data.last_allocated_channel = chan;
      if(existing_fd >= 0) {
        auto cct = new channel_closure_t{static_cast<std::uint16_t>(chan), rc};
        eventer_t e;

        mtev_gettimeofday(&rc->data.channels[chan].create_time, NULL);
        e = eventer_alloc_fd(mtev_reverse_socket_channel_handler, cct, existing_fd,
                             EVENTER_READ | EVENTER_EXCEPTION);
        mtevL(nldeb, "%s - mapping reverse proxy on fd %d for %s [channel %d]\n", __func__, existing_fd, id, chan);
        eventer_add(e);
        rc->append_out(&f);
      }
      else {
        mtevL(nldeb, "%s - no existing_fd for %s [channel %d]\n", __func__, id, chan);
        free(f.buff);
      }
      mtevL(nldeb, "%s - established reverse connection for %s [channel %d] - pair [%d,%d]\n",
            __func__, rc->id, chan, rc->data.channels[chan].pair[0], rc->data.channels[chan].pair[1]);
    }
  }
  pthread_rwlock_unlock(&reverse_sockets_lock);
  if(!rc)
    mtevL(nldeb, "%s - mtev_support_socket[%d,%s] does not exist\n", __func__, existing_fd, id);
  if(rc && fd < 0)
    mtevL(nlerr, "%s - mtev_support_socket[%d,%s] failed operation |%s|: %s\n", __func__, existing_fd,
      rc->id, op ? op : "[NULL]", strerror(errno));
  return fd;
}

static mtev_connection_ctx_t *
mtev_connection_ctx_alloc(mtev_hash_table *t, pthread_mutex_t *l) {
  static constexpr auto mtev_connection_close = [](mtev_connection_ctx_t *ctx, eventer_t e) {
    int mask = 0;
    const char *cn_expected;
    GET_EXPECTED_CN(ctx, cn_expected);
    LIBMTEV_REVERSE_CONNECT_CLOSE(eventer_get_fd(e), ctx->remote_str,
                                  (char *)cn_expected,
                                  ctx->wants_shutdown, errno);
    (void)cn_expected;

    if (eventer_remove_fde(e)) {
      eventer_close(e, &mask);
    }

    ctx->e = NULL;
  };

  mtev_connection_ctx_t *ctx, **pctx;
  ctx = static_cast<mtev_connection_ctx_t*>(calloc(1, sizeof(*ctx)));
  ctx->tracker = t;
  ctx->tracker_lock = l;
  ctx->refcnt = 1;
  ctx->schedule_reattempt = mtev_connection_schedule_reattempt;
  ctx->close = mtev_connection_close;
  pctx = static_cast<mtev_connection_ctx_t**>(malloc(sizeof(*pctx)));
  *pctx = ctx;
  pthread_mutex_lock(l);
  mtev_hash_store(t, (const char *)pctx, sizeof(*pctx), ctx);
  pthread_mutex_unlock(l);
  return ctx;
}

static void
mtev_connection_ctx_free(mtev_connection_ctx_t *ctx) {
  if(ctx->remote_cn) free(ctx->remote_cn);
  if(ctx->remote_str) free(ctx->remote_str);
  if(ctx->retry_event) {
    if (eventer_remove(ctx->retry_event)) {
      eventer_free(ctx->retry_event);
    }
  }
  if(ctx->timeout_event) {
    if (eventer_remove(ctx->timeout_event)) {
      eventer_free(ctx->timeout_event);
    }
  }
  ctx->consumer_free(ctx->consumer_ctx);
  if (ctx->e) {
    if (eventer_remove_fde(ctx->e)) {
      int mask = 0;

      eventer_close(ctx->e, &mask);
      eventer_free(ctx->e);
    }
  }
  free(ctx);
}

extern "C" void
mtev_connection_ctx_ref(mtev_connection_ctx_t *ctx) {
  ck_pr_inc_32(&ctx->refcnt);
}

extern "C" void
mtev_connection_ctx_deref(mtev_connection_ctx_t *ctx) {
  bool zero;
  ck_pr_dec_32_zero(&ctx->refcnt, &zero);
  if(zero) {
    mtev_connection_ctx_free(ctx);
  }
}

extern "C" void
mtev_connection_ctx_dealloc(mtev_connection_ctx_t *ctx) {
  mtev_connection_ctx_t **pctx = &ctx;
  pthread_mutex_t *lock = ctx->tracker_lock;
  if(lock) pthread_mutex_lock(lock);
  if(ctx->tracker)
    mtev_hash_delete(ctx->tracker, (const char *)pctx, sizeof(*pctx),
                     free, (void (*)(void *))mtev_connection_ctx_deref);
  else
    mtev_connection_ctx_deref(ctx);
  /* ctx could be free, so ctx->tracker_lock would be bad */
  if(lock) pthread_mutex_unlock(lock);
}

int
mtev_connection_reinitiate(eventer_t e, int mask, void *closure,
                         struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  auto ctx = static_cast<mtev_connection_ctx_t*>(closure);
  ctx->retry_event = NULL;
  mtev_connection_initiate_connection(ctx);
  return 0;
}

extern "C" int
mtev_connection_disable_timeout(mtev_connection_ctx_t *nctx) {
  if(nctx->timeout_event) {
    if (eventer_remove(nctx->timeout_event)) {
      eventer_free(nctx->timeout_event);
    }

    nctx->timeout_event = NULL;
  }
  return 0;
}

static void
mtev_connection_schedule_reattempt(mtev_connection_ctx_t *ctx,
                                   struct timeval *now) {
  struct timeval __now, interval;
  const char *v, *cn_expected;
  uint32_t min_interval = 1000, max_interval = 8000;

  GET_EXPECTED_CN(ctx, cn_expected);
  mtev_connection_disable_timeout(ctx);
  if(ctx->remote_cn) {
    free(ctx->remote_cn);
    ctx->remote_cn = NULL;
  }
  if(mtev_hash_retr_str(ctx->config,
                        "reconnect_initial_interval",
                        strlen("reconnect_initial_interval"),
                        &v)) {
    min_interval = MAX(atoi(v), 100); /* .1 second minimum */
  }
  if(mtev_hash_retr_str(ctx->config,
                        "reconnect_maximum_interval",
                        strlen("reconnect_maximum_interval"),
                        &v)) {
    max_interval = MIN(atoi(v), 3600*1000); /* 1 hour maximum */
  }
  if(ctx->current_backoff == 0) ctx->current_backoff = min_interval;
  else {
    ctx->current_backoff *= 2;
    ctx->current_backoff = MAX(min_interval, ctx->current_backoff);
    ctx->current_backoff = MIN(max_interval, ctx->current_backoff);
  }
  if(!now) {
    mtev_gettimeofday(&__now, NULL);
    now = &__now;
  }
  interval.tv_sec = ctx->current_backoff / 1000;
  interval.tv_usec = (ctx->current_backoff % 1000) * 1000;
  if(ctx->retry_event) {
    if (eventer_remove(ctx->retry_event)) {
      eventer_free(ctx->retry_event);
    }
  }
  add_timeval(*now, interval, &interval);
  ctx->retry_event = eventer_alloc_timer(mtev_connection_reinitiate, ctx, &interval);
  LIBMTEV_REVERSE_RESCHEDULE(-1, ctx->remote_str, (char *)cn_expected, ctx->current_backoff);
  (void)cn_expected;
  eventer_add(ctx->retry_event);
}

int
mtev_connection_ssl_upgrade(eventer_t e, int mask, void *closure,
                            struct timeval *now) {
  auto nctx = static_cast<mtev_connection_ctx_t*>(closure);
  int rv;
  const char *error = NULL, *cn_expected;
  char error_buff[500];
  eventer_ssl_ctx_t *sslctx = NULL;

  GET_EXPECTED_CN(nctx, cn_expected);
  LIBMTEV_REVERSE_CONNECT_SSL(eventer_get_fd(e), nctx->remote_str, (char *)cn_expected);

  if(mask & EVENTER_EXCEPTION) goto error;

  rv = eventer_SSL_connect(e, &mask);
  sslctx = eventer_get_eventer_ssl_ctx(e);

  if(rv > 0) {
    eventer_set_callback(e, nctx->consumer_callback);
    /* We must make a copy of the mtev_acceptor_closure_t for each new
     * connection.
     */
    if(sslctx != NULL) {
      const char *cn, *end;
      cn = eventer_ssl_get_peer_subject(sslctx);
      if(cn && (cn = strstr(cn, "CN=")) != NULL) {
        cn += 3;
        end = cn;
        while(*end && *end != '/') end++;
        nctx->remote_cn = static_cast<char*>(malloc(end - cn + 1));
        memcpy(nctx->remote_cn, cn, end - cn);
        nctx->remote_cn[end-cn] = '\0';
      }
      if(cn_expected && (!nctx->remote_cn ||
                         strcmp(nctx->remote_cn, cn_expected))) {
        snprintf(error_buff, sizeof(error_buff), "jlog connect CN mismatch - expected %s, got %s",
            cn_expected, nctx->remote_cn ? nctx->remote_cn : "(null)");
        error = error_buff;
        goto error;
      }
    }
    LIBMTEV_REVERSE_CONNECT_SSL_SUCCESS(eventer_get_fd(e), nctx->remote_str, (char *)cn_expected);
    return eventer_callback(e, mask, eventer_get_closure(e), now);
  }
  if(errno == EAGAIN) return mask | EVENTER_EXCEPTION;
  if(sslctx) error = eventer_ssl_get_last_error(sslctx);
  mtevL(nldeb, "%s - SSL upgrade failed.\n", __func__);

 error:
  LIBMTEV_REVERSE_CONNECT_SSL_FAILED(eventer_get_fd(e),
                          nctx->remote_str, (char *)cn_expected,
                          (char *)error, errno);
  if(error) {
    const char *cert_error = eventer_ssl_get_peer_error(sslctx);
    mtevL(nlerr, "[%s] [%s] %s: %s [%s]\n",
      nctx->remote_str ? nctx->remote_str : "(null)",
      cn_expected,
      __func__,
      error,
      cert_error);
  }
  nctx->close(nctx, e);
  mtev_connection_schedule_reattempt(nctx, now);
  return 0;
}

int
mtev_connection_complete_connect(eventer_t e, int mask, void *closure,
                                 struct timeval *now) {
  auto nctx = static_cast<mtev_connection_ctx_t*>(closure);
  const char *layer = NULL, *cert, *key, *ca, *ciphers, *crl = NULL, *cn_expected;
  char remote_str[128], tmp_str[INET6_ADDRSTRLEN+1];
  eventer_ssl_ctx_t *sslctx;
  int aerrno, len;
  socklen_t aerrno_len = sizeof(aerrno);

  GET_EXPECTED_CN(nctx, cn_expected);
  if(getsockopt(eventer_get_fd(e),SOL_SOCKET,SO_ERROR, &aerrno, &aerrno_len) == 0)
    if(aerrno != 0) goto connect_error;
  aerrno = 0;

  if(mask & EVENTER_EXCEPTION) {
    if(aerrno == 0 && (write(eventer_get_fd(e), e, 0) == -1))
      aerrno = errno;
 connect_error:
    switch(nctx->r.remote.sa_family) {
      case AF_INET:
        len = sizeof(struct sockaddr_in);
        inet_ntop(nctx->r.remote.sa_family, &nctx->r.remote_in.sin_addr,
                  tmp_str, len);
        snprintf(remote_str, sizeof(remote_str), "%s:%d",
                 tmp_str, ntohs(nctx->r.remote_in.sin_port));
        break;
      case AF_INET6:
        len = sizeof(struct sockaddr_in6);
        inet_ntop(nctx->r.remote.sa_family, &nctx->r.remote_in6.sin6_addr,
                  tmp_str, len);
        snprintf(remote_str, sizeof(remote_str), "[%s]:%d",
                 tmp_str, ntohs(nctx->r.remote_in6.sin6_port));
       break;
      case AF_UNIX:
        snprintf(remote_str, sizeof(remote_str), "%s", nctx->r.remote_un.sun_path);
        break;
      case AF_UNSPEC:
        snprintf(remote_str, sizeof(remote_str), "unspecified");
        break;
      default:
        snprintf(remote_str, sizeof(remote_str), "(unknown)");
    }
    mtevL(nlerr, "%s: Error connecting to %s (%s): %s\n",
          __func__, remote_str, cn_expected ? cn_expected : "(null)", strerror(aerrno));
    LIBMTEV_REVERSE_CONNECT_FAILED(eventer_get_fd(e), remote_str, (char *)cn_expected, aerrno);
    nctx->close(nctx, e);
    nctx->schedule_reattempt(nctx, now);
    return 0;
  }

#define SSLCONFGET(var,name) do { \
  if(!mtev_hash_retr_str(nctx->sslconfig, name, strlen(name), \
                         &var)) var = NULL; } while(0)
  SSLCONFGET(layer, "layer");
  SSLCONFGET(cert, "certificate_file");
  SSLCONFGET(key, "key_file");
  SSLCONFGET(ca, "ca_chain");
  SSLCONFGET(ciphers, "ciphers");
  SSLCONFGET(crl, "crl");

  sslctx = eventer_ssl_ctx_new(SSL_CLIENT, layer, cert, key, ca, ciphers);
  if(!sslctx) goto connect_error;
  if(crl) {
    if(!eventer_ssl_use_crl(sslctx, crl)) {
      mtevL(nlerr, "%s: Failed to load CRL from %s\n", __func__, crl);
      eventer_ssl_ctx_free(sslctx);
      goto connect_error;
    }
  }

  memcpy(&nctx->last_connect, now, sizeof(*now));
  eventer_ssl_ctx_set_verify(sslctx, eventer_ssl_verify_cert,
                             nctx->sslconfig);
  EVENTER_ATTACH_SSL(e, sslctx);
  eventer_set_callback(e, mtev_connection_ssl_upgrade);
  LIBMTEV_REVERSE_CONNECT_SUCCESS(eventer_get_fd(e), nctx->remote_str, (char *)cn_expected);
  return eventer_callback(e, mask, closure, now);
}

int
mtev_connection_session_timeout(eventer_t e, int mask, void *closure,
                                struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  auto nctx = static_cast<mtev_connection_ctx_t*>(closure);
  eventer_t fde = nctx->e;
  nctx->timeout_event = NULL;
  mtevL(nlerr, "%s: Timing out session: %s, %s\n",
        __func__,
        nctx->remote_cn ? nctx->remote_cn : "(null)",
        nctx->remote_str ? nctx->remote_str : "(null)");
  if(fde)
    eventer_trigger(fde, EVENTER_EXCEPTION);
  return 0;
}

extern "C" int
mtev_connection_update_timeout(mtev_connection_ctx_t *nctx) {
  struct timeval now, diff;
  if(nctx->max_silence == 0) return 0;

  diff.tv_sec = nctx->max_silence / 1000;
  diff.tv_usec = (nctx->max_silence % 1000) * 1000;
  mtev_gettimeofday(&now, NULL);

  if(!nctx->timeout_event) {
    add_timeval(now, diff, &diff);
    nctx->timeout_event =
      eventer_alloc_timer(mtev_connection_session_timeout, nctx, &diff);
    eventer_add(nctx->timeout_event);
  }
  else {
    add_timeval(now, diff, &diff);
    eventer_update_whence(nctx->timeout_event, diff);
  }
  return 0;
}

void
mtev_connection_initiate_connection(mtev_connection_ctx_t *nctx) {
  struct timeval __now;
  eventer_t e;
  const char *cn_expected;
  char reverse_path[256];
  int rv, fd = -1, needs_connect = 1;
#ifdef SO_KEEPALIVE
  int optval;
  socklen_t optlen = sizeof(optval);
#endif

  GET_EXPECTED_CN(nctx, cn_expected);
  nctx->e = NULL;
  if(nctx->wants_permanent_shutdown) {
    LIBMTEV_REVERSE_SHUTDOWN_PERMANENT(-1, nctx->remote_str, (char *)cn_expected);
    mtev_connection_ctx_dealloc(nctx);
    return;
  }
  if(cn_expected) {
    snprintf(reverse_path, sizeof(reverse_path), "%s%s", my_reverse_prefix, cn_expected);
    fd = mtev_reverse_socket_connect(reverse_path, -1);
    if(fd < 0) {
      mtevL(nldeb, "%s - No reverse_socket connection to %s\n", __func__, reverse_path);
    }
    else {
      mtevL(nldeb, "%s - Got a reverse_socket connection to %s\n", __func__, reverse_path);
      needs_connect = 0;
    }
  }

  if(fd < 0) {
    /* If we don't know how to connect, don't bother (reverse only) */
    if(nctx->r.remote.sa_family == AF_UNSPEC) goto reschedule;
    /* If that didn't work, open a socket */
    fd = socket(nctx->r.remote.sa_family, NE_SOCK_CLOEXEC|SOCK_STREAM, 0);
  }
  if(fd < 0) goto reschedule;

  /* Make it non-blocking */
  if(eventer_set_fd_nonblocking(fd)) goto reschedule;
#define set_or_bail(type, opt, val) do { \
  optval = val; \
  optlen = sizeof(optval); \
  if(setsockopt(fd, type, opt, &optval, optlen) < 0) { \
    mtevL(nlerr, "%s: [%s] Cannot set " #type "/" #opt " on socket: %s\n", \
          __func__, nctx->remote_str ? nctx->remote_str : "(null)", \
          strerror(errno)); \
    goto reschedule; \
  } \
} while(0)
#ifdef SO_KEEPALIVE
  set_or_bail(SOL_SOCKET, SO_KEEPALIVE, 1);
#endif
#ifdef TCP_KEEPALIVE_THRESHOLD
  set_or_bail(IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD, 10 * 1000);
#endif
#ifdef TCP_KEEPALIVE_ABORT_THRESHOLD
  set_or_bail(IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD, 30 * 1000);
#endif
#ifdef TCP_CONN_NOTIFY_THRESHOLD
  set_or_bail(IPPROTO_TCP, TCP_CONN_NOTIFY_THRESHOLD, 10 * 1000);
#endif
#ifdef TCP_CONN_ABORT_THRESHOLD
  set_or_bail(IPPROTO_TCP, TCP_CONN_ABORT_THRESHOLD, 30 * 1000);
#endif

  /* Initiate a connection */
  if(needs_connect) {
    rv = connect(fd, &nctx->r.remote, nctx->remote_len);
    if(rv == -1 && errno != EINPROGRESS) goto reschedule;
  }

  /* Register a handler for connection completion */
  e = eventer_alloc_fd(mtev_connection_complete_connect, nctx, fd,
                       EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION);
  nctx->e = e;
  eventer_add(e);

  LIBMTEV_REVERSE_CONNECT(eventer_get_fd(e), nctx->remote_str, (char *)cn_expected);
  mtev_connection_update_timeout(nctx);
  return;
 reschedule:
  if(fd >= 0) close(fd);
  mtev_gettimeofday(&__now, NULL);
  nctx->schedule_reattempt(nctx, &__now);
  return;
}

mtev_connection_ctx_t *
initiate_mtev_connection(mtev_hash_table *tracking, pthread_mutex_t *tracking_lock,
                         const char *host, unsigned short port,
                         mtev_hash_table *sslconfig, mtev_hash_table *config,
                         eventer_func_t handler, void *closure,
                         void (*freefunc)(void *)) {
  mtev_connection_ctx_t *ctx;
  const char *stimeout;
  int8_t family = AF_UNSPEC;
  int rv;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } a;

  if(host[0] == '/') {
    family = AF_UNIX;
  }
  else {
    family = AF_INET;
    rv = inet_pton(family, host, &a);
    if(rv != 1) {
      family = AF_INET6;
      rv = inet_pton(family, host, &a);
      if(rv != 1) {
        if(!strcmp(host, "")) family = AF_UNSPEC;
        else {
          mtevL(nlerr, "%s: Cannot translate '%s' to IP\n", __func__, host);
          return NULL;
        }
      }
    }
  }
  if(handler == NULL) return NULL;

  ctx = mtev_connection_ctx_alloc(tracking, tracking_lock);
  if(*host) {
    ctx->remote_str = static_cast<char *>(calloc(1, strlen(host) + 7));
    snprintf(ctx->remote_str, strlen(host) + 7,
             "%s:%d", host, port);
  }
  else {
    ctx->remote_str = strdup("unspecified");
  }
  memset(&ctx->r, 0, sizeof(ctx->r));
  if(family == AF_UNSPEC) {
    ctx->r.remote.sa_family = family;
  }
  else if(family == AF_UNIX) {
    struct sockaddr_un *s = &ctx->r.remote_un;
    s->sun_family = AF_UNIX;
    strncpy(s->sun_path, host, sizeof(s->sun_path)-1);
    ctx->remote_len = sizeof(*s);
  }
  else if(family == AF_INET) {
    struct sockaddr_in *s = &ctx->r.remote_in;
    s->sin_family = family;
    s->sin_port = htons(port);
    memcpy(&s->sin_addr, &a, sizeof(struct in_addr));
    ctx->remote_len = sizeof(*s);
  }
  else {
    struct sockaddr_in6 *s = &ctx->r.remote_in6;
    s->sin6_family = family;
    s->sin6_port = htons(port);
    memcpy(&s->sin6_addr, &a, sizeof(a));
    ctx->remote_len = sizeof(*s);
  }

  if(ctx->sslconfig)
    mtev_hash_delete_all(ctx->sslconfig, free, free);
  else {
    ctx->sslconfig = static_cast<mtev_hash_table*>(calloc(1, sizeof(mtev_hash_table)));
    mtev_hash_init(ctx->sslconfig);
  }
  mtev_hash_merge_as_dict(ctx->sslconfig, sslconfig);
  if(ctx->config)
    mtev_hash_delete_all(ctx->config, free, free);
  else {
    ctx->config = static_cast<mtev_hash_table*>(calloc(1, sizeof(mtev_hash_table)));
    mtev_hash_init(ctx->config);
  }
  mtev_hash_merge_as_dict(ctx->config, config);

  if(mtev_hash_retr_str(ctx->config, "timeout", strlen("timeout"), &stimeout))
    ctx->max_silence = atoi(stimeout);
  else
    ctx->max_silence = DEFAULT_MTEV_CONNECTION_TIMEOUT;
  ctx->consumer_callback = handler;
  ctx->consumer_free = freefunc;
  ctx->consumer_ctx = closure;
  mtev_connection_initiate_connection(ctx);
  return ctx;
}

extern "C" int
mtev_connections_from_config(mtev_hash_table *tracker, pthread_mutex_t *tracker_lock,
                             const char *toplevel, const char *destination,
                             const char *type,
                             eventer_func_t handler,
                             void *(*handler_alloc)(void), void *handler_ctx,
                             void (*handler_free)(void *)) {
  int i, cnt = 0, found = 0;
  mtev_conf_section_t *mtev_configs;
  char path[256];

  snprintf(path, sizeof(path), "/%s/%ss//%s", toplevel ? toplevel : "*", type, type);
  mtev_configs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, path, &cnt);
  mtevL(nldeb, "%s - Found %d %s stanzas\n", __func__, cnt, path);
  for(i=0; i<cnt; i++) {
    char address[256];
    const char *expected_cn = NULL;
    unsigned short port;
    int32_t portint;
    mtev_hash_table *sslconfig, *config;

    if(!mtev_conf_get_stringbuf(mtev_configs[i],
                                "ancestor-or-self::node()/@address",
                                address, sizeof(address))) {
      mtevL(nlerr, "%s: address attribute missing in %d\n", __func__, i+1);
      continue;
    }
    config = mtev_conf_get_hash(mtev_configs[i], "config");
    if(!mtev_hash_retr_str(config, "cn", strlen("cn"), &expected_cn))
      expected_cn = NULL;

    /* if destination is specified, exact match either the address or CN */
    if(destination && strcmp(address, destination) &&
       (!expected_cn || strcmp(expected_cn, destination))) {
      mtev_hash_destroy(config,free,free);
      continue;
    }

    if(!mtev_conf_get_int32(mtev_configs[i],
                            "ancestor-or-self::node()/@port", &portint))
      portint = 0;
    port = (unsigned short) portint;
    if(address[0] != '/' && (portint == 0 || (port != portint))) {
      /* UNIX sockets don't require a port (they'll ignore it if specified */
      mtevL(nlerr,
            "%s: Invalid port [%d] specified in stanza %d\n", __func__, port, i+1);
      mtev_hash_destroy(config,free,free);
      continue;
    }
    sslconfig = mtev_conf_get_hash(mtev_configs[i], "sslconfig");

    mtevL(nldeb, "%s - initiating to '%s'\n", __func__, address);

    initiate_mtev_connection(tracker, tracker_lock,
                             address, port, sslconfig, config,
                             handler,
                             handler_alloc ? handler_alloc() : handler_ctx,
                             handler_free);
    found++;
    mtev_hash_destroy(sslconfig,free,free);
    free(sslconfig);
    mtev_hash_destroy(config,free,free);
    free(config);
  }
  mtev_conf_release_sections_read(mtev_configs, cnt);
  return found;
}

static int
mtev_reverse_client_handler(eventer_t e, int mask, void *closure,
                             struct timeval *now) {
  auto nctx = static_cast<mtev_connection_ctx_t *>(closure);
  const char *my_cn;
  reverse_socket_sp rc = static_cast<reverse_socket_t*>(nctx->consumer_ctx);
  const char *target, *port_str, *xbind;
  char channel_name[256];
  char reverse_intro[300];
  int8_t family = AF_INET;
  int rv;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } a;
  uuid_t tmpid;
  char tmpidstr[UUID_STR_LEN+1];
  char client_id[ /* client/ */ 7 + UUID_STR_LEN + 1];

  if(nctx->wants_permanent_shutdown) goto fail;

  rc->data.nctx = nctx;
  nctx->close = [](mtev_connection_ctx_t *ctx, eventer_t e) {
    mtev_reverse_socket_shutdown(static_cast<reverse_socket_t *>(ctx->consumer_ctx), e);

    if (eventer_remove_fde(e)) {
      int mask;

      eventer_close(e, &mask);
    }

    ctx->e = NULL;
  };

  if(rc->data.buff) {
    /* We've been here before, we just need to complete the write */
    goto finish_write;
  }

  mtev_gettimeofday(&rc->data.create_time, NULL);

  GET_CONF_STR(nctx, "endpoint", my_cn);
  GET_CONF_STR(nctx, "local_address", target);
  GET_CONF_STR(nctx, "local_port", port_str);
  GET_CONF_STR(nctx, "xbind", xbind);

  if(my_cn) {
    snprintf(channel_name, sizeof(channel_name), "%s%s", my_reverse_prefix, my_cn);
  }
  else {
    eventer_ssl_ctx_t *sslctx;
    strlcpy(channel_name, my_reverse_prefix, sizeof(channel_name));
    sslctx = eventer_get_eventer_ssl_ctx(e);
    if(!sslctx || eventer_ssl_get_local_commonname(sslctx, channel_name+5, sizeof(channel_name)-5) < 1)
      goto fail;
  }
  if(!target) target = "127.0.0.1";
  if(!port_str) port_str = "43191";

  rv = inet_pton(family, target, &a);
  if(rv != 1) {
    family = AF_INET6;
    rv = inet_pton(family, target, &a);
    if(rv != 1) {
      memset(&a, 0, sizeof(a));
      goto fail;
    }
  }

  if(family == AF_INET) {
    rc->data.tgt.ipv4.sin_family = AF_INET;
    rc->data.tgt.ipv4.sin_port = htons(atoi(port_str));
    memcpy(&rc->data.tgt.ipv4.sin_addr, &a.addr4, sizeof(a.addr4));
    rc->data.tgt_len = sizeof(struct sockaddr_in);
  }
  else if(family == AF_INET6) {
    rc->data.tgt.ipv6.sin6_family = AF_INET6;
    rc->data.tgt.ipv6.sin6_port = htons(atoi(port_str));
    memcpy(&rc->data.tgt.ipv6.sin6_addr, &a.addr6, sizeof(a.addr6));
    rc->data.tgt_len = sizeof(struct sockaddr_in6);
  }

  snprintf(reverse_intro, sizeof(reverse_intro),
           "REVERSE /%s%s%s\r\n\r\n", channel_name,
           xbind ? "\r\nX-Bind: " : "", xbind ? xbind : "");
  rc->data.buff = strdup(reverse_intro);
  rc->data.buff_len = strlen(rc->data.buff);

 finish_write: 
  while(rc->data.buff_written < rc->data.buff_len) {
    ssize_t len;
    len = eventer_write(e, rc->data.buff + rc->data.buff_written,
                        rc->data.buff_len - rc->data.buff_written, &mask);
    if(len < 0 && errno == EAGAIN) return mask | EVENTER_EXCEPTION;
    if(len <= 0) goto fail;
    rc->data.buff_written += len;
  }
  free(rc->data.buff);
  rc->data.buff = NULL;
  rc->data.buff_len = rc->data.buff_written = rc->data.buff_read = 0;

  /* We've finished our preamble... so now we will switch handlers */
  if(!rc->id) {
    mtev_uuid_generate(tmpid);
    mtev_uuid_unparse_lower(tmpid, tmpidstr);
    snprintf(client_id, sizeof(client_id), "client/%s", tmpidstr);
    rc->id = strdup(client_id);
    pthread_rwlock_wrlock(&reverse_sockets_lock);
    mtev_hash_store(&reverse_sockets, rc->id, strlen(rc->id), rc->add_ref());
    pthread_rwlock_unlock(&reverse_sockets_lock);
  }

  mtevAssert(e);
  rc->data.e = e;
  eventer_set_callback(e, mtev_reverse_socket_client_handler);
  return eventer_callback(e, EVENTER_READ|EVENTER_WRITE, closure, now);

 fail:
  if(rc->data.buff) {
    free(rc->data.buff);
    rc->data.buff = NULL;
    rc->data.buff_len = rc->data.buff_written = rc->data.buff_read = 0;
  }
  nctx->close(nctx, e);
  nctx->schedule_reattempt(nctx, now);
  return 0;
}

static int
reverse_socket_str_sort(const void *a, const void *b) {
  auto actx = static_cast<const reverse_socket_t * const *>(a);
  auto bctx = static_cast<const reverse_socket_t * const *>(b);
  return strcmp((*actx)->id, (*bctx)->id);
}

static void
nc_print_reverse_socket_brief(mtev_console_closure_t ncct,
                               reverse_socket_t *ctx) {
  int i;
  double age;
  struct timeval now, diff;

  mtev_gettimeofday(&now, NULL);
  sub_timeval(now, ctx->data.create_time, &diff);
  age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
  if(ctx->data.e) {
    char buff[INET6_ADDRSTRLEN];
    nc_printf(ncct, "%s [%d]\n", ctx->id, eventer_get_fd(ctx->data.e.get()));
    if(ctx->data.proxy_ip4_e) {
      inet_ntop(AF_INET, &ctx->data.proxy_ip4.sin_addr, buff, sizeof(buff));
      nc_printf(ncct, "  listening (IPv4): %s :%d\n", buff, ntohs(ctx->data.proxy_ip4.sin_port));
    }
    if(ctx->data.proxy_ip6_e) {
      inet_ntop(AF_INET6, &ctx->data.proxy_ip6.sin6_addr, buff, sizeof(buff));
      nc_printf(ncct, "  listening (IPv6): %s :%d\n", buff, ntohs(ctx->data.proxy_ip6.sin6_port));
    }
    nc_printf(ncct, "  [UP: %0.3fs IN: %llub / %lluf  OUT: %llub / %lluf]\n", age,
              (unsigned long long)ctx->data.in_bytes, (unsigned long long)ctx->data.in_frames,
              (unsigned long long)ctx->data.out_bytes, (unsigned long long)ctx->data.out_frames);
  }
  else {
    nc_printf(ncct, "%s [disconnected]\n", ctx->id);
  }
  for(i=0; i<MAX_CHANNELS; i++) {
    if(ctx->data.channels[i].pair[0] >= 0) {
      sub_timeval(now, ctx->data.channels[i].create_time, &diff);
      age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
      nc_printf(ncct, "  [%3d:%4d:%4d]: [UP: %0.3fs IN: %llub / %lluf  OUT: %llub / %lluf]\n",
            i, ctx->data.channels[i].pair[0], ctx->data.channels[i].pair[1], age,
            (unsigned long long)ctx->data.channels[i].in_bytes, (unsigned long long)ctx->data.channels[i].in_frames,
            (unsigned long long)ctx->data.channels[i].out_bytes, (unsigned long long)ctx->data.channels[i].out_frames);
    }
  }
}

static int
mtev_console_show_reverse(mtev_console_closure_t ncct,
                          int argc, char **argv,
                          mtev_console_state_t *dstate,
                          void *closure) {
  (void)dstate;
  (void)closure;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int n = 0, i;
  reverse_socket_t **ctx;

  pthread_rwlock_rdlock(&reverse_sockets_lock);
  ctx = static_cast<reverse_socket_t**>(malloc(sizeof(*ctx) * mtev_hash_size(&reverse_sockets)));
  while(mtev_hash_adv(&reverse_sockets, &iter)) {
    ctx[n] = (reverse_socket_t *)iter.value.ptr;
    if(argc == 0 ||
       !strcmp(ctx[n]->id, argv[0])) {
      n++;
    }
  }
  qsort(ctx, n, sizeof(*ctx), reverse_socket_str_sort);
  for(i=0; i<n; i++) {
    nc_print_reverse_socket_brief(ncct, ctx[i]);
  }
  pthread_rwlock_unlock(&reverse_sockets_lock);
  free(ctx);
  return 0;
}

static char *
mtev_console_reverse_opts(mtev_console_closure_t ncct,
                          mtev_console_state_stack_t *stack,
                          mtev_console_state_t *dstate,
                          int argc, char **argv, int idx) {
  if(argc == 1) {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    int i = 0;
    reverse_socket_sp ctx;

    pthread_rwlock_rdlock(&reverse_sockets_lock);
    while(mtev_hash_adv(&reverse_sockets, &iter)) {
      ctx = (reverse_socket_t *)iter.value.ptr;
      if(!strncmp(ctx->id, argv[0], strlen(argv[0]))) {
        if(idx == i) {
          pthread_rwlock_unlock(&reverse_sockets_lock);
          return strdup(ctx->id);
        }
        i++;
      }
    }
    pthread_rwlock_unlock(&reverse_sockets_lock);
  }
  if(argc == 2)
    return mtev_console_opt_delegate(ncct, stack, dstate, argc-1, argv+1, idx);
  return NULL;
}

static void
register_console_reverse_commands(void) {
  mtev_console_state_t *tl;
  cmd_info_t *showcmd;

  tl = mtev_console_state_initial();
  showcmd = mtev_console_state_get_cmd(tl, "show");
  mtevAssert(showcmd && showcmd->dstate);

  mtev_console_state_add_cmd(showcmd->dstate,
    NCSCMD("reverse", mtev_console_show_reverse,
           mtev_console_reverse_opts, NULL, (void *)1));
}

static int
rest_show_reverse_json(mtev_http_rest_closure_t *restc,
                       int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_json_object *doc, *node, *channels;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  const char *want_id = NULL;
  int n = 0, i, di;
  double age;
  reverse_socket_t **ctxs;
  struct timeval now, diff;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  want_id = mtev_http_request_querystring(req, "id");

  mtev_gettimeofday(&now, NULL);

  pthread_rwlock_rdlock(&reverse_sockets_lock);
  ctxs = static_cast<reverse_socket**>(malloc(sizeof(*ctxs) * mtev_hash_size(&reverse_sockets)));
  while(mtev_hash_adv(&reverse_sockets, &iter)) {
    ctxs[n] = (reverse_socket_t *)iter.value.ptr;
    n++;
  }

  doc = MJ_OBJ();

  for(i=0; i<n; i++) {
    char scratch[128];
    char buff[INET6_ADDRSTRLEN];
    if(want_id && strcmp(want_id, ctxs[i]->id)) continue;
    reverse_socket_t *rc = ctxs[i];

    node = MJ_OBJ();
    if(rc->data.e) {
#define ADD_ATTR(node, name, fmt...) do { \
  snprintf(scratch, sizeof(scratch), fmt); \
  MJ_KV(node, name, MJ_STR(scratch)); \
} while(0)
      MJ_KV(node, "fd", MJ_INT(eventer_get_fd(rc->data.e.get())));
      sub_timeval(now, rc->data.create_time, &diff);
      age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
      MJ_KV(node, "uptime", MJ_DOUBLE(age));
      MJ_KV(node, "in_bytes", MJ_UINT64(rc->data.in_bytes));
      MJ_KV(node, "in_frames", MJ_UINT64(rc->data.in_frames));
      MJ_KV(node, "out_bytes", MJ_UINT64(rc->data.out_bytes));
      MJ_KV(node, "out_frames", MJ_UINT64(rc->data.out_frames));
      if(rc->data.proxy_ip4_e) {
        inet_ntop(AF_INET, &rc->data.proxy_ip4.sin_addr, buff, sizeof(buff));
        ADD_ATTR(node, "proxy_ipv4", "%s:%d", buff, ntohs(rc->data.proxy_ip4.sin_port));
      }
      if(rc->data.proxy_ip6_e) {
        inet_ntop(AF_INET6, &rc->data.proxy_ip6.sin6_addr, buff, sizeof(buff));
        ADD_ATTR(node, "proxy_ipv6", "[%s]:%d", buff, ntohs(rc->data.proxy_ip6.sin6_port));
      }
      channels = MJ_OBJ();
      for(di=0;di<MAX_CHANNELS;di++) {
        char di_str[32];
        mtev_json_object *channel;
        if(rc->data.channels[di].pair[0] < 0) continue;
        snprintf(di_str, sizeof(di_str), "%d", di);
        channel = MJ_OBJ();
        MJ_KV(channel, "channel_id", MJ_INT(di));
        MJ_KV(channel, "fd", MJ_INT(rc->data.channels[di].pair[0]));
        sub_timeval(now, rc->data.channels[di].create_time, &diff);
        age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
        MJ_KV(channel, "uptime", MJ_DOUBLE(age));
        MJ_KV(channel, "in_bytes", MJ_UINT64(rc->data.channels[di].in_bytes));
        MJ_KV(channel, "in_frames", MJ_UINT64(rc->data.channels[di].in_frames));
        MJ_KV(channel, "out_bytes", MJ_UINT64(rc->data.channels[di].out_bytes));
        MJ_KV(channel, "out_frames", MJ_UINT64(rc->data.channels[di].out_frames));
        MJ_KV(channels, di_str, channel);
      }
      MJ_KV(node, "channels", channels);
#undef ADD_ATTR
    }
    MJ_KV(doc, rc->id, node);
  }
  
  pthread_rwlock_unlock(&reverse_sockets_lock);
  free(ctxs);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}


static int
rest_show_reverse(mtev_http_rest_closure_t *restc,
                  int npats, char **pats) {
  (void)npats;
  (void)pats;
  xmlDocPtr doc;
  xmlNodePtr root;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  const char *want_id = NULL;
  int n = 0, i, di;
  double age;
  reverse_socket_t **ctxs;
  struct timeval now, diff;
  xmlNodePtr node, channels;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  want_id = mtev_http_request_querystring(req, "id");

  mtev_gettimeofday(&now, NULL);

  pthread_rwlock_rdlock(&reverse_sockets_lock);
  ctxs = static_cast<reverse_socket**>(malloc(sizeof(*ctxs) * mtev_hash_size(&reverse_sockets)));
  while(mtev_hash_adv(&reverse_sockets, &iter)) {
    ctxs[n] = (reverse_socket_t *)iter.value.ptr;
    n++;
  }

  doc = xmlNewDoc((xmlChar *)"1.0");
  root = xmlNewDocNode(doc, NULL, (xmlChar *)"reverses", NULL);
  xmlDocSetRootElement(doc, root);

  for(i=0; i<n; i++) {
    char scratch[128];
    char buff[INET6_ADDRSTRLEN];
    if(want_id && strcmp(want_id, ctxs[i]->id)) continue;
    reverse_socket_t *rc = ctxs[i];

    node = xmlNewNode(NULL, (xmlChar *)"reverse");
    xmlSetProp(node, (xmlChar *)"id", (xmlChar *)rc->id);
    if(rc->data.e) {
#define ADD_ATTR(node, name, fmt...) do { \
  snprintf(scratch, sizeof(scratch), fmt); \
  xmlSetProp(node, (xmlChar *)name, (xmlChar *)scratch); \
} while(0)
      ADD_ATTR(node, "fd", "%d", eventer_get_fd(rc->data.e.get()));
      sub_timeval(now, rc->data.create_time, &diff);
      age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
      ADD_ATTR(node, "uptime", "%0.3f", age);
      ADD_ATTR(node, "in_bytes", "%llu", (unsigned long long)rc->data.in_bytes);
      ADD_ATTR(node, "in_frames", "%llu", (unsigned long long)rc->data.in_frames);
      ADD_ATTR(node, "out_bytes", "%llu", (unsigned long long)rc->data.out_bytes);
      ADD_ATTR(node, "out_frames", "%llu", (unsigned long long)rc->data.out_frames);
      if(rc->data.proxy_ip4_e) {
        inet_ntop(AF_INET, &rc->data.proxy_ip4.sin_addr, buff, sizeof(buff));
        ADD_ATTR(node, "proxy_ipv4", "%s:%d", buff, ntohs(rc->data.proxy_ip4.sin_port));
      }
      if(rc->data.proxy_ip6_e) {
        inet_ntop(AF_INET6, &rc->data.proxy_ip6.sin6_addr, buff, sizeof(buff));
        ADD_ATTR(node, "proxy_ipv6", "[%s]:%d", buff, ntohs(rc->data.proxy_ip6.sin6_port));
      }
      channels = xmlNewNode(NULL, (xmlChar *)"channels");
      for(di=0;di<MAX_CHANNELS;di++) {
        xmlNodePtr channel;
        if(rc->data.channels[di].pair[0] < 0) continue;
        channel = xmlNewNode(NULL, (xmlChar *)"channel");
        ADD_ATTR(channel, "channel_id", "%d", di);
        ADD_ATTR(channel, "fd", "%d", rc->data.channels[di].pair[0]);
        sub_timeval(now, rc->data.channels[di].create_time, &diff);
        age = diff.tv_sec + (double)diff.tv_usec/1000000.0;
        ADD_ATTR(channel, "uptime", "%0.3f", age);
        ADD_ATTR(channel, "in_bytes", "%llu", (unsigned long long)rc->data.channels[di].in_bytes);
        ADD_ATTR(channel, "in_frames", "%llu", (unsigned long long)rc->data.channels[di].in_frames);
        ADD_ATTR(channel, "out_bytes", "%llu", (unsigned long long)rc->data.channels[di].out_bytes);
        ADD_ATTR(channel, "out_frames", "%llu", (unsigned long long)rc->data.channels[di].out_frames);
        xmlAddChild(channels, channel);
      }
      xmlAddChild(node, channels);
#undef ADD_ATTR
    }
    xmlAddChild(root, node);
  }
  
  pthread_rwlock_unlock(&reverse_sockets_lock);
  free(ctxs);

  mtev_http_response_ok(restc->http_ctx, "text/xml");
  mtev_http_response_xml(restc->http_ctx, doc);
  mtev_http_response_end(restc->http_ctx);
  xmlFreeDoc(doc);
  return 0;
}

extern "C" void mtev_reverse_socket_init(const char *prefix, const char **cn_prefixes) {
  nlerr = mtev_log_stream_find("error/reverse");
  nldeb = mtev_log_stream_find("debug/reverse");

  my_reverse_prefix = prefix;
  cn_required_prefixes = cn_prefixes;

  pthread_rwlock_init(&reverse_sockets_lock, NULL);
  pthread_mutex_init(&reverses_lock, NULL);
  eventer_name_callback("reverse_socket_accept",
                        mtev_reverse_socket_acceptor);
  eventer_name_callback("reverse_socket_proxy_accept",
                        mtev_reverse_socket_proxy_accept);
  eventer_name_callback("reverse_socket_server_handler",
                        mtev_reverse_socket_server_handler);
  eventer_name_callback("reverse_socket_client_handler",
                        mtev_reverse_socket_client_handler);
  eventer_name_callback("reverse_socket_channel_handler",
                        mtev_reverse_socket_channel_handler);
  eventer_name_callback("mtev_connection_reinitiate",
                        mtev_connection_reinitiate);
  eventer_name_callback("mtev_connection_ssl_upgrade",
                        mtev_connection_ssl_upgrade);
  eventer_name_callback("mtev_connection_complete_connect",
                        mtev_connection_complete_connect);
  eventer_name_callback("mtev_connection_session_timeout",
                        mtev_connection_session_timeout);
  eventer_name_callback("mtev_reverse_socket_wakeup",
                        mtev_reverse_socket_wakeup);

  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_REVERSE,
                                 mtev_reverse_socket_acceptor);

  mtev_connections_from_config(&reverses, &reverses_lock,
                               "", NULL, "reverse",
                               mtev_reverse_client_handler,
                               []() -> void* { return mtev_reverse_socket_alloc()->add_ref(); },
                               NULL,
                               reverse_socket::release_ref_no_return);

  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/reverse/", "^show$", rest_show_reverse,
             mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/reverse/", "^show.json$", rest_show_reverse_json,
             mtev_http_rest_client_cert_auth
  ) == 0);

  register_console_reverse_commands();
}

extern "C" int
mtev_reverse_socket_connection_shutdown(const char *address, int port) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int success = 0;
  char remote_str[INET6_ADDRSTRLEN + 1 + 5 + 1];

  snprintf(remote_str, sizeof(remote_str), "%s:%d", address, port);
  pthread_mutex_lock(&reverses_lock);
  while(mtev_hash_adv(&reverses, &iter)) {
    auto ctx = static_cast<mtev_connection_ctx_t *>(iter.value.ptr);
    if(ctx->remote_str && !strcmp(remote_str, ctx->remote_str)) {
      if(!ctx->wants_permanent_shutdown) {
        ctx->wants_permanent_shutdown = 1;
        if(ctx->e) eventer_trigger(ctx->e, EVENTER_EXCEPTION);
        success = 1;
      }
      break;
    }
  }
  pthread_mutex_unlock(&reverses_lock);
  return success;
}

extern "C" mtev_boolean
mtev_connection_do(const char *address, int port, void (*cb)(mtev_connection_ctx_t *, reverse_socket_t *, void *), void *closure) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_boolean invoked = mtev_false;
  char remote_str[INET6_ADDRSTRLEN + 1 + 5 + 1];

  snprintf(remote_str, sizeof(remote_str), "%s:%d", address, port);
  pthread_mutex_lock(&reverses_lock);
  while(mtev_hash_adv(&reverses, &iter)) {
    auto ctx = static_cast<mtev_connection_ctx_t*>(iter.value.ptr);
    if(ctx->remote_str && !strcmp(remote_str, ctx->remote_str)) {
      reverse_socket_t *rc = NULL;
      if(ctx->consumer_callback == mtev_reverse_client_handler) {
        rc = static_cast<reverse_socket_t*>(ctx->consumer_ctx);
      }
      cb(ctx, rc, closure);
      invoked = mtev_true;
      break;
    }
  }
  pthread_mutex_unlock(&reverses_lock);
  return invoked;
}

extern "C" int
mtev_lua_help_initiate_mtev_connection(const char *address, int port,
                                       mtev_hash_table *sslconfig,
                                       mtev_hash_table *config) {
  mtevL(nldeb, "%s - initiating to %s\n", __func__, address);
  initiate_mtev_connection(&reverses, &reverses_lock,
                           address, port, sslconfig, config,
                           mtev_reverse_client_handler,
                           mtev_reverse_socket_alloc()->add_ref(),
                           reverse_socket::release_ref_no_return);
  return 0;
}

extern "C" void
mtev_reverse_socket_init_globals(void) {
  mtev_hash_init(&reverse_sockets);
  mtev_hash_init(&reverses);
}
