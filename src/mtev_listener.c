/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
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
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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

#include "mtev_defines.h"

#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_watchdog.h"
#include "mtev_listener.h"
#include "mtev_conf.h"

#define MAX_TIMEOUT_CHECK_MS 5000

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;
static mtev_hash_table listener_commands;
static mtev_hash_table *aco_listeners;

struct mtev_acceptor_closure_t {
  union {
    struct sockaddr remote_addr;
    struct sockaddr_in remote_addr4;
    struct sockaddr_in6 remote_addr6;
  } remote;
  char *remote_cn;
  mtev_hash_table *config;
  void *service_ctx;
  eventer_func_t dispatch;
  uint32_t cmd;
  int rlen;
  void (*service_ctx_free)(void *);
  struct timeval last_read;
  struct timeval last_write;
  uint64_t timeout_ms;
  eventer_t timeout;
  int fd;
};

static int
mtev_acceptor_timeout(eventer_t e, int mask, void *closure, struct timeval *tv) {
  (void)mask;
  (void)e;
  mtev_acceptor_closure_t *ac = (mtev_acceptor_closure_t *)closure;
  if(ac->fd >= 0) {
    eventer_t fde = eventer_find_fd(ac->fd);
    if(fde) {
      struct timeval age = { .tv_sec = 0, .tv_usec = 0 };
      mtev_acceptor_closure_readwrite_age(ac, tv, &age);
      if(age.tv_sec * 1000UL + age.tv_usec / 1000UL > ac->timeout_ms) {
        ac->timeout = NULL;
        mtevL(nldeb, "mtev_listener timed out %fs old connection\n",
              age.tv_sec + (double)age.tv_usec/1000000.0);
        eventer_trigger(fde, EVENTER_EXCEPTION);
        return 0;
      }
    }
    else {
      mtevL(nldeb, "skipping timeout enforcement on floated event\n");
    }
  }
  struct timeval tgt, diff;
  uint64_t limited_ms = ac->timeout_ms > MAX_TIMEOUT_CHECK_MS ? MAX_TIMEOUT_CHECK_MS : ac->timeout_ms;
  diff.tv_sec = limited_ms / 1000;
  diff.tv_usec = (limited_ms % 1000) * 1000;
  memcpy(&tgt, tv, sizeof(*tv));
  add_timeval(tgt, diff, &tgt);
  ac->timeout = eventer_add_at(mtev_acceptor_timeout, ac, tgt);
  return 0;
}

void
mtev_acceptor_closure_mark_read(mtev_acceptor_closure_t *ac, struct timeval *now) {
  if(now) memcpy(&ac->last_read, now, sizeof(*now));
  else mtev_gettimeofday(&ac->last_read, NULL);
}
void
mtev_acceptor_closure_mark_write(mtev_acceptor_closure_t *ac, struct timeval *now) {
  if(now) memcpy(&ac->last_write, now, sizeof(*now));
  else mtev_gettimeofday(&ac->last_write, NULL);
}
void
mtev_acceptor_closure_readwrite_age(mtev_acceptor_closure_t *ac, struct timeval *now, struct timeval *diff) {
  struct timeval _now;
  if(now == NULL) {
    mtev_gettimeofday(&_now, NULL);
    now = &_now;
  }
  struct timeval d1;
  sub_timeval(*now, ac->last_read, diff);
  sub_timeval(*now, ac->last_read, &d1);
  if(compare_timeval(*diff, d1) > 0) memcpy(diff, &d1, sizeof(d1));
}
struct sockaddr *
mtev_acceptor_closure_remote(mtev_acceptor_closure_t *ac) {
  return &ac->remote.remote_addr;
}
const char *
mtev_acceptor_closure_remote_cn(mtev_acceptor_closure_t *ac) {
  return ac->remote_cn;
}
void *
mtev_acceptor_closure_ctx(mtev_acceptor_closure_t *ac) {
  return ac->service_ctx;
}
void (*mtev_acceptor_closure_ctx_free_func(mtev_acceptor_closure_t *ac))(void*) {
  return ac->service_ctx_free;
}
void
mtev_acceptor_closure_ctx_free(mtev_acceptor_closure_t *ac) {
  if(ac->service_ctx_free)
    ac->service_ctx_free(ac->service_ctx);
  ac->service_ctx_free = NULL;
  ac->service_ctx = NULL;
  return;
}
eventer_func_t
mtev_acceptor_closure_dispatch(mtev_acceptor_closure_t *ac) {
  return ac->dispatch;
}
mtev_hash_table *
mtev_acceptor_closure_config(mtev_acceptor_closure_t *ac) {
  return ac->config;
}
void
mtev_acceptor_closure_set_ctx(mtev_acceptor_closure_t *ac,
                              void *ctx, void (*freefunc)(void *)) {
  ac->service_ctx = ctx;
  ac->service_ctx_free = freefunc;
}
uint32_t
mtev_acceptor_closure_cmd(mtev_acceptor_closure_t *ac) {
  return ac->cmd;
}

typedef struct {
  int8_t family;
  unsigned short port;
  mtev_boolean fanout;
  eventer_pool_t *pool;
  mtev_boolean in_own_thread;
  eventer_func_t dispatch_callback;
  mtev_acceptor_closure_t *dispatch_closure;
  mtev_hash_table *sslconfig;
} * listener_closure_t;

mtev_hash_table *
mtev_listener_commands(void) {
  return &listener_commands;
}

void
mtev_acceptor_closure_free(mtev_acceptor_closure_t *ac) {
  if (ac) {
    if(ac->remote_cn) free(ac->remote_cn);
    if(ac->service_ctx_free && ac->service_ctx)
      ac->service_ctx_free(ac->service_ctx);
    if(ac->timeout) {
      eventer_remove(ac->timeout);
      eventer_free(ac->timeout);
    }
    free(ac);
  }
}

static struct avoid_listener {
  char *address;
  int port;
  struct avoid_listener *next;
} *listener_avoid_list;
void
mtev_listener_skip(const char *address, int port) {
  struct avoid_listener *al;
  al = calloc(1, sizeof(*al));
  al->address = address ? strdup(address) : NULL;
  al->port = port;
  al->next = listener_avoid_list;
  listener_avoid_list = al;
}
static mtev_boolean
mtev_listener_should_skip(const char *address, int port) {
  struct avoid_listener *al;
  for(al = listener_avoid_list; al; al = al->next)
    if(al->port == port &&
       (al->address == NULL || !strcmp(address, al->address)))
      return mtev_true;
  return mtev_false;
}

static int
mtev_listener_accept_ssl(eventer_t e, int mask,
                         void *closure, struct timeval *tv) {
  const char *sslerr = "no closure";
  int rv;
  listener_closure_t listener_closure = (listener_closure_t)closure;
  mtev_acceptor_closure_t *ac = NULL;
  if(!closure) {
    mtevL(mtev_error, "SSL accept failed: no closure\n");
    goto socketfail;
  }
  ac = listener_closure->dispatch_closure;

  rv = eventer_SSL_accept(e, &mask);
  if(rv > 0) {
    eventer_ssl_ctx_t *sslctx;
    eventer_set_callback(e, listener_closure->dispatch_callback);
    mtev_acceptor_closure_mark_read(ac, tv);
    /* We must make a copy of the mtev_acceptor_closure_t for each new
     * connection.
     */
    if((sslctx = eventer_get_eventer_ssl_ctx(e)) != NULL) {
      const char *cn, *end;
      cn = eventer_ssl_get_peer_subject(sslctx);
      if(cn && (cn = strstr(cn, "CN=")) != NULL) {
        cn += 3;
        end = cn;
        while(*end && *end != '/') end++;
        ac->remote_cn = malloc(end - cn + 1);
        memcpy(ac->remote_cn, cn, end - cn);
        ac->remote_cn[end-cn] = '\0';
      }
    }
    eventer_set_closure(e, ac); 
    mtevL(nldeb, "mtev_listener[%s] SSL_accept on fd %d [%s]\n",
          eventer_name_for_callback_e(eventer_get_callback(e), e),
          eventer_get_fd(e), ac->remote_cn ? ac->remote_cn : "anonymous");
    if(listener_closure) free(listener_closure);
    return eventer_callback(e, mask, eventer_get_closure(e), tv);
  }
  if(errno == EAGAIN) return mask|EVENTER_EXCEPTION;

  sslerr = eventer_ssl_get_peer_error(eventer_get_eventer_ssl_ctx(e));
  if(!sslerr) sslerr = eventer_ssl_get_last_error(eventer_get_eventer_ssl_ctx(e));
  if(!sslerr && errno) sslerr = strerror(errno);

  char ip[INET6_ADDRSTRLEN] = "unknown";
  switch(ac->remote.remote_addr.sa_family) {
    case AF_INET:
     (void)inet_ntop(AF_INET, &ac->remote.remote_addr4.sin_addr, ip, sizeof(ip));
     break;
     case AF_INET6:
     (void)inet_ntop(AF_INET6, &ac->remote.remote_addr6.sin6_addr, ip, sizeof(ip));
     break;
     default: break;
  }
  if(!sslerr) {
    mtevL(mtev_debug, "SSL accept failed from %s: connection closed\n", ip);
  } else {
    mtevL(mtev_error, "SSL accept failed from %s: %s\n", ip, sslerr);
  }

 socketfail:
    
  if(listener_closure) free(listener_closure);
  if(ac) mtev_acceptor_closure_free(ac);
  eventer_remove_fde(e);
  eventer_close(e, &mask);
  return 0;
}

static void
mtev_listener_details(char *buf, int buflen, eventer_t e, void *closure) {
  (void)closure;
  char sbuf[128];
  const char *sbufptr;
  eventer_t stub;
  listener_closure_t listener_closure = eventer_get_closure(e);

  stub = eventer_alloc();
  eventer_set_callback(stub, listener_closure->dispatch_callback);
  eventer_set_closure(stub, listener_closure->dispatch_closure);
  sbufptr = eventer_name_for_callback_e(listener_closure->dispatch_callback, stub);
  eventer_free(stub);
  strlcpy(sbuf, sbufptr, sizeof(sbuf));
  snprintf(buf, buflen, "listener(%s)", sbuf);
}

static int
mtev_listener_acceptor(eventer_t e, int mask,
                       void *closure, struct timeval *tv) {
  (void)tv;
  int conn, newmask = EVENTER_READ;
  socklen_t salen;
  listener_closure_t listener_closure = (listener_closure_t)closure;
  mtev_acceptor_closure_t *ac = NULL;

  /* This might not be set, so set it */
  if(listener_closure->fanout && !listener_closure->pool)
    listener_closure->pool = eventer_get_pool_for_event(e);

  if(mask & EVENTER_EXCEPTION) {
 socketfail:
    if(ac) mtev_acceptor_closure_free(ac);
    /* We don't shut down the socket, it's our listener! */
    return EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
  }

  do {
    ac = malloc(sizeof(*ac));
    memcpy(ac, listener_closure->dispatch_closure, sizeof(*ac));
    salen = sizeof(ac->remote);
    ac->fd = conn = eventer_accept(e, &ac->remote.remote_addr, &salen, &newmask);
    if(conn >= 0) {
      eventer_t newe;
      int nodelay = 1;
      const char *no_delay_str = mtev_hash_dict_get(ac->config, "no_delay");
      if(no_delay_str && (!strcasecmp(no_delay_str, "false") || !strcasecmp(no_delay_str, "off"))) {
        nodelay = 0;
      }
      if(nodelay) {
#ifdef TCP_NODELAY
#ifdef SOL_TCP
        int proto_n = SOL_TCP;
#else
        struct protoent proto_buf, *proto;
        char buff[1024];
        int proto_n = -1;
#ifdef __sun__
        if(NULL != (proto = getprotobyname_r("tcp", &proto_buf, buff, sizeof(buff)))) {
          proto_n = proto->p_proto;
        }
#else
        if(getprotobyname_r("tcp", &proto_buf, buff, sizeof(buff), &proto) == 0) {
          proto_n = proto->p_proto;
        }
#endif
#endif
        if(proto_n < 0) {
          mtevEL(nldeb, MLKV{ MLKV_INT64("errno", errno), MLKV_END }, "getprotobyname_r(\"tcp\") failed: %s\n",
                 strerror(errno));
        } else {
          if(setsockopt(conn, proto_n, TCP_NODELAY, (void *)&nodelay, sizeof(nodelay)) < 0) {
            mtevEL(nldeb, MLKV{ MLKV_INT64("errno", errno), MLKV_END }, "setsockopt TCP_NODELAY failed: %s\n",
                   strerror(errno));
          }
        }
#else
        mtevL(nldeb, "TCP_NODELAY not supported on this system\n");
#endif
      }
      mtev_acceptor_closure_mark_read(ac, tv);
      mtevL(nldeb, "mtev_listener[%s] accepted fd %d on %s\n",
            eventer_name_for_callback(listener_closure->dispatch_callback),
            conn, eventer_get_thread_name());
      if(eventer_set_fd_nonblocking(conn)) {
        close(conn);
        free(ac);
        goto accept_bail;
      }
      const char *idle_timeout_str = mtev_hash_dict_get(ac->config, "idle_timeout");
      if(idle_timeout_str) {
        ac->timeout_ms = strtoull(idle_timeout_str, NULL, 10);
        if(ac->timeout_ms) {
          uint64_t limited_ms = ac->timeout_ms > MAX_TIMEOUT_CHECK_MS ? MAX_TIMEOUT_CHECK_MS : ac->timeout_ms;
          ac->timeout = eventer_in_s_us(mtev_acceptor_timeout, ac,
                                        limited_ms / 1000, (limited_ms % 1000) * 1000);
          eventer_add(ac->timeout);
        }
      }
      if(mtev_hash_size(listener_closure->sslconfig)) {
        const char *layer, *cert, *key, *ca, *ciphers, *crl, *npn;
        eventer_ssl_ctx_t *ctx;
        /* We have an SSL configuration.  While our socket accept is
         * complete, we now have to SSL_accept, which could require
         * several reads and writes and needs its own event callback.
         */
  #define SSLCONFGET(var,name) do { \
    if(!mtev_hash_retr_str(listener_closure->sslconfig, name, strlen(name), \
                           &var)) var = NULL; } while(0)
        SSLCONFGET(layer, "layer");
        SSLCONFGET(cert, "certificate_file");
        SSLCONFGET(key, "key_file");
        SSLCONFGET(ca, "ca_chain");
        SSLCONFGET(ciphers, "ciphers");
        SSLCONFGET(npn, "npn");
        if(!npn) npn="h2";
        ctx = eventer_ssl_ctx_new(SSL_SERVER, layer, cert, key, ca, ciphers);
        if(!ctx) {
          mtevL(mtev_error, "Failed to create SSL context.\n");
          close(conn);
          goto socketfail;
        }
        SSLCONFGET(crl, "crl");
        if(crl) {
          if(!eventer_ssl_use_crl(ctx, crl)) {
            mtevL(mtev_error, "Failed to load CRL from %s\n", crl);
            eventer_ssl_ctx_free(ctx);
            close(conn);
            goto socketfail;
          }
        }
        if(npn && strcasecmp(npn, "none")) {
          eventer_ssl_alpn_advertise(ctx, npn);
        }

        listener_closure_t lc = malloc(sizeof(*listener_closure));
        memcpy(lc, listener_closure, sizeof(*listener_closure));
        lc->dispatch_closure = ac;
        newe = eventer_alloc_fd(mtev_listener_accept_ssl, lc, conn,
                                EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION);

        eventer_ssl_ctx_set_verify(ctx, eventer_ssl_verify_cert,
                                   listener_closure->sslconfig);
        EVENTER_ATTACH_SSL(newe, ctx);
      }
      else {
        newe = eventer_alloc_fd(listener_closure->dispatch_callback, ac, conn,
                                EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION);
      }

      if(!listener_closure->pool) eventer_set_owner(newe, eventer_get_owner(e));
      else {
        eventer_set_owner(newe, eventer_choose_owner_pool(listener_closure->pool, eventer_get_fd(newe)+1));
      }
      eventer_add(newe);
    }
    else {
      if(errno == EAGAIN) {
        if(ac) mtev_acceptor_closure_free(ac);
      }
      else if(errno != EINTR) {
        mtevL(mtev_error, "accept socket error: %s\n", strerror(errno));
        goto socketfail;
      }
    }
  } while(conn >= 0);
 accept_bail:
  return newmask | EVENTER_EXCEPTION;
}

int
mtev_listener(char *host, unsigned short port, int type,
              int backlog, mtev_boolean fanout,
              eventer_pool_t *pool,
              mtev_boolean in_own_thread,
              mtev_hash_table *sslconfig,
              mtev_hash_table *config,
              eventer_func_t handler, void *service_ctx) {
  int rv, fd;
  int8_t family;
  int sockaddr_len;
  socklen_t reuse;
  listener_closure_t listener_closure;
  eventer_t event;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } a;
  union {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr_un addru;
  } s;
  const char *event_name;

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
        if(!strcmp(host, "*") || !strcmp(host, "inet:*")) {
          family = AF_INET;
          a.addr4.s_addr = INADDR_ANY;
        } else if(!strcmp(host, "inet6:*")) {
          family = AF_INET6;
          memset(&a.addr6,0,sizeof(a.addr6));
        } else {
          mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> bad address\n",
                host, port, type, backlog,
                (event_name = eventer_name_for_callback(handler))?event_name:"??",
                service_ctx);
          return -1;
        }
      }
    }
  }

  fd = socket(family, NE_SOCK_CLOEXEC|type, 0);
  if(fd < 0) {
    mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> socket: %s\n",
          host, port, type, backlog,
          (event_name = eventer_name_for_callback(handler))?event_name:"??",
          service_ctx, strerror(errno));
    return -1;
  }

  if(eventer_set_fd_nonblocking(fd)) {
    close(fd);
    mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> nonblock: %s\n",
          host, port, type, backlog,
          (event_name = eventer_name_for_callback(handler))?event_name:"??",
          service_ctx, strerror(errno));
    return -1;
  }

  reuse = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 (void*)&reuse, sizeof(reuse)) != 0) {
    close(fd);
    mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> SO_REUSEADDR: %s\n",
          host, port, type, backlog,
          (event_name = eventer_name_for_callback(handler))?event_name:"??",
          service_ctx, strerror(errno));
    return -1;
  }

  memset(&s, 0, sizeof(s));
  if(family == AF_UNIX) {
    struct stat sb;
    /* unlink the path if it is a socket */
    /* coverity[fs_check_call] */
    if(stat(host, &sb) == -1) {
      if(errno != ENOENT) {
        mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> stat: %s\n",
              host, port, type, backlog,
              (event_name = eventer_name_for_callback(handler))?event_name:"??",
              service_ctx, strerror(errno));
        close(fd);
        return -1;
      }
    }
    else {
      if(sb.st_mode & S_IFSOCK) {
        /* coverity[toctou] */
        unlink(host);
      }
      else {
        mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> unlink: %s\n",
              host, port, type, backlog,
              (event_name = eventer_name_for_callback(handler))?event_name:"??",
              service_ctx, strerror(errno));
        close(fd);
        return -1;
      }
    }
    s.addru.sun_family = AF_UNIX;
    strncpy(s.addru.sun_path, host, sizeof(s.addru.sun_path)-1);
    sockaddr_len = sizeof(s.addru);
  }
  else {
    if(family == AF_INET6) {
      s.addr6.sin6_family = family;
      s.addr6.sin6_port = htons(port);
      memcpy(&s.addr6.sin6_addr, &a.addr6, sizeof(a.addr6));
    }
    else {
      s.addr4.sin_family = family;
      s.addr4.sin_port = htons(port);
      memcpy(&s.addr4.sin_addr, &a.addr4, sizeof(a.addr4));
    }
    sockaddr_len = (family == AF_INET) ?  sizeof(s.addr4) : sizeof(s.addr6);
  }
  if(bind(fd, (struct sockaddr *)&s, sockaddr_len) < 0) {
    mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> bind: %s\n",
          host, port, type, backlog,
          (event_name = eventer_name_for_callback(handler))?event_name:"??",
          service_ctx, strerror(errno));
    close(fd);
    return -1;
  }

  if(type == SOCK_STREAM) {
    if(listen(fd, backlog) < 0) {
      mtevL(mtev_error, "mtev_listener(%s, %d, %d, %d, %s, %p) -> listen: %s\n",
            host, port, type, backlog,
            (event_name = eventer_name_for_callback(handler))?event_name:"??",
            service_ctx, strerror(errno));
      close(fd);
      return -1;
    }
  }
  mtev_watchdog_on_crash_close_add_fd(fd);

  listener_closure = calloc(1, sizeof(*listener_closure));
  listener_closure->family = family;
  listener_closure->port = htons(port);
  listener_closure->fanout = fanout;
  listener_closure->pool = pool;
  listener_closure->in_own_thread = in_own_thread;
  listener_closure->sslconfig = calloc(1, sizeof(mtev_hash_table));
  mtev_hash_init(listener_closure->sslconfig);
  mtev_hash_merge_as_dict(listener_closure->sslconfig, sslconfig);
  listener_closure->dispatch_callback = handler;

  listener_closure->dispatch_closure =
    calloc(1, sizeof(*listener_closure->dispatch_closure));
  listener_closure->dispatch_closure->config = config;
  listener_closure->dispatch_closure->dispatch = handler;
  listener_closure->dispatch_closure->service_ctx = service_ctx;


  event = eventer_alloc_fd(mtev_listener_acceptor, listener_closure, fd,
                           EVENTER_READ | EVENTER_EXCEPTION);

  if(in_own_thread) {
    eventer_run_in_thread(event, EVENTER_READ);
  }
  else {
    eventer_add(event);
  }
  mtevL(nldeb, "mtev_listener(%s, %d, %d, %d, %s, %p) -> success\n",
        host, port, type, backlog,
        (event_name = eventer_name_for_callback(handler))?event_name:"??",
        service_ctx);
  return 0;
}

static void
post_aco_wrap_dispatch(void) {
  eventer_t e = eventer_aco_arg();
  eventer_aco_t aco_e = eventer_set_eventer_aco(e);
  /* We're done with our service_ctx hi-jacking, pull it and zero it */
  mtev_acceptor_closure_t *ac = eventer_aco_get_closure(aco_e);
  void (*f)(void) = mtev_acceptor_closure_ctx(ac);
  mtev_acceptor_closure_set_ctx(ac, NULL, NULL);
  f();
  aco_exit();
}
static int
pre_aco_wrap_dispatch(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)mask;
  (void)closure;
  (void)now;
  eventer_remove_fde(e);
  eventer_aco_start(post_aco_wrap_dispatch, eventer_alloc_copy(e));
  return 0;
}

void
mtev_listener_reconfig(const char *toplevel) {
  int i, cnt = 0;
  mtev_conf_section_t *listener_configs;
  char path[256];

  snprintf(path, sizeof(path), "/%s/listeners//listener|/%s/include/listeners//listener",
           toplevel ? toplevel : "*", toplevel ? toplevel : "*");
  listener_configs = mtev_conf_get_sections(MTEV_CONF_ROOT, path, &cnt);
  mtevL(mtev_debug, "Found %d %s stanzas\n", cnt, path);
  for(i=0; i<cnt; i++) {
    char address[256];
    char type[256];
    unsigned short port;
    int32_t portint;
    int32_t backlog;
    eventer_func_t f;
    mtev_boolean ssl, fanout = mtev_false, in_own_thread = mtev_false;
    eventer_pool_t *pool = NULL;
    char poolname[256];
    mtev_hash_table *sslconfig, *config;
    void *service_ctx = NULL;

    if(!mtev_conf_get_stringbuf(listener_configs[i],
                                "ancestor-or-self::node()/@type",
                                type, sizeof(type))) {
      mtevL(mtev_error, "No type specified in listener stanza %d\n", i+1);
      continue;
    }
    f = eventer_callback_for_name(type);
    if(!f) {
      /* If we have an aco method, we hi-jack the service_ctx to be the function
       * because we need to run a wrapper dispatch function that is an eventer_func_t
       */
      if(mtev_hash_retrieve(aco_listeners, type, strlen(type), &service_ctx))
        f = pre_aco_wrap_dispatch;
    }
    if(!f) {
      mtevL(mtev_error,
            "Cannot find handler for listener type: '%s'\n", type);
      continue;
    }
    if(!mtev_conf_get_stringbuf(listener_configs[i],
                                "ancestor-or-self::node()/@address",
                                address, sizeof(address))) {
      address[0] = '*';
      address[1] = '\0';
    }
    if(!mtev_conf_get_int32(listener_configs[i],
                            "ancestor-or-self::node()/@port", &portint))
      portint = 0;
    port = (unsigned short) portint;
    if(address[0] != '/' && (portint == 0 || (port != portint))) {
      /* UNIX sockets don't require a port (they'll ignore it if specified */
      mtevL(mtev_error,
            "Invalid port [%d] specified in stanza %d\n", port, i+1);
      continue;
    }
    if(mtev_conf_env_off(listener_configs[i], NULL)) {
      if(port)
        mtevL(mtev_debug, "listener %s:%d environmentally disabled.\n", address, port);
      else
        mtevL(mtev_debug, "listener %s environmentally disabled.\n", address);
      continue;
    }
    if(mtev_listener_should_skip(address, port)) {
      if(port)
        mtevL(mtev_error, "Operator forced skipping listener %s:%d\n", address, port);
      else
        mtevL(mtev_error, "Operator forced skipping listener %s\n", address);
      continue;
    }
    if(!mtev_conf_get_int32(listener_configs[i],
                            "ancestor-or-self::node()/@backlog", &backlog))
      backlog = 5;

    if(!mtev_conf_get_boolean(listener_configs[i],
                          "ancestor-or-self::node()/@fanout", &fanout))
      fanout = mtev_false;

    if(mtev_conf_get_stringbuf(listener_configs[i],
                               "ancestor-or-self::node()/@fanout_pool",
                               poolname, sizeof(poolname))) {
      pool = eventer_pool(poolname);
      if(port)
        mtevL(nlerr, "pool '%s' requested for listener %s:%d\n", poolname, address, port);
      else
        mtevL(nlerr, "pool '%s' requested for listener %s\n", poolname, address);
    }

    if(!mtev_conf_get_boolean(listener_configs[i],
                              "ancestor-or-self::node()/@accept_thread", &in_own_thread))
      in_own_thread = mtev_false;

    if(!mtev_conf_get_boolean(listener_configs[i],
                              "ancestor-or-self::node()/@ssl", &ssl))
     ssl = mtev_false;

    sslconfig = ssl ?
                  mtev_conf_get_hash(listener_configs[i], "sslconfig") :
                  NULL;
    config = mtev_conf_get_hash(listener_configs[i], "config");

    if(mtev_listener(address, port, SOCK_STREAM, backlog,
                     fanout, pool, in_own_thread,
                     sslconfig, config, f, service_ctx) != 0) {
      mtev_hash_destroy(config,free,free);
      free(config);
    }
    if(sslconfig) {
      /* A copy of this is made within mtev_listener */
      mtev_hash_destroy(sslconfig,free,free);
      free(sslconfig);
    }
  }
  mtev_conf_release_sections(listener_configs, cnt);
}
mtev_boolean
mtev_listener_apply_alpn(eventer_t e, int *mask, void *closure,
                         struct timeval *now) {
  eventer_ssl_ctx_t *sslctx;
  if((sslctx = eventer_get_eventer_ssl_ctx(e)) == NULL) return 0;
  const uint8_t *alpn = NULL;
  uint8_t alpnlen = 0;
  eventer_ssl_get_alpn_selected(sslctx, &alpn, &alpnlen);
  if(alpnlen && alpn) {
    const char *name = eventer_name_for_callback(eventer_get_callback(e));
    char buff[128];
    snprintf(buff, sizeof(buff), "%s/alpn:%.*s", name, (int)alpnlen, alpn);
    eventer_func_t alpn_f = eventer_callback_for_name(buff);
    if(alpn_f == NULL) {
      mtevL(mtev_debug, "No registered callback for '%s'\n", buff);
      return mtev_false;
    }
    mtevL(mtev_debug, "Upgrading %s -> %s\n", name, buff);
    eventer_set_callback(e, alpn_f);
    *mask = alpn_f(e, *mask, closure, now);
    return mtev_true;
  }
  return mtev_false;
}

int
mtev_listener_http2(eventer_t e, int mask, void *closure,
                    struct timeval *now) {
  (void)mask;
  (void)closure;
  (void)now;
  eventer_close(e, &mask);
  return 0;
}
int
mtev_control_dispatch(eventer_t e, int mask, void *closure,
                      struct timeval *now) {
  uint32_t cmd;
  int len = 0, callmask = mask;
  void *vdelegation_table;
  mtev_hash_table *delegation_table = NULL;
  mtev_acceptor_closure_t *ac = closure;

  if(mask & EVENTER_EXCEPTION) goto socket_error;

  int alpn_mask = mask;
  if(mtev_listener_apply_alpn(e, &alpn_mask, closure, now)) {
    return alpn_mask;
  }

  mtevAssert(ac->rlen >= 0);
  while(ac->rlen < (int)sizeof(cmd)) {
    len = eventer_read(e, ((char *)&cmd) + ac->rlen,
                       sizeof(cmd) - ac->rlen, &mask);
    if(len == -1 && errno == EAGAIN)
      return EVENTER_READ | EVENTER_EXCEPTION;

    if(len > 0) {
      mtev_acceptor_closure_mark_read(ac, now);
      ac->rlen += len;
    }
    if(len <= 0) break;
  }
  mtevAssert(ac->rlen >= 0 && ac->rlen <= (int)sizeof(cmd));

  if(callmask & EVENTER_EXCEPTION || ac->rlen != sizeof(cmd)) {
    int newmask;
socket_error:
    /* Exceptions cause us to simply snip the connection */
    eventer_remove_fde(e);
    eventer_close(e, &newmask);
    mtev_acceptor_closure_free(ac);
    return 0;
  }

  ac->cmd = ntohl(cmd);
  /* Lookup cmd and dispatch */
  if(mtev_hash_retrieve(&listener_commands,
                        (char *)&ac->dispatch, sizeof(ac->dispatch),
                        (void **)&vdelegation_table)) {
    void *vfunc;
    delegation_table = (mtev_hash_table *)vdelegation_table;
    if(mtev_hash_retrieve(delegation_table,
                          (char *)&ac->cmd, sizeof(ac->cmd), &vfunc)) {
      eventer_set_callback(e, *((eventer_func_t *)vfunc));
      return eventer_callback(e, callmask, closure, now);
    }
    else {
    const char *event_name;
      mtevL(mtev_error, "listener (%s %p) has no command: 0x%08x\n",
            (event_name = eventer_name_for_callback(ac->dispatch))?event_name:"???",
            delegation_table, cmd);
    }
  }
  else {
    const char *event_name;
    mtevL(mtev_error, "No delegation table for listener (%s %p)\n",
          (event_name = eventer_name_for_callback(ac->dispatch))?event_name:"???",
          delegation_table);
  }
  goto socket_error;
}
void
mtev_control_dispatch_delegate(eventer_func_t listener_dispatch,
                               uint32_t cmd,
                               eventer_func_t delegate_dispatch) {
  uint32_t *cmd_copy;
  eventer_func_t *handler_copy;
  void *vdelegation_table;
  mtev_hash_table *delegation_table;
  if(!mtev_hash_retrieve(&listener_commands,
                         (char *)&listener_dispatch, sizeof(listener_dispatch),
                         &vdelegation_table)) {
    delegation_table = calloc(1, sizeof(*delegation_table));
    mtev_hash_init_locks(delegation_table, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
    handler_copy = malloc(sizeof(*handler_copy));
    *handler_copy = listener_dispatch;
    mtev_hash_store(&listener_commands,
                    (char *)handler_copy, sizeof(*handler_copy),
                    delegation_table);
  }
  else
    delegation_table = (mtev_hash_table *)vdelegation_table;

  cmd_copy = malloc(sizeof(*cmd_copy));
  *cmd_copy = cmd;
  handler_copy = malloc(sizeof(*handler_copy));
  *handler_copy = delegate_dispatch;
  mtev_hash_replace(delegation_table,
                    (char *)cmd_copy, sizeof(*cmd_copy),
                    handler_copy,
                    free, free);
}

int
mtev_convert_sockaddr_to_buff(char *buff, int blen, struct sockaddr *remote) {
  char name[128] = "";
  buff[0] = '\0';
  if(remote) {
    int len = 0;
    switch(remote->sa_family) {
      case AF_INET:
        len = sizeof(struct sockaddr_in);
        inet_ntop(remote->sa_family, &((struct sockaddr_in *)remote)->sin_addr,
                  name, len);
        break;
      case AF_INET6:
       len = sizeof(struct sockaddr_in6);
        inet_ntop(remote->sa_family, &((struct sockaddr_in6 *)remote)->sin6_addr,
                  name, len);
       break;
      case AF_UNIX:
        snprintf(name, sizeof(name), "%s", ((struct sockaddr_un *)remote)->sun_path);
        break;
      default: return 0;
    }
  }
  strlcpy(buff, name, blen);
  return strlen(buff);
}

void
mtev_listener_init(const char *toplevel) {
  nlerr = mtev_log_stream_find("error/listener");
  nldeb = mtev_log_stream_find("debug/listener");
  if(!nlerr) nlerr = mtev_error;
  if(!nldeb) nldeb = mtev_debug;
  eventer_name_callback_ext("mtev_listener_acceptor", mtev_listener_acceptor,
                            mtev_listener_details, NULL);
  eventer_name_callback("mtev_listener_accept_ssl", mtev_listener_accept_ssl);
  eventer_name_callback("control_dispatch", mtev_control_dispatch);
  mtev_listener_reconfig(toplevel);
}

void
mtev_listener_register_aco_function(const char *name, void(*func)(void)) {
  if(!aco_listeners) {
    aco_listeners = calloc(1, sizeof(*aco_listeners));
    mtev_hash_init_locks(aco_listeners, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  }
  mtev_hash_store(aco_listeners, strdup(name), strlen(name), func);
}

void
mtev_listener_init_globals(void) {
  mtev_hash_init_locks(&listener_commands, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
}

