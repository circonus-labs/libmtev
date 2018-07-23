/*
 * Copyright (c) 2018, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its
 *       contributors may be used to endorse or promote products
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
#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "eventer/eventer_aco_opset.h"
#include "libmtev_dtrace.h"
#include "mtev_stacktrace.h"
#include "aco/aco.h"

#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

typedef struct aco_opset_info_t {
  eventer_func_t       original_callback;
  eventer_fd_opset_t   original_opset;
  void                *original_opset_ctx;

  aco_t               *aco_co;

  struct timeval       accept_timeout;
  struct timeval       read_timeout;
  struct timeval       write_timeout;
  unsigned             has_accept_timeout:1;
  unsigned             has_read_timeout:1;
  unsigned             has_write_timeout:1;
} aco_opset_info_t;

#define WORRISOME_STACK 2048
int
eventer_aco_resume(aco_t *co) {
  aco_resume(co);
  if(co->save_stack.valid_sz > WORRISOME_STACK)
    mtevL(eventer_deb, "aco resume stack copy %zd bytes\n", co->save_stack.valid_sz);
  if(co->is_end) return eventer_aco_shutdown(co);
  return 1;
}

#define TIMEOUT_SETTER(name) \
void \
eventer_aco_set_##name##_timeout(eventer_aco_t e, struct timeval *t) { \
  mtevAssert(e->opset == eventer_aco_fd_opset); \
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx; \
  if(!t) info->has_##name##_timeout = 0; \
  else { \
    memcpy(&info->name##_timeout, t, sizeof(*t)); \
    info->has_##name##_timeout = 1; \
  } \
}
TIMEOUT_SETTER(accept)
TIMEOUT_SETTER(read)
TIMEOUT_SETTER(write)

static int
eventer_aco_callback_wrapper(eventer_t e, int mask, void *closure, struct timeval *tv) {
  mtevAssert(e->opset == eventer_aco_fd_opset);
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  struct aco_cb_ctx *ctx = info->aco_co->arg;
  mtevAssert(pthread_equal(e->thr_owner, pthread_self()));
  if(!eventer_aco_resume(info->aco_co)) return 0;
  return ctx->mask;
}

eventer_aco_t
eventer_set_eventer_aco_co(eventer_t e, aco_t *co) {
  if(co == NULL) {
    mtevAssert(e->opset == eventer_aco_fd_opset);
    aco_opset_info_t *info = e->opset_ctx;
    e->callback = info->original_callback;
    e->opset = info->original_opset;
    e->opset_ctx = info->original_opset_ctx;
    free(info);
    return NULL;
  }
  mtevAssert(e->opset != eventer_aco_fd_opset);
  eventer_ref(e);
  aco_opset_info_t *info = calloc(1, sizeof(*info));
  info->original_callback = e->callback;
  info->original_opset = e->opset;
  info->original_opset_ctx = e->opset_ctx;
  info->aco_co = co;
  e->opset = eventer_aco_fd_opset;
  e->opset_ctx = info;
  e->callback = eventer_aco_callback_wrapper;
  return (eventer_aco_t)e;
}

eventer_aco_t
eventer_set_eventer_aco(eventer_t e) {
  return eventer_set_eventer_aco_co(e, aco_get_co());
}

struct aco_asynch_simple_ctx {
  eventer_asynch_func_t func;
  void *closure;
  aco_t *co;
};

static int
eventer_aco_simple_asynch_wrapper(eventer_t e, int mask, void *closure, struct timeval *now) {
  struct aco_asynch_simple_ctx *simple_ctx = closure;
  if(mask == EVENTER_ASYNCH_WORK) {
    simple_ctx->func(simple_ctx->closure);
  }
  if(mask == EVENTER_ASYNCH) {
    aco_t *co = simple_ctx->co;
    free(simple_ctx);
    eventer_aco_resume(co);
  }
  return 0;
}

void
eventer_aco_simple_asynch_queue_subqueue(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id) {
  struct aco_asynch_simple_ctx *simple_ctx = malloc(sizeof(*simple_ctx));
  simple_ctx->func = func;
  simple_ctx->closure =closure;
  simple_ctx->co = aco_get_co();
  eventer_t e = eventer_alloc_asynch(eventer_aco_simple_asynch_wrapper, simple_ctx);
  eventer_add_asynch_subqueue(q, e, id);
  aco_yield();
}

struct aco_asynch_cb_ctx {
  eventer_t e;
  aco_t *co;
};

static int
eventer_aco_asynch_wrapper(eventer_t e, int mask, void *closure, struct timeval *now) {
  struct aco_asynch_cb_ctx *ctx = closure;
  ctx->e->callback(ctx->e, mask, ctx->e->closure, now);
  if(mask == EVENTER_ASYNCH) {
    aco_t *co = ctx->co;
    free(ctx);
    eventer_aco_resume(co);
  }
  return 0;
}

mtev_boolean
eventer_aco_try_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t sq) {
  struct aco_asynch_cb_ctx *ctx = malloc(sizeof(*ctx));
  ctx->e = e;
  ctx->co = aco_get_co();
  eventer_t ae = eventer_alloc_asynch(eventer_aco_asynch_wrapper, ctx);
  if(eventer_try_add_asynch_subqueue(q, ae, sq)) {
    aco_yield();
    return mtev_true;
  }
  free(ctx);
  return mtev_false;
}

void
eventer_aco_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t sq) {
  struct aco_asynch_cb_ctx *ctx = calloc(1, sizeof(*ctx));
  ctx->e = e;
  ctx->co = aco_get_co();
  eventer_t ae = eventer_alloc_asynch(eventer_aco_asynch_wrapper, ctx);
  eventer_add_asynch_subqueue(q, ae, sq);
  aco_yield();
}

static int
priv_aco_timeout(eventer_t e, int mask, void *closure, struct timeval *now) {
  aco_opset_info_t *info = closure;
  struct aco_cb_ctx *ctx = info->aco_co->arg;
  ctx->timeout_e = NULL;
  ctx->private_errno = ETIME;
  eventer_aco_resume(info->aco_co);
  return 0;
}

void
eventer_aco_sleep(struct timeval *timeout) {
  mtevAssert(aco_get_co());
  struct aco_cb_ctx *ctx = aco_get_arg();
  mtevAssert(!ctx->timeout_e);
  aco_opset_info_t *info = calloc(1, sizeof(*info));
  info->aco_co = aco_get_co();
  ctx->timeout_e = eventer_in(priv_aco_timeout, info, *timeout);
  eventer_add(ctx->timeout_e);
  aco_yield();
  free(info);
}

#define ACO_TIMEOUT_CALL(name, params, args) \
static int \
priv_aco_##name params { \
  eventer_t e = closure; \
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx; \
  struct aco_cb_ctx *ctx = aco_get_arg(); \
  int added = 0; \
\
  mtevAssert(aco_get_co() == info->aco_co); \
  mtevAssert(!ctx->timeout_e); \
  if(!ctx->timeout && info->has_##name##_timeout) ctx->timeout = &info->name##_timeout; \
  if(ctx->timeout) { \
    ctx->timeout_e = eventer_in(priv_aco_timeout, info, *ctx->timeout); \
    ctx->timeout = NULL; \
    eventer_add(ctx->timeout_e); \
  } \
\
  while(1) { \
    if(added) { eventer_remove(e); added = 0; } \
    ctx->rv = info->original_opset->name args; \
    if(ctx->rv == -1 && (errno == EINPROGRESS || errno == EAGAIN)) { \
      e->mask = *mask; \
      ctx->mask = *mask; \
      if(!added) { eventer_add(e); added = 1; } \
      aco_yield(); \
      if(ctx->private_errno == ETIME) { \
        errno = ctx->private_errno; \
        ctx->private_errno = 0; \
        ctx->rv = -1; \
        break; \
      } \
    } \
    else break; \
  } \
  if(ctx->timeout_e) { \
    mtevEvalAssert(eventer_remove(ctx->timeout_e)); \
    eventer_free(ctx->timeout_e); \
    ctx->timeout_e = NULL; \
  } \
  if(added) { \
    mtevEvalAssert(eventer_remove(e)); \
  } \
  return ctx->rv; \
}

ACO_TIMEOUT_CALL(accept,
                 (int fd, struct sockaddr *addr, socklen_t *len, int *mask, void *closure),
                 (fd, addr, len, mask, closure));
ACO_TIMEOUT_CALL(read,
                 (int fd, void *buffer, size_t len, int *mask, void *closure),
                 (fd, buffer, len, mask, closure));
ACO_TIMEOUT_CALL(write,
                 (int fd, const void *buffer, size_t len, int *mask, void *closure),
                 (fd, buffer, len, mask, closure));

static int
priv_aco_close(int fd,
          int *mask, void *closure) {
  eventer_t e = closure;
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  int rv;

  rv = info->original_opset->close(fd, mask, closure);

  return rv;
}

struct _fd_opset *
eventer_aco_get_opset(void *closure) {
  eventer_t e = closure;
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  return info->original_opset;
}

static void
priv_aco_set_opset(void *closure, struct _fd_opset *opset) {
  eventer_t e = closure;
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  info->original_opset = opset;
}

void *
eventer_aco_get_opset_ctx(void *closure) {
  eventer_t e = closure;
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  return info->original_opset_ctx;
}

static void
priv_aco_set_opset_ctx(void *closure, void *newctx) {
  eventer_t e = closure;
  aco_opset_info_t *info = (aco_opset_info_t *)e->opset_ctx;
  info->original_opset_ctx = newctx;
}

struct _fd_opset _eventer_aco_fd_opset = {
  priv_aco_accept,
  priv_aco_read,
  priv_aco_write,
  priv_aco_close,
  priv_aco_set_opset,
  eventer_aco_get_opset_ctx,
  priv_aco_set_opset_ctx,
  "aco"
};

eventer_fd_opset_t eventer_aco_fd_opset = &_eventer_aco_fd_opset;

