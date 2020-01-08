/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015-2017, Circonus, Inc. All rights reserved.
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

#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "mtev_rand.h"
#include "mtev_hash.h"
#include "mtev_stats.h"
#include "mtev_memory.h"
#include "mtev_task.h"
#include "mtev_stacktrace.h"
#define XXH_PRIVATE_API 
#include "xxhash.h"
#undef XXH_PRIVATE_API
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

stats_ns_t *eventer_stats_ns;
stats_handle_t *eventer_callback_latency_orphaned;
stats_handle_t *eventer_unnamed_callback_latency;
static uint64_t ealloccnt;
static uint64_t ealloctotal;

struct callback_details {
  eventer_func_t fptr;
  char *simple_name;
  void (*functional_name)(char *buf, int buflen, eventer_t e, void *closure);
  stats_handle_t *latency;
  void *closure;
};

static unsigned long __ck_hash_from_fname(const void *key, unsigned long seed) {
  const char *n = ((struct callback_details *)key)->simple_name;
  return XXH64(n, strlen(n), seed);
}
static bool __ck_hash_compare_fname(const void *a, const void *b) {
  return 0 == strcmp(((struct callback_details *)a)->simple_name,
                     ((struct callback_details *)b)->simple_name);
}
static unsigned long __ck_hash_from_fptr(const void *key, unsigned long seed) {
  return (uintptr_t )((struct callback_details *)key)->fptr ^ seed;
}
static bool __ck_hash_compare_fptr(const void *a, const void *b) {
  return ((struct callback_details *)a)->fptr ==
         ((struct callback_details *)b)->fptr;
}
static void * gen_malloc(size_t r) { return malloc(r); }

static void gen_free(void *p, size_t b, bool r) {
  (void)b; (void)r; free(p); return;
}
static struct ck_malloc malloc_ck_hs = {
  .malloc = gen_malloc,
  .free = gen_free
};

static struct {
  char *name;
  eventer_context_opset_t *opset;
} eventer_contexts[MAX_EVENT_CTXS];
static int eventer_contexts_cnt = 0;

void eventer_callback_prep(eventer_t e, int m, void *c, struct timeval *n) {
  for(int i=0; i<eventer_contexts_cnt; i++) {
    if(eventer_contexts[i].opset->eventer_t_callback_prep) {
      eventer_contexts[i].opset->eventer_t_callback_prep(e,m,c,n);
    }
  }
}

void eventer_callback_cleanup(eventer_t e, int m) {
  for(int i=0; i<eventer_contexts_cnt; i++) {
    if(eventer_contexts[i].opset->eventer_t_callback_cleanup) {
      eventer_contexts[i].opset->eventer_t_callback_cleanup(e,m);
    }
  }
}

int eventer_register_context(const char *name, eventer_context_opset_t *o) {
  if(eventer_contexts_cnt >= MAX_EVENT_CTXS) return -1;
  int idx = eventer_contexts_cnt++;
  eventer_contexts[idx].name = strdup(name);
  eventer_contexts[idx].opset = o;
  return idx;
}
void *eventer_get_context(eventer_t e, int idx) {
  if(!e) return NULL;
  if(idx < 0 || idx >= eventer_contexts_cnt) return NULL;
  return e->ctx[idx].data;
}

void *eventer_set_context(eventer_t e, int idx, void *data) {
  if(idx < 0 || idx >= eventer_contexts_cnt) return NULL;
  void *old = e->ctx[idx].data;
  e->ctx[idx].data = data;
  return old;
}

eventer_fd_accept_t eventer_fd_opset_get_accept(eventer_fd_opset_t opset) {
  return opset->accept;
}
eventer_fd_read_t eventer_fd_opset_get_read(eventer_fd_opset_t opset) {
  return opset->read;
}
eventer_fd_write_t eventer_fd_opset_get_write(eventer_fd_opset_t opset) {
  return opset->write;
}
eventer_fd_close_t eventer_fd_opset_get_close(eventer_fd_opset_t opset) {
  return opset->close;
}

eventer_t eventer_alloc(void) {
  eventer_t e;
  e = calloc(1, sizeof(*e));
  e->thr_owner = eventer_in_loop() ? pthread_self() : eventer_choose_owner(0);
  e->fd = -1;
  e->refcnt = 1;
  ck_pr_inc_64(&ealloccnt);
  ck_pr_inc_64(&ealloctotal);
  for(int i=0; i<eventer_contexts_cnt; i++) {
    if(eventer_contexts[i].opset->eventer_t_init) {
      e = eventer_contexts[i].opset->eventer_t_init(e);
    }
  }
  return e;
}

eventer_t eventer_alloc_copy(eventer_t src) {
  eventer_t e = calloc(1, sizeof(*e));
  memcpy(e, src, sizeof(*e));
  e->refcnt = 1;
  ck_pr_inc_64(&ealloccnt);
  ck_pr_inc_64(&ealloctotal);
  for(int i=0; i<eventer_contexts_cnt; i++) {
    if(eventer_contexts[i].opset->eventer_t_copy) {
      eventer_contexts[i].opset->eventer_t_copy(e, src);
    }
  }
  return e;
}

eventer_t eventer_alloc_recurrent(eventer_func_t func, void *closure) {
  eventer_t e = eventer_alloc();
  e->mask = EVENTER_RECURRENT;
  e->callback = func;
  e->closure = closure;
  return e;
}

eventer_t eventer_alloc_timer(eventer_func_t func, void *closure, struct timeval *t) {
  eventer_t e = eventer_alloc();
  e->mask = EVENTER_TIMER;
  e->callback = func;
  e->closure = closure;
  memcpy(&e->whence, t, sizeof(e->whence));
  return e;
}

eventer_t eventer_alloc_fd(eventer_func_t func, void *closure, int fd, int mask) {
  eventer_t e = eventer_alloc();
  e->fd = fd;
  e->mask = mask;
  e->opset = eventer_POSIX_fd_opset;
  e->callback = func;
  e->closure = closure;
  return e;
}

eventer_t eventer_alloc_asynch(eventer_func_t func, void *closure) {
  eventer_t e = eventer_alloc();
  e->mask = EVENTER_ASYNCH;
  e->callback = func;
  e->closure = closure;
  return e;
}

eventer_t eventer_alloc_asynch_timeout(eventer_func_t func, void *closure,
                                       struct timeval *deadline) {
  eventer_t e = eventer_alloc();
  e->mask = EVENTER_ASYNCH;
  e->callback = func;
  e->closure = closure;
  memcpy(&e->whence, deadline, sizeof(e->whence));
  return e;
}

void eventer_free(eventer_t e) {
  bool zero;
  ck_pr_dec_32_zero(&e->refcnt, &zero);
  if(zero) {
    ck_pr_dec_64(&ealloccnt);
    for(int i=0; i<eventer_contexts_cnt; i++) {
      if(eventer_contexts[i].opset->eventer_t_deinit) {
        eventer_contexts[i].opset->eventer_t_deinit(e);
      }
    }
    free(e);
  }
}

int eventer_get_mask(eventer_t e) { return e->mask; }
void eventer_set_mask(eventer_t e, int m) { e->mask = m; }

int eventer_get_fd(eventer_t e) { return e->fd; }
/* No setter here */

struct timeval eventer_get_whence(eventer_t e) { return e->whence; }
void eventer_update_whence(eventer_t e, struct timeval t) {
  if((e->mask & EVENTER_ASYNCH) != 0 && (e->mask & EVENTER_CANCEL) == 0) {
    /* we can change the deadline on an asynch event, but not if it has
     * invasive cancellation enabled as that timeout event is inside the
     * job pointer to which we have no reference; in that case, the ship
     * has sailed.
     */
    e->whence = t;
    return;
  }
  if(e->mask != EVENTER_TIMER) return;
  eventer_update_timed_internal(e, EVENTER_TIMER, &t);
}

pthread_t eventer_get_owner(eventer_t e) { return e->thr_owner; }
void eventer_set_owner(eventer_t e, pthread_t t) {
  if(e->opset == eventer_aco_fd_opset) return;
  e->thr_owner = t;
}

eventer_func_t eventer_get_callback(eventer_t e) { return e->callback; }
void eventer_set_callback(eventer_t e, eventer_func_t f) { e->callback = f; }

void *eventer_get_closure(eventer_t e) { return e->closure; }
void eventer_set_closure(eventer_t e, void *c) { e->closure = c; }

void *eventer_aco_get_closure(eventer_aco_t e) { return e->closure; }
void eventer_aco_set_closure(eventer_aco_t e, void *c) { e->closure = c; }

eventer_fd_opset_t eventer_get_fd_opset(eventer_t e) { return e->opset; }
/* No setter here */

int64_t eventer_allocations_current(void) {
  return (int64_t)ck_pr_load_64(&ealloccnt);
}

int64_t eventer_allocations_total(void) {
  return (int64_t)ck_pr_load_64(&ealloctotal);
}

void eventer_ref(eventer_t e) {
  ck_pr_inc_32(&e->refcnt);
}

void eventer_deref(eventer_t e) {
  eventer_free(e);
}

int eventer_set_fd_nonblocking(int fd) {
  int flags;
  if(((flags = fcntl(fd, F_GETFL, 0)) == -1) ||
     (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1))
    return -1;
  return 0;
}
int eventer_set_fd_blocking(int fd) {
  int flags;
  if(((flags = fcntl(fd, F_GETFL, 0)) == -1) ||
     (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1))
    return -1;
  return 0;
}

ck_spinlock_t naming_write_lock;
static ck_hs_t __name_to_func;
static ck_hs_t __func_to_name;
int eventer_name_callback(const char *name, eventer_func_t f) {
  eventer_name_callback_ext(name, f, NULL, NULL);
  return 0;
}
int eventer_name_callback_ext(const char *name,
                              eventer_func_t f,
                              void (*fn)(char *,int,eventer_t,void *),
                              void *cl) {
  struct callback_details *cd, *old;
  cd = calloc(1, sizeof(*cd));
  cd->fptr = (void *)f;
  cd->simple_name = strdup(name);
  cd->functional_name = fn;
  cd->closure = cl;

  unsigned long hash = CK_HS_HASH(&__func_to_name, __ck_hash_from_fptr, cd);
  unsigned long hash2 = CK_HS_HASH(&__name_to_func, __ck_hash_from_fname, cd);
  ck_spinlock_lock(&naming_write_lock);

  if(ck_hs_put(&__name_to_func, hash2, cd) == false) {
    mtevL(eventer_deb, "callback naming collision: %s\n", name);
    free(cd->simple_name);
    free(cd);
    ck_spinlock_unlock(&naming_write_lock);
    return -1;
  }

  stats_ns_t *ns = mtev_stats_ns(mtev_stats_ns(eventer_stats_ns, "callbacks"), cd->simple_name);
  stats_ns_add_tag(ns, "mtev-callback", cd->simple_name);
  cd->latency = stats_register(ns, "latency", STATS_TYPE_HISTOGRAM);
  stats_handle_units(cd->latency, STATS_UNITS_SECONDS);
  (void)ck_hs_set(&__func_to_name, hash, cd, (void **)&old);
  ck_spinlock_unlock(&naming_write_lock);
  return 0;
}
eventer_func_t eventer_callback_for_name(const char *name) {
  struct callback_details *cd, key = { .simple_name = (char *)name };
  unsigned long hash = CK_HS_HASH(&__name_to_func, __ck_hash_from_fname, &key);
  cd = ck_hs_get(&__name_to_func, hash, &key);
  if(cd) return (eventer_func_t)cd->fptr;
  return (eventer_func_t)NULL;
}

static pthread_key_t _tls_funcname_key;
#define FUNCNAME_SIZE 128
const char *eventer_name_for_callback(eventer_func_t f) {
  return eventer_name_for_callback_e(f, NULL);
}
stats_handle_t *eventer_latency_handle_for_callback(eventer_func_t f) {
  struct callback_details *cd, key = { .fptr = (void *)f };
  unsigned long hash = CK_HS_HASH(&__func_to_name, __ck_hash_from_fptr, &key);
  cd = (struct callback_details *)ck_hs_get(&__func_to_name, hash, &key);
  if(cd != NULL) return cd->latency;
  return eventer_unnamed_callback_latency;
}
const char *eventer_name_for_callback_e(eventer_func_t f, eventer_t e) {
  struct callback_details *cd, key = { .fptr = (void *)f };
  unsigned long hash = CK_HS_HASH(&__func_to_name, __ck_hash_from_fptr, &key);
again:
  cd = (struct callback_details *)ck_hs_get(&__func_to_name, hash, &key);
  if(cd) {
    if(cd->functional_name && e) {
      char *buf;
      buf = pthread_getspecific(_tls_funcname_key);
      if(!buf) {
        buf = malloc(FUNCNAME_SIZE);
        pthread_setspecific(_tls_funcname_key, buf);
      }
      cd->functional_name(buf, FUNCNAME_SIZE, e, cd->closure);
      return buf;
    }
    return cd->simple_name;
  }
  const char *dyn;
  dyn = mtev_function_name((uintptr_t)f);
  if(dyn == NULL) {
    cd = calloc(1, sizeof(*cd));
    cd->fptr = f;
    ck_spinlock_lock(&naming_write_lock);
    if(NULL != ck_hs_get(&__func_to_name, hash, &key)) {
      ck_spinlock_unlock(&naming_write_lock);
      free(cd);
      goto again;
    }
    if(!ck_hs_put(&__func_to_name, hash, cd)) {
      ck_spinlock_unlock(&naming_write_lock);
      free(cd);
      goto again;
    }
    ck_spinlock_unlock(&naming_write_lock);
  } else {
    eventer_name_callback(dyn, f);
    return dyn;
  }
  return NULL;
}

int eventer_choose(const char *name) {
  int i = 0;
  eventer_impl_t choice;
  pthread_key_create(&_tls_funcname_key, free);
  for(choice = registered_eventers[i];
      choice;
      choice = registered_eventers[++i]) {
    if(!strcmp(choice->name, name)) {
      __eventer = choice;
      return 0;
    }
  }
  return -1;
}

void eventer_init_globals(void) {
  eventer_stats_ns = mtev_stats_ns(mtev_stats_ns(NULL, "mtev"), "eventer");
  stats_ns_add_tag(eventer_stats_ns, "mtev", "eventer");
  ck_spinlock_init(&naming_write_lock);
  if(ck_hs_init(&__name_to_func,
                CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                __ck_hash_from_fname, __ck_hash_compare_fname,
                &malloc_ck_hs, 10000, mtev_rand()) == false) {
    mtevFatal(mtev_error, "Failed to initialize ck_hs for callback function maps\n");
  }
  if(ck_hs_init(&__func_to_name,
                CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                __ck_hash_from_fptr, __ck_hash_compare_fptr,
                &malloc_ck_hs, 10000, mtev_rand()) == false) {
    mtevFatal(mtev_error, "Failed to initialize ck_hs for callback function maps\n");
  }

  stats_ns_t *ns;
  ns = mtev_stats_ns(mtev_stats_ns(eventer_stats_ns, "callbacks"), "_orphaned");
  stats_ns_add_tag(ns, "mtev-callback", "_orphaned");
  eventer_callback_latency_orphaned = stats_register(ns, "latency", STATS_TYPE_HISTOGRAM_FAST);
  stats_handle_units(eventer_callback_latency_orphaned, STATS_UNITS_SECONDS);

  ns = mtev_stats_ns(mtev_stats_ns(eventer_stats_ns, "callbacks"), "_orphaned");
  stats_ns_add_tag(ns, "mtev-callback", "_unnamed");
  eventer_unnamed_callback_latency = stats_register(ns, "latency", STATS_TYPE_HISTOGRAM_FAST);
  stats_handle_units(eventer_unnamed_callback_latency, STATS_UNITS_SECONDS);

  stats_rob_i64(eventer_stats_ns, "events_total", (void *)&ealloctotal);
  stats_rob_i64(eventer_stats_ns, "events_current", (void *)&ealloccnt);
  eventer_impl_init_globals();
  eventer_ssl_init_globals();
  mtev_task_eventer_init();
}


