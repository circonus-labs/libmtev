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

#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "mtev_hash.h"
#include "mtev_stats.h"
#include "mtev_memory.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static mtev_allocator_t eventer_t_allocator;
eventer_impl_t __eventer;
mtev_log_stream_t eventer_err;
mtev_log_stream_t eventer_deb;
stats_ns_t *eventer_stats_ns;
stats_handle_t *eventer_callback_latency;
stats_handle_t *eventer_unnamed_callback_latency;
static mtev_atomic64_t ealloccnt;
static mtev_atomic64_t ealloctotal;

eventer_t eventer_alloc() {
  eventer_t e;
  e = mtev_calloc(eventer_t_allocator, 1, sizeof(*e));
  e->thr_owner = pthread_self();
  e->opset = eventer_POSIX_fd_opset;
  e->refcnt = 1;
  mtev_atomic_inc64(&ealloccnt);
  mtev_atomic_inc64(&ealloctotal);
  return e;
}

int eventer_timecompare(const void *av, const void *bv) {
  /* Herein we avoid equality.  This function is only used as a comparator
   * for a heap of timed events.  If they are equal, b is considered less
   * just to maintain an order (despite it not being stable).
   */
  const eventer_t a = (eventer_t)av;
  const eventer_t b = (eventer_t)bv;
  if(a->whence.tv_sec < b->whence.tv_sec) return -1;
  if(a->whence.tv_sec == b->whence.tv_sec &&
     a->whence.tv_usec < b->whence.tv_usec) return -1;
  return 1;
}

void eventer_free(eventer_t e) {
  if(mtev_atomic_dec32(&e->refcnt) == 0) {
    mtev_atomic_dec64(&ealloccnt);
    mtev_free(eventer_t_allocator, e);
  }
}

int64_t eventer_allocations_current() {
  return ealloccnt;
}

int64_t eventer_allocations_total() {
  return ealloctotal;
}

void eventer_ref(eventer_t e) {
  register int32_t newval;
  newval = mtev_atomic_inc32(&e->refcnt);
  mtevAssert(newval != 1);
  (void)newval;
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

struct callback_details {
  char *simple_name;
  void (*functional_name)(char *buf, int buflen, eventer_t e, void *closure);
  stats_handle_t *latency;
  void *closure;
};
static void
free_callback_details(void *vcd) {
  struct callback_details *cd = (struct callback_details *)vcd;
  if(cd->simple_name) free(cd->simple_name);
  /* We can't just go and free the stats handle as the metrics system has a ref to it */
  free(vcd);
}

static mtev_hash_table __name_to_func;
static mtev_hash_table __func_to_name;
int eventer_name_callback(const char *name, eventer_func_t f) {
  eventer_name_callback_ext(name, f, NULL, NULL);
  return 0;
}
int eventer_name_callback_ext(const char *name,
                              eventer_func_t f,
                              void (*fn)(char *,int,eventer_t,void *),
                              void *cl) {
  void **fptr = malloc(sizeof(*fptr));
  *fptr = (void *)f;
  mtev_hash_replace(&__name_to_func, strdup(name), strlen(name),
                    (void *)f, free, NULL);
  struct callback_details *cd;
  cd = calloc(1, sizeof(*cd));
  cd->simple_name = strdup(name);
  cd->functional_name = fn;
  cd->closure = cl;
  cd->latency = stats_register(mtev_stats_ns(eventer_stats_ns, "callbacks"),
                               cd->simple_name, STATS_TYPE_HISTOGRAM);
  mtev_hash_replace(&__func_to_name, (char *)fptr, sizeof(*fptr), cd,
                    free, free_callback_details);
  return 0;
}
eventer_func_t eventer_callback_for_name(const char *name) {
  void *vf;
  if(mtev_hash_retrieve(&__name_to_func, name, strlen(name), &vf))
    return (eventer_func_t)vf;
  return (eventer_func_t)NULL;
}

static pthread_key_t _tls_funcname_key;
#define FUNCNAME_SIZE 128
const char *eventer_name_for_callback(eventer_func_t f) {
  return eventer_name_for_callback_e(f, NULL);
}
stats_handle_t *eventer_latency_handle_for_callback(eventer_func_t f) {
  void *vcd;
  if(mtev_hash_retrieve(&__func_to_name, (char *)&f, sizeof(f), &vcd)) {
    struct callback_details *cd = vcd;
    return cd->latency;
  }
  return eventer_unnamed_callback_latency;
}
const char *eventer_name_for_callback_e(eventer_func_t f, eventer_t e) {
  void *vcd;
  struct callback_details *cd;
  if(mtev_hash_retrieve(&__func_to_name, (char *)&f, sizeof(f), &vcd)) {
    cd = vcd;
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

void eventer_init_globals() {
  mtev_allocator_options_t opts = mtev_allocator_options_create();
  mtev_allocator_options_fixed_size(opts, sizeof(struct _event));
  mtev_allocator_options_freelist_perthreadlimit(opts, 1000);
  eventer_t_allocator = mtev_allocator_create(opts);
  mtev_allocator_options_free(opts);

  eventer_stats_ns = mtev_stats_ns(mtev_stats_ns(NULL, "mtev"), "eventer");
  mtev_hash_init_locks(&__name_to_func, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  mtev_hash_init_locks(&__func_to_name, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  eventer_callback_latency =
    stats_register(mtev_stats_ns(eventer_stats_ns, "callbacks"),
                   "_aggregate", STATS_TYPE_HISTOGRAM);
  eventer_unnamed_callback_latency =
    stats_register(mtev_stats_ns(eventer_stats_ns, "callbacks"),
                   "_unnamed", STATS_TYPE_HISTOGRAM);
  stats_rob_i64(eventer_stats_ns, "events_total", (void *)&ealloctotal);
  stats_rob_i64(eventer_stats_ns, "events_current", (void *)&ealloccnt);
  eventer_impl_init_globals();
  eventer_ssl_init_globals();
}


