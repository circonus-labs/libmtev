/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015-2016, Circonus, Inc. All rights reserved.
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
#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "mtev_memory.h"
#include "mtev_log.h"
#include "mtev_skiplist.h"
#include "mtev_thread.h"
#include "mtev_watchdog.h"
#include "mtev_stats.h"
#include "libmtev_dtrace.h"
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <hwloc.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

static struct timeval *eventer_impl_epoch = NULL;
static int PARALLELISM_MULTIPLIER = 4;
static int EVENTER_DEBUGGING = 0;
static int desired_nofiles = 1024*1024;
static stats_ns_t *pool_ns, *threads_ns;
static uint32_t init_called = 0;

#define NS_PER_S 1000000000
#define NS_PER_MS 1000000
#define NS_PER_US 1000

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

struct cross_thread_trigger {
  struct cross_thread_trigger *next;
  eventer_t e;
  int mask;
};
struct eventer_impl_data {
  int id;
  pthread_t tid;
  pthread_mutex_t te_lock;
  mtev_skiplist *timed_events;
  mtev_skiplist *staged_timed_events;
  eventer_jobq_t *__global_backq;
  pthread_mutex_t recurrent_lock;
  struct recurrent_events {
    eventer_t e;
    struct recurrent_events *next;
  } *recurrent_events;
  pthread_mutex_t cross_lock;
  struct cross_thread_trigger *cross;
  void *spec;
  eventer_pool_t *pool;
  mtev_watchdog_t *hb;
  mtev_hrtime_t last_cb_ns;
  mtev_hrtime_t last_loop_start;
  stats_handle_t *loop_times;
};

static __thread eventer_t current_eventer_in_callback;
/* private */
void eventer_set_this_event(eventer_t e) { current_eventer_in_callback = e; }

eventer_t
eventer_get_this_event(void) {
  return current_eventer_in_callback;
}
static __thread struct eventer_impl_data *my_impl_data;
static pthread_key_t thread_name_key;
struct thread_name {
  char *name;
  mtev_boolean unsafe;
};
static struct eventer_impl_data *eventer_impl_tls_data = NULL;

static inline void
eventer_set_thread_name_internal(const char *name, mtev_boolean unsafe) {
  struct thread_name *to_free = pthread_getspecific(thread_name_key);
  if(to_free != NULL) {
    char *oldname = to_free->name;
    if(name) {
      to_free->name = unsafe ? strdup(name) : mtev_memory_safe_strdup(name);
    } else {
      to_free->name = NULL;
    }
    if(to_free->unsafe) free(oldname);
    else mtev_memory_safe_free(oldname);
    to_free->unsafe = unsafe;
  }
  else {
    to_free = calloc(1, sizeof(*to_free));
    to_free->unsafe = unsafe;
    if(name) {
      to_free->name = unsafe ? strdup(name) : mtev_memory_safe_strdup(name);
    } else {
      to_free->name = NULL;
    }
    pthread_setspecific(thread_name_key, to_free);
  }
  mtev_thread_setname(name);
}
static void
eventer_thread_name_free(void *vtn) {
  struct thread_name *to_free = vtn;
  if(to_free == NULL) return;
  if(to_free->name != NULL) {
    if(to_free->unsafe) free(to_free->name);
    else mtev_memory_safe_free(to_free->name);
  }
  free(to_free);
}
void eventer_set_thread_name(const char *name) {
  eventer_set_thread_name_internal(name, mtev_false);
}
void eventer_set_thread_name_unsafe(const char *name) {
  eventer_set_thread_name_internal(name, mtev_true);
}
const char *eventer_get_thread_name(void) {
  struct thread_name *thread_name = pthread_getspecific(thread_name_key);
  if(!thread_name) return NULL;
  return thread_name->name;
}

#ifdef HAVE_KQUEUE
extern struct _eventer_impl eventer_kqueue_impl;
#endif
#ifdef HAVE_EPOLL
extern struct _eventer_impl eventer_epoll_impl;
#endif
#ifdef HAVE_PORTS
extern struct _eventer_impl eventer_ports_impl;
#endif

eventer_impl_t registered_eventers[] = {
#ifdef HAVE_KQUEUE
  &eventer_kqueue_impl,
#endif
#ifdef HAVE_EPOLL
  &eventer_epoll_impl,
#endif
#ifdef HAVE_PORTS
  &eventer_ports_impl,
#endif
  NULL
};

eventer_impl_t __eventer = NULL;
mtev_log_stream_t eventer_err = NULL;
mtev_log_stream_t eventer_deb = NULL;

static uint32_t __default_queue_threads = 5;
static uint32_t __total_loop_count = 0;
static uint32_t __default_loop_concurrency = 0;
static eventer_jobq_t *__default_jobq;

struct eventer_pool_t {
  char *name;
  uint32_t __global_tid_offset;
  uint32_t __loop_concurrency;
  uint32_t __loops_started;
  double hb_timeout;
  stats_handle_t *loop_times;
};

static eventer_pool_t default_pool = { "default", 0 };
static mtev_hash_table eventer_pools;

void eventer_pool_create(const char *name, int concurrency) {
  /* We cannot create pool once we've initialized */
  mtevAssert(eventer_impl_tls_data == NULL);
  if(__total_loop_count > 0) {
    mtevFatal(mtev_stderr, "Cannot create eventer_pool after start.\n");
  }

  void *vnp = NULL;
  eventer_pool_t *np;
  if(mtev_hash_retrieve(&eventer_pools, name, strlen(name), &vnp)) {
    np = vnp;
  } else {
    np = calloc(1, sizeof(*np));
    np->name = strdup(name);
    mtevAssert(pool_ns);
    stats_ns_t *tns = mtev_stats_ns(pool_ns, np->name);
    np->loop_times = stats_register(tns, "cycletime", STATS_TYPE_HISTOGRAM);
    mtev_hash_store(&eventer_pools, np->name, strlen(np->name), np);
  }
  np->__loop_concurrency = concurrency;
}

const char *eventer_pool_name(eventer_pool_t *pool) {
  return pool->name;
}

uint32_t eventer_pool_concurrency(eventer_pool_t *pool) {
  return pool->__loop_concurrency;
}

void eventer_pool_watchdog_timeout(eventer_pool_t *pool, double timeout) {
  if(pool->hb_timeout == timeout) return;
  pool->hb_timeout = timeout;
  if(eventer_impl_tls_data != NULL) {
    int base = pool->__global_tid_offset;
    int offset;
    for(offset = 0; offset < pool->__loop_concurrency; offset++) {
      if(eventer_impl_tls_data[base+offset].hb) {
        mtev_watchdog_override_timeout(eventer_impl_tls_data[base+offset].hb, pool->hb_timeout);
      }
    }
  }
}

eventer_pool_t *eventer_pool(const char *name) {
  void *vptr;
  if(mtev_hash_retrieve(&eventer_pools, name, strlen(name), &vptr))
    return (eventer_pool_t *)vptr;
  return NULL;
}

int eventer_loop_concurrency(void) { return default_pool.__loop_concurrency; }

/* Multi-threaded event loops...

   We will instantiate __total_loop_count separate threads each running their
   own event loop.  This event loops can concurrently fire callbacks, so it is
   important that they be written in a thread-safe manner.

   Sadly, some libraries that are leveraged simply aren't up to the challenge.

   We reserve the first event loop in the default pool to run all stuff that isn't multi-thread safe.
   If you don't specify an thr_owner for an event, it will be assigned idx=0.
   This can cause a lot of (unavoidable) contention on that event thread.  In
   order to alleviate (or at least avoid) that contention, we will assist thread-
   safe events by only choosing thr_owners other than idx=0.

   This has the effect of using 1 thread for some checks and __total_loop_count-1
   for all the others.

*/

pthread_t eventer_choose_owner_pool(eventer_pool_t *pool, int i) {
  int idx, adjidx;
  if(pool->__loop_concurrency == 1) return eventer_impl_tls_data[pool->__global_tid_offset].tid;
  if(pool == &default_pool) {
    if(i==0)
      idx = 0;
    else
      idx = ((unsigned int)i)%(pool->__loop_concurrency-1) + 1; /* see comment above */
  }
  else {
    idx = ((unsigned int)i)%(pool->__loop_concurrency); /* see comment above */
  }
  adjidx = pool->__global_tid_offset + idx;
  mtevL(eventer_deb, "eventer_choose -> %u %% %d = (%s) %d t@%u\n",
        (unsigned int)i, pool->__loop_concurrency, pool->name, idx,
        (unsigned int)(intptr_t)eventer_impl_tls_data[adjidx].tid);
  return eventer_impl_tls_data[adjidx].tid;
}
pthread_t eventer_choose_owner(int i) {
  return eventer_choose_owner_pool(&default_pool, i);
}
static struct eventer_impl_data *get_my_impl_data(void) {
  return my_impl_data;
}
static struct eventer_impl_data *get_tls_impl_data(pthread_t tid) {
  int i;
  for(i=0;i<__total_loop_count;i++) {
    if(pthread_equal(eventer_impl_tls_data[i].tid, tid))
      return &eventer_impl_tls_data[i];
  }
  mtevL(mtev_error, "get_tls_impl_data called from non-eventer thread\n");
  return NULL;
}
static struct eventer_impl_data *get_event_impl_data(eventer_t e) {
  return get_tls_impl_data(e->thr_owner);
}
int eventer_is_loop(pthread_t tid) {
  int i;
  for(i=0;i<__total_loop_count;i++)
    if(pthread_equal(eventer_impl_tls_data[i].tid, tid)) return i;
  return -1;
}

double eventer_watchdog_timeout(void) {
  struct eventer_impl_data *t = get_my_impl_data();
  if(t == NULL) return 0.0;
  return mtev_watchdog_get_timeout(t->hb);
}

void *eventer_get_spec_for_event(eventer_t e) {
  struct eventer_impl_data *t;
  if(e == NULL) t = get_my_impl_data();
  else t = get_event_impl_data(e);
  mtevAssert(t);
  if(t->spec == NULL) t->spec = __eventer->alloc_spec();
  return t->spec;
}

eventer_pool_t *eventer_get_pool_for_event(eventer_t e) {
  struct eventer_impl_data *t;
  t = get_event_impl_data(e);
  if(!t) return NULL;
  return t->pool;
}

#undef ADVTOK
#define ADVTOK do { \
    tok = nv; \
    if(tok) nv = strchr(tok, ','); \
    if(nv) *nv++ = '\0'; \
} while(0) \

int eventer_impl_propset(const char *key, const char *value) {
  if(!strcasecmp(key, "concurrency")) {
    if(ck_pr_load_32(&init_called) != 0) {
      mtevL(mtev_error, "Cannot change eventer concurrency after startup\n");
      return -1;
    }
    int requested = atoi(value);
    if(requested < 1) requested = 1;
    __default_loop_concurrency = requested;
    return 0;
  }
  if(!strncasecmp(key, "loop_", strlen("loop_"))) {
    if(ck_pr_load_32(&init_called) != 0) {
      mtevL(mtev_error, "Cannot change alternate eventer loop concurrency after startup\n");
      return -1;
    }
    char *nv = alloca(strlen(value)+1), *tok;
    memcpy(nv, value, strlen(value)+1);
    const char *name = key + strlen("loop_");
    if(strlen(name) == 0) return -1;

    ADVTOK; /* concurrency */
    int requested = tok ? atoi(tok) : 0;
    ADVTOK;
    double hb_timeout = tok ? atof(tok) : 0;

    if(requested < 0) requested = 0;
    eventer_pool_create(name, requested);
    eventer_pool_t *ep = eventer_pool(name);
    ep->hb_timeout = hb_timeout;
    return 0;
  }
  if(!strncasecmp(key, "jobq_", strlen("jobq_"))) {
    char *nv = alloca(strlen(value)+1), *tok;
    memcpy(nv, value, strlen(value)+1);
    const char *name = key + strlen("jobq_");
    if(strlen(name) == 0) return -1;

    uint32_t concurrency, min = 0, max = 0, backlog = 0;
    eventer_jobq_memory_safety_t mem_safety = EVENTER_JOBQ_MS_NONE;

    ADVTOK;
    concurrency = atoi(tok);
    if(concurrency == 0) return -1;
    
    ADVTOK; /* min */
    if(tok) min = max = atoi(tok);
    ADVTOK; /* max */
    if(tok) max = atoi(tok);
    if((min && max && min > max) ||
       (min && concurrency < min) ||
       (max && concurrency > max)) {
      mtevL(mtev_error, "eventer jobq '%s' must have reasonable concurrency\n", name);
      return -1;
    }
    ADVTOK;
    if(tok) {
      if(!strcmp(tok, "gc")) mem_safety = EVENTER_JOBQ_MS_GC;
      else if(!strcmp(tok, "cs")) mem_safety = EVENTER_JOBQ_MS_CS;
      else if(strcmp(tok, "none")) {
        mtevL(mtev_error, "eventer jobq '%s' has unknown memory safety setting: %s\n",
              name, tok);
        return -1;
      }
    }
    ADVTOK;
    if(tok) backlog = atoi(tok);
#undef ADVTOK

    eventer_jobq_t *jq = eventer_jobq_retrieve(name);
    if(jq && jq->mem_safety != mem_safety) {
      mtevL(mtev_error, "eventer jobq '%s' cannot be redefined\n", name);
      return -1;
    }
    if(!jq) jq = eventer_jobq_create_ms(name, mem_safety);
    if(!jq) {
      mtevL(mtev_error, "eventer jobq '%s' could not be created\n", name);
      return -1;
    }
    eventer_jobq_set_concurrency(jq, concurrency);
    eventer_jobq_set_min_max(jq, min, max);
    eventer_jobq_set_max_backlog(jq, backlog);
    return 0;
  }
  if(!strcasecmp(key, "default_queue_threads")) {
    int requested = atoi(value);
    if(requested < 1) {
      mtevL(mtev_error, "default_queue_threads must be >= 1\n");
      return -1;
    }
    __default_queue_threads = requested;
    return 0;
  }
  else if(!strcasecmp(key, "rlim_nofiles")) {
    desired_nofiles = atoi(value);
    if(desired_nofiles < 256) {
      mtevL(mtev_error, "rlim_nofiles must be >= 256\n");
      return -1;
    }
    return 0;
  }
  else if(!strcasecmp(key, "debugging")) {
    if(strcmp(value, "0")) {
      EVENTER_DEBUGGING = 1;
      mtevL(mtev_error, "Enabling debugging from property\n");
    }
    return 0;
  }
  else if(!strcasecmp(key, "default_ca_chain")) {
    /* used by eventer consumers */
    return 0;
  }
  else if(!strncmp(key, "ssl_", 4)) {
    if(eventer_ssl_config(key, value) == 0) return 0;
    /* if we return 1, we'll fall through to the error message */
  }
  mtevL(mtev_error, "Warning: unknown eventer config '%s'\n", key);
  return 0;
}

eventer_jobq_t *eventer_default_backq(eventer_t e) {
  pthread_t tid;
  struct eventer_impl_data *impl_data;
  tid = e ? e->thr_owner : pthread_self();
  impl_data = get_tls_impl_data(tid);
  mtevAssert(impl_data);
  return impl_data->__global_backq;
}

int eventer_get_epoch(struct timeval *epoch) {
  if(!eventer_impl_epoch) return -1;
  memcpy(epoch, eventer_impl_epoch, sizeof(*epoch));
  return 0;
}

int NE_SOCK_CLOEXEC = 0;
int NE_O_CLOEXEC = 0;

static int
eventer_mtev_memory_maintenance(eventer_t e, int mask, void *c,
                                struct timeval *now) {
  unsigned int *counter = (unsigned int *)c;

  /* Each time through we'll try to reclaim memory, if it
   * fails 1000 times in a row, we'll schedule an asynchronous
   * force (barrier) cleanup.
   */
  if(*counter < 1000) {
    if(mtev_memory_maintenance_ex(MTEV_MM_TRY) < 0) {
      (*counter)++;
      return 0; /* no work was done */
    } else
      *counter = 0;
  }
  else {
    mtev_memory_maintenance_ex(MTEV_MM_BARRIER_ASYNCH);
    *counter = 0;
  }
  return EVENTER_RECURRENT;
}
static void eventer_per_thread_init(struct eventer_impl_data *t) {
  char qname[80];
  eventer_t e;

  if(t->timed_events != NULL) return;

  t->tid = pthread_self();
  my_impl_data = t;

  pthread_mutex_init(&t->cross_lock, NULL);
  pthread_mutex_init(&t->te_lock, NULL);
  pthread_mutex_init(&t->recurrent_lock, NULL);
  t->timed_events = mtev_skiplist_alloc();
  mtev_skiplist_set_compare(t->timed_events,
                            eventer_timecompare, eventer_timecompare);
  mtev_skiplist_add_index(t->timed_events,
                          mtev_compare_voidptr, mtev_compare_voidptr);
  t->staged_timed_events = mtev_skiplist_alloc();
  mtev_skiplist_set_compare(t->staged_timed_events,
                            eventer_timecompare, eventer_timecompare);
  mtev_skiplist_add_index(t->staged_timed_events,
                          mtev_compare_voidptr, mtev_compare_voidptr);

  snprintf(qname, sizeof(qname), "default_back_queue/%d", t->id);
  t->__global_backq = eventer_jobq_create_backq(qname);
  e = eventer_alloc();
  e->mask = EVENTER_RECURRENT;
  e->closure = t->__global_backq;
  e->callback = eventer_jobq_consume_available;
  eventer_add_recurrent(e);

  e = eventer_alloc();
  e->mask = EVENTER_RECURRENT;
  e->closure = calloc(1,sizeof(unsigned int));
  e->callback = eventer_mtev_memory_maintenance;
  eventer_add_recurrent(e);

  /* The "main" thread uses a NULL heartbeat,
   * all other threads get their own. */
  if(t->id != 0) t->hb = mtev_watchdog_create();
  if(t->pool->hb_timeout)
    mtev_watchdog_override_timeout(t->hb, t->pool->hb_timeout);
  e = mtev_watchdog_recurrent_heartbeat(t->hb);
  eventer_add_recurrent(e);

  ck_pr_inc_32(&t->pool->__loops_started);
}

static void *thrloopwrap(void *vid) {
  struct eventer_impl_data *t;
  char thr_name[64];
  int id = (int)(intptr_t)vid;
  t = &eventer_impl_tls_data[id];
  t->id = id;
  snprintf(thr_name, sizeof(thr_name), "%s/%d", t->pool->name, id);
  stats_ns_t *tns = mtev_stats_ns(threads_ns, thr_name);
  t->loop_times = stats_register(tns, "cycletime", STATS_TYPE_HISTOGRAM);
  mtev_memory_init(); /* Just in case no one has initialized this */
  mtev_memory_init_thread();
  eventer_set_thread_name(thr_name);
  eventer_per_thread_init(t);
  return (void *)(intptr_t)__eventer->loop(id);
}

void eventer_loop(void) {
  mtevL(mtev_debug, "eventer_loop() started\n");
  thrloopwrap((void *)(intptr_t)0);
}

static void eventer_loop_prime(eventer_pool_t *pool, int start) {
  int i;
  mtevL(mtev_debug, "Starting eventer pool '%s' with concurrency of %d\n",
        pool->name, pool->__loop_concurrency);
  for(i=start; i<pool->__loop_concurrency; i++) {
    pthread_t tid;
    int adjidx = pool->__global_tid_offset + i;
    mtevAssert(pool == eventer_impl_tls_data[adjidx].pool);
    pthread_create(&tid, NULL, thrloopwrap, (void *)(intptr_t)adjidx);
  }
  while(ck_pr_load_32(&pool->__loops_started) < ck_pr_load_32(&pool->__loop_concurrency));
}

static void hw_topo_free(hwloc_topology_t *topo) {
  if(topo) {
    hwloc_topology_destroy(*topo);
    free(topo);
  }
}

static hwloc_topology_t *hw_topo_alloc(void) {
#ifdef __sun
#ifdef RUNNING_ON_VALGRIND
  if(RUNNING_ON_VALGRIND != 0) return NULL;
#endif
#endif
  hwloc_topology_t *topo = calloc(1, sizeof(*topo));
  if(!topo) return NULL;
  if(hwloc_topology_init(topo)) goto out;
  if(hwloc_topology_load(*topo)) goto destroy_out;

  return topo;

 destroy_out:
  hw_topo_free(topo);
  return NULL;
 out:
  free(topo);
  return NULL;
}

int eventer_boot_ctor(void) {
  return 0;
}

int eventer_cpu_sockets_and_cores(int *sockets, int *cores) {
  hwloc_topology_t *topo;
  int depth, nsockets = 0, ncores = 0;

  topo = hw_topo_alloc();
  if(topo == NULL) return -1;
  depth = hwloc_get_type_depth(*topo, HWLOC_OBJ_SOCKET);
  if(depth != HWLOC_TYPE_DEPTH_UNKNOWN)
    nsockets = hwloc_get_nbobjs_by_depth(*topo, depth);
  depth = hwloc_get_type_or_below_depth(*topo, HWLOC_OBJ_CORE);
  if(depth != HWLOC_TYPE_DEPTH_UNKNOWN)
    ncores = hwloc_get_nbobjs_by_depth(*topo, depth);

  if(sockets) *sockets = nsockets;
  if(cores) *cores = ncores;
  hw_topo_free(topo);
  return 0;
}

int eventer_impl_setrlimit(void) {
  struct rlimit rlim;
  int try;
  getrlimit(RLIMIT_NOFILE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = try = desired_nofiles;
  while(setrlimit(RLIMIT_NOFILE, &rlim) != 0 && errno == EPERM && try > 1024) {
    mtev_watchdog_child_heartbeat();
    rlim.rlim_cur = rlim.rlim_max = (try /= 2);
  }
  getrlimit(RLIMIT_NOFILE, &rlim);
  mtevL(mtev_debug, "rlim { %u, %u }\n", (uint32_t)rlim.rlim_cur, (uint32_t)rlim.rlim_max);
  return rlim.rlim_cur;
}

static void
eventer_impl_tls_data_from_pool(eventer_pool_t *pool) {
  int i;
  for (i=0; i<pool->__loop_concurrency; i++) {
    int adjidx = pool->__global_tid_offset + i;
    struct eventer_impl_data *t = &eventer_impl_tls_data[adjidx];
    t->pool = pool;
  }
}

static int periodic_jobq_maintenance(eventer_t e, int mask, void *vjobq, struct timeval *now) {
  eventer_jobq_t *jobq = vjobq;
  eventer_jobq_ping(jobq);
  eventer_add_in_s_us(periodic_jobq_maintenance, jobq, 1, 0);
  return 0;
}

static void register_jobq_maintenance(eventer_jobq_t *jobq, void *unused) {
  eventer_add_in_s_us(periodic_jobq_maintenance, jobq, 1, 0);
}

static void periodic_jobq_maintenance_namer(char *buf, int buflen,
                                            eventer_t e, void *cl) {
  (void)cl;
  eventer_jobq_t *jobq = eventer_get_closure(e);
  snprintf(buf, buflen, "maintenance(%s)", jobq->queue_name);
}

void eventer_impl_init_globals(void) {
  pthread_key_create(&thread_name_key, eventer_thread_name_free);
  eventer_name_callback_ext("periodic_jobq_maintenance",
                            periodic_jobq_maintenance,
                            periodic_jobq_maintenance_namer, NULL);
  mtev_hash_init(&eventer_pools);

  pool_ns = mtev_stats_ns(eventer_stats_ns, "pool");
  threads_ns = mtev_stats_ns(eventer_stats_ns, "threads");

  stats_ns_t *tns = mtev_stats_ns(pool_ns, "default");
  default_pool.loop_times = stats_register(tns, "cycletime", STATS_TYPE_HISTOGRAM);

  mtevAssert(mtev_hash_store(&eventer_pools,
                             default_pool.name, strlen(default_pool.name),
                             &default_pool));
}

int eventer_impl_init(void) {
  int try;
  char *evdeb;

  mtevAssert(ck_pr_load_32(&init_called) == 0);
  ck_pr_inc_32(&init_called);

  (void)try;
#ifdef SOCK_CLOEXEC
  /* We can test, still might not work */
  try = socket(AF_INET, SOCK_CLOEXEC|SOCK_STREAM, IPPROTO_TCP);
  if(try >= 0) {
    close(try);
    NE_SOCK_CLOEXEC = SOCK_CLOEXEC;
  }
#endif
#ifdef O_CLOEXEC
  NE_O_CLOEXEC = O_CLOEXEC;
#endif

  if(__default_loop_concurrency == 0) {
    int sockets = 0, cores = 0;

    (void)eventer_cpu_sockets_and_cores(&sockets, &cores);
    if(sockets == 0) sockets = 1;
    if(cores == 0) cores = sockets;
    __default_loop_concurrency = 1 + PARALLELISM_MULTIPLIER * cores;
    mtevL(mtev_debug, "found %d sockets, %d cores -> default concurrency %d\n",
          sockets, cores, __default_loop_concurrency);
  }

  evdeb = getenv("EVENTER_DEBUGGING");
  if(evdeb) {
    if(strcmp(evdeb, "0")) {
      /* Set to anything but "0" turns debugging on */
      EVENTER_DEBUGGING = 1;
      mtevL(mtev_error, "Enabling eventer debugging from environment\n");
    }
    else {
      EVENTER_DEBUGGING = 0;
      mtevL(mtev_error, "Disabling eventer debugging from environment\n");
    }
  }
  eventer_name_callback("eventer_jobq_execute_timeout",
                        eventer_jobq_execute_timeout);
  eventer_name_callback("eventer_jobq_consume_available",
                        eventer_jobq_consume_available);
  eventer_name_callback("eventer_mtev_memory_maintenance",
                        eventer_mtev_memory_maintenance);

  eventer_impl_epoch = malloc(sizeof(struct timeval));
  mtev_gettimeofday(eventer_impl_epoch, NULL);

  eventer_err = mtev_log_stream_find("error/eventer");
  eventer_deb = mtev_log_stream_find("debug/eventer");
  if(!eventer_err) eventer_err = mtev_stderr;
  if(!eventer_deb) eventer_deb = mtev_debug;

  __default_jobq = eventer_jobq_create("default_queue");
  eventer_jobq_set_concurrency(__default_jobq, __default_queue_threads);

  mtevAssert(eventer_impl_tls_data == NULL);

  /* Zip through the pools and set their concurrencies. */
  /* default is always first with an offset of 0 */
  if(default_pool.__loop_concurrency == 0)
    default_pool.__loop_concurrency = __default_loop_concurrency;
  __total_loop_count = default_pool.__loop_concurrency;

  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(&eventer_pools, &iter)) {
    eventer_pool_t *pool = iter.value.ptr;
    if(pool == &default_pool) continue; 
    if(pool->__loop_concurrency == 0)
      pool->__loop_concurrency = __default_loop_concurrency;
    pool->__global_tid_offset = __total_loop_count;
    __total_loop_count += pool->__loop_concurrency;
  }
  eventer_impl_tls_data = calloc(__total_loop_count, sizeof(*eventer_impl_tls_data));

  int accum_check = 0;

  /* first the default pool */
  eventer_impl_tls_data_from_pool(&default_pool);
  eventer_per_thread_init(&eventer_impl_tls_data[0]);
  /* thread 0 is this thread, so we prime starting at 1 */
  eventer_loop_prime(&default_pool, 1);
  accum_check += default_pool.__loop_concurrency;

  /* then everythign but the default pool */
  memset(&iter, 0, sizeof(iter));
  while(mtev_hash_adv(&eventer_pools, &iter)) {
    eventer_pool_t *pool = iter.value.ptr;
    if(pool == &default_pool) continue;
    eventer_impl_tls_data_from_pool(pool);
    eventer_loop_prime(pool, 0); /* prime all threads starting at 0 */
    accum_check += pool->__loop_concurrency;
  }
  mtevAssert(accum_check == __total_loop_count);

  eventer_ssl_init();

  eventer_jobq_process_each(register_jobq_maintenance, NULL);
  return 0;
}

void eventer_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t subqueue) {
  eventer_job_t *job;
  /* always use 0, if unspecified */
  if(eventer_is_loop(e->thr_owner) < 0) e->thr_owner = eventer_impl_tls_data[0].tid;
  job = calloc(1, sizeof(*job));
  job->subqueue = subqueue;
  job->fd_event = e;
  job->jobq = q ? q : __default_jobq;
  job->create_hrtime = mtev_gethrtime(); /* use sys as this is cross-thread */
  /* If we're debugging the eventer, these cross thread timeouts will
   * make it impossible for us to slowly trace an asynch job. */
  if(e->whence.tv_sec) {
    job->timeout_event = eventer_alloc();
    job->timeout_event->thr_owner = e->thr_owner;
    memcpy(&job->timeout_event->whence, &e->whence, sizeof(e->whence));
    job->timeout_event->mask = EVENTER_TIMER;
    job->timeout_event->closure = job;
    job->timeout_event->callback = eventer_jobq_execute_timeout;
    eventer_add(job->timeout_event);
  }
  eventer_jobq_enqueue(q ? q : __default_jobq, job, NULL);
}

void eventer_add_asynch(eventer_jobq_t *q, eventer_t e) {
  eventer_add_asynch_subqueue(q, e, 0);
}

void eventer_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t subqueue) {
  eventer_job_t *job;
  /* always use 0, if unspecified */
  if(eventer_is_loop(e->thr_owner) < 0) e->thr_owner = eventer_impl_tls_data[0].tid;
  job = calloc(1, sizeof(*job));
  job->subqueue = subqueue;
  job->fd_event = e;
  job->jobq = q ? q : __default_jobq;
  job->create_hrtime = mtev_gethrtime(); /* use sys as this is cross-thread */
  /* If we're debugging the eventer, these cross thread timeouts will
   * make it impossible for us to slowly trace an asynch job. */
  if(e->whence.tv_sec) {
    job->timeout_event = eventer_alloc();
    job->timeout_event->thr_owner = e->thr_owner;
    memcpy(&job->timeout_event->whence, &e->whence, sizeof(e->whence));
    job->timeout_event->mask = EVENTER_TIMER;
    job->timeout_event->closure = job;
    job->timeout_event->callback = eventer_jobq_execute_timeout;
    eventer_add(job->timeout_event);
  }
  eventer_jobq_enqueue(job->jobq, job, eventer_jobq_inflight());
}

void eventer_add_asynch_dep(eventer_jobq_t *q, eventer_t e) {
  eventer_add_asynch_dep_subqueue(q, e, 0);
}

mtev_boolean eventer_try_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t subqueue) {
  eventer_t timeout = NULL;
  eventer_job_t *job;
  /* always use 0, if unspecified */
  if(eventer_is_loop(e->thr_owner) < 0) e->thr_owner = eventer_impl_tls_data[0].tid;
  job = calloc(1, sizeof(*job));
  job->subqueue = subqueue;
  job->fd_event = e;
  job->jobq = q ? q : __default_jobq;
  job->create_hrtime = mtev_gethrtime(); /* use sys as this is cross-thread */
  /* If we're debugging the eventer, these cross thread timeouts will
   * make it impossible for us to slowly trace an asynch job. */
  if(e->whence.tv_sec) {
    timeout = job->timeout_event = eventer_alloc();
    job->timeout_event->thr_owner = e->thr_owner;
    memcpy(&job->timeout_event->whence, &e->whence, sizeof(e->whence));
    job->timeout_event->mask = EVENTER_TIMER;
    job->timeout_event->closure = job;
    job->timeout_event->callback = eventer_jobq_execute_timeout;
    eventer_add(job->timeout_event);
  }
  if(eventer_jobq_try_enqueue(q ? q : __default_jobq, job, NULL)) return mtev_true;
  if(timeout) {
    eventer_remove(timeout);
    eventer_free(timeout);
  }
  return mtev_false;
}

mtev_boolean eventer_try_add_asynch(eventer_jobq_t *q, eventer_t e) {
  return eventer_try_add_asynch_subqueue(q, e, 0);
}

mtev_boolean eventer_try_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t subqueue) {
  eventer_t timeout = NULL;
  eventer_job_t *job;
  /* always use 0, if unspecified */
  if(eventer_is_loop(e->thr_owner) < 0) e->thr_owner = eventer_impl_tls_data[0].tid;
  job = calloc(1, sizeof(*job));
  job->subqueue = subqueue;
  job->fd_event = e;
  job->jobq = q ? q : __default_jobq;
  job->create_hrtime = mtev_gethrtime(); /* use sys as this is cross-thread */
  /* If we're debugging the eventer, these cross thread timeouts will
   * make it impossible for us to slowly trace an asynch job. */
  if(e->whence.tv_sec) {
    timeout = job->timeout_event = eventer_alloc();
    job->timeout_event->thr_owner = e->thr_owner;
    memcpy(&job->timeout_event->whence, &e->whence, sizeof(e->whence));
    job->timeout_event->mask = EVENTER_TIMER;
    job->timeout_event->closure = job;
    job->timeout_event->callback = eventer_jobq_execute_timeout;
    eventer_add(job->timeout_event);
  }
  if(eventer_jobq_try_enqueue(job->jobq, job, eventer_jobq_inflight())) return mtev_true;
  if(timeout) {
    eventer_remove(timeout);
    eventer_free(timeout);
  }
  return mtev_false;
}

mtev_boolean eventer_try_add_asynch_dep(eventer_jobq_t *q, eventer_t e) {
  return eventer_try_add_asynch_dep_subqueue(q, e, 0);
}

void eventer_add_timed(eventer_t e) {
  struct eventer_impl_data *t;
  int should_wake = (e->whence.tv_sec == 0 && e->whence.tv_usec == 0);

  mtevAssert(e->mask & EVENTER_TIMER);
  if(EVENTER_DEBUGGING) {
    const char *cbname;
    cbname = eventer_name_for_callback_e(e->callback, e);
    mtevL(eventer_deb, "debug: eventer_add timed (%s)\n",
          cbname ? cbname : "???");
  }
  t = get_event_impl_data(e);
  if (should_wake) eventer_ref(e);
  pthread_mutex_lock(&t->te_lock);
  mtev_skiplist_insert(t->staged_timed_events, e);
  pthread_mutex_unlock(&t->te_lock);
  if (should_wake) {
    eventer_wakeup(e);
    eventer_deref(e);
  }
}
eventer_t eventer_remove_timed(eventer_t e) {
  struct eventer_impl_data *t;
  eventer_t removed = NULL;
  mtevAssert(e->mask & EVENTER_TIMER);
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->te_lock);
  if(mtev_skiplist_remove_compare(t->timed_events, e, NULL,
                                  mtev_compare_voidptr))
    removed = e;
  else if(mtev_skiplist_remove_compare(t->staged_timed_events, e, NULL,
                                       mtev_compare_voidptr))
    removed = e;
  pthread_mutex_unlock(&t->te_lock);
  return removed;
}
void eventer_update_timed_internal(eventer_t e, int mask, struct timeval *new_whence) {
  struct eventer_impl_data *t;
  mtevAssert(mask & EVENTER_TIMER);
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->te_lock);
  mtev_skiplist_remove_compare(t->timed_events, e, NULL, mtev_compare_voidptr);
  mtev_skiplist_remove_compare(t->staged_timed_events, e, NULL, mtev_compare_voidptr);
  e->whence = *new_whence;
  mtev_skiplist_insert(t->staged_timed_events, e);
  pthread_mutex_unlock(&t->te_lock);
}
void eventer_dispatch_timed(struct timeval *next) {
  struct timeval now;
  struct eventer_impl_data *t;
  int max_timed_events_to_process;
    /* Handle timed events...
     * we could be multithreaded, so if we pop forever we could starve
     * ourselves. */
  t = get_my_impl_data();

  /* we enter here once per loop, use this opportunity to count */
  mtev_hrtime_t nowhr = mtev_gethrtime();
  if(t->last_loop_start) {
    mtev_hrtime_t elapsed = nowhr - t->last_loop_start;
    stats_set_hist_intscale(t->loop_times, elapsed, -9, 1);
    stats_set_hist_intscale(t->pool->loop_times, elapsed, -9, 1);
  }
  t->last_loop_start = nowhr;

  max_timed_events_to_process = mtev_skiplist_size(t->timed_events);
  if(max_timed_events_to_process == 0) mtev_gettimeofday(&now, NULL);
  while(max_timed_events_to_process-- > 0) {
    int newmask;
    uint64_t start, duration;
    const char *cbname = NULL;
    eventer_t timed_event;

    eventer_mark_callback_time();
    eventer_gettimeofcallback(&now, NULL);

    pthread_mutex_lock(&t->te_lock);
    /* Peek at our next timed event, if should fire, pop it.
     * otherwise we noop and NULL it out to break the loop. */
    timed_event = mtev_skiplist_peek(t->timed_events);
    if(timed_event) {
      if(compare_timeval(timed_event->whence, now) < 0) {
        timed_event = mtev_skiplist_pop(t->timed_events, NULL);
      }
      else {
        sub_timeval(timed_event->whence, now, next);
        timed_event = NULL;
      }
    }
    pthread_mutex_unlock(&t->te_lock);
    if(timed_event == NULL) break;
    if(EVENTER_DEBUGGING ||
       LIBMTEV_EVENTER_CALLBACK_ENTRY_ENABLED() ||
       LIBMTEV_EVENTER_CALLBACK_RETURN_ENABLED()) {
      cbname = eventer_name_for_callback_e(timed_event->callback, timed_event);
      mtevL(eventer_deb, "debug: timed dispatch(%s)\n",
            cbname ? cbname : "???");
    }
    /* Make our call */
    mtev_memory_begin();
    LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)timed_event,
                           (void *)timed_event->callback, (char *)cbname, -1,
                           timed_event->mask, EVENTER_TIMER);
    start = mtev_gethrtime();
    newmask = eventer_run_callback(timed_event, EVENTER_TIMER,
                           timed_event->closure, &now);
    duration = mtev_gethrtime() - start;
    stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
    stats_set_hist_intscale(eventer_latency_handle_for_callback(timed_event->callback), duration, -9, 1);
    LIBMTEV_EVENTER_CALLBACK_RETURN((void *)timed_event,
                            (void *)timed_event->callback, (char *)cbname, newmask);
    mtev_memory_end();
    if(newmask)
      eventer_add_timed(timed_event);
    else
      eventer_free(timed_event);
  }

  /* Sweep the staged timed events into the processing queue */
  if(mtev_skiplist_size(t->staged_timed_events)) {
    eventer_t timed_event;
    pthread_mutex_lock(&t->te_lock);
    while(NULL !=
          (timed_event = mtev_skiplist_pop(t->staged_timed_events, NULL))) {
      mtev_skiplist_insert(t->timed_events, timed_event);
    }
    if(NULL != (timed_event = mtev_skiplist_peek(t->timed_events))) {
      sub_timeval(timed_event->whence, now, next);
      if(next->tv_sec < 0 || next->tv_usec < 0)
        next->tv_sec = next->tv_usec = 0;
    }
    pthread_mutex_unlock(&t->te_lock);
  }

  if(compare_timeval(eventer_max_sleeptime, *next) < 0) {
    /* we exceed our configured maximum, set it down */
    memcpy(next, &eventer_max_sleeptime, sizeof(*next));
  }
}
void
eventer_foreach_timedevent(void (*f)(eventer_t e, void *), void *closure) {
  mtev_skiplist_node *iter = NULL;
  int i;
  for(i=0;i<__total_loop_count;i++) {
    struct eventer_impl_data *t = &eventer_impl_tls_data[i];
    pthread_mutex_lock(&t->te_lock);
    for(iter = mtev_skiplist_getlist(t->timed_events); iter;
        mtev_skiplist_next(t->timed_events,&iter)) {
      if(mtev_skiplist_data(iter)) f(mtev_skiplist_data(iter), closure);
    }
    for(iter = mtev_skiplist_getlist(t->staged_timed_events); iter;
        mtev_skiplist_next(t->staged_timed_events,&iter)) {
      if(mtev_skiplist_data(iter)) f(mtev_skiplist_data(iter), closure);
    }
    pthread_mutex_unlock(&t->te_lock);
  }
}

void eventer_cross_thread_trigger(eventer_t e, int mask) {
  struct eventer_impl_data *t;
  struct cross_thread_trigger *ctt;
  t = get_event_impl_data(e);
  ctt = malloc(sizeof(*ctt));
  ctt->e = e;
  ctt->mask = mask;
  mtevAssert(0 == (ctt->mask & EVENTER_CROSS_THREAD_TRIGGER));
  ctt->mask |= EVENTER_CROSS_THREAD_TRIGGER;
  mtevL(eventer_deb, "queueing fd:%d from t@%d to t@%d\n", e->fd, (int)(intptr_t)pthread_self(), (int)(intptr_t)e->thr_owner);
  eventer_ref(e);
  pthread_mutex_lock(&t->cross_lock);
  ctt->next = t->cross;
  t->cross = ctt;
  pthread_mutex_unlock(&t->cross_lock);
  eventer_wakeup(e);
  eventer_deref(e);
}
void eventer_cross_thread_process(void) {
  struct eventer_impl_data *t;
  struct cross_thread_trigger *ctt = NULL;
  t = get_my_impl_data();
  while(1) {
    pthread_mutex_lock(&t->cross_lock);
    ctt = t->cross;
    if(ctt) t->cross = ctt->next;
    pthread_mutex_unlock(&t->cross_lock);
    if(ctt) {
      mtevL(eventer_deb, "executing queued fd:%d / %x\n", ctt->e->fd, ctt->mask);
      eventer_trigger(ctt->e, ctt->mask);
      free(ctt);
    }
    else break;
  }
}

void eventer_mark_callback_time(void) {
  struct eventer_impl_data *t;
  t = get_my_impl_data();
  mtevAssert(t);
  t->last_cb_ns = mtev_now_us() * NS_PER_US;
}
void eventer_dispatch_recurrent(void) {
  struct timeval __now;
  struct eventer_impl_data *t;
  struct recurrent_events *node;
  t = get_my_impl_data();

  eventer_mark_callback_time();
  eventer_gettimeofcallback(&__now, NULL);

  pthread_mutex_lock(&t->recurrent_lock);
  for(node = t->recurrent_events; node; node = node->next) {
    int rv;
    uint64_t start, duration;
    start = mtev_gethrtime();
    rv = eventer_run_callback(node->e, EVENTER_RECURRENT, node->e->closure, &__now);
    if(rv != 0) {
      /* For RECURRENT calls, we don't want to overmeasure what are noops...
       * So we trust that the call returns 0 after such a noop, but
       * EVENTER_RECURRENT when work is done.
       */
      duration = mtev_gethrtime() - start;
      stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
      stats_set_hist_intscale(eventer_latency_handle_for_callback(node->e->callback), duration, -9, 1);
    }
  }
  pthread_mutex_unlock(&t->recurrent_lock);
}
eventer_t eventer_remove_recurrent(eventer_t e) {
  struct eventer_impl_data *t;
  struct recurrent_events *node, *prev = NULL;
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->recurrent_lock);
  for(node = t->recurrent_events; node; node = node->next) {
    if(node->e == e) {
      if(prev) prev->next = node->next;
      else t->recurrent_events = node->next;
      free(node);
      pthread_mutex_unlock(&t->recurrent_lock);
      return e;
    }
    prev = node;
  }
  pthread_mutex_unlock(&t->recurrent_lock);
  return NULL;
}

int eventer_gettimeofcallback(struct timeval *now, void *tzp) {
  struct eventer_impl_data *t;
  if(NULL != (t = get_my_impl_data())) {
    now->tv_sec = t->last_cb_ns / NS_PER_S;
    now->tv_usec = (t->last_cb_ns % NS_PER_S) / NS_PER_US;
    return 0;
  }
  return mtev_gettimeofday(now, tzp);
}
uint64_t eventer_callback_ms(void) {
  struct eventer_impl_data *t;
  if(NULL != (t = get_my_impl_data())) {
    return t->last_cb_ns / NS_PER_MS;
  }
  return mtev_now_ms();
}
uint64_t eventer_callback_us(void) {
  struct eventer_impl_data *t;
  if(NULL != (t = get_my_impl_data())) {
    return t->last_cb_ns / NS_PER_US;
  }
  return mtev_now_us();
}

void eventer_wakeup_noop(eventer_t e) { }
void eventer_add_recurrent(eventer_t e) {
  struct eventer_impl_data *t;
  struct recurrent_events *node;
  mtevAssert(e->mask & EVENTER_RECURRENT);
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->recurrent_lock);
  for(node = t->recurrent_events; node; node = node->next)
    if(node->e == e) {
      pthread_mutex_unlock(&t->recurrent_lock);
      return;
    }
  node = calloc(1, sizeof(*node));
  node->e = e;
  node->next = t->recurrent_events;
  t->recurrent_events = node;
  pthread_mutex_unlock(&t->recurrent_lock);
}

static void *eventer_thread_harness(void *ve) {
  eventer_t e = ve;
  char thrname[64];
  snprintf(thrname, sizeof(thrname),
           "dedicated/%u", mtev_thread_id());
  eventer_set_thread_name_unsafe(thrname);
  int mask = e->mask;
  while(1) {
    struct timeval now;
    mtev_gettimeofday(&now, NULL);
    eventer_run_callback(e, mask, e->closure, &now);
    if(mask == 0) {
      eventer_free(e);
      return NULL;
    }
    /* give it what it wants, but not an exception */
    mask &= ~EVENTER_EXCEPTION;
  }
}
void eventer_run_in_thread(eventer_t e, int mask) {
  eventer_remove_fde(e);
  eventer_set_fd_blocking(e->fd);
  e->mask = mask;

  pthread_t tid;
  pthread_attr_t tattr;
  mtevL(eventer_deb, "Starting dedicated thread for event on fd: %d\n", e->fd);
  pthread_attr_init(&tattr);
  pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
  pthread_create(&tid, &tattr, eventer_thread_harness, e);
}

int eventer_thread_check(eventer_t e) {
  return pthread_equal(pthread_self(), e->thr_owner);
}


