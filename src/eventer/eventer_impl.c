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
#include "libmtev_dtrace_probes.h"
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <hwloc.h>

static struct timeval *eventer_impl_epoch = NULL;
static int PARALLELISM_MULTIPLIER = 4;
static int EVENTER_DEBUGGING = 0;
static int desired_nofiles = 1024*1024;

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
};

static __thread struct eventer_impl_data *my_impl_data;
static struct eventer_impl_data *eventer_impl_tls_data = NULL;

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

eventer_pool_t *eventer_pool(const char *name) {
  void *vptr;
  if(mtev_hash_retrieve(&eventer_pools, name, strlen(name), &vptr))
    return (eventer_pool_t *)vptr;
  return NULL;
}

int eventer_loop_concurrency() { return default_pool.__loop_concurrency; }

/* Multi-threaded event loops...

   We will instantiate __total_loop_count separate threads each running their
   own event loop.  This event loops can concurrently fire callbacks, so it is
   important that they be written in a thread-safe manner.

   Sadly, some libraries that are leveraged simply aren't up to the challenge.

   We reserve the first event loop to run all stuff that isn't multi-thread safe.
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
  if(i==0)
    idx = 0;
  else
    idx = ((unsigned int)i)%(pool->__loop_concurrency-1) + 1; /* see comment above */
  adjidx = pool->__global_tid_offset + idx;
  mtevL(eventer_deb, "eventer_choose -> %u %% %d = (%s) %d t@%u\n",
        (unsigned int)i, pool->__loop_concurrency, pool->name, idx,
        (unsigned int)eventer_impl_tls_data[adjidx].tid);
  return eventer_impl_tls_data[adjidx].tid;
}
pthread_t eventer_choose_owner(int i) {
  return eventer_choose_owner_pool(&default_pool, i);
}
static struct eventer_impl_data *get_my_impl_data() {
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

int eventer_impl_propset(const char *key, const char *value) {
  if(!strcasecmp(key, "concurrency")) {
    int requested = atoi(value);
    if(requested < 1) requested = 1;
    __default_loop_concurrency = requested;
    return 0;
  }
  if(!strncasecmp(key, "loop_", strlen("loop_"))) {
    const char *name = key + strlen("loop_");
    int requested = atoi(value);
    if(requested < 0) requested = 0;
    eventer_pool_create(name, requested);
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
    if(mtev_memory_maintenance_ex(MTEV_MM_TRY) < 0)
      (*counter)++;
    else
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
  t->timed_events = calloc(1, sizeof(*t->timed_events));
  mtev_skiplist_init(t->timed_events);
  mtev_skiplist_set_compare(t->timed_events,
                            eventer_timecompare, eventer_timecompare);
  mtev_skiplist_add_index(t->timed_events,
                          mtev_compare_voidptr, mtev_compare_voidptr);
  t->staged_timed_events = calloc(1, sizeof(*t->staged_timed_events));
  mtev_skiplist_init(t->staged_timed_events);
  mtev_skiplist_set_compare(t->staged_timed_events,
                            eventer_timecompare, eventer_timecompare);
  mtev_skiplist_add_index(t->staged_timed_events,
                          mtev_compare_voidptr, mtev_compare_voidptr);

  snprintf(qname, sizeof(qname), "default_back_queue/%d", t->id);
  t->__global_backq = eventer_jobq_create_backq(qname);
  e = eventer_alloc();
  e->mask = EVENTER_RECURRENT;
  e->closure = &t->__global_backq;
  e->callback = eventer_jobq_consume_available;
  eventer_add_recurrent(e);

  e = eventer_alloc();
  e->mask = EVENTER_RECURRENT;
  e->closure = calloc(1,sizeof(unsigned int));
  e->callback = eventer_mtev_memory_maintenance;
  eventer_add_recurrent(e);
  ck_pr_inc_32(&t->pool->__loops_started);
}

static void *thrloopwrap(void *vid) {
  struct eventer_impl_data *t;
  int id = (int)(vpsized_int)vid;
  t = &eventer_impl_tls_data[id];
  t->id = id;
  mtev_memory_init(); /* Just in case no one has initialized this */
  mtev_memory_init_thread();
  eventer_per_thread_init(t);
  return (void *)(vpsized_int)__eventer->loop(id);
}

void eventer_loop() {
  thrloopwrap((void *)(vpsized_int)0);
}

static void eventer_loop_prime(eventer_pool_t *pool, int start) {
  int i;
  mtevL(mtev_debug, "Starting eventer pool '%s' with concurrency of %d\n",
        pool->name, pool->__loop_concurrency);
  for(i=start; i<pool->__loop_concurrency; i++) {
    pthread_t tid;
    int adjidx = pool->__global_tid_offset + i;
    mtevAssert(pool == eventer_impl_tls_data[adjidx].pool);
    pthread_create(&tid, NULL, thrloopwrap, (void *)(vpsized_int)adjidx);
  }
  while(ck_pr_load_32(&pool->__loops_started) < ck_pr_load_32(&pool->__loop_concurrency));
}

static hwloc_topology_t *topo = NULL;
static int assess_hw_topo() {
  if(topo) return 0;
  topo = calloc(1, sizeof(*topo));
  if(hwloc_topology_init(topo)) goto out;
  if(hwloc_topology_load(*topo)) goto destroy_out;

  return 0;

 destroy_out:
  hwloc_topology_destroy(*topo);
 out:
  free(topo);
  topo = NULL;
  return -1;
}

int eventer_boot_ctor() {
  if(assess_hw_topo() != 0) return -1;
  return 0;
}

int eventer_cpu_sockets_and_cores(int *sockets, int *cores) {
  int depth, nsockets = 0, ncores = 0;

  if(!topo) return -1;
  depth = hwloc_get_type_depth(*topo, HWLOC_OBJ_SOCKET);
  if(depth != HWLOC_TYPE_DEPTH_UNKNOWN)
    nsockets = hwloc_get_nbobjs_by_depth(*topo, depth);
  depth = hwloc_get_type_or_below_depth(*topo, HWLOC_OBJ_CORE);
  if(depth != HWLOC_TYPE_DEPTH_UNKNOWN)
    ncores = hwloc_get_nbobjs_by_depth(*topo, depth);

  if(sockets) *sockets = nsockets;
  if(cores) *cores = ncores;
  return 0;
}

int eventer_impl_setrlimit() {
  struct rlimit rlim;
  int try;
  getrlimit(RLIMIT_NOFILE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = try = desired_nofiles;
  while(setrlimit(RLIMIT_NOFILE, &rlim) != 0 && errno == EPERM && try > 1024) {
    mtev_watchdog_child_heartbeat();
    rlim.rlim_cur = rlim.rlim_max = (try /= 2);
  }
  getrlimit(RLIMIT_NOFILE, &rlim);
  mtevL(mtev_debug, "rlim { %u, %u }\n", (u_int32_t)rlim.rlim_cur, (u_int32_t)rlim.rlim_max);
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

void eventer_impl_init_globals() {
  mtev_hash_init(&eventer_pools);
  mtevAssert(mtev_hash_store(&eventer_pools,
                             default_pool.name, strlen(default_pool.name),
                             &default_pool));
}

int eventer_impl_init() {
  int try;
  char *evdeb;

  assess_hw_topo();

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
  return 0;
}

void eventer_add_asynch(eventer_jobq_t *q, eventer_t e) {
  eventer_job_t *job;
  /* always use 0, if unspecified */
  if(eventer_is_loop(e->thr_owner) < 0) e->thr_owner = eventer_impl_tls_data[0].tid;
  job = calloc(1, sizeof(*job));
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
  eventer_jobq_enqueue(q ? q : __default_jobq, job);
}

void eventer_add_timed(eventer_t e) {
  struct eventer_impl_data *t;
  mtevAssert(e->mask & EVENTER_TIMER);
  if(EVENTER_DEBUGGING) {
    const char *cbname;
    cbname = eventer_name_for_callback_e(e->callback, e);
    mtevL(eventer_deb, "debug: eventer_add timed (%s)\n",
          cbname ? cbname : "???");
  }
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->te_lock);
  mtev_skiplist_insert(t->staged_timed_events, e);
  pthread_mutex_unlock(&t->te_lock);
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
void eventer_update_timed(eventer_t e, int mask) {
  struct eventer_impl_data *t;
  mtevAssert(mask & EVENTER_TIMER);
  t = get_event_impl_data(e);
  pthread_mutex_lock(&t->te_lock);
  mtev_skiplist_remove_compare(t->timed_events, e, NULL, mtev_compare_voidptr);
  mtev_skiplist_remove_compare(t->staged_timed_events, e, NULL, mtev_compare_voidptr);
  mtev_skiplist_insert(t->staged_timed_events, e);
  pthread_mutex_unlock(&t->te_lock);
}
void eventer_dispatch_timed(struct timeval *now, struct timeval *next) {
  struct eventer_impl_data *t;
  int max_timed_events_to_process;
    /* Handle timed events...
     * we could be multithreaded, so if we pop forever we could starve
     * ourselves. */
  t = get_my_impl_data();
  max_timed_events_to_process = t->timed_events->size;
  while(max_timed_events_to_process-- > 0) {
    int newmask;
    u_int64_t start, duration;
    const char *cbname = NULL;
    eventer_t timed_event;

    mtev_gettimeofday(now, NULL);

    pthread_mutex_lock(&t->te_lock);
    /* Peek at our next timed event, if should fire, pop it.
     * otherwise we noop and NULL it out to break the loop. */
    timed_event = mtev_skiplist_peek(t->timed_events);
    if(timed_event) {
      if(compare_timeval(timed_event->whence, *now) < 0) {
        timed_event = mtev_skiplist_pop(t->timed_events, NULL);
      }
      else {
        sub_timeval(timed_event->whence, *now, next);
        timed_event = NULL;
      }
    }
    pthread_mutex_unlock(&t->te_lock);
    if(timed_event == NULL) break;
    if(EVENTER_DEBUGGING ||
       LIBMTEV_EVENTER_CALLBACK_ENTRY_ENABLED() ||
       LIBMTEV_EVENTER_CALLBACK_RETURN_ENABLED()) {
      cbname = eventer_name_for_callback_e(timed_event->callback, timed_event);
      mtevLT(eventer_deb, now, "debug: timed dispatch(%s)\n",
             cbname ? cbname : "???");
    }
    /* Make our call */
    mtev_memory_begin();
    LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)timed_event,
                           (void *)timed_event->callback, (char *)cbname, -1,
                           timed_event->mask, EVENTER_TIMER);
    start = mtev_gethrtime();
    newmask = timed_event->callback(timed_event, EVENTER_TIMER,
                                    timed_event->closure, now);
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
  if(t->staged_timed_events->size) {
    eventer_t timed_event;
    pthread_mutex_lock(&t->te_lock);
    while(NULL !=
          (timed_event = mtev_skiplist_pop(t->staged_timed_events, NULL))) {
      mtev_skiplist_insert(t->timed_events, timed_event);
    }
    if(NULL != (timed_event = mtev_skiplist_peek(t->timed_events))) {
      mtev_gettimeofday(now, NULL);
      sub_timeval(timed_event->whence, *now, next);
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
      if(iter->data) f(iter->data, closure);
    }
    for(iter = mtev_skiplist_getlist(t->staged_timed_events); iter;
        mtev_skiplist_next(t->staged_timed_events,&iter)) {
      if(iter->data) f(iter->data, closure);
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
  mtevL(eventer_deb, "queueing fd:%d from t@%d to t@%d\n", e->fd, (int)pthread_self(), (int)e->thr_owner);
  pthread_mutex_lock(&t->cross_lock);
  ctt->next = t->cross;
  t->cross = ctt;
  pthread_mutex_unlock(&t->cross_lock);
  eventer_wakeup(e);
}
void eventer_cross_thread_process() {
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
      ctt->mask |= EVENTER_CROSS_THREAD_TRIGGER;
      eventer_trigger(ctt->e, ctt->mask);
      free(ctt);
    }
    else break;
  }
}

void eventer_dispatch_recurrent(struct timeval *now) {
  struct eventer_impl_data *t;
  struct recurrent_events *node;
  struct timeval __now;
  if(!now) {
    mtev_gettimeofday(&__now, NULL);
    now = &__now;
  }
  t = get_my_impl_data();
  pthread_mutex_lock(&t->recurrent_lock);
  for(node = t->recurrent_events; node; node = node->next) {
    u_int64_t start, duration;
    start = mtev_gethrtime();
    node->e->callback(node->e, EVENTER_RECURRENT, node->e->closure, now);
    duration = mtev_gethrtime() - start;
    stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
    stats_set_hist_intscale(eventer_latency_handle_for_callback(node->e->callback), duration, -9, 1);
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

int eventer_thread_check(eventer_t e) {
  return pthread_equal(pthread_self(), e->thr_owner);
}


