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

#ifndef EVENTER_EVENTER_IMPL_PRIVATE_H
#define EVENTER_EVENTER_IMPL_PRIVATE_H

#include "mtev_stats.h"
#include "mtev_memory.h"
#include "mtev_log.h"
#include "aco/aco.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <ck_hs.h>

#define EVENTER_JOBQ_RUNNING 0
#define EVENTER_JOBQ_SHUTTING_DOWN 1
#define EVENTER_JOBQ_SHUT_DOWN 2

typedef struct eventer_context_t {
  void *data;
} eventer_context_t;

#define MAX_EVENT_CTXS 3
struct _fd_opset {
  eventer_fd_accept_t accept;
  eventer_fd_read_t   read;
  eventer_fd_write_t  write;
  eventer_fd_close_t  close;
  eventer_fd_set_opset_t set_opset;
  eventer_fd_get_opset_ctx_t get_opset_ctx;
  eventer_fd_set_opset_ctx_t set_opset_ctx;
  const char *name;
};

#define EVENTER_STRUCT(name) \
struct name { \
  eventer_func_t      callback; \
  struct timeval      whence; \
  int                 fd; \
  int                 mask; \
  struct _fd_opset   *opset; \
  void               *opset_ctx; \
  void               *closure; \
  pthread_t           thr_owner; \
  uint32_t            refcnt; \
  eventer_context_t   ctx[MAX_EVENT_CTXS]; \
}

EVENTER_STRUCT(_event);
EVENTER_STRUCT(_event_aco);

struct aco_cb_ctx {
  void *closure;
  int rv;
  int mask;
  int private_errno;
  mtev_memory_section_t section;

  struct timeval *timeout;
  eventer_t timeout_e;
};

int eventer_aco_resume(aco_t *co);

struct _eventer_job_t {
  pthread_mutex_t         lock;
  eventer_hrtime_t        create_hrtime;
  eventer_hrtime_t        start_hrtime;
  eventer_hrtime_t        finish_hrtime;
  struct timeval          finish_time;
  pthread_t               executor;
  eventer_t               timeout_event;
  eventer_t               fd_event;
  uint64_t                subqueue;
  int                     timeout_triggered; /* set, if it expires in-flight */
  uint32_t                inflight;
  uint32_t                has_cleanedup;
  void                  (*cleanup)(struct _eventer_job_t *);
  uint32_t                dependents;
  struct _eventer_job_t  *waiting;
  struct _eventer_job_t  *next;
  struct _eventer_jobq_t *jobq;
  struct _eventer_jobsq_t *squeue;
};

typedef struct _eventer_jobsq_t {
  uint64_t                subqueue;
  uint32_t                inflight;
  eventer_job_t          *headq;
  eventer_job_t          *tailq;
  struct _eventer_jobsq_t *prev, *next;
} eventer_jobsq_t;

struct _eventer_jobq_t {
  const char             *queue_name;
  const char             *short_name;
  pthread_mutex_t         lock;
  int64_t                 consumer_jobs;
  pthread_mutex_t         consumer_lock;
  pthread_cond_t          consumer_signal;
  uint32_t                concurrency;
  uint32_t                desired_concurrency;
  uint32_t                pending_cancels;
  uint32_t                subqueue_count;
  ck_hs_t                *subqueues;
  eventer_jobsq_t        *current_squeue;
  /* This isn't just doubly-linked,
   * it is circular w/ queue as a fixed participant. */
  eventer_jobsq_t         queue;
  pthread_key_t           threadenv;
  pthread_key_t           activejob;
  uint32_t                backlog;
  uint32_t                inflight;
  uint64_t                total_jobs;
  uint64_t                timeouts;
  uint64_t                avg_wait_ns; /* smoother alpha = 0.8 */
  uint64_t                avg_run_ns; /* smoother alpha = 0.8 */
  stats_handle_t         *wait_latency;
  stats_handle_t         *run_latency;
  eventer_jobq_memory_safety_t mem_safety;
  mtev_boolean            isbackq;
  uint32_t                floor_concurrency;
  uint32_t                min_concurrency;
  uint32_t                max_concurrency;
  uint32_t                max_backlog;
  mtev_log_stream_t       callback_tracker;
  const mtev_boolean     *lifo;
  uint32_t                consumer_threads_running;
  /* shutdown_state should use one of these defines,
   * defined above:
   * EVENTER_JOBQ_RUNNING
   * EVENTER_JOBQ_SHUTTING_DOWN
   * EVENTER_JOBQ_SHUT_DOWN
   * This could be done via an enum, but this is accessed
   * via multiple threads, so we want to make sure we can
   * use atomic load/set functions to access this - hence
   * the uint8_t */
  uint8_t                 shutdown_state;
};

#ifdef LOCAL_EVENTER

typedef enum { EV_OWNED, EV_ALREADY_OWNED } ev_lock_state_t;
static ev_lock_state_t
acquire_master_fd(int fd) {
  if(ck_spinlock_trylock(&master_fds[fd].lock)) {
    master_fds[fd].executor = pthread_self();
    return EV_OWNED;
  }
  if(pthread_equal(master_fds[fd].executor, pthread_self())) {
    return EV_ALREADY_OWNED;
  }
  ck_spinlock_lock(&master_fds[fd].lock);
  master_fds[fd].executor = pthread_self();
  return EV_OWNED;
}
static void
release_master_fd(int fd, ev_lock_state_t as) {
  if(as == EV_OWNED) {
    memset(&master_fds[fd].executor, 0, sizeof(master_fds[fd].executor));
    ck_spinlock_unlock(&master_fds[fd].lock);
  }
}

static void
LOCAL_EVENTER_foreach_fdevent (void (*f)(eventer_t e, void *),
                               void *closure) {
  int fd;
  for(fd = 0; fd < maxfds; fd++) {
    ev_lock_state_t ls;
    ls = acquire_master_fd(fd);
    if(master_fds[fd].e) f(master_fds[fd].e, closure);
    release_master_fd(fd, ls);
  }
}

#endif

void eventer_set_thread_name(const char *);
void eventer_set_thread_name_unsafe(const char *);
void eventer_wakeup_noop(eventer_t);
void eventer_cross_thread_trigger(eventer_t e, int mask);
void eventer_cross_thread_process(eventer_impl_data_t *);
void eventer_impl_init_globals(void);
void eventer_dispatch_recurrent(eventer_impl_data_t *);
void eventer_dispatch_timed(eventer_impl_data_t *, struct timeval *next);
void eventer_mark_callback_time(eventer_impl_data_t *t);
void eventer_set_this_event(eventer_t e);
void eventer_callback_prep(eventer_t, int, void *, struct timeval *);
void eventer_update_timed_internal(eventer_t e, int mask, struct timeval *);
void eventer_callback_cleanup(eventer_t, int);

static inline void eventer_adjust_max_sleeptime(struct timeval *dur) {
  struct timeval ht;
  if(eventer_watchdog_timeout_timeval(&ht)) {
    uint64_t us = ht.tv_sec * 1000000 + ht.tv_usec;
    us /= 20;
    ht.tv_sec = us / 1000000;
    ht.tv_usec = us % 1000000;
    if(compare_timeval(ht, *dur) < 0) {
      *dur = ht;
    }
  }
}

extern stats_ns_t *eventer_stats_ns;
extern stats_handle_t *eventer_callback_latency_orphaned;
extern __thread stats_handle_t *eventer_callback_pool_latency;
extern stats_handle_t *eventer_unnamed_callback_latency;
#define eventer_callback_latency (eventer_callback_pool_latency ? eventer_callback_pool_latency : eventer_callback_latency_orphaned)
stats_handle_t *eventer_latency_handle_for_callback(eventer_func_t f);

int eventer_jobq_init_internal(eventer_jobq_t *jobq, const char *queue_name);
const char *eventer_thread_name(pthread_t tid);
eventer_job_t *eventer_current_job(void);
void eventer_heartbeat(void);
void eventer_jobq_ping(eventer_jobq_t *jobq);
void eventer_aco_init(void);
void *eventer_aco_get_opset_ctx(void *closure);
struct _fd_opset *eventer_aco_get_opset(void *closure);
mtev_boolean eventer_is_aco_opset(eventer_t e);
int eventer_aco_shutdown(aco_t *co);
void posix_asynch_shutdown_close(int fd);
void set_callback_tracker_log(mtev_log_stream_t ls);

#ifdef __cplusplus
}
#endif

#endif
