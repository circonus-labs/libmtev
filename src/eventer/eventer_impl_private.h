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

#include "mtev_stats.h"

struct _eventer_job_t {
  pthread_mutex_t         lock;
  eventer_hrtime_t        create_hrtime;
  eventer_hrtime_t        start_hrtime;
  eventer_hrtime_t        finish_hrtime;
  struct timeval          finish_time;
  pthread_t               executor;
  eventer_t               timeout_event;
  eventer_t               fd_event;
  int                     timeout_triggered; /* set, if it expires in-flight */
  uint32_t                inflight;
  uint32_t                has_cleanedup;
  void                  (*cleanup)(struct _eventer_job_t *);
  struct _eventer_job_t  *next;
  struct _eventer_jobq_t *jobq;
};

struct _eventer_jobq_t {
  const char             *queue_name;
  pthread_mutex_t         lock;
  sem_t                   semaphore;
  uint32_t                concurrency;
  uint32_t                desired_concurrency;
  uint32_t                pending_cancels;
  eventer_job_t          *headq;
  eventer_job_t          *tailq;
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
  uint32_t                min_concurrency;
  uint32_t                max_concurrency;
};

#ifdef LOCAL_EVENTER

typedef enum { EV_OWNED, EV_ALREADY_OWNED } ev_lock_state_t;
static ev_lock_state_t
acquire_master_fd(int fd) {
  if(mtev_spinlock_trylock(&master_fds[fd].lock)) {
    master_fds[fd].executor = pthread_self();
    return EV_OWNED;
  }
  if(pthread_equal(master_fds[fd].executor, pthread_self())) {
    return EV_ALREADY_OWNED;
  }
  mtev_spinlock_lock(&master_fds[fd].lock);
  master_fds[fd].executor = pthread_self();
  return EV_OWNED;
}
static void
release_master_fd(int fd, ev_lock_state_t as) {
  if(as == EV_OWNED) {
    memset(&master_fds[fd].executor, 0, sizeof(master_fds[fd].executor));
    mtev_spinlock_unlock(&master_fds[fd].lock);
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

void eventer_wakeup_noop(eventer_t);
void eventer_cross_thread_trigger(eventer_t e, int mask);
void eventer_cross_thread_process();
void eventer_impl_init_globals();

extern stats_ns_t *eventer_stats_ns;
extern stats_handle_t *eventer_callback_latency;
extern stats_handle_t *eventer_unnamed_callback_latency;
stats_handle_t *eventer_latency_handle_for_callback(eventer_func_t f);

int eventer_jobq_init_internal(eventer_jobq_t *jobq, const char *queue_name);
