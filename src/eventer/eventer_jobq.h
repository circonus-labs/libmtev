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

#ifndef _MTEV_JOBQUEUE_H
#define _MTEV_JOBQUEUE_H

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "mtev_sem.h"
#include "mtev_stats.h"

#include <pthread.h>
#include <setjmp.h>

/*
 * This is for jobs that would block and need more forceful timeouts.
 */

typedef struct _eventer_job_t {
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
} eventer_job_t;

typedef enum {
  EVENTER_JOBQ_MS_CS,  /* manages init, critical sections, and gc */
  EVENTER_JOBQ_MS_GC,  /* manages init, and gc */
  EVENTER_JOBQ_MS_NONE /* managed nothing at all */
} eventer_jobq_memory_safety_t;

typedef struct _eventer_jobq_t {
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
} eventer_jobq_t;

int eventer_jobq_init(eventer_jobq_t *jobq, const char *queue_name);
int eventer_jobq_init_backq(eventer_jobq_t *jobq, const char *queue_name);
int eventer_jobq_init_ms(eventer_jobq_t *jobq, const char *queue_name,
                         eventer_jobq_memory_safety_t);
eventer_jobq_t *eventer_jobq_retrieve(const char *name);
void eventer_jobq_enqueue(eventer_jobq_t *jobq, eventer_job_t *job);
eventer_job_t *eventer_jobq_dequeue(eventer_jobq_t *jobq);
eventer_job_t *eventer_jobq_dequeue_nowait(eventer_jobq_t *jobq);
void eventer_jobq_destroy(eventer_jobq_t *jobq);
int eventer_jobq_execute_timeout(eventer_t e, int mask, void *closure,
                                 struct timeval *now);
int eventer_jobq_consume_available(eventer_t e, int mask, void *closure,
                                   struct timeval *now);
void eventer_jobq_set_concurrency(eventer_jobq_t *jobq, uint32_t new_concurrency);
void eventer_jobq_set_min_max(eventer_jobq_t *jobq, uint32_t min, uint32_t max);
void eventer_jobq_increase_concurrency(eventer_jobq_t *jobq);
void eventer_jobq_decrease_concurrency(eventer_jobq_t *jobq);
void *eventer_jobq_consumer(eventer_jobq_t *jobq);
void eventer_jobq_process_each(void (*func)(eventer_jobq_t *, void *), void *);
void eventer_jobq_init_globals();

#endif
