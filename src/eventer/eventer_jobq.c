/*
 * Copyright (c) 2014-2016, Circonus, Inc. All rights reserved.
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
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
#include "mtev_memory.h"
#include "mtev_log.h"
#include "mtev_thread.h"
#include "mtev_rand.h"
#include "mtev_sem.h"
#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "libmtev_dtrace.h"
#include <errno.h>
#include <setjmp.h>
#include <signal.h>

#ifndef JOBQ_SIGNAL
#define JOBQ_SIGNAL SIGALRM
#endif
#define THREAD_IDLE_NS (1000000000ULL * 5)

#define pthread_self_ptr() ((void *)(intptr_t)pthread_self())

static uint32_t threads_jobq_inited = 0;
static pthread_key_t threads_jobq;
static sigset_t alarm_mask;
static mtev_hash_table all_queues;
static __thread eventer_job_t *current_job;
pthread_mutex_t all_queues_lock;
mtev_boolean jobq_lifo_default = mtev_false;
static mtev_boolean jobq_lifo_true = mtev_true;
static mtev_boolean jobq_lifo_false = mtev_false;

eventer_job_t *
eventer_current_job(void) {
  return current_job;
}

static void
eventer_jobq_queue_completion(eventer_job_t *job) {
  struct _event wakeupcopy;
  bool done;

  ck_pr_dec_32_zero(&job->dependents, &done);
  if(done) {
    if(job->waiting)
      eventer_jobq_queue_completion(job->waiting);
    memcpy(&wakeupcopy, job->fd_event, sizeof(wakeupcopy));
    /* All backq completion jobs do not use subqueues */
    job->subqueue = 0;
    eventer_jobq_enqueue(eventer_default_backq(job->fd_event), job, NULL);
    eventer_wakeup(&wakeupcopy);
  }
}
static unsigned long
__ck_hash_from_uint64(const void *key, unsigned long seed) {
  unsigned long v = *(uint64_t *)key;
  return v^seed;
}
static bool
__ck_hash_compare_uint64(const void *a, const void *b) {
  return *(uint64_t *)a == *(uint64_t *)b;
}
static void *
gen_malloc(size_t r)
{
  return malloc(r);
}

static void
gen_free(void *p, size_t b, bool r)
{
  (void)b;
  (void)r;
  free(p);
  return;
}
static struct ck_malloc malloc_ck_hs = {
  .malloc = gen_malloc,
  .free = gen_free
};
static void
eventer_jobq_consumer_notify(eventer_jobq_t *jobq) {
  int64_t consumer_jobs;

  pthread_mutex_lock(&jobq->consumer_lock);
  jobq->consumer_jobs++;
  consumer_jobs = jobq->consumer_jobs;
  pthread_mutex_unlock(&jobq->consumer_lock);

  mtevAssert(consumer_jobs >= 0);

  if (consumer_jobs == 1) {
    pthread_cond_signal(&jobq->consumer_signal);
  } else {
    pthread_cond_broadcast(&jobq->consumer_signal);
  }
}
static void
eventer_jobq_consumer_wait(eventer_jobq_t *jobq) {
  pthread_mutex_lock(&jobq->consumer_lock);

  while (jobq->consumer_jobs == 0) {
    pthread_cond_wait(&jobq->consumer_signal, &jobq->consumer_lock);
  }

  jobq->consumer_jobs--;
  mtevAssert(jobq->consumer_jobs >= 0);
  pthread_mutex_unlock(&jobq->consumer_lock);
}
static bool
eventer_jobq_consumer_try_wait(eventer_jobq_t *jobq) {
  if (pthread_mutex_trylock(&jobq->consumer_lock) == 0) {
    if (jobq->consumer_jobs == 0) {
      pthread_mutex_unlock(&jobq->consumer_lock);
      return false;
    }

    jobq->consumer_jobs--;
    mtevAssert(jobq->consumer_jobs >= 0);
    pthread_mutex_unlock(&jobq->consumer_lock);
    return true;
  }

  return false;
}
static eventer_jobsq_t *
eventer_jobq_get_sq_nolock(eventer_jobq_t *jobq, uint64_t subqueue) {
  if(subqueue == 0) return &jobq->queue;

  if(!jobq->subqueues) {
    jobq->subqueues = calloc(1, sizeof(*jobq->subqueues));
    if(ck_hs_init(jobq->subqueues,
                  CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE | CK_HS_MODE_SPMC,
                  __ck_hash_from_uint64, __ck_hash_compare_uint64,
                  &malloc_ck_hs, 100, mtev_rand()) == false) {
      mtevFatal(mtev_error, "Cannot initialize ck_hs\n");
    }
  }
  unsigned long hash = CK_HS_HASH(jobq->subqueues, __ck_hash_from_uint64, &subqueue);
  void *entry = ck_hs_get(jobq->subqueues, hash, &subqueue);
  if(entry) return (eventer_jobsq_t *)entry;
  eventer_jobsq_t *squeue = calloc(1, sizeof(*squeue));
  squeue->subqueue = subqueue;
  mtevEvalAssert(ck_hs_set(jobq->subqueues, hash, &squeue->subqueue, &entry));
  mtevAssert(entry == NULL);
  jobq->subqueue_count++;
  /* Insert this jobsq in front of the fixed queue */
  squeue->next = jobq->queue.next;
  jobq->queue.next = squeue;
  squeue->prev = squeue->next->prev;
  squeue->next->prev = squeue;
  return squeue;
}

static void
mark_squeue_job_completed(eventer_jobq_t *jobq, eventer_job_t *job) {
  bool done;
  if(job->squeue != &jobq->queue) {
    eventer_jobsq_t *squeue = job->squeue;
    pthread_mutex_lock(&jobq->lock);
    ck_pr_dec_32_zero(&job->squeue->inflight, &done);
    if(done && squeue->headq == NULL) {
      /* There are no more jobs and we're not in the default subqueue...
       * tear it down. */
      /* squeue->prev must exist (because we're not &jobq->queue) */
      squeue->prev->next = squeue->next;
      squeue->next->prev = squeue->prev;
      unsigned long hash = CK_HS_HASH(jobq->subqueues, __ck_hash_from_uint64,
                                      &squeue->subqueue);
      void *entry = ck_hs_remove(jobq->subqueues, hash, &squeue->subqueue);
      mtevAssert(entry == squeue);
      jobq->subqueue_count--;
      /* If the current pointer for RR assignement is here, advance it */
      if(jobq->current_squeue == squeue) jobq->current_squeue = squeue->next;

      free(squeue);
    }
    pthread_mutex_unlock(&jobq->lock);
  }
}
static void
eventer_jobq_finished_job(eventer_jobq_t *jobq, eventer_job_t *job) {
  int ntries;
  eventer_hrtime_t wait_time, run_time;
  mark_squeue_job_completed(jobq, job);
  ck_pr_dec_32(&jobq->inflight);
  if(job->create_hrtime > job->start_hrtime) wait_time = 0;
  else wait_time = job->start_hrtime - job->create_hrtime;
  if(job->start_hrtime > job->finish_hrtime) run_time = 0;
  else run_time = job->finish_hrtime - job->start_hrtime;
  stats_set_hist_intscale(jobq->wait_latency, wait_time, -9, 1);
  stats_set_hist_intscale(jobq->run_latency, run_time, -9, 1);
  if(job->timeout_triggered) ck_pr_inc_64(&jobq->timeouts);
  for(ntries = 0; ntries < 100; ntries++) {
    uint64_t current_avg_wait_ns = ck_pr_load_64((uint64_t *)&jobq->avg_wait_ns);
    eventer_hrtime_t newv = current_avg_wait_ns * 0.8 + wait_time * 0.2;
    if(ck_pr_cas_64(&jobq->avg_wait_ns, current_avg_wait_ns, newv))
      break;
  }
  for(ntries = 0; ntries < 100; ntries++) {
    uint64_t current_avg_run_ns = ck_pr_load_64((uint64_t *)&jobq->avg_run_ns);
    eventer_hrtime_t newv = current_avg_run_ns * 0.8 + run_time * 0.2;
    if(ck_pr_cas_64(&jobq->avg_run_ns, current_avg_run_ns, newv))
      break;
  }

  /* Actually finish the job up -- schedule completion on the backq */
  eventer_jobq_queue_completion(job);
}

static void
eventer_jobq_handler(int signo)
{
  (void)signo;
  eventer_jobq_t *jobq;
  eventer_job_t *job;
  sigjmp_buf *env;

  jobq = pthread_getspecific(threads_jobq);
  mtevAssert(jobq);
  env = pthread_getspecific(jobq->threadenv);
  job = pthread_getspecific(jobq->activejob);
  if(env && job && job->fd_event && job->fd_event->mask & EVENTER_EVIL_BRUTAL)
    if(ck_pr_cas_32(&job->inflight, 1, 0))
       siglongjmp(*env, 1);
}

eventer_job_t *eventer_jobq_inflight(void) {
  eventer_jobq_t *jobq = pthread_getspecific(threads_jobq);
  mtevAssert(jobq);
  return pthread_getspecific(jobq->activejob);
}
static eventer_jobq_t *
eventer_jobq_create_internal(const char *queue_name, eventer_jobq_memory_safety_t mem_safety, mtev_boolean isbackq) {
  eventer_jobq_t *jobq;
  stats_ns_t *jobq_ns;
  pthread_mutexattr_t mutexattr;

  if(ck_pr_cas_32(&threads_jobq_inited, 0, 1)) {
    struct sigaction act;

    sigemptyset(&alarm_mask);
    sigaddset(&alarm_mask, JOBQ_SIGNAL);
    act.sa_handler = eventer_jobq_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);

    if(sigaction(JOBQ_SIGNAL, &act, NULL) < 0) {
      mtevFatal(mtev_error, "Cannot initialize signal handler: %s\n",
                strerror(errno));
    }

    if(pthread_key_create(&threads_jobq, NULL)) {
      mtevFatal(mtev_error, "Cannot initialize thread-specific jobq: %s\n",
                strerror(errno));
    }
    if(pthread_mutex_init(&all_queues_lock, NULL)) {
      mtevFatal(mtev_error, "Cannot initialize all_queues mutex: %s\n",
                strerror(errno));
    }
  }

  pthread_mutex_lock(&all_queues_lock);
  void *vjobq;
  if(mtev_hash_retrieve(&all_queues, queue_name, strlen(queue_name),
                        &vjobq)) {
    jobq = vjobq;
    mtevAssert(!strcmp(queue_name, jobq->queue_name));
    mtevAssert(isbackq == jobq->isbackq);
    if(mem_safety != jobq->mem_safety) {
      if(jobq->concurrency == 0) jobq->mem_safety = mem_safety;
      else jobq = NULL;
    }
    pthread_mutex_unlock(&all_queues_lock);
    return jobq;
  }
  jobq = calloc(1, sizeof(*jobq));
  jobq->subqueue_count = 1;
  jobq->current_squeue = jobq->queue.next = jobq->queue.prev = &jobq->queue;
  jobq->queue_name = strdup(queue_name);
  jobq->mem_safety = mem_safety;
  jobq->isbackq = isbackq;
  jobq->lifo = &jobq_lifo_default;
  ck_pr_store_8(&jobq->shutdown_state, EVENTER_JOBQ_RUNNING);
  jobq->consumer_threads_running = 0;
  if(!jobq->isbackq)
    jobq->callback_tracker = mtev_log_stream_findf("debug/eventer/callbacks/jobq/%s", queue_name);
  if(pthread_mutexattr_init(&mutexattr) != 0) {
    mtevL(mtev_error, "Cannot initialize lock attributes\n");
    goto error_out;
  }
  if(pthread_mutex_init(&jobq->lock, &mutexattr) != 0) {
    mtevL(mtev_error, "Cannot initialize lock\n");
    goto error_out;
  }
  if (pthread_mutex_init(&jobq->consumer_lock, NULL) != 0) {
    mtevL(mtev_error, "Cannot initialize consumer_lock\n");
    goto error_out;
  }
  pthread_cond_init(&jobq->consumer_signal, NULL);
  if(pthread_key_create(&jobq->activejob, NULL)) {
    mtevL(mtev_error, "Cannot initialize thread-specific activejob: %s\n",
          strerror(errno));
    goto error_out;
  }
  if(pthread_key_create(&jobq->threadenv, NULL)) {
    mtevL(mtev_error, "Cannot initialize thread-specific sigsetjmp env: %s\n",
          strerror(errno));
    goto error_out;
  }
  if(mtev_hash_store(&all_queues, jobq->queue_name, strlen(jobq->queue_name),
                     jobq) == 0) {
    mtevFatal(mtev_error, "Duplicate queue named!\n");
  }
  if(!jobq->isbackq) {
    jobq_ns = mtev_stats_ns(mtev_stats_ns(eventer_stats_ns, "jobq"), jobq->queue_name);
    stats_ns_add_tag(jobq_ns, "mtev-jobq", jobq->queue_name);
    jobq->wait_latency = stats_register(jobq_ns, "wait", STATS_TYPE_HISTOGRAM);
    stats_handle_units(jobq->wait_latency, STATS_UNITS_SECONDS);
    jobq->run_latency = stats_register(jobq_ns, "latency", STATS_TYPE_HISTOGRAM);
    stats_handle_units(jobq->run_latency, STATS_UNITS_SECONDS);
    jobq->desired_concurrency = 1;
    stats_set_str(stats_register(jobq_ns, "mem_safety", STATS_TYPE_STRING),
                  eventer_jobq_memory_safety_name(jobq->mem_safety));
    stats_handle_t *h;
    h = stats_rob_u32(jobq_ns, "concurrency", (void *)&jobq->concurrency);
    stats_handle_units(h, "threads");
    h = stats_rob_u32(jobq_ns, "desired_concurrency", (void *)&jobq->desired_concurrency);
    stats_handle_units(h, "threads");
    h = stats_rob_u32(jobq_ns, "floor_concurrency", (void *)&jobq->floor_concurrency);
    stats_handle_units(h, "threads");
    h = stats_rob_u32(jobq_ns, "min_concurrency", (void *)&jobq->min_concurrency);
    stats_handle_units(h, "threads");
    h = stats_rob_u32(jobq_ns, "max_concurrency", (void *)&jobq->max_concurrency);
    stats_handle_units(h, "threads");
    h = stats_rob_u32(jobq_ns, "backlog", (void *)&jobq->backlog);
    stats_handle_units(h, "jobs");
    h = stats_rob_u32(jobq_ns, "max_backlog", (void *)&jobq->max_backlog);
    stats_handle_units(h, "jobs");
    h = stats_rob_u64(jobq_ns, "timeouts", (void *)&jobq->timeouts);
    stats_handle_units(h, "jobs");
    h = stats_rob_u64(jobq_ns, "total_jobs", (void *)&jobq->total_jobs);
    stats_handle_units(h, "jobs");
  }
  pthread_mutex_unlock(&all_queues_lock);
  return jobq;

 error_out:
  free((void *)jobq->queue_name);
  free((void *)jobq);
  pthread_mutex_unlock(&all_queues_lock);
  return NULL;

}

eventer_jobq_t *
eventer_jobq_create_backq(const char *queue_name) {
  return eventer_jobq_create_internal(queue_name, EVENTER_JOBQ_MS_GC, mtev_true);
}
eventer_jobq_t *
eventer_jobq_create_ms(const char *queue_name,
                       eventer_jobq_memory_safety_t ms) {
  return eventer_jobq_create_internal(queue_name, ms, mtev_false);
}
eventer_jobq_t *
eventer_jobq_create(const char *queue_name) {
  return eventer_jobq_create_internal(queue_name, EVENTER_JOBQ_MS_GC, mtev_false);
}

eventer_jobq_t *
eventer_jobq_retrieve(const char *name) {
  void *vjq = NULL;
  pthread_mutex_lock(&all_queues_lock);
  (void)mtev_hash_retrieve(&all_queues, name, strlen(name), &vjq);
  pthread_mutex_unlock(&all_queues_lock);
  return vjq;
}

static void *
eventer_jobq_consumer_pthreadentry(void *vp) {
  eventer_jobq_t *jobq = vp;
  char thr_name[64];
  const char *name = jobq->short_name ? jobq->short_name : jobq->queue_name;
  snprintf(thr_name, sizeof(thr_name), "q:%s", name);
  set_callback_tracker_log(jobq->callback_tracker);
  if(jobq->mem_safety != EVENTER_JOBQ_MS_NONE) {
    mtev_memory_init_thread();
    eventer_set_thread_name(thr_name);
  }
  else {
    eventer_set_thread_name_unsafe(thr_name);
  }
  return eventer_jobq_consumer(jobq);
}
static void
eventer_jobq_maybe_spawn(eventer_jobq_t *jobq, int bump) {
  /* if we've no desired concurrency, this doesn't apply to us */
  if(jobq->desired_concurrency == 0) return;
  /* If we have none, we definitely should launch a thread.
   * otherwise we should check that all current threads are inflight
   * and ensure we don't jump past our desired_concurrency.
   */
  int32_t current = ck_pr_load_32(&jobq->concurrency);
  int32_t backlog = ck_pr_load_32(&jobq->backlog) + bump;
  int32_t inflight = ck_pr_load_32(&jobq->inflight);
  if(current == 0 || (current < (int32_t)jobq->desired_concurrency && current < (backlog + inflight))) {
    /* we need another thread, maybe... this is a race as we do the
     * increment in the new thread, but we check there and back it out
     * if we did something we weren't supposed to. */
    pthread_t tid;
    pthread_attr_t tattr;
    mtevL(eventer_deb, "Starting queue[%s] thread now at %d\n",
          jobq->queue_name, jobq->concurrency);
    pthread_attr_init(&tattr);
    pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &tattr, eventer_jobq_consumer_pthreadentry, jobq);
  }
  mtevL(eventer_deb, "jobq_queue[%s] pending cancels [%d/%d]\n",
        jobq->queue_name, jobq->pending_cancels,
        jobq->desired_concurrency);
  if(jobq->pending_cancels == jobq->desired_concurrency) {
    /* we're absolutely screwed at this point... it's time to just die */
    mtevL(mtev_error, "jobq_queue[%s] induced [%d/%d] game over.\n",
          jobq->queue_name, jobq->pending_cancels,
          jobq->desired_concurrency);
    mtevAssert(jobq->pending_cancels != jobq->desired_concurrency);
  }
}

void
eventer_jobq_enqueue_internal(eventer_jobq_t *jobq, eventer_job_t *job, eventer_job_t *parent) {
  if(job->fd_event) ck_pr_inc_64(&jobq->total_jobs);
  mtevL(eventer_deb, "jobq %p enqueue job [%p]\n", jobq, job);

  /* If the parent is not NULL, setup a dependency */
  if(parent) {
    ck_pr_inc_32(&parent->dependents);
    job->waiting = parent;
  }

  eventer_jobq_maybe_spawn(jobq, 1);
  pthread_mutex_lock(&jobq->lock);
  job->squeue = eventer_jobq_get_sq_nolock(jobq, job->subqueue);
  if(*jobq->lifo) {
    job->next = job->squeue->headq;
    job->squeue->headq = job;
  } else {
    if(job->squeue->tailq) {
      /* If there is a tail (queue has items), just push it on the end. */
      job->squeue->tailq->next = job;
      job->squeue->tailq = job;
    }
    else {
      /* Otherwise, this is the first and only item on the list. */
      job->squeue->headq = job->squeue->tailq = job;
    }
  }
  pthread_mutex_unlock(&jobq->lock);

  /* Signal consumers */
  eventer_jobq_consumer_notify(jobq);
}

mtev_boolean
eventer_jobq_try_enqueue(eventer_jobq_t *jobq, eventer_job_t *job, eventer_job_t *parent) {
  job->next = NULL;
  if (ck_pr_load_8(&jobq->shutdown_state) != EVENTER_JOBQ_RUNNING) {
    free(job);
    return mtev_false;
  }
  /* Do not increase the concurrency from zero for a noop */
  if(ck_pr_load_32(&jobq->concurrency) == 0 && job->fd_event == NULL) {
    free(job);
    return mtev_true;
  }
  if(job->fd_event) {
   if(jobq->max_backlog) {
     /* Enforce a quick failure */
     uint32_t bl;
     do {
       bl = ck_pr_load_32(&jobq->backlog);
       if(bl >= jobq->max_backlog) {
         free(job);
         return mtev_false;
       }
     } while(!ck_pr_cas_32(&jobq->backlog, bl, bl+1));
   }
   else ck_pr_inc_32(&jobq->backlog);
  }
  eventer_jobq_enqueue_internal(jobq, job, parent);
  return mtev_true;
}

void
eventer_jobq_enqueue(eventer_jobq_t *jobq, eventer_job_t *job, eventer_job_t *parent) {
  /* If we're shutting down, we shouldn't be attempting to add jobs to it.
   * If the user isn't using eventer_jobq_try_enqueue to catch errors, we
   * should just assert */
  mtevAssert(ck_pr_load_8(&jobq->shutdown_state) == EVENTER_JOBQ_RUNNING);
  job->next = NULL;
  /* Do not increase the concurrency from zero for a noop */
  if(ck_pr_load_32(&jobq->concurrency) == 0 && job->fd_event == NULL) {
    free(job);
    return;
  }
  if(job->fd_event) ck_pr_inc_32(&jobq->backlog);
  eventer_jobq_enqueue_internal(jobq, job, parent);
}

static eventer_job_t *
__eventer_jobq_dequeue(eventer_jobq_t *jobq, int should_wait) {
  eventer_job_t *job = NULL;
  int cycles = 0;

  /* Wait for a job */
  if (should_wait) {
    eventer_jobq_consumer_wait(jobq);
  }
  /* Or Try-wait for a job */
  else if (!eventer_jobq_consumer_try_wait(jobq)) {
    return NULL;
  }

  pthread_mutex_lock(&jobq->lock);
  eventer_jobsq_t *starting_point = jobq->current_squeue;
  uint32_t tgt_inflight = 0;
  /* We're going to spin around our work queues aiming for a balance
   * of inflight jobs per queue.
   * First choose the next queue with <= (concurrent/queues) inflight jobs.
   * There are possible rounding errors, so next bump by one and repeat.
   * If we have no jobs it means some of the queues have no more work,
   * so we run one last time with no inflight limit.
   */
  while(job == NULL) {
    eventer_jobsq_t *squeue = jobq->current_squeue;
    if(squeue == starting_point) {
      cycles++;
      tgt_inflight = (jobq->concurrency / jobq->subqueue_count);
      if(cycles == 1 && tgt_inflight == 0) {
        cycles = 2; tgt_inflight = 1;
      }

      if(cycles == 1) tgt_inflight--;
      else if(cycles == 2) (void)tgt_inflight; /* no op */
      else if(cycles == 3) tgt_inflight = UINT32_MAX;
      else break;
    }
    if(squeue->headq && squeue->inflight < tgt_inflight) {
      /* If there are items, pop and advance the header pointer */
      job = squeue->headq;
      squeue->headq = squeue->headq->next;
      if(!squeue->headq) squeue->tailq = NULL;
    }
    jobq->current_squeue = jobq->current_squeue->next;
  }
  if(job) ck_pr_inc_32(&job->squeue->inflight);
  pthread_mutex_unlock(&jobq->lock);

  if(job) {
    job->next = NULL; /* To reduce any confusion */
    if(job->fd_event) ck_pr_dec_32(&jobq->backlog);
    ck_pr_inc_32(&jobq->inflight);
  }
  /* Our semaphores are counting semaphores, not locks. */
  /* coverity[missing_unlock] */
  return job;
}

eventer_job_t *
eventer_jobq_dequeue(eventer_jobq_t *jobq) {
  return __eventer_jobq_dequeue(jobq, 1);
}

eventer_job_t *
eventer_jobq_dequeue_nowait(eventer_jobq_t *jobq) {
  return __eventer_jobq_dequeue(jobq, 0);
}

void
eventer_jobq_destroy(eventer_jobq_t *jobq) {
  if (ck_pr_load_8(&jobq->shutdown_state) != EVENTER_JOBQ_SHUT_DOWN) {
    mtevL(mtev_error, "WARNING: Attempting to shut down jobq %s before draining/shutting down\n", jobq->queue_name);
  }
  pthread_mutex_lock(&all_queues_lock);
  mtev_hash_delete(&all_queues, jobq->queue_name, strlen(jobq->queue_name),
                   (NoitHashFreeFunc) free, 0);
  pthread_mutex_unlock(&all_queues_lock);

  if(jobq->subqueues) {
    ck_hs_iterator_t iterator = CK_HS_ITERATOR_INITIALIZER;
    void *entry;
    while(ck_hs_next(jobq->subqueues, &iterator, &entry)) {
      free(entry);
    }
    free(jobq->subqueues);
  }
  pthread_mutex_destroy(&jobq->lock);
  pthread_cond_destroy(&jobq->consumer_signal);
  pthread_mutex_destroy(&jobq->consumer_lock);
  if(jobq->short_name) mtev_memory_safe_free((void *)jobq->short_name);
  free(jobq);
}

void
eventer_jobq_drain_and_shutdown(eventer_jobq_t *jobq) {
  int64_t todo = 0;

  eventer_jobq_set_min_max(jobq, 0, 0);
  eventer_jobq_set_concurrency(jobq, 0);

  ck_pr_store_8(&jobq->shutdown_state, EVENTER_JOBQ_SHUTTING_DOWN);

  /* Wait until there's nothing either in flight or in the backlog */
  while (1) {
    todo = ck_pr_load_32(&jobq->backlog) + ck_pr_load_32(&jobq->inflight);
    if (!todo) {
      break;
    }
    usleep(100);
  }

  /* Wait for concurrency to hit zero */
  while (1) {
    todo = ck_pr_load_32(&jobq->concurrency);
    if (!todo) {
      break;
    }
    usleep(100);
  }

  /* Wait for all the consumer threads to exit */
  while (1) {
    todo = ck_pr_load_32(&jobq->consumer_threads_running);
    if (!todo) {
      break;
    }
    usleep(100);
  }

  ck_pr_store_8(&jobq->shutdown_state, EVENTER_JOBQ_SHUT_DOWN);
}

int
eventer_jobq_execute_timeout(eventer_t e, int mask, void *closure,
                             struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  eventer_job_t *job = closure;
  job->timeout_triggered = 1;
  job->timeout_event = NULL;
  mtevL(eventer_deb, "%p jobq -> timeout job [%p]\n", pthread_self_ptr(), job);
  if(job->inflight) {
    eventer_job_t *jobcopy;
    if(job->fd_event && (job->fd_event->mask & EVENTER_CANCEL)) {
      eventer_t my_precious = job->fd_event;
      /* we set this to null so we can't complete on it */
      job->fd_event = NULL;
      mtevL(eventer_deb, "[inline] timeout cancelling job\n");
      ck_pr_inc_32(&job->jobq->pending_cancels);
      pthread_cancel(job->executor);
      /* complete on it ourselves */
      if(ck_pr_cas_32(&job->has_cleanedup, 0, 1)) {
        /* We need to cleanup... we haven't done it yet. */
        mtevL(eventer_deb, "[inline] %p jobq[%s] -> cleanup [%p]\n",
              pthread_self_ptr(), job->jobq->queue_name, job);
        /* This is the real question... asynch cleanup is supposed to
         * be called asynch -- we're going to call it synchronously
         * I think this is a bad idea, but not cleaning up seems worse.
         * Because we're synchronous, if we hang, we'll be watchdogged.
         *
         * Uncooperative plugins/third-party libs can truly suck
         * one's soul out.
         */
        if(my_precious) {
          mtev_gettimeofday(&job->finish_time, NULL); /* We're done */
          current_job = job;
          stats_handle_t *lat = eventer_latency_handle_for_callback(my_precious->callback);
          LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)my_precious, (void *)my_precious->callback, NULL,
                                 my_precious->fd, my_precious->mask,
                                 EVENTER_ASYNCH_CLEANUP);
          eventer_set_this_event(my_precious);
          uint64_t duration;
          eventer_run_callback(my_precious->callback, my_precious, EVENTER_ASYNCH_CLEANUP,
                       my_precious->closure, &job->finish_time, lat ? &duration : NULL);
          eventer_set_this_event(NULL);
          LIBMTEV_EVENTER_CALLBACK_RETURN((void *)my_precious, (void *)my_precious->callback, NULL, -1);
          current_job = NULL;
          if(lat) stats_set_hist_intscale(lat, duration, -9, 1);
        }
      }
      jobcopy = malloc(sizeof(*jobcopy));
      memcpy(jobcopy, job, sizeof(*jobcopy));
      free(job);
      jobcopy->fd_event = my_precious;
      jobcopy->finish_hrtime = mtev_gethrtime();
      if(ck_pr_load_32(&jobcopy->jobq->concurrency) == 0)
        eventer_jobq_maybe_spawn(jobcopy->jobq, 0);
      eventer_jobq_finished_job(jobcopy->jobq, jobcopy);
    }
    else
      pthread_kill(job->executor, JOBQ_SIGNAL);
  }
  return 0;
}
int
eventer_jobq_consume_available(eventer_t e, int mask, void *closure,
                               struct timeval *now) {
  (void)e;
  (void)mask;
  eventer_jobq_t *jobq = closure;
  eventer_job_t *job;
  /* This can only be called with a backq jobq
   * (a standalone queue with no backq itself)
   */
  mtevAssert(jobq);
  int32_t max_amount = (int32_t)jobq->backlog;
  if(max_amount < 1) max_amount = 1;
  while((job = eventer_jobq_dequeue_nowait(jobq)) != NULL) {
    int newmask;
    max_amount--;
    if(job->fd_event) {
      uint64_t duration;
      if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_begin();
      current_job = job;
      LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)job->fd_event,
                             (void *)job->fd_event->callback, NULL,
                             job->fd_event->fd, job->fd_event->mask,
                             job->fd_event->mask);
      stats_handle_t *lat = eventer_latency_handle_for_callback(job->fd_event->callback);
      mtevL(eventer_deb, "jobq %p running job [%p]\n", jobq, job);
      newmask = eventer_run_callback(job->fd_event->callback, job->fd_event, job->fd_event->mask,
                             job->fd_event->closure, now, &duration);
      LIBMTEV_EVENTER_CALLBACK_RETURN((void *)job->fd_event,
                              (void *)job->fd_event->callback, NULL, newmask);
      current_job = NULL;
      mtevL(eventer_deb, "jobq %p completed job [%p]\n", jobq, job);
      stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
      if(lat) stats_set_hist_intscale(lat, duration, -9, 1);
      if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_end();
      if(!newmask) eventer_free(job->fd_event);
      else {
        job->fd_event->mask = newmask;
        eventer_add(job->fd_event);
      }
      job->fd_event = NULL;
    }
    mtevAssert(job->timeout_event == NULL);
    mtevAssert(job->subqueue == 0);
    /* Because subqueue == 0, there's nothing fancy to do; squeue is our static queue. */
    ck_pr_dec_32(&job->squeue->inflight);
    ck_pr_dec_32(&jobq->inflight);
    free(job);
    if(max_amount < 0) break;
  }
  return 0;
}
static void
eventer_jobq_cancel_cleanup(void *vp) {
  eventer_jobq_t *jobq = vp;
  ck_pr_dec_32(&jobq->pending_cancels);
  ck_pr_dec_32(&jobq->concurrency);
}
static mtev_boolean
jobq_thread_should_terminate(eventer_jobq_t *jobq, mtev_boolean want_reduce) {
  uint32_t have, want;
  while(1) {
    have = ck_pr_load_32(&jobq->concurrency);
    if(want_reduce) {
      want = ck_pr_load_32(&jobq->floor_concurrency);
    } else {
      want = ck_pr_load_32(&jobq->desired_concurrency);
    }
    if(have <= want) break;
    if(ck_pr_cas_32(&jobq->concurrency, have, have-1)) {
      mtevL(eventer_deb, "jobq[%s/%p] %s turn down.\n",
            jobq->queue_name, pthread_self_ptr(), want_reduce ? "implicit" : "explicit");
      return mtev_true;
    }
  }
  return mtev_false;
}
static int
wrap_sigsetjmp(sigjmp_buf env, int v) {
  return sigsetjmp(env,v);
}
void *
eventer_jobq_consumer(eventer_jobq_t *jobq) {
  eventer_job_t *job;
  uint32_t current_count;
  sigjmp_buf env;
  volatile mtev_hrtime_t last_job_hrtime = 0;

  ck_pr_inc_32(&jobq->consumer_threads_running);

  current_count = ck_pr_faa_32(&jobq->concurrency, 1) + 1;
  mtevL(eventer_deb, "jobq[%s/%p] -> %d\n", jobq->queue_name, pthread_self_ptr(), current_count);
  if(current_count > jobq->desired_concurrency) {
    mtevL(eventer_deb, "jobq[%s] over provisioned, backing out.",
          jobq->queue_name);
    ck_pr_dec_32(&jobq->concurrency);
    if(jobq->mem_safety != EVENTER_JOBQ_MS_NONE) {
      eventer_set_thread_name(NULL);
      mtev_memory_fini_thread();
    }
    ck_pr_dec_32(&jobq->consumer_threads_running);
    pthread_exit(NULL);
    return NULL;
  }
  /* Each thread can consume from only one queue */
  pthread_setspecific(threads_jobq, jobq);
  pthread_setspecific(jobq->threadenv, &env);
  pthread_cleanup_push(eventer_jobq_cancel_cleanup, jobq);

  if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_begin();
  while(1) {
    pthread_setspecific(jobq->activejob, NULL);
    if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_end();
    if(jobq->mem_safety != EVENTER_JOBQ_MS_NONE) mtev_memory_maintenance_ex(MTEV_MM_BARRIER_ASYNCH);
    job = eventer_jobq_dequeue(jobq);
    if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_begin();
    if(!job) continue;

    mtev_hrtime_t nowhr = mtev_gethrtime();
    if(!job->fd_event) {
      mark_squeue_job_completed(jobq, job);
      free(job);
      ck_pr_dec_32(&jobq->inflight);
      /* We might want to decrease our concurrency here */
      if(jobq_thread_should_terminate(jobq, mtev_false)) break;
      if(last_job_hrtime && ((uint64_t)nowhr - (uint64_t)last_job_hrtime > THREAD_IDLE_NS)) {
        if(jobq_thread_should_terminate(jobq, mtev_true)) break;
      }
      continue;
    }
    pthread_setspecific(jobq->activejob, job);
    ck_pr_inc_32(&job->dependents);
    mtevL(eventer_deb, "%p jobq[%s] -> running job [%p]\n", pthread_self_ptr(),
          jobq->queue_name, job);

    /* Mark our commencement */
    last_job_hrtime = nowhr;
    job->start_hrtime = nowhr;

    struct timeval now;
    mtev_gettimeofday(&now, NULL);
    /* If the job's event has a timeout, but isn't explicitly a cancelation event
     * then we just check once before invocation to "time it out". */
    if(0 == (job->fd_event->mask & EVENTER_CANCEL) &&
       job->fd_event->whence.tv_sec != 0 && job->fd_event->whence.tv_usec != 0 &&
       compare_timeval(job->fd_event->whence, now) < 0) {
      mtevAssert(job->timeout_event == NULL);
      job->timeout_triggered = 1;
    }

    /* Safely check and handle if we've timed out while in queue */
    pthread_mutex_lock(&job->lock);
    if(job->timeout_triggered) {
      volatile uint64_t duration;
      struct timeval diff;
      /* This happens if the timeout occurred before we even had the change
       * to pull the job off the queue.  We must be in bad shape here.
       */
      if(ck_pr_cas_32(&job->has_cleanedup, 0, 1)) {
        mtevL(eventer_deb, "%p jobq[%s] -> timeout before start [%p]\n",
              pthread_self_ptr(), jobq->queue_name, job);
        job->finish_hrtime = mtev_gethrtime();
        job->finish_time = now;
        sub_timeval(job->finish_time, job->fd_event->whence, &diff);
        stats_handle_t *lat = eventer_latency_handle_for_callback(job->fd_event->callback);
        current_job = job;
        LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)job->fd_event,
                             (void *)job->fd_event->callback, NULL,
                             job->fd_event->fd, job->fd_event->mask,
                             EVENTER_ASYNCH_CLEANUP);
        eventer_run_callback(job->fd_event->callback, job->fd_event, EVENTER_ASYNCH_CLEANUP,
                   job->fd_event->closure, &job->finish_time, lat ? (uint64_t *)&duration : NULL);
        LIBMTEV_EVENTER_CALLBACK_RETURN((void *)job->fd_event,
                              (void *)job->fd_event->callback, NULL, -1);
        current_job = NULL;
        if(lat) stats_set_hist_intscale(lat, duration, -9, 1);
        eventer_jobq_finished_job(jobq, job);
        pthread_mutex_unlock(&job->lock);
        continue;
      }
    }
    pthread_mutex_unlock(&job->lock);

    /* Run the job, if we timeout, will be killed with a JOBQ_SIGNAL from
     * the master thread.  We handle the alarm by longjmp'd out back here.
     */
    job->executor = pthread_self();
    if(0 == (job->fd_event->mask & EVENTER_EVIL_BRUTAL) ||
       wrap_sigsetjmp(env, 1) == 0) {
      /* We could get hit right here... (timeout and terminated from
       * another thread.  inflight isn't yet set (next line), so it
       * won't longjmp.  But timeout_triggered will be set... so we
       * should recheck that after we mark ourselves inflight.
       */
      if(ck_pr_cas_32(&job->inflight, 0, 1)) {
        if(!job->timeout_triggered) {
          mtevL(eventer_deb, "%p jobq[%s] -> executing [%p]\n",
                pthread_self_ptr(), jobq->queue_name, job);
          /* Choose the right cancellation policy (or none) */
          if(job->fd_event->mask & EVENTER_CANCEL_ASYNCH) {
            mtevL(eventer_deb, "PTHREAD_CANCEL_ASYNCHRONOUS\n");
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
          }
          else if(job->fd_event->mask & EVENTER_CANCEL_DEFERRED) {
            mtevL(eventer_deb, "PTHREAD_CANCEL_DEFERRED\n");
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
          }
          else {
            mtevL(eventer_deb, "PTHREAD_CANCEL_DISABLE\n");
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
          }
          /* run the job */
          volatile uint64_t duration;
          struct timeval start_time;
          mtev_gettimeofday(&start_time, NULL);
          mtevL(eventer_deb, "jobq[%s] -> dispatch BEGIN\n", jobq->queue_name);
          current_job = job;
          LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)job->fd_event,
                                 (void *)job->fd_event->callback, NULL,
                                 job->fd_event->fd, job->fd_event->mask,
                                 EVENTER_ASYNCH_WORK);
          stats_handle_t *lat = eventer_latency_handle_for_callback(job->fd_event->callback);
          eventer_run_callback(job->fd_event->callback, job->fd_event, EVENTER_ASYNCH_WORK,
                       job->fd_event->closure, &start_time, lat ? (uint64_t *)&duration : NULL);
          LIBMTEV_EVENTER_CALLBACK_RETURN((void *)job->fd_event,
                                  (void *)job->fd_event->callback, NULL, -1);
          current_job = NULL;
          if(lat) stats_set_hist_intscale(lat, duration, -9, 1);
          mtevL(eventer_deb, "jobq[%s] -> dispatch END\n", jobq->queue_name);
          if(job->fd_event && job->fd_event->mask & EVENTER_CANCEL)
            pthread_testcancel();
          /* reset the cancellation policy */
          pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
          pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        }
      }
    }

    job->inflight = 0;
    mtevL(eventer_deb, "%p jobq[%s] -> finished [%p]\n", pthread_self_ptr(),
          jobq->queue_name, job);
    /* No we know we won't have siglongjmp called on us */

    mtev_gettimeofday(&job->finish_time, NULL);
    if(job->timeout_event) {
      if(eventer_remove(job->timeout_event)) {
        eventer_free(job->timeout_event);
      }
    }
    job->timeout_event = NULL;

    if(ck_pr_cas_32(&job->has_cleanedup, 0, 1)) {
      /* We need to cleanup... we haven't done it yet. */
      mtevL(eventer_deb, "%p jobq[%s] -> cleanup [%p]\n", pthread_self_ptr(),
            jobq->queue_name, job);
      /* threaded issue, need to recheck. */
      /* coverity[check_after_deref] */
      if(job->fd_event) {
        volatile uint64_t duration;
        stats_handle_t *lat = eventer_latency_handle_for_callback(job->fd_event->callback);
        current_job = job;
        LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)job->fd_event,
                               (void *)job->fd_event->callback, NULL,
                               job->fd_event->fd, job->fd_event->mask,
                               EVENTER_ASYNCH_CLEANUP);
        eventer_run_callback(job->fd_event->callback, job->fd_event, EVENTER_ASYNCH_CLEANUP,
                     job->fd_event->closure, &job->finish_time, lat ? (uint64_t *)&duration : NULL);
        LIBMTEV_EVENTER_CALLBACK_RETURN((void *)job->fd_event,
                                (void *)job->fd_event->callback, NULL, -1);
        current_job = NULL;
        if(lat) stats_set_hist_intscale(lat, duration, -9, 1);
      }

      job->finish_hrtime = mtev_gethrtime();
      eventer_jobq_finished_job(jobq, job);
    }
  }
  if(jobq->mem_safety == EVENTER_JOBQ_MS_CS) mtev_memory_end();
  pthread_cleanup_pop(0);
  mtevL(eventer_deb, "jobq[%s/%p] -> terminating\n", jobq->queue_name, pthread_self_ptr());
  if(jobq->mem_safety != EVENTER_JOBQ_MS_NONE) {
    eventer_set_thread_name(NULL);
    mtev_memory_fini_thread();
  }
  /* If we've gotten here and there's a backlog... something odd is happening.
   * We should kick up another thread potentially.
   */
  if(ck_pr_load_32(&jobq->backlog) > 0) {
    eventer_jobq_maybe_spawn(jobq, 0);
  }
  ck_pr_dec_32(&jobq->consumer_threads_running);
  pthread_exit(NULL);
  return NULL;
}

static void jobq_fire_blanks(eventer_jobq_t *jobq, int n) {
  int i;
  for(i=0; i<n; i++) {
    eventer_job_t *job = calloc(1, sizeof(*job));
    eventer_jobq_enqueue(jobq, job, NULL);
  }
}

void eventer_jobq_ping(eventer_jobq_t *jobq) {
  jobq_fire_blanks(jobq, 1);
}

static int
eventer_jobq_post_noop(eventer_t e, int mask, void *c, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)c;
  (void)now;
  return 0;
}
void eventer_jobq_post(eventer_jobq_t *jobq) {
  eventer_jobq_consumer_notify(jobq);
  eventer_add_asynch(jobq, eventer_alloc_asynch(eventer_jobq_post_noop, NULL));
  eventer_jobq_consumer_notify(jobq);
}

void eventer_jobq_set_shortname(eventer_jobq_t *jobq, const char *name) {
  if(jobq->short_name) mtev_memory_safe_free((void *)jobq->short_name);
  if(name == NULL) jobq->short_name = NULL;
  else {
    /* we append this to "q:" so this gives us up to 16 including \0 */
    char *p = mtev_memory_safe_malloc(14);
    strlcpy(p, name, 14);
    jobq->short_name = p;
  }
}
void eventer_jobq_set_lifo(eventer_jobq_t *jobq, mtev_boolean nv) {
  if(nv) jobq->lifo = &jobq_lifo_true;
  else jobq->lifo = &jobq_lifo_false;
}
void eventer_jobq_set_max_backlog(eventer_jobq_t *jobq, uint32_t max) {
  jobq->max_backlog = max;
}

void eventer_jobq_set_floor(eventer_jobq_t *jobq, uint32_t floor_concurrency) {
  if(floor_concurrency > jobq->min_concurrency)
  jobq->min_concurrency = floor_concurrency;
  if(jobq->min_concurrency > jobq->max_concurrency) jobq->max_concurrency = jobq->min_concurrency;
  jobq->floor_concurrency = floor_concurrency;
  if(jobq->desired_concurrency < jobq->floor_concurrency || jobq->desired_concurrency > jobq->max_concurrency) {
    /* set concurrency will handle capping this in bounds */
    eventer_jobq_set_concurrency(jobq, jobq->desired_concurrency);
  }
}
void eventer_jobq_set_min_max(eventer_jobq_t *jobq, uint32_t min, uint32_t max) {
  mtevAssert(min <= max);
  mtevAssert(!jobq->isbackq);
  jobq->min_concurrency = min;
  jobq->max_concurrency = max;
  if(min < jobq->floor_concurrency) jobq->floor_concurrency = min;
  if(jobq->desired_concurrency < jobq->floor_concurrency || jobq->desired_concurrency > jobq->max_concurrency) {
    /* set concurrency will handle capping this in bounds */
    eventer_jobq_set_concurrency(jobq, jobq->desired_concurrency);
  }
}
void eventer_jobq_set_concurrency(eventer_jobq_t *jobq, uint32_t new_concurrency) {
  int notifies;
  mtevAssert(!jobq->isbackq);
  if(jobq->min_concurrency && new_concurrency < jobq->min_concurrency)
    new_concurrency = jobq->min_concurrency;
  if(jobq->max_concurrency && new_concurrency > jobq->max_concurrency)
    new_concurrency = jobq->max_concurrency;
  if(jobq->desired_concurrency > new_concurrency)
    notifies = jobq->desired_concurrency - new_concurrency;
  else
    notifies = 0;
  jobq->desired_concurrency = new_concurrency;
  if(notifies) jobq_fire_blanks(jobq, notifies);
}

void eventer_jobq_process_each(mtev_boolean (*func)(eventer_jobq_t *, void *),
                               void *closure) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

  pthread_mutex_lock(&all_queues_lock);
  while(mtev_hash_adv(&all_queues, &iter)) {
    if(!func((eventer_jobq_t *)iter.value.ptr, closure)) break;
  }
  pthread_mutex_unlock(&all_queues_lock);
}
void eventer_jobq_init_globals(void) {
  mtev_hash_init(&all_queues);
}

const char *eventer_jobq_get_queue_name(eventer_jobq_t *jobq) {
  return jobq->queue_name;
}
uint32_t eventer_jobq_get_concurrency(eventer_jobq_t *jobq) {
  return jobq->concurrency;
}
uint32_t eventer_jobq_get_backlog(eventer_jobq_t *jobq) {
  return jobq->backlog;
}
void eventer_jobq_get_min_max(eventer_jobq_t *jobq, uint32_t *min_, uint32_t *max_) {
  if(min_) *min_ = jobq->min_concurrency;
  if(max_) *max_ = jobq->max_concurrency;
}
eventer_jobq_memory_safety_t eventer_jobq_get_memory_safety(eventer_jobq_t *jobq) {
  return jobq->mem_safety;
}
uint32_t eventer_jobq_get_floor(eventer_jobq_t *jobq) {
  return jobq->floor_concurrency;
}
