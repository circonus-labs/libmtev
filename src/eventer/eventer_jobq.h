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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is for jobs that would block and need more forceful timeouts.
 */

typedef struct _eventer_job_t eventer_job_t;

typedef enum {
  EVENTER_JOBQ_MS_CS,  /* manages init, critical sections, and gc */
  EVENTER_JOBQ_MS_GC,  /* manages init, and gc */
  EVENTER_JOBQ_MS_NONE /* managed nothing at all */
} eventer_jobq_memory_safety_t;

static inline const char *
eventer_jobq_memory_safety_name(eventer_jobq_memory_safety_t ms) {
  switch(ms) {
    case EVENTER_JOBQ_MS_NONE: return "none";
    case EVENTER_JOBQ_MS_CS: return "cs";
    case EVENTER_JOBQ_MS_GC: return "gc";
  }
  return "unknown";
}

typedef struct _eventer_jobq_t eventer_jobq_t;

/*! \fn eventer_jobq_t *eventer_jobq_create(const char *queue_name)
    \brief Create a new jobq.
    \param queue_name a name for the new jobq
    \return a pointer to a new (or existing) jobq with that name. NULL on error.
*/
API_EXPORT(eventer_jobq_t *) eventer_jobq_create(const char *queue_name);

/*! \fn eventer_jobq_t *eventer_jobq_create_backq(const char *queue_name)
    \brief Create a new jobq for use as a return queue.
    \param queue_name a name for the new jobq
    \return a pointer to a new (or existing) jobq with that name. NULL on error.
*/
API_EXPORT(eventer_jobq_t *) eventer_jobq_create_backq(const char *queue_name);

/*! \fn eventer_jobq_t *eventer_jobq_create_ms(const char *queue_name, eventer_jobq_memory_safety_t safety)
    \brief Create a new jobq with the specified memory safety.
    \param queue_name a name for the new jobq
    \param safety a specific mtev_memory safey level for epoch-based memory reclamation schemes.
    \return a pointer to a new (or existing) jobq with that name. NULL on error.
*/
API_EXPORT(eventer_jobq_t *) eventer_jobq_create_ms(const char *queue_name,
                                                    eventer_jobq_memory_safety_t);

/*! \fn eventer_job_t *eventer_jobq_inflight(void)
    \brief Reveal the currently executing job (visiable to a callee).
    \return the job that is currentlt running in the calling thread.
*/
API_EXPORT(eventer_job_t *) eventer_jobq_inflight(void);

/*! \fn eventer_jobq_t *eventer_jobq_retrieve(const char *name)
    \brief Find a jobq by name.
    \param name the name of a jobq
    \return a jobq or NULL if no such jobq exists.
*/
API_EXPORT(eventer_jobq_t *) eventer_jobq_retrieve(const char *name);

/*! \fn void eventer_jobq_destroy(eventer_jobq_t *jobq)
    \brief Destory a jobq.
*/
API_EXPORT(void) eventer_jobq_destroy(eventer_jobq_t *jobq);

/*! \fn void eventer_jobq_set_shortname(eventer_jobq_t *jobq, const char *name)
    \brief Set a "shorter" name for a jobq to be used in terse displays.
    \param jobq the jobq to modify
    \param name a shorter name for a job (clipped to 13 characters)
*/
API_EXPORT(void) eventer_jobq_set_shortname(eventer_jobq_t *jobq, const char *name);

/*! \fn void eventer_jobq_set_lifo(eventer_jobq_t *jobq, mtev_boolean nv)
    \brief Instruct the jobq system to process jobs in LIFO vs. FIFO ordering.
    \param jobq the jobq to modify
    \param nv Use LIFO or FIFO ordering if true or false, respectively.
*/
API_EXPORT(void) eventer_jobq_set_lifo(eventer_jobq_t *jobq, mtev_boolean nv);

/*! \fn void eventer_jobq_set_concurrency(eventer_jobq_t *jobq, uint32_t new_concurrency)
    \brief Set a jobq's concurrency level.
    \param jobq the jobq to modify
    \param new_concurrency the new number of desired threads
*/
API_EXPORT(void) eventer_jobq_set_concurrency(eventer_jobq_t *jobq, uint32_t new_concurrency);

/*! \fn void eventer_jobq_set_floor(eventer_jobq_t *jobq, uint32_t new_floor)
    \brief Set a jobq's minimum active thread count.
    \param jobq the jobq to modify
    \param new_floor the new number of minimum threads
*/
API_EXPORT(void) eventer_jobq_set_floor(eventer_jobq_t *jobq, uint32_t new_concurrency);

/*! \fn void eventer_jobq_set_min_max(eventer_jobq_t *jobq, uint32_t min, uint32_t max)
    \brief Set the upper and lower bounds on desired concurrency for a jobq.
    \param jobq the jobq to modify
    \param min a minimum number of threads to maintain
    \param max a maximum number of threads to not exceed
*/
API_EXPORT(void) eventer_jobq_set_min_max(eventer_jobq_t *jobq, uint32_t min, uint32_t max);

/*! \fn void eventer_jobq_set_max_backlog(eventer_jobq_t *jobq, uint32_t max)
    \brief Set and advisory limit on the backlog a jobq will handle.
    \param jobq the jobq to modify
    \param max a maximum pending jobs count before eventer_try_add_asynch calls will fail.
*/
API_EXPORT(void) eventer_jobq_set_max_backlog(eventer_jobq_t *jobq, uint32_t max);

/*! \fn void eventer_jobq_post(eventer_jobq_t *jobq)
    \brief Wake up a jobq to see if there are pending events.
    \param jobq the jobq to post to.
*/
API_EXPORT(void) eventer_jobq_post(eventer_jobq_t *jobq);

void eventer_jobq_enqueue(eventer_jobq_t *jobq, eventer_job_t *job, eventer_job_t *parent);
mtev_boolean eventer_jobq_try_enqueue(eventer_jobq_t *jobq, eventer_job_t *job, eventer_job_t *parent);
eventer_job_t *eventer_jobq_dequeue(eventer_jobq_t *jobq);
eventer_job_t *eventer_jobq_dequeue_nowait(eventer_jobq_t *jobq);
int eventer_jobq_execute_timeout(eventer_t e, int mask, void *closure,
                                 struct timeval *now);
int eventer_jobq_consume_available(eventer_t e, int mask, void *closure,
                                   struct timeval *now);
void *eventer_jobq_consumer(eventer_jobq_t *jobq);
void eventer_jobq_process_each(mtev_boolean (*func)(eventer_jobq_t *, void *), void *);
void eventer_jobq_init_globals(void);

const char *eventer_jobq_get_queue_name(eventer_jobq_t *jobq);
uint32_t eventer_jobq_get_concurrency(eventer_jobq_t *jobq);
void eventer_jobq_get_min_max(eventer_jobq_t *jobq, uint32_t *min_, uint32_t *max_);
eventer_jobq_memory_safety_t eventer_jobq_get_memory_safety(eventer_jobq_t *jobq);
uint32_t eventer_jobq_get_floor(eventer_jobq_t *jobq);

#ifdef __cplusplus
}
#endif

#endif
