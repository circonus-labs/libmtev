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

typedef struct _eventer_job_t eventer_job_t;

typedef enum {
  EVENTER_JOBQ_MS_CS,  /* manages init, critical sections, and gc */
  EVENTER_JOBQ_MS_GC,  /* manages init, and gc */
  EVENTER_JOBQ_MS_NONE /* managed nothing at all */
} eventer_jobq_memory_safety_t;

typedef struct _eventer_jobq_t eventer_jobq_t;

eventer_jobq_t *eventer_jobq_create(const char *queue_name);
eventer_jobq_t *eventer_jobq_create_backq(const char *queue_name);
eventer_jobq_t *eventer_jobq_create_ms(const char *queue_name,
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
void *eventer_jobq_consumer(eventer_jobq_t *jobq);
void eventer_jobq_process_each(void (*func)(eventer_jobq_t *, void *), void *);
void eventer_jobq_init_globals();

const char *eventer_jobq_get_queue_name(eventer_jobq_t *jobq);
uint32_t eventer_jobq_get_concurrency(eventer_jobq_t *jobq);

#endif
