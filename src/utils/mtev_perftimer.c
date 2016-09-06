/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
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

#include "mtev_perftimer.h"
#include "mtev_time.h"
#include <ck_md.h>
#include <time.h>
#include <sys/time.h>

/* If the compile time hasn't slected something in particular,
 * use mtev_gethrtime as we already tried to be careful with that.
 */

typedef struct mtev_perftimer_private_t {
  union {
    mtev_perftimer_t opaque;
#if defined(MTEV_PT_USE_GETHRTIME)
    hrtime_t start;
#elif defined(MTEV_PT_USE_CLOCK_GETTIME)
    struct timespec start;
#elif defined(MTEV_PT_USE_GETTIMEOFDAY)
    struct timeval start;
#else
    mtev_hrtime_t start;
#endif
  } d;
} mtev_perftimer_private_t;

void
mtev_perftimer_start(mtev_perftimer_t *aliased) {
  register mtev_perftimer_private_t *impl =
    (mtev_perftimer_private_t *)aliased;
#if defined(MTEV_PT_USE_GETHRTIME)
  impl->d.start = mtev_sys_gethrtime();
#elif defined(MTEV_PT_USE_CLOCK_GETTIME)
  clock_gettime(CLOCK_HIRES, &impl->d.start);
#elif defined(MTEV_PT_USE_GETTIMEOFDAY)
  gettimeofday(&impl->d.start, NULL);
#else
  impl->d.start = mtev_gethrtime();
#endif
}

int64_t
mtev_perftimer_elapsed(mtev_perftimer_t *aliased) {
  register int64_t rv;
  register mtev_perftimer_private_t *impl =
    (mtev_perftimer_private_t *)aliased;
#if defined(MTEV_PT_USE_GETHRTIME)
  rv = mtev_sys_gethrtime() - impl->d.start;
#elif defined(MTEV_PT_USE_CLOCK_GETTIME)
  struct timespec now;
  clock_gettime(CLOCK_HIRES, &now);
  rv = (int64_t)now.tv_sec - (int64_t)impl->d.start.tv_sec;
  rv *= 1000000000;
  rv += ((int64_t)now.tv_nsec - (int64_t)impl->d.start.tv_nsec);
#elif defined(MTEV_PT_USE_GETTIMEOFDAY)
  struct timeval now;
  gettimeofday(&now, NULL);
  rv = (int64_t)now.tv_sec - (int64_t)impl->d.start.tv_sec;
  rv *= 1000000000;
  rv += ((int64_t)now.tv_usec - (int64_t)impl->d.start.tv_usec) * 1000;
#else
  rv = mtev_gethrtime() - impl->d.start;
#endif
  return rv;
}
