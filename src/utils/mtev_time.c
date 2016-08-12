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

#include <ck_pr.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <mtev_time.h>
#include <mtev_cpuid.h>
#include <mtev_thread.h>
#include <mtev_log.h>
#include <mtev_defines.h>

typedef uint64_t rdtsc_func(void);

static __thread rdtsc_func *rdtsc_function;
static __thread double ticks_per_nano;
#ifdef ENABLE_RDTSC
static __thread uint64_t last_ticks;
#endif

#define unlikely(x) __builtin_expect(!!(x), 0)

static inline uint64_t
mtev_rdtsc(void)
{
  uint32_t eax = 0, edx;

  __asm__ __volatile__("xorl %%eax, %%eax;"
                       "cpuid;"
                       "rdtsc;"
                         : "+a" (eax), "=d" (edx)
                         :
                         : "%ecx", "%ebx", "memory");

  return (((uint64_t)edx << 32) | eax);
}

static inline uint64_t
mtev_rdtscp(void)
{
  uint32_t eax = 0, edx;

  __asm__ __volatile__("rdtscp"
                       : "+a" (eax), "=d" (edx)
                       :
                       : "%ecx", "memory");

  return (((uint64_t)edx << 32) | eax);
}

#if defined(linux) || defined(__linux) || defined(__linux__)
#include <time.h>
static inline mtev_hrtime_t 
mtev_gethrtime_fallback() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ((ts.tv_sec * 1000000000) + ts.tv_nsec);
  }
#elif defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_time.h>

static inline mtev_hrtime_t 
mtev_gethrtime_fallback() {
    static int initialized = 0;
    static mach_timebase_info_data_t    sTimebaseInfo;
    uint64_t t;
    if(!initialized) {
        if(sTimebaseInfo.denom == 0)
            (void) mach_timebase_info(&sTimebaseInfo);
      }
    t = mach_absolute_time();
    return t * sTimebaseInfo.numer / sTimebaseInfo.denom;
  }
#else
static inline mtev_hrtime_t 
mtev_gethrtime_fallback() {
    return (mtev_hrtime_t)gethrtime();
  }
#endif

#ifdef ENABLE_RDTSC
static mtev_boolean 
mtev_calibrate_rdtsc_ticks() 
{
  if (unlikely(rdtsc_function == NULL)) {
    return mtev_false;
  }

  uint64_t start_ticks, end_ticks, start_ts, end_ts;
  int j = 0;

  /* 
   * we are pinned to a core here, so sleep for short periods and measure the ticks per nano second
   */
  double total_ticks = 0.0, avg_ticks = 0.0;
  for (int i = 0; i < 100; i++) {
    start_ticks = rdtsc_function();
    start_ts = mtev_gethrtime_fallback();
    usleep(10);
    end_ts = mtev_gethrtime_fallback();
    end_ticks = rdtsc_function();

    /* toss out clock weirdnesses */
    if (start_ticks > end_ticks) {
      continue;
    }
    if (start_ts > end_ts) {
      continue;
    }
    total_ticks += ((double) (end_ticks - start_ticks) - avg_ticks) / (end_ts - start_ts);
    j++;
  }
  mtevAssert(j > 0);
  avg_ticks = total_ticks / (double)j;
  ck_pr_store_double(&ticks_per_nano, avg_ticks);

  mtevL(mtev_debug, "%lf ticks/nano\n", ticks_per_nano);

  return true;
}  
#endif

static inline uint64_t
ticks_to_nanos(const uint64_t ticks)
{
  return (uint64_t)llround((double) ticks / ck_pr_load_double(&ticks_per_nano));
}  

void  
mtev_time_start_tsc(void)
{
#ifdef ENABLE_RDTSC
  rdtsc_function = NULL;
  if (mtev_cpuid_feature(MTEV_CPU_FEATURE_RDTSCP) == mtev_true) {
    mtevL(mtev_debug, "Using rdtscp for clock\n");
    rdtsc_function = mtev_rdtscp;
  }
  else if (mtev_cpuid_feature(MTEV_CPU_FEATURE_RDTSC) == mtev_true)  {
    mtevL(mtev_debug, "Using rdtsc for clock\n");
    rdtsc_function = mtev_rdtsc;
  }
  else {
    mtevL(mtev_debug, "CPU is wrong vendor or missing feature.  Cannot use TSC clock.\n");
    rdtsc_function = NULL;
    return;
  }

  mtev_calibrate_rdtsc_ticks();
#endif
}

void 
mtev_time_stop_tsc(void)
{
  rdtsc_function = NULL;
}

u_int64_t
mtev_get_nanos(void)
{
#ifdef ENABLE_RDTSC
  if (unlikely(rdtsc_function == NULL)) {
    return mtev_gethrtime_fallback();
  }

  uint64_t ticks = rdtsc_function();
  uint64_t nanos = ticks_to_nanos(ticks);

  return nanos;
#else
  return mtev_gethrtime_fallback();
#endif
}

u_int64_t
mtev_get_ticks(void)
{
#ifdef ENABLE_RDTSC
  if (unlikely(rdtsc_function == NULL)) {
    return 0;
  }

  return rdtsc_function();
#else
  return 0;
#endif
}

mtev_hrtime_t
mtev_gethrtime()
{
  return mtev_get_nanos();
}

mtev_hrtime_t
mtev_sys_gethrtime()
{
  return mtev_gethrtime_fallback();
}


#define RECALIBRATE_TIMEOUT_NANOS 3e+10

void
mtev_time_maintain(void)
{
#ifdef ENABLE_RDTSC
  if (unlikely(rdtsc_function == NULL)) {
    return;
  }

  uint64_t ticks = rdtsc_function();
  uint64_t nanos = ticks_to_nanos(ticks);
  uint64_t last_nanos = ticks_to_nanos(last_ticks);

  if (nanos - last_nanos > RECALIBRATE_TIMEOUT_NANOS) {
    mtev_calibrate_rdtsc_ticks();
    last_ticks = ticks;
  }
#endif

}


