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

/* 
 * don't allow rdtsc on mach systems as there is only currently experimental support 
 * for affining threads to cores on mach systems
 */
#if defined(__MACH__)
#undef ENABLE_RDTSC
#endif

static __thread mtev_boolean thread_enable_rdtsc;
static mtev_boolean enable_rdtsc = mtev_true;

typedef uint64_t rdtsc_func(void);

#define NCPUS 128
struct cclocks {
  pthread_mutex_t update_lock;
  rdtsc_func *rdtsc_function;
  double ticks_per_nano;
  uint64_t last_ticks;
} CK_CC_CACHELINE;
static struct cclocks coreclocks[NCPUS] = {{PTHREAD_MUTEX_INITIALIZER, NULL, 0.0, 0}};
static __thread int current_cpu;
  
#define unlikely(x) __builtin_expect(!!(x), 0)
#define NO_TSC unlikely(enable_rdtsc == mtev_false || thread_enable_rdtsc == mtev_false || \
                        coreclocks[current_cpu].rdtsc_function == NULL)


#ifdef ENABLE_RDTSC
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

static inline uint64_t
ticks_to_nanos(const uint64_t ticks)
{
  return (uint64_t)llround((double) ticks / ck_pr_load_double(&coreclocks[current_cpu].ticks_per_nano));
}  
#endif

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
  if (NO_TSC) {
    return mtev_false;
  }

  uint64_t start_ticks, end_ticks, start_ts, end_ts;
  int j = 0;
  rdtsc_func *f = coreclocks[current_cpu].rdtsc_function;

  /* 
   * we are pinned to a core here, so sleep for short periods and measure the ticks per nano second
   */
  double total_ticks = 0.0, avg_ticks = 0.0;
  for (int i = 0; i < 100; i++) {
    start_ticks = f();
    start_ts = mtev_gethrtime_fallback();
    usleep(10);
    end_ts = mtev_gethrtime_fallback();
    end_ticks = f();

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
  ck_pr_store_double(&coreclocks[current_cpu].ticks_per_nano, avg_ticks);

  mtevL(mtev_debug, "%lf ticks/nano on CPU:%d\n", coreclocks[current_cpu].ticks_per_nano, current_cpu);

  return true;
}  
#endif

void
mtev_time_toggle_tsc(mtev_boolean enable) 
{
  enable_rdtsc = enable;
}

void  
mtev_time_start_tsc(int cpu)
{
#ifdef ENABLE_RDTSC
  current_cpu = cpu;
  rdtsc_func *rdtsc_function = NULL;
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
    coreclocks[cpu].rdtsc_function = NULL;
    return;
  }
  thread_enable_rdtsc = mtev_true;
  coreclocks[current_cpu].rdtsc_function = rdtsc_function;
  mtev_calibrate_rdtsc_ticks();
#endif
}

void 
mtev_time_stop_tsc()
{
  coreclocks[current_cpu].rdtsc_function = NULL;
  thread_enable_rdtsc = mtev_false;
}

u_int64_t
mtev_get_nanos(void)
{
#ifdef ENABLE_RDTSC
  if (NO_TSC) {
    return mtev_gethrtime_fallback();
  }

  uint64_t ticks = coreclocks[current_cpu].rdtsc_function();
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
  if (NO_TSC) {
    return 0;
  }

  return coreclocks[current_cpu].rdtsc_function();
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
  if (NO_TSC) {
    return;
  }

  uint64_t ticks = coreclocks[current_cpu].rdtsc_function();
  uint64_t nanos = ticks_to_nanos(ticks);
  uint64_t last_nanos = ticks_to_nanos(coreclocks[current_cpu].last_ticks);

  if (nanos - last_nanos > RECALIBRATE_TIMEOUT_NANOS) {
    if ( pthread_mutex_trylock(&coreclocks[current_cpu].update_lock) ) {
      mtevL(mtev_debug, "Got lock for CPU %d, calibrating\n", current_cpu);
      coreclocks[current_cpu].last_ticks = ticks;
      mtev_calibrate_rdtsc_ticks();
      pthread_mutex_unlock(&coreclocks[current_cpu].update_lock);
    } else {
      mtevL(mtev_debug, "Another thread is already updating this core clock %d, skipping\n", current_cpu);
    }
  }
#endif

}


