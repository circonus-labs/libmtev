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
#include <ck_spinlock.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include "mtev_conf.h"
#include "mtev_defines.h"
#include "mtev_time.h"
#include "mtev_cpuid.h"
#include "mtev_thread.h"
#include "mtev_log.h"

static mtev_log_stream_t tdeb_impl;
#define tdeb (tdeb_impl ? tdeb_impl : mtev_debug)

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif
/* 
 * don't allow rdtsc on mach systems as there is only currently experimental support 
 * for affining threads to cores on mach systems
 */
#ifdef ENABLE_RDTSC
#define MAX_REASON_LEN 80
static char variable_reason[MAX_REASON_LEN+1] = { '\0' };
static const char *disable_reason = "still starting up";
#else
static const char *disable_reason = "compiled off";
#endif

typedef uint64_t rdtsc_func(int *);

#ifdef ENABLE_RDTSC
static pthread_mutex_t maintenance_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t maintenance_thread;
static ck_spinlock_t hrtime_epoch_skew_lock;
static uint64_t hrtime_epoch_skew_last_hrtime;
static uint64_t hrtime_epoch_skew;
static mtev_boolean maintenance_started;
static mtev_boolean use_system_gettimeofday;
#endif

static mtev_boolean ready_rdtsc;
static mtev_boolean require_invariant_tsc = mtev_true;
static __thread mtev_boolean thread_disable_rdtsc;
static volatile mtev_boolean enable_rdtsc = mtev_true;
static rdtsc_func *global_rdtsc_function = NULL;


/* Prevent recalibrations faster than 1s */
#define RECALIBRATE_MIN_NANOS 1e+9
/* Target time to cycle through all CPUs: 5s */
#define FULL_RECALIBRATE_CYCLE_NANOS 5e+9
/* An individual CPU will "desync" if not successfully calibrated in 15s */
#define DELINQUENT_NS 15e+9
/* Of our samples, none may be further from the average than 100ns */
#define MAX_NS_SKEW_SKEW 100

#define TICKS_PER_NANO(cpuid) ck_pr_load_double(&coreclocks[cpuid].calc.ticks_per_nano)

#if defined(linux) || defined(__linux) || defined(__linux__)
#define NCPUS 4096
#else
#define NCPUS 256
#endif

/* This is 16 bytes packed as we need to set and load them as one */
struct cclock_scale {
  double ticks_per_nano;          /* scale */
  uint64_t skew;                  /* hrtime skew in ns (actually signed) */
};
struct cclocks {
  struct cclock_scale calc;

  pthread_mutex_t update_lock;
  uint64_t last_ticks;            /* last ticks of calibration attempt */
  uint64_t last_sync;             /* last system hrtime of calibration success */

  /* last coterminus measurement... for longer, more acurate tps calc */
  uint64_t mark_ticks;
  mtev_hrtime_t mark_time;

  /* counts */
  uint64_t fast;
  mtev_atomic64_t desyncs;
} CK_CC_CACHELINE;
static struct cclocks coreclocks[NCPUS] = {{{0.0,0}, PTHREAD_MUTEX_INITIALIZER, 0, 0, 0}};

static void
mtev_time_reset_scale(void) {
  for(int i=0; i<NCPUS; i++) {
    ck_pr_store_64(&coreclocks[i].calc.skew, 0);
    ck_pr_store_double(&coreclocks[i].calc.ticks_per_nano, 0.0);
  }
}

mtev_boolean
mtev_time_coreclock_info(int cpuid, mtev_time_coreclock_t *info) {
  if(cpuid < 0 || cpuid >= NCPUS) return mtev_false;
  if(info) {
    struct cclock_scale cs;
#ifdef CK_F_PR_LOAD_64_2
    ck_pr_load_64_2((uint64_t *)&coreclocks[cpuid].calc, (uint64_t *)&cs);
#else
    cs.skew = ck_pr_load_64(&coreclocks[cpuid].calc.skew);
    cs.ticks_per_nano = TICKS_PER_NANO(cpuid);
#endif
    int64_t *skewptr = (int64_t *)&cs.skew;
    info->ticks_per_nano = cs.ticks_per_nano;
    info->skew_ns = *skewptr;
    info->fast_calls = coreclocks[cpuid].fast;
    info->desyncs = coreclocks[cpuid].desyncs;
  }
  return mtev_true;
}

#define unlikely(x) __builtin_expect(!!(x), 0)
#define NO_TSC unlikely(ready_rdtsc == mtev_false || thread_disable_rdtsc == mtev_true)

#ifdef ENABLE_RDTSC
static inline uint64_t
mtev_rdtsc(int *cpuid)
{
  uint32_t eax = 0, ebx, edx;

  if(cpuid) {
    __asm__ __volatile__("movl $0x01, %%eax;"
                         "cpuid;"
                         "shr $24, %%ebx;"
                           : "=b" (ebx)
                           :
                           : "%ecx", "%edx", "memory");
    __asm__ __volatile__("rdtsc;"
                           : "+a" (eax), "=d" (edx)
                           :
                           : "%ebx", "%ecx", "memory");
#if defined(linux) || defined(__linux) || defined(__linux__)
    *cpuid = ebx & (NCPUS-1);
#else
    *cpuid = ebx;
#endif
  } else {
    __asm__ __volatile__("lfence;"
                         "rdtsc;"
                           : "+a" (eax), "=d" (edx)
                           :
                           : "%ebx", "%ecx", "memory");
  }

  return (((uint64_t)edx << 32) | eax);
}

static inline uint64_t
mtev_rdtscp(int *cpuid)
{
  uint32_t eax = 0, ecx, edx;

  __asm__ __volatile__("rdtscp"
                       : "+a" (eax), "=c" (ecx), "=d" (edx)
                       :
                       : "%ebx", "memory");

#if defined(linux) || defined(__linux) || defined(__linux__)
  if(cpuid) *cpuid = ecx & (NCPUS-1);
#else
  if(cpuid) *cpuid = ecx;
#endif
  return (((uint64_t)edx << 32) | eax);
}

static inline uint64_t
ticks_to_nanos(int cpuid, const uint64_t ticks)
{
  return (uint64_t)((double) ticks / TICKS_PER_NANO(cpuid));
}
static inline uint64_t
ticks_to_nanos_skewed_ex(int cpuid, const uint64_t ticks, struct cclock_scale *cs)
{
  int64_t *skewptr = (int64_t *)&cs->skew;
  return (uint64_t)(((double) ticks / cs->ticks_per_nano) + *skewptr);
}
static inline mtev_boolean
fetch_cclock_scale(int cpuid, struct cclock_scale *cs) {
#if NCPUS == 256
  if(unlikely(cpuid & ~0xff)) return mtev_false;
#elif NCPUS == 4096
  if(unlikely(cpuid & ~0xfff)) return mtev_false;
#else
  if(unlikely(cpuid < 0 || cpuid > NCPUS)) {
    mtevL(tdeb, "fetch_cclock_scale called with bad CPU:%d\n", cpuid);
    return mtev_false;
  }
#endif
#ifdef CK_F_PR_LOAD_64_2
  ck_pr_load_64_2((uint64_t *)&coreclocks[cpuid].calc, (uint64_t *)cs);
#else
  cs->skew = ck_pr_load_64(&coreclocks[cpuid].calc.skew);
  cs->ticks_per_nano = TICKS_PER_NANO(cpuid);
#endif
  return mtev_true;
}
#endif

#if defined(linux) || defined(__linux) || defined(__linux__)
#include <time.h>
static inline mtev_hrtime_t 
mtev_gethrtime_fallback(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ((ts.tv_sec * 1000000000) + ts.tv_nsec);
}
#elif defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_time.h>

static inline mtev_hrtime_t 
mtev_gethrtime_fallback(void) {
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
#elif defined(BSD) || defined(__FreeBSD__)
#include <time.h>
#define NANOSEC 1000000000
static inline mtev_hrtime_t 
mtev_gethrtime_fallback(void) {
  struct timespec ts;
  clock_gettime(CLOCK_UPTIME,&ts);
  return (((u_int64_t) ts.tv_sec) * NANOSEC + ts.tv_nsec);
}
#else
static inline mtev_hrtime_t 
mtev_gethrtime_fallback(void) {
#if defined(sun) || defined(__sun__)
    static hrtime_t (*gethrtimesym)(void);
    if(gethrtimesym == NULL) gethrtimesym = dlsym(RTLD_NEXT, "gethrtime");
    /* Maybe we've been loaded from a system that doesn't use libc? */
    if(gethrtimesym == NULL) return (mtev_hrtime_t)gethrtime();
    return (mtev_hrtime_t)gethrtimesym();
#else
    return (mtev_hrtime_t)gethrtime();
#endif
}
#endif

static inline int
mtev_gettimeofday_fallback(struct timeval *t, void *ttp) {
#if defined(sun) || defined(__sun__)
  static int (*gtodsym)(struct timeval *, void *);
  if(gtodsym == NULL) gtodsym = dlsym(RTLD_NEXT, "gettimeofday");
  return gtodsym(t, ttp);
#else
  return gettimeofday(t, ttp);
#endif
}

int mtev_gettimeofday(struct timeval *t, void *ttp) {
#ifdef ENABLE_RDTSC
  if(hrtime_epoch_skew && !use_system_gettimeofday) {
    mtev_hrtime_t hrnow = mtev_get_nanos();
    if(hrnow - hrtime_epoch_skew_last_hrtime < DELINQUENT_NS) {
      hrnow += hrtime_epoch_skew;
      t->tv_sec = hrnow / 1000000000;
      t->tv_usec = (hrnow / 1000) % 1000000;
      return 0;
    }
    /* Save everyone else the effort */
    ck_pr_store_64(&hrtime_epoch_skew, 0);
  }
#endif
  return mtev_gettimeofday_fallback(t, ttp);
}

uint64_t mtev_now_ms(void)
{
  uint64_t rval;
  struct timeval tv;
  if (mtev_gettimeofday(&tv, NULL) == 0) {
    rval = ((uint64_t)tv.tv_sec * 1000UL) + ((uint64_t)tv.tv_usec / 1000);
    return rval;
  }
  return 0;
}

uint64_t mtev_now_us(void)
{
  uint64_t rval;
  struct timeval tv;
  if (mtev_gettimeofday(&tv, NULL) == 0) {
    rval = ((uint64_t)tv.tv_sec * 1000000UL) + ((uint64_t)tv.tv_usec);
    return rval;
  }
  return 0;
}

#ifdef ENABLE_RDTSC
static double
mtev_time_adjust_tps(int cpuid) {
  int ncpuid;
  uint64_t mark_ticks = coreclocks[cpuid].mark_ticks;
  uint64_t mark_time = coreclocks[cpuid].mark_time;
  uint64_t new_ticks = global_rdtsc_function(&ncpuid);
  if(ncpuid == cpuid) {
    coreclocks[cpuid].mark_ticks = new_ticks;
    coreclocks[cpuid].mark_time = mtev_gethrtime_fallback();
    if(mark_time) {
      /* We have a span */
      uint64_t elapsed_ticks = coreclocks[cpuid].mark_ticks - mark_ticks;
      mtev_hrtime_t elapsed_ns = coreclocks[cpuid].mark_time - mark_time;
      return (double)elapsed_ticks / (double)elapsed_ns;
    }
  }
  return 0.0;
}

static int
int64_t_cmp(const void *av, const void *bv) {
  const int64_t *a = av;
  const int64_t *b = bv;
  if(*a < *b) return -1;
  if(*a == *b) return 0;
  return 1;
}
static mtev_boolean 
mtev_calibrate_rdtsc_ticks(int cpuid, uint64_t ticks)
{
  if (!enable_rdtsc) return mtev_false;

  mtevAssert(ticks);
  int ncpuid;
  uint64_t h2;

  mtevL(tdeb, "mtev_calibrate_rdtsc_ticks(CPU:%d, ticks:%" PRIu64 ")\n", cpuid, ticks);
  coreclocks[cpuid].last_ticks = ticks;

  double avg_ticks = mtev_time_adjust_tps(cpuid);
  int64_t skew = 0, avg_skew, min_skew = INT64_MAX, max_skew = INT64_MIN;
  if(avg_ticks != 0.0) {
    /* Detect skew from hrtime */
    int i;
#define CALIBRATION_ITERS 6
    int64_t this_skew[CALIBRATION_ITERS];
    
    for(i=0; i<CALIBRATION_ITERS; i++) {
      uint64_t h1 = mtev_gethrtime_fallback();
      uint64_t start_ticks = global_rdtsc_function(&ncpuid);
      h2 = mtev_gethrtime_fallback();
      mtevAssert(cpuid == ncpuid);
      /* no TICKS_TO_NANOS macro as we need to use the new avg_ticks */
      uint64_t start_nanos = (uint64_t)((double) start_ticks / avg_ticks);
      uint64_t start_ts = h1/2 + h2/2;
      if(start_ts > start_nanos) this_skew[i] = (start_ts - start_nanos);
      else this_skew[i] = 0 - (start_nanos - start_ts);
    }
    qsort(this_skew, CALIBRATION_ITERS, sizeof(this_skew[0]), int64_t_cmp);

    /* We want to trim log2 sample off (half off each side) */
    int trim_cnt = 0;
    for(i=CALIBRATION_ITERS; i>1; i >>= 1) trim_cnt++;
    trim_cnt /= 2;
    for(skew=0, i=trim_cnt; i<CALIBRATION_ITERS - trim_cnt; i++) skew += this_skew[i];
    skew /= (CALIBRATION_ITERS - 2 * trim_cnt);
    min_skew = this_skew[trim_cnt];
    max_skew = this_skew[CALIBRATION_ITERS-trim_cnt-1];
    avg_skew = skew;
    if(skew == 0) skew = 1; /* This way we know it is initialized */
  
    mtevL(tdeb, "CPU:%d [%" PRId64" (%" PRId64 ",%" PRId64 ")] tps:%lf\n",
          cpuid, avg_skew, min_skew - avg_skew, max_skew - avg_skew, avg_ticks);
    if(avg_skew-min_skew > MAX_NS_SKEW_SKEW) skew = 0;
    if(max_skew-avg_skew > MAX_NS_SKEW_SKEW) skew = 0;
    if(skew != 0) {
#if defined(CK_F_PR_LOAD_64_2) && defined(CK_F_PR_CAS_64_2)
      struct cclock_scale newcs;
      uint64_t *hackref = (uint64_t *)&coreclocks[cpuid].calc, prev[2];
      newcs.ticks_per_nano = avg_ticks;
      newcs.skew = *((uint64_t *)&skew);
      mtevAssert(sizeof(newcs) == 16);
      do {
        ck_pr_load_64_2(hackref, prev);
      } while(!ck_pr_cas_64_2(hackref, prev, (uint64_t *)&newcs));
      mtevL(tdeb, "%lf ticks/nano 64_2 on CPU:%d [skew: %" PRId64 "]\n",
            TICKS_PER_NANO(cpuid), cpuid, *(int64_t *)&coreclocks[cpuid].calc.skew);
#else
      ck_pr_store_double(&coreclocks[cpuid].calc.ticks_per_nano, avg_ticks);
      ck_pr_store_64(&coreclocks[cpuid].calc.skew, *((uint64_t *)&skew));
      mtevL(tdeb, "%lf ticks/nano 64x2 on CPU:%d [skew: %" PRId64 "]\n",
            TICKS_PER_NANO(cpuid), cpuid, skew);
#endif
      coreclocks[cpuid].last_sync = h2;
    }
    else {
      if(h2 - coreclocks[cpuid].last_sync > DELINQUENT_NS) {
        if(ck_pr_load_64(&coreclocks[cpuid].calc.skew) != 0) {
          mtev_atomic_inc64(&coreclocks[cpuid].desyncs);
          ck_pr_store_64(&coreclocks[cpuid].calc.skew, 0);
        }
        mtevL(tdeb, "CPU:%d desync! [%" PRId64 ",%" PRId64 "]\n",
              cpuid, min_skew - avg_skew, max_skew - avg_skew);
      }
        mtevL(tdeb, "CPU:%d failed sync [%" PRId64 ",%" PRId64 "]\n",
              cpuid, min_skew - avg_skew, max_skew - avg_skew);
    }
  }

  /* calibrate the hrtime-wallclock skew */
  if(ck_spinlock_trylock(&hrtime_epoch_skew_lock)) {
    mtev_hrtime_t now = mtev_gethrtime_fallback();
    if(now - hrtime_epoch_skew_last_hrtime > RECALIBRATE_MIN_NANOS) {
      int i;
      int64_t skew = 0, this_skew;
      hrtime_epoch_skew_last_hrtime = now;
      for(i=0;i<4;i++) {
        mtev_hrtime_t t_g;
        struct timeval g1, g2, diff;
        mtev_gettimeofday_fallback(&g1, NULL);
        mtev_hrtime_t t_h = mtev_gethrtime_fallback();
        mtev_gettimeofday_fallback(&g2, NULL);
        sub_timeval(g2, g1, &diff);
        add_timeval(g1, diff, &g1);
        t_g = (mtev_hrtime_t)g1.tv_sec * 1000000000UL + (mtev_hrtime_t)g1.tv_usec * 1000UL;
        if(t_g > t_h) this_skew = (t_g - t_h);
        else this_skew = 0 - (t_h - t_g);
        skew += this_skew;
      }
      skew /= i;
      if(skew == 0) skew = 1;
      ck_pr_store_64(&hrtime_epoch_skew, (uint64_t)skew);
    }
    ck_spinlock_unlock(&hrtime_epoch_skew_lock);
  }
  return true;
}
#endif

static void
mtev_log_reason(void) {
  mtevL(mtev_notice, "mtev_time disabled: %s\n", disable_reason);
}
void
mtev_time_toggle_tsc(mtev_boolean enable) 
{
  enable_rdtsc = enable;
  if(!enable_rdtsc) {
    disable_reason = "explicitly disabled at runtime";
    mtev_log_reason();
    mtev_time_reset_scale();
  }
}

void
mtev_time_toggle_require_invariant_tsc(mtev_boolean enable) 
{
  require_invariant_tsc = enable;
}

#ifdef ENABLE_RDTSC
/* This function attempts to implement a cycle-alike get_nanos */
static inline uint64_t
mtev_get_nanos_force(void)
{
  int cpuid = 0;
  uint64_t ticks = 0;
  struct cclock_scale cs;

  if(NO_TSC) {
    ticks = global_rdtsc_function(&cpuid);
  } else if(global_rdtsc_function != NULL) {
    ticks = global_rdtsc_function(&cpuid);
  }
  if(fetch_cclock_scale(cpuid, &cs) == mtev_false) {
    (void)ticks_to_nanos_skewed_ex(cpuid, ticks, &cs);
    (void)ticks_to_nanos_skewed_ex(cpuid, coreclocks[cpuid].last_ticks, &cs);
  } else {
    (void)ticks_to_nanos_skewed_ex(cpuid, ticks, &cs);
    (void)ticks_to_nanos_skewed_ex(cpuid, coreclocks[cpuid].last_ticks, &cs);
  }
  return ticks;
}

#define PERF_ITERS 10000
static mtev_boolean
rdtsc_perf_test(void) {
  int i;
  struct timeval tv;
  mtev_hrtime_t start, elapsed_fast, elapsed_system;

  if(global_rdtsc_function == NULL) return mtev_false;

  start = mtev_gethrtime_fallback();
  for(i=0;i<PERF_ITERS;i++) mtev_get_nanos_force();
  elapsed_fast = mtev_gethrtime_fallback() - start;
  start = mtev_gethrtime_fallback();
  for(i=0;i<PERF_ITERS;i++) mtev_gettimeofday_fallback(&tv, NULL);
  elapsed_system = mtev_gethrtime_fallback() - start;

  if(elapsed_fast > elapsed_system) use_system_gettimeofday = mtev_true;

  if(global_rdtsc_function == NULL) return mtev_false;
  start = mtev_gethrtime_fallback();
  for(i=0;i<PERF_ITERS;i++) mtev_get_nanos_force();
  elapsed_fast = mtev_gethrtime_fallback() - start;
  start = mtev_gethrtime_fallback();
  for(i=0;i<PERF_ITERS;i++) mtev_gethrtime_fallback();
  elapsed_system = mtev_gethrtime_fallback() - start;

  if(elapsed_fast < elapsed_system) return mtev_true;
  return mtev_false;
}

static void *
mtev_time_tsc_maintenance(void *unused) {
  int delay_us = 0;
  (void)unused;
  long nrcpus = sysconf(_SC_NPROCESSORS_ONLN);
  mtev_thread_bind_to_cpu(0);
  if(!mtev_thread_is_bound_to_cpu()) {
    mtevL(mtev_error, "No cpu:thread binding support, using slower timings.\n");
    maintenance_started = mtev_false;
    mtev_time_reset_scale();
    return NULL;
  }

  if(!mtev_thread_realtime(100000)) /* 100us */
    mtevL(tdeb, "Time maintenance not real-time!\n");
  if(!mtev_thread_prio(INT_MAX))
    mtevL(tdeb, "Time maintenance not high priority!.\n");

  mtevL(tdeb, "mtev_time_tsc_maintenance thread started.\n");

  uint64_t bits_ready[NCPUS/64] = { 0 };
  uint64_t bits_needed[NCPUS/64] = { 0 };
  for(int i=0;i<nrcpus;i++) {
    int cpuid;
    mtev_thread_bind_to_cpu(i);
    global_rdtsc_function(&cpuid);
    if(i != cpuid) {
      snprintf(variable_reason, MAX_REASON_LEN,
               "bad rdtscp or cpuid mapping: bind(%d) -> cpuid:%d", i, cpuid);
      disable_reason = variable_reason;
      mtev_log_reason();
      enable_rdtsc = mtev_false;
      break;
    }
    /* Mark all the CPUs as our rdtsc identifies them */
    bits_needed[cpuid/64] |= (1UL << (cpuid%64));
  }

  while(1) {
    if(enable_rdtsc && !rdtsc_perf_test()) {
      disable_reason = "performance test failed";
      mtev_log_reason();
      enable_rdtsc = false;
    }
    if(enable_rdtsc) {

      for(int i=0; i<nrcpus; i++) {
        mtev_boolean is_ready = mtev_true;

        mtev_thread_bind_to_cpu(i);
        mtev_boolean working = mtev_time_maintain();
        if(working) bits_ready[i/64] |= (1UL << (i%64));
        else        bits_ready[i/64] &= ~(1UL << (i%64));

        for(int j=0; j<(NCPUS/64); j++)
          if(bits_ready[j] != bits_needed[j]) is_ready = mtev_false;
        if(ready_rdtsc != is_ready) {
          mtevL(mtev_notice, "mtev_time -> fast mode %s\n", is_ready ? "enabled" : "disabled");
          ready_rdtsc = is_ready;
          if(!ready_rdtsc) {
            disable_reason = "not all processors synchronized";
            mtev_log_reason();
          }
        }
        if(delay_us > 0) usleep(delay_us);
      }
      if(delay_us <= 0) {
        usleep(5000000); /* 5 seconds */
      }
      delay_us = FULL_RECALIBRATE_CYCLE_NANOS / 1000;
      delay_us /= nrcpus;
    } else {
      mtev_time_reset_scale();
      usleep(5000000);
    }
  }
  return NULL;
}
#endif

void  
mtev_time_start_tsc(void)
{
  tdeb_impl = mtev_log_stream_find("debug/time");
#ifdef __sun
#ifdef RUNNING_ON_VALGRIND
  if(RUNNING_ON_VALGRIND) {
    mtevL(tdeb, "mtev_time_start_tsc() -> disabled under valgrind.\n");
    return;
  }
#endif
#endif
#ifdef ENABLE_RDTSC
  long nrcpus = sysconf(_SC_NPROCESSORS_ONLN);
  if(nrcpus > NCPUS) {
    mtevL(mtev_error, "mtev_time_start_tsc failed, too many CPUs: %d > %d\n",
          (int)nrcpus, NCPUS);
    enable_rdtsc = mtev_false;
  }
  if(!enable_rdtsc) {
    mtevL(tdeb, "mtev_time_start_tsc() -> aborted, rdtsc disabled.\n");
    return;
  }
  if(pthread_mutex_lock(&maintenance_thread_lock) == 0) {
    if(maintenance_started == mtev_false) {
      if (mtev_cpuid_feature(MTEV_CPU_FEATURE_INVARIANT_TSC) == mtev_false) {
        if(require_invariant_tsc) {
          mtevL(mtev_notice, "fast time support disabled due to lack of invariant TSC support\n");
          disable_reason = "no invariant TSC";
          mtev_log_reason();
          enable_rdtsc = mtev_false;
          global_rdtsc_function = NULL;
          return;
        }
      }
      if (mtev_cpuid_feature(MTEV_CPU_FEATURE_RDTSCP) == mtev_true) {
        mtevL(tdeb, "Using rdtscp for clock\n");
        global_rdtsc_function = mtev_rdtscp;
      }
      else if (mtev_cpuid_feature(MTEV_CPU_FEATURE_RDTSC) == mtev_true)  {
        mtevL(tdeb, "Using rdtsc for clock\n");
        global_rdtsc_function = mtev_rdtsc;
      }
      else {
        mtevL(mtev_notice, "CPU is wrong vendor or missing feature.  Cannot use TSC clock.\n");
        disable_reason = "No CPU support for TSC";
        mtev_log_reason();
        enable_rdtsc = mtev_false;
        global_rdtsc_function = NULL;
        return;
      }
      maintenance_started = mtev_true;

      pthread_attr_t tattr;
      pthread_attr_init(&tattr);
      pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
      if(mtev_thread_create(&maintenance_thread, &tattr, mtev_time_tsc_maintenance, NULL) != 0) {
        maintenance_started = mtev_false;
        mtevL(mtev_error, "Failed time maintenance thread\n");
      }
    }
  } else {
    mtevL(mtev_error, "time mutex failure: %s\n", strerror(errno));
  }
  pthread_mutex_unlock(&maintenance_thread_lock);
#endif
}

void 
mtev_time_stop_tsc(void)
{
  thread_disable_rdtsc = mtev_true;
}

inline uint64_t
mtev_get_nanos(void)
{
#ifdef ENABLE_RDTSC
  int cpuid;
  struct cclock_scale cs;
  /* If we're off, we're off */
  if (NO_TSC)
    return mtev_gethrtime_fallback();

  uint64_t ticks = global_rdtsc_function(&cpuid);
  if(fetch_cclock_scale(cpuid, &cs) == mtev_false) return mtev_gethrtime_fallback();
  if(cs.skew != 0) {
    uint64_t nanos = ticks_to_nanos_skewed_ex(cpuid, ticks, &cs);
#if 0
    uint64_t last_nanos = ticks_to_nanos_skewed_ex(cpuid, coreclocks[cpuid].last_ticks, &cs);
    if (nanos - last_nanos < DELINQUENT_NS) {
#endif
      coreclocks[cpuid].fast++;
      return nanos;
#if 0
    }
    mtev_atomic_inc64(&coreclocks[cpuid].desyncs);
    ck_pr_store_64(&coreclocks[cpuid].calc.skew, 0);
#endif
  }
#endif
  return mtev_gethrtime_fallback();
}

uint64_t
mtev_get_ticks(void)
{
#ifdef ENABLE_RDTSC
  if (NO_TSC) {
    return 0;
  }

  return global_rdtsc_function(NULL);
#else
  return 0;
#endif
}

mtev_hrtime_t
mtev_gethrtime(void)
{
  return mtev_get_nanos();
}

mtev_hrtime_t
mtev_sys_gethrtime(void)
{
  return mtev_gethrtime_fallback();
}

static mtev_boolean
mtev_time_possibly_maintain(int cpuid, uint64_t ticks)
{
#ifdef ENABLE_RDTSC
  if(unlikely(cpuid < 0 || cpuid > NCPUS)) return  mtev_false;

  uint64_t nanos = ticks_to_nanos(cpuid, ticks);
  uint64_t last_nanos = ticks_to_nanos(cpuid, coreclocks[cpuid].last_ticks);

  if(nanos == last_nanos && ticks != coreclocks[cpuid].last_ticks) {
    /* We don't have a clock speed yet, so we'll fake "one" juse for the purpose
     * of timing the next calibration.
     */
     nanos = ticks;
     last_nanos = coreclocks[cpuid].last_ticks;
  }

  if (nanos - last_nanos > RECALIBRATE_MIN_NANOS) {
    if ( pthread_mutex_trylock(&coreclocks[cpuid].update_lock) == 0 ) {
      /* recheck with lock */
      last_nanos = ticks_to_nanos(cpuid, coreclocks[cpuid].last_ticks);
      if (nanos - last_nanos > RECALIBRATE_MIN_NANOS) {
        mtev_calibrate_rdtsc_ticks(cpuid, ticks);
      }
      pthread_mutex_unlock(&coreclocks[cpuid].update_lock);
    } else {
      mtevAssert(errno == EBUSY);
    }
  }
  return coreclocks[cpuid].calc.skew != 0;
#else
  return mtev_false;
#endif
}


mtev_boolean
mtev_time_maintain(void)
{
  int cpuid;
  if (!mtev_thread_is_bound_to_cpu()) return mtev_false;
  uint64_t ticks = global_rdtsc_function(&cpuid);
  return mtev_time_possibly_maintain(cpuid, ticks);
}

mtev_boolean
mtev_time_fast_mode(const char **reason)
{
  *reason = ready_rdtsc ? NULL : disable_reason;
#ifdef ENABLE_RDTSC
  if (ready_rdtsc && use_system_gettimeofday) {
    *reason = "using system gettimeofday() for performance reasons";
  }
#endif
  return ready_rdtsc;
}
