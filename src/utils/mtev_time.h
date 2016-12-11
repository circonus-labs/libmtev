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
#ifndef MTEV_TIME_H
#define MTEV_TIME_H

#include <mtev_defines.h>

/**
 * use TSC clock if possible for this CPU num
 * 
 * This will remain active in the thread until you call stop
 */
API_EXPORT(void)
  mtev_time_start_tsc();

/** 
 * Turn off TSC usage for the current cpu of this thread (from when start_tsc was called)
 */
API_EXPORT(void)
  mtev_time_stop_tsc(void);

/**
 * will switch on/off rdtsc usage across all cores regardless
 * of detected state of rdtsc or start/stop usage.
 * 
 * Defaults to enabled.
 * 
 * This is idependent of start_tsc/stop_tsc.  You can disable all and reenable and the thread
 * will keep going using the state from the last start/stop_tsc
 */
API_EXPORT(void)
  mtev_time_toggle_tsc(mtev_boolean enable);

/**
 * will switch on/off the requirement of an invariant tsc.  This must be run before
 * any call to mtev_time_toggle_tsc() or mtev_time_tsc_start() and is a one time call.
 *
 * Defaults to enabled.
 */
API_EXPORT(void)
  mtev_time_toggle_require_invariant_tsc(mtev_boolean enable);

/**
 * safe to call at any time but if you start_tsc, you should never need to call this
 * as the maintenance system can do it for you.. However, if you find you need to call it
 * you must be bound to a thread using the mtev_thread APIs and the function will return
 * whether it was successful in parameterizing the CPU for rdtsc use.
 */
API_EXPORT(mtev_boolean)
  mtev_time_maintain(void);

/**
 * Like mtev_gethrtime... it actually is the implementation of mtev_gethrtime()
 */
API_EXPORT(uint64_t)
  mtev_get_nanos(void);

/**
 * if start_tsc has been called for this thread and the CPU supports it,
 * this will return the number of current TSC ticks
 */
API_EXPORT(uint64_t)
  mtev_get_ticks(void);

/** 
 * same as mtev_get_nanos.  Number of nanoseconds since unix epoch.  Unlike gethrtime()
 * which is nanoseconds from some arbitrary point in time.
 */
API_EXPORT(mtev_hrtime_t)
  mtev_gethrtime(void);

/**
 * Exposes the system gethrtime() or equivalent impl
 */
API_EXPORT(mtev_hrtime_t)
  mtev_sys_gethrtime(void);

/**
 * Exposes a possibly fast-pathed gettimeofday equivalent.
 * If the fast path is taken, tzp is ignored.
 */
API_EXPORT(int)
  mtev_gettimeofday(struct timeval *t, void *ttp);

typedef struct mtev_time_coreclock_t {
  double ticks_per_nano;   /* ticks per nano on this cpu core */
  int64_t skew_ns;         /* How far off system hrtime */
  uint64_t fast_calls;     /* Number of fast paths taken */
  uint64_t desyncs;        /* Number of times the CPU has lost sync */
} mtev_time_coreclock_t;

API_EXPORT(mtev_boolean)
  mtev_time_coreclock_info(int cpuid, mtev_time_coreclock_t *info);

/**
 * returns whether mtev is currently operating in fast mode
 */
API_EXPORT(mtev_boolean)
  mtev_time_fast_mode(const char **reason);

#endif
