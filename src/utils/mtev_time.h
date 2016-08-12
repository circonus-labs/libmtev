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
  mtev_time_start_tsc(int cpu);

/** 
 * Turn off TSC usage for this cpu num
 */
API_EXPORT(void)
  mtev_time_stop_tsc(void);

/**
 * safe to call at any time but if you start_tsc, you should call this periodically to recalibrate the clock
 */
API_EXPORT(void)
  mtev_time_maintain(void);

/**
 * same as mtev_gethrtime.  Number of nanoseconds from some arbitrary time in the past
 */
API_EXPORT(u_int64_t)
  mtev_get_nanos(void);

/**
 * if start_tsc has been called for this thread and the CPU supports it,
 * this will return the number of current TSC ticks
 */
API_EXPORT(u_int64_t)
  mtev_get_ticks(void);

/** 
 * same as mtev_get_nanos.  Number of nanoseconds from some artibrary time in the past 
 */
API_EXPORT(mtev_hrtime_t)
  mtev_gethrtime(void);

/**
 * Exposes the system gethrtime() or equivalent impl
 */
API_EXPORT(mtev_hrtime_t)
  mtev_sys_gethrtime(void);

#endif
