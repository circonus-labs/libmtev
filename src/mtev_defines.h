/*
 * Copyright (c) 2007-2009, OmniTI Computer Consulting, Inc.
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

#ifndef _MTEV_DEFINES_H
#define _MTEV_DEFINES_H

#include "mtev_config.h"

#include <stdbool.h>
#define _BOOL

#ifndef __FUNCTION__
#define __FUNCTION__ __func__
#endif

#define API_EXPORT(type) extern type

static inline int compare_timeval(struct timeval a, struct timeval b) {
  if (a.tv_sec < b.tv_sec) return -1;
  if (a.tv_sec > b.tv_sec) return 1;
  if (a.tv_usec < b.tv_usec) return -1;
  if (a.tv_usec > b.tv_usec) return 1;
  return 0;
}

static inline void sub_timeval(struct timeval a, struct timeval b,
                               struct timeval *out)
{
  out->tv_usec = a.tv_usec - b.tv_usec;
  if (out->tv_usec < 0L) {
    a.tv_sec--;
    out->tv_usec += 1000000L;
  }
  out->tv_sec = a.tv_sec - b.tv_sec;
  if (out->tv_sec < 0L) {
    out->tv_sec++;
    out->tv_usec -= 1000000L;
  }
}

static inline double sub_timeval_d(struct timeval a, struct timeval b)
{
  struct timeval d;
  sub_timeval(a,b,&d);
  return (double)d.tv_sec + (double)d.tv_usec / 1000000.0;
}

static inline int64_t sub_timeval_ms(struct timeval a, struct timeval b)
{
  struct timeval d;
  sub_timeval(a,b,&d);
  return d.tv_sec*1000 + d.tv_usec / 1000;
}

static inline void add_timeval(struct timeval a, struct timeval b,
                               struct timeval *out)
{
  out->tv_usec = a.tv_usec + b.tv_usec;
  if (out->tv_usec >= 1000000L) {
    a.tv_sec++;
    out->tv_usec -= 1000000L;
  }
  out->tv_sec = a.tv_sec + b.tv_sec;
}

#include <uuid/uuid.h>

#undef UUID_STR_LEN
#define UUID_STR_LEN 36

#ifndef UUID_PRINTABLE_STRING_LENGTH
#define UUID_PRINTABLE_STRING_LENGTH UUID_STR_LEN + 1
#endif

#ifndef HAVE_UUID_UNPARSE_LOWER
/* Sigh, need to implement out own */
#include <ctype.h>
static inline void uuid_unparse_lower(uuid_t in, char *out) {
  int i;
  uuid_unparse(in, out);
  for(i=0;i<UUID_STR_LEN;i++) out[i] = tolower(out[i]);
}
#endif

#ifdef HAVE_TERMIO_H
#define USE_TERMIO
#endif

#ifndef MIN
#define MIN(x,y)  ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y)  ((x) > (y) ? (x) : (y))
#endif
#ifndef SUN_LEN
#define SUN_LEN(ptr) (sizeof(*(ptr)) - sizeof((ptr)->sun_path) + strlen((ptr)->sun_path))
#endif

/* This is for udns */
#ifdef HAVE_INET_PTON
#ifdef HAVE_INET_NTOP
#define HAVE_INET_PTON_NTOP 1
#endif
#endif
/* udns checks for IPv6 */
#define HAVE_IPv6

#if defined(__sun) && !defined(HAVE_POSIX_READDIR_R) && !defined(_POSIX_PTHREAD_SEMANTICS)
#define portable_readdir_r(a,b,c) (((*(c)) = readdir_r(a,b)) == NULL)
#else
#define portable_readdir_r readdir_r
#endif
#include "noitedit/strlcpy.h"

#define UUID_REGEX "[0-9a-fA-F]{4}(?:[0-9a-fA-F]{4}-){4}[0-9a-fA-F]{12}"
#include <uuid/uuid.h>
struct uuid_dummy { uuid_t foo; };
#define UUID_SIZE sizeof(struct uuid_dummy)

#if defined(__MACH__)
typedef uint64_t mtev_hrtime_t;
#elif defined(linux) || defined(__linux) || defined(__linux__)
typedef long long unsigned int mtev_hrtime_t;
#else
typedef hrtime_t mtev_hrtime_t;
#endif

#if defined(linux) || defined(__linux) || defined(__linux__)
#include <time.h>
static inline mtev_hrtime_t mtev_gethrtime() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ((ts.tv_sec * 1000000000) + ts.tv_nsec);
}
#elif defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_time.h>

static inline mtev_hrtime_t mtev_gethrtime() {
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
static inline mtev_hrtime_t mtev_gethrtime() {
  return (mtev_hrtime_t)gethrtime();
}
#endif

#endif
