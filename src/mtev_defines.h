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

#include <mtev_config.h>

#define IFS_CH '/'

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#else
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifndef DTRACE_ENABLED
#define DTRACE_PROBES_DISABLED 1
#endif

/* The number of bytes in a void * (workaround for OpenBSD). */
#undef SIZEOF_VOID__
#if !defined(SIZEOF_VOID_P) && defined(SIZEOF_VOID__)
#  define SIZEOF_VOID_P SIZEOF_VOID__
#endif

/* Deal with the `restrict` keyword by making `__restrict` work */
#ifndef __restrict
  #if !defined(__cplusplus) /* C++11 compilers seem to define this */
    #if (__STDC_VERSION__ >= 199901L)
      #define __restrict restrict
    #endif
  #endif
#endif
#ifndef __restrict
#define __restrict
#endif

/* BIND, Kerberos and Berkeley DB use __BIT_TYPES_DEFINED__ to protect
 * against multiple redefinitions of these types (uint{8,16,32,64}_t)
 * and so shall we.
 */
#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__
#endif

#ifdef MAKE_HTOBE64_HTONLL
#undef htonll
#define htonll htobe64
#endif

#ifdef MAKE_BE64TOH_NTOHLL
#undef ntohll
#define ntohll be64toh
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif

typedef enum { mtev_false = 0, mtev_true } mtev_boolean;

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

#if defined(__sun) && !defined(HAVE_POSIX_READDIR_R)
#define portable_readdir_r(a,b,c) (((*(c)) = readdir_r(a,b)) == NULL)
#else
/* https://lwn.net/Articles/696474/ */
/* https://lists.nongnu.org/archive/html/libunwind-devel/2011-11/msg00046.html */
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 24)
#if HAVE_DIRENT_H
#include <dirent.h>
#endif
static inline int portable_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  return readdir_r(dirp, entry, result);
#pragma GCC diagnostic pop
}
#else
/* glibc < 2.24 */
#define portable_readdir_r readdir_r
#endif
#else
/* not glibc */
#define portable_readdir_r readdir_r
#endif
#endif
#include <mtev_str.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UUID_REGEX "[0-9a-fA-F]{4}(?:[0-9a-fA-F]{4}-){4}[0-9a-fA-F]{12}"
#define UUID_SIZE 16

#if defined(BSD) || defined(__FreeBSD__)
typedef uint64_t mtev_hrtime_t;
#elif defined(__MACH__)
typedef uint64_t mtev_hrtime_t;
#elif defined(linux) || defined(__linux) || defined(__linux__)
typedef long long unsigned int mtev_hrtime_t;
#else
typedef hrtime_t mtev_hrtime_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
