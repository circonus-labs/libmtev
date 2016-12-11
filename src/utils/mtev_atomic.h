/*
 * Copyright (c) 2005-2009, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
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
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
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

#ifndef UTILS_MTEV_ATOMIC_H
#define UTILS_MTEV_ATOMIC_H

#include "mtev_config.h"

typedef volatile int32_t mtev_atomic32_t;
typedef volatile int64_t mtev_atomic64_t;

#if defined(__GNUC__)

typedef mtev_atomic32_t mtev_spinlock_t;
static inline mtev_atomic32_t
mtev_atomic_cas32(volatile mtev_atomic32_t *ptr,
                  volatile mtev_atomic32_t rpl,
                  volatile mtev_atomic32_t curr) {
  mtev_atomic32_t prev;
  __asm__ volatile (
      "lock; cmpxchgl %1, %2"
    : "=a" (prev)
    : "r"  (rpl), "m" (*(ptr)), "0" (curr)
    : "memory");
  return prev;
}

#if (SIZEOF_VOID_P == 4)
static inline void *
mtev_atomic_casptr(volatile void **ptr,
                   /* coverity[noescape] */
                   volatile void *rpl,
                   volatile void *curr) {
  void *prev;
  __asm__ volatile (
      "lock; cmpxchgl %1, %2"
    : "=a" (prev)
    : "r"  (rpl), "m" (*(ptr)), "0" (curr)
    : "memory");
  return prev;
}
#endif

#ifdef __x86_64__
static inline mtev_atomic64_t
mtev_atomic_cas64(volatile mtev_atomic64_t *ptr,
                  volatile mtev_atomic64_t rpl,
                  volatile mtev_atomic64_t curr) {
  mtev_atomic64_t prev;
  __asm__ volatile (
      "lock; cmpxchgq %1, %2"
    : "=a" (prev)
    : "r"  (rpl), "m" (*(ptr)), "0" (curr)
    : "memory");
  return prev;
}
#if (SIZEOF_VOID_P == 8)
static inline void *
mtev_atomic_casptr(volatile void **ptr,
                  /* coverity[noescape] */
                  volatile void *rpl,
                  volatile void *curr) {
  void *prev;
  __asm__ volatile (
      "lock; cmpxchgq %1, %2"
    : "=a" (prev)
    : "r"  (rpl), "m" (*(ptr)), "0" (curr)
    : "memory");
  return prev;
}
#endif
#else

static inline mtev_atomic64_t
mtev_atomic_cas64_asm (volatile mtev_atomic64_t* ptr,
		       volatile uint32_t old_high, 
		       volatile uint32_t old_low,
		       volatile uint32_t new_high,
		       volatile uint32_t new_low) {
  mtev_atomic64_t prev;
  uint64_t tmp;
  __asm__ volatile (
      "lock; cmpxchg8b (%6);"
    : "=a" (old_low), "=d" (old_high)
    : "0" (old_low),  "1" (old_high),
      "c" (new_high),  "r" (new_low),
      "r" (ptr)
    : "memory", "cc");
  tmp = old_high;
  prev = old_low | tmp << 32;
  return prev;
}
static inline mtev_atomic64_t
mtev_atomic_cas64(volatile mtev_atomic64_t *ptr,
                  volatile mtev_atomic64_t rpl,
                  volatile mtev_atomic64_t curr) {
  mtev_atomic64_t prev;
#ifdef __PIC__
  __asm__ volatile (
      "pushl %%ebx;"
      "mov 4+%1,%%ecx;"
      "mov %1,%%ebx;"
      "lock;"
      "cmpxchg8b (%3);"
      "popl %%ebx"
    : "=A" (prev)
    : "m" (rpl), "A" (curr), "r" (ptr)
    : "%ecx", "memory", "cc");
#else
  /* These have to be unsigned or bit shifting doesn't work
   * properly */
  register uint32_t old_high = *ptr >> 32, old_low = *ptr;
  register uint32_t new_high = rpl >> 32, new_low = rpl;
  /* We need to break the 64-bit variables into 2 32-bit variables, do a 
   * compare-and-swap, then combine the results */
  prev = mtev_atomic_cas64_asm(ptr, old_high, old_low, new_high, new_low);
#endif
  return prev;
};
#if (SIZEOF_VOID_P == 8)
/* This should never be triggered.. 8 byte pointers on 32bit machines */
#error "64bit pointers on a 32bit architecture?"
#endif
#endif

static inline void mtev_spinlock_lock(volatile mtev_spinlock_t *lock) {
  while(mtev_atomic_cas32(lock, 1, 0) != 0);
}
static inline void mtev_spinlock_unlock(volatile mtev_spinlock_t *lock) {
  while(mtev_atomic_cas32(lock, 0, 1) != 1);
}
static inline int mtev_spinlock_trylock(volatile mtev_spinlock_t *lock) {
  return (mtev_atomic_cas32(lock, 1, 0) == 0);
}

#elif (defined(__sparc) || defined(__sparcv9) || defined(__amd64) || defined(__i386)) && (defined(__SUNPRO_C) || defined(__SUNPRO_CC))

typedef mtev_atomic32_t mtev_spinlock_t;

extern mtev_atomic32_t mtev_atomic_cas32(volatile mtev_atomic32_t *mem,
        volatile mtev_atomic32_t newval, volatile mtev_atomic32_t cmpval);
extern mtev_atomic64_t mtev_atomic_cas64(volatile mtev_atomic64_t *mem,
        volatile mtev_atomic64_t newval, volatile mtev_atomic64_t cmpval);
extern void *mtev_atomic_casptr(volatile void **mem,
        volatile void *newval, volatile void *cmpval);

static inline void mtev_spinlock_lock(volatile mtev_spinlock_t *lock) {
  while(mtev_atomic_cas32(lock, 1, 0) != 0);
}
static inline void mtev_spinlock_unlock(volatile mtev_spinlock_t *lock) {
  while(mtev_atomic_cas32(lock, 0, 1) != 1);
}
static inline int mtev_spinlock_trylock(volatile mtev_spinlock_t *lock) {
  return (mtev_atomic_cas32(lock, 1, 0) == 0);
}

#else
#error Please stub out the atomics section for your platform
#endif

#ifndef mtev_atomic_add32
static inline mtev_atomic32_t mtev_atomic_add32(volatile mtev_atomic32_t *loc,
                                                volatile mtev_atomic32_t diff) {
  register mtev_atomic32_t current;
  do {
    current = *(loc);
  } while(mtev_atomic_cas32(loc, current + diff, current) != current);
  return current + diff;
}
#endif

#ifndef mtev_atomic_add64
static inline mtev_atomic64_t mtev_atomic_add64(volatile mtev_atomic64_t *loc,
                                                volatile mtev_atomic64_t diff) {
  register mtev_atomic64_t current;
  do {
    current = *(loc);
  } while(mtev_atomic_cas64(loc, current + diff, current) != current);
  return current + diff;
}
#endif

#ifndef mtev_atomic_sub32
static inline mtev_atomic32_t mtev_atomic_sub32(volatile mtev_atomic32_t *loc,
                                                volatile mtev_atomic32_t diff) {
  register mtev_atomic32_t current;
  do {
    current = *(loc);
  } while(mtev_atomic_cas32(loc, current - diff, current) != current);
  return current - diff;
}
#endif

#ifndef mtev_atomic_sub64
static inline mtev_atomic64_t mtev_atomic_sub64(volatile mtev_atomic64_t *loc,
                                                volatile mtev_atomic64_t diff) {
  register mtev_atomic64_t current;
  do {
    current = *(loc);
  } while(mtev_atomic_cas64(loc, current - diff, current) != current);
  return current - diff;
}
#endif

#ifndef mtev_atomic_inc32
#define mtev_atomic_inc32(a) mtev_atomic_add32(a, 1)
#endif

#ifndef mtev_atomic_inc64
#define mtev_atomic_inc64(a) mtev_atomic_add64(a, 1)
#endif

#ifndef mtev_atomic_dec32
#define mtev_atomic_dec32(a) mtev_atomic_add32(a, -1)
#endif

#ifndef mtev_atomic_dec64
#define mtev_atomic_dec64(a) mtev_atomic_add64(a, -1)
#endif

#endif
