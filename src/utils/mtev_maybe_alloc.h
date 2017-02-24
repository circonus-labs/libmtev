/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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

#ifndef MTEV_MAYBE_ALLOC_H
#define MTEV_MAYBE_ALLOC_H

#include <stdlib.h>

/*! \fn MTEV_MAYBE_DECL_VARS(type, name, cnt)
    \brief C Macro for declaring a "maybe" buffer.
    \param type A C type (e.g. char)
    \param name The name of the C variable to declare.
    \param cnt The number of type elements initially declared.
 */
#define MTEV_MAYBE_DECL_VARS(type, name, cnt) \
  struct { \
    size_t sz; \
    type   static_buff[cnt]; \
  } __##name##_support; \
  type *name

/*! \fn MTEV_MAYBE_INIT_VARS(name)
    \brief C Macro for initializing a "maybe" buffer
    \param name The name of "maybe" buffer.
 */
#define MTEV_MAYBE_INIT_VARS(name) \
  __##name##_support.sz = sizeof(__##name##_support.static_buff); \
  name = __##name##_support.static_buff

/*! \fn MTEV_MAYBE_DECL(type, name, cnt)
    \brief C Macro for declaring a "maybe" buffer.
    \param type A C type (e.g. char)
    \param name The name of the C variable to declare.
    \param cnt The number of type elements initially declared.

    A "maybe" buffer is a buffer that is allocated on-stack, but
    if more space is required can be reallocated off stack (malloc).
    One should always call `MTEV_MAYBE_FREE` on any allocated
    maybe buffer.
 */
#define MTEV_MAYBE_DECL(type, name, cnt) \
  MTEV_MAYBE_DECL_VARS(type, name, cnt); \
  MTEV_MAYBE_INIT_VARS(name)

/*! \fn MTEV_MAYBE_SIZE(name)
    \brief C Macro for number of bytes available in this buffer.
    \param name The name of the "maybe" buffer.
 */
#define MTEV_MAYBE_SIZE(name) (__##name##_support.sz + 0)

/*! \fn MTEV_MAYBE_REALLOC(name, cnt)
    \brief C Macro to ensure a maybe buffer has at least cnt elements allocated.
    \param name The name of the "maybe" buffer.
    \param cnt The total number of elements expected in the allocation.

    This macro will never reduce the size and is a noop if a size smaller
    than or equal to the current allocation size is specified.  It is safe
    to simply run this macro prior to each write to the buffer.
 */
#define MTEV_MAYBE_REALLOC(name, cnt) \
do { \
  if(__##name##_support.sz < (cnt) * sizeof(*(name))) { \
    size_t prevsz = __##name##_support.sz; \
    __##name##_support.sz = (cnt) * sizeof(*(name)); \
    if(name != __##name##_support.static_buff) { \
      name = realloc(name, __##name##_support.sz); \
    } else { \
      name = malloc(__##name##_support.sz); \
      memcpy(name, __##name##_support.static_buff, prevsz); \
    } \
  } \
} while(0)

/*! \fn MTEV_MAYBE_FREE(name)
    \brief C Macro to free any heap space associated with a "maybe" buffer.
    \param name The name of the "maybe" buffer.
 */
#define MTEV_MAYBE_FREE(name) \
do { if(name != __##name##_support.static_buff) free(name); } while(0)

#endif
