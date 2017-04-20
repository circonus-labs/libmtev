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

#ifndef _UTILS_MTEV_LOGBUF_H
#define _UTILS_MTEV_LOGBUF_H

#include <mtev_log.h>
#include "mtev_defines.h"

typedef struct _mtev_logbuf_t mtev_logbuf_t;
typedef struct _mtev_logbuf_log_t mtev_logbuf_log_t;

typedef enum {
  MTEV_LOGBUF_TYPE_STRING = 1,
  MTEV_LOGBUF_TYPE_POINTER = 2,
  MTEV_LOGBUF_TYPE_INT32 = 3,
  MTEV_LOGBUF_TYPE_INT64 = 4,
  MTEV_LOGBUF_TYPE_UINT32 = 5,
  MTEV_LOGBUF_TYPE_UINT64 = 6,
} mtev_logbuf_type_t;

/* forward compatibility - controls behavior of log buffering when
 * buffer is full. */
typedef enum {
  /* reject log attempts when buffer is full. */
  MTEV_LOGBUF_ONFULL_REJECT,
  /* anticipate adding ability to overwrite "oldest" logs when buffer
   * is full. */
} mtev_logbuf_onfull_t;

/* ABI risk: this structure is not opaque, because users need to look
 * into this structure to make logging efficient. */
struct _mtev_logbuf_log_t {
  size_t size;
  size_t align;
  int nargs;
  mtev_logbuf_type_t *args;
  size_t arg_offsets[];
};

/* create a memory buffer that can be used to capture logs with little
 * run-time overhead. */
API_EXPORT(mtev_logbuf_t *) mtev_logbuf_create(size_t size, mtev_logbuf_onfull_t on_full);
API_EXPORT(void) mtev_logbuf_destroy(mtev_logbuf_t *logbuf);

API_EXPORT(mtev_logbuf_log_t *) mtev_logbuf_create_log(mtev_logbuf_type_t *args, size_t nargs);
API_EXPORT(void) mtev_logbuf_destroy_log(mtev_logbuf_log_t *log);

API_EXPORT(void *)
mtev_logbuf_log_start(mtev_logbuf_t *logbuf, const mtev_logbuf_log_t *log, struct timeval now);
API_EXPORT(void) mtev_logbuf_log_commit(const mtev_logbuf_log_t *log, void *buf);

#define MTEV_LOGBUF_LOG_FN(name, type)                                                           \
  static inline void mtev_logbuf_log_##name(void *buf, const mtev_logbuf_log_t *log, size_t arg, \
                                            type value)                                          \
  {                                                                                              \
    uintptr_t wr_pos = (uintptr_t) buf + log->args[arg];                                         \
    *((type *) wr_pos) = value;                                                                  \
  }                                                                                              \
  /* to allow macro invocations to use semicolons */                                             \
  extern void *__unused_mtev_logbuf_log_##name

MTEV_LOGBUF_LOG_FN(string, const char *);
MTEV_LOGBUF_LOG_FN(pointer, void *);
MTEV_LOGBUF_LOG_FN(int32, int32_t);
MTEV_LOGBUF_LOG_FN(uint32, uint32_t);
MTEV_LOGBUF_LOG_FN(int64, int64_t);
MTEV_LOGBUF_LOG_FN(uint64, uint64_t);

API_EXPORT(void) mtev_logbuf_reset(mtev_logbuf_t *logbuf);
API_EXPORT(void) mtev_logbuf_dump(mtev_log_stream_t ls, mtev_logbuf_t *logbuf);

/* example usage:
 *   mtev_logbuf_type_t logtypes[] = {
 *     MTEV_LOGBUF_TYPE_STRING, MTEV_LOGBUF_TYPE_INT32
 *   };
 *   mtev_logbuf_log_t *log = mtev_logbuf_log_create(logtypes, 2);
 *
 *   static inline void log_string_then_int32(mtev_logbuf_t *logbuf,
 *                                            const char *string, int32_t int) {
 *     void *buf = mtev_logbuf_log_start(logbuf, log);
 *     mtev_logbuf_log_string(buf, log, 0, string);
 *     mtev_logbuf_log_int32(buf, log, 1, int);
 *     mtev_logbuf_log_commit(buf, logbuf);
 *   }
 */

#endif
