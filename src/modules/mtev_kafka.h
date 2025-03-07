/*
 * Copyright (c) 2025, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_KAFKA_HPP
#define _MTEV_KAFKA_HPP

#include "mtev_defines.h"
#include "mtev_hooks.h"
#include "mtev_log.h"

#include <ck_pr.h>

#ifndef _RDKAFKA_H_
typedef void rd_kafka_message_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtev_rd_kafka_message {
  rd_kafka_message_t *msg;
  uint32_t refcnt;
  const void *key;
  size_t key_len;
  const void *payload;
  size_t payload_len;
  int64_t offset;
  int32_t partition;
  const char *protocol;
  const mtev_hash_table *extra_configs;
  void (*free_fn)(struct mtev_rd_kafka_message *m);
} mtev_rd_kafka_message_t;

static inline void mtev_rd_kafka_message_ref(mtev_rd_kafka_message_t *msg)
{
  ck_pr_inc_uint(&msg->refcnt);
}

static inline void mtev_rd_kafka_message_deref(mtev_rd_kafka_message_t *msg)
{
  bool zero;
  ck_pr_dec_uint_zero(&msg->refcnt, &zero);
  if (zero) {
    if (msg->free_fn) {
      msg->free_fn(msg);
    }
  }
}

// TODO: Need write hooks

MTEV_HOOK_PROTO(mtev_kafka_handle_message_dyn,
                (mtev_rd_kafka_message_t * msg),
                void *,
                closure,
                (void *closure, mtev_rd_kafka_message_t *msg))

/* This maps exposes a runtime resolved hook register function people should
 * use: mtev_kafka_handle_message_hook_register
 */
MTEV_RUNTIME_AVAIL(mtev_kafka_handle_message_hook_register,
                   mtev_kafka_handle_message_dyn_hook_register)
MTEV_RUNTIME_RESOLVE(mtev_kafka_handle_message_hook_register,
                     mtev_kafka_handle_message_dyn_hook_register,
                     mtev_hook_return_t,
                     (const char *name,
                      mtev_hook_return_t (*func)(void *closure, mtev_rd_kafka_message_t *msg),
                      void *closure),
                     (name, func, closure))

#ifdef __cplusplus
}
#endif

#endif
