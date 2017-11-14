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

#ifndef MTEV_FRRH_H
#define MTEV_FRRH_H

#include <mtev_defines.h>

typedef struct mtev_frrh_entry_t {
  uint32_t keylen;
  uint8_t key[];
} mtev_frrh_entry_t;

#define MTEV_FRRH_DATA(e, keylen) (void *)(((uintptr_t)(e)->key + keylen + 7) & ~0x7ULL)

typedef struct mtev_frrh_t mtev_frrh_t;

typedef uint64_t (*mtev_frrh_hash)(const void *, size_t);
typedef void *(*mtev_frrh_alloc_entry)(size_t);
typedef void (*mtev_frrh_free_entry)(void *);

API_EXPORT(mtev_frrh_t *)
  mtev_frrh_alloc(uint64_t size, size_t datasize, uint32_t prob,
                  mtev_frrh_hash,
                  mtev_frrh_alloc_entry, mtev_frrh_free_entry);


API_EXPORT(void)
  mtev_frrh_adjust_prob(mtev_frrh_t *, uint32_t);

API_EXPORT(void)
  mtev_frrh_stats(mtev_frrh_t *, uint64_t *accesses, uint64_t *hits);

API_EXPORT(const void *)
  mtev_frrh_get(mtev_frrh_t *, const void *key, uint32_t keylen);

API_EXPORT(mtev_boolean)
  mtev_frrh_set(mtev_frrh_t *, const void *key, uint32_t keylen, const void *data);

#endif
