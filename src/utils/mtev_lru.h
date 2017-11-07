/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names
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

#ifndef _MTEV_LRU_H
#define _MTEV_LRU_H

#include "mtev_defines.h"

typedef struct mtev_lru mtev_lru_t;
typedef void *mtev_lru_entry_token;

/**
 * make an LRU cache of max_entries.  call free_fn when an item is evicted.
 * if free_fn is null, call free.  If max_entries == -1 then this devolves to a normal hashtable
 */
API_EXPORT(mtev_lru_t *)
  mtev_lru_create(int32_t max_entries, void (*free_fn)(void *));

API_EXPORT(void)
  mtev_lru_destroy(mtev_lru_t *lru);

API_EXPORT(void)
  mtev_lru_invalidate(mtev_lru_t *lru);

/* if some other thread has added a val at this key this will overwrite it */
API_EXPORT(mtev_boolean)
  mtev_lru_put(mtev_lru_t *lru, const char *key, size_t key_len, void *value);

API_EXPORT(mtev_lru_entry_token)
  mtev_lru_get(mtev_lru_t *lru, const char *key, size_t key_len, void **value);

API_EXPORT(void)
  mtev_lru_release(mtev_lru_t *lru, mtev_lru_entry_token token);

/**
 * remove key from cache.  This does not call the free_fn, instead it returns the value
 */
API_EXPORT(void *)
  mtev_lru_remove(mtev_lru_t *lru, const char *key, size_t key_len);

API_EXPORT(int32_t)
  mtev_lru_size(mtev_lru_t *lru);

#endif
