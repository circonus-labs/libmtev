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

#ifndef _MTEV_LFU_H
#define _MTEV_LFU_H

#include "mtev_defines.h"

typedef struct mtev_lfu mtev_lfu_t;
typedef void *mtev_lfu_entry_token;

/*!
  \fn mtev_lfu_create(int32_t max_entries, void (*free_fn)(void *))
  \brief Create an LFU of max_entries size

  Will call free_fn when an item is evicted. if free_fn is null, call free().
  If max_entries == -1 then this devolves to a normal hashtable.
 */
API_EXPORT(mtev_lfu_t *)
  mtev_lfu_create(int32_t max_entries, void (*free_fn)(void *));

/*!
  \fn mtev_lfu_destroy(mtev_lfu_t *)
  \brief Destroy the LFU
 */
API_EXPORT(void)
  mtev_lfu_destroy(mtev_lfu_t *lfu);

/*!
  \fn mtev_lfu_invalidate(mtev_lfu_t *)
  \brief Remove all entries from the LFU
 */
API_EXPORT(void)
  mtev_lfu_invalidate(mtev_lfu_t *lfu);

/*!
  \fn mtev_lfu_put(mtev_lfu_t *lfu, const char *key, size_t key_len, void *value)
  \brief Put a new item into the LFU

  If some other thread has added a val at this key this will overwrite it and
  restart the frequency count at 1.

  This will cause an eviction of the least frequently used item if the cache is full.
 */
API_EXPORT(mtev_boolean)
  mtev_lfu_put(mtev_lfu_t *lfu, const char *key, size_t key_len, void *value);

/*!
  \fn mtev_lfu_entry_token mtev_lfu_get(mtev_lfu_t *lfu, const char *key, size_t key_len, void **value)
  \brief Get an item from the LFU by key

  This will fetch the item at "key" and put the value in "value". It will also
  return a token as the return value of the function.  This token is used
  as the checkout of the item from the LFU.  When you are finished using
  the value, you must call "mtev_lfu_release(mtev_lfu_t *lfu, mtev_lfu_entry_token token)"
  to let the LFU know that reclamation for that key/value is possible.
 */
API_EXPORT(mtev_lfu_entry_token)
  mtev_lfu_get(mtev_lfu_t *lfu, const char *key, size_t key_len, void **value);

/*!
  \fn void mtev_lfu_release(mtev_lfu_t *lfu, mtev_lfu_entry_token token)
  \brief Surrender an item back to the LFU

  To be memory safe LFU tokens must be released back to the LFU when
  the user is finished using them.
 */
API_EXPORT(void)
  mtev_lfu_release(mtev_lfu_t *lfu, mtev_lfu_entry_token token);

/*!
  \fn mtev_lfu_remove(mtev_lfu_t *lfu, const char *key, size_t key_len)
  \brief Remove key from the LFU

  This does not call the free_fn, instead it returns the value
 */
API_EXPORT(void *)
  mtev_lfu_remove(mtev_lfu_t *lfu, const char *key, size_t key_len);

/*!
  \fn mtev_lfu_size(mtev_lfu_t *lfu)
  \brief Return the total entry count in the LFU
 */
API_EXPORT(int32_t)
  mtev_lfu_size(mtev_lfu_t *lfu);

#endif
