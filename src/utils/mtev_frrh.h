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

/*! \fn mtev_frrh_t * mtev_frrh_alloc(uint64_t size, size_t datasize, uint32_t prob, mtev_frrh_hash hashf, mtev_frrh_alloc_entry allocf, mtev_frrh_free_entry freef)
    \brief Allocate a fast random replacement hash.
    \param size is the total capacity of the hash.
    \param datasize is the fixed-size of the data which will be stored.
    \param prob is the probability of replaement on collision (0 to UINT_MAX).
    \param hashf is the hashing function, NULL uses XXH64.
    \param allocf is the allocation function to use, NULL uses malloc.
    \param freef is the free function to use, NULL uses free.
    \return a pointer to a `mtev_frrh_t` on success, NULL otherwise.
 */
API_EXPORT(mtev_frrh_t *)
  mtev_frrh_alloc(uint64_t size, size_t datasize, uint32_t prob,
                  mtev_frrh_hash,
                  mtev_frrh_alloc_entry, mtev_frrh_free_entry);


/*! \fn void mtev_frrh_adjust_prob(mtev_frrh_t *cache, uint32_t prob)
    \brief Change the replacement probability on a `mtev_frrh_t`.
    \param cache the `mtev_frrh_t` on which to change the probability.
    \param prob is the probability of replaement on collision (0 to UINT_MAX).
*/
API_EXPORT(void)
  mtev_frrh_adjust_prob(mtev_frrh_t *, uint32_t);

/*! \fn void mtev_frrh_stats(mtev_frrh_t *cache, uint64_t *accesses, uint64_t *hits)
    \brief Retrieve access and hit statatistics.
    \param cache the `mtev_frrh_t` in question.
    \param accesses is an optional out pointer to store the number of accesses.
    \param hits is an optional out pointer to store the number of hits.
*/
API_EXPORT(void)
  mtev_frrh_stats(mtev_frrh_t *, uint64_t *accesses, uint64_t *hits);


/*! \fn const void * mtev_frrh_get(mtev_frrh_t *cache, const void *key, uint32_t keylen)
    \brief Retrieves the data associated with the provided key from the cache.
    \param cache a `mtev_frrh_t`.
    \param key a pointer to the key.
    \param keylen the length of the key in bytes.
    \return a pointer to a copy of the data store with the key.
*/
API_EXPORT(const void *)
  mtev_frrh_get(mtev_frrh_t *, const void *key, uint32_t keylen);

/*! \fn mtev_boolean mtev_frrh_set(mtev_frrh_t *cache, const void *key, uint32_t keylen, const void *data)
    \brief Possibly set a key-value pair in a `mtev_frrh_t`
    \param cache a `mtev_frrh_t`.
    \param key a pointer to the key.
    \param keylen the length of the key in bytes.
    \param data a pointer to the data (must be of the specified datasize for the `mtev_frrh_t`.
    \return `mtev_true` if added, `mtev_false` if not.
*/
API_EXPORT(mtev_boolean)
  mtev_frrh_set(mtev_frrh_t *, const void *key, uint32_t keylen, const void *data);

#endif
