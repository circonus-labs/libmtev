/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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

#ifndef MTEV_INTERN_H
#define MTEV_INTERN_H

#include "mtev_defines.h"
#include <stdint.h>

typedef struct {
  uintptr_t opaque1;
} mtev_intern_t;

extern const mtev_intern_t mtev_intern_null;

typedef struct {
  size_t      extent_size;
  int         estimated_item_count;
  const char *backing_directory;
} mtev_intern_pool_attr_t;

typedef struct {
  uint32_t  item_count;
  uint32_t  extent_count;
  size_t    allocated;
  size_t    internal_memory;
  size_t    available_total;
  size_t    available[32];
  uint32_t  fragments_total;
  uint32_t  fragments[32];
  uint32_t  staged_count;
  size_t    staged_size;
} mtev_intern_pool_stats_t;

typedef struct mtev_intern_pool mtev_intern_pool_t;

#define MTEV_INTERN_DEFAULT_POOL ((mtev_intern_pool_t *)NULL)

/*! \fn mtev_intern_pool_t *mtev_intern_pool_new(mtev_intern_pool_attr_t *attr)
    \brief Create a new intern pool.
    \param attr the attributes describing the pool.
    \return A new intern pool.
 */
API_EXPORT(mtev_intern_pool_t *)
  mtev_intern_pool_new(mtev_intern_pool_attr_t *);

/*! \fn mtev_intern_t mtev_intern_pool_str(mtev_intern_pool_t *pool, const char *buff, size_t len)
    \brief Request an interned string item with specific contents.
    \param pool The pool in which to intern the string.
    \param buff The string to be interned.
    \param len The length of `buff`. `len` must be less than 2^23-1. If 0, strlen will be invoked.
    \return A new, or pre-existing intern from the pool.

    This function will attempt to find the specified string in the pool, but create it on absence.
    The reference count of the interned string returned will be increased and it must be released
    using `mtev_intern_release_pool`.
 */
API_EXPORT(mtev_intern_t)
  mtev_intern_pool_str(mtev_intern_pool_t *, const char *, size_t);

/*! \fn mtev_intern_t mtev_intern_pool(mtev_intern_pool_t *pool, const void *buff, size_t len)
    \brief Request an interned data item with specific contents.
    \param pool The pool in which to intern the data.
    \param buff The data to be interned.
    \param len The length of data to be considered (0, 2^23)
    \return A new, or pre-existing intern from the pool.

    This function will attempt to find the specified data in the pool, but create it on absence.
    The reference count of the interned object returned will be increased and it must be released
    using `mtev_intern_release_pool`.
 */
API_EXPORT(mtev_intern_t)
  mtev_intern_pool(mtev_intern_pool_t *, const void *, size_t);

/*! \fn mtev_intern_t mtev_intern_str(const char *buff, size_t len)
    \brief Like `mtev_intern_pool` invoked with `MTEV_INTERN_DEFAULT_POOL`.
    \param buff The string to be interned.
    \param len The length of string. `len` must be less than 2^23-1. If 0, strlen will be invoked.
    \return A new, or pre-existing intern from the default pool.
 */
API_EXPORT(mtev_intern_t)
  mtev_intern_str(const char *, size_t);

/*! \fn mtev_intern_t mtev_intern(const void *buff, size_t len)
    \brief Like `mtev_intern_pool` invoked with `MTEV_INTERN_DEFAULT_POOL`.
    \param buff The data to be interned.
    \param len The length of data to be considered (0, 2^23)
    \return A new, or pre-existing intern from the default pool.
 */
API_EXPORT(mtev_intern_t)
  mtev_intern(const void *, size_t);

/*! \fn mtev_intern_t mtev_intern_copy(const mtev_intern_t iv)
    \brief Return a reference to an existing `mtev_intern_t`.
    \param iv An existing, valid `mtev_intern_t`
    \return A reference to the interned data.

    The copy must be released just as if you created it via `mtev_intern_pool`.
 */
API_EXPORT(mtev_intern_t)
  mtev_intern_copy(const mtev_intern_t);

/*! \fn void mtev_intern_release_pool(mtev_intern_pool_t *pool, mtev_intern_t iv)
    \brief Release interned data back to a pool.
    \param pool The pool to release `iv` to.
    \param iv The interned value to release.

    Interned values must be released to the pool they were retrieved from.  Attempting
    to release to a different pool will cause a crash.
*/
API_EXPORT(void)
  mtev_intern_release_pool(mtev_intern_pool_t *, mtev_intern_t);

/*! \fn void mtev_intern_release(mtev_intern_t iv)
    \brief Release interned data back to the pool from which it was allocated.
    \param iv The interned value to release.
 */
API_EXPORT(void)
  mtev_intern_release(mtev_intern_t);

/*! \fn uint32_t mtev_intern_get_refcnt(mtev_intern_t iv)
    \brief Retrieve the current refcnt for an intern item.
    \param iv The interned value.
    \return The number of references currently outstanding.
*/
API_EXPORT(uint32_t)
  mtev_intern_get_refcnt(mtev_intern_t);

/*! \fn const char *mtev_intern_get_cstr(const mtev_intern_t iv, size_t *len)
    \brief Retrieve the string from an `mtev_intern_t` type.
    \param iv The interned data.
    \param len An out value for the length of the string. Unused if NULL.
    \return The string contained in the interned value.

    The return value is only valid until `mtev_intern_release*` is called.
 */
#define miSTR(a) mtev_intern_get_str((a), NULL)
#define miSTRL(a,b) mtev_intern_get_str((a), (b))
API_EXPORT(const char *)
  mtev_intern_get_str(const mtev_intern_t, size_t *);

/*! \fn const void *mtev_intern_get_ptr(const mtev_intern_t iv, size_t *len)
    \brief Retrieve the data from an `mtev_intern_t` type.
    \param iv The interned data.
    \param len An out value for the length of the string. Unused if NULL.
    \return The memory contained in the interned value.

    The return value is only valid until `mtev_intern_release*` is called.
 */
#define miPTR(a) mtev_intern_get_ptr((a), NULL)
#define miPTRL(a,b) mtev_intern_get_ptr((a), (b))
API_EXPORT(const void *)
  mtev_intern_get_ptr(const mtev_intern_t, size_t *);

/*! \fn uint32_t mtev_intern_pool_item_count(mtev_intern_pool_t *pool)
    \brief Return the number of unique interned items in a pool.
    \param pool The pool to analyze.
    \return The number of unique interned items.
 */
API_EXPORT(uint32_t)
  mtev_intern_pool_item_count(mtev_intern_pool_t *);

/*! \fn int mtev_intern_pool_compact(mtev_intern_pool_t *pool, mtev_boolean force)
    \brief Attempt a compaction of an intern pool.
    \param pool The pool to compact.
    \param force A boolean dictating if compaction should be forced.
    \return The number of free fragment merges that occurred.

    This function will walk all the free fragment lists within the
    pool joining adjacent ones and promoting them into the the right
    slabs.  If force is false, compaction will be avoided if there are less
    than approximately 1.5x fragments as there were after the previous successful
    compaction.
  */
API_EXPORT(int)
  mtev_intern_pool_compact(mtev_intern_pool_t *, mtev_boolean force);

/*! \fn void mtev_intern_pool_stats(mtev_intern_pool_t *pool, mtev_intern_pool_stats_t *stats)
    \brief Return statistics for an intern pool.
    \param pool The pool to inspect.
    \param stats The statistics structure to fill out.
 */
API_EXPORT(void)
  mtev_intern_pool_stats(mtev_intern_pool_t *, mtev_intern_pool_stats_t *);

#endif
