/*
 * Copyright (c) 2005-2007, OmniTI Computer Consulting, Inc.
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

/* this is just a copy (with search and replace) from jlog_hash */

#ifndef _MTEV_HASH_H
#define _MTEV_HASH_H

#include "mtev_config.h"
#include <ck_hs.h>
#include <ck_spinlock.h>

typedef void (*NoitHashFreeFunc)(void *);

typedef enum mtev_hash_lock_mode {
  MTEV_HASH_LOCK_MODE_NONE = 0,
  MTEV_HASH_LOCK_MODE_MUTEX = 1,
  MTEV_HASH_LOCK_MODE_SPIN = 2
} mtev_hash_lock_mode_t;

#define MTEV_HASH_FAILURE 0
#define MTEV_HASH_SUCCESS 1
#define MTEV_HASH_SUCCESS_REPLACEMENT 2

typedef struct mtev_hash_table {
  union {
    ck_hs_t hs;
    /**
     * This is evil.  In order to maintain ABI compat
     * we are sneaking lock info into a pointer
     * in the leftover space for cache alignment
     *
     * A ck_hs_t is ~48 bytes but since it has
     * always been declared up to a cache line
     * there is trailing space we can sneak a
     * pointer into
     */
    struct {
      char pad[sizeof(ck_hs_t)];
      void *locks;
    } locks;
  } u CK_CC_CACHELINE;
} mtev_hash_table;

typedef struct mtev_hash_iter {
  ck_hs_iterator_t iter;
  union {
    const char *str;
    const void *ptr;
  } key;
  union {
    char *str;
    void *ptr;
  } value;
  int klen;
} mtev_hash_iter;

/* mdb support relies on this being exposed */
typedef struct ck_key {
  uint32_t len;
  char label[1];
} ck_key_t;

typedef struct ck_hash_attr {
  void *data;
  void *key_ptr;
  ck_key_t key;
} ck_hash_attr_t;

CK_CC_CONTAINER(ck_key_t, struct ck_hash_attr, key,
                index_attribute_container)

#define MTEV_HASH_EMPTY { {{ NULL, NULL, 0, 0, NULL, NULL}} }
#define MTEV_HASH_ITER_ZERO { .iter = CK_HS_ITERATOR_INITIALIZER, .key = { .ptr = NULL }, .value = { .ptr = NULL }, .klen = 0 }
#define MTEV_HASH_DEFAULT_SIZE (1<<7)

/*!
  \fn void mtev_hash_init(mtev_hash_table *h)
  \brief initialize a hash_table

  will default to LOCK_MODE_NONE and MTEV_HASH_DEFAULT_SIZE (1<<7)
 */
void mtev_hash_init(mtev_hash_table *h);

/*!
  \fn void mtev_hash_init_size(mtev_hash_table *h, int size)
  \brief initialize a hash_table with an initial size

  will default to LOCK_MODE_NONE
 */
void mtev_hash_init_size(mtev_hash_table *h, int size);

/*!
  \fn void mtev_hash_init_locks(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode)
  \brief choose the lock mode when initing the hash.

  It's worth noting that the lock only affects the write side of the hash,
  the read side remains completely lock free.
 */
void mtev_hash_init_locks(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode);

/*!
  \fn void mtev_hash_init_mtev_memory(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode)
  \brief choose the lock mode when initing the hash.

  It's worth noting that the lock only affects the write side of the hash,
  the read side remains completely lock free.

  This variant will use mtev_memory ck allocator functions to allow this
  hash to participate in SMR via mtev_memory transactions.  You need to wrap
  memory transactions in mtev_memory_begin()/mtev_memory_end()
 */
void mtev_hash_init_mtev_memory(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode);

/*!
  \fn int mtev_hash_store(mtev_hash_table *h, const void *k, int klen, const void *data)
  \brief put something in the hash_table

  This will fail if the key already exists in the hash_table

  NOTE! "k" and "data" MUST NOT be transient buffers, as the hash table
  implementation does not duplicate them.  You provide a pair of
  NoitHashFreeFunc functions to free up their storage when you call
  mtev_hash_delete(), mtev_hash_delete_all() or mtev_hash_destroy().
 */
int mtev_hash_store(mtev_hash_table *h, const void *k, int klen, const void *data);

/*!
  \fn int mtev_hash_replace(mtev_hash_table *h, const void *k, int klen, const void *data, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
  \brief replace and delete (call keyfree and datafree functions) anything that was already in this hash location
 */
int mtev_hash_replace(mtev_hash_table *h, const void *k, int klen, const void *data,
                      NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree);

/*!
  \fn int mtev_hash_set(mtev_hash_table *h, const void *k, int klen, const void *data, char **oldkey, void **olddata)
  \brief replace and return the old value and old key that was in this hash location

  will return MTEV_HASH_SUCCESS on successful set with no replacement
  will return MTEV_HASH_FAILURE on failure to set
  will return MTEV_HASH_SUCCESS_REPLACEMENT on successful set with replacement
 */
int mtev_hash_set(mtev_hash_table *h, const void *k, int klen, const void *data,
                  char **oldkey, void **olddata);

/*!
  \fn int mtev_hash_retrieve(mtev_hash_table *h, const void *k, int klen, void **data)
  \brief fetch the value at "k" into "data"
 */
int mtev_hash_retrieve(mtev_hash_table *h, const void *k, int klen, void **data);

/*!
  \fn void * mtev_hash_get(mtev_hash_table *h, const void *k, int klen)
  \brief return the value at "k
 */
void *mtev_hash_get(mtev_hash_table *h, const void *k, int klen);

/*!
  \fn int mtev_hash_retr_str(mtev_hash_table *h, const void *k, int klen, const char **dstr)
  \brief fetch the value at "k" into "data" as a string
 */
int mtev_hash_retr_str(mtev_hash_table *h, const void *k, int klen, const char **dstr);

/*!
  \fn int mtev_hash_delete(mtev_hash_table *h, const void *k, int klen, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
  \brief remove the key/value stored at "k" and call keyfree and datafree if they are provided
 */
int mtev_hash_delete(mtev_hash_table *h, const void *k, int klen,
                     NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree);

/*!
  \fn void mtev_hash_delete_all(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
  \brief remove all keys and values and call keyfree and datafree if they are provided
 */
void mtev_hash_delete_all(mtev_hash_table *h, NoitHashFreeFunc keyfree,
                          NoitHashFreeFunc datafree);
/*!
  \fn void mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
  \brief remove all keys and values and call keyfree and datafree if they are provided but also wipe out the underlying map

  This must be called on any hash_table that has been mtev_hash_inited or it will leak memory
 */
void mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree,
                       NoitHashFreeFunc datafree);

/*!
  \fn int mtev_hash_size(mtev_hash_table *h)
  \brief return the number of entries in the hash_table
 */
int mtev_hash_size(mtev_hash_table *h);

/*!
  \fn void mtev_hash_merge_as_dict(mtev_hash_table *dst, mtev_hash_table *src)
  \brief merge string values in "src" into "dst"

  This is a convenience function only.  It assumes that all keys and values
  in the destination hash are strings and allocated with malloc() and
  assumes that the source contains only keys and values that can be
  suitably duplicated by strdup().
 */
void mtev_hash_merge_as_dict(mtev_hash_table *dst, const mtev_hash_table *src);

/*!
  \fn  int mtev_hash_adv(mtev_hash_table *h, mtev_hash_iter *iter)
  \brief iterate through key/values in the hash_table

  This is an iterator and requires the hash to not be written to during the
   iteration process.
   To use:
     mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

     while(mtev_hash_adv(h, &iter)) {
       .... use iter.key.{str,ptr}, iter.klen and iter.value.{str,ptr} ....
     }
*/
int mtev_hash_adv(const mtev_hash_table *h, mtev_hash_iter *iter);

/*!
  \fn int mtev_hash_adv_spmc(mtev_hash_table *h, mtev_hash_iter *iter)
  \brief iterate through the key/values in the hash_table

   This is an iterator and requires that if the hash it written to
   during the iteration process, you must employ SMR on the hash itself
   to prevent destruction of memory for hash resizes by using the
   special init function mtev_hash_init_mtev_memory.

   To use:
   mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

   while(mtev_hash_adv_spmc(h, &iter)) {
   .... use iter.key.{str,ptr}, iter.klen and iter.value.{str,ptr} ....
   }
*/
int mtev_hash_adv_spmc(const mtev_hash_table *h, mtev_hash_iter *iter);

/*!
  \fn int mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter, const char **k, int *klen, void **data)
  \brief iterate through the key/values in the hash_table


  These are older, more painful APIs... use mtev_hash_adv
   Note that neither of these sets the key, value, or klen in iter
*/
int mtev_hash_next(const mtev_hash_table *h, mtev_hash_iter *iter,
                   const char **k, int *klen, void **data);

/*!
  \fn int mtev_hash_next_str(mtev_hash_table *h, mtev_hash_iter *iter, const char **k, int *klen, const char **dstr)
  \brief iterate through the key/values in the hash_table as strings


  These are older, more painful APIs... use mtev_hash_adv */
/* Note that neither of these sets the key, value, or klen in iter */
int mtev_hash_next_str(const mtev_hash_table *h, mtev_hash_iter *iter,
                       const char **k, int *klen, const char ** dstr);


/*!
  \fn uint32_t mtev_hash__hash(const void *k, uint32_t length, uint32_t initval)
  \brief the internal hash function that mtev_hash_table uses exposed for external usage
 */
uint32_t mtev_hash__hash(const void *k, uint32_t length, uint32_t initval);

#define mtev_hash_dict_init(h) mtev_hash_init(h)
#define mtev_hash_dict_replace(h,a,b) mtev_hash_replace((h),strdup(a),strlen(a),strdup(b),free,free)
#define mtev_hash_dict_store(h,a,b) mtev_hash_store((h),strdup(a),strlen(a),strdup(b))
#define mtev_hash_dict_delete(h,a) mtev_hash_delete((h),(a),strlen(a),free,free)
#define mtev_hash_dict_get(h,a) (char *)mtev_hash_get((h),(a),strlen(a))
#define mtev_hash_dict_delete_all(h) mtev_hash_delete_all((h),free,free)
#define mtev_hash_dict_destroy(h) mtev_hash_destroy((h),free,free)
#define mtev_hash_dict_adv mtev_hash_adv

#endif
