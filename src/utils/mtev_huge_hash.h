/*
 * Copyright (c) 2018, Circonus, Inc. All rights reserved.
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
 *    * Neither the name Circonnus, Inc. nor the names
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

#ifndef _MTEV_HUGE_HASH_H
#define _MTEV_HUGE_HASH_H


#include "mtev_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This is a disk backed hash table of arbitrary size (up to free space on disk).
 * 
 * If the used space is small enough to fit in RAM it will provide O(log N) search, 
 * insert and delete time.  If it will not fit wholly in RAM the operations are the
 * same but paging by the OS will slow down performance considerably.
 * 
 * Entries are stored sorted in key order and iteration will always be in key order.
 * 
 * Memory returned on `retrieve` calls is owned by the huge_hash and if you intend to 
 * use it you should copy it if the huge_hash is destroyed or you intend to alter the memory.
 * 
 * Example usage:
 * 
 * // create will ensure /var/tmp/my_hash exists as an on-disk database, 
 * // if it already exists, it will open it
 * mtev_huge_hash_t *hh = mtev_huge_hash_create("/var/tmp/my_hash");
 * mtev_huge_hash_store(hh, "foo", 3, "bar", 3);
 * 
 * size_t val_len = 0;
 * void *x = mtev_huge_hash_retrieve(hh, "foo", 3, &val_len);
 * 
 * // if you want to purge the data from disk:
 * mtev_huge_hash_destroy(hh);
 * 
 * // if you want the data to stick around:
 * mtev_huge_hash_close(hh);
 * 
 * 
 */


typedef struct mtev_huge_hash mtev_huge_hash_t;
typedef struct mtev_huge_hash_iter mtev_huge_hash_iter_t; 

/*!
  \fn mtev_huge_hash_t *mtev_huge_hash_create(const char *path)
  \brief create or open a huge_hash

  Failure to open or create will return NULL and errno will be set appropriately.
  See: mtev_huge_hash_strerror()
 */
mtev_huge_hash_t *mtev_huge_hash_create(const char *path);
void mtev_huge_hash_close(mtev_huge_hash_t *hh);
void mtev_huge_hash_destroy(mtev_huge_hash_t *hh);

/*!
  \fn int mtev_huge_hash_store(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data, size_t dlen)
  \brief put something in the huge_hash

  This will fail if the key already exists in the hash_table
  Copies are made of `k` and `data`
  
  Returns mtev_true on success
 */
mtev_boolean mtev_huge_hash_store(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data, size_t dlen);

/*!
  \fn int mtev_huge_hash_replace(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data, size_t dlen)
  \brief replace anything that was already in this hash location
 */
mtev_boolean mtev_huge_hash_replace(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data, size_t dlen);

/*!
  \fn const void *mtev_huge_hash_retrieve(mtev_huge_hash_t *hh, const void *k, size_t klen, size_t *data_len)
  \brief return the value at "k" and fill data_len with sizeof the data
   
  The memory returned here is owned by the huge_hash.  Do not modify
 */
const void *mtev_huge_hash_retrieve(mtev_huge_hash_t *hh, const void *k, size_t klen, size_t *data_len);

/*!
  \fn mtev_boolean mtev_huge_hash_delete(mtev_huge_hash_t *hh, const void *k, size_t klen)
  \brief remove the key/value stored at "k"
 */
mtev_boolean mtev_huge_hash_delete(mtev_huge_hash_t *h, const void *k, size_t klen);

/*!
  \fn size_t mtev_huge_hash_size(mtev_huge_hash_t *hh)
  \brief return the number of entries in the huge_hash
 */
size_t mtev_huge_hash_size(mtev_huge_hash_t *hh);

/*!
  \fn mtev_huge_hash_iter_t *mtev_huge_hash_create_iter(mtev_huge_hash_t *hh);
  \brief create an iterator for walking the huge_hash
   
  Note that the existence of an interator can prevent calls to mtev_huge_hash_store
  from completing if the underlying data has to resize.  Iterate with caution.
*/
mtev_huge_hash_iter_t *mtev_huge_hash_create_iter(mtev_huge_hash_t *hh);

void mtev_huge_hash_destroy_iter(mtev_huge_hash_iter_t *it);

/*!
  \fn  int mtev_huge_hash_adv(mtev_huge_hash_iter_t *iter)
  \brief iterate through key/values in the hash_table

   To use:
     mtev_huge_hash_iter_t *iter = mtev_huge_hash_create_iter(hh);

     while(mtev_huge_hash_adv(iter)) {
       size_t key_len, data_len;
       void *k = mtev_huge_hash_iter_key(iter, &key_len);
       void *d = mtev_huge_hash_iter_value(iter, &data_len);
     }
*/
mtev_boolean mtev_huge_hash_adv(mtev_huge_hash_iter_t *iter);

void *mtev_huge_hash_iter_key(mtev_huge_hash_iter_t *iter, size_t *key_len);
void *mtev_huge_hash_iter_val(mtev_huge_hash_iter_t *iter, size_t *val_len);

#ifdef __cplusplus
}
#endif

#endif
