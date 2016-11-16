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
#include "mtev_atomic.h"
#include <ck_hs.h>

typedef void (*NoitHashFreeFunc)(void *);

typedef enum mtev_hash_lock_mode {
  MTEV_HASH_LOCK_MODE_NONE = 0,
  MTEV_HASH_LOCK_MODE_MUTEX = 1,
  MTEV_HASH_LOCK_MODE_SPIN = 2
} mtev_hash_lock_mode_t;


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
    void *ptr;
  } key;
  union {
    const char *str;
    void *ptr;
  } value;
  int klen;
} mtev_hash_iter;

/* mdb support relies on this being exposed */
typedef struct ck_key {
  u_int32_t len;
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
#define MTEV_HASH_ITER_ZERO { CK_HS_ITERATOR_INITIALIZER }
#define MTEV_HASH_DEFAULT_SIZE (1<<7)

/**
 * will default to LOCK_MODE_MUTEX
 */
void mtev_hash_init(mtev_hash_table *h);
/**
 * will default to LOCK_MODE_MUTEX
 */
void mtev_hash_init_size(mtev_hash_table *h, int size);
/**
 * Choose the lock mode when initing the hash.
 * 
 * It's worth noting that the lock only affects the write side of the hash,
 * the read side remains completely lock free.
 */
void mtev_hash_init_locks(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode);

/* NOTE! "k" and "data" MUST NOT be transient buffers, as the hash table
 * implementation does not duplicate them.  You provide a pair of
 * NoitHashFreeFunc functions to free up their storage when you call
 * mtev_hash_delete(), mtev_hash_delete_all() or mtev_hash_destroy().
 * */
int mtev_hash_store(mtev_hash_table *h, const char *k, int klen, void *data);
int mtev_hash_replace(mtev_hash_table *h, const char *k, int klen, void *data,
                      NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree);
int mtev_hash_retrieve(mtev_hash_table *h, const char *k, int klen, void **data);
int mtev_hash_retr_str(mtev_hash_table *h, const char *k, int klen, const char **dstr);
int mtev_hash_delete(mtev_hash_table *h, const char *k, int klen,
                     NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree);
void mtev_hash_delete_all(mtev_hash_table *h, NoitHashFreeFunc keyfree,
                          NoitHashFreeFunc datafree);
void mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree,
                       NoitHashFreeFunc datafree);
int mtev_hash_size(mtev_hash_table *h);

/* This is a convenience function only.  It assumes that all keys and values
 * in the destination hash are strings and allocated with malloc() and
 * assumes that the source contains only keys and values that can be
 * suitably duplicated by strdup().
 */
void mtev_hash_merge_as_dict(mtev_hash_table *dst, mtev_hash_table *src);

/* This is an iterator and requires the hash to not be written to during the
   iteration process.
   To use:
     mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

     while(mtev_hash_adv(h, &iter)) {
       .... use iter.key.{str,ptr}, iter.klen and iter.value.{str,ptr} ....
     }
*/
int mtev_hash_adv(mtev_hash_table *h, mtev_hash_iter *iter);

/* These are older, more painful APIs... use mtev_hash_adv */
/* Note that neither of these sets the key, value, or klen in iter */
int mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter,
                   const char **k, int *klen, void **data);
int mtev_hash_next_str(mtev_hash_table *h, mtev_hash_iter *iter,
                       const char **k, int *klen, const char **dstr);

u_int32_t mtev_hash__hash(const char *k, u_int32_t length, u_int32_t initval);

#endif
