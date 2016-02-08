/*
 * Copyright (c) 2014-2015, Circonus Inc. All rights reserved.
 * Copyright (c) 2005-2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
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

#include "mtev_config.h"
#include "mtev_hash.h"
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <ck_epoch.h>
#include <unistd.h>

#define ONSTACK_KEY_SIZE 128
#define NoitHASH_INITIAL_SIZE (1<<7)

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

static inline
u_int32_t __hash(const char *k, u_int32_t length, u_int32_t initval)
{
   register u_int32_t a,b,c,len;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((u_int32_t)k[1]<<8) +((u_int32_t)k[2]<<16) +((u_int32_t)k[3]<<24));
      b += (k[4] +((u_int32_t)k[5]<<8) +((u_int32_t)k[6]<<16) +((u_int32_t)k[7]<<24));
      c += (k[8] +((u_int32_t)k[9]<<8) +((u_int32_t)k[10]<<16)+((u_int32_t)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((u_int32_t)k[10]<<24);
   case 10: c+=((u_int32_t)k[9]<<16);
   case 9 : c+=((u_int32_t)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((u_int32_t)k[7]<<24);
   case 7 : b+=((u_int32_t)k[6]<<16);
   case 6 : b+=((u_int32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((u_int32_t)k[3]<<24);
   case 3 : a+=((u_int32_t)k[2]<<16);
   case 2 : a+=((u_int32_t)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

u_int32_t mtev_hash__hash(const char *k, u_int32_t length, u_int32_t initval) {
  return __hash(k,length,initval);
}

static unsigned long
hs_hash(const void *object, unsigned long seed)
{
  const ck_key_t *c = object;
  unsigned long h;

  h = (unsigned long)__hash((const char *)c, c->len, seed);
  return h;
}

static bool
hs_compare(const void *previous, const void *compare)
{
  const ck_key_t *prev_key = previous;
  const ck_key_t *cur_key = compare;
  return strcmp(prev_key->label, cur_key->label) == 0;
}

static int rand_init;
void mtev_hash_init(mtev_hash_table *h) {
  return mtev_hash_init_size(h, NoitHASH_INITIAL_SIZE);
}

static void *
ht_malloc(size_t r)
{
  return malloc(r);
}

static void
ht_free(void *p, size_t b, bool r)
{
  (void)b;
  (void)r;
  free(p);
  return;
}

static struct ck_malloc my_allocator = {
  .malloc = ht_malloc,
  .free = ht_free
};

#define CK_HS_EMPTY     NULL
#define CK_HS_TOMBSTONE ((void *)~(uintptr_t)0)
#define CK_HS_G     (2)
#define CK_HS_G_MASK    (CK_HS_G - 1)

#if defined(CK_F_PR_LOAD_8) && defined(CK_F_PR_STORE_8)
#define CK_HS_WORD          uint8_t
#define CK_HS_WORD_MAX	    UINT8_MAX
#define CK_HS_STORE(x, y)   ck_pr_store_8(x, y)
#define CK_HS_LOAD(x)       ck_pr_load_8(x)
#elif defined(CK_F_PR_LOAD_16) && defined(CK_F_PR_STORE_16)
#define CK_HS_WORD          uint16_t
#define CK_HS_WORD_MAX	    UINT16_MAX
#define CK_HS_STORE(x, y)   ck_pr_store_16(x, y)
#define CK_HS_LOAD(x)       ck_pr_load_16(x)
#elif defined(CK_F_PR_LOAD_32) && defined(CK_F_PR_STORE_32)
#define CK_HS_WORD          uint32_t
#define CK_HS_WORD_MAX	    UINT32_MAX
#define CK_HS_STORE(x, y)   ck_pr_store_32(x, y)
#define CK_HS_LOAD(x)       ck_pr_load_32(x)
#else
#error "ck_hs is not supported on your platform."
#endif

struct ck_hs_map {
  unsigned int generation[CK_HS_G];
  unsigned int probe_maximum;
  unsigned long mask;
  unsigned long step;
  unsigned int probe_limit;
  unsigned int tombstones;
  unsigned long n_entries;
  unsigned long capacity;
  unsigned long size;
  CK_HS_WORD *probe_bound;
  void **entries;
};

void mtev_hash_init_size(mtev_hash_table *h, int size) {
  if(!rand_init) {
    srand48((long int)time(NULL));
    rand_init = 1;
  }

  if(size < 8) size = 8;

  assert(ck_hs_init(&h->hs, CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC, hs_hash, hs_compare, &my_allocator,
                         size, lrand48()));
  assert(h->hs.hf != NULL);
}
int mtev_hash_size(mtev_hash_table *h) {
  if(h->hs.hf == NULL) mtev_hash_init(h);
  return ck_hs_count(&h->hs);
}
int mtev_hash_replace(mtev_hash_table *h, const char *k, int klen, void *data,
                      NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  long hashv;
  int ret;
  void *retrieved_key = NULL;
  ck_hash_attr_t *data_struct;
  ck_hash_attr_t *attr = calloc(1, sizeof(ck_hash_attr_t) + klen + 1);

  if(h->hs.hf == NULL) mtev_hash_init(h);

  memcpy(attr->key.label, k, klen);
  attr->key.label[klen] = 0;
  attr->key.len = klen + sizeof(u_int32_t);
  attr->data = data;
  attr->key_ptr = (char*)k;
  hashv = CK_HS_HASH(&h->hs, hs_hash, &attr->key);
  ret = ck_hs_set(&h->hs, hashv, &attr->key, &retrieved_key);
  if (ret) {
    if (retrieved_key) {
      data_struct = index_attribute_container(retrieved_key);
      if (data_struct) {
        if (keyfree) keyfree(data_struct->key_ptr);
        if (datafree) datafree(data_struct->data);
      }
      free(data_struct);
    }
  }
  else {
    free(attr);
  }
  return 1;
}
int mtev_hash_store(mtev_hash_table *h, const char *k, int klen, void *data) {
  long hashv;
  int ret = 0;
  ck_hash_attr_t *attr = calloc(1, sizeof(ck_hash_attr_t) + klen + 1);

  if(h->hs.hf == NULL) mtev_hash_init(h);

  memcpy(attr->key.label, k, klen);
  attr->key.label[klen] = 0;
  attr->key.len = klen + sizeof(u_int32_t);
  attr->key_ptr = (char*)k;
  attr->data = data;
  hashv = CK_HS_HASH(&h->hs, hs_hash, &attr->key);
  ret = ck_hs_put(&h->hs, hashv, &attr->key);
  if (!ret) free(attr);
  return ret;
}
int mtev_hash_retrieve(mtev_hash_table *h, const char *k, int klen, void **data) {
  long hashv;
  int ret;
  ck_key_t *retrieved_key;
  union {
    ck_key_t key;
    char pad[sizeof(ck_key_t) + ONSTACK_KEY_SIZE];
  } onstack_key;
  ck_key_t *key = &onstack_key.key;
  ck_hash_attr_t *data_struct;

  if(!h) return 0;
  if(h->hs.hf == NULL) mtev_hash_init(h);

  if(klen > ONSTACK_KEY_SIZE) key = calloc(1, sizeof(ck_key_t) + klen + 1);
  memcpy(key->label, k, klen);
  key->label[klen] = 0;
  key->len = klen + sizeof(u_int32_t);;
  hashv = CK_HS_HASH(&h->hs, hs_hash, key);
  retrieved_key = ck_hs_get(&h->hs, hashv, key);
  if (retrieved_key) {
    data_struct = index_attribute_container(retrieved_key);
    if (data) {
      if (data_struct) {
        *data = data_struct->data;
      }
      else {
        *data = NULL;
      }
    }
    if(key != &onstack_key.key) free(key);
    return 1;
  }
  if(key != &onstack_key.key) free(key);
  return 0;
}
int mtev_hash_retr_str(mtev_hash_table *h, const char *k, int klen, const char **dstr) {
  void *data;
  if(!h) return 0;
  if(mtev_hash_retrieve(h, k, klen, &data)) {
    if(dstr) *dstr = data;
    return 1;
  }
  return 0;
}
int mtev_hash_delete(mtev_hash_table *h, const char *k, int klen,
                     NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  long hashv;
  int ret;
  ck_hash_attr_t *data_struct;
  ck_key_t *retrieved_key;
  union {
    ck_key_t key;
    char pad[sizeof(ck_key_t) + ONSTACK_KEY_SIZE];
  } onstack_key;
  ck_key_t *key = &onstack_key.key;

  if(!h) return 0;
  if(h->hs.hf == NULL) mtev_hash_init(h);

  if(klen > ONSTACK_KEY_SIZE) key = calloc(1, sizeof(ck_key_t) + klen + 1);
  memcpy(key->label, k, klen);
  key->label[klen] = 0;
  key->len = klen + sizeof(u_int32_t);
  hashv = CK_HS_HASH(&h->hs, hs_hash, key);
  retrieved_key = ck_hs_remove(&h->hs, hashv, key);
  if (retrieved_key) {
    data_struct = index_attribute_container(retrieved_key);
    if (data_struct) {
      if (keyfree) keyfree(data_struct->key_ptr);
      if (datafree) datafree(data_struct->data);
      free(data_struct);
      if(key != &onstack_key.key) free(key);
      return 1;
    }
  }
  if(key != &onstack_key.key) free(key);
  return 0;
}

void mtev_hash_delete_all(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  void *entry = NULL;
  ck_hs_iterator_t iterator = CK_HS_ITERATOR_INITIALIZER;
  ck_hash_attr_t *data_struct;

  if(!h) return;
  if(!keyfree && !datafree) return;
  if(h->hs.hf == NULL) mtev_hash_init(h);
  while(ck_hs_next(&h->hs, &iterator, &entry)) {
    data_struct = index_attribute_container((ck_key_t*)entry);
    if (data_struct) {
      if (keyfree) keyfree(data_struct->key_ptr);
      if (datafree) datafree(data_struct->data);
      free(data_struct);
    }
  }
}

void mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  if(!h) return;
  if(h->hs.hf == NULL) mtev_hash_init(h);
  mtev_hash_delete_all(h, keyfree, datafree);
  ck_hs_destroy(&h->hs);
}

void mtev_hash_merge_as_dict(mtev_hash_table *dst, mtev_hash_table *src) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  const char *k;
  int klen;
  void *data;
  if(src == NULL || dst == NULL) return;
  while(mtev_hash_next(src, &iter, &k, &klen, &data)) {
    mtev_hash_replace(dst, strdup(k), klen, strdup((char *)data), free, free);
  }
}

int mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter,
                const char **k, int *klen, void **data) {
  void *cursor = NULL;
  ck_key_t *key;
  ck_hash_attr_t *data_struct;

  if(h->hs.hf == NULL) mtev_hash_init(h);

  if(!ck_hs_next(&h->hs, iter, &cursor)) return 0;
  key = (ck_key_t *)cursor;
  data_struct = index_attribute_container(key);
  if (data_struct) {
    *k = data_struct->key_ptr;
    *klen = data_struct->key.len - sizeof(u_int32_t);
    *data = data_struct->data;
  }
  return 1;
}

int mtev_hash_next_str(mtev_hash_table *h, mtev_hash_iter *iter,
                       const char **k, int *klen, const char **dstr) {
  void *data = NULL;
  int rv;
  rv = mtev_hash_next(h,iter,k,klen,&data);
  *dstr = data;
  return rv;
}

/* This exists so that we have an instance of this to pull in the CTF
 * definition so that mdb can "know" the type alias here.
 */
struct _mtev_hash_bucket {
#ifdef CK_HT_PP
  uintptr_t key;
  uintptr_t value CK_CC_PACKED;
} CK_CC_ALIGN(16);
#else
  /* these are simply renamed to make them look like the same
   * keys as the old mtev_hash_bucket implelentation...
   * If ck_ht is pointer-packed, it's not reasonable.
   */
  const char *k;
  void *data;
  uint64_t klen;
  uint64_t hash;
} CK_CC_ALIGN(32);
#endif
typedef struct _mtev_hash_bucket mtev_hash_bucket;
static mtev_hash_bucket __mtev_hash_use_of_hash_bucket __attribute__((unused));

/* vim: se sw=2 ts=2 et: */
