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
#include "mtev_log.h"
#include "mtev_memory.h"
#include "mtev_rand.h"
#include "mtev_watchdog.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ONSTACK_KEY_SIZE 128

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
uint32_t __hash(const char *k, uint32_t length, uint32_t initval)
{
   register uint32_t a,b,c,len;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
      b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
      c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((uint32_t)k[10]<<24);
   case 10: c+=((uint32_t)k[9]<<16);
   case 9 : c+=((uint32_t)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((uint32_t)k[7]<<24);
   case 7 : b+=((uint32_t)k[6]<<16);
   case 6 : b+=((uint32_t)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((uint32_t)k[3]<<24);
   case 3 : a+=((uint32_t)k[2]<<16);
   case 2 : a+=((uint32_t)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

uint32_t mtev_hash__hash(const char *k, uint32_t length, uint32_t initval) {
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

  if (prev_key->len == cur_key->len) {
    return memcmp(prev_key, cur_key, prev_key->len) == 0;
  }
  /* We know they're not equal if they have different lengths */
  return false;
}

void mtev_hash_init(mtev_hash_table *h) {
  return mtev_hash_init_size(h, MTEV_HASH_DEFAULT_SIZE);
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

static struct ck_malloc mtev_memory_allocator = {
  .malloc = mtev_memory_ck_malloc,
  .free = mtev_memory_ck_free
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

struct locks_container {
  void (*lock)(struct locks_container *h);
  void (*unlock)(struct locks_container *h);
  union {
    pthread_mutex_t hs_lock;
    mtev_spinlock_t hs_spinlock;
  } locks;
};

static inline void
none_lock(struct locks_container *h) {
  (void)h;
};

static inline void
none_unlock(struct locks_container *h) {
  (void)h;
};

static inline void
spinlock_lock(struct locks_container *h) {
  mtev_spinlock_lock(&h->locks.hs_spinlock);
}

static inline void
spinlock_unlock(struct locks_container *h) {
  mtev_spinlock_unlock(&h->locks.hs_spinlock);
}

static inline void
mutex_lock(struct locks_container *h) {
  pthread_mutex_lock(&h->locks.hs_lock);
}

static inline void
mutex_unlock(struct locks_container *h) {
  pthread_mutex_unlock(&h->locks.hs_lock);
}


#define LOCK(h) do { \
  ((struct locks_container *)h->u.locks.locks)->lock(h->u.locks.locks); \
  } while (0)

#define UNLOCK(h) do { \
  ((struct locks_container *)h->u.locks.locks)->unlock(h->u.locks.locks); \
  } while (0)

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

static void
mtev_hash_set_lock_mode_funcs(mtev_hash_table *h, mtev_hash_lock_mode_t lock_mode)
{
  struct locks_container *lc = h->u.locks.locks;
  switch (lock_mode) {
  case MTEV_HASH_LOCK_MODE_NONE:
    lc->lock = &none_lock;
    lc->unlock = &none_unlock;
    break;
  case MTEV_HASH_LOCK_MODE_MUTEX:
    pthread_mutex_init(&lc->locks.hs_lock, NULL);
    lc->lock = &mutex_lock;
    lc->unlock = &mutex_unlock;
    break;
  case MTEV_HASH_LOCK_MODE_SPIN:
    lc->locks.hs_spinlock = 0;
    lc->lock = &spinlock_lock;
    lc->unlock = &spinlock_unlock;
    break;
  };
}

static void
mtev_hash_destroy_locks(mtev_hash_table *h)
{
  struct locks_container *lc = h->u.locks.locks;
  if (lc->lock == mutex_lock) {
    pthread_mutex_destroy(&lc->locks.hs_lock);
  }
}


void mtev_hash_init_size(mtev_hash_table *h, int size) {
  mtev_hash_init_locks(h, size, MTEV_HASH_LOCK_MODE_NONE);
}

void mtev_hash_init_locks(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode) {
  mtev_rand_init();

  if(size < 8) size = 8;

  mtevAssert(ck_hs_init(&h->u.hs, CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC, hs_hash, hs_compare, &my_allocator,
                        size, mtev_rand()));
  mtevAssert(h->u.hs.hf != NULL);

  h->u.locks.locks = calloc(1, sizeof(struct locks_container));

  mtev_hash_set_lock_mode_funcs(h, lock_mode);
}

void mtev_hash_init_mtev_memory(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode) {
  mtev_rand_init();

  if(size < 8) size = 8;

  mtevAssert(ck_hs_init(&h->u.hs, CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC, hs_hash, hs_compare, &mtev_memory_allocator,
                        size, mtev_rand()));
  mtevAssert(h->u.hs.hf != NULL);

  h->u.locks.locks = calloc(1, sizeof(struct locks_container));

  mtev_hash_set_lock_mode_funcs(h, lock_mode);
}


int mtev_hash_size(mtev_hash_table *h) {
  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_size... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }
  return ck_hs_count(&h->u.hs);
}

int mtev_hash_replace(mtev_hash_table *h, const char *k, int klen, void *data,
                      NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  char *oldkey = NULL;
  void *olddata = NULL;
  int ret = mtev_hash_set(h, k, klen, data, &oldkey, &olddata);
  if (ret) {
    if (keyfree) keyfree(oldkey);
    if (datafree) datafree(olddata);
  }
  return ret;
}

int mtev_hash_store(mtev_hash_table *h, const char *k, int klen, void *data) {
  long hashv;
  int ret = 0;
  ck_hash_attr_t *attr = NULL;

  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_store... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  if (h->u.hs.m == &mtev_memory_allocator) {
    attr = mtev_memory_safe_calloc(1, sizeof(ck_hash_attr_t) + klen + 1);
  } else {
    attr = calloc(1, sizeof(ck_hash_attr_t) + klen + 1);
  }

  memcpy(attr->key.label, k, klen);
  attr->key.label[klen] = 0;
  attr->key.len = klen + sizeof(uint32_t);
  attr->key_ptr = (char*)k;
  attr->data = data;
  hashv = CK_HS_HASH(&h->u.hs, hs_hash, &attr->key);
  LOCK(h);
  ret = ck_hs_put(&h->u.hs, hashv, &attr->key);
  UNLOCK(h);
  if (!ret) {
    if (h->u.hs.m == &mtev_memory_allocator) {
      mtev_memory_safe_free(attr);
    } else {
      free(attr);
    }
  }
  return ret;
}

int mtev_hash_set(mtev_hash_table *h, const char *k, int klen, void *data,
                  char **oldkey, void **olddata) 
{
  long hashv;
  int ret;
  void *retrieved_key = NULL;
  ck_hash_attr_t *data_struct;
  ck_hash_attr_t *attr = NULL;

  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_set... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  if (h->u.hs.m == &mtev_memory_allocator) {
    attr = mtev_memory_safe_calloc(1, sizeof(ck_hash_attr_t) + klen + 1);
  } else {
    attr = calloc(1, sizeof(ck_hash_attr_t) + klen + 1);
  }

  memcpy(attr->key.label, k, klen);
  attr->key.label[klen] = 0;
  attr->key.len = klen + sizeof(uint32_t);
  attr->data = data;
  attr->key_ptr = (char*)k;
  hashv = CK_HS_HASH(&h->u.hs, hs_hash, &attr->key);
  LOCK(h);
  ret = ck_hs_set(&h->u.hs, hashv, &attr->key, &retrieved_key);
  UNLOCK(h);
  if (ret) {
    if (retrieved_key) {
      data_struct = index_attribute_container(retrieved_key);
      if (data_struct) {
        if (oldkey) *oldkey = data_struct->key_ptr;
        if (olddata) *olddata = data_struct->data;
      }
      if (h->u.hs.m == &mtev_memory_allocator) {
        mtev_memory_safe_free(data_struct);
      } else {
        free(data_struct);
      }
    }
  }
  else {
    if (h->u.hs.m == &mtev_memory_allocator) {
      mtev_memory_safe_free(attr);
    } else {
      free(attr);
    }
  }
  return ret;
}

int mtev_hash_retrieve(mtev_hash_table *h, const char *k, int klen, void **data) {
  long hashv;
  ck_key_t *retrieved_key;
  union {
    ck_key_t key;
    char pad[sizeof(ck_key_t) + ONSTACK_KEY_SIZE];
  } onstack_key;
  ck_key_t *key = &onstack_key.key;
  ck_hash_attr_t *data_struct;

  if(!h) return 0;
  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_retrieve... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  if(klen > ONSTACK_KEY_SIZE) key = calloc(1, sizeof(ck_key_t) + klen + 1);
  memcpy(key->label, k, klen);
  key->label[klen] = 0;
  key->len = klen + sizeof(uint32_t);;
  hashv = CK_HS_HASH(&h->u.hs, hs_hash, key);
  retrieved_key = ck_hs_get(&h->u.hs, hashv, key);
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
  ck_hash_attr_t *data_struct;
  ck_key_t *retrieved_key;
  union {
    ck_key_t key;
    char pad[sizeof(ck_key_t) + ONSTACK_KEY_SIZE];
  } onstack_key;
  ck_key_t *key = &onstack_key.key;

  if(!h) return 0;
  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_delete... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  if(klen > ONSTACK_KEY_SIZE) key = calloc(1, sizeof(ck_key_t) + klen + 1);
  memcpy(key->label, k, klen);
  key->label[klen] = 0;
  key->len = klen + sizeof(uint32_t);
  hashv = CK_HS_HASH(&h->u.hs, hs_hash, key);
  LOCK(h);
  retrieved_key = ck_hs_remove(&h->u.hs, hashv, key);
  UNLOCK(h);
  if (retrieved_key) {
    data_struct = index_attribute_container(retrieved_key);
    if (data_struct) {
      if (keyfree) keyfree(data_struct->key_ptr);
      if (datafree) datafree(data_struct->data);
      if (h->u.hs.m == &mtev_memory_allocator) {
        mtev_memory_safe_free(data_struct);
      } else {
        free(data_struct);
      }
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
  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_delete_all... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  int count = mtev_hash_size(h);
  LOCK(h);
  while(ck_hs_next(&h->u.hs, &iterator, &entry)) {
    data_struct = index_attribute_container((ck_key_t*)entry);
    if (data_struct) {
      if (keyfree) keyfree(data_struct->key_ptr);
      if (datafree) datafree(data_struct->data);
      if (h->u.hs.m == &mtev_memory_allocator) {
        mtev_memory_safe_free(data_struct);
      } else {
        free(data_struct);
      }
    }
  }
  ck_hs_reset_size(&h->u.hs, count);
  UNLOCK(h);
}

void mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  if(!h) return;
  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_destroy... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }
  mtev_hash_delete_all(h, keyfree, datafree);
  LOCK(h);
  ck_hs_destroy(&h->u.hs);
  UNLOCK(h);
  mtev_hash_destroy_locks(h);
  free(h->u.locks.locks);
}

void mtev_hash_merge_as_dict(mtev_hash_table *dst, mtev_hash_table *src) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  if(src == NULL || dst == NULL) return;
  while(mtev_hash_adv(src, &iter)) {
    mtev_hash_replace(dst, strdup(iter.key.str), iter.klen,
                      strdup(iter.value.str), free, free);
  }
}

/* _mtev_hash_next(_str) should not use anything in iter past the
 * ck_hs_iterator_t b/c older consumers could have the smaller
 * version of the mtev_hash_iter allocated on stack.
 */
int _mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter,
                    const char **k, int *klen, void **data, 
                    mtev_boolean spmc) {
  void *cursor = NULL;
  ck_key_t *key;
  ck_hash_attr_t *data_struct;

  if(h->u.hs.hf == NULL) {
    mtevL(mtev_error, "warning: null hashtable in mtev_hash_next... initializing\n");
    mtev_stacktrace(mtev_error);
    mtev_hash_init(h);
  }

  if (spmc) {
    if(!ck_hs_next_spmc(&h->u.hs, &iter->iter, &cursor)) return 0;
  } else {
    if(!ck_hs_next(&h->u.hs, &iter->iter, &cursor)) return 0;
  }
  key = (ck_key_t *)cursor;
  data_struct = index_attribute_container(key);
  if (data_struct) {
    *k = data_struct->key_ptr;
    *klen = data_struct->key.len - sizeof(uint32_t);
    *data = data_struct->data;
  }
  return 1;
}

int mtev_hash_adv(mtev_hash_table *h, mtev_hash_iter *iter) {
  return _mtev_hash_next(h, iter, &iter->key.str, &iter->klen, &iter->value.ptr, mtev_false);
}

int mtev_hash_adv_spmc(mtev_hash_table *h, mtev_hash_iter *iter) {
  return _mtev_hash_next(h, iter, &iter->key.str, &iter->klen, &iter->value.ptr, mtev_true);
}

int mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter,
                    const char **k, int *klen, void **data) {
  return _mtev_hash_next(h, iter, k, klen, data, mtev_false);
}


int mtev_hash_next_str(mtev_hash_table *h, mtev_hash_iter *iter,
                       const char **k, int *klen, const char **dstr) {
  void *data = NULL;
  int rv;
  /* Leave this hash_next for ABI safety.
   * (this mtev_hash_iter could be too small)
   */
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
