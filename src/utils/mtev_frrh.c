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

#include "mtev_defines.h"
#include "mtev_frrh.h"
#include "mtev_rand.h"
#include <ck_pr.h>

struct mtev_frrh_t {
  uint64_t size;
  size_t datasize;
  uint32_t prob;
  mtev_frrh_hash hashf;
  mtev_frrh_alloc_entry allocf;
  mtev_frrh_free_entry freef;
  uint64_t access, hit;
  mtev_frrh_entry_t **map;
};

#define MTEV_FRRH_BASE_SIZE(e, keylen) ((uintptr_t)MTEV_FRRH_DATA((mtev_frrh_entry_t *)e, keylen) - (uintptr_t)(e))

#define XXH_SEED (unsigned long long)0xdeadc0de
#define XXH_PRIVATE_API
#include "xxhash.h"
static uint64_t xxhash(const void *buf, size_t len) {
  return XXH64(buf,len,XXH_SEED);
}
#undef XXH_PRIVATE_API

mtev_frrh_t *
mtev_frrh_alloc(uint64_t size, size_t datasize, uint32_t prob,
                mtev_frrh_hash hashf, mtev_frrh_alloc_entry allocf,
                mtev_frrh_free_entry freef) {
  mtev_frrh_t *f;
  f = calloc(1, sizeof(*f));
  if(!f) return NULL;
  f->map = calloc(size, sizeof(*f->map));
  if(!f->map) {
    free(f);
    return NULL;
  }
  f->size = size;
  f->datasize = datasize;
  f->prob = UINT_MAX - prob;
  if(!hashf) hashf = xxhash;
  f->hashf = hashf;
  if(!allocf) allocf = malloc;
  f->allocf = allocf;
  if(!freef) freef = free;
  f->freef = freef;
  return f;
}

void
mtev_frrh_adjust_prob(mtev_frrh_t *f, uint32_t prob) {
  f->prob = UINT_MAX - prob;
}

void
mtev_frrh_stats(mtev_frrh_t *f, uint64_t *access, uint64_t *hit) {
  if(access) *access = f->access;
  if(hit) *hit = f->hit;
}

const void *
mtev_frrh_get(mtev_frrh_t *f, const void *key, uint32_t keylen) {
  uint64_t hval = f->hashf(key, keylen);
  uint32_t offset = (hval % f->size);
  mtev_frrh_entry_t *e = ck_pr_load_ptr(&f->map[offset]);
  ck_pr_inc_64(&f->access);

  if(e == NULL) return NULL;
  if(e->keylen != keylen) return NULL;
  if(memcmp(e->key, key, keylen)) return NULL;

  ck_pr_inc_64(&f->hit);
  return MTEV_FRRH_DATA(e, keylen);
}

mtev_boolean
mtev_frrh_set(mtev_frrh_t *f, const void *key, uint32_t keylen, const void *data) {
  uint64_t hval = f->hashf(key, keylen);
  uint32_t offset = (hval % f->size);
  while(1) {
    mtev_frrh_entry_t *prev = ck_pr_load_ptr(&f->map[offset]);
    if(prev == NULL || f->prob == 0 || f->prob <= (uint32_t)mtev_rand()) {
      /* attempt replace */
      mtev_frrh_entry_t *e = f->allocf(MTEV_FRRH_BASE_SIZE(0, keylen) + f->datasize);
      e->keylen = keylen;
      memcpy(e->key, key, keylen);
      memcpy(MTEV_FRRH_DATA(e, e->keylen), data, f->datasize);
      if(ck_pr_cas_ptr(&f->map[offset], prev, e)) {
        f->freef(prev);
        return mtev_true;
      }
      f->freef(e);
    }
    if(prev) break;
  }
  return mtev_false;
}
