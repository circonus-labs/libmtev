/*
 * Copyright (c) 2014, Circonus, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <ck_epoch.h>
#include "utils/mtev_log.h"

#define MTEV_EPOCH_SAFE_MAGIC 0x5afe5afe

static int initialized = 0;
static ck_epoch_t epoch_ht;
static __thread ck_epoch_record_t *epoch_rec;

void mtev_memory_init_thread() {
  if(epoch_rec == NULL) {
    epoch_rec = malloc(sizeof(*epoch_rec));
    ck_epoch_register(&epoch_ht, epoch_rec);
  }
}
void mtev_memory_init() {
  if(initialized) return;
  initialized = 1;
  ck_epoch_init(&epoch_ht);
  mtev_memory_init_thread();
}
void mtev_memory_maintenance() {
  ck_epoch_record_t epoch_temporary = *epoch_rec;
  if(ck_epoch_poll(&epoch_ht, epoch_rec)) {
    if(epoch_temporary.n_pending != epoch_rec->n_pending ||
       epoch_temporary.n_peak != epoch_rec->n_peak ||
       epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
      mtevL(mtev_debug,
            "summary: [%u/%u/%u] %u pending, %u peak, %lu reclamations -> "
              "[%u/%u/%u] %u pending, %u peak, %lu reclamations\n",
              epoch_temporary.state, epoch_temporary.epoch,epoch_temporary.active,
              epoch_temporary.n_pending, epoch_temporary.n_peak, epoch_temporary.n_dispatch,
              epoch_rec->state, epoch_rec->epoch,epoch_rec->active,
              epoch_rec->n_pending, epoch_rec->n_peak, epoch_rec->n_dispatch);
    }
  }
}
void mtev_memory_begin() {
  ck_epoch_begin(&epoch_ht, epoch_rec);
}
void mtev_memory_end() {
  ck_epoch_end(&epoch_ht, epoch_rec);
}

struct safe_epoch {
  ck_epoch_entry_t epoch_entry;
  uint32_t magic;
};

static void mtev_memory_real_free(ck_epoch_entry_t *e) {
  free(e);
  return;
}

void *mtev_memory_safe_malloc(size_t r) {
  struct safe_epoch *b;
  b = malloc(sizeof(*b) + r);
  b->magic = MTEV_EPOCH_SAFE_MAGIC;
  return b + 1;
}

void *mtev_memory_safe_calloc(size_t nelem, size_t elsize) {
  void *buf;
  size_t size = nelem * elsize;
  if(size < nelem || size < elsize) return NULL;
  buf = mtev_memory_safe_malloc(size);
  if(buf) memset(buf, 0, size);
  return buf;
}

char *mtev_memory_safe_strdup(const char *in) {
  char *out;
  size_t inlen = strlen(in);
  out = mtev_memory_safe_malloc(inlen+1);
  if(out) memcpy(out, in, inlen+1);
  return out;
}

void *mtev_memory_ck_malloc(size_t r) {
  return mtev_memory_safe_malloc(r);
}

void mtev_memory_ck_free(void *p, size_t b, bool r) {
  struct safe_epoch *e = (p - sizeof(struct safe_epoch));

  if(p == NULL) return;
  (void)b;
  assert(e->magic == MTEV_EPOCH_SAFE_MAGIC);

  if (r == true) {
    /* Destruction requires safe memory reclamation. */
    ck_epoch_call(&epoch_ht, epoch_rec, &e->epoch_entry, mtev_memory_real_free);
  } else {
    mtev_memory_real_free(&e->epoch_entry);
  }

  return;
}

void mtev_memory_safe_free(void *p) {
  mtev_memory_ck_free(p, 0, true);
}

