/*
 * Copyright (c) 2014-2016, Circonus, Inc. All rights reserved.
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
#include <unistd.h>
#include <ck_epoch.h>
#include <ck_fifo.h>
#include "mtev_log.h"
#include "mtev_memory.h"
#include "mtev_thread.h"

#define MTEV_EPOCH_SAFE_MAGIC 0x5afe5afe

static int initialized = 0;
static int asynch_gc = 0;
static ck_fifo_spsc_t gc_queue;
static __thread ck_fifo_spsc_t *return_gc_queue;
static ck_epoch_t epoch_ht;
static __thread ck_epoch_record_t *epoch_rec;
static void *mtev_memory_gc(void *unused);

void mtev_memory_init_thread() {
  if(epoch_rec == NULL) {
    epoch_rec = malloc(sizeof(*epoch_rec));
    ck_epoch_register(&epoch_ht, epoch_rec);
  }
}

void mtev_memory_init() {
  pthread_attr_t tattr;
  pthread_t tid;
  if(initialized) return;
  initialized = 1;
  ck_epoch_init(&epoch_ht);
  mtev_memory_init_thread();

  ck_fifo_spsc_init(&gc_queue, malloc(sizeof(ck_fifo_spsc_entry_t)));
  pthread_attr_init(&tattr);
  pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
  asynch_gc = 1;
  if(mtev_thread_create(&tid, &tattr, mtev_memory_gc, NULL) == 0) {
    mtevL(mtev_stderr, "mtev_memory starting gc thread\n");
  }
  else {
    mtevL(mtev_stderr, "mtev_memory failed to spawn gc thread\n");
    asynch_gc = 0;
  }
}

typedef bool (*e_sweep_t)(ck_epoch_record_t *);
static e_sweep_t do_cleanup = NULL;

static bool ck_epoch_barrier_true(ck_epoch_record_t *r) {
  ck_epoch_barrier(r);
  return true;
}
mtev_boolean mtev_memory_barriers(mtev_boolean *b) {
  mtev_boolean old = (do_cleanup == ck_epoch_barrier_true);
  if(b) {
    if(*b) do_cleanup = ck_epoch_barrier_true;
    else do_cleanup = ck_epoch_poll;
  }
  return old;
}

void mtev_memory_maintenance() {
  ck_epoch_record_t epoch_temporary = *epoch_rec;
  if(do_cleanup == NULL) do_cleanup = ck_epoch_poll;
  if(do_cleanup(epoch_rec)) {
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

struct asynch_reclaim {
  ck_epoch_record_t *owner;
  ck_stack_t pending[CK_EPOCH_LENGTH];
  unsigned int n_pending;
  ck_fifo_spsc_t *backq;
};

CK_STACK_CONTAINER(struct ck_epoch_entry, stack_entry, epoch_entry_container)

static void
mtev_gc_sync_complete(struct asynch_reclaim *ar) {
  int i;
  unsigned long n_dispatch = 0;
  ck_epoch_record_t epoch_temporary = *epoch_rec;

  for(i=0;i<CK_EPOCH_LENGTH;i++) {
    unsigned int epoch = i & (CK_EPOCH_LENGTH - 1);
    ck_stack_entry_t *head, *next, *cursor;

    head = CK_STACK_FIRST(&ar->pending[epoch]);

    for (cursor = head; cursor != NULL; cursor = next) {
      struct ck_epoch_entry *entry = epoch_entry_container(cursor);
      next = CK_STACK_NEXT(cursor);
      entry->function(entry);
      n_dispatch++;
    }

  }
  if(epoch_rec->n_pending > epoch_rec->n_peak)
    epoch_rec->n_peak = epoch_rec->n_pending;

  epoch_rec->n_dispatch += n_dispatch;
  epoch_rec->n_pending -= n_dispatch;

  if(epoch_temporary.n_pending != epoch_rec->n_pending ||
     epoch_temporary.n_peak != epoch_rec->n_peak ||
     epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
    mtevL(mtev_debug,
          "[%p:asynch] summary: [%u/%u/%u] %u pending, %u peak, %lu reclamations -> "
            "[%u/%u/%u] %u pending, %u peak, %lu reclamations\n",
            epoch_rec,
            epoch_temporary.state, epoch_temporary.epoch,epoch_temporary.active,
            epoch_temporary.n_pending, epoch_temporary.n_peak, epoch_temporary.n_dispatch,
            epoch_rec->state, epoch_rec->epoch,epoch_rec->active,
            epoch_rec->n_pending, epoch_rec->n_peak, epoch_rec->n_dispatch);
  }
  free(ar);
}

static void *
mtev_memory_gc(void *unused) {
  (void)unused;
  mtev_memory_init_thread();
  while(1) {
    struct asynch_reclaim *ar;
    ck_epoch_begin(epoch_rec, NULL);
    ck_epoch_end(epoch_rec, NULL);
    ck_fifo_spsc_dequeue_lock(&gc_queue);
    while(ck_fifo_spsc_dequeue(&gc_queue, &ar)) {
      ck_epoch_synchronize(epoch_rec);
      ck_fifo_spsc_enqueue_lock(ar->backq);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(ar->backq);
      if(fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_fifo_spsc_enqueue(ar->backq, fifo_entry, ar);
      ck_fifo_spsc_enqueue_unlock(ar->backq);
    }
    ck_fifo_spsc_dequeue_unlock(&gc_queue);
    usleep(500000);
  }
  return NULL;
}

int
mtev_memory_maintenance_ex(mtev_memory_maintenance_method_t method) {
  static int error_once = 1;
  struct asynch_reclaim *ar;
  unsigned long n_dispatch = 0;
  mtev_boolean success = mtev_false;
  ck_epoch_record_t epoch_temporary =  *epoch_rec;

  /* regardless of invocation intent, we cleanup our backq */
  if(!return_gc_queue) {
    return_gc_queue = calloc(1, sizeof(*return_gc_queue));
    ck_fifo_spsc_init(return_gc_queue, malloc(sizeof(ck_fifo_spsc_entry_t)));
  }
  ck_fifo_spsc_dequeue_lock(return_gc_queue);
  while(ck_fifo_spsc_dequeue(return_gc_queue, &ar)) {
    mtev_gc_sync_complete(ar);
  }
  ck_fifo_spsc_dequeue_unlock(return_gc_queue);

  if(!asynch_gc && method == MTEV_MM_BARRIER_ASYNCH) {
    if(error_once) {
      mtevL(mtev_error, "mtev_memory asynch gc not enabled, forcing synch\n");
      error_once = 0;
    }
    method = MTEV_MM_BARRIER;
  }
  mtevAssert(epoch_rec->active == 0);
  switch(method) {
    case MTEV_MM_BARRIER:
      ck_epoch_barrier(epoch_rec);
      success = mtev_true;
      break;
    case MTEV_MM_TRY:
      success = ck_epoch_poll(epoch_rec);
      break;
    case MTEV_MM_BARRIER_ASYNCH:
      ar = malloc(sizeof(*ar));
      ar->owner = epoch_rec;
      ar->backq = return_gc_queue;
      memcpy(ar->pending, epoch_rec->pending, sizeof(ar->pending));
      ar->n_pending = epoch_rec->n_pending;
      memset(epoch_rec->pending, 0, sizeof(ar->pending));
      ck_fifo_spsc_enqueue_lock(&gc_queue);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(&gc_queue);
      if(fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_fifo_spsc_enqueue(&gc_queue, fifo_entry, ar);
      ck_fifo_spsc_enqueue_unlock(&gc_queue);
      success = mtev_true;
      break;
  }

  if(success && method != MTEV_MM_BARRIER_ASYNCH) {
    if(epoch_temporary.n_pending != epoch_rec->n_pending ||
       epoch_temporary.n_peak != epoch_rec->n_peak ||
       epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
      mtevL(mtev_debug,
            "[%p:%s] summary: [%u/%u/%u] %u pending, %u peak, %lu reclamations -> "
              "[%u/%u/%u] %u pending, %u peak, %lu reclamations\n",
              epoch_rec, (method == MTEV_MM_TRY) ? "try" : "barrier",
              epoch_temporary.state, epoch_temporary.epoch,epoch_temporary.active,
              epoch_temporary.n_pending, epoch_temporary.n_peak, epoch_temporary.n_dispatch,
              epoch_rec->state, epoch_rec->epoch,epoch_rec->active,
              epoch_rec->n_pending, epoch_rec->n_peak, epoch_rec->n_dispatch);
    }
    if(epoch_rec->n_dispatch > epoch_temporary.n_dispatch)
      n_dispatch = epoch_rec->n_dispatch - epoch_temporary.n_dispatch;
  }
  return success ? n_dispatch : -1;
}

void mtev_memory_begin() {
  ck_epoch_begin(epoch_rec, NULL);
}
void mtev_memory_end() {
  ck_epoch_end(epoch_rec, NULL);
}

struct safe_epoch {
  ck_epoch_entry_t epoch_entry;
  uint32_t magic;
  void (*cleanup)(void *);
};

static void mtev_memory_real_free(ck_epoch_entry_t *e) {
  struct safe_epoch *se = (struct safe_epoch *)e;
  if(se->cleanup) se->cleanup(se+1);
  free(e);
  return;
}

void *mtev_memory_safe_malloc(size_t r) {
  struct safe_epoch *b;
  b = malloc(sizeof(*b) + r);
  b->magic = MTEV_EPOCH_SAFE_MAGIC;
  b->cleanup = NULL;
  return b + 1;
}

void *mtev_memory_safe_malloc_cleanup(size_t r, void (*f)(void *)) {
  struct safe_epoch *b;
  b = malloc(sizeof(*b) + r);
  b->magic = MTEV_EPOCH_SAFE_MAGIC;
  b->cleanup = f;
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


static void
mtev_memory_ck_free_func(void *p, size_t b, bool r,
                         void (*f)(ck_epoch_entry_t *)) {
  struct safe_epoch *e = (p - sizeof(struct safe_epoch));

  if(p == NULL) return;
  (void)b;
  mtevAssert(e->magic == MTEV_EPOCH_SAFE_MAGIC);

  if (r == true) {
    /* Destruction requires safe memory reclamation. */
    ck_epoch_call(epoch_rec, &e->epoch_entry, f);
  } else {
    f(&e->epoch_entry);
  }

  return;
}

void mtev_memory_ck_free(void *p, size_t b, bool r) {
  mtev_memory_ck_free_func(p, b, r, mtev_memory_real_free);
}

void mtev_memory_safe_free(void *p) {
  mtev_memory_ck_free_func(p, 0, true, mtev_memory_real_free);
}
