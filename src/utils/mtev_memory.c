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

#if defined(HAVE_LIBUMEM) && defined(HAVE_UMEM_H)
#include <umem.h>
#endif
#define MTEV_EPOCH_SAFE_MAGIC 0x5afe5afe

static int initialized = 0;
static int asynch_gc = 0;
static ck_fifo_spsc_t gc_queue;
static uint64_t gc_queue_enqueued = 0;
static uint64_t gc_queue_requeued = 0;
static __thread ck_fifo_spsc_t *return_gc_queue;
static ck_epoch_t epoch_ht;
static __thread ck_epoch_record_t *epoch_rec;
static __thread int begin_end_depth = 0;
/* needs_maintenance is used to avoid doing unnecessary work
 * in the epoch free cycle.
 * 0    means not participating, (never freed)
 * &1   means freed something.
 */
static __thread uint64_t needs_maintenance = 0;
static void *mtev_memory_gc(void *unused);
static mtev_log_stream_t mem_debug = NULL;
static pthread_mutex_t mem_debug_lock = PTHREAD_MUTEX_INITIALIZER;

mtev_boolean mtev_memory_thread_initialized(void) {
  return epoch_rec != NULL;
}

void mtev_memory_init_thread(void) {
  if(epoch_rec == NULL) {
    epoch_rec = malloc(sizeof(*epoch_rec));
    ck_epoch_register(&epoch_ht, epoch_rec, NULL);
  }
}

void mtev_memory_fini_thread(void) {
  if(begin_end_depth > 1) {
    ck_epoch_end(epoch_rec, NULL);
    begin_end_depth = 0; // setting this doesn't actually matter.
  }
  if(return_gc_queue != NULL) {
    uint64_t st_enq = ck_pr_load_64(&gc_queue_enqueued);
    mtev_memory_maintenance_ex(MTEV_MM_BARRIER);
    while(ck_pr_load_64(&gc_queue_requeued) < st_enq) {
      mtev_memory_maintenance_ex(MTEV_MM_NONE);
      usleep(100);
    }
    mtev_memory_maintenance_ex(MTEV_MM_NONE);
    ck_fifo_spsc_entry_t *garbage = NULL;
    ck_fifo_spsc_deinit(return_gc_queue, &garbage);
    while (garbage != NULL) {
      ck_fifo_spsc_entry_t *n = garbage->next;
      free(garbage);
      garbage = n;
    }
    return_gc_queue = NULL;
  }
  if(epoch_rec != NULL) {
    ck_epoch_unregister(epoch_rec);
    epoch_rec = NULL;
  }
}

void
mtev_memory_gc_asynch(void) {
  static pid_t work_pid;
  pid_t current_pid;
  pthread_attr_t tattr;
  pthread_t tid;

  current_pid = getpid();
  /* If the work pid is this pid, we already have a thread running. */
  if(current_pid == work_pid) return;
  work_pid = current_pid;

  pthread_attr_init(&tattr);
  pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
  asynch_gc = 1;
  if(pthread_create(&tid, &tattr, mtev_memory_gc, NULL) == 0) {
    mtevL(mem_debug, "mtev_memory starting gc thread\n");
  }
  else {
    mtevL(mem_debug, "mtev_memory failed to spawn gc thread\n");
    asynch_gc = 0;
  }
}
static void mtev_memory_gc_restart_thread(void) {
  /* If we think we're async, we should have a thread */
  if(ck_pr_load_int(&asynch_gc)) mtev_memory_gc_asynch();
}
void mtev_memory_init(void) {
  if(initialized) return;
  initialized = 1;

  ck_epoch_init(&epoch_ht);
  mtev_memory_init_thread();

  ck_fifo_spsc_init(&gc_queue, malloc(sizeof(ck_fifo_spsc_entry_t)));
  pthread_atfork(NULL,NULL,mtev_memory_gc_restart_thread);
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

void mtev_memory_maintenance(void) {
  if((needs_maintenance & 1) == 0) return;
  ck_epoch_record_t epoch_temporary = *epoch_rec;
  if(!mem_debug) {
    pthread_mutex_lock(&mem_debug_lock);
    if (!mem_debug)
      mem_debug = mtev_log_stream_find("debug/memory");
    pthread_mutex_unlock(&mem_debug_lock);
  }
  if(do_cleanup == NULL) do_cleanup = ck_epoch_poll;
  if(do_cleanup(epoch_rec)) {
    if(epoch_temporary.n_pending != epoch_rec->n_pending ||
       epoch_temporary.n_peak != epoch_rec->n_peak ||
       epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
      mtevL(mem_debug,
            "summary: [%u/%u/%u] %u pending, %u peak, %u reclamations -> "
              "[%u/%u/%u] %u pending, %u peak, %u reclamations\n",
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

  if(!mem_debug) {
    pthread_mutex_lock(&mem_debug_lock);
    if (!mem_debug)
      mem_debug = mtev_log_stream_find("debug/memory");
    pthread_mutex_unlock(&mem_debug_lock);
  }
  if(epoch_temporary.n_pending != epoch_rec->n_pending ||
     epoch_temporary.n_peak != epoch_rec->n_peak ||
     epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
    mtevL(mem_debug,
          "[%p:asynch] summary: [%u/%u/%u] %u pending, %u peak, %u reclamations -> "
            "[%u/%u/%u] %u pending, %u peak, %u reclamations\n",
            epoch_rec,
            epoch_temporary.state, epoch_temporary.epoch,epoch_temporary.active,
            epoch_temporary.n_pending, epoch_temporary.n_peak, epoch_temporary.n_dispatch,
            epoch_rec->state, epoch_rec->epoch,epoch_rec->active,
            epoch_rec->n_pending, epoch_rec->n_peak, epoch_rec->n_dispatch);
  }
  free(ar);
}

#ifdef HAVE_CK_EPOCH_SYNCHRONIZE_WAIT
static void
mtev_memory_sync_wait(ck_epoch_t *e, ck_epoch_record_t *rec, void *c) {
  /* just don't take a whole core */
  usleep(100);
}
#endif
static void *
mtev_memory_gc(void *unused) {
  (void)unused;
  mtev_thread_setname("mtev_memory_gc");
  mtev_memory_init_thread();
  const int max_setsize = 100;
  mtevL(mem_debug, "GC maintenance thread pid:%d exiting.\n", getpid());
  while(ck_pr_load_int(&asynch_gc) == 1) {
    struct asynch_reclaim *ar;
    struct asynch_reclaim *arset[max_setsize];;

    /* These are various pending lists from other threads.
     * Let's pull a whole bunch of these lists as one time.
     */
    ck_fifo_spsc_dequeue_lock(&gc_queue);
    int setsize = 0;
    while(setsize < max_setsize && ck_fifo_spsc_dequeue(&gc_queue, &ar)) {
      arset[setsize++] = ar;
    }
    ck_fifo_spsc_dequeue_unlock(&gc_queue);

    /* Now we have isolated lists of things that have been freed in the past.
     * Let's make sure they are in the epoch past by moving out epoch forward
     * and synchronizing.
     */
    ck_epoch_begin(epoch_rec, NULL);
    ck_epoch_end(epoch_rec, NULL);

#ifdef HAVE_CK_EPOCH_SYNCHRONIZE_WAIT
    ck_epoch_synchronize_wait(&epoch_ht, mtev_memory_sync_wait, NULL);
#else
    ck_epoch_synchronize(epoch_rec);
#endif

    /* Now we hand them back from where they came and they are guaranteed
     * to to be epoch safe.
     */
    for(int i=0; i<setsize; i++) {
      ar = arset[i];
      ck_fifo_spsc_enqueue_lock(ar->backq);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(ar->backq);
      if(fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_pr_inc_64(&gc_queue_requeued);
      ck_fifo_spsc_enqueue(ar->backq, fifo_entry, ar);
      ck_fifo_spsc_enqueue_unlock(ar->backq);
    }
    if(setsize != max_setsize) usleep(500000);
  }
  mtevL(mem_debug, "GC maintenance thread pid:%d exiting.\n", getpid());
  mtev_memory_fini_thread();
  return NULL;
}

int
mtev_memory_maintenance_ex(mtev_memory_maintenance_method_t method) {
  static int error_once = 1;
  struct asynch_reclaim *ar;
  unsigned long n_dispatch = 0;
  mtev_boolean success = mtev_false;
  ck_epoch_record_t epoch_temporary =  *epoch_rec;

  if(needs_maintenance == 0) return -1;

  mtevAssert(begin_end_depth == 0);

  if(!mem_debug) {
    pthread_mutex_lock(&mem_debug_lock);
    if (!mem_debug)
      mem_debug = mtev_log_stream_find("debug/memory");
    pthread_mutex_unlock(&mem_debug_lock);
  }

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
  /* If the 1 bit isn't set, we've not freed on this thread since last invocation.
   * no sense in doing work to pass an "empty todo list" to asynch collection or
   * attempt a poll or barrier.
   */
  if((needs_maintenance & 1) == 0) return 0;
  needs_maintenance++; /* unsets the 1 bit */
  mtevAssert(epoch_rec->active == 0);
  switch(method) {
    case MTEV_MM_NONE:
      break;
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
      memset(epoch_rec->pending, 0, sizeof(ar->pending));
      ck_fifo_spsc_enqueue_lock(&gc_queue);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(&gc_queue);
      if(fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_pr_inc_64(&gc_queue_enqueued);
      ck_fifo_spsc_enqueue(&gc_queue, fifo_entry, ar);
      ck_fifo_spsc_enqueue_unlock(&gc_queue);
      success = mtev_true;
      break;
  }

  if(success && method != MTEV_MM_BARRIER_ASYNCH) {
    if(epoch_temporary.n_pending != epoch_rec->n_pending ||
       epoch_temporary.n_peak != epoch_rec->n_peak ||
       epoch_temporary.n_dispatch != epoch_rec->n_dispatch) {
      mtevL(mem_debug,
            "[%p:%s] summary: [%u/%u/%u] %u pending, %u peak, %u reclamations -> "
              "[%u/%u/%u] %u pending, %u peak, %u reclamations\n",
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

void mtev_memory_begin(void) {
  if(begin_end_depth == 0) ck_epoch_begin(epoch_rec, NULL);
  begin_end_depth++;
}
void mtev_memory_end(void) {
  begin_end_depth--;
  if(begin_end_depth == 0) ck_epoch_end(epoch_rec, NULL);
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
  mtevAssert(epoch_rec != NULL);
  b = malloc(sizeof(*b) + r);
  b->magic = MTEV_EPOCH_SAFE_MAGIC;
  b->cleanup = NULL;
  return b + 1;
}

void *mtev_memory_safe_malloc_cleanup(size_t r, void (*f)(void *)) {
  struct safe_epoch *b;
  mtevAssert(epoch_rec != NULL);
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
    needs_maintenance |= 1;
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

static uint32_t nallocators;
struct mtev_allocator_options {
  char name[32];
  mtev_boolean wants_fill;
  int freelist_limit;
  uint64_t fill;
  size_t alignment;
  size_t fixed_size;
  uint32_t hints;
};

struct tls_data_container {
  mtev_allocator_t a;
  /* overalloc an put impl specific stuff later */
};

struct mtev_allocator {
  struct mtev_allocator_options options;
  pthread_key_t tls;
  void *impl_data;
  struct tls_data_container *(*tls_setup)(struct mtev_allocator *);
  void (*tls_teardown)(struct mtev_allocator *, struct tls_data_container *);
  void *(*malloc_impl)(struct mtev_allocator *, size_t);
  void *(*calloc_impl)(struct mtev_allocator *, size_t, size_t);
  void *(*realloc_impl)(struct mtev_allocator *, void *, size_t);
  void *(*reallocf_impl)(struct mtev_allocator *, void *, size_t);
  void (*free_impl)(struct mtev_allocator *, void *);
  void (*release_impl)(struct mtev_allocator *, void *);
};

mtev_allocator_options_t mtev_allocator_options_create(void) {
  return calloc(1, sizeof(struct mtev_allocator_options));
}
void mtev_allocator_options_free(mtev_allocator_options_t ptr) {
  free(ptr);
}
void
mtev_allocator_options_name(mtev_allocator_options_t opt, char *name) {
  strlcpy(opt->name, name, sizeof(opt->name));
}
void
mtev_allocator_options_alignment(mtev_allocator_options_t opt, size_t alignment) {
  opt->alignment = alignment;
}
void
mtev_allocator_options_fixed_size(mtev_allocator_options_t opt, size_t size) {
  opt->fixed_size = size;
}
void
mtev_allocator_options_fill(mtev_allocator_options_t opt, uint64_t fill) {
  opt->wants_fill = mtev_true;
  opt->fill = fill;
}
void
mtev_allocator_options_freelist_perthreadlimit(mtev_allocator_options_t opt, int items) {
  opt->freelist_limit = items;
}
void
mtev_allocator_options_hints(mtev_allocator_options_t opt, uint32_t hints) {
  opt->hints = hints;
}

static inline void *
mtev_memory_fill(mtev_allocator_t a, void *ptr, size_t size) {
  size_t sp = 0;
  if(!a->options.wants_fill) return ptr;
  while(sp < size) {
    size_t towrite = size-sp;
    if(towrite > sizeof(uint64_t)) towrite = sizeof(uint64_t);
    memcpy(ptr + sp, &a->options.fill, towrite);
    sp += sizeof(uint64_t);
  }
  return ptr;
}

void *mtev_malloc(mtev_allocator_t a, size_t size) {
  assert(a);
  if(a->options.fixed_size && a->options.fixed_size < size) return NULL;
  return mtev_memory_fill(a, a->malloc_impl(a, size), size);
}
void *mtev_calloc(mtev_allocator_t a, size_t nmemb, size_t elemsize) {
  assert(a);
  if(a->options.fixed_size && a->options.fixed_size < (nmemb*elemsize)) return NULL;
  return a->calloc_impl(a, nmemb, elemsize);
}
void *mtev_realloc(mtev_allocator_t a, void *ptr, size_t size) {
  assert(a);
  if(a->options.fixed_size && a->options.fixed_size < size) return NULL;
  return a->realloc_impl(a, ptr, size);
}
void *mtev_reallocf(mtev_allocator_t a, void *ptr, size_t size) {
  assert(a);
  if(a->options.fixed_size && a->options.fixed_size < size) {
    mtev_free(a, ptr);
    return NULL;
  }
  return a->reallocf_impl(a, ptr, size);
}
void mtev_free(mtev_allocator_t a, void *ptr) {
  assert(a);
  a->free_impl(a, ptr);
}

struct mtev_alloc_freelist_node {
  struct mtev_alloc_freelist_node *next;
};

/* Default allocator implementation */
struct default_allocator_data_container {
  mtev_allocator_t a;
  int freelist_size;
  struct mtev_alloc_freelist_node *freelist;
};

void mtev_allocator_thread_teardown(void *tls_data) {
  struct tls_data_container *tdc = (struct tls_data_container *)tls_data;
  tdc->a->tls_teardown(tdc->a, tls_data);
}
static struct tls_data_container *
default_allocator_tls_setup(mtev_allocator_t a) {
  struct default_allocator_data_container *dadc;
  dadc = calloc(1, sizeof(*dadc));
  dadc->a = a;
  return (struct tls_data_container *)dadc;
}
static void
default_allocator_tls_teardown(mtev_allocator_t a, struct tls_data_container *tdc) {
  struct default_allocator_data_container *dadc;
  struct mtev_alloc_freelist_node *tofree;
  if(!tdc) return;
  dadc = (struct default_allocator_data_container *)tdc;
  while(NULL != (tofree = dadc->freelist)) {
    dadc->freelist = tofree->next;
    a->release_impl(a, tofree);
  }
  free(tdc);
}
static struct tls_data_container *
generic_allocator_gettls(mtev_allocator_t a) {
  struct tls_data_container *tdc;
  if(a->tls_setup == NULL) return NULL;
  tdc = pthread_getspecific(a->tls);
  if(tdc) return tdc;
  if(a->tls_setup) {
    tdc = a->tls_setup(a);
    if(tdc) {
      tdc->a = a;
      pthread_setspecific(a->tls, tdc);
    }
  }
  return tdc;
}
static void *
default_allocator_malloc(mtev_allocator_t a, size_t size) {
  struct default_allocator_data_container *dadc =
    (struct default_allocator_data_container *)generic_allocator_gettls(a);
  size = MAX(size, sizeof(void *));
  assert(a->options.fixed_size == 0 || size <= a->options.fixed_size);
  if(a->options.fixed_size > 0) {
    if(a->options.freelist_limit > 0 && dadc->freelist) {
    /* FreeList applies */
      void *ptr = dadc->freelist;
      dadc->freelist = dadc->freelist->next;
      dadc->freelist_size--;
      return ptr;
    }
    return malloc(a->options.fixed_size);
  }
  return malloc(size);
}

static void *
default_allocator_calloc(mtev_allocator_t a, size_t nmemb, size_t elemsize) {
  void *ptr;
  size_t size = nmemb * elemsize;
  if(size < nmemb || size < elemsize) /* rolled */ return NULL;
  ptr = default_allocator_malloc(a, size);
  memset(ptr, 0, size);
  return ptr;
}

static void *
default_allocator_realloc(mtev_allocator_t a, void *ptr, size_t size) {
  void *newptr;
  size = MAX(size, sizeof(void *));
  if(a->options.fixed_size && a->options.fixed_size >= size) return ptr;
  newptr = realloc(ptr, size);
  return newptr;
}

static void *
default_allocator_reallocf(mtev_allocator_t a, void *ptr, size_t size) {
  void *newptr;
  size = MAX(size, sizeof(void *));
  if(a->options.fixed_size && a->options.fixed_size >= size) return ptr;
  newptr = realloc(ptr, size);
  if(newptr == NULL) a->free_impl(a,ptr);
  return newptr;
}

static void
default_allocator_free(mtev_allocator_t a, void *ptr) {
  if(a->options.fixed_size) {
    /* freelists */
    struct default_allocator_data_container *dadc =
      (struct default_allocator_data_container *)generic_allocator_gettls(a);
    if(a->options.freelist_limit > dadc->freelist_size) {
      struct mtev_alloc_freelist_node *node = ptr;
      node->next = dadc->freelist;
      dadc->freelist = node;
      dadc->freelist_size++;
      return;
    }
  }
  a->release_impl(a,ptr);
}

static void
default_allocator_release(mtev_allocator_t a, void *ptr) {
  free(ptr);
}

static struct mtev_allocator default_allocator = {
  .tls_setup = default_allocator_tls_setup,
  .tls_teardown = default_allocator_tls_teardown,
  .malloc_impl = default_allocator_malloc,
  .calloc_impl = default_allocator_calloc,
  .realloc_impl = default_allocator_realloc,
  .reallocf_impl = default_allocator_reallocf,
  .free_impl = default_allocator_free,
  .release_impl = default_allocator_release,
};
static void
default_allocator_init(struct mtev_allocator *a, mtev_allocator_options_t opt) {
  memcpy(a, &default_allocator, sizeof(default_allocator));
  memcpy(&a->options, opt, sizeof(*opt));
}

#if defined(HAVE_LIBUMEM) && defined(HAVE_UMEM_H)
static void
fixed_umem_release(mtev_allocator_t a, void *ptr) {
  umem_cache_t *ucache = a->impl_data;
  umem_cache_free(ucache, ptr);
}
static void
fixed_umem_free(mtev_allocator_t a, void *ptr) {
  fixed_umem_release(a, ptr);
}
static void *
fixed_umem_malloc(mtev_allocator_t a, size_t s) {
  if(a->options.fixed_size == 0 || s > a->options.fixed_size) return NULL;
  umem_cache_t *ucache = a->impl_data;
  return umem_cache_alloc(ucache, UMEM_DEFAULT);
}
static void *
fixed_umem_calloc(mtev_allocator_t a, size_t nmemb, size_t elemsize) {
  size_t s = nmemb * elemsize;
  void *ptr = fixed_umem_malloc(a, s);
  if(ptr) memset(ptr, 0, s);
  return ptr;
}
static void *
fixed_umem_realloc(mtev_allocator_t a, void *ptr, size_t s) {
  if(ptr == NULL) return fixed_umem_malloc(a, s);
  if(s > a->options.fixed_size) return NULL;
  return ptr;
}
static void *
fixed_umem_reallocf(mtev_allocator_t a, void *ptr, size_t s) {
  if(ptr == NULL) return fixed_umem_malloc(a, s);
  if(s > a->options.fixed_size) {
    fixed_umem_free(a, ptr);
    return NULL;
  }
  return ptr;
}
static struct mtev_allocator fixed_umem_allocator = {
  .tls_setup = NULL,
  .tls_teardown = NULL,
  .malloc_impl = fixed_umem_malloc,
  .calloc_impl = fixed_umem_calloc,
  .realloc_impl = fixed_umem_realloc,
  .reallocf_impl = fixed_umem_reallocf,
  .free_impl = fixed_umem_free,
  .release_impl = fixed_umem_release,
};

static void
fixed_umem_allocator_init(struct mtev_allocator *a, mtev_allocator_options_t opt) {
  memcpy(a, &fixed_umem_allocator, sizeof(fixed_umem_allocator));
  memcpy(&a->options, opt, sizeof(*opt));
  a->impl_data = 
    umem_cache_create(a->options.name, a->options.fixed_size,
                      a->options.alignment, NULL, NULL, NULL, a,
                      NULL, 0);
}
#endif
mtev_allocator_t mtev_allocator_create(mtev_allocator_options_t opt) {
  mtev_allocator_t allocator = calloc(1, sizeof(*allocator));
  if(opt->name[0] == '\0') {
    uint32_t id = ck_pr_faa_32(&nallocators, 1) + 1;
    snprintf(opt->name, sizeof(opt->name), "mtev_umem_n%u_%d",
             id, (int)opt->fixed_size);
  }
  if(0) { }
#if defined(HAVE_LIBUMEM) && defined(HAVE_UMEM_H)
  else if(opt->fixed_size) {
    fixed_umem_allocator_init(allocator, opt);
  }
#endif
  else {
    default_allocator_init(allocator, opt);
  }
  if(allocator->tls_setup) {
    pthread_key_create(&allocator->tls, mtev_allocator_thread_teardown);
    struct tls_data_container *tdc = allocator->tls_setup(allocator);
    if(tdc) {
      tdc->a = allocator;
      pthread_setspecific(allocator->tls, tdc);
    }
  }
  return allocator;
}

