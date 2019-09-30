/*
 * Copyright (c) 2005-2009, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015-2017, Circonus, Inc. All rights reserved.
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

#define DEFAULT_JLOG_SUBSCRIBER "stratcon"

#include "mtev_defines.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <assert.h>
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <ck_pr.h>
#include <ck_fifo.h>
#include <yajl/yajl_gen.h>

#define mtev_log_impl
#include "mtev_log.h"
#include "mtev_dyn_buffer.h"
#include "mtev_maybe_alloc.h"
#include "mtev_hash.h"
#include "mtev_hooks.h"
#include "mtev_json.h"
#include "mtev_str.h"
#include "mtev_thread.h"
#include "mtev_zipkin.h"
#include "mtev_dyn_buffer.h"
#define XXH_PRIVATE_API
#include "xxhash.h"
#undef XXH_PRIVATE_API
#include <jlog.h>
#include <jlog_private.h>
#include "libmtev_dtrace.h"
#include "flatbuffer/mtevlogline_builder.h"
#include "flatbuffer/mtevlogline_verifier.h"

#define BOOT_STDERR_FLAGS MTEV_LOG_STREAM_ENABLED|MTEV_LOG_STREAM_TIMESTAMPS|MTEV_LOG_STREAM_SPLIT
#define BOOT_DEBUG_FLAGS MTEV_LOG_STREAM_TIMESTAMPS
#define MAX_PARTS 64

extern const char *eventer_get_thread_name(void);

static pthread_mutex_t resize_lock = PTHREAD_MUTEX_INITIALIZER;
static int min_flush_seconds = ((MTEV_LOG_DEFAULT_DEDUP_S-1) / 2) + 1;

MTEV_HOOK_IMPL(mtev_log_plain,
               (mtev_log_stream_t ls, const struct timeval *whence,
                const char *buffer, size_t len),
               void *, closure,
               (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                const char *buffer, size_t len),
               (closure,ls,whence,buffer,len))

MTEV_HOOK_IMPL(mtev_log_flatbuffer,
               (mtev_log_stream_t ls, const struct timeval *whence,
                const uint8_t *buffer, size_t len),
               void *, closure,
               (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                const uint8_t *buffer, size_t len),
               (closure,ls,whence,buffer,len))

MTEV_HOOK_IMPL(mtev_log_line,
               (mtev_log_stream_t ls, const struct timeval *whence,
                const char *timebuf, int timebuflen,
                const char *debugbuf, int debugbuflen,
                const char *buffer, size_t len),
               void *, closure,
               (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                const char *timebuf, int timebuflen,
                const char *debugbuf, int debugbuflen,
                const char *buffer, size_t len),
               (closure,ls,whence,timebuf,timebuflen,debugbuf,debugbuflen,buffer,len))


static int _mtev_log_siglvl = 0;
void mtev_log_enter_sighandler(void) { _mtev_log_siglvl++; }
void mtev_log_leave_sighandler(void) { _mtev_log_siglvl--; }

#define SUPPORTS_ASYNC(ls) ((ls) && (ls)->ops && (ls)->path && (ls)->ops->supports_async)

static int DEBUG_LOG_ENABLED(void) {
  static int enabled = -1;
  if(enabled == -1) {
    char *env = getenv("MTEV_LOG_DEBUG");
    enabled = env ? atoi(env) : 0;
  }
  return enabled;
}
#define debug_printf(a...) do { \
  if(DEBUG_LOG_ENABLED()) fprintf(stderr, a); \
} while(0)

struct _mtev_log_stream {
  unsigned flags;
  /* Above is exposed... 'do not change it... dragons' */
  char *type;
  char *name;
  int mode;
  char *path;
  logops_t *ops;
  void *op_ctx;
  mtev_hash_table *config;
  struct _mtev_log_stream_outlet_list *outlets;
  pthread_rwlock_t *lock;
  uint64_t written;
  unsigned deps_materialized:1;
  unsigned flags_below;
  mtev_log_format_t format;
};

struct posix_op_ctx {
  int fd;
  struct stat sb;
};

typedef struct {
  uint64_t head;
  uint64_t tail;
  unsigned int noffsets;
  unsigned int *offsets;
  unsigned int segmentsize;
  unsigned int segmentcut;
  char *segment;
  pthread_mutex_t lock;
} membuf_ctx_t;

static membuf_ctx_t *
log_stream_membuf_init(int nlogs, int nbytes) {
  membuf_ctx_t *membuf;
  membuf = calloc(1, sizeof(*membuf));
  membuf->head = membuf->tail = 0;
  membuf->segment = malloc(nbytes);
  membuf->segmentsize = nbytes;
  membuf->segmentcut = membuf->segmentsize;
  membuf->offsets = calloc(nlogs, sizeof(*membuf->offsets));
  membuf->noffsets = nlogs;
  pthread_mutex_init(&membuf->lock, NULL);
  return membuf;
}
static void
log_stream_membuf_free(membuf_ctx_t *membuf) {
  if(membuf->offsets) free(membuf->offsets);
  if(membuf->segment) free(membuf->segment);
  pthread_mutex_destroy(&membuf->lock);
  free(membuf);
}

static int
membuf_logio_open(mtev_log_stream_t ls) {
  int cnt = 0, size = 0;
  char *cp;
  cp = strchr(ls->path, ',');
  cnt = atoi(ls->path);
  if(cp) size = atoi(cp+1);
  if(!cnt) cnt = 10000;
  if(!size) size = 100000;
  ls->op_ctx = log_stream_membuf_init(cnt, size);
  return 0;
}

static int
intersect_seg(int a1, int a2, int b1, int b2) {
  int rv = 0;
  if(a1 >= b1 && a1 <= b2) rv=1;
  if(a2 >= b1 && a2 <= b2) rv=1;
  assert(a1 < a2 && b1 < b2);
  return rv;
}
static int
membuf_logio_writev(mtev_log_stream_t ls, const struct timeval *whence,
                    const struct iovec *iov, int iovcnt) {
  struct timeval __now;
  int i, offset, headoffset, headend, tailoffset, tailend,
      attemptoffset = -3, attemptend = -1, nexttailoff, nexttail;
  membuf_ctx_t *membuf = ls->op_ctx;
  size_t len = sizeof(*whence);

  for(i=0; i<iovcnt; i++) len += iov[i].iov_len;
  if(len > membuf->segmentsize) return 0;

  if(whence == NULL) {
    mtev_gettimeofday(&__now, NULL);
    whence = &__now;
  }

  pthread_mutex_lock(&membuf->lock); 
  /* use tail */
  offset = membuf->offsets[membuf->tail % membuf->noffsets];
  if(offset + len > membuf->segmentcut)
    membuf->segmentcut = membuf->segmentsize;
  if(offset + len > membuf->segmentsize) {
    attemptoffset = offset;
    attemptend = offset + len;
    membuf->segmentcut = offset;
    offset = 0;
    membuf->offsets[membuf->tail % membuf->noffsets] = offset;
  }
  nexttailoff = offset + len;
  nexttail = membuf->tail + 1;

  /* clean up head until it is ahead of the next tail */
  headoffset = membuf->offsets[membuf->head % membuf->noffsets];
  headend = membuf->offsets[(membuf->head+1) % membuf->noffsets];
  if(headend < headoffset) headend = membuf->segmentsize;
  tailoffset = membuf->offsets[membuf->tail % membuf->noffsets];
  tailend = nexttailoff;
  /* while we're about to write over the head (attempt or actual), advance */
  while(membuf->head != membuf->tail &&
        (intersect_seg(headoffset, headend-1, attemptoffset, attemptend-1) ||
         intersect_seg(headoffset, headend-1, tailoffset, tailend-1))) {
    membuf->head++;
    headoffset = membuf->offsets[membuf->head % membuf->noffsets];
    headend = membuf->offsets[(membuf->head+1) % membuf->noffsets];
    if(headend < headoffset) headend = membuf->segmentsize;
    //if((membuf->head % membuf->noffsets) == 0) {
  }

  /* move tail forward updating head if needed */
  if((nexttail % membuf->noffsets) == (membuf->head % membuf->noffsets))
    membuf->head++;
  /* note where the new tail is */
  membuf->offsets[nexttail % membuf->noffsets] = nexttailoff;

  len = 0;
  memcpy(membuf->segment + offset, whence, sizeof(*whence));
  len += sizeof(*whence);
  for(i=0;i<iovcnt;i++) {
    memcpy(membuf->segment + offset + len, iov[i].iov_base, iov[i].iov_len);
    len += iov[i].iov_len;
  }
  membuf->tail = nexttail;

  pthread_mutex_unlock(&membuf->lock); 
  return len;
}

static int
membuf_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                   const void *buf, size_t len) {
  struct iovec iov;
  iov.iov_base = (char *)buf;
  iov.iov_len = len;
  return membuf_logio_writev(ls, whence, &iov, 1);
}
static int
membuf_logio_reopen(mtev_log_stream_t ls) {
  (void)ls;
  return 0;
}
static int
membuf_logio_close(mtev_log_stream_t ls) {
  membuf_ctx_t *membuf = ls->op_ctx;
  log_stream_membuf_free(membuf);
  ls->op_ctx = NULL;
  return 0;
}
static size_t
membuf_logio_size(mtev_log_stream_t ls) {
  membuf_ctx_t *membuf = ls->op_ctx;
  return membuf->segmentsize;
}
static int
membuf_logio_rename(mtev_log_stream_t ls, const char *newname) {
  (void)ls;
  (void)newname;
  /* Not supported (and makes no sense) */
  return -1;
}
static int
membuf_logio_cull(mtev_log_stream_t ls, int age, ssize_t bytes) {
  (void)ls;
  (void)age;
  (void)bytes;
  /* Could be supported, but wouldn't reduce memory usage, so why bother? */
  return -1;
}

static logops_t membuf_logio_ops = {
  mtev_false,
  membuf_logio_open,
  membuf_logio_reopen,
  membuf_logio_write,
  membuf_logio_writev,
  membuf_logio_close,
  membuf_logio_size,
  membuf_logio_rename,
  membuf_logio_cull
};

int
mtev_log_memory_lines(mtev_log_stream_t ls, int log_lines,
                      int (*f)(uint64_t, const struct timeval *,
                               const char *, size_t, void *),
                      void *closure) {
  unsigned int nmsg;
  uint64_t idx;
  if(strcmp(ls->type, "memory")) return -1;
  membuf_ctx_t *membuf = ls->op_ctx;
  if(membuf == NULL) return 0;

  pthread_mutex_lock(&membuf->lock); 
  nmsg = ((membuf->tail % membuf->noffsets) >= (membuf->head % membuf->noffsets)) ?
           ((membuf->tail % membuf->noffsets) - (membuf->head % membuf->noffsets)) :
           ((membuf->tail % membuf->noffsets) + membuf->noffsets - (membuf->head % membuf->noffsets));
  assert(nmsg < membuf->noffsets);
  if(log_lines <= 0) log_lines = nmsg;
  log_lines = MIN((unsigned int)log_lines,nmsg);
  idx = (membuf->tail >= (unsigned int)log_lines) ?
          (membuf->tail - log_lines) : 0;
  pthread_mutex_unlock(&membuf->lock); 
  return mtev_log_memory_lines_since(ls, idx, f, closure);
}

int
mtev_log_memory_lines_since(mtev_log_stream_t ls, uint64_t afterwhich,
                            int (*f)(uint64_t, const struct timeval *,
                                    const char *, size_t, void *),
                            void *closure) {
  unsigned int nmsg = 0, count = 0;
  uint64_t idx = afterwhich;
  if(strcmp(ls->type, "memory")) return -1;
  membuf_ctx_t *membuf = ls->op_ctx;
  if(membuf == NULL) return 0;

  pthread_mutex_lock(&membuf->lock); 
  if(membuf->head == membuf->tail) goto leave;
  nmsg = ((membuf->tail % membuf->noffsets) >= (membuf->head % membuf->noffsets)) ?
           ((membuf->tail % membuf->noffsets) - (membuf->head % membuf->noffsets)) :
           ((membuf->tail % membuf->noffsets) + membuf->noffsets - (membuf->head % membuf->noffsets));
  assert(nmsg < membuf->noffsets);
  /* We want stuff *after* this, so add one */
  idx++;
  if(idx == membuf->tail) goto leave;

  /* If we're asked for a starting index outside our range, then we should set it to head. */
  if((membuf->head > membuf->tail && idx < membuf->head && idx >= membuf->tail) ||
     (membuf->head < membuf->tail && (idx >= membuf->tail || idx < membuf->head)))
    idx = membuf->head;

  while(idx != membuf->tail) {
    uint64_t nidx;
    size_t len;
    nidx = idx + 1;
    len = (membuf->offsets[idx % membuf->noffsets] < membuf->offsets[nidx % membuf->noffsets]) ?
            membuf->offsets[nidx % membuf->noffsets] - membuf->offsets[idx % membuf->noffsets] :
            membuf->segmentcut - membuf->offsets[idx % membuf->noffsets];
    struct timeval copy;
    const char *logline;
    memcpy(&copy, membuf->segment + membuf->offsets[idx % membuf->noffsets], sizeof(copy));
    logline = membuf->segment + membuf->offsets[idx % membuf->noffsets] + sizeof(copy);
    len -= sizeof(copy);
    if(f(idx, &copy, logline, len, closure))
      break;
    idx = nidx;
    count++;
  }
 leave:
  pthread_mutex_unlock(&membuf->lock); 
  return count;
}
#define IS_ENABLED_ON(ls) ((ls)->flags & MTEV_LOG_STREAM_ENABLED)
#define IS_TIMESTAMPS_ON(ls) ((ls)->flags & MTEV_LOG_STREAM_TIMESTAMPS)
#define IS_DEBUG_ON(ls) ((ls)->flags & MTEV_LOG_STREAM_DEBUG)
#define IS_FACILITY_ON(ls) ((ls)->flags & MTEV_LOG_STREAM_FACILITY)
#define IS_ENABLED_BELOW(ls) ((ls)->flags_below & MTEV_LOG_STREAM_ENABLED)
#define IS_TIMESTAMPS_BELOW(ls) ((ls)->flags_below & MTEV_LOG_STREAM_TIMESTAMPS)
#define IS_DEBUG_BELOW(ls) ((ls)->flags_below & MTEV_LOG_STREAM_DEBUG)
#define IS_FACILITY_BELOW(ls) ((ls)->flags_below & MTEV_LOG_STREAM_FACILITY)

static mtev_hash_table mtev_loggers;
static mtev_hash_table mtev_logops;

int mtev_log_global_enabled(void) {
  return LIBMTEV_LOG_ENABLED();
}

mtev_boolean mtev_log_has_material_output(mtev_log_stream_t ls) {
  /* This is materialized already into flags_below as "ENABLED" */
  return (IS_ENABLED_ON(ls) && IS_ENABLED_BELOW(ls));
}

static mtev_boolean has_material_output(mtev_log_stream_t ls) {
  mtev_boolean state = mtev_false;
  struct _mtev_log_stream_outlet_list *node;

  if(!IS_ENABLED_ON(ls)) goto ret;
  if(ls->ops != NULL) {
    state = mtev_true;
    goto ret;
  }

  for(node = ls->outlets; node; node = node->next) {
    if(has_material_output(node->outlet)) {
      state = mtev_true;
      goto ret;
    }
  }

 ret:
  debug_printf("has_material_output(%s) -> %s\n", ls->name, state ? "true" : "false");
  return state;
}
static void materialize_deps(mtev_log_stream_t ls) {
  struct _mtev_log_stream_outlet_list *node;
  if(ls->deps_materialized) {
    debug_printf("materialize(%s) [already done]\n", ls->name);
    return;
  }
  /* pass forward all but enabled */
  ls->flags_below |= (ls->flags & MTEV_LOG_STREAM_FEATURES);

  /* we might have children than need these */
  for(node = ls->outlets; node; node = node->next) {
    materialize_deps(node->outlet);
    /* our flags_below should be augmented by our outlets flags_below */
    ls->flags_below |= (~(ls->flags) & MTEV_LOG_STREAM_FEATURES) &
                       node->outlet->flags_below;
    debug_printf("materialize(%s) |= (%s) %x\n", ls->name,
                 node->outlet->name,
                 node->outlet->flags_below & MTEV_LOG_STREAM_FEATURES);
  }

  if(has_material_output(ls)) ls->flags_below |= MTEV_LOG_STREAM_ENABLED;
  else ls->flags_below &= ~MTEV_LOG_STREAM_ENABLED;

  debug_printf("materialize(%s) -> %x\n", ls->name, ls->flags_below);
  ls->deps_materialized = 1;
}

static void
mtev_log_dematerialize(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_log_init_globals();

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    mtev_log_stream_t ls = iter.value.ptr;
    ls->deps_materialized = 0;
    debug_printf("dematerializing(%s)\n", ls->name);
  }
  pthread_mutex_unlock(&resize_lock);
}

static void
mtev_log_materialize(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_log_init_globals();

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    mtev_log_stream_t ls = iter.value.ptr;
    debug_printf("materializing(%s)\n", ls->name);
    materialize_deps(ls);
  }
  pthread_mutex_unlock(&resize_lock);
}

static void
mtev_log_rematerialize(void) {
  mtev_log_dematerialize();
  mtev_log_materialize();
}


typedef struct asynch_log_line {
  char *buf_dynamic;
  char buf_static[512];
  int len;
} asynch_log_line;

typedef struct asynch_log_ctx {
  ck_fifo_mpmc_t q;
  ck_fifo_mpmc_entry_t *qhead;
  char *name;
  int (*write)(struct asynch_log_ctx *, asynch_log_line *);
  void *userdata;
  pthread_t writer;
  pthread_mutex_t singleton;
  uint32_t gen;  /* generation */
  int pid;
  int is_asynch;
  int last_errno;
} asynch_log_ctx;

static asynch_log_line *
asynch_log_pop(asynch_log_ctx *actx) {
  ck_fifo_mpmc_entry_t *garbage = NULL;
  asynch_log_line *ll = NULL;
  if(ck_fifo_mpmc_dequeue(&actx->q, &ll, &garbage) == true) {
    /* We can free this only because this fifo is used as a
     * multi-producer and *single* consumer */
    if(garbage != actx->qhead) free(garbage);
    return ll;
  }
  return NULL;
}

static void
asynch_log_push(asynch_log_ctx *actx, asynch_log_line *n) {
  ck_fifo_mpmc_entry_t *fifo_entry;
  fifo_entry = malloc(sizeof(ck_fifo_mpmc_entry_t));
  ck_fifo_mpmc_enqueue(&actx->q, fifo_entry, n);
}

asynch_log_ctx *asynch_log_ctx_alloc(void) {
  asynch_log_ctx *actx;
  actx = calloc(1, sizeof(*actx));
  actx->qhead = calloc(1, sizeof(*actx->qhead));
  ck_fifo_mpmc_init(&actx->q, actx->qhead);
  pthread_mutex_init(&actx->singleton, NULL);
  return actx;
}
void asynch_log_ctx_free(asynch_log_ctx *tf) {
  asynch_log_line *ll;
  while((ll = asynch_log_pop(tf)) != NULL) {
    if(ll->buf_dynamic) free(ll->buf_dynamic);
    free(ll);
  }
  if(tf->qhead) free(tf->qhead);
  pthread_mutex_destroy(&tf->singleton);
  free(tf);
}

static void
asynch_logio_drain(asynch_log_ctx *actx) {
  asynch_log_line *line;
  if(actx->qhead == NULL) return;
  while(NULL != (line = asynch_log_pop(actx))) {
    if(actx->write(actx, line) == -1) abort();
    if(line->buf_dynamic != NULL) free(line->buf_dynamic);
    free(line);
  }
}

static void *
asynch_logio_writer(void *vls) {
  char thr_name[16];
  mtev_log_stream_t ls = vls;
  asynch_log_ctx *actx = ls->op_ctx;
  uint32_t gen;
  gen = ck_pr_faa_32(&actx->gen, 1) + 1;
  snprintf(thr_name, sizeof(thr_name), "l:%s", ls->name);
  mtev_thread_setname(thr_name);
  pthread_mutex_lock(&actx->singleton);
  mtevL(mtev_debug, "starting asynchronous %s writer[%d/%p]\n",
        actx->name, (int)getpid(), (void *)(intptr_t)pthread_self());
  while(gen == ck_pr_load_32(&actx->gen)) {
    pthread_rwlock_t *lock;
    int fast = 0, max = 1000;
    asynch_log_line *line;
    lock = ls->lock;
    if(lock) pthread_rwlock_rdlock(lock);
    while(max > 0 && NULL != (line = asynch_log_pop(actx))) {
      if(actx->write(actx, line) == -1) abort();
      if(line->buf_dynamic != NULL) free(line->buf_dynamic);
      free(line);
      fast = 1;
      max--;
    }
    if(lock) pthread_rwlock_unlock(lock);
    if(max > 0) {
      /* we didn't hit our limit... so we ran the queue dry */
      /* 200ms if there was nothing, 10ms otherwise..
       *
       * unlock before sleep */
      pthread_mutex_unlock(&actx->singleton);
      usleep(fast ? 10000 : 200000);
      pthread_mutex_lock(&actx->singleton);
    }
  }
  mtevL(mtev_debug, "stopping asynchronous %s writer[%d/%p]\n",
        actx->name, (int)getpid(), (void *)(intptr_t)pthread_self());
  pthread_mutex_unlock(&actx->singleton);
  pthread_exit((void *)0);
}

static int
posix_logio_asynch_write(asynch_log_ctx *actx, asynch_log_line *line) {
  struct posix_op_ctx *po;
  int rv = -1;
  po = actx->userdata;
  actx->last_errno = 0;
  if(po && po->fd >= 0) {
    rv = write(po->fd, line->buf_dynamic ? line->buf_dynamic : line->buf_static,
               line->len);
    if(rv < 0) actx->last_errno = errno;
  }
  return rv;
}

static int
asynch_thread_create(mtev_log_stream_t ls, asynch_log_ctx *actx, void* function) {
  pthread_attr_t tattr;
  int pid = getpid();

  if (actx->pid != pid) {
    if (actx->pid) {
      pthread_mutex_destroy(&actx->singleton);
    }
    pthread_mutex_init(&actx->singleton, NULL);
    ck_pr_inc_32(&actx->gen);
    actx->pid = pid;
  }
  pthread_attr_init(&tattr);
  pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
  if(pthread_create(&actx->writer, &tattr, function, ls) != 0) {
    return -1;
  }
  return 0;
}

static int
posix_logio_open(mtev_log_stream_t ls) {
  int fd, rv;
  struct stat sb;
  asynch_log_ctx *actx;
  struct posix_op_ctx *po;
  ls->mode = 0664;
  fd = open(ls->path, O_CREAT|O_WRONLY|O_APPEND, ls->mode);
  debug_printf("opened '%s' => %d\n", ls->path, fd);
  if(fd < 0) {
    ls->op_ctx = NULL;
    return -1;
  }

  po = malloc(sizeof(*po));
  po->fd = fd;
  while((rv = fstat(fd, &sb)) != 0 && errno == EINTR);
  if(rv == 0) {
    memcpy(&po->sb, &sb, sizeof(sb));
    ls->written = sb.st_size;
  }

  actx = asynch_log_ctx_alloc();

  actx->userdata = po;
  actx->name = "posix";
  actx->write = posix_logio_asynch_write;
  ls->op_ctx = actx;

  if (actx->is_asynch &&
      asynch_thread_create(ls, actx, asynch_logio_writer)) {
    actx->last_errno = errno;
    return -1;
  }
  return 0;
}
static int
posix_logio_reopen(mtev_log_stream_t ls) {
  if(ls->path) {
    struct posix_op_ctx *po;
    struct stat newpathsb, sb;
    asynch_log_ctx *actx;
    pthread_rwlock_t *lock = ls->lock;
    int newfd, rv = -1, oldrv = -1;
    if(lock) pthread_rwlock_wrlock(lock);
    actx = ls->op_ctx;
    po = actx->userdata;

    /* Let's see if the we're looking at the right file already */
    while((oldrv = fstat(po->fd, &po->sb)) != 0 && errno == EINTR);
    while((rv = stat(ls->path, &newpathsb)) != 0 && errno == EINTR);
    if(oldrv == 0 && rv == 0 &&
       po->sb.st_dev == newpathsb.st_dev &&
       po->sb.st_ino == newpathsb.st_ino) {
      /* reopening wouldn't do anything... skip the work */
      /* rv is already 0... */
      goto out;
    }

    newfd = open(ls->path, O_CREAT|O_WRONLY|O_APPEND, ls->mode);
    ls->written = 0;
    if(newfd >= 0) {
      int fd_to_close = po->fd;
      po->fd = newfd;
      if(fd_to_close >= 0) close(fd_to_close);
      while((rv = fstat(newfd, &sb)) != 0 && errno == EINTR);
      if(rv == 0) {
        if(oldrv == 0 && /* have ownership of old file */
           (po->sb.st_uid != sb.st_uid || po->sb.st_gid != sb.st_gid)) {
          /* doesn't match the new one, set the new one like the old one */
          int unused __attribute__((unused));
          unused = fchown(newfd, po->sb.st_uid, po->sb.st_gid);
          /* Not much we can do if it fails. */
          sb.st_uid = po->sb.st_uid;
          sb.st_gid = po->sb.st_gid;
          memcpy(&po->sb, &sb, sizeof(sb));
        }
        ls->written = sb.st_size;
      }
      rv = 0;
    }
   out:
    if(lock) pthread_rwlock_unlock(lock);
    if(actx->is_asynch) {
      if(asynch_thread_create(ls, actx, asynch_logio_writer)) {
        return -1;
      }
    }
    return rv;
  }
  return -1;
}
static int
posix_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                  const void *buf, size_t len) {
  int rv = -1;
  asynch_log_ctx *actx;
  asynch_log_line *line;
  (void)whence;
  if(!ls->op_ctx) return -1;
  actx = ls->op_ctx;
  if(!actx->is_asynch || _mtev_log_siglvl > 0) {
    struct posix_op_ctx *po;
    pthread_rwlock_t *lock = ls->lock;
    po = actx->userdata;
    if(lock) pthread_rwlock_rdlock(lock);

    /* Drain any asynch queue (if we've come back from asynch mode) */
    asynch_logio_drain(actx);

    if(po && po->fd >= 0) rv = write(po->fd, buf, len);
    if(lock) pthread_rwlock_unlock(lock);
    if(rv > 0) ck_pr_add_64(&ls->written, rv);
    return rv;
  }
  line = malloc(sizeof(*line));
  line->buf_dynamic = NULL;
  if(len > sizeof(line->buf_static)) {
    line->buf_dynamic = malloc(len);
    memcpy(line->buf_dynamic, buf, len);
  }
  else {
    memcpy(line->buf_static, buf, len);
  }
  rv = line->len = len;
  ck_pr_add_64(&ls->written, rv);
  asynch_log_push(actx, line);
  return rv;
}
static int
posix_logio_close(mtev_log_stream_t ls) {
  int rv;
  struct posix_op_ctx *po;
  asynch_log_ctx *actx;
  pthread_rwlock_t *lock = ls->lock;
  if(lock) pthread_rwlock_wrlock(lock);
  actx = ls->op_ctx;
  po = actx->userdata;
  actx->userdata = NULL;
  rv = close(po->fd);
  if(lock) pthread_rwlock_unlock(lock);
  return rv;
}
static size_t
posix_logio_size(mtev_log_stream_t ls) {
  int rv;
  struct posix_op_ctx *po;
  size_t s = (size_t)-1;
  asynch_log_ctx *actx = ls->op_ctx;
  pthread_rwlock_t *lock = ls->lock;
  if(lock) pthread_rwlock_rdlock(lock);
  po = actx->userdata;
  if(po && po->fd >= 0) {
    while((rv = fstat(po->fd, &po->sb)) == -1 && errno == EINTR);
    if(rv == 0) s = (size_t)po->sb.st_size;
  }
  if(lock) pthread_rwlock_unlock(lock);
  return s;
}
static int
posix_logio_rename(mtev_log_stream_t ls, const char *name) {
  int rv = 0;
  char autoname[PATH_MAX];
  pthread_rwlock_t *lock = ls->lock;
  if(name == MTEV_LOG_RENAME_AUTOTIME) {
    time_t now = time(NULL);
    snprintf(autoname, sizeof(autoname), "%s.%llu",
             ls->path, (unsigned long long)now);
    name = autoname;
  }
  if(!strcmp(name, ls->path)) return 0; /* noop */
  if(lock) pthread_rwlock_rdlock(lock);
  rv = rename(ls->path, name);
  if(lock) pthread_rwlock_unlock(lock);
  return rv;
}
struct log_finfo {
  char *name;
  int age;
  size_t bytes;
  struct log_finfo *next;
};

static int
autoname_order(const void *av, const void *bv) {
  struct log_finfo * const *a = av, * const *b = bv;
  if((*a)->age < (*b)->age) return -1;
  if((*a)->age == (*b)->age) return 0;
  return 1;
}
static int
posix_logio_cull(mtev_log_stream_t ls, int age, ssize_t bytes) {
  /* This only applies to auto-named things, so assume it is autonamed */
  size_t cumm_size = 0;
  time_t now;
  struct log_finfo *candidates = NULL;
  struct log_finfo **sortset;
  DIR *d;
  struct dirent *de, *entry;
  char *filename;
  char dir[PATH_MAX], path[PATH_MAX];
  int size = 0, cnt = 0, i;
  size_t pathlen;

  mtevL(mtev_debug, "cull(%s, %d, %lld)\n", ls->path, age,
        (long long)bytes);

  strlcpy(dir, ls->path, sizeof(dir));
  filename = strrchr(dir, IFS_CH);
  if(!filename) return -1;
  *filename++ = '\0';

  d = opendir(dir);
  if(!d) return -1;

#ifdef _PC_NAME_MAX
  size = pathconf(dir, _PC_NAME_MAX);
  if(size < 0) size = PATH_MAX + 128;
#endif
  size = MIN(size, PATH_MAX + 128);
  de = malloc(size);

  pathlen = strlen(filename);
  now = time(NULL);
  while(portable_readdir_r(d, de, &entry) == 0 && entry != NULL) {
    int rv;
    struct log_finfo *node;
    struct stat sb;
    time_t whence;
    char *endptr = NULL;

    if(strlen(entry->d_name) <= pathlen + 2) continue;      /* long enough */
    if(memcmp(entry->d_name, filename, pathlen)) continue;  /* prefix matches */
    if(entry->d_name[pathlen] != '.') continue;             /* with dot */
    whence = strtoull(entry->d_name + pathlen + 1, &endptr, 10);
    if(!endptr || *endptr != '\0') continue;                /* followed by ts */

    node = malloc(sizeof(*node));
    snprintf(path, sizeof(path), "%s%c%s", dir, IFS_CH, entry->d_name);
    node->name = strdup(path);
    node->age = now - whence;
    while((rv = stat(node->name, &sb)) == -1 && errno == EINTR);
    node->bytes = (rv == 0) ? sb.st_size : 0;
    node->next = candidates;
    candidates = node;
    cnt++;
  }
  closedir(d);
  free(de);

  if(cnt == 0) return 0;

  /* construct a sorted set */
  sortset = malloc(cnt * sizeof(*sortset));
  i = 0;
  while(candidates) {
    assert(i < cnt);
    sortset[i++] = candidates;
    candidates = candidates->next;
  }
  qsort(sortset, cnt, sizeof(*sortset), autoname_order);

  for(i=0;i<cnt;i++) {
    int remove = 0;
    char * old_str = "", *size_str = "";
    if(age >= 0 && sortset[i]->age > age) {
      remove = 1;
      old_str = " [age]";
    }
    if(bytes >= 0 && (ssize_t)cumm_size > bytes) {
      remove = 1;
      size_str = " [size]";
    }
    cumm_size += sortset[i]->bytes;

    if(remove) {
      mtevL(mtev_debug, "removing log %s%s%s\n", sortset[i]->name, old_str, size_str);
      unlink(sortset[i]->name);
    }

    free(sortset[i]->name);
    free(sortset[i]);
  }
  free(sortset);
  return cnt;
}

static logops_t posix_logio_ops = {
  mtev_true,
  posix_logio_open,
  posix_logio_reopen,
  posix_logio_write,
  NULL,
  posix_logio_close,
  posix_logio_size,
  posix_logio_rename,
  posix_logio_cull
};

static int
jlog_lspath_to_fspath(mtev_log_stream_t ls, char *buff, int len,
                      char **subout) {
  char *sub;
  if(subout) *subout = NULL;
  if(!ls->path) return -1;
  strlcpy(buff, ls->path, len);
  sub = strchr(buff, '(');
  if(sub) {
    char *esub = strchr(sub, ')');
    if(esub) {
      *esub = '\0';
      *sub = '\0';
      sub += 1;
      if(subout) *subout = sub;
    }
  }
  return strlen(buff);
}

/* These next functions arr basically cribbed from jlogctl.c */
static int
is_datafile(const char *f, uint32_t *logid) {
  int i;
  uint32_t l = 0;
  for(i=0; i<8; i++) {
    if((f[i] >= '0' && f[i] <= '9') ||
       (f[i] >= 'a' && f[i] <= 'f')) {
      l <<= 4;
      l |= (f[i] < 'a') ? (f[i] - '0') : (f[i] - 'a' + 10);
    }
    else
      return 0;
  }
  if(f[i] != '\0') return 0;
  if(logid) *logid = l;
  return 1;
}

static int
jlog_logio_cleanse(mtev_log_stream_t ls) {
  asynch_log_ctx *actx;
  jlog_ctx *log;
  DIR *d;
  struct dirent *de, *entry;
  int cnt = 0, readers;
  uint32_t earliest = 0;
  char path[PATH_MAX];
  int size = 0;

  actx = ls->op_ctx;
  if(!actx) return -1;
  log = actx->userdata;
  if(!log) return -1;
  if(jlog_lspath_to_fspath(ls, path, sizeof(path), NULL) <= 0) return -1;
  d = opendir(path);

  /* populate earliest, if this fails, we assume */
  readers = jlog_pending_readers(log, log->current_log, &earliest);
  if(readers < 0) {
    if (d) {
      closedir(d);
    }
    return -1;
  }
  if(readers == 0) {
    if (d) {
      closedir(d);
    }
    return 0;
  }
  if(!d) return -1;

#ifdef _PC_NAME_MAX
  size = pathconf(path, _PC_NAME_MAX);
  if(size < 0) size = PATH_MAX + 128;
#endif
  size = MIN(size, PATH_MAX + 128);
  de = malloc(size);

  while(portable_readdir_r(d, de, &entry) == 0 && entry != NULL) {
    uint32_t logid;
    /* the current log file isn't a deletion target. period. */
    if(is_datafile(entry->d_name, &logid) &&  /* make sure it is a datafile */
       logid < earliest &&                    /* and that is older enough */
       logid != log->current_log) {           /* and that isn't current */
      char fullfile[PATH_MAX];
      char fullidx[PATH_MAX];

      snprintf(fullfile, sizeof(fullfile), "%s/%s", path, entry->d_name);
      snprintf(fullidx, sizeof(fullidx), "%s/%s" INDEX_EXT,
               path, entry->d_name);
      (void)unlink(fullfile);
      (void)unlink(fullidx); /* this might fail ENOENT; don't care */
      cnt++;
    }
  }
  closedir(d);
  free(de);
  return cnt;
}
static int
jlog_logio_reopen(mtev_log_stream_t ls) {
  char **subs;
  asynch_log_ctx *actx = ls->op_ctx;
  pthread_rwlock_t *lock = ls->lock;
  jlog_ctx *log = actx->userdata;
  int i;
  /* reopening only has the effect of removing temporary subscriptions */
  /* (they start with ~ in our hair-brained model */

  if(lock) pthread_rwlock_wrlock(lock);
  if(jlog_ctx_list_subscribers(log, &subs) == -1)
    goto bail;

  for(i=0;subs[i];i++)
    if(subs[i][0] == '~')
      jlog_ctx_remove_subscriber(log, subs[i]);

  jlog_ctx_list_subscribers_dispose(log, subs);
  jlog_logio_cleanse(ls);
 bail:
  if(lock) pthread_rwlock_unlock(lock);

  if (actx->is_asynch &&
      asynch_thread_create(ls, actx, asynch_logio_writer)) {
    return -1;
  }
  
  return 0;
}
static void
mtev_log_jlog_err(void *ctx, const char *format, ...) {
  (void)ctx;
  struct timeval now;
  va_list arg;
  va_start(arg, format);
  mtev_gettimeofday(&now, NULL);
  (void)mtev_vlog(mtev_error, &now, "jlog.c", 0, format, arg);
  va_end(arg);
}

int jlog_logio_asynch_write(asynch_log_ctx *actx, asynch_log_line *line) {
  int rv;
  jlog_ctx *log = actx->userdata;
  actx->last_errno = 0;
  rv = jlog_ctx_write(log, line->buf_dynamic ?
                             line->buf_dynamic :
                             line->buf_static,
                      line->len);
  if(rv == -1) {
    actx->last_errno = jlog_ctx_errno(log);
    mtevL(mtev_error, "jlog_ctx_write failed(%d): %s\n",
          jlog_ctx_errno(log), jlog_ctx_err_string(log));
  }
  return rv;
}

static int
jlog_logio_open(mtev_log_stream_t ls) {
  char path[PATH_MAX], *sub, **subs, *p;
  asynch_log_ctx *actx;
  jlog_ctx *log = NULL;
  int i, listed, found, allow_unmatched = 0;

  if(jlog_lspath_to_fspath(ls, path, sizeof(path), &sub) <= 0) return -1;
  log = jlog_new(path);
  if(!log) return -1;
  jlog_set_error_func(log, mtev_log_jlog_err, ls);
  /* Open the writer. */
  if(jlog_ctx_open_writer(log)) {
    /* If that fails, we'll give one attempt at initiailizing it. */
    /* But, since we attempted to open it as a writer, it is tainted. */
    /* path: close, new, init, close, new, writer, add subscriber */
    jlog_ctx_close(log);
    log = jlog_new(path);
    jlog_set_error_func(log, mtev_log_jlog_err, ls);
    if(jlog_ctx_init(log)) {
      mtevL(mtev_error, "Cannot init jlog writer: %s\n",
            jlog_ctx_err_string(log));
      jlog_ctx_close(log);
      return -1;
    }
    /* After it is initialized, we can try to reopen it as a writer. */
    jlog_ctx_close(log);
    log = jlog_new(path);
    jlog_set_error_func(log, mtev_log_jlog_err, ls);
    if(jlog_ctx_open_writer(log)) {
      mtevL(mtev_error, "Cannot open jlog writer: %s\n",
            jlog_ctx_err_string(log));
      jlog_ctx_close(log);
      return -1;
    }
  }

  /* Add or remove subscribers according to the current configuration. */
  listed = jlog_ctx_list_subscribers(log, &subs);
  if(listed == -1) {
    mtevL(mtev_error, "Cannot list jlog subscribers: %s\n",
          jlog_ctx_err_string(log));
    jlog_ctx_close(log);
    return -1;
  }

  if(sub) {
    /* Match all configured subscribers against jlog's list. */
    for(p=strtok(sub, ",");p;p=strtok(NULL, ",")) {
      if(!strcmp(p,"*")) allow_unmatched = 1;
      for(i=0;i<listed;i++) {
        if((subs[i]) && (strcmp(p, subs[i]) == 0)) {
          free(subs[i]);
          subs[i] = NULL;
          break;
        }
      }
      if(i == listed && strcmp(p,"*"))
        jlog_ctx_add_subscriber(log, p, JLOG_BEGIN);
    }

    /* Remove all unmatched subscribers. */
    for(i=0;i<listed;i++) {
      if(subs[i] &&
         (!allow_unmatched || subs[i][0] == '~')) {
        jlog_ctx_remove_subscriber(log, subs[i]);
      }
      free(subs[i]);
      subs[i] = NULL;
    }

    free(subs);
    subs = NULL;
  } else {
    /* Remove all subscribers other than DEFAULT_JLOG_SUBSCRIBER. */
    found = 0;
    for(i=0;i<listed;i++) {
      if((subs[i]) && (strcmp(DEFAULT_JLOG_SUBSCRIBER, subs[i]) == 0)) {
        found = 1;
        continue;
      }
      jlog_ctx_remove_subscriber(log, subs[i]);
    }

    /* Add DEFAULT_JLOG_SUBSCRIBER if it wasn't already on the jlog's list. */
    if(!found)
      jlog_ctx_add_subscriber(log, DEFAULT_JLOG_SUBSCRIBER, JLOG_BEGIN);

    jlog_ctx_list_subscribers_dispose(log, subs);
  }

  actx = asynch_log_ctx_alloc();
  actx->userdata = log;
  actx->name = "jlog";
  actx->write = jlog_logio_asynch_write;
  ls->op_ctx = actx;

  /* We do this to clean things up and start our thread */
  return jlog_logio_reopen(ls);
}

static int
jlog_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                 const void *buf, size_t len) {
  int rv = -1;
  asynch_log_ctx *actx;
  asynch_log_line *line;
  (void)whence;
  if(!ls->op_ctx) return -1;
  actx = ls->op_ctx;
  if(!actx->is_asynch || _mtev_log_siglvl > 0) {
    int rv;
    jlog_ctx *log = actx->userdata;

    /* Drain any asynch queue (if we've come back from asynch mode) */
    asynch_logio_drain(actx);

    rv = jlog_ctx_write(log, buf, len);
    if(rv == -1) {
      mtevL(mtev_error, "jlog_ctx_write failed(%d): %s\n",
            jlog_ctx_errno(log), jlog_ctx_err_string(log));
    }
    return rv;
  }
  line = calloc(1, sizeof(*line));
  if(len > sizeof(line->buf_static)) {
    line->buf_dynamic = malloc(len);
    memcpy(line->buf_dynamic, buf, len);
  }
  else {
    memcpy(line->buf_static, buf, len);
  }
  line->len = len;
  asynch_log_push(actx, line);
  return rv;
}
static int
jlog_logio_close(mtev_log_stream_t ls) {
  if(ls->op_ctx) {
    asynch_log_ctx *actx = ls->op_ctx;
    jlog_ctx *log = actx->userdata;
    jlog_ctx_close(log);
    ls->op_ctx = NULL;
  }
  return 0;
}
static size_t
jlog_logio_size(mtev_log_stream_t ls) {
  size_t size;
  asynch_log_ctx *actx;
  jlog_ctx *log;
  pthread_rwlock_t *lock = ls->lock;
  if(!ls->op_ctx) return -1;
  actx = ls->op_ctx;
  log = actx->userdata;
  if(lock) pthread_rwlock_rdlock(lock);
  size = jlog_raw_size(log);
  if(lock) pthread_rwlock_unlock(lock);
  return size;
}
static int
jlog_logio_rename(mtev_log_stream_t ls, const char *newname) {
  (void)ls;
  (void)newname;
  /* Not supported (and makes no sense) */
  return -1;
}
static int
jlog_logio_cull(mtev_log_stream_t ls, int age, ssize_t bytes) {
  (void)ls;
  (void)age;
  (void)bytes;
  /* Not supported (and makes no sense) */
  return -1;
}
static logops_t jlog_logio_ops = {
  mtev_true,
  jlog_logio_open,
  jlog_logio_reopen,
  jlog_logio_write,
  NULL,
  jlog_logio_close,
  jlog_logio_size,
  jlog_logio_rename,
  jlog_logio_cull
};

static void
mtev_log_shutdown(void) {
  mtev_log_go_synch();
}

static void prep_resize_lock(void) {
  pthread_mutex_lock(&resize_lock);
}
void
mtev_log_init(int debug_on) {
  mtev_log_init_globals();
  atexit(mtev_log_shutdown);
  mtev_register_logops("file", &posix_logio_ops);
  mtev_register_logops("jlog", &jlog_logio_ops);
  mtev_register_logops("memory", &membuf_logio_ops);
  mtev_stderr = mtev_log_stream_new_on_fd("stderr", 2, NULL);
  mtev_stderr->flags = BOOT_STDERR_FLAGS;
  mtev_stderr->flags_below = BOOT_STDERR_FLAGS;
  mtev_error = mtev_log_stream_new("error", NULL, NULL, NULL, NULL);
  mtev_log_stream_add_stream(mtev_error, mtev_stderr);
  mtev_debug = mtev_log_stream_new("debug", NULL, NULL, NULL, NULL);
  mtev_log_stream_add_stream(mtev_debug, mtev_stderr);
  mtev_notice = mtev_log_stream_new("notice", NULL, NULL, NULL, NULL);
  mtev_log_stream_add_stream(mtev_notice, mtev_error);
  mtev_debug->flags = (mtev_debug->flags & ~MTEV_LOG_STREAM_DEBUG) |
                      (debug_on ? MTEV_LOG_STREAM_DEBUG : 0);
  if(debug_on) mtev_debug->flags |= MTEV_LOG_STREAM_ENABLED;
  else mtev_debug->flags &= ~MTEV_LOG_STREAM_ENABLED;
}

void
mtev_register_logops(const char *name, logops_t *ops) {
  mtev_hash_store(&mtev_logops, strdup(name), strlen(name), ops);
}

void *
mtev_log_stream_get_ctx(mtev_log_stream_t ls) {
  return ls->op_ctx;
}

void
mtev_log_stream_set_ctx(mtev_log_stream_t ls, void *nctx) {
  ls->op_ctx = nctx;
}

int
mtev_log_stream_get_flags(mtev_log_stream_t ls) {
  return ls->flags;
}

int
mtev_log_stream_set_dedup_s(mtev_log_stream_t ls, int s) {
  return 0;
}

int
mtev_log_stream_get_dedup_s(mtev_log_stream_t ls) {
  return 0;
}

mtev_boolean
mtev_log_stream_set_format(mtev_log_stream_t ls, mtev_log_format_t f) {
  if(ls->ops == NULL) return mtev_false;
  ls->format = f;
  return mtev_true;
}

int
mtev_log_stream_set_flags(mtev_log_stream_t ls, int new_flags) {
  int previous_flags = ls->flags;
  ls->flags = new_flags;
  if(previous_flags != new_flags) mtev_log_rematerialize();
  return previous_flags;
}

const char *
mtev_log_stream_get_type(mtev_log_stream_t ls) {
  return ls->type;
}

const char *
mtev_log_stream_get_name(mtev_log_stream_t ls) {
  return ls->name;
}

const char *
mtev_log_stream_get_path(mtev_log_stream_t ls) {
  return ls->path;
}

const char *
mtev_log_stream_get_property(mtev_log_stream_t ls,
                             const char *prop) {
  const char *v;
  if(ls && ls->config &&
     mtev_hash_retr_str(ls->config, prop, strlen(prop), &v))
    return v;
  return NULL;
}

void
mtev_log_stream_set_property(mtev_log_stream_t ls,
                             const char *prop, const char *v) {
  if(!ls) return;
  if(!ls->config) {
    ls->config = calloc(1, sizeof(*ls->config));
    mtev_hash_init(ls->config);
  }
  mtev_hash_replace(ls->config, prop, strlen(prop), (void *)v, free, free);
}

static void
mtev_log_init_rwlock(mtev_log_stream_t ls) {
  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
  pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
  pthread_rwlock_init(ls->lock, &attr);
}

mtev_log_stream_t
mtev_log_stream_new_on_fd(const char *name, int fd, mtev_hash_table *config) {
  char *lsname;
  struct posix_op_ctx *po;
  mtev_log_stream_t ls;
  asynch_log_ctx *actx;
  ls = calloc(1, sizeof(*ls));
  actx = asynch_log_ctx_alloc();
  actx->name = "posix";
  actx->write = posix_logio_asynch_write;
  po = calloc(1, sizeof(*po));
  po->fd = fd;
  actx->userdata = po;
  ls->name = strdup(name);
  ls->ops = &posix_logio_ops;
  ls->op_ctx = actx;
  ls->flags |= MTEV_LOG_STREAM_ENABLED;
  ls->config = config;
  ls->lock = calloc(1, sizeof(*ls->lock));
  mtev_log_init_rwlock(ls);
  /* This double strdup of ls->name is needed, look for the next one
   * for an explanation.
   */
  lsname = strdup(ls->name);
  pthread_mutex_lock(&resize_lock);
  if(mtev_hash_store(&mtev_loggers,
                     lsname, strlen(ls->name), ls) == 0) {
    pthread_mutex_unlock(&resize_lock);
    free(lsname);
    free(ls->name);
    free(ls);
    asynch_log_ctx_free(actx);
    return NULL;
  }
  pthread_mutex_unlock(&resize_lock);
  return ls;
}

mtev_log_stream_t
mtev_log_stream_new_on_file(const char *path, mtev_hash_table *config) {
  return mtev_log_stream_new(path, "file", path, NULL, config);
}

static mtev_boolean
mtev_log_resolve(mtev_log_stream_t ls) {
  void *vops = NULL;
  if(!ls->type) return mtev_true;
  if(ls->ops) return mtev_true;
  if(mtev_hash_retrieve(&mtev_logops, ls->type, strlen(ls->type),
                        &vops)) {
    ls->ops = vops;
  }
  else return mtev_false;
  if(ls->ops->openop(ls)) return mtev_false;
  return mtev_true;
}

mtev_boolean
mtev_log_final_resolve(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    if(!mtev_log_resolve((mtev_log_stream_t)iter.value.ptr)) {
      pthread_mutex_unlock(&resize_lock);
      mtevL(mtev_stderr, "Failed to resolve log: %s\n", iter.key.str);
      return mtev_false;
    }
  }
  pthread_mutex_unlock(&resize_lock);
  return mtev_true;
}

static mtev_log_stream_t
mtev_log_stream_new_internal(const char *name, const char *type, const char *path,
                    void *ctx, mtev_hash_table *config, mtev_log_stream_t saved) {
  mtev_log_stream_t ls;
  struct _mtev_log_stream tmpbuf;
  void *vops = NULL;

  ls = calloc(1, sizeof(*ls));
  ls->name = strdup(name);
  ls->path = path ? strdup(path) : NULL;
  ls->type = type ? strdup(type) : NULL;
  if(ls->type && 0 == strcmp(ls->type, "file"))
    ls->flags |= MTEV_LOG_STREAM_SPLIT;
  ls->flags |= MTEV_LOG_STREAM_ENABLED;
  ls->config = config;
  if(!type)
    ls->ops = NULL;
  else if(mtev_hash_retrieve(&mtev_logops, type, strlen(type),
                             &vops))
    ls->ops = vops;
 
  if(ls->ops && ls->ops->openop(ls)) goto freebail;

  if(saved) {
    pthread_rwlock_t *lock = saved->lock;
    memcpy(&tmpbuf, saved, sizeof(*saved));
    memcpy(saved, ls, sizeof(*saved));
    memcpy(ls, &tmpbuf, sizeof(*saved));
    saved->lock = lock;

    ls->lock = NULL;
    mtev_log_stream_free(ls);
    ls = saved;
  }
  else {
    /* We strdup the name *again*.  We'going to kansas city shuffle the
     * ls later (see memcpy above).  However, if don't strdup, then the
     * mtev_log_stream_free up there will sweep our key right our from
     * under us.
     */
    char *lsname;
    lsname = strdup(ls->name);
    pthread_mutex_lock(&resize_lock);
    if(mtev_hash_store(&mtev_loggers,
                       lsname, strlen(ls->name), ls) == 0) {
      pthread_mutex_unlock(&resize_lock);
      free(lsname);
      goto freebail;
    }
    pthread_mutex_unlock(&resize_lock);
    ls->lock = calloc(1, sizeof(*ls->lock));
    mtev_log_init_rwlock(ls);
  }
  /* This is for things that don't open on paths */
  if(ctx) ls->op_ctx = ctx;
  mtev_log_rematerialize();
  return ls;

 freebail:
  fprintf(stderr, "Failed to instantiate logger(%s,%s,%s)\n",
          name, type ? type : "[null]", path ? path : "[null]");
  free(ls->name);
  if(ls->path) free(ls->path);
  if(ls->type) free(ls->type);
  free(ls);
  return NULL;
}

mtev_log_stream_t
mtev_log_stream_new(const char *name, const char *type, const char *path,
                    void *ctx, mtev_hash_table *config) {
  if(!strcmp(name, "stderr")) {
    mtev_log_stream_t stderr_ls = mtev_log_stream_find("stderr");
    if(stderr_ls) return stderr_ls;
  }
  return mtev_log_stream_new_internal(name,type,path,ctx,config,
                                      mtev_log_stream_find(name));
}

mtev_boolean
mtev_log_stream_exists(const char *name) {
  void *vls;
  if(mtev_hash_retrieve(&mtev_loggers, name, strlen(name), &vls)) {
    return mtev_true;
  }
  return mtev_false;
}

mtev_log_stream_t
mtev_log_stream_findf(const char *format, ...) {
  char buff[128];
  va_list arg;
  va_start(arg, format);
  int len = vsnprintf(buff, sizeof(buff), format, arg);
  va_end(arg);
  if(len <= 0 || len > (int)sizeof(buff)-1) return NULL;
  return mtev_log_stream_find(buff);
}

mtev_log_stream_t
mtev_log_stream_find(const char *name) {
  char *last_sep;
  void *vls;
  mtev_log_stream_t newls;
  if(mtev_hash_retrieve(&mtev_loggers, name, strlen(name), &vls)) {
    return (mtev_log_stream_t)vls;
  }
  newls = mtev_log_stream_new_internal(name, NULL, NULL, NULL, NULL, NULL);
  if (!newls) {
    /* We may have lost a race..... try to retrieve it again */
    if(mtev_hash_retrieve(&mtev_loggers, name, strlen(name), &vls)) {
      return (mtev_log_stream_t)vls;
    }
    else {
      mtevFatal(mtev_error, "Couldn't open stream: %s\n", name);
    }
  }

  /* Special case debug and stderr to match their boot conditions */
  if(!strcmp(name, "debug")) newls->flags = BOOT_DEBUG_FLAGS;
  else if(!strcmp(name, "stderr")) newls->flags = BOOT_STDERR_FLAGS;

  if(NULL != (last_sep = strrchr(name, '/'))) {
    char *parent = mtev_strndup(name, (int)(last_sep - name));
    mtev_log_stream_add_stream(newls, mtev_log_stream_find(parent));
    free(parent);
  }

  mtev_log_rematerialize();
  return newls;
}

void
mtev_log_stream_remove(const char *name) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_log_stream_t ls;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    ls = iter.value.ptr;
    mtev_log_stream_remove_stream(ls, name);
  }
  mtev_hash_delete(&mtev_loggers, name, strlen(name), free, NULL);
  pthread_mutex_unlock(&resize_lock);
}

void
mtev_log_stream_add_stream(mtev_log_stream_t ls, mtev_log_stream_t outlet) {
  struct _mtev_log_stream_outlet_list *newnode;
  for(newnode = ls->outlets; newnode; newnode = newnode->next) {
    if(!strcmp(newnode->outlet->name, outlet->name)) {
      mtevAssert(outlet == newnode->outlet);
      return;
    }
  }
  newnode = calloc(1, sizeof(*newnode));
  newnode->outlet = outlet;
  newnode->next = ls->outlets;
  ls->outlets = newnode;
  mtev_log_rematerialize();
}

void
mtev_log_stream_removeall_streams(mtev_log_stream_t ls) {
  struct _mtev_log_stream_outlet_list *tofree;
  if(ls->outlets == NULL) return;
  while(NULL != (tofree = ls->outlets)) {
    ls->outlets = ls->outlets->next;
    free(tofree);
  }
  mtev_log_rematerialize();
}

mtev_log_stream_t
mtev_log_stream_remove_stream(mtev_log_stream_t ls, const char *name) {
  mtev_log_stream_t outlet;
  struct _mtev_log_stream_outlet_list *node, *tmp;
  if(!ls->outlets) return NULL;
  if(!strcmp(ls->outlets->outlet->name, name)) {
    node = ls->outlets;
    ls->outlets = node->next;
    outlet = node->outlet;
    free(node);
    mtev_log_rematerialize();
    return outlet;
  }
  for(node = ls->outlets; node->next; node = node->next) {
    if(!strcmp(node->next->outlet->name, name)) {
      /* splice */
      tmp = node->next;
      node->next = tmp->next;
      /* pluck */
      outlet = tmp->outlet;
      /* shed */
      free(tmp);
      /* return */
      mtev_log_rematerialize();
      return outlet;
    }
  }
  return NULL;
}

void mtev_log_stream_reopen(mtev_log_stream_t ls) {
  struct _mtev_log_stream_outlet_list *node;
  if(ls->ops && ls->ops->reopenop) ls->ops->reopenop(ls);
  for(node = ls->outlets; node; node = node->next) {
    mtev_log_stream_reopen(node->outlet);
  }
}

int mtev_log_stream_rename(mtev_log_stream_t ls, const char *newname) {
  return (ls->ops && ls->ops->renameop) ? ls->ops->renameop(ls, newname) : -1;
}

int mtev_log_stream_cull(mtev_log_stream_t ls, int age, ssize_t bytes) {
  return (ls->ops && ls->ops->cullop) ? ls->ops->cullop(ls, age, bytes) : -1;
}

void
mtev_log_stream_close(mtev_log_stream_t ls) {
  if(ls->ops) ls->ops->closeop(ls);
}

size_t
mtev_log_stream_size(mtev_log_stream_t ls) {
  if(ls->ops && ls->ops->sizeop) return ls->ops->sizeop(ls);
  return -1;
}

size_t
mtev_log_stream_written(mtev_log_stream_t ls) {
  return ls->written;
}

void
mtev_log_stream_free(mtev_log_stream_t ls) {
  if(ls) {
    struct _mtev_log_stream_outlet_list *node;
    if(ls->name) free(ls->name);
    if(ls->path) free(ls->path);
    if(ls->type) free(ls->type);
    while(ls->outlets) {
      node = ls->outlets->next;
      free(ls->outlets);
      ls->outlets = node;
    }
    if(ls->config) {
      mtev_hash_destroy(ls->config, free, free);
      free(ls->config);
    }
    if(ls->lock) {
      pthread_rwlock_destroy(ls->lock);
      free(ls->lock);
    }
    free(ls);
  }
}

static int
mtev_log_writev(mtev_log_stream_t ls, const struct timeval *whence,
                const struct iovec *iov, int iovcnt) {
  /* This emulates writev into a buffer for ops that don't support it */
  char stackbuff[16384], *tofree = NULL, *buff = NULL;
  int i, ins = 0, maxi_nomalloc = 0;
  size_t s = 0;

  if(!ls->ops) return -1;
  if(ls->ops->writevop) return ls->ops->writevop(ls, whence, iov, iovcnt);
  if(!ls->ops->writeop) return -1;
  if(iovcnt == 1) return ls->ops->writeop(ls, whence, iov[0].iov_base, iov[0].iov_len);

  for(i=0;i<iovcnt;i++) {
    s+=iov[i].iov_len;
    if(s <= sizeof(stackbuff)) maxi_nomalloc = i;
  }
  buff = stackbuff;
  if(_mtev_log_siglvl > 0) {
    /* If we're in a signal handler, we can't malloc.
     * Instead, shorten iovcnt and write what we can.
     */
    iovcnt = maxi_nomalloc + 1;
  }
  else if(s > sizeof(stackbuff)) {
    tofree = buff = malloc(s);
    if(tofree == NULL) return -1;
  }
  for(i=0;i<iovcnt;i++) {
    memcpy(buff + ins, iov[i].iov_base, iov[i].iov_len);
    ins += iov[i].iov_len;
  }
  i = ls->ops->writeop(ls, whence, buff, s);
  if(tofree) free(tofree);
  return i;
}

extern void
yajl_string_encode(const yajl_print_t print, void * ctx,
                   const unsigned char * str, size_t len,
                   int escape_solidus);

static inline void
yajl_mtev_dyn_buff_append(void *ctx, const char *str, size_t len) {
  mtev_dyn_buffer_t *buff = (mtev_dyn_buffer_t *)ctx;
  mtev_dyn_buffer_add(buff, (uint8_t *)str, len);
}
static inline int
add_to_json(int nelem, mtev_dyn_buffer_t *buff,
            const char *key, mtev_boolean str, const char *string) {
  mtev_dyn_buffer_add(buff, nelem ? (uint8_t *)",\"" : (uint8_t *)"{\"", 2);
  yajl_string_encode(yajl_mtev_dyn_buff_append, buff, (void *)key, strlen(key), 0);
  mtev_dyn_buffer_add(buff, (uint8_t *)"\":\"", str ? 3 : 2);
  if(str) yajl_string_encode(yajl_mtev_dyn_buff_append, buff, (void *)string, strlen(string), 0);
  else mtev_dyn_buffer_add(buff, (uint8_t *)string, strlen(string));
  if(str) mtev_dyn_buffer_add(buff, (uint8_t *)"\"", 1);
  return nelem+1;
}
static inline int
add_to_jsonf(int nelem, mtev_dyn_buffer_t *buff,
             const char *key, mtev_boolean str, const char *fmt, ...) {
  mtev_dyn_buffer_t scratch;
  mtev_dyn_buffer_init(&scratch);
  va_list args;
  va_start(args, fmt);
  mtev_dyn_buffer_add_vprintf(&scratch, fmt, args);
  va_end(args);
  int rv = add_to_json(nelem, buff, key, str, 
                       (const char *)mtev_dyn_buffer_data(&scratch));
  mtev_dyn_buffer_destroy(&scratch);
  return rv;
}
mtev_LogLine_fb_t
mtev_log_flatbuffer_from_buffer(void *buff, size_t buff_len) {
  mtev_LogLine_table_t ll = NULL;
  if(0 != mtev_LogLine_verify_as_root(buff, buff_len)) {
    return NULL;
  }
  ll = mtev_LogLine_as_root(buff);
  if(ll == NULL) {
    return NULL;
  }
  return (mtev_LogLine_fb_t)ll;
}
void
mtev_log_flatbuffer_to_json(mtev_LogLine_fb_t vll, mtev_dyn_buffer_t *tgt) {
  mtev_LogLine_table_t ll = (mtev_LogLine_table_t)vll;
  mtev_KVPair_vec_t kvs = mtev_LogLine_kv(ll);
  int nelem = 0;
  int nkvs = mtev_KVPair_vec_len(kvs);
  struct timeval whence;
  whence.tv_sec = mtev_LogLine_timestamp(ll) / 1000000;
  whence.tv_usec = mtev_LogLine_timestamp(ll) % 1000000;

  nelem = add_to_jsonf(nelem, tgt, "timestamp", mtev_true, "%lu.%06u", whence.tv_sec, whence.tv_usec);
  nelem = add_to_json(nelem, tgt, "facility", mtev_true, mtev_LogLine_facility(ll));
  nelem = add_to_jsonf(nelem, tgt, "threadid", mtev_false, "%zu", mtev_LogLine_threadid(ll));
  if(mtev_LogLine_threadname_is_present(ll)) {
    flatbuffers_string_t tname = mtev_LogLine_threadname(ll);
    if(flatbuffers_string_len(tname))
      nelem = add_to_json(nelem, tgt, "threadname", mtev_true, mtev_LogLine_threadname(ll));
    else
      nelem = add_to_json(nelem, tgt, "threadname", mtev_false, "\"unnamed\"");
  }
  nelem = add_to_json(nelem, tgt, "file", mtev_true, mtev_LogLine_file(ll));
  nelem = add_to_jsonf(nelem, tgt, "line", mtev_false, "%u", mtev_LogLine_line(ll));
  nelem = add_to_json(nelem, tgt, "message", mtev_true, mtev_LogLine_message(ll));
  for(int i=0; i<nkvs; i++) {
    mtev_KVPair_table_t kv = mtev_KVPair_vec_at(kvs, i);
    switch(mtev_KVPair_value_type(kv)) {
      case mtev_Value_StringValue:
        nelem = add_to_json(nelem, tgt, mtev_KVPair_key(kv), mtev_true,
                            mtev_StringValue_value(mtev_KVPair_value(kv)));
        break;
      case mtev_Value_LongValue:
        nelem = add_to_jsonf(nelem, tgt, mtev_KVPair_key(kv), mtev_false,
                             "%zd", mtev_LongValue_value(mtev_KVPair_value(kv)));
        break;
      case mtev_Value_ULongValue:
        nelem = add_to_jsonf(nelem, tgt, mtev_KVPair_key(kv), mtev_false,
                             "%zu", mtev_ULongValue_value(mtev_KVPair_value(kv)));
        break;
      case mtev_Value_DoubleValue:
        nelem = add_to_jsonf(nelem, tgt, mtev_KVPair_key(kv), mtev_false,
                             "%f", mtev_DoubleValue_value(mtev_KVPair_value(kv)));
        break;
      default:
        break;
    }
  }

  mtev_dyn_buffer_add(tgt, (uint8_t *)"}\n", 2);
}
static int
mtev_log_line(mtev_log_stream_t ls, mtev_log_stream_t bitor,
              const void *fbuffer, size_t flen) {
  int rv = 0;
  struct _mtev_log_stream_outlet_list *node;
  struct _mtev_log_stream bitor_onstack;
  memcpy(&bitor_onstack, ls, sizeof(bitor_onstack));
  if(bitor) {
    bitor_onstack.name = bitor->name;
    bitor_onstack.flags |= bitor->flags & MTEV_LOG_STREAM_FACILITY;
    bitor_onstack.flags |= bitor->flags & MTEV_LOG_STREAM_DEBUG;
    bitor_onstack.flags |= bitor->flags & MTEV_LOG_STREAM_TIMESTAMPS;
  }
  bitor = &bitor_onstack;


  if(ls->ops || mtev_log_line_hook_exists() ||
     mtev_log_flatbuffer_hook_exists() ||
     mtev_log_plain_hook_exists()) {
    mtev_LogLine_table_t ll = NULL;
    if(0 != mtev_LogLine_verify_as_root(fbuffer, flen)) {
      return 0;
    }
    ll = mtev_LogLine_as_root(fbuffer);
    if(ll == NULL) {
      return 0;
    }
  
    struct timeval whence;
    whence.tv_sec = mtev_LogLine_timestamp(ll) / 1000000;
    whence.tv_usec = mtev_LogLine_timestamp(ll) % 1000000;
    char tbuf[48], dbuf[64];
    int tbuflen = 0, dbuflen = 0;
    flatbuffers_string_t buffer = mtev_LogLine_message(ll);
    size_t len = flatbuffers_string_len(buffer);
  
    if(mtev_log_line_hook_invoke(ls, &whence, "", 0, "", 0, buffer, len) == MTEV_HOOK_ABORT) {
      return -1;
    }
    if(mtev_log_plain_hook_invoke(ls, &whence, buffer, len) == MTEV_HOOK_ABORT) {
      return -1;
    }
    if(mtev_log_flatbuffer_hook_invoke(ls, &whence, fbuffer, flen) == MTEV_HOOK_ABORT) {
      return -1;
    }
  
    if(ls->ops) {
      const char *this_line = buffer;
      size_t sofar = 0;
      size_t this_line_len = len;
      if(this_line && ls->format == MTEV_LOG_FORMAT_FLATBUFFER) {
        struct iovec iov[1];
        iov[0].iov_base = (void *)fbuffer;
        iov[0].iov_len = flen;
        rv += mtev_log_writev(ls, &whence, iov, 1);
        this_line = NULL;
      }
      if(this_line && ls->format == MTEV_LOG_FORMAT_JSON) {
        int nelem = 0;
        mtev_dyn_buffer_t encoded;
        mtev_dyn_buffer_init(&encoded);
        mtev_log_flatbuffer_to_json((mtev_LogLine_fb_t)ll, &encoded);
        struct iovec iov[1];
        iov[0].iov_base = (void *)mtev_dyn_buffer_data(&encoded);
        iov[0].iov_len = mtev_dyn_buffer_used(&encoded);
        rv += mtev_log_writev(ls, &whence, iov, 1);
        mtev_dyn_buffer_destroy(&encoded);
        this_line = NULL;
      }
      while(this_line && sofar < len) {
        int iovcnt = 0;
        struct iovec iov[7];
        const char *next_line = NULL;
  
        this_line_len = len - sofar;
        if(ls->flags & MTEV_LOG_STREAM_SPLIT) {
          next_line = memchr(this_line, '\n', len - sofar);
          if(next_line) {
            next_line++;
            this_line_len = next_line - this_line;
          }
        }
  
        if(IS_TIMESTAMPS_ON(bitor)) {
          struct tm _tm, *tm;
          char tempbuf[32];
          time_t s = (time_t)whence.tv_sec;
          tm = localtime_r(&s, &_tm);
          strftime(tempbuf, sizeof(tempbuf), "%Y-%m-%d %H:%M:%S", tm);
          snprintf(tbuf, sizeof(tbuf), "[%s.%06d] ", tempbuf, (int)whence.tv_usec);
          tbuflen = strlen(tbuf);
          iov[iovcnt].iov_base = (void *)tbuf;
          iov[iovcnt].iov_len = tbuflen;
          iovcnt++;
        }
        if(IS_FACILITY_ON(bitor)) {
          iov[iovcnt].iov_base = (void *)"[";
          iov[iovcnt].iov_len = 1;
          iovcnt++;
          iov[iovcnt].iov_base = (void *)bitor->name;
          iov[iovcnt].iov_len = strlen(bitor->name);
          iovcnt++;
          iov[iovcnt].iov_base = (void *)"] ";
          iov[iovcnt].iov_len = 2;
          iovcnt++;
        }
        if(IS_DEBUG_ON(bitor)) {
          const char *tname = mtev_LogLine_threadname_is_present(ll) ? mtev_LogLine_threadname(ll) : NULL;
          uint32_t tid = mtev_LogLine_threadid(ll);
          uint32_t line = mtev_LogLine_line(ll);
          const char *file = mtev_LogLine_file(ll);
          if(!tname || strlen(tname) == 0) tname = mtev_thread_getname();
          if(tname && strlen(tname))
            snprintf(dbuf, sizeof(dbuf), "[t@%u/%s,%s:%d] ", tid, tname, file, line);
          else {
            snprintf(dbuf, sizeof(dbuf), "[t@%u,%s:%d] ", tid, file, line);
          }
          dbuflen = strlen(dbuf);
          iov[iovcnt].iov_base = (void *)dbuf;
          iov[iovcnt].iov_len = dbuflen;
          iovcnt++;
        }
        iov[iovcnt].iov_base = (void *)this_line;
        iov[iovcnt].iov_len = this_line_len;
        sofar += this_line_len;
        iovcnt++;
        if(ls->flags & MTEV_LOG_STREAM_SPLIT) {
          if(this_line_len > 0 && this_line[this_line_len-1] != '\n') {
            iov[iovcnt].iov_base = (void *)"\n";
            iov[iovcnt].iov_len = 1;
            iovcnt++;
          }
        }
        rv += mtev_log_writev(ls, &whence, iov, iovcnt);
  
        this_line = next_line;
      }
    }
  }
  for(node = ls->outlets; node; node = node->next) {
    int srv = 0;
    debug_printf(" %s -> %s\n", ls->name, node->outlet->name);
    bitor->flags = ls->flags;
    if(IS_ENABLED_ON(node->outlet) && IS_ENABLED_BELOW(node->outlet)) {
      srv = mtev_log_line(node->outlet, bitor, fbuffer, flen);
    }
    if(srv) rv = srv;
  }
  return rv;
}

static int
mtev_log_fb(mtev_log_stream_t ls, mtev_log_stream_t bitor,
            uint8_t *fbbuf, size_t fblen) {
  return (int)fblen;
}

inline int
mtev_vlog(mtev_log_stream_t ls, const struct timeval *now,
          const char *file, int line,
          const char *format, va_list arg) {
  return mtev_ex_vlog(ls, now, file, line,
      (mtev_log_kv_t *[]){ &(mtev_log_kv_t){ NULL, 0, .value = { .v_string = NULL } } },
      format, arg);
}
int
mtev_ex_vlog(mtev_log_stream_t ls, const struct timeval *now,
             const char *file, int line,
             mtev_log_kv_t **kvs,
             const char *format, va_list arg) {
  int rv = 0, allocd = 0;
  MTEV_MAYBE_DECL(char, buffer, 4096);
  struct timeval __now;
#ifdef va_copy
  va_list copy;
#endif
  /* All hell could break loose under the covers here,
   * and we don't want to confuse the called by setting errno
   * to something they didn't explicitly ask for.
   * Save a copy and restore it before we return.
   */
  int old_errno = errno;
  Zipkin_Span *logspan = mtev_zipkin_active_span(NULL);
  if(!mtev_zipkin_span_logs_attached(logspan)) logspan = NULL;

#define ENSURE_NOW() do { \
  if(now == NULL) { \
    mtev_gettimeofday(&__now, NULL); \
    now = &__now; \
  } \
} while(0)

  if((IS_ENABLED_ON(ls) && IS_ENABLED_BELOW(ls)) || LIBMTEV_LOG_ENABLED() || logspan) {
    int len;
    flatcc_builder_t builder, *B = &builder;

    flatcc_builder_init(B);
    mtev_LogLine_start_as_root(B);
    ENSURE_NOW();
    mtev_LogLine_timestamp_add(B, (uint64_t)now->tv_sec * 1000000 + now->tv_usec);
    const char *tname = eventer_get_thread_name();
    mtev_LogLine_threadid_add(B, mtev_thread_id());
    if(tname) mtev_LogLine_threadname_create_str(B, tname);
    mtev_LogLine_file_create_str(B, file);
    mtev_LogLine_line_add(B, line);
    mtev_LogLine_facility_create_str(B, ls->name);
#ifdef va_copy
    va_copy(copy, arg);
    len = vsnprintf(buffer, MTEV_MAYBE_SIZE(buffer), format, copy);
    va_end(copy);
#else
    len = vsnprintf(buffer, MTEV_MAYBE_SIZE(buffer), format, arg);
#endif
    if(len >= (ssize_t)MTEV_MAYBE_SIZE(buffer) && _mtev_log_siglvl == 0) {
      allocd = MTEV_MAYBE_SIZE(buffer);
      while(len >= allocd) { /* guaranteed true the first time */
        MTEV_MAYBE_REALLOC(buffer, len+1);
        allocd = MTEV_MAYBE_SIZE(buffer);
#ifdef va_copy
        va_copy(copy, arg);
        len = vsnprintf(buffer, allocd, format, copy);
        va_end(copy);
#else
        len = vsnprintf(buffer, allocd, format, arg);
#endif
      }
    }
    else {
      /* This should only happen within a signal handler */
      if(len > (ssize_t)MTEV_MAYBE_SIZE(buffer)) len = MTEV_MAYBE_SIZE(buffer);
    }

    if(kvs && kvs[0]->key != NULL) {
      int kvi = 0;
      mtev_LogLine_kv_start(B);
      for(mtev_log_kv_t *kv = kvs[kvi]; (kv = kvs[kvi])->key != NULL; kvi++) {
        mtev_LogLine_kv_push_start(B);
        mtev_KVPair_key_create_str(B, kv->key);
        switch(kv->value_type) {
          case MTEV_LOG_KV_TYPE_STRING:
            mtev_KVPair_value_StringValue_start(B);
            mtev_StringValue_value_create_str(B, kv->value.v_string);
            mtev_KVPair_value_StringValue_end(B);
            break;
          case MTEV_LOG_KV_TYPE_INT64:
            mtev_KVPair_value_LongValue_start(B);
            mtev_LongValue_value_add(B, kv->value.v_int64);
            mtev_KVPair_value_LongValue_end(B);
            break;
          case MTEV_LOG_KV_TYPE_UINT64:
            mtev_KVPair_value_ULongValue_start(B);
            mtev_ULongValue_value_add(B, kv->value.v_uint64);
            mtev_KVPair_value_ULongValue_end(B);
            break;
          case MTEV_LOG_KV_TYPE_DOUBLE:
            mtev_KVPair_value_DoubleValue_start(B);
            mtev_DoubleValue_value_add(B, kv->value.v_double);
            mtev_KVPair_value_DoubleValue_end(B);
            break;
        }
        mtev_LogLine_kv_push_end(B);
      }
      mtev_LogLine_kv_end(B);
    }

    mtev_LogLine_message_create_str(B, buffer);
    mtev_LogLine_end_as_root(B);

    if(logspan) {
      char lsbuff[1024];
      snprintf(lsbuff, sizeof(lsbuff), "mtev_log %.*s",
               len, buffer);
      int64_t now_us = (int64_t)now->tv_sec * 1000000 + (int64_t)now->tv_usec;
      mtev_zipkin_span_annotate(logspan, &now_us, lsbuff, true);
    }

    /* Already logged above as a ganged dedup */
    LIBMTEV_LOG(ls->name, (char *)file, line, buffer);

    if(IS_ENABLED_ON(ls)) {
      uint8_t fb_buf[16384+16];
      uint8_t *tofree = NULL, *fb = fb_buf + ((16 - ((uintptr_t)fb_buf & 15)) % 16);
      size_t fb_len = sizeof(fb_buf) - (fb - fb_buf);
      if(NULL != flatcc_builder_copy_buffer(B, fb, fb_len)) {
        fb_len = flatcc_builder_get_buffer_size(B);
      } else {
        fb = tofree = flatcc_builder_finalize_aligned_buffer(B, &fb_len);
      }
      rv = mtev_log_line(ls, NULL, fb, fb_len);
      if(tofree) FLATCC_ALIGNED_FREE(tofree);
    }
    flatcc_builder_clear(B);

    MTEV_MAYBE_FREE(buffer);
    errno = old_errno;
    if(rv == len) return 0;
    return -1;
  }
  errno = old_errno;
  return 0;
}

int
mtev_ex_log(mtev_log_stream_t ls, const struct timeval *now,
            const char *file, int line, mtev_log_kv_t **ex, const char *format, ...) {
  int rv;
  va_list arg;
  va_start(arg, format);
  rv = mtev_ex_vlog(ls, now, file, line, ex, format, arg);
  va_end(arg);
  return rv;
}

int
mtev_log(mtev_log_stream_t ls, const struct timeval *now,
         const char *file, int line, const char *format, ...) {
  int rv;
  va_list arg;
  va_start(arg, format);
  rv = mtev_vlog(ls, now, file, line, format, arg);
  va_end(arg);
  return rv;
}

mtev_log_stream_t
mtev_log_speculate(int nlogs, int nbytes)
{
  mtev_log_stream_t speculation;
  speculation = calloc(1, sizeof(*speculation));
  speculation->ops = &membuf_logio_ops;
  speculation->type = strdup("memory");
  speculation->flags |= MTEV_LOG_STREAM_ENABLED;
  speculation->flags_below |= MTEV_LOG_STREAM_ENABLED;
  speculation->op_ctx = log_stream_membuf_init(nlogs, nbytes);
  return speculation;
}

static int
mtev_log_speculate_commit_cb(uint64_t idx, const struct timeval *tv,
                             const char *str, size_t str_bytes, void *v_ls)
{
  (void)idx;
  mtev_log_stream_t ls = v_ls;
  if((IS_ENABLED_ON(ls) && IS_ENABLED_BELOW(ls)) || LIBMTEV_LOG_ENABLED()) {
    mtevLT(ls, tv, "%.*s", (int)str_bytes, str);
    return 0;
  }
  return -1;
}

void
mtev_log_speculate_finish(mtev_log_stream_t ls, mtev_log_stream_t speculation)
{
  if (ls != MTEV_LOG_SPECULATE_ROLLBACK)
    mtev_log_memory_lines(speculation, 0, mtev_log_speculate_commit_cb, ls);
  log_stream_membuf_free(speculation->op_ctx);
  free(speculation->type);
  free(speculation);
}

int
mtev_log_reopen_type(const char *type) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int rv = 0;
  mtev_log_stream_t ls;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    ls = iter.value.ptr;
    if(ls->ops && ls->type && !strcmp(ls->type, type))
      if(ls->ops->reopenop(ls) < 0) rv = -1;
  }
  pthread_mutex_unlock(&resize_lock);
  return rv;
}

int
mtev_log_go_asynch(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int rv = 0;
  mtev_log_stream_t ls;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    ls = iter.value.ptr;
    if(SUPPORTS_ASYNC(ls)) {
      asynch_log_ctx *actx = ls->op_ctx;
      ck_pr_inc_32(&actx->gen);
      actx->is_asynch = 1;
      if(ls->ops->reopenop(ls) < 0) rv = -1;
    }
  }
  pthread_mutex_unlock(&resize_lock);
  return rv;
}

int
mtev_log_go_synch(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int rv = 0;
  mtev_log_stream_t ls;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    ls = iter.value.ptr;
    if(SUPPORTS_ASYNC(ls)) {
      asynch_log_ctx *actx = ls->op_ctx;
      ck_pr_inc_32(&actx->gen);
      actx->is_asynch = 0;
      if(ls->ops->reopenop(ls) < 0) rv = -1;
      asynch_logio_drain(actx);
    }
  }
  pthread_mutex_unlock(&resize_lock);
  return rv;
}

int
mtev_log_reopen_all(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int rv = 0;
  mtev_log_stream_t ls;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    ls = iter.value.ptr;
    if(ls->ops) if(ls->ops->reopenop(ls) < 0) rv = -1;
  }
  pthread_mutex_unlock(&resize_lock);
  return rv;
}

int
mtev_log_list(mtev_log_stream_t *loggers, int nsize) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int count = 0, total = 0, out_of_space_flag = 1;

  pthread_mutex_lock(&resize_lock);
  while(mtev_hash_adv(&mtev_loggers, &iter)) {
    if(count < nsize) loggers[count++] = (mtev_log_stream_t)iter.value.ptr;
    else out_of_space_flag = -1;
    total++;
  }
  pthread_mutex_unlock(&resize_lock);
  return total * out_of_space_flag;
}

static mtev_json_object *
mtev_log_stream_to_json_ex(mtev_log_stream_t ls, mtev_boolean terse) {
  mtev_json_object *doc;
  doc = MJ_OBJ();
  MJ_KV(doc, "name", MJ_STR(ls->name));
  if(!terse) {
    if(ls->type) MJ_KV(doc, "type", MJ_STR(ls->type));
    if(ls->path) MJ_KV(doc, "path", MJ_STR(ls->path));
    MJ_KV(doc, "enabled", MJ_BOOL(IS_ENABLED_ON(ls)));
    MJ_KV(doc, "enabled_below", MJ_BOOL(IS_ENABLED_BELOW(ls)));
    MJ_KV(doc, "debugging", MJ_BOOL(IS_DEBUG_ON(ls)));
    MJ_KV(doc, "timestamps", MJ_BOOL(IS_TIMESTAMPS_ON(ls)));
    MJ_KV(doc, "facility", MJ_BOOL(IS_FACILITY_ON(ls)));
    if(ls->config && mtev_hash_size(ls->config) > 0) {
      mtev_json_object *config;
      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      MJ_KV(doc, "config", config = MJ_OBJ());
      while(mtev_hash_adv(ls->config, &iter)) {
        MJ_KV(config, iter.key.str, MJ_STR(iter.value.str));
      }
    }
  }
  if(ls->outlets) {
    mtev_json_object *arr;
    struct _mtev_log_stream_outlet_list *node;
    MJ_KV(doc, "outlets", arr = MJ_ARR());
    for(node = ls->outlets; node; node = node->next) {
      MJ_ADD(arr, mtev_log_stream_to_json_ex(node->outlet, mtev_true));
    }
  }
  return doc;
}
mtev_json_object *
mtev_log_stream_to_json(mtev_log_stream_t ls) {
  return mtev_log_stream_to_json_ex(ls, mtev_false);
}

void
mtev_log_init_globals(void) {
  static int initialized = 0;
  if(!initialized) {
    initialized = 1;
    mtev_hash_init_locks(&mtev_loggers, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
    mtev_hash_init_locks(&mtev_logops, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  }
}

struct posix_op_ctx boot_stderr_posix_op_ctx = { .fd = 2 };

asynch_log_ctx boot_stderr_actx = {
  .name = "posix",
  .write = posix_logio_asynch_write,
  .userdata = &boot_stderr_posix_op_ctx,
  .is_asynch = 0
};

pthread_rwlock_t boot_stderr_ls_lock = PTHREAD_RWLOCK_INITIALIZER;
struct _mtev_log_stream boot_stderr_ls = {
  .flags = BOOT_STDERR_FLAGS,
  .name = "stderr",
  .ops = &posix_logio_ops,
  .op_ctx = &boot_stderr_actx,
  .deps_materialized = 1,
  .lock = &boot_stderr_ls_lock,
  .flags_below = BOOT_STDERR_FLAGS
};

pthread_rwlock_t boot_debug_ls_lock = PTHREAD_RWLOCK_INITIALIZER;
struct _mtev_log_stream boot_debug_ls = {
  .flags = BOOT_DEBUG_FLAGS,
  .name = "debug",
  .ops = &posix_logio_ops,
  .op_ctx = &boot_stderr_actx,
  .deps_materialized = 1,
  .lock = &boot_debug_ls_lock,
  .flags_below = BOOT_DEBUG_FLAGS
};

mtev_log_stream_t mtev_stderr = &boot_stderr_ls;
mtev_log_stream_t mtev_error = &boot_stderr_ls;
mtev_log_stream_t mtev_debug = &boot_debug_ls;
mtev_log_stream_t mtev_notice = &boot_stderr_ls;
