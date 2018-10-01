/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name Circonus, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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
#include "mtev_log.h"
#include "mtev_intern.h"
#include "mtev_rand.h"
#include "mtev_sort.h"
#include "mtev_hash.h"
#include "mtev_plock.h"
#include <strings.h>
#include <sys/mman.h>
#include <ck_hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/* Basic premise.
 *
 * the mtev_intern is design to allow multiple consumers to point at the same
 * const string in memory without subsequent allocations.  It's a reference counted
 * unique dictionary of blobs.  Sounds easy enough with a hash table, but we
 * also have the situation where we are pointing at more strings than comfortably
 * fit in memory and thus need a "different approach" than just strdup()ing the
 * string in question when it doesn't exit.
 *
 * We support multiple intern pools that allow for different parameters.
 *
 * ## Memory management
 *
 * A pool has extents that are slabs of mmap'd memory (or scratch files)
 * that are allocated on-demand as the intern dictionary grows.
 *
 * blobs have a maximum size of 2^23 - 1 or the pool's extent size, whichever
 * is smaller. Strings are stored null terminated, blobs are not.
 *
 * [ refcnt:32 ] [ poolid:8 ] [ NT:1 ] [ len:23 ] [data <size bytes>] [pad <align 4bytes> ]
 *
 * An exponentially tiered free fragment list is maintained [lsize = 2^(lvl+2)]
 *   Such that lvl zero: 4, lvl one: 8, etc.
 *
 * At each level of this list (freeslots) the fragments (free_nodes) have
 * "at least" lsize. This means that level zero has fragments that have at
 * least 4 bytes in them, but less than 8. Allocations are 4 byte aligned.
 * So, level one has fragments with at least 8 bytes, but less than 16. etc.
 *
 * When attempting an allocation we search for a rounded up power of two slab...
 * If searching for for 12 bytes, we search in level 2 (16 bytes or more).  If
 * no fragments are found there, we bump to level 3 and try again.  If we find
 * no fragments free, we allocatew a new extent.
 *
 * If a fragement is found, we use what we need of that fragment, reducing it's
 * size and potentially reassigning it to a new (appropriate to it's altered
 * size) freeslots level.
 *
 * Allocating an extent mmaps (either ANON or file based) and appends that
 * to our extents list. It then creates a single free fragment in the
 * appropriate level for the whole extent.
 *
 * When an allocation is released, it is convered into a free fragment and
 * inserted into the appropriate sized freeslots level.
 *
 * ## Tracking existence.
 *
 * A ck_hs hashset is maintained with all the allocated objects
 * (pointers to them).  When an intern'd thing is requested, we first look
 * in the ck_hs. If it exists, we increment the refcnt and return it.
 * If it does not exist, we allocate opportunistically and insert.  Upon
 * failed insert, we release our allocation and return the existing entry.
 *
 * Upon release, if the refcnt hits zero, we remove from the hashset and
 * release the allocation into the freeslots as a fragment.
 *
 * ## Compaction
 *
 * As things are allocated then released, the fragments list can become
 * quite a mess.  Compaction will "steal" all the fragments, sort them,
 * merge adjecent ones, and reinsert them into the freeslots tiers. It
 * is highly lock-friendly and can be performed periodoically in a
 * maintenance thread if there are pools with churn.  There is no
 * movement of allocations, so some fragmentation patterns can be
 * impossible to fix.
 */


const mtev_intern_t mtev_intern_null;

/* While we don't want consumers to allocate things as small as 2 bytes,
 * b/c we do best-fit allocations, we can have left over fragments as small
 * as 4 bytes, so we need to be able to represent them.
 */
#define SMALLEST_POWER 2
#define SMALLEST_ALLOC (1 << SMALLEST_POWER)
/* Our free nodes (managing free fragments) are allocated in chunks */
#define DEFAULT_FREE_NODES_BATCH 100000
/* fetches of existing intern require reformatting of the key and if that
 * key is "too large" it will require an malloc.
 */
#define MAX_WITHOUT_MALLOC 32678

/* From bithacks - DeBruijn multiplication for branchless log2 */
static const int MultiplyDeBruijnBitPosition[32] = 
{
  0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
  8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
};

static inline int
fast_log2_rd(uint32_t v) {
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return MultiplyDeBruijnBitPosition[(uint32_t)(v * 0x07C4ACDDU) >> 27];
}
static inline int
fast_log2_ru(uint32_t v) {
  v*=2;
  v--;
  return fast_log2_rd(v);
}


typedef struct mtev_intern_internal {
  uint32_t  refcnt;
  unsigned  poolid:8;
  unsigned  nt:1;
  unsigned  len:23; /* len, internally, includes the null terminator on strings */
  uint8_t   v[0];
} mtev_intern_internal_t;

struct mtev_intern_pool_extent {
  size_t    size;
  void     *base;
  uint32_t  id;
  int       fd;
  int       internal;
  struct mtev_intern_pool_extent *next;
};

struct mtev_intern_free_node {
  void  *base;
  size_t size;
  struct mtev_intern_free_node *next;
};

struct mtev_intern_free_list {
  struct mtev_intern_free_node *head;
  size_t lsize; /* All framgents in the list have *at least* lsize bytes */
  uint32_t cnt;
  mtev_plock_t lock;
};

struct mtev_intern_pool {
  mtev_plock_t plock;
  /* Finding things */
  struct ck_hs  map;
  /* big ol' slabs of memory */
  uint32_t extent_id;
  struct mtev_intern_pool_extent *extents;

  uint8_t poolid;
  size_t extent_size;

  /* These two are used for mmap'ing files */
  char *backing_directory;

  /* freelists of fragments */
  int nfreeslots;
  struct mtev_intern_free_list *freeslots;
  struct mtev_intern_free_node *staged_free_nodes;
  uint32_t staged_free_nodes_count;
  uint64_t staged_free_nodes_size;

  /* This is a freelist of nodes to be reused */
  ck_spinlock_t mifns_lock;
  struct mtev_intern_free_node *mifns;

  /* some stats */
  int last_fragment_compact;
  uint32_t item_count;
};

static inline void more_free_nodes(mtev_intern_pool_t *);
static inline struct mtev_intern_free_node *get_free_node(mtev_intern_pool_t *);

static inline struct mtev_intern_free_node *
get_free_node(mtev_intern_pool_t *pool) {
  struct mtev_intern_free_node *node;
  /* This attempts to pull the head node off the mifns freelist.
   * if it is null, it will force a new slab of free nodes.
   */
  do {
    while(NULL == (node = ck_pr_load_ptr(&pool->mifns))) {
      more_free_nodes(pool);
    }
  } while(!ck_pr_cas_ptr(&pool->mifns, node, node->next));
  /* Here we have our very own node. */
  return node;
}
static inline void
return_free_node(mtev_intern_pool_t *pool,
                 struct mtev_intern_free_node *node) {
  /* Return an individual free node into the mifns freelist */
  do {
    node->next = ck_pr_load_ptr(&pool->mifns);
  } while(!ck_pr_cas_ptr(&pool->mifns, node->next, node));
}

static inline void
replace_free_node(mtev_intern_pool_t *pool,
                 struct mtev_intern_free_node *node) {
  int idx = fast_log2_rd(node->size) - SMALLEST_POWER;
  /* If we have multiple extents that are seamlessly aligned,
   * we could have a merged across boundaries and created a bigger
   * node than we have segments... cap it.
   */
  if(idx >= pool->nfreeslots) idx = pool->nfreeslots - 1;

  mtev_plock_take_s(&pool->freeslots[idx].lock);
  node->next = pool->freeslots[idx].head;
  pool->freeslots[idx].head = node;
  ck_pr_inc_32(&pool->freeslots[idx].cnt);
  mtev_plock_drop_s(&pool->freeslots[idx].lock);
}

static inline void
stage_replace_free_node(mtev_intern_pool_t *pool,
                        struct mtev_intern_free_node *node) {
  /* This stage area revents ABA issues where
   * A             | B                  | C
   * --------------+--------------------+----------------------
   *               | release P (dec->0) |
   * P = ck_hs_get |                    |
   *               | ck_hs_remove P     |
   *               | release P          |
   *               |                    | P = allocate (refcnt@1)
   * refcnt (1->2) |                    |
   */
  node->next = ck_pr_load_ptr(&pool->staged_free_nodes);
  while(!ck_pr_cas_ptr(&pool->staged_free_nodes, node->next, node)) {
    ck_pr_stall();
    node->next = ck_pr_load_ptr(&pool->staged_free_nodes);
  }
  ck_pr_inc_32(&pool->staged_free_nodes_count);
  ck_pr_add_64(&pool->staged_free_nodes_size, node->size);
}

static inline size_t
unstage_replace_free_nodes_with_w(mtev_intern_pool_t *pool) {
  /* Here we need a writelock to prevent returning something before 
   * callers complete their read (and refcnt'ing)
   */
  size_t replaced = 0;
  struct mtev_intern_free_node *node;
  while(NULL != (node = ck_pr_load_ptr(&pool->staged_free_nodes))) {
    if(ck_pr_cas_ptr(&pool->staged_free_nodes, node, node->next)) {
      ck_pr_dec_32(&pool->staged_free_nodes_count);
      ck_pr_sub_64(&pool->staged_free_nodes_size, node->size);
      replaced += node->size;
      replace_free_node(pool, node);
    }
  }
  return replaced;
}
/* steal some data.. if it changes the freelist this node should be in,
 * node will be set and the caller must reinsert
 */
static inline void *
borrow_free_node(mtev_intern_pool_t *pool,
                 struct mtev_intern_free_list *l, size_t len,
                 struct mtev_intern_free_node **node) {
  size_t oldsize;
  struct mtev_intern_free_node *n;

  mtev_plock_take_r(&l->lock);
  n = l->head;
  if(!n) {
     mtev_plock_drop_r(&l->lock);
    return NULL;
  }
  assert(len > 8);        // header
  assert(len <= n->size); // not too big
  assert((len & 3) == 0); // aligned

retry:

  /* If we can manage to borrow the requested len without needing
   * to move this node into another freeslot, we can just "borrow"
   * the bytes from be done. */
  while((oldsize = ck_pr_load_64(&n->size)) - len >= l->lsize) {
    if(ck_pr_cas_64(&n->size, oldsize, oldsize - len) == true) {
      mtev_plock_drop_r(&l->lock);
      return n->base + oldsize - len;
    }
    else ck_pr_stall();
  }
  /* stealing this much space would drop this node into a new freeslot
   * which means we need to remove head an need an s lock */
  if(!mtev_plock_try_rtos(&l->lock)) {
    mtev_plock_drop_r(&l->lock);
    mtev_plock_take_s(&l->lock);
  }
  /* we reacquire head, because someone might have done stuff between
   * our drop_r and take_s */
  n = l->head;
  /* so much so, that we could have no list at all anymore */
  if(!n) {
    mtev_plock_drop_s(&l->lock);
    return NULL;
  }
  /* or be back in the situation that our borrowing doesn't require
   * moving this node, in which case we drop back into 'R' and retry. */
  if(ck_pr_load_64(&n->size) - len >= l->lsize) {
    mtev_plock_stor(&l->lock);
    goto retry;
  }
  /* but now we have the real deal... a node that will require reinsertion
   * at another level once we've taken out part... take a 'W' and steal head */
  mtev_plock_stow(&l->lock);
  l->head = l->head->next;
  mtev_plock_drop_w(&l->lock);
  ck_pr_dec_32(&l->cnt);
  /* n is now exclusively ours */
  oldsize = n->size;
  n->size -= len;
  void *rv = n->base + oldsize - len;
  if(n->size == 0) {
    /* If there is nothing left, we can give this fragment back */
    return_free_node(pool, n);
  } else {
    /* if there's stuff left, the caller is responsible for reinserting. */
    *node = n;
  }
  return rv;
}

static inline void *
pool_extend(mtev_intern_pool_t *pool, size_t size) {
  int flags = 0;

  /* Pool_extend is used for data extends and other internal slab allocations.
   * Create a new extent, with the specified size (an internal extent)
   * or the default extent_size for a data extent. */
  struct mtev_intern_pool_extent *newe = calloc(1, sizeof(*newe));
  if(size == 0) size = pool->extent_size;
  else newe->internal = 1;
  newe->id = ck_pr_faa_32(&pool->extent_id, 1);

  /* If we are using backing files, do all the work to safely open and size
   * the backing file. */
  if(pool->backing_directory) {
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s/%08x", pool->backing_directory, newe->id);
    newe->fd = open(filename, O_CREAT|O_RDWR, 0600);
    assert(newe->fd >= 0);
    int rv;
    while(0 != (rv = ftruncate(newe->fd, size)) && errno == EINTR);
    if(rv != 0) {
      /* This can fail on ZFS */
      while(0 != (rv = ftruncate(newe->fd, 0)) && errno == EINTR);
      if(rv != 0) {
        close(newe->fd);
        newe->fd = open(filename, O_CREAT|O_RDWR|O_TRUNC, 0600);
        assert(newe->fd > 0);
      }
    }
    /* write a nul at the last byte.. if we fail, we'll pick i tup on the fstat check */
    (void)lseek(newe->fd, SEEK_SET, size-1);
    rv = write(newe->fd, "", 1);
    assert(rv == 1);
    struct stat sb;
    while(0 != (rv = fstat(newe->fd, &sb)) && errno == EINTR);
    assert(rv == 0 && sb.st_size == size);
    flags = MAP_SHARED;
#ifdef MAP_NONBLOCK
    flags |= MAP_NONBLOCK;
#endif
#ifdef MAP_NORESERVE
    flags |= MAP_NORESERVE;
#endif
  }
  else{
    newe->fd = -1;
    flags = MAP_PRIVATE|MAP_ANON;
  }
  /* Map it, set the size, and prepend it to our extents list */
  newe->base = mmap(NULL, size, PROT_READ|PROT_WRITE, flags, newe->fd, 0);
  newe->size = size;
  assert(newe->base != MAP_FAILED);
  /* It's possible we don't have an 'S'/'W' lock here, so atomically prepend */
  do {
    newe->next = ck_pr_load_ptr(&pool->extents);
  } while(!ck_pr_cas_ptr(&pool->extents, newe->next, newe));
  return newe->base;
}

static inline void
more_free_nodes(mtev_intern_pool_t *pool) {
  size_t cnt = DEFAULT_FREE_NODES_BATCH;
  /* Needing new slabs of free nodes is uncommon b/c the slabs are large.
   * We can simpley spinlock around the whole thing. */
  ck_spinlock_lock(&pool->mifns_lock);
  /* Maybe someone beat us to it... check for NULL first */
  if(pool->mifns == NULL) {
    /* Allocate a slab that can hold cnt many */
    void *base = pool_extend(pool, cnt * sizeof(struct mtev_intern_free_node));
    struct mtev_intern_free_node *nodes = base;
    nodes[cnt-1].next = NULL;
    /* Zip through them and link them all together as a link list. */
    for(int i=0; i<cnt-1; i++) {
      nodes[i].next = &nodes[i+1];
    }
    /* Atomically prepend this linked list into mifns.
     * We're the only one adding a new slab, but there can be others
     * adding and removing individual elements concurrently. */
    do {
      nodes[cnt-1].next = ck_pr_load_ptr(&pool->mifns);
    } while(!ck_pr_cas_ptr(&pool->mifns, nodes[cnt-1].next, nodes));
  }
  ck_spinlock_unlock(&pool->mifns_lock);
}

static mtev_intern_pool_attr_t default_attrs = {
  .extent_size = 1 << 20,
  .estimated_item_count = 1 << 19
};

static uint8_t poolcnt = 0;
static mtev_intern_pool_t *all_pools[256];

/* We want a default pool so that the simple forms of the API
 * have something to act on. poolid 0 will become the default
 * pool.
 */
__attribute__((constructor))
void mtev_intern_ctor(void) {
  (void)mtev_intern_pool_new(NULL);
}

static unsigned long
mi_hash(const void *key, unsigned long seed) {
  const mtev_intern_internal_t *s = key;
  return mtev_hash__hash((const char *)s->v, s->len, seed);
}
static bool
mi_compare(const void *a, const void *b) {
  const mtev_intern_internal_t *sa = a;
  const mtev_intern_internal_t *sb = b;
  if(sa->len != sb->len) return false;
  return (0 == memcmp(sa->v, sb->v, sa->len));
}
static void *
gen_malloc(size_t r) {
  return malloc(r);
}

static void
gen_free(void *p, size_t b, bool r) {
  (void)b;
  (void)r;
  free(p);
  return;
}
static struct ck_malloc mi_alloc = {
  .malloc = gen_malloc,
  .free = gen_free
};


mtev_intern_pool_t *
mtev_intern_pool_new(mtev_intern_pool_attr_t *attr) {
  uint8_t oldcnt;
  /* Get the next pool ID up to 255 as out pool id is 8 bits */
  while(1) {
    oldcnt = ck_pr_load_8(&poolcnt);
    if(oldcnt == 255) return NULL;
    if(ck_pr_cas_8(&poolcnt, oldcnt, oldcnt+1)) break;
  }
  if(!attr) attr = &default_attrs;
  mtev_intern_pool_t *pool = calloc(1, sizeof(*pool));
  mtev_plock_init(&pool->plock, MTEV_PLOCK_HEAVY);
  pool->poolid = oldcnt;
  pool->extent_size = attr->extent_size;
  if(attr->backing_directory) {
    pool->backing_directory = strdup(attr->backing_directory);
  }
  /* We want to represent cleanly up to the extent size in out
   * power-of-two freeslots levels. */
  pool->nfreeslots = fast_log2_ru(pool->extent_size) - SMALLEST_POWER + 1;
  pool->freeslots = calloc(pool->nfreeslots, sizeof(*pool->freeslots));
  for(int i = 0; i < pool->nfreeslots; i++) {
    mtev_plock_init(&pool->plock, MTEV_PLOCK_ATOMIC);
  }
  /* Build out our power-of-two tiers */
  pool->freeslots[0].lsize = SMALLEST_ALLOC;
  for(int i = 1; i < pool->nfreeslots; i++) {
    pool->freeslots[i].lsize = pool->freeslots[i-1].lsize << 1;
  }
  mtevAssert(ck_hs_init(&pool->map, CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                        mi_hash, mi_compare, &mi_alloc,
                        attr->estimated_item_count * 2, mtev_rand()));
  all_pools[oldcnt] = pool;
  return pool;
}

/* This function is called without any locks on pool->plock */
static inline
mtev_intern_internal_t *mtev_intern_pool_find(mtev_intern_pool_t *pool, size_t len) {
  if(len > pool->extent_size || len > (1 << 23)) return NULL;
  /* log2 rounded up to start at a level that we know will
   * be large enough to hold the requested allocation. */
  int tgt = fast_log2_ru(len) - SMALLEST_POWER;
  struct mtev_intern_free_list *tgtlist = NULL;
  int attempt = 0;
  while(1) {
    attempt++;
    /* Iterate up the levels looking for a suitable allocation */
    for(int i=tgt; i<pool->nfreeslots; i++) {
      if(pool->freeslots[i].head) {
        tgtlist = &pool->freeslots[i];
        struct mtev_intern_free_node *node = NULL;
        void *rv = borrow_free_node(pool, tgtlist, len, &node);
        if(node) {
          /* we must return this node to the freeslots */
          replace_free_node(pool, node);
        }
        if(rv) return rv;
      }
    }
    /* The first time we can't find an allocation,
     * we should attempt to unstage free nodes and if
     * that is successful, try again.
     */
    if(attempt == 1) {
      mtev_plock_take_w(&pool->plock);
      size_t replaced = unstage_replace_free_nodes_with_w(pool);
      mtev_plock_drop_w(&pool->plock);
      if(replaced) continue;
    }
    /* If we're here, there was no free space!
     * Two thread could be here at the same time, so let's use the extent_id
     * as a epoch as it will be incremented in pool_extend.  This allows us
     * to acquire the 'S' lock and then see if someone already did all this
     * work such that we can not do it twice. */
    uint32_t lastextentid = ck_pr_load_32(&pool->extent_id);
    mtev_plock_take_s(&pool->plock);
    /* skip this work if someone did it while we were waiting */
    if(ck_pr_load_32(&pool->extent_id) == lastextentid) {
      void *base = pool_extend(pool, 0);
      struct mtev_intern_free_node *node = get_free_node(pool);
      /* Create a free fragment the size of the allocation and insert it. */
      node->base = base;
      node->size = pool->extent_size;
      replace_free_node(pool, node);
    }
    mtev_plock_drop_s(&pool->plock);
  }
}

static inline void
mtev_intern_internal_release(mtev_intern_pool_t *pool, mtev_intern_internal_t *ii, mtev_boolean inhash) {
  assert(ii->poolid == pool->poolid);
  bool zero;
  ck_pr_dec_32_zero(&ii->refcnt, &zero);
  if(zero) {
    /* free back to pool */
    if(!inhash) {
      /* If this isn't in the hash structure, we can just return it to the freeslot
       * without locks and hashing work.  This happens when we lost an optimistic
       * insert.
       */
      struct mtev_intern_free_node *node = get_free_node(pool);
      node->base = ii;
      node->size = 8 + ((ii->len + 3) & ~3);
      replace_free_node(pool, node);
      return;
    }
    unsigned long hash = CK_HS_HASH(&pool->map, mi_hash, ii);

    /* ck_hs_remove is read-concurrent safe */
    mtev_plock_take_s(&pool->plock);
    assert(ck_pr_load_32(&ii->refcnt) == 0);
    assert(ck_hs_remove(&pool->map, hash, ii));
    mtev_plock_drop_s(&pool->plock);

    ck_pr_dec_32(&pool->item_count);

    /* Release the free fragment back for *staged* reuse..
     * see comments in stage_replace_free_node */
    struct mtev_intern_free_node *node = get_free_node(pool);
    node->base = ii;
    node->size = 8 + ((ii->len + 3) & ~3);
    stage_replace_free_node(pool, node);
  }
}
mtev_intern_t
mtev_intern_pool_ex(mtev_intern_pool_t *pool, const void *buff, size_t len, int nt) {
  /* nt (null terminator) is either 0 or 1 ... coerce it */
  nt = !!nt;

  if(len == 0) len = strlen(buff);
  len += nt;
  uint8_t *ibuff[MAX_WITHOUT_MALLOC];
  mtev_intern_internal_t *ii = NULL;
  mtev_intern_internal_t *lookfor = (mtev_intern_internal_t *)ibuff;
  mtev_intern_t rv;
  /* We don't every expect to have more than one item on the trashpile.
   * so we make the first node on stack, then alloc for subsequent ones
   * in the very very rare case we every produce multiple trash items
   * due to more than one failed put, get, release release cycle.
   */
  struct miit_trash_stack {
    struct miit_trash_stack *next;
    mtev_intern_internal_t *item;
  } trashpile = { .next = NULL, .item = NULL }, *trash = NULL;

  /* This sucks, but if the key is "really big" we'll need to alloc to
   * construct our key. */
  if(len + sizeof(mtev_intern_internal_t) > MAX_WITHOUT_MALLOC) {
    lookfor = malloc(len + sizeof(mtev_intern_internal_t));
  }

  /* construct our key to look for an existing copy */
  lookfor->poolid = pool->poolid;
  lookfor->refcnt = 0;
  lookfor->nt = nt;
  lookfor->len = len;
  memcpy(lookfor->v, buff, len);
  unsigned long hash = CK_HS_HASH(&pool->map, mi_hash, lookfor);

  mtev_plock_take_r(&pool->plock);

 retry_fetch:
  /* Look for it */
  ii = ck_hs_get(&pool->map, hash, lookfor);
  if(ii) {
    /* Refcnt it, but consider that we cannot go from 0->1.
     * If it had a refcnt of zero, it was being removed and
     * we've got a copy we shouldn't have... we're racing hard. */
    uint32_t prev;
    while(0 != (prev = ck_pr_load_32(&ii->refcnt))) {
      if(ck_pr_cas_32(&ii->refcnt, prev, prev+1)) break;
    }
    /* prev == 0, then it is being freed */
    if(prev == 0) goto retry_fetch;
    mtev_plock_drop_r(&pool->plock);
  } else {
    mtev_plock_drop_r(&pool->plock);
    /* align len on a 4 byte boundary and add the 8 byte header */
    size_t alen = ((len + 3) & ~3) + 8;

    /* Get us a suitable new allocation in our pool */
    ii = mtev_intern_pool_find(pool, alen);
    if(!ii) {
      if((void *)ibuff != (void *)lookfor) free(lookfor);
      assert(ii); /* We don't handle failed memory allocations */
      return mtev_intern_null;
    }
    /* build out our new intern object */
    ii->poolid = pool->poolid;
    ii->refcnt = 1;
    ii->len = len;
    ii->nt = nt;
    memcpy(ii->v, buff, len);

    mtev_plock_take_w(&pool->plock);
    /* Attempt to store this in our mapping */
    if(ck_hs_put(&pool->map, hash, ii) == false) {
      mtev_plock_wtos(&pool->plock);
      /* The put failed, so we need to accumulate the ii we created
       * in our trashpile to give it back. We don't give it back here
       * because we aren't in the right lockstate, we don't want to
       * do that with an S or W lock held.
       */
      if(trash == NULL) {
        trash = &trashpile;
      } else {
        trash->next = calloc(1, sizeof(*trash));
        trash = trash->next;
      }
      trash->item = ii;

      assert(lookfor->len == ii->len);
      /* Get the item that is presumably there causing our put to fail. */
      ii = ck_hs_get(&pool->map, hash, lookfor);
      assert(ii != trash->item);
      /* It must be here because we've been in S/W since the failed put. */
      assert(ii);
      /* However, someone else could have released it and refcnt -> 0 and
       * just not completed the ck_hs_remove yet.
       * Same as above, refcnt, but not from zero */
      uint32_t prev;
      while(0 != (prev = ck_pr_load_32(&ii->refcnt))) {
        if(ck_pr_cas_32(&ii->refcnt, prev, prev+1)) break;
      }
      if(prev == 0) {
        mtev_plock_stor(&pool->plock);
        goto retry_fetch;
      }
      mtev_plock_drop_s(&pool->plock);
    }
    else {
      mtev_plock_drop_w(&pool->plock);
      ck_pr_inc_32(&pool->item_count);
    }
  }

  /* This is the intern the caller is looking for */
  rv.opaque1 = (uintptr_t)&ii->v;


  /* cleanup */
  if((void *)ibuff != (void *)lookfor) free(lookfor);
  /* Free any items on our trashpile */
  if(trashpile.item) mtev_intern_internal_release(pool, trashpile.item, mtev_false);
  while(NULL != (trash = trashpile.next)) {
    if(trash->item) mtev_intern_internal_release(pool, trash->item, mtev_false);
    trashpile.next = trash->next;
    free(trash);
  }
  return rv;
}

inline mtev_intern_t
mtev_intern_pool(mtev_intern_pool_t *pool, const void *buff, size_t len) {
  assert(len);
  return mtev_intern_pool_ex(pool, buff, len, 0);
}

inline mtev_intern_t
mtev_intern_pool_str(mtev_intern_pool_t *pool, const char *buff, size_t len) {
  return mtev_intern_pool_ex(pool, buff, len, 1);
}

mtev_intern_t
mtev_intern(const void *buff, size_t len) {
  assert(len);
  return mtev_intern_pool(all_pools[0], buff, len);
}

mtev_intern_t
mtev_intern_str(const char *buff, size_t len) {
  return mtev_intern_pool_str(all_pools[0], buff, len);
}

mtev_intern_t
mtev_intern_copy(const mtev_intern_t i) {
  mtev_intern_internal_t *ii = (mtev_intern_internal_t *)(i.opaque1 - offsetof(mtev_intern_internal_t, v));
  ck_pr_inc_32(&ii->refcnt);
  return i;
}

inline void
mtev_intern_release_pool(mtev_intern_pool_t *pool, mtev_intern_t i) {
  mtev_intern_internal_t *ii = (mtev_intern_internal_t *)(i.opaque1 - offsetof(mtev_intern_internal_t, v));
  mtev_intern_internal_release(pool, ii, mtev_true);
}

void
mtev_intern_release(mtev_intern_t i) {
  mtev_intern_release_pool(all_pools[0], i);
}

uint32_t
mtev_intern_get_refcnt(mtev_intern_t i) {
  mtev_intern_internal_t *ii = (mtev_intern_internal_t *)(i.opaque1 - offsetof(mtev_intern_internal_t, v));
  return ck_pr_load_32(&ii->refcnt);
}

const char *
mtev_intern_get_str(mtev_intern_t i, size_t *len) {
  if(len) {
    /* only do any unwrapping of the input if we need to fill out the len */
    if(i.opaque1 == 0) {
      *len = 0;
      return NULL;
    }
    mtev_intern_internal_t *ii = (mtev_intern_internal_t *)(i.opaque1 - offsetof(mtev_intern_internal_t, v));
    *len = ii->len - ii->nt;
  }
  return (const char *)i.opaque1;
}

uint32_t
mtev_intern_pool_item_count(mtev_intern_pool_t *pool) {
  if(!pool) pool = all_pools[0];
  return ck_pr_load_32(&pool->item_count);;
}


 int compare_free_node(void* left, void *right) {
   struct mtev_intern_free_node *l = left;
   struct mtev_intern_free_node *r = right;
   if(l->base < r->base) return -1;
   if(r->base > l->base) return 1;
   assert(r->base != l->base);
   return 0;
}
void *next_free_node(void *x) {
  struct mtev_intern_free_node *y = x;
  return y->next;
}
void set_next_free_node(void *current, void *value) {
  struct mtev_intern_free_node *y = current;
  y->next = value;
}

static int
compact_freelist(mtev_intern_pool_t *pool) {
  struct mtev_intern_free_node dummy, *surrogate = &dummy, *last = surrogate;
  int cnt = 0;
  /* Take the list */
  for(int i=0; i<pool->nfreeslots; i++) {
    struct mtev_intern_free_list *l = &pool->freeslots[i];
    mtev_plock_take_w(&l->lock);
    last->next = l->head;
    l->head = NULL;
    l->cnt = 0;
    mtev_plock_drop_w(&l->lock);
    while(last->next) last = last->next;
  }

  /* Steal the stages free nodes... see the barrier below regarding
   * why this is safe. */
  while(NULL != (last->next = ck_pr_load_ptr(&pool->staged_free_nodes))) {
    if(ck_pr_cas_ptr(&pool->staged_free_nodes, last->next, NULL)) break;
    ck_pr_stall();
  }
  /* zip through what we stole to count, so we can correct our accounting */
  uint32_t staged = 0;
  uint64_t staged_size = 0;
  for(last = last->next; last; last = last->next) {
    staged++;
    staged_size += last->size;
  }
  ck_pr_sub_32(&pool->staged_free_nodes_count, staged);
  ck_pr_sub_64(&pool->staged_free_nodes_size, staged_size);

  /* Perhaps we actually have no work to do at all? */
  if(surrogate->next == NULL) return 0;

  /* Sort it */
  mtev_merge_sort((void **)&surrogate->next, next_free_node, set_next_free_node, compare_free_node);

  /* iterate, collapse, and splice them out */
  for(struct mtev_intern_free_node *node = surrogate->next; node && node->next; ) {
    if(node->base + node->size == node->next->base) {
      /* collapse */
      struct mtev_intern_free_node *tofree = node->next;
      node->size += tofree->size;
      node->next = tofree->next;
      return_free_node(pool, tofree);
      cnt++;
    } else {
      node = node->next;
    }
  }
  /* We need a barrier here so that reads until now can't be
   * reads when we do and re-insert the free nodes.  We could
   * accidentally include a staged freenode that is referenced
   * in an in-flight read. */
  mtev_plock_take_w(&pool->plock);
  mtev_plock_drop_w(&pool->plock);

  /* Replace them all back into the freeslots */
  struct mtev_intern_free_node *toinsert;
  while(NULL != (toinsert = surrogate->next)) {
    surrogate->next = toinsert->next;
    toinsert->next = NULL;
    replace_free_node(pool, toinsert);
  }

  return cnt;
}

int
mtev_intern_pool_compact(mtev_intern_pool_t *pool, mtev_boolean force) {
  int cnt = 0;
  if(!pool) pool = all_pools[0];
  int current_fragments = 0;
  for(int i=0; i<pool->nfreeslots; i++) {
    current_fragments += pool->freeslots[i].cnt;
  }
  current_fragments += pool->staged_free_nodes_count;
  /* increase of 1.5 */
  if(force || current_fragments > pool->last_fragment_compact + (pool->last_fragment_compact >> 1)) {
    cnt = compact_freelist(pool);
    pool->last_fragment_compact = current_fragments - cnt;
  }
  return cnt;
}
void
mtev_intern_pool_stats(mtev_intern_pool_t *pool, mtev_intern_pool_stats_t *stats) {
  if(!pool) pool = all_pools[0];
  mtev_plock_take_r(&pool->plock);
  memset(stats, 0, sizeof(*stats));
  stats->item_count = ck_pr_load_32(&pool->item_count);
  for(struct mtev_intern_pool_extent *node = pool->extents; node; node = node->next) {
    if(node->internal) {
      stats->internal_memory += node->size;
    } else {
      stats->allocated += node->size;
      stats->extent_count++;
    }
  }
  stats->staged_count = ck_pr_load_32(&pool->staged_free_nodes_count);
  stats->staged_size = ck_pr_load_64(&pool->staged_free_nodes_size);
  mtev_plock_drop_r(&pool->plock);
  stats->fragments_total = stats->staged_count;
  stats->available_total = stats->staged_size;
  for(int i=0; i<32; i++) {
    if(i < pool->nfreeslots && pool->freeslots[i].head) {
      mtev_plock_take_r(&pool->freeslots[i].lock);
      for(struct mtev_intern_free_node *node = pool->freeslots[i].head; node; node = node->next) {
        stats->available[i] += node->size;
      }
      stats->fragments[i] = pool->freeslots[i].cnt;
      mtev_plock_drop_r(&pool->freeslots[i].lock);
      stats->available_total += stats->available[i];
      stats->fragments_total += stats->fragments[i];
    }
  }
}
