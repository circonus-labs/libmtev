/*
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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

#include <sys/mdb_modapi.h>
#include <ck_hs.h>
#include "utils/mtev_skiplist.h"
#include "utils/mtev_hash.h"

struct _iskiplist {
  mtev_skiplist_comparator_t compare;
  mtev_skiplist_comparator_t comparek;
  int height;
  int preheight;
  int size;
  struct _mtev_skiplist_node *top;
  struct _mtev_skiplist_node *bottom;
  struct _iskiplist *index;
};

struct _mtev_skiplist_node {
  void *data;
  struct _mtev_skiplist_node *next;
  struct _mtev_skiplist_node *prev;
  struct _mtev_skiplist_node *down;
  struct _mtev_skiplist_node *up;
  struct _mtev_skiplist_node *previndex;
  struct _mtev_skiplist_node *nextindex;
  mtev_skiplist *sl;
};

static int mtev_skiplist_walk_init(mdb_walk_state_t *s) {
  mtev_skiplist l;
  mtev_skiplist_node n;
  if(mdb_vread(&l, sizeof(l), s->walk_addr) == -1) return WALK_ERR;
  if(l.bottom == NULL) return WALK_DONE;
  if(mdb_vread(&n, sizeof(n), (uintptr_t)l.bottom) == -1) return WALK_ERR;
  s->walk_addr = (uintptr_t)n.data;
  s->walk_data = n.next;
  return WALK_NEXT;
}
static int mtev_skiplist_walk_step(mdb_walk_state_t *s) {
  mtev_skiplist_node n;
  void *dummy = NULL;
  if(s->walk_data == NULL) return WALK_DONE;
  if(mdb_vread(&n, sizeof(n), (uintptr_t)s->walk_data) == -1) return WALK_ERR;
  s->walk_addr = (uintptr_t)n.data;
  s->walk_callback(s->walk_addr, &dummy, s->walk_cbdata);
  s->walk_data = n.next;
  return WALK_NEXT;
}

static void mtev_skiplist_walk_fini(mdb_walk_state_t *s) {
  (void)s;
}


#ifndef CK_HS_PROBE_L1_SHIFT
#define CK_HS_PROBE_L1_SHIFT 3ULL
#endif /* CK_HS_PROBE_L1_SHIFT */

#define CK_HS_PROBE_L1 (1 << CK_HS_PROBE_L1_SHIFT)
#define CK_HS_PROBE_L1_MASK (CK_HS_PROBE_L1 - 1)

#ifndef CK_HS_PROBE_L1_DEFAULT
#define CK_HS_PROBE_L1_DEFAULT CK_MD_CACHELINE
#endif

#define CK_HS_VMA_MASK ((uintptr_t)((1ULL << CK_MD_VMA_BITS) - 1))
#define CK_HS_VMA(x)	\
  ((void *)((uintptr_t)(x) & CK_HS_VMA_MASK))

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

enum ck_hs_probe_behavior {
  CK_HS_PROBE = 0,	/* Default behavior. */
  CK_HS_PROBE_TOMBSTONE,	/* Short-circuit on tombstone. */
  CK_HS_PROBE_INSERT	/* Short-circuit on probe bound if tombstone found. */
};

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

static inline unsigned int
ck_hs_map_bound_get(struct ck_hs_map *m, unsigned long h)
{
  unsigned long offset = h & m->mask;
  unsigned int r = CK_HS_WORD_MAX;

  if (m->probe_bound != NULL) {
    r = m->probe_bound[offset];
    if (r == CK_HS_WORD_MAX)
      r = m->probe_maximum;
  } 
  else {
    r = m->probe_maximum;
  }
  return r;
}

static inline unsigned long
ck_hs_map_probe_next(struct ck_hs_map *map,
    unsigned long offset,
    unsigned long h,
    unsigned long level,
    unsigned long probes)
{
  unsigned long r, stride;

  r = (h >> map->step) >> level;
  stride = (r & ~CK_HS_PROBE_L1_MASK) << 1 | (r & CK_HS_PROBE_L1_MASK);

  return (offset + (probes >> CK_HS_PROBE_L1_SHIFT) +
    (stride | CK_HS_PROBE_L1)) & map->mask;
}

static const void **
ck_hs_map_probe(struct ck_hs *hs,
    struct ck_hs_map *map,
    unsigned long *n_probes,
    const void ***priority,
    unsigned long h,
    const void *key,
    const void **object,
    unsigned long probe_limit,
    enum ck_hs_probe_behavior behavior)
{
  const void **bucket, **cursor, *k, *compare;
  const void **pr = NULL;
  unsigned long offset, j, i, probes, opl;

#ifdef CK_HS_PP
  /* If we are storing object pointers, then we may leverage pointer packing. */
  unsigned long hv = 0;

  if (hs->mode & CK_HS_MODE_OBJECT) {
    hv = (h >> 25) & CK_HS_KEY_MASK;
    compare = CK_HS_VMA(key);
  } 
  else {
    compare = key;
  }
#else
  compare = key;
#endif

  offset = h & map->mask;
  *object = NULL;
  i = probes = 0;

  opl = probe_limit;
  if (behavior == CK_HS_PROBE_INSERT) {
    probe_limit = ck_hs_map_bound_get(map, h);
  }

  for (;;) {
    bucket = (const void **)((uintptr_t)&map->entries[offset] & ~(CK_MD_CACHELINE - 1));

    for (j = 0; j < CK_HS_PROBE_L1; j++) {
      cursor = bucket + ((j + offset) & (CK_HS_PROBE_L1 - 1));
      if (probes++ == probe_limit) {
        if (probe_limit == opl || pr != NULL) {
          k = CK_HS_EMPTY;
          goto leave;
        }
        /*
         * If no eligible slot has been found yet, continue probe
         * sequence with original probe limit.
         */
        probe_limit = opl;
      }
      k = *cursor;
      if (k == CK_HS_EMPTY) {
        goto leave;
      }

      if (k == CK_HS_TOMBSTONE) {
        if (pr == NULL) {
          pr = cursor;
          *n_probes = probes;

          if (behavior == CK_HS_PROBE_TOMBSTONE) {
            k = CK_HS_EMPTY;
            goto leave;
          }
        }
        continue;
      }
#ifdef CK_HS_PP
      if (hs->mode & CK_HS_MODE_OBJECT) {
        if (((uintptr_t)k >> CK_MD_VMA_BITS) != hv)
          continue;

        k = CK_HS_VMA(k);
      }
#endif

      if (k == compare) {
        goto leave;
      }

      if (hs->compare == NULL)
        continue;

      if (hs->compare(k, key) == true)
        goto leave;
    }

    offset = ck_hs_map_probe_next(map, offset, h, i++, probes);
  }

leave:
  if (probes > probe_limit) {
    cursor = NULL;
  } else {
    *object = k;
  }
  if (pr == NULL)
    *n_probes = probes;

  *priority = pr;
  return cursor;
}

void *
ck_hs_get(struct ck_hs *hs, unsigned long h, const void *key)
{
  const void **first, *object;
  struct ck_hs_map *map;
  unsigned long n_probes;
  unsigned int g, g_p, probe;
  unsigned int *generation;

  do {
    map = hs->map;
    generation = &map->generation[h & CK_HS_G_MASK];
    g = *generation;
    probe  = ck_hs_map_bound_get(map, h);

    ck_hs_map_probe(hs, map, &n_probes, &first, h, key, &object, probe, CK_HS_PROBE);

    g_p = *generation;
  } while (g != g_p);
  return CK_CC_DECONST_PTR(object);
}
/* end libck sync section */

/* must be synced with mtev_hash.c */
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

int mtev_hash_retrieve2(struct ck_hs_map *hs, ck_key_t *key, void **data) {
  (void)hs;
  ck_hash_attr_t *data_struct;

  if (key) {
    data_struct = index_attribute_container(key);
    if (data) {
      if (data_struct) {
        *data = data_struct->data;
      }
      else {
        *data = NULL;
      }
    }
    return 1;
  }
  else {
    *data = NULL;
  }
  return 0;
}
/* end mtev_hash.c sync section*/

struct hash_helper {
  int size;
  int bucket;
  void *vmem;
  mtev_hash_table l;
};
static int mtev_hash_walk_init(mdb_walk_state_t *s) {
  mtev_hash_table l;
  struct ck_hs_map *map;
  struct hash_helper *hh;
  void *dummy;
  CK_HS_WORD *probe_bound;
  ck_key_t **buckets;
  int found = 0;

  map = mdb_zalloc(sizeof(struct ck_hs_map), UM_GC);
  if(mdb_vread(&l, sizeof(l), s->walk_addr) == -1) {
    return WALK_ERR;
  }
  if(mdb_vread(map, sizeof(struct ck_hs_map), (uintptr_t)l.u.hs.map) == -1) {
    return WALK_ERR;
  }
  probe_bound = mdb_zalloc(sizeof(CK_HS_WORD) * map->n_entries, UM_GC);
  if (mdb_vread(probe_bound, sizeof(CK_HS_WORD) * map->n_entries, (uintptr_t)map->probe_bound) == -1) {
    map->probe_bound = NULL;
  }
  else {
    map->probe_bound = probe_bound;
  }
  if(map->n_entries == 0) {
    return WALK_DONE;
  }
  l.u.hs.map = map;
  l.u.hs.compare = hs_compare;
  l.u.hs.hf = hs_hash;
  //l.hs.m = &my_allocator;
  hh = mdb_zalloc(sizeof(struct hash_helper), UM_GC);
  hh->l = l;
  hh->size = map->capacity;
  buckets = mdb_zalloc(sizeof(void *) * map->capacity, UM_GC);
  s->walk_data = hh;
  hh->vmem = (void *)map->entries;
  mdb_vread(buckets, sizeof(void *) * map->capacity, (uintptr_t)hh->vmem);
  hh->bucket = 0;
  for(;hh->bucket<hh->size;hh->bucket++) {
    if (buckets[hh->bucket] != CK_HS_EMPTY && buckets[hh->bucket] != CK_HS_TOMBSTONE) {
      uint32_t len = 0;
      int ret = mdb_vread(&len, sizeof(uint32_t), (uintptr_t)buckets[hh->bucket]);
      if (ret > 0 && len > 0) {
        /* The object sits before the key */
        size_t offset = ((size_t)&((ck_hash_attr_t *)0)->key);
        void *fullkey = mdb_zalloc((size_t)(offset + len + 1), UM_GC);
        mdb_vread(fullkey, (size_t)len+offset, ((uintptr_t)buckets[hh->bucket])-offset);
        buckets[hh->bucket] = CK_HS_VMA(fullkey+offset);
        found++;
      }
    }
    else {
      buckets[hh->bucket] = NULL;
    }
  }
  map->entries = (void**)buckets;
  hh->bucket = 0;
  for(;hh->bucket<hh->size;hh->bucket++) {
    ck_key_t *key = l.u.hs.map->entries[hh->bucket];
    if (key && key->len != 0) {
      void *data = NULL;

      mtev_hash_retrieve2(map, key, &data);
      s->walk_addr = (uintptr_t)data;
      s->walk_callback(s->walk_addr, &dummy, s->walk_cbdata);
      hh->bucket++;
      return WALK_NEXT;
    }
  }
  return WALK_DONE;
}
static int mtev_hash_walk_step(mdb_walk_state_t *s) {
  void *dummy = NULL;
  struct hash_helper *hh = s->walk_data;
  mtev_hash_table l = hh->l;
  if(s->walk_data == NULL) return WALK_DONE;
  for(;hh->bucket<hh->size;hh->bucket++) {
    ck_key_t *key = l.u.hs.map->entries[hh->bucket];
    if (key && key->len != 0) {
      void *data = NULL;

      mtev_hash_retrieve2(l.u.hs.map, key, &data);
      s->walk_addr = (uintptr_t)data;
      s->walk_callback(s->walk_addr, &dummy, s->walk_cbdata);
      hh->bucket++;
      return WALK_NEXT;
    }
  }
  return WALK_DONE;
}
static void mtev_hash_walk_fini(mdb_walk_state_t *s) {
  (void)s;
}

static int
_print_hash_bucket_data_cb(uintptr_t addr, const void *u, void *data)
{
  (void)u;
  (void)data;
  mdb_printf("%p\n", addr);
  return WALK_NEXT;
}

static int
mtev_log_dcmd(uintptr_t addr, unsigned flags, int argc, const mdb_arg_t *argv) {
  (void)addr;
  (void)flags;
  mtev_hash_table l;
  struct ck_hs_map map;
  void **buckets;
  uintptr_t vmem;
  size_t bucket = 0;
  char logname[128];

  if(argv == 0) {
    GElf_Sym sym;
    int rv;
    if(mdb_lookup_by_name("mtev_loggers", &sym) == -1) return DCMD_ERR;
    rv = mdb_pwalk("mtev_hash", _print_hash_bucket_data_cb, NULL, sym.st_value);
    return (rv == WALK_DONE) ? DCMD_OK : DCMD_ERR;
  }
  if(argc != 1 || argv[0].a_type != MDB_TYPE_STRING) {
    return DCMD_USAGE;
  }
  if(mdb_readsym(&l, sizeof(l), "mtev_loggers") == -1) return DCMD_ERR;
  if(mdb_vread(&map, sizeof(map), (uintptr_t)l.u.hs.map) == -1) return DCMD_ERR;
  if(map.n_entries == 0) return DCMD_OK;
  buckets = mdb_zalloc(sizeof(void *) * map.capacity, UM_GC);
  vmem = (uintptr_t)map.entries;
  mdb_vread(buckets, sizeof(void *) * map.capacity, (uintptr_t)vmem);
  for(;bucket<map.capacity;bucket++) {
    if(buckets[bucket] != CK_HS_EMPTY && buckets[bucket] != CK_HS_TOMBSTONE) {
      uint32_t len = 0;
      size_t offset = ((size_t)&((ck_hash_attr_t *)0)->key);
      if(mdb_vread(&len, sizeof(uint32_t), (uintptr_t)buckets[bucket]) < 0) return DCMD_ERR;
      /* The object sits before the key */
      ck_hash_attr_t *fullkey = mdb_zalloc((size_t)(offset + len + 1), UM_GC);
      mdb_vread(fullkey, (size_t)len+offset, ((uintptr_t)buckets[bucket])-offset);
      logname[0] = '\0';
      memcpy(logname, fullkey->key.label, MIN(sizeof(logname), fullkey->key.len - sizeof(fullkey->key.len)));
      logname[MIN(len,sizeof(logname)-1)] = '\0';
      if(!strcmp(logname, argv[0].a_un.a_str)) {
        mdb_printf("%p\n", fullkey->data);
        return DCMD_OK;
      }
    }
  }
  return DCMD_OK;
}

struct _mtev_log_stream {
  unsigned flags;
  /* Above is exposed... 'do not change it... dragons' */
  char *type;
  char *name;
  int mode;
  char *path;
  void *ops;
  void *op_ctx;
  mtev_hash_table *config;
  struct _mtev_log_stream_outlet_list *outlets;
  pthread_rwlock_t *lock;
  int32_t written;
  unsigned deps_materialized:1;
  unsigned flags_below;
};

typedef struct {
  uint64_t head;
  uint64_t tail;
  int noffsets;
  int *offsets;
  int segmentsize;
  int segmentcut;
  char *segment;
} membuf_ctx_t;

static int
membuf_print_dmcd(uintptr_t addr, unsigned flags, int argc, const mdb_arg_t *argv) {
  (void)flags;
  unsigned opt_v = FALSE;
  int rv = DCMD_OK;
  struct _mtev_log_stream ls;
  char logtype[128];
  membuf_ctx_t mb, *membuf;
  int nmsg;
  size_t log_lines = 0;
  size_t idx;
  int *offsets;
  uint64_t opt_n = 0;

  if(mdb_getopts(argc, argv,
     'v', MDB_OPT_SETBITS, TRUE, &opt_v,
     'n', MDB_OPT_UINT64, &opt_n, NULL) != argc)
                return (DCMD_USAGE);

  log_lines = (int)opt_n;
  if(mdb_vread(&ls, sizeof(ls), addr) == -1) return DCMD_ERR;
  if(mdb_readstr(logtype, sizeof(logtype), (uintptr_t)ls.type) == -1) return DCMD_ERR;
  if(strcmp(logtype, "memory")) {
    mdb_warn("log_stream not of type 'memory'\n");
    return DCMD_ERR;
  }
  if(mdb_vread(&mb, sizeof(mb), (uintptr_t)ls.op_ctx) == -1) return DCMD_ERR;
  membuf = &mb;

  /* Find out how many lines we have */
  nmsg = ((membuf->tail % membuf->noffsets) >= (membuf->head % membuf->noffsets)) ?
           ((membuf->tail % membuf->noffsets) - (membuf->head % membuf->noffsets)) :
           ((membuf->tail % membuf->noffsets) + membuf->noffsets - (membuf->head % membuf->noffsets));
  if(nmsg >= membuf->noffsets) return DCMD_ERR;
  if(log_lines == 0) log_lines = nmsg;
  log_lines = MIN(log_lines,nmsg);
  idx = (membuf->tail >= log_lines) ?
          (membuf->tail - log_lines) : 0;
 
  mdb_printf("Displaying %d of %d logs\n", log_lines, nmsg);
  mdb_printf("==================================\n");

  if(idx == membuf->tail) return 0;

  /* If we're asked for a starting index outside our range, then we should set it to head. */
  if((membuf->head > membuf->tail && idx < membuf->head && idx >= membuf->tail) ||
     (membuf->head < membuf->tail && (idx >= membuf->tail || idx < membuf->head)))
    idx = membuf->head;

  offsets = mdb_zalloc(sizeof(*offsets) * membuf->noffsets, UM_SLEEP);
  if(mdb_vread(offsets, sizeof(*offsets) * membuf->noffsets, (uintptr_t)membuf->offsets) == -1) {
    mdb_warn("error reading offsets\n");
    return DCMD_ERR;
  }
  while(idx != membuf->tail) {
    char line[65536];
    struct timeval copy;
    uintptr_t logline;
    uint64_t nidx;
    size_t len;
    nidx = idx + 1;
    len = (offsets[idx % membuf->noffsets] < offsets[nidx % membuf->noffsets]) ?
            offsets[nidx % membuf->noffsets] - offsets[idx % membuf->noffsets] :
            membuf->segmentcut - offsets[idx % membuf->noffsets];
    if(mdb_vread(&copy, sizeof(copy), (uintptr_t)membuf->segment + offsets[idx % membuf->noffsets]) == -1) {
      mdb_warn("error reading timeval from log line\n");
      rv = DCMD_ERR;
      break;
    }
    logline = (uintptr_t)membuf->segment + offsets[idx % membuf->noffsets] + sizeof(copy);
    len -= sizeof(copy);
    if(len > sizeof(line)-1) {
      mdb_warn("logline too long\n");
    }
    else if(mdb_vread(line, len, logline) == -1) {
      mdb_warn("error reading log line\n");
      break;
    }
    else {
      line[len]='\0';
      if(opt_v) {
        mdb_printf("[%u] [%u.%u]\n", idx, copy.tv_sec, copy.tv_usec);
        mdb_inc_indent(4);
      }
      mdb_printf("%s", line);
      if(opt_v) {
        mdb_dec_indent(4);
      }
    }
    idx = nidx;
  }
  return rv;
}

static mdb_walker_t _utils_walkers[] = {
  {
  .walk_name = "mtev_skiplist",
  .walk_descr = "walk a mtev_skiplist along it's ordered bottom row",
  .walk_init = mtev_skiplist_walk_init,
  .walk_step = mtev_skiplist_walk_step,
  .walk_fini = mtev_skiplist_walk_fini,
  .walk_init_arg = NULL
  },
  {
  .walk_name = "mtev_hash",
  .walk_descr = "walk a mtev_hash",
  .walk_init = mtev_hash_walk_init,
  .walk_step = mtev_hash_walk_step,
  .walk_fini = mtev_hash_walk_fini,
  .walk_init_arg = NULL
  },
  { NULL }
};
static mdb_dcmd_t _utils_dcmds[] = {
  {
    "mtev_log",
    "[logname]",
    "returns the mtev_log_stream_t for the named log",
    mtev_log_dcmd,
    NULL,
    NULL
  },
  {
    "mtev_print_membuf_log",
    "[-v] [-n nlines]",
    "prints the at most [n] log lines",
    membuf_print_dmcd,
    NULL,
    NULL
  },
  { NULL }
};

static mdb_modinfo_t mtevutils_linkage = {
  .mi_dvers = MDB_API_VERSION,
  .mi_dcmds = _utils_dcmds,
  .mi_walkers = _utils_walkers
};
