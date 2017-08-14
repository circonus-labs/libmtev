#include "mtev_lfu.h"
#include "mtev_hash.h"
#include "mtev_log.h"
#include "mtev_rand.h"

#include <ck_hs.h>
#include <sys/queue.h>
#include <stddef.h>

#define GC_CADENCE 10000

struct lfu_cache_entry;

STAILQ_HEAD(frequency_list, lfu_cache_entry);

struct lfu_entry {
  void *entry;
  size_t key_len;
  STAILQ_ENTRY(lfu_entry) freq_list_entry;
  struct lfu_cache_entry *frequency_list_head;
  char key[];
};

struct lfu_cache_entry {
  size_t frequency;
  STAILQ_HEAD(lfu_cache, lfu_entry) lfu_cache;
  STAILQ_ENTRY(lfu_cache_entry) list_entry;
};

struct mtev_lfu {
  ck_hs_t hash;
  int32_t max_entries;
  struct frequency_list lfu_frequency_list;
  int32_t lfu_cache_size;
  uint32_t expire_count;
  void (*free_fn)(void *);
  pthread_mutex_t mutex;
};

static void *
lfu_malloc(size_t r)
{
  return malloc(r);
}

static void
lfu_free(void *p, size_t b, bool r)
{
  (void)b;
  (void)r;
  free(p);
  return;
}

static struct ck_malloc malloc_ck_hs = {
  .malloc = lfu_malloc,
  .free = lfu_free
};

static unsigned long
lfu_entry_hash(const void *k, unsigned long seed)
{
  return mtev_hash__hash(k, strlen((const char *)k), seed);
}

#define container_of(derived_ptr, type, field)                \
  ((type *)((char *)(derived_ptr) - offsetof(type, field)))

static void
hs_init(ck_hs_t *hs, unsigned int mode, ck_hs_hash_cb_t *hf, ck_hs_compare_cb_t *cf, unsigned long size)
{
  mtev_rand_init();
  struct ck_malloc *allocator = &malloc_ck_hs;

  if (ck_hs_init(hs, mode | CK_HS_MODE_SPMC, hf, cf, allocator, size, mtev_rand()) == false) {
    mtevFatal(mtev_error, "Cannot initialize ck_hs\n");
  }
}

static bool
hs_string_compare(const void *a, const void *b)
{
  return strcmp((const char * const)a, (const char * const)b) == 0;
}

mtev_lfu_t *
mtev_lfu_create(int32_t max_entries, void (*free_fn)(void *))
{
  struct mtev_lfu *r = malloc(sizeof(struct mtev_lfu));
  if (max_entries <= 0) {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lfu_entry_hash, hs_string_compare, 1024);
  } else {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lfu_entry_hash, hs_string_compare, max_entries * 2);
  }
  STAILQ_INIT(&r->lfu_frequency_list);
  r->lfu_cache_size = 0;
  r->expire_count = 0;
  r->max_entries = max_entries;
  if (free_fn != NULL) {
    r->free_fn = free_fn;
  } else {
    r->free_fn = free;
  }
  pthread_mutex_init(&r->mutex, NULL);
  return r;
}

void
mtev_lfu_destroy(mtev_lfu_t *lfu)
{
  mtev_lfu_invalidate(lfu);
  ck_hs_destroy(&lfu->hash);
  free(lfu);
}

void
mtev_lfu_invalidate(mtev_lfu_t *lfu)
{
  pthread_mutex_lock(&lfu->mutex);

  while (!STAILQ_EMPTY(&lfu->lfu_frequency_list)) {
    struct lfu_cache_entry *e = STAILQ_FIRST(&lfu->lfu_frequency_list);
    STAILQ_REMOVE(&lfu->lfu_frequency_list, e, lfu_cache_entry, list_entry);
    while (!STAILQ_EMPTY(&e->lfu_cache)) {
      struct lfu_entry *le = STAILQ_FIRST(&e->lfu_cache);
      STAILQ_REMOVE(&e->lfu_cache, le, lfu_entry, freq_list_entry);
      lfu->free_fn(le->entry);
      free(le);
    }
    free(e);
  }

  ck_hs_reset(&lfu->hash);
  lfu->lfu_cache_size = 0;
  pthread_mutex_unlock(&lfu->mutex);
}

static struct lfu_cache_entry *
remove_from_frequency_list_no_lock(mtev_lfu_t *lfu, struct lfu_entry *le)
{
  struct lfu_cache_entry *rval = NULL;
  STAILQ_REMOVE(&le->frequency_list_head->lfu_cache, le, lfu_entry, freq_list_entry);
  if (STAILQ_FIRST(&le->frequency_list_head->lfu_cache) == NULL) {

    /* we can remove the entire frequency bucket */
    STAILQ_REMOVE(&lfu->lfu_frequency_list, le->frequency_list_head, lfu_cache_entry, list_entry);
    /* don't free, instead return the bucket for possible reuse */
    rval = le->frequency_list_head;
    rval->list_entry.stqe_next = NULL;
    rval->frequency = 0;
    rval->lfu_cache.stqh_first = NULL;
    rval->lfu_cache.stqh_last = &rval->lfu_cache.stqh_first;
  }
  le->frequency_list_head = NULL;
  return rval;
}

/* this requires a lock to be held elsewhere
 *
 * There are potentially several items in the same
 * frequency bucket, we remove the first one
 */
static void
expire_least_lfu_cache_no_lock(mtev_lfu_t *c)
{
  /* peek at the first entry in the frequency list */
  struct lfu_cache_entry *e = STAILQ_FIRST(&c->lfu_frequency_list);
  struct lfu_entry *le = STAILQ_FIRST(&e->lfu_cache);

  struct lfu_cache_entry *empty = remove_from_frequency_list_no_lock(c, le);

  c->lfu_cache_size--;

  /* remove from hs */
  unsigned long hash = CK_HS_HASH(&c->hash, lfu_entry_hash, le->key);
  ck_hs_remove(&c->hash, hash, le->key);

  int ec = ck_pr_load_32(&c->expire_count);
  if (ec == GC_CADENCE) {
    c->expire_count = 0;
    ck_hs_gc(&c->hash, GC_CADENCE, (rand() % ck_hs_count(&c->hash)));
  }
  c->expire_count++;

  c->free_fn(le->entry);
  free(le);
  if (empty) {
    free(empty);
  }
}

static inline void
insert_to_bucket_list(mtev_lfu_t *c, struct lfu_cache_entry *bucket, struct lfu_cache_entry *prior)
{
  if (prior) {
    STAILQ_INSERT_AFTER(&c->lfu_frequency_list, prior, bucket, list_entry);
  } else {
    STAILQ_INSERT_HEAD(&c->lfu_frequency_list, bucket, list_entry);
  }
}

static struct lfu_cache_entry *
new_frequency_bucket_no_lock(mtev_lfu_t *c, size_t freq, struct lfu_cache_entry *prior)
{
  struct lfu_cache_entry *e = calloc(1, sizeof(struct lfu_cache_entry));
  e->frequency = freq;
  STAILQ_INIT(&e->lfu_cache);
  insert_to_bucket_list(c, e, prior);
  return e;
}

static void
add_lfu_cache_no_lock(mtev_lfu_t *c, struct lfu_entry *le)
{
  if (c->max_entries > 0) {
    if ((c->lfu_cache_size + 1) > c->max_entries) {
      expire_least_lfu_cache_no_lock(c);
    }
    /* new entries always go in the list at frequency == 1 */
    struct lfu_cache_entry *e = STAILQ_FIRST(&c->lfu_frequency_list);
    if (e == NULL || e->frequency > 1) {
      /* make a frequency bucket of 1 */
      e = new_frequency_bucket_no_lock(c, 1, NULL);
    }
    /* add to tail */
    le->frequency_list_head = e;
    STAILQ_INSERT_TAIL(&e->lfu_cache, le, freq_list_entry);
  }
  c->lfu_cache_size++;
}

static void
touch_lfu_cache_no_lock(mtev_lfu_t *c, struct lfu_entry *e)
{
  if (c->max_entries > 0) {
    struct lfu_cache_entry *bucket = e->frequency_list_head;
    struct lfu_cache_entry *next_bucket = STAILQ_NEXT(bucket, list_entry);
    size_t bucket_freq = bucket->frequency;
    mtev_boolean need_new_bucket = mtev_false;

    if (next_bucket == NULL ||
        next_bucket == STAILQ_FIRST(&c->lfu_frequency_list) ||
        next_bucket->frequency != bucket_freq + 1) {
      need_new_bucket = mtev_true;
    }
    struct lfu_cache_entry *empty = remove_from_frequency_list_no_lock(c, e);
    if (need_new_bucket) {
      if (empty != NULL) {
        next_bucket = empty;
        next_bucket->frequency = bucket_freq + 1;
        insert_to_bucket_list(c, next_bucket, bucket);
      } else {
        next_bucket = new_frequency_bucket_no_lock(c, bucket_freq + 1, bucket);
      }
    }

    STAILQ_INSERT_TAIL(&next_bucket->lfu_cache, e, freq_list_entry);
    e->frequency_list_head = next_bucket;
  }
}


mtev_boolean
mtev_lfu_put(mtev_lfu_t *lfu, const char *key, size_t key_len, void *val)
{
  /* a max size of zero means to disable the LFU */
  if (lfu->max_entries == 0) {
    return mtev_false;
  }

  unsigned long hash = CK_HS_HASH(&lfu->hash, lfu_entry_hash, key);
  struct lfu_entry *e = malloc(sizeof(struct lfu_entry) + key_len + 1);
  e->entry = val;
  e->key_len = key_len;
  memcpy(e->key, key, key_len);
  e->key[key_len] = '\0';

  pthread_mutex_lock(&lfu->mutex);
  void *previous = NULL;
  if (ck_hs_set(&lfu->hash, hash, e->key, &previous) == false) {
    free(e);
    pthread_mutex_unlock(&lfu->mutex);
    return mtev_false;
  }
  if (previous) {
    struct lfu_entry *p = container_of(previous, struct lfu_entry, key);
    struct lfu_cache_entry *empty = remove_from_frequency_list_no_lock(lfu, p);
    lfu->free_fn(p->entry);
    free(p);
    if (empty) {
      free(empty);
    }
  }
  add_lfu_cache_no_lock(lfu, e);
  pthread_mutex_unlock(&lfu->mutex);
  return mtev_true;
}

void *
mtev_lfu_get(mtev_lfu_t *c, const char *key, size_t key_len)
{
  /* a max size of zero means to disable the LFU */
  if (c->max_entries == 0) {
    return NULL;
  }

  unsigned long hash = CK_HS_HASH(&c->hash, lfu_entry_hash, key);
  void *entry = ck_hs_get(&c->hash, hash, key);

  if (entry != NULL) {
    struct lfu_entry *r = container_of(entry, struct lfu_entry, key);
    pthread_mutex_lock(&c->mutex);
    touch_lfu_cache_no_lock(c, r);
    pthread_mutex_unlock(&c->mutex);
    return r->entry;
  }
  return NULL;
}


void *
mtev_lfu_remove(mtev_lfu_t *c, const char *key, size_t key_len)
{
  /* a max size of zero means to disable the LFU */
  if (c->max_entries == 0) {
    return NULL;
  }

  unsigned long hash = CK_HS_HASH(&c->hash, lfu_entry_hash, key);
  void *rval = NULL;
  pthread_mutex_lock(&c->mutex);
  void *entry = ck_hs_remove(&c->hash, hash, key);
  if (entry != NULL) {
    struct lfu_entry *r = container_of(entry, struct lfu_entry, key);
    if (c->max_entries > 0) {
      struct lfu_cache_entry *empty = remove_from_frequency_list_no_lock(c, r);
      if (empty) {
        free(empty);
      }
    }
    c->lfu_cache_size--;
    rval = r->entry;
    free(r);

    /* when removing, perform GC every GC_CADENCE changes */
    int ec = ck_pr_load_32(&c->expire_count);
    if (ec == GC_CADENCE && ck_hs_count(&c->hash) > 0) {
      c->expire_count = 0;
      ck_hs_gc(&c->hash, GC_CADENCE, (rand() % ck_hs_count(&c->hash)));
    }
    c->expire_count++;
  }
  pthread_mutex_unlock(&c->mutex);
  return rval;
}

int32_t
mtev_lfu_size(mtev_lfu_t *c)
{
  return c->lfu_cache_size;
}
