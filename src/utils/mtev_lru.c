#include "mtev_lru.h"
#include "mtev_hash.h"
#include "mtev_log.h"
#include "mtev_rand.h"

#include <ck_hs.h>
#include <sys/queue.h>
#include <stddef.h>

struct lru_entry {
  void *entry;
  size_t key_len;
  TAILQ_ENTRY(lru_entry) list_entry;
  char key[];
};

struct mtev_lru {
  ck_hs_t hash;
  int32_t max_entries;
  TAILQ_HEAD(lru_list, lru_entry) lru_cache;
  int32_t lru_cache_size;
  uint32_t expire_count;
  void (*free_fn)(void *);
  pthread_mutex_t mutex;
};

static void *
lru_malloc(size_t r)
{
  return malloc(r);
}

static void
lru_free(void *p, size_t b, bool r)
{
  (void)b;
  (void)r;
  free(p);
  return;
}

static struct ck_malloc malloc_ck_hs = {
  .malloc = lru_malloc,
  .free = lru_free
};

static unsigned long
lru_entry_hash(const void *k, unsigned long seed)
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

mtev_lru_t *
mtev_lru_create(int32_t max_entries, void (*free_fn)(void *))
{
  struct mtev_lru *r = malloc(sizeof(struct mtev_lru));
  if (max_entries <= 0) {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lru_entry_hash, hs_string_compare, 1024);
  } else {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lru_entry_hash, hs_string_compare, max_entries * 2);
  }
  TAILQ_INIT(&r->lru_cache);
  r->lru_cache_size = 0;
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
mtev_lru_destroy(mtev_lru_t *lru)
{
  mtev_lru_invalidate(lru);
  ck_hs_destroy(&lru->hash);
  free(lru);
}

void
mtev_lru_invalidate(mtev_lru_t *lru)
{
  pthread_mutex_lock(&lru->mutex);

  while (!TAILQ_EMPTY(&lru->lru_cache)) {
    struct lru_entry *e = TAILQ_FIRST(&lru->lru_cache);
    TAILQ_REMOVE(&lru->lru_cache, e, list_entry);
    lru->free_fn(e->entry);
    free(e);
  }

  ck_hs_reset(&lru->hash);
  lru->lru_cache_size = 0;
  pthread_mutex_unlock(&lru->mutex);
}

#define GC_CADENCE 10000

/* this requires a lock to be held elsewhere */
static void
expire_oldest_lru_cache_no_lock(mtev_lru_t *c)
{
  /* remove from TAILQ */
  struct lru_entry *e = TAILQ_LAST(&c->lru_cache, lru_list);
  TAILQ_REMOVE(&c->lru_cache, e, list_entry);
  c->lru_cache_size--;

  /* remove from hs */
  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, e->key);
  ck_hs_remove(&c->hash, hash, e->key);

  int ec = ck_pr_load_32(&c->expire_count);
  if (ec == GC_CADENCE) {
    c->expire_count = 0;
    ck_hs_gc(&c->hash, GC_CADENCE, (rand() % ck_hs_count(&c->hash)));
  }
  c->expire_count++;

  if (e->entry != NULL) {
    c->free_fn(e->entry);
  }
  free(e);
}

static void
add_lru_cache_no_lock(mtev_lru_t *c, struct lru_entry *e)
{
  if (c->max_entries > 0) {
    if ((c->lru_cache_size + 1) > c->max_entries) {
      expire_oldest_lru_cache_no_lock(c);
    }
    TAILQ_INSERT_HEAD(&c->lru_cache, e, list_entry);
  }
  c->lru_cache_size++;
}

static void
touch_lru_cache_no_lock(mtev_lru_t *c, struct lru_entry *e)
{
  if (c->max_entries > 0) {
    if (e->list_entry.tqe_next != NULL || e->list_entry.tqe_prev != NULL) {
      TAILQ_REMOVE(&c->lru_cache, e, list_entry);
    }
    TAILQ_INSERT_HEAD(&c->lru_cache, e, list_entry);
  }
}


mtev_boolean
mtev_lru_put(mtev_lru_t *lru, const char *key, size_t key_len, void *val)
{
  unsigned long hash = CK_HS_HASH(&lru->hash, lru_entry_hash, key);
  struct lru_entry *e = malloc(sizeof(struct lru_entry) + key_len + 1);
  e->entry = val;
  e->key_len = key_len;
  memcpy(e->key, key, key_len);
  e->key[key_len] = '\0';

  pthread_mutex_lock(&lru->mutex);
  void *previous = NULL;
  if (ck_hs_set(&lru->hash, hash, e->key, &previous) == false) {
    free(e);
    pthread_mutex_unlock(&lru->mutex);
    return mtev_false;
  }
  if (previous) {
    struct lru_entry *p = container_of(previous, struct lru_entry, key);
    TAILQ_REMOVE(&lru->lru_cache, p, list_entry);
    lru->free_fn(p->entry);
    free(p);
  }
  add_lru_cache_no_lock(lru, e);
  pthread_mutex_unlock(&lru->mutex);
  return mtev_true;
}

void *
mtev_lru_get(mtev_lru_t *c, const char *key, size_t key_len)
{
  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, key);
  void *entry = ck_hs_get(&c->hash, hash, key);

  if (entry != NULL) {
    struct lru_entry *r = container_of(entry, struct lru_entry, key);
    pthread_mutex_lock(&c->mutex);
    touch_lru_cache_no_lock(c, r);
    pthread_mutex_unlock(&c->mutex);
    return r->entry;
  }
  return NULL;
}


void *
mtev_lru_remove(mtev_lru_t *c, const char *key, size_t key_len)
{
  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, key);
  void *rval = NULL;
  pthread_mutex_lock(&c->mutex);
  void *entry = ck_hs_remove(&c->hash, hash, key);
  if (entry != NULL) {
    struct lru_entry *r = container_of(entry, struct lru_entry, key);
    if (c->max_entries > 0) {
      TAILQ_REMOVE(&c->lru_cache, r, list_entry);
    }
    c->lru_cache_size--;
    rval = r->entry;
    free(r);

    /* when removing, perform GC every 100K rows */
    if (ck_hs_count(&c->hash) > 0 && c->lru_cache_size % GC_CADENCE == 0) {
      ck_hs_gc(&c->hash, GC_CADENCE, (rand() % ck_hs_count(&c->hash)));
    }
  }
  pthread_mutex_unlock(&c->mutex);
  return rval;
}

int32_t
mtev_lru_size(mtev_lru_t *c)
{
  return c->lru_cache_size;
}
