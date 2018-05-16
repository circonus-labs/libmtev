#include "mtev_lru.h"
#include "mtev_hash.h"
#include "mtev_log.h"
#include "mtev_rand.h"

#include <ck_hs.h>
#include <sys/queue.h>
#include <stddef.h>

#define ALLOCA_LIMIT 1024

struct lru_key {
  size_t key_len;
  char key[];
};

struct lru_entry {
  void *entry;
  uint64_t ref_cnt;
  TAILQ_ENTRY(lru_entry) list_entry;
  struct lru_key key;
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
  const struct lru_key *key = (const struct lru_key *)k;
  return mtev_hash__hash(key->key, key->key_len, seed);
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
hs_lru_key_compare(const void *a, const void *b)
{
  const struct lru_key *left = (const struct lru_key *)a;
  const struct lru_key *right = (const struct lru_key *)b;

  if (left->key_len != right->key_len) return false;

  return memcmp(left->key, right->key, left->key_len) == 0;
}

mtev_lru_t *
mtev_lru_create(int32_t max_entries, void (*free_fn)(void *))
{
  struct mtev_lru *r = malloc(sizeof(struct mtev_lru));
  if (max_entries <= 0) {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lru_entry_hash, hs_lru_key_compare, 1024);
  } else {
    hs_init(&r->hash, CK_HS_MODE_OBJECT | CK_HS_MODE_DELETE, lru_entry_hash, hs_lru_key_compare, max_entries * 2);
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
    mtev_lru_release(lru, e);
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
  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, &e->key);
  ck_hs_remove(&c->hash, hash, &e->key);

  int ec = ck_pr_load_32(&c->expire_count);
  if (ec == GC_CADENCE) {
    c->expire_count = 0;
    ck_hs_gc(&c->hash, GC_CADENCE, (mtev_rand() % ck_hs_count(&c->hash)));
  }
  c->expire_count++;

  mtev_lru_release(c, e);
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
  struct lru_entry *e = malloc(sizeof(struct lru_entry) + key_len + 1);
  e->entry = val;
  e->ref_cnt = 1;
  e->key.key_len = key_len;
  memcpy(e->key.key, key, key_len);
  unsigned long hash = CK_HS_HASH(&lru->hash, lru_entry_hash, &e->key);

  pthread_mutex_lock(&lru->mutex);
  void *previous = NULL;
  if (ck_hs_set(&lru->hash, hash, &e->key, &previous) == false) {
    free(e);
    pthread_mutex_unlock(&lru->mutex);
    return mtev_false;
  }
  if (previous) {
    struct lru_entry *p = container_of(previous, struct lru_entry, key);
    TAILQ_REMOVE(&lru->lru_cache, p, list_entry);
    mtev_lru_release(lru, p);
  }
  add_lru_cache_no_lock(lru, e);
  pthread_mutex_unlock(&lru->mutex);
  return mtev_true;
}

mtev_lru_entry_token
mtev_lru_get(mtev_lru_t *c, const char *key, size_t key_len, void **value)
{
  struct lru_key *tempkey = NULL;
  if (key_len <= ALLOCA_LIMIT) {
    tempkey = alloca(sizeof(struct lru_key) + key_len);
  } else {
    tempkey = malloc(sizeof(struct lru_key) + key_len);
  }
  tempkey->key_len = key_len;
  memcpy(tempkey->key, key, key_len);
  
  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, tempkey);
  pthread_mutex_lock(&c->mutex);
  void *entry = ck_hs_get(&c->hash, hash, tempkey);
  if (key_len > ALLOCA_LIMIT) {
    free(tempkey);
  }

  if (entry != NULL) {
    struct lru_entry *r = container_of(entry, struct lru_entry, key);
    touch_lru_cache_no_lock(c, r);
    ck_pr_inc_64(&r->ref_cnt);
    pthread_mutex_unlock(&c->mutex);
    *value = r->entry;
    return r;
  }
  pthread_mutex_unlock(&c->mutex);
  *value = NULL;
  return NULL;
}

void
mtev_lru_release(mtev_lru_t *c, mtev_lru_entry_token token)
{
  bool zero = false;
  if (token == NULL) {
    return;
  }
  struct lru_entry *r = (struct lru_entry *)token;

  ck_pr_dec_64_zero(&r->ref_cnt, &zero);
  if (zero) {
    /* free it */
    c->free_fn(r->entry);
    free(r);
  }
}


void *
mtev_lru_remove(mtev_lru_t *c, const char *key, size_t key_len)
{

  struct lru_key *tempkey = NULL;
  if (key_len <= ALLOCA_LIMIT) {
    tempkey = alloca(sizeof(struct lru_key) + key_len);
  } else {
    tempkey = malloc(sizeof(struct lru_key) + key_len);
  }
  tempkey->key_len = key_len;
  memcpy(tempkey->key, key, key_len);

  unsigned long hash = CK_HS_HASH(&c->hash, lru_entry_hash, tempkey);
  void *rval = NULL;
  pthread_mutex_lock(&c->mutex);
  void *entry = ck_hs_remove(&c->hash, hash, tempkey);
  if (key_len > ALLOCA_LIMIT) {
    free(tempkey);
  }
  if (entry != NULL) {
    struct lru_entry *r = container_of(entry, struct lru_entry, key);
    if (c->max_entries > 0) {
      TAILQ_REMOVE(&c->lru_cache, r, list_entry);
    }
    c->lru_cache_size--;
    rval = r->entry;
    r->entry = NULL;
    mtev_lru_release(c, r);

    /* when removing, perform GC every GC_CADENCE changes */
    int ec = ck_pr_load_32(&c->expire_count);
    if (ec == GC_CADENCE && ck_hs_count(&c->hash) > 0) {
      c->expire_count = 0;
      ck_hs_gc(&c->hash, GC_CADENCE, (mtev_rand() % ck_hs_count(&c->hash)));
    }
    c->expire_count++;
  }
  pthread_mutex_unlock(&c->mutex);
  return rval;
}

int32_t
mtev_lru_size(mtev_lru_t *c)
{
  return c->lru_cache_size;
}
