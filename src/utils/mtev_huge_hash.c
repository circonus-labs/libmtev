#include "mtev_huge_hash.h"
#include "mtev_log.h"
#include "mtev_mkdir.h"
#ifdef HAVE_LMDB
#include <lmdb.h>
#endif
#include <ck_rwlock.h>
#include <errno.h>
#include <stdio.h>

struct mtev_huge_hash {
#ifdef HAVE_LMDB
  MDB_env *env;
  MDB_dbi dbi;
#endif
  char *path;
  ck_rwlock_t resize_lock;
};

struct mtev_huge_hash_iter {
  mtev_huge_hash_t *hh;
#ifdef HAVE_LMDB
  MDB_cursor *cursor;
  MDB_val key;
  MDB_val data;
#endif
  mtev_boolean before_first;
};

#define RESIZE_FACTOR 1.5
#ifdef HAVE_LMDB
static void
map_resize(mtev_huge_hash_t *hh)
{

  MDB_envinfo mei;
  MDB_stat mst;
  uint64_t new_mapsize;

  /* prevent new transactions on the write side */
  ck_rwlock_write_lock(&hh->resize_lock);

  /* check if resize is necessary.. another thread may have already resized. */
  mdb_env_info(hh->env, &mei);
  mdb_env_stat(hh->env, &mst);

  uint64_t size_used = mst.ms_psize * mei.me_last_pgno;

  /* resize on 80% full */
  if ((double)size_used / mei.me_mapsize < 0.8) {
    ck_rwlock_write_unlock(&hh->resize_lock);
    return;
  }

  new_mapsize = (double)mei.me_mapsize * RESIZE_FACTOR;
  new_mapsize += (new_mapsize % mst.ms_psize);

  mdb_env_set_mapsize(hh->env, new_mapsize);

  mtevL(mtev_notice, "mtev_huge_hash Mapsize increased. old: %" PRIu64 " MiB, new: %" PRIu64 " MiB\n",
        mei.me_mapsize / (1024 * 1024), new_mapsize / (1024 * 1024));

  ck_rwlock_write_unlock(&hh->resize_lock);
}
#endif

static mtev_boolean
huge_hash_mkdir(const char *path)
{
  char to_make[PATH_MAX];
  size_t copy_len = strlen(path);
  memset(to_make, 0, PATH_MAX);
  memcpy(to_make, path, MIN(copy_len, PATH_MAX));
  strlcat(to_make, "/dummy", sizeof(to_make));
  if (mkdir_for_file(to_make, 0777)) {
    mtevL(mtev_error, "mkdir %s: %s\n", to_make, strerror(errno));
    return mtev_false;
  }
  return mtev_true;
}


mtev_huge_hash_t *mtev_huge_hash_create(const char *path)
{
#ifndef HAVE_LMDB
  return NULL;
#else
  mtev_huge_hash_t *hh;
  int rc;
  MDB_env *env;

  if (huge_hash_mkdir(path) != mtev_true) {
    return NULL;
  }

  rc = mdb_env_create(&env);
  if (rc != 0) {
    errno = rc;
    return NULL;
  }

  /* let lots of threads read us */
  rc = mdb_env_set_maxreaders(env, 1024);
  if (rc != 0) {
    errno = rc;
    mdb_env_close(env);
    return NULL;
  }

  rc = mdb_env_open(env, path, MDB_NOMETASYNC | MDB_NOSYNC | MDB_NOMEMINIT, 0644);
  if (rc != 0) {
    errno = rc;
    mdb_env_close(env);
    return NULL;
  }

  MDB_txn *txn;
  MDB_dbi dbi;
  rc = mdb_txn_begin(env, NULL, 0, &txn);
  if (rc != 0) {
    errno = rc;
    mdb_env_close(env);
    return NULL;
  }
  rc = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
  if (rc != 0) {
    mdb_txn_abort(txn);
    mdb_env_close(env);
    errno = rc;
    return NULL;
  }
  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    mdb_txn_abort(txn);
    mdb_env_close(env);
    errno = rc;
    return NULL;
  }
  
  hh = (mtev_huge_hash_t *)malloc(sizeof(mtev_huge_hash_t));
  if (hh == NULL) {
    mtevL(mtev_error, "Cannot allocate mtev_huge_hash_t, OOM?\n");
    return NULL;
  }
  hh->env = env;
  hh->dbi = dbi;
  hh->path = strdup(path);
  ck_rwlock_init(&hh->resize_lock);
  return hh;
#endif
}

void mtev_huge_hash_close(mtev_huge_hash_t *hh)
{
#ifdef HAVE_LMDB
  /* no transactions can be in flight */
  ck_rwlock_write_lock(&hh->resize_lock);
  mdb_dbi_close(hh->env, hh->dbi);
  mdb_env_close(hh->env);
  ck_rwlock_write_unlock(&hh->resize_lock);
  free(hh->path);
  free(hh);
#endif
}

void mtev_huge_hash_destroy(mtev_huge_hash_t *hh)
{
#ifdef HAVE_LMDB
  char data_path[PATH_MAX];
  char lock_path[PATH_MAX];

  /* no transactions can be in flight */
  ck_rwlock_write_lock(&hh->resize_lock);
  mdb_dbi_close(hh->env, hh->dbi);
  mdb_env_close(hh->env);

  snprintf(data_path, PATH_MAX, "%s/data.mdb", hh->path);
  snprintf(lock_path, PATH_MAX, "%s/lock.mdb", hh->path);

  unlink(data_path);
  unlink(lock_path);

  ck_rwlock_write_unlock(&hh->resize_lock);

  free(hh->path);
  free(hh);
#endif
}

mtev_boolean 
mtev_huge_hash_replace(mtev_huge_hash_t *hh, void *k, size_t klen, void *val, size_t dlen)
{
#ifndef HAVE_LMDB
  return mtev_false;
#else
  MDB_val key, data;
  MDB_txn *txn;
  MDB_cursor *cursor;
  int rc;

 put_retry:
  ck_rwlock_read_lock(&hh->resize_lock);
  rc = mdb_txn_begin(hh->env, NULL, 0, &txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  rc = mdb_cursor_open(txn, hh->dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  key.mv_data = k;
  key.mv_size = klen;
  data.mv_data = val;
  data.mv_size = dlen;
  
  rc = mdb_cursor_put(cursor, &key, &data, 0);
  if (rc == MDB_MAP_FULL) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    map_resize(hh);
    goto put_retry;
  } else if (rc != 0) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  mdb_cursor_close(cursor);
  rc = mdb_txn_commit(txn);
  if (rc == MDB_MAP_FULL) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    map_resize(hh);
    goto put_retry;
  } else if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  ck_rwlock_read_unlock(&hh->resize_lock);
  return mtev_true;
#endif
}

mtev_boolean 
mtev_huge_hash_store(mtev_huge_hash_t *hh, void *k, size_t klen, void *val, size_t dlen)
{
#ifndef HAVE_LMDB
  return mtev_false;
#else
  MDB_val key, data;
  MDB_txn *txn;
  MDB_cursor *cursor;
  int rc;

 put_retry:
  ck_rwlock_read_lock(&hh->resize_lock);
  rc = mdb_txn_begin(hh->env, NULL, 0, &txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  rc = mdb_cursor_open(txn, hh->dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  key.mv_data = k;
  key.mv_size = klen;
  rc = mdb_cursor_get(cursor, &key, &data, MDB_SET);
  if (rc == 0) {
    /* key already exists */
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  data.mv_data = val;
  data.mv_size = dlen;

  rc = mdb_cursor_put(cursor, &key, &data, 0);
  if (rc == MDB_MAP_FULL) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    map_resize(hh);
    goto put_retry;
  } else if (rc != 0) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  mdb_cursor_close(cursor);
  rc = mdb_txn_commit(txn);
  if (rc == MDB_MAP_FULL) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    map_resize(hh);
    goto put_retry;
  } else if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  ck_rwlock_read_unlock(&hh->resize_lock);
  return mtev_true;
#endif
}


void *
mtev_huge_hash_retrieve(mtev_huge_hash_t *hh, void *k, size_t klen, size_t *data_len)
{
#ifndef HAVE_LMDB
  return NULL;
#else
  MDB_val key, data;
  MDB_txn *txn;
  MDB_cursor *cursor;
  int rc;

  *data_len = 0;

  ck_rwlock_read_lock(&hh->resize_lock);
  rc = mdb_txn_begin(hh->env, NULL, MDB_RDONLY, &txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return NULL;
  }

  rc = mdb_cursor_open(txn, hh->dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return NULL;
  }

  key.mv_data = k;
  key.mv_size = klen;
  rc = mdb_cursor_get(cursor, &key, &data, MDB_SET);
  if (rc != 0) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return NULL;
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);
  ck_rwlock_read_unlock(&hh->resize_lock);
  *data_len = data.mv_size;
  return data.mv_data;
#endif
}

mtev_boolean
mtev_huge_hash_delete(mtev_huge_hash_t *hh, void *k, size_t klen)
{
#ifndef HAVE_LMDB
  return mtev_false;
#else
  MDB_val key, data;
  MDB_txn *txn;
  MDB_cursor *cursor;
  int rc;

  ck_rwlock_read_lock(&hh->resize_lock);
  rc = mdb_txn_begin(hh->env, NULL, 0, &txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  rc = mdb_cursor_open(txn, hh->dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  key.mv_data = k;
  key.mv_size = klen;
  rc = mdb_cursor_get(cursor, &key, &data, MDB_SET);
  if (rc != 0) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  rc = mdb_cursor_del(cursor, 0);
  if (rc != 0) {
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }

  mdb_cursor_close(cursor);
  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    return mtev_false;
  }
  ck_rwlock_read_unlock(&hh->resize_lock);
  return mtev_true;
#endif
}

size_t mtev_huge_hash_size(mtev_huge_hash_t *hh)
{
#ifndef HAVE_LMDB
  return 0;
#else
  MDB_stat mst;

  mdb_env_stat(hh->env, &mst);

  return mst.ms_entries;
#endif
}

mtev_huge_hash_iter_t *
mtev_huge_hash_create_iter(mtev_huge_hash_t *hh)
{
#ifndef HAVE_LMDB
  return NULL;
#else
  int rc;
  MDB_txn *txn;
  mtev_huge_hash_iter_t *it = (mtev_huge_hash_iter_t *)malloc(sizeof(mtev_huge_hash_iter_t));

  ck_rwlock_read_lock(&hh->resize_lock);
  rc = mdb_txn_begin(hh->env, NULL, MDB_RDONLY, &txn);
  if (rc != 0) {
    ck_rwlock_read_unlock(&hh->resize_lock);
    free(it);
    return NULL;
  }

  rc = mdb_cursor_open(txn, hh->dbi, &it->cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    ck_rwlock_read_unlock(&hh->resize_lock);
    free(it);
    return NULL;
  }
  it->before_first = mtev_true;
  it->hh = hh;
  return it;
#endif
}

void mtev_huge_hash_destroy_iter(mtev_huge_hash_iter_t *it)
{
#ifdef HAVE_LMDB
  MDB_txn *txn = mdb_cursor_txn(it->cursor);
  mdb_cursor_close(it->cursor);
  mdb_txn_abort(txn);
  ck_rwlock_read_unlock(&it->hh->resize_lock);
  free(it);
#endif
}

mtev_boolean 
mtev_huge_hash_adv(mtev_huge_hash_iter_t *iter)
{
#ifndef HAVE_LMDB
  return mtev_false;
#else

  MDB_cursor_op op = MDB_NEXT;
  if (iter->before_first) {
    op = MDB_FIRST;
    iter->before_first = mtev_false;
  }
  return mdb_cursor_get(iter->cursor, &iter->key, &iter->data, op) == 0;
#endif
}

void *mtev_huge_hash_iter_key(mtev_huge_hash_iter_t *iter, size_t *key_len)
{
#ifndef HAVE_LMDB
  return NULL;
#else

  *key_len = iter->key.mv_size;
  return iter->key.mv_data;
#endif
}

void *mtev_huge_hash_iter_val(mtev_huge_hash_iter_t *iter, size_t *val_len)
{
#ifndef HAVE_LMDB
  return NULL;
#else
  *val_len = iter->data.mv_size;
  return iter->data.mv_data;
#endif
}

