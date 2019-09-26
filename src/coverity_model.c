typedef void (*NoitHashFreeFunc)(void *);
typedef int (*eventer_func_t)
             (struct _event *e, int mask, void *closure, struct timeval *tv);

int mtev_conf_get_string(void *base, char *path, char **val) {
  int is_ok;
  if(is_ok) {
    *val = __coverity_alloc_nosize__();
    return 1;
  }
  return 0;
}
void mtev_skiplist_insert(void *list, void *entry) {
  __coverity_escape__(entry);
}

int mtev_hash_store(void *h, void *k, int klen, void *data) {
  __coverity_escape__(k);
  __coverity_escape__(data);
}

int mtev_hash_replace(void *h, void *k, int klen, void *data,
                      NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree) {
  __coverity_escape__(k);
  __coverity_escape__(data);
}

int mtev_hash_set(void *h, void *k, int klen, void *data, void **oldk, void **olddata) {
  int is_ok;
  __coverity_escape__(k);
  __coverity_escape__(data);
  if(is_ok) {
    *oldk = __coverity_alloc__(klen);
    *olddata = __coverity_alloc_nosize__();
    return 1;
  } else {
    return 0;
  }
}

struct _event *eventer_alloc_asynch(eventer_func_t f, void *cl) {
  __coverity_escape__(cl);
  return __coverity_alloc__(32);
}
struct _event *eventer_alloc_recurrent(eventer_func_t f, void *cl) {
  __coverity_escape__(cl);
  return __coverity_alloc__(32);
}
void eventer_add(struct _event *e) {
  __coverity_escape__(e);
}
void eventer_add_recurrent(struct _event *e) {
  __coverity_escape__(e);
}
void eventer_add_timed(struct _event *e) {
  __coverity_escape__(e);
}
void eventer_add_asynch(void *q, struct _event *e) {
  __coverity_escape__(e);
}
void eventer_add_asynch_subqueue(void *q, struct _event *e, size_t sq) {
  __coverity_escape__(e);
}
void eventer_add_asynch_dep(void *q, struct _event *e) {
  __coverity_escape__(e);
}
void eventer_add_asynch_dep_subqueue(void *q, struct _event *e, size_t sq) {
  __coverity_escape__(e);
}

void ck_fifo_spsc_enqueue(void *q, void *e, void  *v) {
  __coverity_escape__(e);
  __coverity_escape__(v);
}

int ck_fifo_spsc_dequeue(void *q, void **v) {
  int is_ok;
  if(is_ok) {
    *v = __coverity_alloc_nosize__();
    return 1;
  }
  return 0;
}
