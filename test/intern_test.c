#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "mtev_defines.h"
#include "mtev_intern.h"
#include "mtev_perftimer.h"
#include "mtev_rand.h"

struct workload {
  const char *name;
  int iters;
  mtev_intern_t (*acquire)(void *, const char *, size_t len);
  void (*release)(void *, mtev_intern_t);
  void *closure;
};
struct tc {
  pthread_t tid;
  const struct workload *wl;
  int cnt;
};

mtev_intern_pool_t *pool = NULL;

static mtev_intern_t wl_intern_acquire(void *c, const char *k, size_t l) {
  mtev_intern_pool_t **p = c;
  return mtev_intern_pool_str(*p, k, l);
}
static void wl_intern_release(void *c, mtev_intern_t i) {
  mtev_intern_pool_t **p = c;
  mtev_intern_release_pool(*p, i);
}
static mtev_intern_t wl_strdup(void *c, const char *k, size_t l) {
  mtev_intern_t i;
  i.opaque1 = (uintptr_t)strdup(k);
  return i;
}
static void wl_free(void *c, mtev_intern_t i) {
  free((void *)i.opaque1);
}

struct workload workload[3] = {
 {
  .name = "intern competing insert",
  .iters = 1,
  .acquire = wl_intern_acquire,
  .release = NULL,
  .closure = &pool
 },
 /* ^^^ does the insert */
 /* This next one is lookup by the fact that it runs second */
 {
  .name = "intern competing lookup",
  .iters = 1,
  .acquire = wl_intern_acquire,
  .release = wl_intern_release,
  .closure = &pool
 },
 {
  .name = "strdup",
  .iters = 1,
  .acquire = wl_strdup,
  .release = wl_free,
  .closure = NULL
 }
};

#define WORKLOADS 3

char **words = NULL;
int word_cnt = 0;
void load_words(void) {
  int cnt = 0;
  char buff[1024];
  FILE *fp = fopen("/usr/share/dict/words", "rb");
  if(fp == NULL) {
    fprintf(stderr, "Failed to open /usr/share/dict/words\n");
    exit(-1);
  }
  while(fgets(buff, sizeof(buff), fp)) cnt++;
  rewind(fp);
  words = calloc(cnt, sizeof(*words));
  while(fgets(buff, sizeof(buff), fp)) {
    if(strlen(buff) < 1) continue;
    if(buff[strlen(buff)-1] == '\n') buff[strlen(buff)-1] = '\0';
    words[word_cnt++] = strdup(buff);
  }
  fclose(fp);
}
void *thr(void *closure) {
  int cnt = 0;
  struct tc *info = closure;
  const struct workload *w = info->wl;

  info->cnt = 0;
  uint32_t off = mtev_rand() & 0x0fffffff;
  for(int i=0; i<w->iters; i++) {
    for(uint32_t j = 0; j < word_cnt; j++) {
      int idx = (j+off) % word_cnt;
      mtev_intern_t iv = w->acquire(w->closure, words[idx], strlen(words[idx]));
      if(w->release) w->release(w->closure, iv);
      info->cnt++;
    }
  }
  return NULL;
}

int NTHREAD = 10;
int main(int argc, char **argv) {
  mtev_perftimer_t timer;
  int64_t elapsed;
  int i, cnt, loops = 2;
  const char *path = NULL;

  load_words();
  if(argc > 1) {
    NTHREAD = atoi(argv[1]);
  }
  if(argc > 2) {
    path = argv[2];
  }

  struct tc *info = calloc(NTHREAD, sizeof(*info));
  mtev_intern_pool_attr_t attr = {
    .extent_size = 1 << 22,
    .estimated_item_count = 1 << 20,
    .backing_directory = path
  };
  pool = mtev_intern_pool_new(&attr);

  double ns_per_op[3];
  printf("concurrency: %d\n", NTHREAD);
  for(int wl=0; wl<WORKLOADS; wl++) {
    mtev_perftimer_start(&timer);
    for(i=0; i<NTHREAD; i++) {
      info[i].wl = &workload[wl];
      pthread_create(&info[i].tid, NULL, thr, &info[i]);
    }
    cnt = 0;
    for(i=0; i<NTHREAD; i++) {
      void *ignored;
      pthread_join(info[i].tid, &ignored);
      cnt += info[i].cnt;
    }
    elapsed = mtev_perftimer_elapsed(&timer);
    ns_per_op[wl] = 0;
    for(i=0; i<NTHREAD; i++) {
      ns_per_op[wl] += (double)elapsed / (double)info[i].cnt;
    }
    ns_per_op[wl] /= (double)NTHREAD;
    printf("%30s %12.0f/s (%6.1f ns/op)\n", workload[wl].name,
           1000000000.0 * (double)cnt /(double)elapsed, ns_per_op[wl]);
  }
  free(info);
}
