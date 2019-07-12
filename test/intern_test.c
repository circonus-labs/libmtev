#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "eventer/eventer.h"
#include "mtev_defines.h"
#include "mtev_conf.h"
#include "mtev_listener.h"
#include "mtev_memory.h"
#include "mtev_main.h"
#include "mtev_intern.h"
#include "mtev_console.h"
#include "mtev_perftimer.h"
#include "mtev_rand.h"
#include "mtev_log.h"

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
static void wl_intern_release_double(void *c, mtev_intern_t i) {
  mtev_intern_pool_t **p = c;
  mtev_intern_release_pool(*p, i);
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

struct workload workload[] = {
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
  .name = "intern cleanup",
  .iters = 1,
  .acquire = wl_intern_acquire,
  .release = wl_intern_release_double,
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

#define WORKLOADS (sizeof(workload)/sizeof(*workload))

char **words = NULL;
int word_cnt = 0;
void load_words(void) {
  int cnt = 0;
  char buff[1024];
  FILE *fp = fopen("/usr/share/dict/words", "rb");
  if(fp == NULL) {
    fprintf(stderr, "Skipping test, no /usr/share/dict/words (or variant)\n");
    exit(0);
  }
  while(fgets(buff, sizeof(buff), fp)) cnt++;
  rewind(fp);
  words = calloc(cnt, sizeof(*words));
  while(fgets(buff, sizeof(buff), fp)) {
    if(strlen(buff) < 1) continue;
    if(buff[strlen(buff)-1] == '\n') buff[strlen(buff)-1] = '\0';
    int upsize = mtev_rand() % 4096;
    if(upsize < strlen(buff)) upsize = strlen(buff);
    char *str = malloc(upsize+1);
    memset(str, 'x', upsize);
    str[upsize] = '\0';
    memcpy(str, buff, strlen(buff));
    words[word_cnt++] = str;
  }
  fclose(fp);
}
void *thr(void *closure) {
  int cnt = 0;
  struct tc *info = closure;
  const struct workload *w = info->wl;
  mtev_memory_init_thread();

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

  mtev_memory_fini_thread();
  return NULL;
}

void *singles(void *unused) {
  (void)unused;
  mtev_memory_init_thread();
  for(int i=0; i<50000; i++) {
    mtev_intern_t mi = mtev_intern_pool_str(pool, words[0], strlen(words[0]));
    mtev_intern_release(mi);
  }
  mtev_memory_fini_thread();
  pthread_exit(NULL);
}

int NTHREAD = 4;
int NREPS = 1;
const char *path = NULL;

int child_main() {
  mtev_perftimer_t timer;
  int64_t elapsed;
  int i, cnt, loops = 2;
  mtev_intern_pool_t *pools[2];

  mtev_conf_load(NULL);
  eventer_init();
  mtev_console_init("intern_test");
  mtev_listener_init("intern_test");
  eventer_loop_return();
  load_words();
  struct tc *info = calloc(NTHREAD, sizeof(*info));
  mtev_intern_pool_attr_t attr = {
    .extent_size = 1 << 22,
    .estimated_item_count = 1 << 20,
    .backing_directory = path
  };
  pools[0] = mtev_intern_pool_new(&attr);
  attr.extent_size = 0;
  attr.backing_directory = NULL;
  pools[1] = mtev_intern_pool_new(&attr);

  double ns_per_op[WORKLOADS];
  printf("concurrency: %d\n", NTHREAD);
  for(int reps=0; reps<NREPS; reps++) {
  for(int p=0; p<2; p++) {
  pool = pools[p];
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
    printf("%10s%30s %12.0f/s (%6.1f ns/op)\n", p ? "malloc" : "extent", workload[wl].name,
           1000000000.0 * (double)cnt /(double)elapsed, ns_per_op[wl]);
  }
  }
  }
  for(int p=0; p<2; p++) {
  pool = pools[p];
  mtev_perftimer_start(&timer);
  for(i=0; i<NTHREAD; i++) {
    pthread_create(&info[i].tid, NULL, singles, NULL);
  }
  for(i=0; i<NTHREAD; i++) {
    void *ignored;
    pthread_join(info[i].tid, &ignored);
  }
  elapsed = mtev_perftimer_elapsed(&timer);
  printf(" %s contended add/remove %6.1f /s\n", p ? "malloc" : "extent", 1000000000.0 * 1000000.0 * (double)i / (double)elapsed);
  }
  free(info);
  if(getenv("PAUSE") && !strcmp(getenv("PAUSE"),"1")) pause();
  exit(0);
  return 0;
}

int main(int argc, char **argv) {
  if(argc > 1) {
    NTHREAD = atoi(argv[1]);
  }
  if(argc > 2) {
    path = argv[2];
    if(!strcmp(path,"none")) path = NULL;
  }
  if(argc > 3) {
    NREPS = atoi(argv[3]);
  }

  mtev_memory_init();
  mtev_main("intern_test", "intern_test.conf", false, true,
        MTEV_LOCK_OP_LOCK, NULL, NULL, NULL,
       child_main);
  return 0;
}
