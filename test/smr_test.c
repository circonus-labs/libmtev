#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "eventer/eventer.h"
#include "mtev_defines.h"
#include "mtev_conf.h"
#include "mtev_listener.h"
#include "mtev_memory.h"
#include "mtev_main.h"
#include "mtev_console.h"
#include "mtev_perftimer.h"
#include "mtev_rand.h"
#include "mtev_log.h"

/* test repeatedly allocates and frees
 * NSLOTS worth of BSIZE byte buffers.
 */
#define NSLOTS 128
#define BSIZE 64
int NITERS = 50000;
int NTHREAD = 4;
char *memslots[NSLOTS] = { 0 };

static uint64_t gbl = 0;

void *thr_alloc_free(void *unused) {
  (void)unused;
  mtev_memory_init_thread();
  for(int iters=0; iters<NITERS/2; iters++) {
    mtev_memory_begin();
    for(int i=0; i<NSLOTS; i++) {
      mtev_memory_safe_free(memslots[i]);
      memslots[i] = mtev_memory_safe_malloc(BSIZE);
    }
    mtev_memory_end();
    usleep(2);
  }
  mtev_memory_fini_thread();
  return NULL;
}

void *thr_access(void *unused) {
  (void)unused;
  mtev_memory_init_thread();
  for(int iters=0; iters<NITERS/5; iters++) {
    char *my_memslots[NSLOTS];
    mtev_memory_begin();
    for(int i=0; i<NSLOTS; i++) {
      my_memslots[i] = memslots[i];
    }
    usleep(100); /* they've likely been release. */
    for(int i=0; i<NSLOTS; i++) {
      if(my_memslots[i]) {
        gbl += my_memslots[i][BSIZE-1];
      }
    }
    mtev_memory_end();
  }
  mtev_memory_fini_thread();
  pthread_exit(NULL);
}

int child_main() {
  mtev_perftimer_t timer;
  int i;
  void *ignored;

  mtev_conf_load(NULL);
  eventer_init();
  mtev_console_init("smr_test");
  mtev_listener_init("smr_test");
  eventer_loop_return();

  pthread_t tid, thrtid[NTHREAD];
  pthread_create(&tid, NULL, thr_alloc_free, NULL);

  for(i=0; i<NTHREAD; i++) {
    pthread_create(&thrtid[i], NULL, thr_access, NULL);
  }
  for(i=0; i<NTHREAD; i++) {
    void *ignored;
    pthread_join(tid, &ignored);
  }
  pthread_join(tid, &ignored);
  sleep(2);
  exit(0);
  return 0;
}

int main(int argc, char **argv) {
  if(argc > 1) {
    NITERS = atoi(argv[1]);
  }

  if(argc > 2) {
    NTHREAD = atoi(argv[2]);
  }

  mtev_memory_init();
  mtev_main("smr_test", "smr_test.conf", false, true,
        MTEV_LOCK_OP_LOCK, NULL, NULL, NULL,
       child_main);
  return 0;
}
