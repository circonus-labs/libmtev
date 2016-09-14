#include <mtev_hash.h>
#include <pthread.h>
#include <stdio.h>

void *thread_func(void *arg) 
{
  mtev_hash_table *h = arg;

  pthread_t me = pthread_self();

  char *key = NULL;
  for (int i = 0; i < 100; i++) {
    asprintf(&key, "%lu-%d", (unsigned long) me, i);
    mtev_hash_store(h, key, strlen(key), key);
  }

  return NULL;
}

#define THREAD_COUNT 4

static void do_test(mtev_hash_lock_mode_t lock_mode) {
  mtev_hash_table hash;

  mtev_hash_init_locks(&hash, 400, lock_mode);

  pthread_t threads[THREAD_COUNT];
  for (int i = 0; i < THREAD_COUNT; i++) {
    pthread_create(&threads[i], NULL, thread_func, &hash);
  }

  for (int i = 0; i < THREAD_COUNT; i++) {
    pthread_join(threads[i], NULL);
  }

  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

  const char *k;
  int klen;
  void *data;

  while(mtev_hash_next(&hash, &iter, &k, &klen, &data)) {
    printf("%s\n", k);
  }

  mtev_hash_destroy(&hash, free, NULL);
}

int main(int argc, char **argv) 
{
  printf("MUTEX TEST\n");
  do_test(MTEV_HASH_LOCK_MODE_MUTEX);
  printf("SPIN TEST\n");
  do_test(MTEV_HASH_LOCK_MODE_SPIN);

  // this last one should do bad things.
  printf("NONE TEST, expect crash\n");
  do_test(MTEV_HASH_LOCK_MODE_NONE);

  return 0;
}
