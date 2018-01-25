#include <mtev_huge_hash.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int failed;

void *thread_func(void *arg) 
{
  mtev_huge_hash_t *h = arg;

  pthread_t me = pthread_self();

  char key[100];
  for (int i = 0; i < 100; i++) {
    sprintf(key, "%lu-%d", (unsigned long) me, i);
    mtev_huge_hash_store(h, key, strlen(key), key, strlen(key));
  }

  return NULL;
}

#define THREAD_COUNT 4

static int do_test() {
  mtev_huge_hash_t *hash = mtev_huge_hash_create("/var/tmp/huge_hash_test");

  pthread_t threads[THREAD_COUNT];
  for (int i = 0; i < THREAD_COUNT; i++) {
    pthread_create(&threads[i], NULL, thread_func, hash);
  }

  for (int i = 0; i < THREAD_COUNT; i++) {
    pthread_join(threads[i], NULL);
  }

  mtev_huge_hash_iter_t *iter = mtev_huge_hash_create_iter(hash);

  while(mtev_huge_hash_adv(iter)) {
    size_t key_len;
    const char *k = (const char *)mtev_huge_hash_iter_key(iter, &key_len); 
    printf("%.*s\n", key_len, k);
  }

  mtev_huge_hash_destroy_iter(iter);
  mtev_huge_hash_destroy(hash);
  return 0;
}

int main(int argc, char **argv) 
{
  do_test();
  return 0;
}
