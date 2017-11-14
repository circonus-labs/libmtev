#include <mtev_defines.h>
#include <mtev_memory.h>
#include <mtev_frrh.h>
#include <mtev_perftimer.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>

#define KEYSPACE 10000
#define KEYLEN 100
#define ITERS 10000000
#define HASHSIZE 100000 
#define PROB UINT_MAX/100

int main() {
  uint32_t prob = PROB;
  mtev_perftimer_t start;
  uint64_t elapsed_slow, elapsed;
  char **keys = calloc(KEYSPACE, sizeof(*keys));
  unsigned char sha256[SHA256_DIGEST_LENGTH];
  mtev_frrh_t *cache;

  for(int i=0; i<KEYSPACE; i++) {
    keys[i] = calloc(1, KEYLEN);
    *(int *)keys[i] = i;
  }

  mtev_memory_init();
  cache = mtev_frrh_alloc(HASHSIZE, SHA256_DIGEST_LENGTH, PROB,
                          NULL, mtev_memory_safe_malloc,
                          mtev_memory_safe_free);

  mtev_perftimer_start(&start);
  for(int j=0; j<ITERS; j++) {
    char *key = keys[j % KEYSPACE];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, key, KEYLEN);
    SHA256_Final(sha256, &ctx);
  }
  elapsed_slow = mtev_perftimer_elapsed(&start);
  fprintf(stderr, "SHA %f ns/op\n",
          (double)elapsed_slow/(double)ITERS);

  mtev_perftimer_start(&start);
  for(int j=0; j<ITERS; j++) {
    char *key = keys[j % KEYSPACE];
    const unsigned char *hash = mtev_frrh_get(cache, key, KEYLEN);
    if(hash == NULL) {
      SHA256_CTX ctx;
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, key, KEYLEN);
      SHA256_Final(sha256, &ctx);
      hash = sha256;
      mtev_frrh_set(cache, key, KEYLEN, hash);
    }
  }
  elapsed = mtev_perftimer_elapsed(&start);
  fprintf(stderr, "%d iters, %d keys, %d frrh, %f%% prob : %" PRIu64 "ns\n",
          ITERS, KEYSPACE, HASHSIZE, 100*((double)prob/(double)UINT_MAX),
          elapsed);
  uint64_t accesses, hits;
  mtev_frrh_stats(cache, &accesses, &hits);
  fprintf(stderr, "%f ns/op, %" PRIu64 " accesses, %" PRIu64 " hits.\n",
          (double)elapsed/(double)ITERS, accesses, hits);
  return 0;
}
