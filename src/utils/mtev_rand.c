#include "mtev_rand.h"
#include "mtev_time.h"

#include <openssl/rand.h>

static int rand_init = 0;

inline int
mtev_secure_rand(uint64_t *out)
{
  if(RAND_bytes((void *)out, sizeof(*out)) != 0) {
    return -1;
  }
  return 0;
}

void
mtev_rand_init(void){
  if(rand_init == 0) {
    uint64_t seed;
    if(mtev_secure_rand(&seed) != 0) seed = time(NULL);
    srand48((long int)seed);
    rand_init = 1;
  }
}

inline uint64_t
mtev_trysecure_rand(void) {
  uint64_t rv;
  if(mtev_secure_rand(&rv) == 0) return rv;
  return mtev_rand();
}

static __thread struct {
  unsigned short work[3];
  bool initialized;
} random_tracer_help;

inline uint64_t
mtev_rand(void)
{
  if(!random_tracer_help.initialized) {
    uint64_t scratch = 0, i;
    mtev_hrtime_t t;
    if(mtev_secure_rand(&scratch) != 0) {
      for(i=0;i<8;i++) {
        t = mtev_gethrtime();
        scratch = (scratch << 8) ^ t;
      }
    }
    memcpy(random_tracer_help.work, ((unsigned char *)&scratch)+2, 6);
  }
  /* coverity[DC.WEAK_CRYPTO] */
  uint64_t v = jrand48(random_tracer_help.work);
  /* coverity[DC.WEAK_CRYPTO] */
  v = (v << 31) ^ jrand48(random_tracer_help.work);
  /* coverity[DC.WEAK_CRYPTO] */
  v = (v << 31) ^ jrand48(random_tracer_help.work);
  return v;
}
