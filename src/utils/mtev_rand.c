#include "mtev_rand.h"

static int rand_init = 0;

void
mtev_rand_init(void){
  if(rand_init == 0) {
    srand48((long int)time(NULL));
    rand_init = 1;
  }
}

inline uint64_t
mtev_rand(void)
{
  uint64_t v = lrand48();
  v = (v << 31) | (uint64_t)lrand48();
  v = (v << 31) | (uint64_t)lrand48();
  return v;
}
