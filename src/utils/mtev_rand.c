#include "mtev_rand.h"
#include "mtev_time.h"

#include <openssl/rand.h>

/* We leave this stub here for backware compatibility. */
#undef mtev_rand_init
void mtev_rand_init(void){ }


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
    if(mtev_rand_secure(&scratch) != 0) {
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

inline int
mtev_rand_secure(uint64_t *out)
{
  if(RAND_bytes((void *)out, sizeof(*out)) != 1) {
    return -1;
  }
  return 0;
}

inline uint64_t
mtev_rand_trysecure(void) {
  uint64_t rv;
  if(mtev_rand_secure(&rv) == 0) return rv;
  return mtev_rand();
}

size_t
mtev_rand_buf(void *vbuf, size_t len) {
  uint8_t *buf = vbuf;
  for(int i = 0; i < len; i+=sizeof(uint64_t)) {
    uint64_t rblob = mtev_rand();
    memcpy(buf+i, &rblob, (len-i < sizeof(uint64_t)) ? len - i : sizeof(uint64_t));
  }
  return len;
}

size_t
mtev_rand_buf_secure(void *vbuf, size_t len) {
  if(RAND_bytes(vbuf, len) != 1) return 0;
  return len;
}

size_t
mtev_rand_buf_trysecure(void *vbuf, size_t len) {
  uint8_t *buf = vbuf;
  for(int i = 0; i < len; i+=sizeof(uint64_t)) {
    uint64_t rblob = mtev_rand_trysecure();
    memcpy(buf+i, &rblob, (len-i < sizeof(uint64_t)) ? len - i : sizeof(uint64_t));
  }
  return len;
}
