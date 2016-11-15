#include <mtev_hyperloglog.h>
#include <mtev_hash.h>
#include <mtev_log.h>

#include <math.h>

struct mtev_hyperloglog {
  uint8_t bitcount;
  size_t size;
  uint8_t *regs;
};

/* from the hyperloglog paper */
static double 
mtev_hyperloglog_alpha(uint8_t bitcount) {
  switch (bitcount) {
  case 4:
    return 0.673;
  case 5:
    return 0.697;
  case 6:
    return 0.709;
  default:
    return 0.7213 / (1 + 1.079 / (1 << bitcount));
  }
}

mtev_hyperloglog_t *
mtev_hyperloglog_alloc(int bitcount)
{
  if (bitcount < 4 || bitcount > 20) {
    mtevL(mtev_error, "Illegal bitcount for mtev_hyperloglog.  Must be between 4 and 20 inclusive\n");
    return NULL;
  }

  mtev_hyperloglog_t *hll = calloc(1, sizeof(struct mtev_hyperloglog));

  hll->bitcount = bitcount;
  hll->size = (size_t)1 << bitcount;
  hll->regs = calloc(hll->size, 1);
  
  return hll;
}

void 
mtev_hyperloglog_destroy(mtev_hyperloglog_t *hll)
{
  free(hll->regs);
  free(hll);
}

void 
mtev_hyperloglog_add(mtev_hyperloglog_t *hll, const void *data, size_t len)
{
  uint32_t hash, index;
  uint8_t bitarea;

  /* shift size */
  bitarea = 32 - hll->bitcount;

  /* share the hash function from the mtev_hash_table */
  hash = mtev_hash__hash(data, len, 0x6F61567A);

  /* pick initial index based on precision */
  index = hash >> bitarea;

  /* shift out the index bits from the hash */
  hash = hash << hll->bitcount | (1 << (hll->bitcount -1 ));

  /* count leading zeroes */
  int l = __builtin_clz(hash) + 1;

  /* save the register if we got bigger */
  if (l > hll->regs[index]) {
    hll->regs[index] = l;
  }
}

static inline double 
mtev_hyperloglog_estimate(mtev_hyperloglog_t *hll, int *zero_count)
{
  int c;
  double m, sum;

  c = (1 << hll->bitcount);
  m = mtev_hyperloglog_alpha(hll->bitcount) * c * c;
  sum = 0;

  for (int i=0; i < c; i++) {
    sum += 1.0 / (1 << hll->regs[i]);
  }
  return m / sum;
}

double 
mtev_hyperloglog_size(mtev_hyperloglog_t *hll) 
{
  int zc;
  double est = mtev_hyperloglog_estimate(hll, &zc);

  if (est <= (5.0 / 2.0 * (double)hll->size)) {
    if(zc > 0) {
      est = (double)hll->size * log((double)hll->size / zc);
    }
  } else if (est > (1.0 / 30.0) * 4294967296.0) {
    est = -4294967296.0 * log(1.0 - (est / 4294967296.0));
  }

  return est;
}





