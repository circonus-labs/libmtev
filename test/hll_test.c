#include <mtev_hyperloglog.h>
#include <mtev_time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);


int main(int argc, char **argv) 
{
  uuid_t uuid;
  char s[PATH_MAX];
  srand(time(NULL));

  mtev_hyperloglog_t *hll = mtev_hyperloglog_alloc(16);
  mtev_hrtime_t start = mtev_gethrtime();
  for (int i = 0; i < 10000000; i++) {
    sprintf(s, "some string %d %d %d %d %d %d ", rand(), rand(), rand(), rand(), rand(), rand());
    mtev_hyperloglog_add(hll, s, strlen(s));
  }
  mtev_hrtime_t end = mtev_gethrtime();

  printf("Filling took %llu nanos\n", end - start);

  int zc = 0;
  start = mtev_gethrtime();
  double est = mtev_hyperloglog_size(hll);
  end = mtev_gethrtime();

  printf("Size took %llu nanos\n", end - start);


  if (est < 9000000 || est > 11000000) {
    FAIL("Estimate count %f is too far off", est);
  } else {
    printf("SUCCESS, estimate: %f\n", est);
  }

  hll = mtev_hyperloglog_alloc(16);
  start = mtev_gethrtime();
  for (int i = 0; i < 10000; i++) {
    sprintf(s, "some string %d %d %d %d %d %d ", rand(), rand(), rand(), rand(), rand(), rand());
    mtev_hyperloglog_add(hll, s, strlen(s));
  }
  end = mtev_gethrtime();

  printf("Filling took %llu nanos\n", end - start);

  start = mtev_gethrtime();
  est = mtev_hyperloglog_size(hll);
  end = mtev_gethrtime();

  printf("Size took %llu nanos\n", end - start);


  if (est < 9000 || est > 11000) {
    FAIL("Estimate count %f is too far off", est);
  } else {
    printf("SUCCESS, estimate: %f\n", est);
  }

  mtev_hyperloglog_destroy(hll);
}
