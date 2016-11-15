#include <mtev_hyperloglog.h>
#include <mtev_time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);


int main(int argc, char **argv) 
{
  char s[256];
  mtev_hyperloglog_t *hll = mtev_hyperloglog_alloc(20);
  
  for (int i = 0; i < 1000000; i++) {
    sprintf(s, "%d some string", i);
    mtev_hyperloglog_add(hll, s, strlen(s));
  }

  int zc = 0;
  double est = mtev_hyperloglog_size(hll);

  if (est < 900000 || est > 1100000) {
    FAIL("Estimate count %f is too far off", est);
  } else {

    printf("SUCCESS, estimate: %f\n", est);
  }
  mtev_hyperloglog_destroy(hll);
}
