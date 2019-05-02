#include <mtev_time.h>
#include <mtev_thread.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);

#define loop_count 10000000

int main(int argc, char **argv) 
{
  mtev_thread_init();
  mtev_time_start_tsc();
  mtev_hrtime_t start = mtev_sys_gethrtime();
  uint64_t nstart = mtev_get_nanos();
  usleep(1000000);

  uint64_t nend = mtev_get_nanos();
  mtev_hrtime_t end = mtev_sys_gethrtime();

  printf("**** 1 second usleep\n");
  printf("* hrtime elapsed: %llu\n", end - start);
  printf("* nanos elapsed: %" PRIu64 "\n", nend - nstart);

  start = mtev_sys_gethrtime();
  for (int i = 0; i < loop_count; i++) {
    (void) mtev_get_nanos();
  }
  end = mtev_sys_gethrtime();

  printf("**** call mtev_get_nanos(), %d times\n", loop_count);
  printf("* hrtime elapsed: %llu\n", end - start);
  
  start = mtev_sys_gethrtime();
  for (int i = 0; i < loop_count; i++) {
    (void) mtev_sys_gethrtime();
  }
  end = mtev_sys_gethrtime();

  printf("**** call mtev_gethrtime(), %d times\n", loop_count);
  printf("* hrtime elapsed: %llu\n", end - start);

  printf("* SUCCESS\n");
  return 0;
}
