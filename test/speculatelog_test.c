#include <mtev_defines.h>
#include <mtev_log.h>
#include <stdio.h>
int main(int argc, char *argv[])
{
  mtev_log_init_globals();
  mtev_log_stream_t *speculation = mtev_log_speculate(100, 65536);
  for (size_t index = 0; index < 100; index++)
    mtevL(speculation, "string %s i32 %d\n", "str1", (int) index);
  mtev_log_speculate_commit(mtev_stderr, speculation);

  speculation = mtev_log_speculate(100, 65536);
  for (size_t index = 0; index < 100; index++)
    mtevL(speculation, "discarded %s i32 %d\n", "str1", (int) index);
  mtev_log_speculate_commit(NULL, speculation);
  return 0;
}
