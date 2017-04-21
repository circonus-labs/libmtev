#include <mtev_logbuf.h>
#include <stdio.h>

mtev_logbuf_el_t log_args[] = {{"string", MTEV_LOGBUF_TYPE_STRING},
                               {"i32", MTEV_LOGBUF_TYPE_INT32}};
mtev_logbuf_log_t *my_log;

static inline void log_string_then_int32(mtev_logbuf_t *logbuf, const char *str, int32_t i)
{
  struct timeval now;
  mtev_gettimeofday(&now, NULL);
  void *buf = mtev_logbuf_log_start(logbuf, my_log, now);
  mtev_logbuf_log_string(buf, my_log, 0, str);
  mtev_logbuf_log_int32(buf, my_log, 1, i);
  mtev_logbuf_log_commit(my_log, buf);
}

int main(int argc, char *argv[])
{
  mtev_log_init_globals();
  mtev_logbuf_t *logbuf = mtev_logbuf_create(2048, MTEV_LOGBUF_ONFULL_REJECT);
  my_log = mtev_logbuf_create_log("test_log", log_args, sizeof(log_args) / sizeof(log_args[0]));
  /* timestamps will be displayed from these logs, giving a sense of performance. */
  log_string_then_int32(logbuf, "str1", 123);
  log_string_then_int32(logbuf, "str2", 456);
  log_string_then_int32(logbuf, "str3", 789);
  log_string_then_int32(logbuf, "str4", 31337);
  mtev_logbuf_dump(mtev_stderr, logbuf);
  mtev_logbuf_destroy_log(my_log);
  mtev_logbuf_destroy(logbuf);
  /* and, for comparison purposes, times from direct mtevL calls */
  mtevL(mtev_stderr, "string %s i32 %d\n", "str1", 123);
  mtevL(mtev_stderr, "string %s i32 %d\n", "str2", 456);
  mtevL(mtev_stderr, "string %s i32 %d\n", "str3", 789);
  mtevL(mtev_stderr, "string %s i32 %d\n", "str4", 31337);
  return 0;
}
