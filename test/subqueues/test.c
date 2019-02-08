#include <mtev_capabilities_listener.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_defines.h>
#include <mtev_dso.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_stats.h>
#include <mtev_perftimer.h>
#include <eventer/eventer.h>
#include <inttypes.h>
#include <ck_pr.h>

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
  const char *name;
  uint32_t jobs;
  uint32_t cost_s;
  uint32_t deadline_s;
  uint32_t work_calls;
  bool timeouts_expected;
  uint32_t cleanup_calls;
  uint32_t completion_calls;
  mtev_perftimer_t start;
  uint64_t duration;
} work_description_t;

work_description_t work[] = {
  { .name = "abusive", .jobs = 20, .cost_s = 1 },
  { .name = "abusive2", .jobs = 20, .cost_s = 1 },
  { .name = "abusive3", .jobs = 20, .cost_s = 1 },
  { .name = "abusive deadline", .jobs = 20, .cost_s = 1, .deadline_s = 1, .timeouts_expected = true },
  { .name = "fast", .jobs = 1000, .cost_s = 0 },
  { .name = "fast deadline", .jobs = 1000, .cost_s = 0, .deadline_s = 5 }
};
uint32_t todo = 0, done = 0;

#define APPNAME "subqueues"
static char *config_file = NULL;
static int debug = 1;
static int foreground = 1;

static int usage(const char *prog)
{
  fprintf(stderr, "%s <-c conffile>\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  return 2;
}

static void parse_cli_args(int argc, char *const *argv)
{
  int c;
  while ((c = getopt(argc, argv, "c:")) != EOF) {
    switch (c) {
    case 'c':
      config_file = optarg;
      break;
    }
  }
}

static int
toil(eventer_t e, int mask, void *c, struct timeval *now) {
  work_description_t *w = c;
  const char *type = "unknown";
  switch(mask) {
    case EVENTER_ASYNCH_WORK: ck_pr_inc_32(&w->work_calls); type = "work"; break;
    case EVENTER_ASYNCH_CLEANUP: ck_pr_inc_32(&w->cleanup_calls); type = "cleanup"; break;
    case EVENTER_ASYNCH_COMPLETE: ck_pr_inc_32(&w->completion_calls); type = "completion"; break;
  }
  mtevL(mtev_error, "Starting %s on %s\n", type, w->name);
  if(mask == EVENTER_ASYNCH_WORK && w->cost_s) sleep(w->cost_s);
  mtevL(mtev_error, "Ending %s on %s\n", type, w->name);
  if(mask == EVENTER_ASYNCH_COMPLETE) ck_pr_inc_32(&done);
  return 0;
}

static int child_main(void)
{
  /* reload out config, to make sure we have the most current */

  if (mtev_conf_load(NULL) == -1) {
    mtevL(mtev_debug, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_capabilities_listener_init();
  mtev_stats_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_conf_write_log();
  mtev_conf_watch_and_journal_watchdog((int (*)(void *)) mtev_conf_write_log, NULL);

  eventer_jobq_t *test_jobq = eventer_jobq_create_ms("test_jobq", EVENTER_JOBQ_MS_GC);
  eventer_jobq_set_concurrency(test_jobq, 4);

  for(int i=0; i<sizeof(work)/sizeof(*work); i++) {
    mtevL(mtev_error, "Starting: %s\n", work[i].name);
    for(int j=0; j<work[i].jobs; j++) {
      eventer_t e;
      if(work[i].deadline_s) {
        struct timeval deadline;
        mtev_gettimeofday(&deadline, NULL);
        deadline.tv_sec += work[i].deadline_s;
        e = eventer_alloc_asynch_timeout(toil, &work[i], &deadline);
      } else {
        e = eventer_alloc_asynch(toil, &work[i]);
      }
      todo++;
      eventer_add_asynch_subqueue(test_jobq, e, i);
    }
  }
  /* Lastly, spin up the event loop */
  eventer_loop_return();

  while(ck_pr_load_32(&done) < todo) {
    sleep(1);
  }
  mtevL(mtev_error, "%u/%u\n", done, todo);
  for(int i=0; i<sizeof(work)/sizeof(*work); i++) {
    work_description_t *w = &work[i];
    mtevL(mtev_error, "workload %s (%u/%u/%u)\n", w->name, w->work_calls, w->cleanup_calls, w->completion_calls);
    mtevAssert(w->timeouts_expected || w->jobs == w->work_calls);
    mtevAssert(w->jobs == w->cleanup_calls);
    mtevAssert(w->jobs == w->completion_calls);
  }
  return 0;
}

int main(int argc, char **argv)
{
  parse_cli_args(argc, argv);
  if (!config_file) exit(usage(argv[0]));

  mtev_memory_init();
  mtev_main(APPNAME, config_file, debug, foreground, MTEV_LOCK_OP_LOCK, NULL, NULL, NULL,
            child_main);
  return 0;
}
