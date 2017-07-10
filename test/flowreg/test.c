#include <mtev_capabilities_listener.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_defines.h>
#include <mtev_dso.h>
#include <mtev_flow_regulator.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_stats.h>
#include <eventer/eventer.h>
#include <inttypes.h>

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

/*
 * test flow-regulator "stable" APIs under stress. multi-producer,
 * multi-consumer model. consumer takes on producer role when
 * re-enabling flow.
 */

typedef struct {
  mtev_flow_regulator_t *flowreg;
  unsigned int work_total;
  unsigned int work_added;
  unsigned int work_removed;
  unsigned int work_last_check;
} work_description_t;

#define APPNAME "flowreg_test"
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

static eventer_jobq_t *test_jobq;

int test_job_cb(eventer_t e, int mask, void *v_work_description, struct timeval *now);

void add_jobs_loop(work_description_t *work_description)
{
  while (mtev_flow_regulator_stable_try_raise_one(work_description->flowreg)) {
    unsigned int old_work_added;
    do {
      old_work_added = ck_pr_load_uint(&work_description->work_added);
    } while (old_work_added < work_description->work_total &&
             !ck_pr_cas_uint(&work_description->work_added, old_work_added, old_work_added + 1));
    if (old_work_added >= work_description->work_total) {
      /* ran out of work to do, so undo the `raise_one` we're handling. */
      mtev_flow_regulator_stable_lower(work_description->flowreg, 1);
    }
    else {
      eventer_t e = eventer_alloc_asynch(test_job_cb, (void *) work_description);
      eventer_add_asynch(test_jobq, e);
    }
  }
}

int test_job_cb(eventer_t e, int mask, void *v_work_description, struct timeval *now)
{
  if (mask == EVENTER_ASYNCH_WORK) {
    work_description_t *work_description = (work_description_t *) v_work_description;
    unsigned int old_work_removed;
    do {
      old_work_removed = ck_pr_load_uint(&work_description->work_removed);
    } while (
      !ck_pr_cas_uint(&work_description->work_removed, old_work_removed, old_work_removed + 1));
    if (mtev_flow_regulator_stable_lower(work_description->flowreg, 1))
      add_jobs_loop(work_description);
  }
  return 0;
}

int test_job_done(eventer_t e, int mask, void *v_work_description, struct timeval *now)
{
  if (mask == EVENTER_ASYNCH_WORK) {
    work_description_t *work_description = (work_description_t *) v_work_description;
  }
  return 0;
}

int test_poll(eventer_t e, int mask, void *v_work_description, struct timeval *now)
{
  work_description_t *work_description = (work_description_t *) v_work_description;
  unsigned int work_added = ck_pr_load_uint(&work_description->work_added);
  unsigned int work_removed = ck_pr_load_uint(&work_description->work_removed);
  if (work_removed == work_description->work_last_check) {
    mtevL(mtev_error, "work_removed stall at %u\n", work_removed);
    if (work_removed == work_description->work_total) exit(0);
    exit(1);
  }
  work_description->work_last_check = work_removed;
  eventer_add_in_s_us(test_poll, v_work_description, 1, 0);
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

  work_description_t *work_description =
    (work_description_t *) calloc(1, sizeof(work_description_t));
  work_description->work_total = 1000000;
  work_description->flowreg = mtev_flow_regulator_create(3, 4);

  test_jobq = eventer_jobq_create_ms("test_jobq", EVENTER_JOBQ_MS_GC);
  eventer_jobq_set_concurrency(test_jobq, 10);
  add_jobs_loop(work_description);
  eventer_add_in_s_us(test_poll, (void *) work_description, 1, 0);

  /* Lastly, spin up the event loop */
  eventer_loop();
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
