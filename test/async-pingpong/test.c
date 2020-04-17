#include <mtev_defines.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_dso.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_rest.h>
#include <mtev_capabilities_listener.h>
#include <mtev_events_rest.h>
#include <mtev_stats.h>
#include <mtev_perftimer.h>
#include <circllhist.h>
#include <eventer/eventer.h>
#include <inttypes.h>

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

int ITERS = 100000;
#define APPNAME "example1"
static char *config_file = NULL;
static int debug = 0;
static int foreground = 1;

static int
usage(const char *prog) {
	fprintf(stderr, "%s <-c conffile>\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  return 2;
}
static void
parse_cli_args(int argc, char * const *argv) {
  int c;
  while((c = getopt(argc, argv, "c:di:")) != EOF) {
    switch(c) {
      case 'i':
        ITERS = atoi(optarg);
        break;
      case 'd':
        debug = 1;
        break;
      case 'c':
        config_file = optarg;
        break;
    }
  }
}

struct test_closure {
  mtev_perftimer_t start;
  mtev_perftimer_t last;
  uint64_t elapsed;
  uint64_t step1, step2;
  int times;
  int count;
  histogram_t *rt;
};
static int
noop_asynch(eventer_t e, int mask, void *closure, struct timeval *now) {
  return 0;
}
static int
doasynchstuff(eventer_t e, int mask, void *closure, struct timeval *now) {
  mtev_http_rest_closure_t *restc = closure;
  struct test_closure *cc = restc->closure;

  if(mask == EVENTER_ASYNCH_WORK) {
   if(cc->times == 0) cc->step1 = mtev_perftimer_elapsed(&cc->start);
    //mtevL(mtev_debug, "here asynch\n");
  }
  if(mask == EVENTER_ASYNCH) {
    if(cc->times == 0) cc->step2 = mtev_perftimer_elapsed(&cc->start);
    else {
      hist_insert_intscale(cc->rt, mtev_perftimer_elapsed(&cc->last), -9, 1);
    }
    mtev_perftimer_start(&cc->last);
    cc->times++;
    if(cc->times < cc->count) {
      //mtevL(mtev_debug, "here asynch pingpong\n");
      eventer_add(eventer_alloc_asynch(doasynchstuff, restc));
    }
    else {
      cc->elapsed = mtev_perftimer_elapsed(&cc->start);
      mtevL(mtev_debug, "here asynch complete\n");
      
      eventer_t e = mtev_http_connection_event(mtev_http_session_connection(restc->http_ctx));
      eventer_trigger(e, EVENTER_READ|EVENTER_WRITE);
    }
  }
  return 0;
}
static int
test_complete(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  struct test_closure *cc = restc->closure;
  mtevL(mtev_debug, "-> test_complete()\n");
  mtev_http_response_ok(restc->http_ctx, "text/plain");
  mtev_http_response_appendf(restc->http_ctx, "first iteration asynch delay: %0.2f us\n",
                             (double)cc->step1 / 1000.0);
  mtev_http_response_appendf(restc->http_ctx, "first iteration asynch complete: %0.2f us\n",
                             (double)cc->step2 / 1000.0);
  mtev_http_response_appendf(restc->http_ctx, "rounds:\t%d/%d\nmean:\t%0.2f us\n",
                             cc->times, cc->count, (double)cc->elapsed / (double)cc->times / 1000.0);
  double in[6] = { 0, 0.25, 0.5, 0.75, 0.99, 1 }, p[6];
  int rv = hist_approx_quantile(cc->rt, in, 6, p);
  mtevAssert(rv == 0);
  for(int i=0; i<6; i++) p[i] *= 1000000.0;
  mtev_http_response_appendf(restc->http_ctx,
    "p0:\t%0.2f us\np25:\t%0.2f us\np50:\t%0.2f us\np75:\t%0.2f us\np99:\t%0.2f us\np100:\t%0.2f us\n",
    p[0],p[1],p[2],p[3],p[4],p[5]);
  mtev_http_response_end(restc->http_ctx);
  hist_free(cc->rt);
  free(cc);
  restc->closure = NULL;
  return 0;
}
static int
test(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  mtevL(mtev_debug, "-> test()\n");
  restc->fastpath = test_complete;

  eventer_t conne = mtev_http_connection_event_float(mtev_http_session_connection(restc->http_ctx));
  if(conne) eventer_remove_fde(conne);

  struct test_closure *cc = calloc(1, sizeof(*cc));
  cc->count = ITERS;
  cc->rt = hist_fast_alloc();
  mtev_perftimer_start(&cc->start);
  restc->closure = cc;
  eventer_t e = eventer_alloc_asynch(doasynchstuff, restc);
  eventer_add(e);
  return 0;
}

static int
child_main(void) {
  /* reload out config, to make sure we have the most current */

  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_debug, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_stats_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_conf_write_log();
  mtev_conf_watch_and_journal_watchdog((int (*)(void *))mtev_conf_write_log, NULL);

  mtev_rest_mountpoint_t *mp;
  mp = mtev_http_rest_new_rule(
    "GET", "/", "^test$", test
  );
  eventer_pool_t *other = eventer_pool("other");
  assert(other);
  mtev_rest_mountpoint_set_eventer_pool(mp, other);

  /* The first asynch event will start a thread in the pool.
   * This primes prevents that startup cost from being in the benchmark.
   */
  eventer_add(eventer_alloc_asynch(noop_asynch, NULL));
  /* Lastly, spin up the event loop */
  eventer_loop();
  return 0;
}

int main(int argc, char **argv) {
  parse_cli_args(argc, argv);
  if(!config_file) exit(usage(argv[0]));
  
  mtev_memory_init();
  mtev_main(APPNAME, config_file, debug, foreground,
            MTEV_LOCK_OP_LOCK, NULL, NULL, NULL,
            child_main);
  return 0;
}
