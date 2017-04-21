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
#include <eventer/eventer.h>
#include <inttypes.h>

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#define APPNAME "example1"
static char *config_file = NULL;
static int debug = 1;
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
  while((c = getopt(argc, argv, "c:")) != EOF) {
    switch(c) {
      case 'c':
        config_file = optarg;
        break;
    }
  }
}

static int
doasynchstuff(eventer_t e, int mask, void *closure, struct timeval *now) {
  mtev_http_rest_closure_t *restc = closure;
  if(mask == EVENTER_ASYNCH_WORK) {
    mtevL(mtev_debug, "here asynch\n");
  }
  if(mask == EVENTER_ASYNCH) {
    mtevL(mtev_debug, "here asynch complete\n");
    eventer_t e = mtev_http_connection_event(mtev_http_session_connection(restc->http_ctx));
    eventer_trigger(e, EVENTER_READ|EVENTER_WRITE);
  }
  return 0;
}
static int
test_complete(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  mtevL(mtev_debug, "-> test_complete()\n");
  mtev_http_response_ok(restc->http_ctx, "text/plain");
  mtev_http_response_append_str(restc->http_ctx, "Hello world\n");
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
test(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  mtevL(mtev_debug, "-> test()\n");
  restc->fastpath = test_complete;

  eventer_t conne = mtev_http_connection_event_float(mtev_http_session_connection(restc->http_ctx));
  if(conne) eventer_remove_fde(conne);

  eventer_t e = eventer_alloc_asynch(doasynchstuff, restc);
  eventer_add(e);

  /* Allow the asynch event to fire before we finish and return */
  usleep(1000);

  mtevL(mtev_debug, "<- test()\n");
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
