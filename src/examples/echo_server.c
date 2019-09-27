#include <mtev_defines.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_dso.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_http.h>
#include <mtev_rest.h>
#include <mtev_cluster.h>
#include <mtev_capabilities_listener.h>
#include <mtev_events_rest.h>
#include <eventer/eventer.h>

#include <errno.h>
#include <stdio.h>
#include <getopt.h>

#define APPNAME "echo_server"
#define FLUSH_BUFFER_MAX 4194304
static char *config_file = NULL;
static int debug = 0;
static int foreground = 0;
static char *droptouser = NULL, *droptogroup = NULL;
static int appends = 0;

static int
usage(const char *prog) {
	fprintf(stderr, "%s <-c conffile> [-D] [-d]\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  fprintf(stderr, "\t-D\t\trun in the foreground (don't daemonize)\n");
  fprintf(stderr, "\t-d\t\tturn on debugging\n");
  return 2;
}
static void
parse_cli_args(int argc, char * const *argv) {
  int c;
  while((c = getopt(argc, argv, "c:Dd")) != EOF) {
    switch(c) {
      case 'c':
        config_file = optarg;
        break;
      case 'd': debug = 1; break;
      case 'D': foreground++; break;
    }
  }
}

static int my_post_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  (void)npats;
  (void)pats;
  /* intentionally small */
  size_t buffer_size = 98;
  char buffer[98];
  int mask = EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
  int len;
  int done = 0;

  if (!restc->call_closure) {
    appends = 0;
    restc->call_closure = restc;
    restc->call_closure_free = NULL;
    mtev_http_response_standard(restc->http_ctx, 200, "OK", "text/plain");
    (void)mtev_http_response_option_set(restc->http_ctx, MTEV_HTTP_CLOSE);
    mtev_http_response_header_set(restc->http_ctx, "Content-Type", "text/plain");
  }

  len = mtev_http_session_req_consume(restc->http_ctx, buffer, buffer_size, buffer_size, &mask);
  if (len > 0) {
    mtev_http_response_append(restc->http_ctx, buffer, len);
    /* periodically flush */
    appends++;
    if (appends % 250 == 0) {
      if (mtev_http_response_flush(restc->http_ctx, mtev_false) == mtev_false) {
        mtevL(mtev_error, "ERROR: cannot flush\n");
      }
    }
  }
  if ((len < 0 && errno != EAGAIN) || len == 0) {
    done = 1;
  }

  if (done) {
    mtev_http_response_end(restc->http_ctx);
    return 0;
  }
  return EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
}


static int
child_main(void) {

  /* reload our config, to make sure we have the most current */
  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_http_rest_register("POST", "/", "^(.*)$", my_post_handler);

  /* Lastly, spin up the event loop */
  eventer_loop();
  return 0;
}

int main(int argc, char **argv) {
  parse_cli_args(argc, argv);
  if(!config_file) exit(usage(argv[0]));
  
  mtev_memory_init();
  mtev_main(APPNAME, config_file, debug, foreground,
            MTEV_LOCK_OP_LOCK, NULL, droptouser, droptogroup,
            child_main);
  return 0;
}
