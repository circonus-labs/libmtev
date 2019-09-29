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
#include <mtev_heap_profiler.h>
#include <mtev_uuid.h>
#include <eventer/eventer.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>

#define APPNAME "example1"
#define CLUSTER_NAME "ponies"
static char *config_file = NULL;
static int debug = 0;
static int foreground = 0;
static int strict_module_load = 0;
static enum {
  PROC_OP_START,
  PROC_OP_STOP,
  PROC_OP_STATUS,
  PROC_OP_ERROR
} proc_op = PROC_OP_START;
static char *droptouser = NULL, *droptogroup = NULL;

static int
usage(const char *prog) {
  fprintf(stderr, "%s <-c conffile> [-k <start|stop|status>] [-D] [-d]\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  fprintf(stderr, "\t-D\t\trun in the foreground (don't daemonize)\n");
  fprintf(stderr, "\t-d\t\tturn on debugging\n");
  fprintf(stderr, "\t-k <op>\t\tstart, stop or check a running instance\n");
  return 2;
}
static void
parse_cli_args(int argc, char * const *argv) {
  int c;
  while((c = getopt(argc, argv, "c:DMdk:l:L:")) != EOF) {
    switch(c) {
      case 'c':
        config_file = optarg;
        break;
      case 'd': debug = 1; break;
      case 'D': foreground++; break;
      case 'k': 
        if(!strcmp(optarg, "start")) proc_op = PROC_OP_START;
        else if(!strcmp(optarg, "stop")) proc_op = PROC_OP_STOP;
        else if(!strcmp(optarg, "status")) proc_op = PROC_OP_STATUS;
        else proc_op = PROC_OP_ERROR;
        break;
      case 'l':
        mtev_main_enable_log(optarg);
        break;
      case 'L':
        mtev_main_disable_log(optarg);
        break;
      case 'M':
        strict_module_load = 1;
        break;
    }
  }
}

static void asynch_hello(void *closure) {
  mtev_http_rest_closure_t *restc = closure;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  usleep(100);
  mtev_http_response_append_str(ctx, "Hello world.\n");
}

static int handler_traditional(eventer_t e, int mask, void *closure,
                        struct timeval *now) {
  (void)e;
  (void)now;
  mtev_http_rest_closure_t *restc = closure;
  if(mask == EVENTER_ASYNCH_WORK) {
    mtev_http_session_ctx *ctx = restc->http_ctx;
    mtev_http_response_appendf(ctx, "traditional work %s\n", eventer_get_thread_name());
  }
  if(mask == EVENTER_ASYNCH) {
    mtev_http_session_resume_after_float(restc->http_ctx);
  }
  return 0;
}

void subcall2(mtev_http_rest_closure_t *restc) {
  eventer_aco_gate_t gate = eventer_aco_gate();
  mtevL(mtev_error, "subcall2 entry\n");
  int count = 2;
  const char *style = mtev_http_request_querystring(mtev_http_session_request(restc->http_ctx), "style");
  const char *count_str = mtev_http_request_querystring(mtev_http_session_request(restc->http_ctx), "count");
  if(count_str) count = atoi(count_str);
  for(int i=0; i<count; i++) {
    if(style && !strcmp(style, "trad")) {
      eventer_t e = eventer_alloc_asynch(handler_traditional, restc);
      eventer_aco_run_asynch_gated(gate, e);
    } else {
      eventer_aco_simple_asynch_gated(gate, asynch_hello, restc);
    }
  }
  mtevL(mtev_error, "subcall2 return\n");
  eventer_aco_gate_wait(gate);
}
void subcall1(mtev_http_rest_closure_t *restc) {
  mtevL(mtev_error, "subcall1 entry\n");
  subcall2(restc);
  mtevL(mtev_error, "subcall1 return\n");
}
static int upload_handler_no_aco(mtev_http_rest_closure_t *restc,
                           int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  int64_t size;
  int mask;
  if(!mtev_rest_complete_upload(restc, &mask)) return mask;
  const void *buffer = mtev_http_request_get_upload(mtev_http_session_request(ctx), &size);
  (void)buffer;

  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_appendf(ctx, "read %zd bytes...\n", size);
  mtev_http_response_end(ctx);
  return 0;
}
static int upload_handler(mtev_http_rest_closure_t *restc,
                          int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  int64_t size;
  int mask;
  mtevAssert(mtev_rest_complete_upload(restc, &mask));
  const void *buffer = mtev_http_request_get_upload(mtev_http_session_request(ctx), &size);
  (void)buffer;

  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_appendf(ctx, "read %zd bytes...\n", size);
  mtev_http_response_end(ctx);
  return 0;
}
static int hello_handler(mtev_http_rest_closure_t *restc,
                         int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_ok(ctx, "text/plain");
  subcall1(restc);
  mtev_http_response_end(ctx);
  return 0;
}

static void
workie(void *closure) {
  (void)closure;
  mtevL(mtev_error, "doing asynch stuff...\n");
  sleep(1);
  mtevL(mtev_error, "done asynch stuff...\n");
}
static void
listen_to_me(void) {
  eventer_aco_t e = eventer_aco_arg();

  struct timeval two_sec = { 2, 0 };

  while(1) {
    int rv;
    char buff[1024], out[1024];
    memset(buff, 1, sizeof(buff));
    rv = eventer_aco_read(e, buff, sizeof(buff), &two_sec);
    if(rv == -1) {
      if(errno != ETIME) break;
      rv = eventer_aco_write(e, "idle\n", 5, NULL);
    } else {
      if(rv >= 4 && !strncasecmp(buff, "quit", 4)) {
        rv = eventer_aco_write(e, "bye!\n", 5, NULL);
        break;
      }
      eventer_aco_simple_asynch(workie, NULL);
      snprintf(out, sizeof(out), "I just read %d bytes '%.*s', errno %d\n", rv, (rv > 2) ? rv - 2 : 0, buff, errno);
      rv = eventer_aco_write(e, out, strlen(out), NULL);
    }
    if(rv == -1) break;
  }

  eventer_aco_close(e);
  eventer_aco_free(e);
}

static void
ping(void) {
  while(1) {
    mtevEL(mtev_error, MLKV { MLKV_STR("key1", "a string"), MLKV_END }, "ping...\n");
    eventer_aco_sleep(&(struct timeval){ 1UL, 0UL });
  }
}
static int
child_main(void) {
  /* reload out config, to make sure we have the most current */

  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();

  mtev_listener_register_aco_function("listen_to_me", listen_to_me);

  mtev_dso_init();
  mtev_console_init(APPNAME);
  mtev_console_conf_init();
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_stats_rest_init();
  mtev_heap_profiler_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_post_init();

  if(strict_module_load &&
     (mtev_dso_load_failures() > 0)) {
    mtevL(mtev_stderr, "Failed to load some modules and -M given.\n");
    exit(2);
  }

  mtev_conf_coalesce_changes(10); /* 10 seconds of no changes before we write */
  mtev_conf_watch_and_journal_watchdog(NULL, NULL);

  mtev_rest_mountpoint_t *rule = mtev_http_rest_new_rule(
    "GET", "/", "^hello$", hello_handler
  );
  mtev_rest_mountpoint_set_auth(rule, mtev_http_rest_client_cert_auth);
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  rule = mtev_http_rest_new_rule(
    "POST", "/", "^upload2$", upload_handler_no_aco
  );

  rule = mtev_http_rest_new_rule(
    "GET", "/", "^upload2$", upload_handler_no_aco
  );

  rule = mtev_http_rest_new_rule(
    "POST", "/", "^upload$", upload_handler
  );
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  mtev_http_rest_register_auth(
    "GET", "/", "^(.*)$", mtev_rest_simple_file_handler,
           mtev_http_rest_client_cert_auth
  );

  /* Two pings to make sure stack switching is all good */
  eventer_aco_start(ping, NULL);
  eventer_aco_start(ping, NULL);

  /* Lastly, spin up the event loop */
  eventer_loop();
  return 0;
}

int main(int argc, char **argv) {
  pid_t pid, pgid;
  parse_cli_args(argc, argv);
  if(!config_file) exit(usage(argv[0]));
  mtev_memory_init();
  switch(proc_op) {
    case PROC_OP_START:
      mtev_main(APPNAME, config_file, debug, foreground,
                MTEV_LOCK_OP_LOCK, NULL, droptouser, droptogroup,
                child_main);
      break;
    case PROC_OP_STOP:
      exit(mtev_main_terminate(APPNAME, config_file, debug));
      break;
    case PROC_OP_STATUS:
      if(mtev_main_status(APPNAME, config_file, debug, &pid, &pgid) != 0) exit(-1);
      mtevL(mtev_debug, "running pid: %d, pgid: %d\n", pid, pgid);
      break;
    case PROC_OP_ERROR:
      exit(usage(argv[0]));
      break;
   }
  return 0;
}
