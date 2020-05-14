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
#include "mtev_stacktrace.h"

#include <errno.h>
#include <stdio.h>
#include <getopt.h>

#define APPNAME "test_http_server"
#define FLUSH_BUFFER_MAX 4194304
static char *config_file = NULL;
static int debug = 0;
static int foreground = 0;
static char *droptouser = NULL, *droptogroup = NULL;

struct my_call_closure {
  uint32_t seed;
  size_t buffer_size;
  char* buffer;
  uint64_t delay_us;
};

static void
my_cc_free(void *vp) {
  if(!vp) return;
  struct my_call_closure *cc = (struct my_call_closure*) vp;
  free(cc->buffer);
  free(cc);
}

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
  while((c = getopt(argc, argv, "c:Ddx")) != EOF) {
    switch(c) {
    case 'c':
      config_file = optarg;
      break;
    case 'd': debug = 1; break;
    case 'D': foreground++; break;
    }
  }
}

/* http://www.cse.yorku.ca/~oz/hash.html */
static uint32_t hash_djb2(uint32_t seed, char *p, size_t len) {
  char *q = p + len;
  for(; p < q; p++) {
    seed = ((seed << 5) + seed) + (int) *p;
  }
  return seed;
}

static int my_post_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  (void)npats;
  (void)pats;

  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  struct my_call_closure *cc;

  int mask = EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
  int len;
  int done = 0;

  if (!restc->call_closure) {
    cc = calloc(1, sizeof *cc);
    cc->seed = 5381;
    cc->buffer_size = 1024 * 1024;
    const char *buffer_size_str = mtev_http_request_querystring(req , "readsize");
    if(buffer_size_str) {
      size_t buffer_size;
      if (sscanf(buffer_size_str, "%zu", &buffer_size) == 1) {
        mtevL(mtev_error, "Setting buffer size to %zu\n", buffer_size);
        cc->buffer_size = buffer_size;
      }
    }
    cc->buffer = malloc(cc->buffer_size);
    cc->delay_us = 0;
    const char *delay_str = mtev_http_request_querystring(req, "delay");
    if(delay_str) {
      cc->delay_us = atof(delay_str) * 1e6;
      mtevL(mtev_error, "Setting http delay to %f\n", cc->delay_us * 1e-6);
    }
    restc->call_closure = cc;
    restc->call_closure_free = my_cc_free;
    mtev_http_response_standard(ctx, 200, "OK", "text/plain");
    (void)mtev_http_response_option_set(ctx, MTEV_HTTP_CLOSE);
    mtev_http_response_header_set(ctx, "Content-Type", "text/plain");
  } else {
    cc = restc->call_closure;
  }

  len = mtev_http_session_req_consume(ctx, cc->buffer, cc->buffer_size, cc->buffer_size, &mask);
  if (len > 0) {
    cc->seed = hash_djb2(cc->seed, cc->buffer, len);
  }
  if ((len < 0 && errno != EAGAIN) || len == 0) {
    done = 1;
  }
  /* Avoid busy looping on the socket, spamming the debug logs */
  usleep(cc->delay_us);
  if (done) {
    mtev_http_response_appendf(ctx, "HASH %" PRId64 "\r\n", cc->seed);
    mtev_http_response_end(restc->http_ctx);
    return 0;
  }
  return EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
}
static int my_aco_post_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  (void)npats;
  (void)pats;

  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  struct my_call_closure *cc;

  if (!restc->call_closure) {
    cc = calloc(1, sizeof *cc);
    cc->seed = 5381;
    cc->buffer_size = 1024 * 1024;
    const char *buffer_size_str = mtev_http_request_querystring(req , "readsize");
    if(buffer_size_str) {
      size_t buffer_size;
      if (sscanf(buffer_size_str, "%zu", &buffer_size) == 1) {
        mtevL(mtev_error, "Setting buffer size to %zu\n", buffer_size);
        cc->buffer_size = buffer_size;
      }
    }
    cc->buffer = malloc(cc->buffer_size);
    cc->delay_us = 0;
    const char *delay_str = mtev_http_request_querystring(req, "delay");
    if(delay_str) {
      cc->delay_us = atof(delay_str) * 1e6;
      mtevL(mtev_error, "Setting http delay to %f\n", cc->delay_us * 1e-6);
    }
    restc->call_closure = cc;
    restc->call_closure_free = my_cc_free;
    mtev_http_response_standard(ctx, 200, "OK", "text/plain");
    (void)mtev_http_response_option_set(ctx, MTEV_HTTP_CLOSE);
    mtev_http_response_header_set(ctx, "Content-Type", "text/plain");
  } else {
    cc = restc->call_closure;
  }

  int len = 0;
  do {
    int mask;
    len = mtev_http_session_req_consume(ctx, cc->buffer, cc->buffer_size, cc->buffer_size, &mask);
    if (len > 0) {
      cc->seed = hash_djb2(cc->seed, cc->buffer, len);
    }
  } while(len > 0);
  /* Avoid busy looping on the socket, spamming the debug logs */
  usleep(cc->delay_us);
  mtev_http_response_appendf(ctx, "HASH %" PRId64 "\r\n", cc->seed);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

static void
tick(void) {
  while(1) eventer_aco_sleep(&(struct timeval){1,0});
  aco_exit();
}
static int
child_main(void) {
  mtev_rest_mountpoint_t *rule;
  /* reload our config, to make sure we have the most current */
  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_stats_rest_init();
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_http_rest_disclose_endpoints("/mtev/", "^rest\\.json$");

  mtev_http_rest_register("POST", "/", "^(.*)$", my_post_handler);

  rule = mtev_http_rest_new_rule("POST", "/", "^aco$", my_aco_post_handler);
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  mtevL(mtev_error, "Ready.\n");

  eventer_aco_start(tick, NULL);
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
