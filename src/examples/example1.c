#include <mtev_defines.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_dso.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_rest.h>
#include <mtev_cluster.h>
#include <mtev_capabilities_listener.h>
#include <mtev_events_rest.h>
#include <mtev_stats.h>
#include <eventer/eventer.h>
#include <inttypes.h>

#include <stdio.h>
#include <getopt.h>

#define APPNAME "example1"
#define CLUSTER_NAME "ponies"
static char *config_file = NULL;
static int debug = 0;
static int foreground = 0;
static enum {
  PROC_OP_START,
  PROC_OP_STOP,
  PROC_OP_STATUS,
  PROC_OP_ERROR
} proc_op = PROC_OP_START;
static char *droptouser = NULL, *droptogroup = NULL;
static mtev_cluster_t *my_cluster = NULL;
static char my_payload[32];
static char my_payload2[32];

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
  while((c = getopt(argc, argv, "c:Ddk:l:L:")) != EOF) {
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
    }
  }
}

static mtev_hook_return_t
on_node_updated(void *closure, mtev_cluster_node_changes_t node_changes, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
    struct timeval old_boot_time) {
  mtev_boolean i_am_oldest = mtev_cluster_am_i_oldest_node(my_cluster);

  mtevL(mtev_stderr, "The cluster topology has changed (seq=%"PRId64"): I am oldest node: %d\n",
      mtev_cluster_node_get_config_seq(updated_node), i_am_oldest);
  if(node_changes & MTEV_CLUSTER_NODE_REBOOTED) {
    mtevL(mtev_stderr, "Found new node\n");
  }
  if(node_changes & MTEV_CLUSTER_NODE_CHANGED_PAYLOAD) {
    mtevL(mtev_stderr, "Node's payload has changed:\n");
  }

  if(mtev_cluster_node_has_payload(updated_node)) {
    char* payload = NULL;
    char* payload2 = NULL;
    assert(mtev_cluster_get_heartbeat_payload(updated_node, 2, 1, (void**)&payload) == -1);
    mtev_cluster_get_heartbeat_payload(updated_node, 1, 1, (void**)&payload);
    mtev_cluster_get_heartbeat_payload(updated_node, 1, 2, (void**)&payload2);
    mtevL(mtev_stderr, "Payloads attached to cluster heartbeat: 1: %s\t2:%s\n", payload, payload2);
  } else {
    mtevL(mtev_stderr, "No payload attached to cluster heartbeat\n");
  }

  // Changing the payload will trigger another node update on all cluster members
  memcpy(my_payload, "Changed payload!", 16);
  mtev_cluster_unset_heartbeat_payload(cluster, 1, 2);
  return MTEV_HOOK_CONTINUE;
}

static void init_cluster(void) {
  mtev_cluster_init();
  if (mtev_cluster_enabled() != mtev_false) {
    my_cluster = mtev_cluster_by_name(CLUSTER_NAME);
    if (my_cluster == NULL) {
      mtevL(mtev_stderr, "Unable to find cluster %s\n", CLUSTER_NAME);
      exit(1);
    }
    uuid_t my_cluster_id;
    mtev_cluster_get_self(my_cluster_id);

    mtev_cluster_handle_node_update_hook_register("cluster-topology-listener", on_node_updated, NULL);

    char uuid_str[UUID_STR_LEN + 1];
    uuid_unparse(my_cluster_id, uuid_str);
    mtevL(mtev_stderr, "Initialized cluster. My uuid is: %s\n", uuid_str);

    assert(mtev_cluster_set_heartbeat_payload(my_cluster, 1, 1, my_payload2, sizeof(my_payload)));
    assert(mtev_cluster_set_heartbeat_payload(my_cluster, 1, 1, my_payload, sizeof(my_payload)));
    assert(mtev_cluster_set_heartbeat_payload(my_cluster, 1, 2, my_payload2, sizeof(my_payload2)));
    memcpy(my_payload, "Hello world!", 12);
    memcpy(my_payload2,"another payload!", 16);
  }
}

static int handler_subwork(eventer_t e, int mask, void *closure,
                        struct timeval *now) {
  uintptr_t len = (uintptr_t)closure;
  int i;
  int us = (len % 1000000);
  int lvl = (len / 10) % 10;
  if(mask == EVENTER_ASYNCH_WORK) {
    for(i=0;i<(10-lvl)/2;i++) {
      long foo = lrand48() * 100;
      foo += (lvl-1) * 10;
      foo += i;
      usleep(us/10);
      eventer_add_asynch_dep(NULL, eventer_alloc_asynch(handler_subwork, (void *)foo));
    }
  }
  return 0;
}
static int handler_work(eventer_t e, int mask, void *closure,
                        struct timeval *now) {
  mtev_http_rest_closure_t *restc = closure;
  if(mask == EVENTER_ASYNCH_WORK) {
    mtev_http_session_ctx *ctx = restc->http_ctx;
    mtev_http_response_appendf(ctx, "Passing by %s\n", eventer_get_thread_name());
    eventer_add_asynch_dep(NULL, eventer_alloc_asynch(handler_subwork, (void *)20));
  }
  if(mask == EVENTER_ASYNCH) {
    mtev_http_session_resume_after_float(restc->http_ctx);
  }
  return 0;
}

static int handler_complete(mtev_http_rest_closure_t *restc,
                            int npats, char **pats) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_appendf(ctx, "Good-bye from %s\n", eventer_get_thread_name());
  mtev_http_response_end(ctx);
  return 0;
}

static int handler(mtev_http_rest_closure_t *restc,
                   int npats, char **pats) {
  eventer_t conne, worke;
  mtev_http_session_ctx *ctx = restc->http_ctx;

  /* remove the eventer */
  conne = mtev_http_connection_event_float(mtev_http_session_connection(ctx));
  if(conne) eventer_remove_fde(conne);

  /* set a completion routine */
  restc->fastpath = handler_complete;

  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_appendf(ctx, "Hello from %s\n", eventer_get_thread_name());

  /* schedule our work */
  worke = eventer_alloc_asynch(handler_work, restc);
  eventer_add(worke);
  return 0;
}

static int
child_main(void) {
  /* reload out config, to make sure we have the most current */

  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_console_conf_init();
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_stats_rest_init();
  mtev_listener_init(APPNAME);
  init_cluster();
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_conf_coalesce_changes(10); /* 10 seconds of no changes before we write */
  mtev_conf_watch_and_journal_watchdog(NULL, NULL);

  mtev_http_rest_register_auth(
    "GET", "/", "^test$", handler,
           mtev_http_rest_client_cert_auth
  );
  mtev_http_rest_register_auth(
    "GET", "/", "^(.*)$", mtev_rest_simple_file_handler,
           mtev_http_rest_client_cert_auth
  );

  eventer_name_callback("handler_work", handler_work);
  eventer_name_callback("handler_subwork", handler_subwork);
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
