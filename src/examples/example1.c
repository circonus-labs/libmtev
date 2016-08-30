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
static char *droptouser = NULL, *droptogroup = NULL;
static mtev_cluster_t *my_cluster = NULL;
static char my_payload[32];
static char my_payload2[32];

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

static mtev_hook_return_t
on_node_updated(void *closure, mtev_cluster_node_changes_t node_changes, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
    struct timeval old_boot_time) {
  mtev_boolean i_am_oldest = mtev_cluster_am_i_oldest_node(my_cluster);

  mtevL(mtev_stderr, "The cluster topology has changed (seq=%"PRId64"): I am oldest node: %d\n",
      updated_node->config_seq, i_am_oldest);
  if(node_changes & MTEV_CLUSTER_NODE_REBOOTED) {
    mtevL(mtev_stderr, "Found new node\n");
  }
  if(node_changes & MTEV_CLUSTER_NODE_CHANGED_PAYLOAD) {
    mtevL(mtev_stderr, "Node's payload has changed:\n");
  }

  if(updated_node->payload) {
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

static void init_cluster() {
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

static int
child_main() {
  /* reload out config, to make sure we have the most current */

  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_stats_rest_init();
  mtev_listener_init(APPNAME);
  init_cluster();
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_conf_write_log();
  mtev_conf_coalesce_changes(10); /* 10 seconds of no changes before we write */
  mtev_conf_watch_and_journal_watchdog(mtev_conf_write_log, NULL);

  mtev_http_rest_register_auth(
    "GET", "/", "^(.*)$", mtev_rest_simple_file_handler,
           mtev_http_rest_client_cert_auth
  );

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
