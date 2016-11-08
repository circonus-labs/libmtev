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
#include <mtev_websocket_client.h>
#include <mtev_thread.h>

#include <stdio.h>
#include <getopt.h>

#define APPNAME "websocket_client"
static char *config_file = NULL;
static int debug = 0;
static int foreground = 0;
static char *droptouser = NULL, *droptogroup = NULL;

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

int websocket_msg_handler(mtev_websocket_client_t *client, int opcode,
                          const unsigned char *msg, size_t msg_len) {
  char buf[256];
  size_t len;
  snprintf(buf, msg_len, "%s", msg);
  mtevL(mtev_error, "I received a message! %s\n", buf);
  len = snprintf(buf, sizeof(buf), "%ld", lrand48());
  mtev_websocket_client_send(client, opcode, buf, len);
  return 0;
}

static mtev_websocket_client_t *client;

void *run_client(void *arg) {
  if(!client) {
    mtevL(mtev_error, "Websocket client creation failed\n");
    exit(1);
  }

  /* waiting for handshake to complete */
  while(!mtev_websocket_client_is_ready(client));

  if(mtev_websocket_client_is_closed(client)) {
    mtevL(mtev_error, "Websocket client error'd out while performing handshake\n");
    exit(1);
  }

  mtev_websocket_client_send(client, 0x1, "Hello world!", 13);

  /* while(!mtev_websocket_client_is_closed(client)); */
  /* mtev_websocket_client_close(client); */
  /* client = NULL; */

  return 0;
}

static int
child_main() {
  pthread_t t;

  /* reload our config, to make sure we have the most current */
  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_listener_init(APPNAME);
  mtev_dso_init();
  mtev_dso_post_init();

  client = mtev_websocket_client_new("localhost", 8888, "/", "echo-protocol", websocket_msg_handler);

  mtev_thread_create(&t, NULL, run_client, NULL);

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
