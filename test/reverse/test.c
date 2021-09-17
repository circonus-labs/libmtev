#include <mtev_capabilities_listener.h>
#include <mtev_conf.h>
#include <mtev_console.h>
#include <mtev_defines.h>
#include <mtev_dso.h>
#include <mtev_events_rest.h>
#include <mtev_listener.h>
#include <mtev_main.h>
#include <mtev_memory.h>
#include <mtev_perftimer.h>
#include <mtev_rand.h>
#include <mtev_rest.h>
#include <mtev_reverse_socket.h>
#include <mtev_stats.h>
#include <circllhist.h>
#include <eventer/eventer.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <getopt.h>
#include <unistd.h>

static const size_t N_FRAMES = 1;
static const size_t ITERATIONS = 20;
static const char *const APPNAME = "reverse_socket_test";
static char *config_file = NULL;
static int debug = 0;
static int foreground = 1;
static bool is_saas;

static const char *reverse_prefix = "test/";
static const char *reverse_prefix_cns[] = {NULL};
static mtev_hash_table *sslconfig;
static const uint32_t magic = 42;

struct client {
  size_t time_between_writes_s;
  int64_t frame_counters[N_FRAMES];
  int64_t frame_errors[N_FRAMES];
  int64_t total_frames;
  const char *name;
  mtev_dyn_buffer_t frames[N_FRAMES];
};

typedef struct client client_t;
static client_t heavier_client = {};
static client_t light_client = {};

eventer_jobq_t *worker_jobq;

static int32_t usage(const char *prog)
{
  fprintf(stderr, "%s <-c conffile>\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  return 2;
}

static void parse_cli_args(int argc, char *const *argv)
{
  int32_t c;
  while ((c = getopt(argc, argv, "c:d:s")) != EOF) {
    switch (c) {
    case 'd':
      debug = 1;
      break;
    case 'c':
      config_file = optarg;
      break;
    case 's':
      is_saas = true;
      break;
    }
  }
}

static void write_frames(client_t *const client, const int fd)
{
  for (size_t it = 0; it < ITERATIONS; it++) {
    for (size_t i = 0; i < N_FRAMES; i++) {
      mtev_dyn_buffer_t *frame = &client->frames[i];
      size_t offset = 0;
      size_t remaining = mtev_dyn_buffer_used(frame);

      while (true) {
        const ssize_t n = write(fd, mtev_dyn_buffer_data(frame) + offset, remaining);

        if (n == -1) {
          mtevL(mtev_error, "%s unable to write frame %zu with %zd errors.  %s\n", client->name, it,
                ++client->frame_errors[i], strerror(errno));
          sleep(10);
        }
        else if (n >= 0) {
          remaining -= n;
          offset += n;

          if (client->time_between_writes_s) {
            sleep(client->time_between_writes_s);
          }

          if (remaining == 0) {
            offset = 0;
            client->total_frames++;
            client->frame_counters[i]++;
            break;
          }
        }
      }
    }
  }
}

static void setup_frames(client_t *const client)
{
  for (size_t i = 0; i < N_FRAMES; i++) {
    mtev_dyn_buffer_t *frame = &client->frames[i];

    mtev_dyn_buffer_init(frame);
    mtev_dyn_buffer_ensure(frame, 2048);
    mtev_rand_buf(mtev_dyn_buffer_write_pointer(frame), 2048);
    mtev_dyn_buffer_advance(frame, 2048);
  }
}

static int client_runner(eventer_t e, int mask, void *closure, struct timeval *now)
{
  client_t *client = closure;

  if (mask == EVENTER_ASYNCH_WORK) {
    size_t number_of_errors = 0;
    size_t number_completed = 0;
    const int fd = mtev_reverse_socket_connect("mtev/test-server", -1);

    if (fd == -1) {
      eventer_t newe;

      mtevL(mtev_notice, "%s Rescheduling...\n", client->name);
      newe = eventer_alloc_asynch(client_runner, client);
      sleep(3);
      eventer_add_asynch(worker_jobq, newe);
    }
    else {
      uint32_t tmp = htonl(magic);
      char buf[8192];

      mtevL(mtev_notice, "%s starting work\n", client->name);
      mtevAssert(fd != -1);
      eventer_set_fd_blocking(fd);
      setup_frames(client);
      mtevAssert(write(fd, &tmp, sizeof(magic)) == sizeof(magic));

      mtevL(mtev_notice, "%s sending data\n", client->name);
      write_frames(client, fd);
    }
  }
  else if (mask == EVENTER_ASYNCH_COMPLETE) {
    for (size_t i = 0; i < N_FRAMES; i++) {
      mtev_dyn_buffer_destroy(&client->frames[i]);
    }

    mtevL(mtev_notice, "%s completed writing %zu frames\n", client->name, client->total_frames);
  }

  return 0;
}

static int saas_run(eventer_t e, const int mask, void *closure, struct timeval *now)
{
  // Get off default thread pool
  eventer_t newe = eventer_alloc_asynch(client_runner, &heavier_client);

  eventer_add_asynch(worker_jobq, newe);
  newe = eventer_alloc_asynch(client_runner, &light_client);
  eventer_add_asynch(worker_jobq, newe);
  return 0;
}

static int on_prem_startup(eventer_t e, const int mask, void *closure, struct timeval *now)
{
  mtevL(mtev_notice, "Starting clients...\n");
  mtev_lua_help_initiate_mtev_connection("127.0.0.1", 8888, sslconfig, NULL);
  return 0;
}

static int saas_startup(eventer_t e, const int mask, void *closure, struct timeval *now)
{
  mtevL(mtev_notice, "Initiating connection...\n");
  // No defined way to get connection status since usually both ends
  // aren't in the same process or machine
  eventer_add(eventer_in_s_us(saas_run, NULL, 5, 0));
  return 0;
}

static mtev_reverse_acl_decision_t reverse_socket_allow(const char *id, mtev_acceptor_closure_t *ac)
{
  return MTEV_ACL_ALLOW;
}

static int on_prem_socket_data_handler(eventer_t e, int mask, void *closure, struct timeval *now)
{
  static int64_t counter = 0;
  char bb[1024];
  const ssize_t len = eventer_read(e, bb, sizeof(bb), &mask);

  if (len < 0) {
    if (errno == EAGAIN) {
      return mask | EVENTER_EXCEPTION;
    }

    eventer_remove_fde(e);
    eventer_close(e, &mask);
    return 0;
  }

  if (len > 0) {
    mtevL(mtev_error, "%zu Received frame %zu of size %zd\n", pthread_self(), ++counter, len);
  }

  return EVENTER_READ | EVENTER_EXCEPTION;
}

static int saas_child_main(void)
{
  mtev_conf_section_t *mtev_configs;
  int cnt;

  if (mtev_conf_load(NULL) == -1) {
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

  mtev_reverse_socket_init_globals();
  mtev_reverse_socket_init(reverse_prefix, reverse_prefix_cns);
  mtev_reverse_socket_acl(reverse_socket_allow);

  mtev_conf_write_log();
  mtev_conf_watch_and_journal_watchdog((int (*)(void *)) mtev_conf_write_log, NULL);

  mtev_configs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, "/reverse_socket_test", &cnt);
  sslconfig = mtev_conf_get_hash(mtev_configs[0], "sslconfig");

  worker_jobq = eventer_jobq_create_ms("worker_q", EVENTER_JOBQ_MS_CS);
  eventer_jobq_set_concurrency(worker_jobq, 2);
  eventer_jobq_set_min_max(worker_jobq, 1, 20);

  eventer_add(eventer_in_s_us(saas_startup, NULL, 2, 0));
  eventer_loop();
  return 0;
}

static int on_prem_child_main(void)
{
  mtev_conf_section_t *mtev_configs;
  int cnt;

  if (mtev_conf_load(NULL) == -1) {
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

  mtev_reverse_socket_init_globals();
  mtev_reverse_socket_acl(reverse_socket_allow);

  mtev_conf_write_log();
  mtev_conf_watch_and_journal_watchdog((int (*)(void *)) mtev_conf_write_log, NULL);

  mtev_configs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, "/reverse_socket_test", &cnt);
  sslconfig = mtev_conf_get_hash(mtev_configs[0], "sslconfig");

  eventer_add(eventer_in_s_us(on_prem_startup, NULL, 5, 0));

  eventer_name_callback("on_prem_reverse_socket_handler", on_prem_socket_data_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch, magic, on_prem_socket_data_handler);

  eventer_loop();
  return 0;
}

int main(int argc, char **argv)
{
  heavier_client.name = "Heavy";
  heavier_client.time_between_writes_s = 0;
  light_client.name = "Light";
  light_client.time_between_writes_s = 15;
  parse_cli_args(argc, argv);

  if (!config_file)
    exit(usage(argv[0]));

  mtev_memory_init();

  if (is_saas) {
    mtev_main(APPNAME, config_file, debug, foreground, MTEV_LOCK_OP_NONE, NULL, NULL, NULL,
              saas_child_main);
  }
  else {
    mtev_main(APPNAME, config_file, debug, foreground, MTEV_LOCK_OP_NONE, NULL, NULL, NULL,
              on_prem_child_main);
  }

  return 0;
}
