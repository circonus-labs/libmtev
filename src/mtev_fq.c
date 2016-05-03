/*
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mtev_fq.h"

#include "mtev_log.h"
#include "mtev_conf.h"

#define CONFIG_FQ_IN_MQ "//network/in/mq[@type='fq']"
#define CONFIG_FQ_OUT_MQ "//network/out/mq[@type='fq']"
#define CONFIG_FQ_HOST "self::node()/host"
#define CONFIG_FQ_PORT "self::node()/port"
#define CONFIG_FQ_USER "self::node()/user"
#define CONFIG_FQ_PASS "self::node()/pass"
#define CONFIG_FQ_EXCHANGE "self::node()/exchange"
#define CONFIG_FQ_PROGRAM "self::node()/program"
#define CONFIG_FQ_ROUTE "self::node()/route"

typedef struct connection_configs {
  char* host;
  int port;
  char* user;
  char* pass;
} connection_configs;

static fq_client* fq_receivers;
static uint number_of_receivers;
static fq_receiver_func_t on_msg_received_callback;

static fq_client* fq_senders;
static int number_of_senders;
static char* sender_exchange;
static int sender_exchange_len;
static char* sender_route;
static int sender_route_len;

typedef struct exchange_and_program {
  char* exchange;
  char* program;
} exchange_and_program;

static exchange_and_program* create_exchange_and_program(char* exchange,
    char* program) {
  exchange_and_program* eap = malloc(sizeof(exchange_and_program));
  eap->exchange = strdup(exchange);
  eap->program = strdup(program);
  return eap;
}

static void free_exchange_and_program(exchange_and_program* eap) {
  free(eap->exchange);
  free(eap->program);
  free(eap);
}

static void logger(fq_client c, const char *s) {
  (void) c;
  mtevL(mtev_error, "fq_logger: %s\n", s);
}

static void my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;

  if (error)
    return;

  breq = malloc(sizeof(*breq));
  memset(breq, 0, sizeof(*breq));

  exchange_and_program* eap = fq_client_get_userdata(c);
  char *exchange = eap->exchange;

  memcpy(breq->exchange.name, exchange, strlen(exchange));
  breq->exchange.len = strlen(exchange);
  breq->flags = FQ_BIND_TRANS;
  breq->program = strdup(eap->program);
  fq_client_bind(c, breq);

  free_exchange_and_program(eap);
}

static int poll_fq(eventer_t e, int mask, void *unused, struct timeval *now) {
  fq_msg *m;

  for (int client = 0; client != number_of_receivers; ++client) {
    while (NULL != (m = fq_client_receive(fq_receivers[client]))) {
      on_msg_received_callback(client, m);
    }
  }

  return 1;
}

static void start_polling() {
  eventer_t receiver = eventer_alloc();
  receiver->mask = EVENTER_RECURRENT;
  receiver->callback = poll_fq;
  eventer_add(receiver);
}

static void my_bind_handler(fq_client c, fq_bind_req *breq) {
  (void) c;
  mtevL(mtev_debug, "route set -> %u\n", breq->out__route_id);
  if (breq->out__route_id == FQ_BIND_ILLEGAL) {
    mtevL(mtev_error, "Failure to bind...\n");
    exit(-1);
  }
}

fq_hooks hooks = { .version = FQ_HOOKS_V1, .auth = my_auth_handler, .bind =
    my_bind_handler };

static void connect_fq_client(fq_client *fq_c, char *host, int port, char *user,
    char *pass, char* exchange, char* program) {
  mtevL(mtev_debug, "Connecting with fq broker: %s:%d!\n", host, port);

  char *fq_debug = getenv("FQ_DEBUG");
  if (fq_debug)
    fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(fq_c, 0, logger);

  if (exchange != NULL) {
    if (fq_client_hooks(*fq_c, &hooks)) {
      mtevL(mtev_error, "Can't register hooks\n");
      exit(-1);
    }
    fq_client_set_userdata(*fq_c,
        create_exchange_and_program(exchange, program));
  }

  fq_client_creds(*fq_c, host, port, user, pass);
  fq_client_heartbeat(*fq_c, 1000);
  fq_client_set_backlog(*fq_c, 10000, 100);
  fq_client_connect(*fq_c);
}

static connection_configs* check_connection_conf(mtev_conf_section_t section) {
  struct mtev_conf_description_t descs[] = {

  { section, CONFIG_FQ_HOST, MTEV_CONF_TYPE_STRING,
      "Hostname of the fq broker data should be received from" },

      { section, CONFIG_FQ_PORT, MTEV_CONF_TYPE_INT,
          "Port number of the fq broker" },

      { section, CONFIG_FQ_USER, MTEV_CONF_TYPE_STRING,
          "User name used to connect to the fq broker" },

      { section, CONFIG_FQ_PASS, MTEV_CONF_TYPE_STRING,
          "Password used to connect to the fq broker" }

  };

  mtev_hash_table* configs_hash;
  if ((configs_hash = mtev_conf_check(descs,
      sizeof(descs) / sizeof(struct mtev_conf_description_t))) == NULL) {
    mtevL(mtev_error, "Incomplete fq config found!\n");
    exit(2);
  }

  connection_configs* configs_table = malloc(sizeof(connection_configs));

  const mtev_conf_description_t *host_desc, *port_desc, *user_desc, *pass_desc;

  mtev_hash_retrieve(configs_hash, CONFIG_FQ_HOST, strlen(CONFIG_FQ_HOST),
      (void*) &host_desc);
  mtev_hash_retrieve(configs_hash, CONFIG_FQ_PORT, strlen(CONFIG_FQ_PORT),
      (void*) &port_desc);
  mtev_hash_retrieve(configs_hash, CONFIG_FQ_USER, strlen(CONFIG_FQ_USER),
      (void*) &user_desc);
  mtev_hash_retrieve(configs_hash, CONFIG_FQ_PASS, strlen(CONFIG_FQ_PASS),
      (void*) &pass_desc);

  configs_table->host = host_desc->value.val_string;
  configs_table->port = port_desc->value.val_int;
  configs_table->user = user_desc->value.val_string;
  configs_table->pass = pass_desc->value.val_string;

  mtev_hash_destroy(configs_hash, NULL, NULL);
  free(configs_hash);

  return configs_table;
}

static char* check_string_conf(mtev_conf_description_t desc) {
  mtev_hash_table* configs_hash;
  if ((configs_hash = mtev_conf_check(&desc, 1)) == NULL) {
    mtevL(mtev_error, "Incomplete fq config found!\n");
    exit(2);
  }
  const mtev_conf_description_t *exchange_desc;

  mtev_hash_retrieve(configs_hash, CONFIG_FQ_EXCHANGE,
      strlen(CONFIG_FQ_EXCHANGE), (void*) &exchange_desc);

  char* exchange = exchange_desc->value.val_string;
  mtev_hash_destroy(configs_hash, NULL, NULL);
  free(configs_hash);

  return exchange;
}

static void init_receivers(fq_receiver_func_t on_msg_received) {
  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_FQ_IN_MQ,
      &number_of_receivers);

  if (on_msg_received == NULL && number_of_receivers > 0) {
    mtevL(mtev_error,
        "The on_msg_received callback may not be null if an fq receiver is set in the config!\n");
    exit(2);
  }

  on_msg_received_callback = on_msg_received;
  if (fq_receivers) {
    free(fq_receivers);
  }

  fq_receivers = malloc(number_of_receivers * sizeof(fq_client));

  for (int section_id = 0; section_id != number_of_receivers; ++section_id) {
    char *type;
    mtev_conf_get_string(mqs[section_id], "self::node()/@type", &type);

    connection_configs* connection_configs = check_connection_conf(
        mqs[section_id]);

    mtev_conf_description_t exchange_desc = { mqs[section_id],
    CONFIG_FQ_EXCHANGE, MTEV_CONF_TYPE_STRING, "Exchange to connect to" };
    char *exchange = check_string_conf(exchange_desc);

    mtev_conf_description_t program_desc = { mqs[section_id], CONFIG_FQ_PROGRAM,
        MTEV_CONF_TYPE_STRING, "Program filtering incoming messages" };
    char *program = check_string_conf(program_desc);

    connect_fq_client(&fq_receivers[section_id], connection_configs->host,
        connection_configs->port, connection_configs->user,
        connection_configs->pass, exchange, program);
  }
  start_polling();
}

static void init_senders() {
  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_FQ_OUT_MQ,
      &number_of_senders);

  if (fq_senders) {
    free(fq_senders);
  }

  fq_senders = malloc(number_of_senders * sizeof(fq_client));

  for (int section_id = 0; section_id != number_of_senders; ++section_id) {
    char *type;
    mtev_conf_get_string(mqs[section_id], "self::node()/@type", &type);

    connection_configs* connection_configs = check_connection_conf(
        mqs[section_id]);

    mtev_conf_description_t exchange_desc = { mqs[section_id],
    CONFIG_FQ_EXCHANGE, MTEV_CONF_TYPE_STRING,
        "Exchange messages should be sent to" };
    sender_exchange = check_string_conf(exchange_desc);
    sender_exchange_len = strlen(sender_exchange);

    mtev_conf_description_t route_desc = { mqs[section_id], CONFIG_FQ_ROUTE,
        MTEV_CONF_TYPE_STRING, "Rotue messages should be sent to" };
    sender_route = check_string_conf(route_desc);
    sender_route_len = strlen(sender_route);

    connect_fq_client(&fq_senders[section_id], connection_configs->host,
        connection_configs->port, connection_configs->user,
        connection_configs->pass, NULL, NULL);
  }
}

void mtev_fq_send(char* message, int message_len,
    int connection_id_broadcast_if_negative) {
  if (connection_id_broadcast_if_negative >= number_of_senders) {
    mtevL(mtev_error,
        "mtev_fq_send called with a connection_id of %d but there are only %d brokers connected!\n");
    return;
  }

  int first_host = connection_id_broadcast_if_negative;
  int last_host_plus_one = connection_id_broadcast_if_negative + 1;
  if (connection_id_broadcast_if_negative < 0) {
    first_host = 0;
    last_host_plus_one = number_of_senders;
  }

  fq_msg* msg = fq_msg_alloc(message, message_len);
  fq_msg_exchange(msg, sender_exchange, sender_exchange_len);
  fq_msg_route(msg, sender_route, sender_route_len);
  fq_msg_id(msg, NULL);

  for (int connection_id = first_host; connection_id != last_host_plus_one; ++connection_id) {
    fq_client_publish(fq_senders[connection_id], msg);
  }
  fq_msg_deref(msg);
}

void mtev_fq_init(fq_receiver_func_t on_msg_received) {
  init_receivers(on_msg_received);
  init_senders();

  if (number_of_receivers == 0) {
    mtevL(mtev_error, "No fq reciever setting found in the config!\n");
  }

  if (number_of_senders == 0) {
    mtevL(mtev_error, "No fq sender setting found in the config!\n");
  }
}
