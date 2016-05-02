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
#define CONFIG_FQ_HOST "self::node()/host"
#define CONFIG_FQ_PORT "self::node()/port"
#define CONFIG_FQ_USER "self::node()/user"
#define CONFIG_FQ_PASS "self::node()/pass"
#define CONFIG_FQ_EXCHANGE "self::node()/exchange"
#define CONFIG_FQ_PROGRAM "self::node()/program"

static fq_client* fq_clients;
static uint number_of_connections;
static fq_receiver_func_t on_msg_received_callback;

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

  for (int client = 0; client != number_of_connections; ++client) {
    while (NULL != (m = fq_client_receive(fq_clients[client]))) {
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
  hrtime_t s, f;
  uint64_t cnt = 0, icnt = 0, icnt_total = 0;
  int rcvd = 0;
  fq_msg *m;

  mtevL(mtev_debug, "Connecting with fq broker: %s:%d!\n", host, port);

  char *fq_debug = getenv("FQ_DEBUG");
  if (fq_debug)
    fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(fq_c, 0, logger);
  if (fq_client_hooks(*fq_c, &hooks)) {
    mtevL(mtev_error, "Can't register hooks\n");
    exit(-1);
  }

  fq_client_hooks(*fq_c, &hooks);
  fq_client_creds(*fq_c, host, port, user, pass);
  fq_client_heartbeat(*fq_c, 1000);
  fq_client_set_backlog(*fq_c, 10000, 100);

  fq_client_set_userdata(*fq_c, create_exchange_and_program(exchange, program));

  fq_client_connect(*fq_c);
}

void mtev_fq_init(fq_receiver_func_t on_msg_received) {

  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_FQ_IN_MQ,
      &number_of_connections);

  on_msg_received_callback = on_msg_received;
  if (fq_clients) {
    free(fq_clients);
  }

  fq_clients = malloc(number_of_connections * sizeof(fq_client));

  for (int section_id = 0; section_id != number_of_connections; ++section_id) {
    char *type;
    mtev_conf_get_string(mqs[section_id], "self::node()/@type", &type);

    struct mtev_conf_description_t descs[] = {

    { mqs[section_id], CONFIG_FQ_HOST, MTEV_CONF_TYPE_STRING,
        "Hostname of the fq broker data should be received from" },

    { mqs[section_id], CONFIG_FQ_PORT, MTEV_CONF_TYPE_INT,
        "Port number of the fq broker" },

    { mqs[section_id], CONFIG_FQ_USER, MTEV_CONF_TYPE_STRING,
        "User name used to connect to the fq broker" },

    { mqs[section_id], CONFIG_FQ_PASS, MTEV_CONF_TYPE_STRING,
        "Password used to connect to the fq broker" },

    { mqs[section_id], CONFIG_FQ_EXCHANGE, MTEV_CONF_TYPE_STRING,
        "Exchange to connect to" },

    { mqs[section_id], CONFIG_FQ_PROGRAM, MTEV_CONF_TYPE_STRING,
        "Program filtering incoming messages" }

    };

    mtev_hash_table* configs;
    if ((configs = mtev_conf_check(descs,
        sizeof(descs) / sizeof(struct mtev_conf_description_t))) == NULL) {
      mtevL(mtev_error, "Incomplete fq config found!\n");
      exit(2);
    }

    const mtev_conf_description_t *host_desc, *port_desc, *user_desc,
        *pass_desc, *exchange_desc, *program_desc;

    mtev_hash_retrieve(configs, CONFIG_FQ_HOST, strlen(CONFIG_FQ_HOST),
        (void*) &host_desc);
    mtev_hash_retrieve(configs, CONFIG_FQ_PORT, strlen(CONFIG_FQ_PORT),
        (void*) &port_desc);
    mtev_hash_retrieve(configs, CONFIG_FQ_USER, strlen(CONFIG_FQ_USER),
        (void*) &user_desc);
    mtev_hash_retrieve(configs, CONFIG_FQ_PASS, strlen(CONFIG_FQ_PASS),
        (void*) &pass_desc);
    mtev_hash_retrieve(configs, CONFIG_FQ_EXCHANGE, strlen(CONFIG_FQ_EXCHANGE),
        (void*) &exchange_desc);
    mtev_hash_retrieve(configs, CONFIG_FQ_PROGRAM, strlen(CONFIG_FQ_PROGRAM),
        (void*) &program_desc);

    connect_fq_client(&fq_clients[section_id], host_desc->value.val_string,
        port_desc->value.val_int, user_desc->value.val_string,
        pass_desc->value.val_string, exchange_desc->value.val_string,
        program_desc->value.val_string);

    mtev_hash_destroy(configs, NULL, NULL);
    free(configs);
  }
  start_polling();

  if (number_of_connections == 0) {
    mtevL(mtev_error, "No fq config found!\n");
    exit(2);
  }
}
