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
#include <fq.h>

#define CONFIG_FQ_IN_MQ "//network/in/mq[@type='fq']"
#define CONFIG_FQ_HOST "self::node()/host"
#define CONFIG_FQ_PORT "self::node()/port"
#define CONFIG_FQ_USER "self::node()/user"
#define CONFIG_FQ_PASS "self::node()/pass"

static void logger(fq_client c, const char *s) {
  (void) c;
  mtevL(mtev_error, "fq_logger: %s\n", s);
}


static fq_client fq_c;

static void my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;

  if (error)
    return;

  printf("attempting bind\n");
  breq = malloc(sizeof(*breq));
  memset(breq, 0, sizeof(*breq));

  char* exchange = "noit.firehose";
  memcpy(breq->exchange.name, exchange, strlen(exchange));
  breq->exchange.len = strlen(exchange);
  breq->flags = FQ_BIND_TRANS;
  breq->program = strdup("prefix:\"test\"");
  fq_client_bind(c, breq);
}

static int poll_fq(eventer_t e, int mask, void *unused, struct timeval *now) {
  fq_msg *m;

  while (NULL != (m = fq_client_receive(fq_c))) {
    fq_msg_deref(m);
    mtevL(mtev_error, "Received!\n");
  }

  return 1;
}

static void my_bind_handler(fq_client c, fq_bind_req *breq) {
  (void) c;
  printf("route set -> %u\n", breq->out__route_id);
  if (breq->out__route_id == FQ_BIND_ILLEGAL) {
    fprintf(stderr, "Failure to bind...\n");
    exit(-1);
  }
}

fq_hooks hooks = { .version = FQ_HOOKS_V1, .auth = my_auth_handler, .bind =
    my_bind_handler };



static void connect_fq_client() {
  hrtime_t s, f;
  uint64_t cnt = 0, icnt = 0, icnt_total = 0;
  int rcvd = 0;
  fq_msg *m;

  char *fq_debug = getenv("FQ_DEBUG");
  if (fq_debug)
    fq_debug_set_bits(atoi(fq_debug));
  signal(SIGPIPE, SIG_IGN);
  fq_client_init(&fq_c, 0, logger);
  if (fq_client_hooks(fq_c, &hooks)) {
    fprintf(stderr, "Can't register hooks\n");
    exit(-1);
  }

  char* host = "mq4.dev.circonus.net";
  int port = 8765;
  char* user = "beaker";
  char* pass = "pass";

  fq_client_hooks(fq_c, &hooks);
  fq_client_creds(fq_c, host, port, user, pass);
  fq_client_heartbeat(fq_c, 1000);
  fq_client_set_backlog(fq_c, 10000, 100);
  fq_client_connect(fq_c);

  eventer_t receiver = eventer_alloc();
  receiver->mask = EVENTER_RECURRENT;
  receiver->callback = poll_fq;
  eventer_add(receiver);
}

void mtev_fq_init() {

  int number_of_connections = 0;
  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_FQ_IN_MQ, &number_of_connections);

  for (int section_id = 0; section_id != number_of_connections; ++section_id) {
    char* type;
    mtev_conf_get_string(mqs[section_id], "self::node()/@type", &type);

    struct mtev_conf_description_t descs[] = {

    { mqs[section_id], CONFIG_FQ_HOST, MTEV_CONF_TYPE_STRING,
        "Hostname of the fq broker data should be received from" },

    { mqs[section_id], CONFIG_FQ_PORT, MTEV_CONF_TYPE_INT,
        "Port number of the fq broker" },

    { mqs[section_id], CONFIG_FQ_USER, MTEV_CONF_TYPE_STRING,
        "User name used to connect to the fq broker" },

    { mqs[section_id], CONFIG_FQ_PASS, MTEV_CONF_TYPE_STRING,
        "Password used to connect to the fq broker" } };

    mtev_hash_table* configs;
    if ((configs = mtev_conf_check(descs,
        sizeof(descs) / sizeof(struct mtev_conf_description_t))) == NULL) {
      mtevL(mtev_error, "Incomplete fq config found!\n");
      exit(2);
    }

    const mtev_conf_description_t *dstr;
    mtev_hash_retrieve(configs, CONFIG_FQ_HOST, strlen(CONFIG_FQ_HOST), (void*)&dstr);

    mtevL(mtev_error, "Read host: %s!\n", dstr->value.val_string);
    free(configs);
  }

  if (number_of_connections == 0) {
    mtevL(mtev_error, "No fq config found!\n");
    exit(2);
  }
}
