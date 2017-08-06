/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
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

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"
#include "mtev_conf.h"
#include <fq.h>
#include "mtev_fq.h"

MTEV_HOOK_IMPL(mtev_fq_handle_message_dyn,
               (fq_client client, int id, struct fq_msg *msg, void *payload, size_t payload_len),
               void *, closure,
               (void *closure, fq_client client, int id, struct fq_msg *msg, void *payload, size_t payload_len),
               (closure,client,id,msg,payload,payload_len))

#define CONFIG_FQ_IN_MQ "//network//mq[@type='fq']"
#define CONFIG_FQ_HOST "self::node()/host"
#define CONFIG_FQ_PORT "self::node()/port"
#define CONFIG_FQ_USER "self::node()/user"
#define CONFIG_FQ_PASS "self::node()/pass"
#define CONFIG_FQ_EXCHANGE "self::node()/exchange"
#define CONFIG_FQ_PROGRAM "self::node()/program"

typedef struct connection_configs {
  char* host;
  int32_t port;
  char* user;
  char* pass;
} connection_configs;

static void
connection_configs_free(connection_configs *c) {
  free(c->host);
  free(c->user);
  free(c->pass);
  free(c);
}

struct fq_module_config {
  eventer_t receiver;
  fq_client* fq_conns;
  int number_of_conns;
};

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;
static struct fq_module_config *the_conf;

static struct fq_module_config *get_config(mtev_dso_generic_t *self) {
  if(the_conf) return the_conf;
  the_conf = mtev_image_get_userdata(&self->hdr);
  if(the_conf) return the_conf;
  the_conf = calloc(1, sizeof(*the_conf));
  mtev_image_set_userdata(&self->hdr, the_conf);
  return the_conf;
}

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

static void logger(fq_client c, const char *s) {
  (void) c;
  mtevL(nlerr, "fq_logger: %s\n", s);
}

static void my_auth_handler(fq_client c, int error) {
  fq_bind_req *breq;

  if (error)
    return;

  breq = malloc(sizeof(*breq));
  memset(breq, 0, sizeof(*breq));

  exchange_and_program* eap = fq_client_get_userdata(c);
  if(eap) {
    char *exchange = eap->exchange;

    memcpy(breq->exchange.name, exchange, strlen(exchange));
    breq->exchange.len = strlen(exchange);
    breq->flags = FQ_BIND_TRANS;
    breq->program = strdup(eap->program);
    fq_client_bind(c, breq);
  }
}

static int poll_fq(eventer_t e, int mask, void *unused, struct timeval *now) {
  int cnt = 0;
  fq_msg *m;

  for (int client = 0; client != the_conf->number_of_conns; ++client) {
    while (NULL != (m = fq_client_receive(the_conf->fq_conns[client]))) {
      mtev_fq_handle_message_dyn_hook_invoke(the_conf->fq_conns[client], client, m, m->payload, m->payload_len);
      fq_msg_deref(m);
      cnt++;
    }
  }

  return cnt ? EVENTER_RECURRENT : 0;
}

static void my_bind_handler(fq_client c, fq_bind_req *breq) {
  (void) c;
  mtevL(nldeb, "route set -> %u\n", breq->out__route_id);
  if (breq->out__route_id == FQ_BIND_ILLEGAL) {
    mtevL(nlerr, "Failure to bind...\n");
    exit(-1);
  }
  free(breq->program);
  free(breq);
}
static bool my_message_ping(fq_client client, fq_msg *m) {
  (void)client;
  (void)m;
  eventer_wakeup(the_conf->receiver);
  return false; /* This causes it to be delivered normally via the queue. */
}

fq_hooks hooks = {
  .version = FQ_HOOKS_V4,
  .auth = my_auth_handler,
  .bind = my_bind_handler,
  .message = my_message_ping
};

static void connect_fq_client(fq_client *fq_c, char *host, int port, char *user,
    char *pass, char* exchange, char* program) {
  mtevL(nldeb, "Connecting with fq broker: %s:%d!\n", host, port);
  fq_client_init(fq_c, 0, logger);

  if (fq_client_hooks(*fq_c, &hooks)) {
    mtevL(nlerr, "Can't register hooks\n");
    exit(-1);
  }
  if (exchange != NULL && program != NULL) {
    fq_client_set_userdata(*fq_c,
        create_exchange_and_program(exchange, program));
  }

  fq_client_creds(*fq_c, host, port, user, pass);
  fq_client_heartbeat(*fq_c, 1000);
  fq_client_set_backlog(*fq_c, 10000, 100);
  fq_client_connect(*fq_c);
}

static connection_configs *check_connection_conf(mtev_conf_section_t section) {
  connection_configs *configs_table = calloc(1, sizeof(connection_configs));

  mtev_conf_description_t desc;
  desc = mtev_conf_description_string(section,
  CONFIG_FQ_HOST, "Hostname of the fq broker data should be received from",
      mtev_conf_default_string("localhost"));
  mtev_conf_get_value(&desc, &configs_table->host);

  desc = mtev_conf_description_int32(section, CONFIG_FQ_PORT,
      "Port number of the fq broker", mtev_conf_default_int32(8765));
  mtev_conf_get_value(&desc, &configs_table->port);

  desc = mtev_conf_description_string(section, CONFIG_FQ_USER,
      "User name used to connect to the fq broker",
      mtev_conf_default_string("guest"));
  mtev_conf_get_value(&desc, &configs_table->user);

  desc = mtev_conf_description_string(section, CONFIG_FQ_PASS,
      "User name used to connect to the fq broker",
      mtev_conf_default_string("guest"));
  mtev_conf_get_value(&desc, &configs_table->pass);


  return configs_table;
}

static void
init_conns(void) {
  mtev_conf_section_t *mqs = mtev_conf_get_sections(MTEV_CONF_ROOT, CONFIG_FQ_IN_MQ,
      &the_conf->number_of_conns);

  if(the_conf->number_of_conns == 0) {
    mtev_conf_release_sections(mqs, the_conf->number_of_conns);
    return;
  }

  the_conf->fq_conns = malloc(the_conf->number_of_conns * sizeof(fq_client));

  for (int section_id = 0; section_id != the_conf->number_of_conns; ++section_id) {
    char *exchange = NULL, *program = NULL;
    connection_configs *connection_configs = check_connection_conf(mqs[section_id]);
    mtev_conf_get_string(mqs[section_id], CONFIG_FQ_EXCHANGE, &exchange);
    mtev_conf_get_string(mqs[section_id], CONFIG_FQ_PROGRAM, &program);
    connect_fq_client(&the_conf->fq_conns[section_id], connection_configs->host,
        connection_configs->port, connection_configs->user,
        connection_configs->pass, exchange, program);
    connection_configs_free(connection_configs);
    free(exchange);
    free(program);
  }
  mtev_conf_release_sections(mqs, the_conf->number_of_conns);
}

/* Do not mtevL in these functions, as they may implement mtevL */
void
mtev_fq_send_function(fq_msg *msg, int connection_id_broadcast_if_negative) {
  if (connection_id_broadcast_if_negative >= the_conf->number_of_conns) return;

  int first_host = connection_id_broadcast_if_negative;
  int last_host_plus_one = connection_id_broadcast_if_negative + 1;
  if (connection_id_broadcast_if_negative < 0) {
    first_host = 0;
    last_host_plus_one = the_conf->number_of_conns;
  }

  for (int connection_id = first_host; connection_id != last_host_plus_one; ++connection_id) {
    fq_client_publish(the_conf->fq_conns[connection_id], msg);
  }
}

void
mtev_fq_send_data_function(char *exchange, char *route, void *payload, int len, int connection_id_broadcast_if_negative) {
  fq_msg *m;
  m = fq_msg_alloc(payload, len);
  fq_msg_exchange(m, exchange, strlen(exchange));
  fq_msg_route(m, route, strlen(route));
  mtev_fq_send_function(m, connection_id_broadcast_if_negative);
  fq_msg_free(m);
}

static int
fq_logio_open(mtev_log_stream_t ls) {
  return 0;
}

static int
fq_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
               const void *buf, size_t len) {
  char exchange[127], route[127], *prefix, *path;
  path = (char *)mtev_log_stream_get_path(ls);
  prefix = strchr(path, '/');
  if(!prefix) {
    strlcpy(exchange, path, sizeof(exchange));
    snprintf(route, sizeof(route), "mtev.log.%s", mtev_log_stream_get_name(ls));
  } else {
    prefix++;
    strlcpy(exchange, path, MIN(sizeof(exchange), (prefix - path)));
    snprintf(route, sizeof(route), "%s.%s", prefix, mtev_log_stream_get_name(ls));
  }
  mtev_fq_send_data(exchange, route, (void *)buf, len, -1);
  return len;
}

static logops_t fq_logio_ops = {
  mtev_false,
  fq_logio_open,
  NULL,
  fq_logio_write,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static int
fq_driver_init(mtev_dso_generic_t *img) {
  struct fq_module_config *conf = get_config(img);

  mtev_register_logops("fq", &fq_logio_ops);

  nlerr = mtev_log_stream_find("error/fq");
  nldeb = mtev_log_stream_find("debug/fq");
  init_conns();

  if (the_conf->number_of_conns == 0) {
    mtevL(nlerr, "No fq reciever setting found in the config!\n");
    return 0;
  }

  conf->receiver = eventer_alloc_recurrent(poll_fq, NULL);
  eventer_add(conf->receiver);
  return 0;
}

static int
fq_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    mtevL(mtev_error, "%s %s!\n", iter.key.str, iter.value.str);
  }
  return 0;
}
#include "fq.xmlh"
mtev_dso_generic_t fq = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "fq",
    .description = "A Fq subscriber and publisher",
    .xml_description = fq_xml_description,
  },
  fq_driver_config,
  fq_driver_init
};
