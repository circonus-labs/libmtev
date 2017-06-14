/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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
 *
 *
 * Portions created by Alan Antonuk are Copyright (c) 2012-2013
 * Alan Antonuk. All Rights Reserved.
 *
 * Portions created by VMware are Copyright (c) 2007-2012 VMware, Inc.
 * All Rights Reserved.
 *
 * Portions created by Tony Garnock-Jones are Copyright (c) 2009-2010
 * VMware, Inc. and Tony Garnock-Jones. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"
#include "mtev_conf.h"
#include <ck_fifo.h>
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#include "mtev_amqp.h"

#include <errno.h>

MTEV_HOOK_IMPL(mtev_amqp_handle_message_dyn,
               (amqp_connection_state_t client, int id, amqp_envelope_t *msg, void *payload, size_t payload_len),
               void *, closure,
               (void *closure, amqp_connection_state_t client, int id, amqp_envelope_t *msg, void *payload, size_t payload_len),
               (closure,client,id,msg,payload,payload_len))

MTEV_HOOK_IMPL(mtev_amqp_handle_connection_dyn,
               (amqp_connection_state_t client, int id, mtev_boolean connected),
               void *, closure,
               (void *closure, amqp_connection_state_t client, int id, mtev_boolean connected),
               (closure,client,id,connected))

#define CONFIG_AMQP_IN_MQ "//network//mq[@type='amqp']"
#define CONFIG_AMQP_HOST "self::node()/host"
#define CONFIG_AMQP_VHOST "self::node()/vhost"
#define CONFIG_AMQP_FRAMESIZE "self::node()/framesize"
#define CONFIG_AMQP_PORT "self::node()/port"
#define CONFIG_AMQP_USER "self::node()/user"
#define CONFIG_AMQP_PASS "self::node()/pass"
#define CONFIG_AMQP_EXCHANGE "self::node()/exchange"
#define CONFIG_AMQP_BINDINGKEY "self::node()/bindingkey"

#define ENV_MANDATORY 1
#define ENV_IMMEDIATE 2

struct amqp_module_config {
  eventer_t receiver;
  struct amqp_conn {
    pthread_t tid;
    int idx;
    amqp_connection_state_t conn;
    ck_fifo_spsc_t outbound, inbound;
    struct connection_configs *config;
    char *host;
    int   port;
    char *user;
    char *pass;
    char *vhost;
    char *exchange;
    char *bindingkey;
    int   framesize;
  } *amqp_conns;
  int number_of_conns;
};

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;
static struct amqp_module_config *the_conf;

static struct amqp_module_config *get_config(mtev_dso_generic_t *self) {
  if(the_conf) return the_conf;
  the_conf = mtev_image_get_userdata(&self->hdr);
  if(the_conf) return the_conf;
  the_conf = calloc(1, sizeof(*the_conf));
  mtev_image_set_userdata(&self->hdr, the_conf);
  return the_conf;
}

static int poll_amqp(eventer_t e, int mask, void *unused, struct timeval *now) {
  int client = 0;
  amqp_envelope_t *env = NULL;
  for (client = 0; client != the_conf->number_of_conns; ++client) {
    while(1) {
      struct amqp_conn *cc = &the_conf->amqp_conns[client];
      ck_fifo_spsc_dequeue_lock(&cc->inbound);
      bool found = ck_fifo_spsc_dequeue(&cc->inbound, &env);
      ck_fifo_spsc_dequeue_unlock(&cc->inbound);
      if(!found) break;
      mtev_amqp_handle_message_dyn_hook_invoke(cc->conn, client, env,
        env->message.body.bytes, env->message.body.len);
      amqp_destroy_envelope(env);
      free(env);
    }
  }

  return 1;
}

#define die_on_amqp_error(t,c) do { \
  if(on_amqp_error(t,c) != 0) goto teardown; \
} while(0)
static int on_amqp_error(amqp_rpc_reply_t x, char const *context)
{
  switch (x.reply_type) {
  case AMQP_RESPONSE_NORMAL:
    return 0;

  case AMQP_RESPONSE_NONE:
    mtevL(nlerr, "%s: missing RPC reply type!\n", context);
    break;

  case AMQP_RESPONSE_LIBRARY_EXCEPTION:
    mtevL(nlerr, "%s: %s\n", context, amqp_error_string2(x.library_error));
    break;

  case AMQP_RESPONSE_SERVER_EXCEPTION:
    switch (x.reply.id) {
    case AMQP_CONNECTION_CLOSE_METHOD: {
      amqp_connection_close_t *m = (amqp_connection_close_t *) x.reply.decoded;
      mtevL(nlerr, "%s: server connection error %uh, message: %.*s\n",
              context,
              m->reply_code,
              (int) m->reply_text.len, (char *) m->reply_text.bytes);
      break;
    }
    case AMQP_CHANNEL_CLOSE_METHOD: {
      amqp_channel_close_t *m = (amqp_channel_close_t *) x.reply.decoded;
      mtevL(nlerr, "%s: server channel error %uh, message: %.*s\n",
              context,
              m->reply_code,
              (int) m->reply_text.len, (char *) m->reply_text.bytes);
      break;
    }
    default:
      mtevL(nlerr, "%s: unknown server error, method id 0x%08X\n", context, x.reply.id);
      break;
    }
    break;
  }
  return -1;
}

/* We use the fifo a bit unconventionally here, but we are
   actually the only consumer on this, so there is no competitor
   that could come in an confuse this.
   We effectively peek (instead of pop) the message for sending
   so that if it fails we can leave it enqueued where it is.
   If we send without issue, then we dequeue and then free.
 */
static int
drain_outbound_queue(struct amqp_conn *cc) {
  int cnt = 0;
  while(1) {
    amqp_envelope_t *env = NULL, *sameenv = NULL;
    struct ck_fifo_spsc_entry *entry;
    int rv;
    ck_fifo_spsc_dequeue_lock(&cc->outbound);
    entry = CK_FIFO_SPSC_FIRST(&cc->outbound);
    if(entry != NULL) env = entry->value;
    ck_fifo_spsc_dequeue_unlock(&cc->outbound);
    if(env) {
      amqp_boolean_t mandatory = (uintptr_t)env & ENV_MANDATORY;
      amqp_boolean_t immediate = (uintptr_t)env & ENV_IMMEDIATE;
      env = (void *)((uintptr_t)env & ~(sizeof(uintptr_t)-1));
      rv = amqp_basic_publish(cc->conn, 1, env->exchange, env->routing_key,
                              mandatory, immediate,
                              &env->message.properties, env->message.body);
      if(rv != AMQP_STATUS_OK) {
        mtevL(nlerr, "basic_publish failed: %d\n", rv);
        return -1;
      }
    }
    ck_fifo_spsc_dequeue_lock(&cc->outbound);
    bool found = ck_fifo_spsc_dequeue(&cc->outbound, &sameenv);
    ck_fifo_spsc_dequeue_unlock(&cc->outbound);
    if(!found) break;
    sameenv = (void *)((uintptr_t)sameenv & ~(sizeof(uintptr_t)-1));
    mtevAssert(env == sameenv);
    amqp_destroy_envelope(env);
    free(env);
    cnt++;
  }
  return cnt;
}
/* Because amqp_connection_state_t's are not thread safe, we must read and
   write to this connection in the same thread... here.
   This is problematic b/c knowing we have data to write and knowing we can
   read data use different fascilitites and thus we have to spin.

   So.. we will wait for "up to" 50ms to receive a message and then drain
   our outbound queue.  If the inbound channel is idle, this means that we
   will send outbound data in tight bunches every 50ms.

   This function does work until it can't make progress (error) and then
   returns to the caller (which will shutdown the connection and attempt to
   bring it back online).
 */
static void
handleconn(struct amqp_conn *conn) {
  while(1) {
    struct timeval small_sleep = { 0, 100000 }; /* 50ms */
    amqp_envelope_t envelope;
    amqp_frame_t frame;

    if(drain_outbound_queue(conn) < 0) return;

    amqp_maybe_release_buffers(conn->conn);

    amqp_rpc_reply_t ret = amqp_consume_message(conn->conn, &envelope, &small_sleep, 0);

    if (ret.reply_type == AMQP_RESPONSE_NORMAL) {
      amqp_envelope_t *env = malloc(sizeof(*env));
      memcpy(env, &envelope, sizeof(*env));
      ck_fifo_spsc_enqueue_lock(&conn->inbound);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(&conn->inbound);
      if (fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_fifo_spsc_enqueue(&conn->inbound, fifo_entry, env);
      ck_fifo_spsc_enqueue_unlock(&conn->inbound);
    }
    else if (ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
             ret.library_error == AMQP_STATUS_UNEXPECTED_STATE) {
      if (amqp_simple_wait_frame(conn->conn, &frame) != AMQP_STATUS_OK) {
        on_amqp_error(ret, "consuming message");
        return;
      }

      if (frame.frame_type == AMQP_FRAME_METHOD) {
        switch (frame.payload.method.id) {
          case AMQP_BASIC_ACK_METHOD:
            break;
          case AMQP_BASIC_RETURN_METHOD:
            ret = amqp_read_message(conn->conn, frame.channel, &envelope.message, 0);
            if (ret.reply_type != AMQP_RESPONSE_NORMAL) {
              on_amqp_error(ret, "reading basic return");
              return;
            }
            amqp_destroy_message(&envelope.message);
            break;

          case AMQP_CHANNEL_CLOSE_METHOD:
          case AMQP_CONNECTION_CLOSE_METHOD:
          default:
            mtevL(nlerr ,"closing amqp session[%s] %x\n", conn->host, frame.payload.method.id);
            return;
        }
      }
    }
  }
}
static void *
rabbitmq_manage_connection(void *vconn) {
  struct timeval fiveseconds = { 5, 0 };
  struct amqp_conn *conn = vconn;

  while(1) {
    conn->conn = amqp_new_connection();
    amqp_socket_t *socket = amqp_tcp_socket_new(conn->conn);
    if (!socket) {
      mtevL(nlerr, "AMQP error creating socket: %s\n", strerror(errno));
      goto teardown;
    }
    eventer_set_fd_blocking(amqp_socket_get_sockfd(socket));
    int status = amqp_socket_open_noblock(socket, conn->host, conn->port, &fiveseconds);
    if (status) {
      mtevL(nlerr, "AMQP error connecting socket: %s\n", strerror(errno));
      goto teardown;
    }

    die_on_amqp_error(
      amqp_login(conn->conn, conn->vhost, 0, conn->framesize, 0,
                 AMQP_SASL_METHOD_PLAIN, conn->user, conn->pass),
      "logging in");
    amqp_channel_open(conn->conn, 1);
    die_on_amqp_error(amqp_get_rpc_reply(conn->conn), "opening channel");

    if(conn->bindingkey && strlen(conn->bindingkey)) {
      amqp_queue_declare_ok_t *r =
        amqp_queue_declare(conn->conn, 1,
                           amqp_empty_bytes, 0, 0, 0, 1,
                           amqp_empty_table);
      die_on_amqp_error(amqp_get_rpc_reply(conn->conn), "declaring queue");
      amqp_bytes_t queuename = amqp_bytes_malloc_dup(r->queue);
      mtevAssert(queuename.bytes != NULL);
      amqp_queue_bind(conn->conn, 1, queuename,
                      amqp_cstring_bytes(conn->exchange),
                      amqp_cstring_bytes(conn->bindingkey),
                      amqp_empty_table);
      die_on_amqp_error(amqp_get_rpc_reply(conn->conn), "binding queue");
      amqp_basic_consume(conn->conn, 1, queuename, amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
      die_on_amqp_error(amqp_get_rpc_reply(conn->conn), "consuming");
    }

    mtev_amqp_handle_connection_dyn_hook_invoke(conn->conn, conn->idx, mtev_true);
    handleconn(conn);
    mtev_amqp_handle_connection_dyn_hook_invoke(conn->conn, conn->idx, mtev_false);

    die_on_amqp_error(amqp_channel_close(conn->conn, 1, AMQP_REPLY_SUCCESS), "Closing channel");
    die_on_amqp_error(amqp_connection_close(conn->conn, AMQP_REPLY_SUCCESS), "Closing connection");

  teardown:
    amqp_destroy_connection(conn->conn);
  }
}

static int
init_conns(void) {
  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_AMQP_IN_MQ,
      &the_conf->number_of_conns);

  if(the_conf->number_of_conns == 0) {
    free(mqs);
    return 0;
  }

  the_conf->amqp_conns = calloc(the_conf->number_of_conns, sizeof(*the_conf->amqp_conns));

  for (int section_id = 0; section_id != the_conf->number_of_conns; ++section_id) {
    struct amqp_conn *cc = &the_conf->amqp_conns[section_id];

    cc->idx = section_id;

    ck_fifo_spsc_init(&cc->inbound, malloc(sizeof(ck_fifo_spsc_entry_t)));
    ck_fifo_spsc_init(&cc->outbound, malloc(sizeof(ck_fifo_spsc_entry_t)));

    if(!mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_HOST, &cc->host))
      cc->host = strdup("localhost");
    if(!mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_VHOST, &cc->vhost))
      cc->vhost = strdup("/");
    if(!mtev_conf_get_int(mqs[section_id], CONFIG_AMQP_PORT, &cc->port))
      cc->port = 5672;
    if(!mtev_conf_get_int(mqs[section_id], CONFIG_AMQP_FRAMESIZE, &cc->framesize))
      cc->framesize = AMQP_DEFAULT_FRAME_SIZE;
    if(!mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_USER, &cc->user))
      cc->user = strdup("guest");
    if(!mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_PASS, &cc->pass))
      cc->pass = strdup("guest");
    if(!mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_EXCHANGE, &cc->exchange))
      cc->exchange = strdup("amq.direct");
    mtev_conf_get_string(mqs[section_id], CONFIG_AMQP_BINDINGKEY, &cc->bindingkey);

    if(pthread_create(&the_conf->amqp_conns[section_id].tid, NULL,
                      rabbitmq_manage_connection, cc) != 0) {
      mtevL(nlerr, "Failed to start thread for amqp: %s\n", strerror(errno));
      goto bail;
    }
  }
  free(mqs);
  return 0;

 bail:
  free(mqs);
  return -1;
}

static uint64_t dtag;

static amqp_envelope_t *copy_envelope(amqp_envelope_t *in) {
  amqp_envelope_t *out = calloc(1, sizeof(*out));
  memcpy(out, in, sizeof(*out));
  init_amqp_pool(&out->message.pool, 0);
#undef CIO
#define CIO(f) do { \
  if(out->f.bytes) { \
    amqp_pool_alloc_bytes(&out->message.pool, in->f.len, &out->f); \
    memcpy(out->f.bytes, in->f.bytes, in->f.len); \
  } \
} while(0)
  /* These are all the keys from amqp.h and amqp_framing.h */
  CIO(message.properties.content_type);
  CIO(message.properties.content_encoding);
  CIO(message.properties.correlation_id);
  CIO(message.properties.reply_to);
  CIO(message.properties.expiration);
  CIO(message.properties.message_id);
  CIO(message.properties.type);
  CIO(message.properties.user_id);
  CIO(message.properties.app_id);
  CIO(message.properties.cluster_id);
#undef CIO
  /* now we clone the headers */
  amqp_table_clone(&in->message.properties.headers,
                   &out->message.properties.headers, &out->message.pool);
  /* now the simple dup of envelope bytes */
  out->consumer_tag = amqp_bytes_malloc_dup(in->consumer_tag);
  out->exchange = amqp_bytes_malloc_dup(in->exchange);
  out->routing_key = amqp_bytes_malloc_dup(in->routing_key);
  return out;
}

void
mtev_amqp_send_function(amqp_envelope_t *env, int mandatory, int immediate, int connection_id_broadcast_if_negative) {
  int i;
  uintptr_t mask = 0;
  if(mandatory != 0) mask |= ENV_MANDATORY;
  if(immediate != 0) mask |= ENV_IMMEDIATE;
  /* We need to make N copies of the message here if we're broadcassting */
  amqp_envelope_t *copies[the_conf->number_of_conns];
  for (i=0; i<the_conf->number_of_conns; i++) {
    copies[i] = NULL;
  }
  if(connection_id_broadcast_if_negative < 0) {
    copies[0] = (void *)((uintptr_t)env | mask);
    for(i=1; i<the_conf->number_of_conns; i++) {
      copies[i] = copy_envelope(env);
      copies[i] = (void *)((uintptr_t)copies[i] | mask);
    }
  }
  else {
    env = (void *)((uintptr_t)env | mask);
    copies[connection_id_broadcast_if_negative] = env;
  }

  for (i=0; i<the_conf->number_of_conns; i++) {
    struct amqp_conn *cc = &the_conf->amqp_conns[i];
    if(connection_id_broadcast_if_negative < 0 ||
       i == connection_id_broadcast_if_negative) {
      ck_fifo_spsc_enqueue_lock(&cc->outbound);
      ck_fifo_spsc_entry_t *fifo_entry = ck_fifo_spsc_recycle(&cc->outbound);
      if (fifo_entry == NULL) fifo_entry = malloc(sizeof(*fifo_entry));
      ck_fifo_spsc_enqueue(&cc->outbound, fifo_entry, copies[i]);
      ck_fifo_spsc_enqueue_unlock(&cc->outbound);
    }
  }
}
void
mtev_amqp_send_data_function(char *exchange, char *route, int mandatory, int immediate,
                             void *payload, int len, int connection_id_broadcast_if_negative) {
  amqp_envelope_t *env = calloc(1, sizeof(*env));
  init_amqp_pool(&env->message.pool, 0);
  env->channel = 1;
  env->delivery_tag = ck_pr_faa_64(&dtag, 1);
  env->exchange.bytes = strdup(exchange);
  env->exchange.len = strlen(exchange);
  env->routing_key.bytes = strdup(route);
  env->routing_key.len = strlen(route);
  env->message.body = amqp_bytes_malloc(len);
  memcpy(env->message.body.bytes, payload, len);
  mtev_amqp_send_function(env, mandatory, immediate, connection_id_broadcast_if_negative);
}

static int
amqp_logio_open(mtev_log_stream_t ls) {
  return 0;
}

static int
amqp_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
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
  mtev_amqp_send_data(exchange, route, false, false, (void *)buf, len, -1);
  return len;
}

static logops_t amqp_logio_ops = {
  mtev_false,
  amqp_logio_open,
  NULL,
  amqp_logio_write,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static int
amqp_driver_init(mtev_dso_generic_t *img) {
  struct amqp_module_config *conf = get_config(img);

  mtev_register_logops("amqp", &amqp_logio_ops);

  nlerr = mtev_log_stream_find("error/amqp");
  nldeb = mtev_log_stream_find("debug/amqp");

  if(init_conns() != 0) return -1;

  if (the_conf->number_of_conns == 0) {
    mtevL(nlerr, "No amqp reciever setting found in the config!\n");
    return 0;
  }

  conf->receiver = eventer_alloc_recurrent(poll_amqp, NULL);
  eventer_add(conf->receiver);
  return 0;
}

static int
amqp_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    mtevL(nldeb, "AMQP module config: %s=%s\n", iter.key.str, iter.value.str);
  }
  return 0;
}
#include "amqp.xmlh"
mtev_dso_generic_t amqp = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "amqp",
    .description = "An AMQP subscriber and publisher",
    .xml_description = amqp_xml_description,
  },
  amqp_driver_config,
  amqp_driver_init
};
