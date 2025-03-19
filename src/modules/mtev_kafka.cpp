/*
 * Copyright (c) 2025, Circonus, Inc. All rights reserved.
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

#include <librdkafka/rdkafka.h>

#include "mtev_conf.h"
#include "mtev_dso.h"
#include "mtev_hooks.h"
#include "mtev_kafka.h"
#include "mtev_log.h"
#include "mtev_rand.h"
#include "mtev_thread.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#define CONFIG_KAFKA_IN_MQ "//network//mq[@type='kafka']"

static constexpr const char *VARIABLE_PARAMETER_PREFIX = "override_";
static constexpr size_t VARIABLE_PARAMETER_PREFIX_LEN = strlen(VARIABLE_PARAMETER_PREFIX);

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;

constexpr int32_t DEFAULT_POLL_TIMEOUT_MS = 10;
constexpr int32_t DEFAULT_POLL_LIMIT = 10000;

extern "C" {
MTEV_HOOK_IMPL(mtev_kafka_handle_message_dyn,
               (mtev_rd_kafka_message_t * msg),
               void *,
               closure,
               (void *closure, mtev_rd_kafka_message_t *msg),
               (closure, msg))
}

static void mtev_rd_kafka_message_free(mtev_rd_kafka_message_t *msg)
{
  mtevAssert(msg->refcnt == 0);
  rd_kafka_message_destroy(msg->msg);
  free(msg);
}

static mtev_rd_kafka_message_t *
  mtev_rd_kafka_message_alloc(rd_kafka_message_t *msg,
                              const char *protocol,
                              const mtev_hash_table *extra_configs,
                              void (*free_func)(struct mtev_rd_kafka_message *))
{
  mtev_rd_kafka_message_t *m =
    (mtev_rd_kafka_message_t *) calloc(1, sizeof(mtev_rd_kafka_message_t));
  m->msg = msg;
  m->refcnt = 1;
  m->free_fn = free_func;
  m->key = msg->key;
  m->key_len = msg->key_len;
  m->payload = msg->payload;
  m->payload_len = msg->len;
  m->offset = msg->offset;
  m->partition = msg->partition;
  m->protocol = protocol;
  m->extra_configs = extra_configs;
  return m;
}

struct kafka_stats_t {
  kafka_stats_t() : msgs_in{0}, msgs_out{0}, errors{0} {}
  ~kafka_stats_t() = default;

  uint64_t msgs_in;
  uint64_t msgs_out;
  uint64_t errors;
};

struct kafka_connection {
  kafka_connection(const std::string &host_in,
                   const int32_t port_in,
                   const std::string &topic_in,
                   const std::string consumer_group_in,
                   const std::string protocol_in,
                   mtev_hash_table *extra_configs_in)
  {
    host = host_in;
    port = port_in;
    topic = topic_in;
    broker_with_port = host + ":" + std::to_string(port);
    consumer_group = consumer_group_in;
    protocol = protocol_in;
    extra_configs = extra_configs_in;

    constexpr size_t error_string_size = 256;
    char error_string[error_string_size];

    // Set consumer configuration stuff
    rd_consumer_conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(rd_consumer_conf, "enable.idempotence", "true", error_string,
                          error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting enable.idempotence field on consumer for " +
        broker_with_port + ", topic " + topic + ": kafka reported error |" + error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_consumer_conf, "bootstrap.servers", broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting bootstrap.servers field on consumer for " +
        broker_with_port + ", topic " + topic + ": kafka reported error |" + error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_consumer_conf, "group.id", consumer_group.c_str(), error_string,
                          error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "kafka config error: error setting group.id field on consumer for " +
        broker_with_port + ", topic " + topic + ": kafka reported error |" + error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }

    // Set producer configuration stuff
    // TODO: The producer is not actively used for anything yet. Need to implement write/publish
    // functions and hooks.
    rd_producer_conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(rd_producer_conf, "enable.idempotence", "true", error_string,
                          error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting enable.idempotence field on producer for " +
        broker_with_port + ", topic " + topic + ": kafka reported error |" + error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      rd_kafka_conf_destroy(rd_producer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_producer_conf, "bootstrap.servers", broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting bootstrap.servers field on producer for " +
        broker_with_port + ", topic " + topic + ": kafka reported error |" + error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      rd_kafka_conf_destroy(rd_producer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }

    rd_consumer =
      rd_kafka_new(RD_KAFKA_CONSUMER, rd_consumer_conf, error_string, error_string_size);

    rd_producer =
      rd_kafka_new(RD_KAFKA_PRODUCER, rd_producer_conf, error_string, error_string_size);

    rd_consumer_topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(rd_consumer_topics, topic.c_str(), RD_KAFKA_PARTITION_UA);
    rd_kafka_subscribe(rd_consumer, rd_consumer_topics);
  }
  kafka_connection() = delete;
  ~kafka_connection()
  {
    rd_kafka_topic_partition_list_destroy(rd_consumer_topics);
    rd_kafka_unsubscribe(rd_consumer);
    rd_kafka_conf_destroy(rd_consumer_conf);
    rd_kafka_destroy(rd_consumer);
    rd_kafka_conf_destroy(rd_producer_conf);
    rd_kafka_destroy(rd_producer);
    mtev_hash_destroy(extra_configs, free, free);
    free(extra_configs);
  }
  void write_to_console(const mtev_console_closure_t &ncct)
  {
    nc_printf(ncct,
              "== %s:%d ==\n"
              "  topic: %s\n  consumer_group: %s\n"
              "  (s) msgs tx: %zu\n  (s) msgs rx: %zu\n  (s) msgs tx errors: %zu\n",
              host.c_str(), port, topic.c_str(), consumer_group.c_str(), stats.msgs_in,
              stats.msgs_out, stats.errors);
  }

  std::string host;
  int32_t port;
  std::string broker_with_port;
  std::string topic;
  std::string consumer_group;
  std::string protocol;
  mtev_hash_table *extra_configs;
  rd_kafka_conf_t *rd_producer_conf;
  rd_kafka_t *rd_producer;
  rd_kafka_conf_t *rd_consumer_conf;
  rd_kafka_t *rd_consumer;
  rd_kafka_topic_partition_list_t *rd_consumer_topics;
  kafka_stats_t stats;
};

class kafka_module_config {
public:
  kafka_module_config()
    : _poll_timeout{std::chrono::milliseconds{DEFAULT_POLL_TIMEOUT_MS}}, _poll_limit{
                                                                           DEFAULT_POLL_LIMIT}
  {
    int number_of_conns = 0;
    mtev_conf_section_t *mqs =
      mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_IN_MQ, &number_of_conns);

    if (number_of_conns == 0) {
      mtev_conf_release_sections_read(mqs, number_of_conns);
      return;
    }
    for (int section_id = 0; section_id < number_of_conns; section_id++) {
      std::string host_string = "localhost";
      int32_t port = 9092;
      std::string topic_string = "mtev_default_topic";
      std::string consumer_group_string = "mtev_default_group";
      std::string protocol_string = "not_provided";
      mtev_hash_table *extra_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));
      mtev_hash_init(extra_configs);

      auto entries = mtev_conf_get_hash(mqs[section_id], "self::node()");
      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      while (mtev_hash_adv(entries, &iter)) {
        if (!strcasecmp("host", iter.key.str)) {
          host_string = iter.value.str;
        }
        else if (!strcasecmp("port", iter.key.str)) {
          port = atoi(iter.value.str);
        }
        else if (!strcasecmp("topic", iter.key.str)) {
          topic_string = iter.value.str;
        }
        else if (!strcasecmp("consumer_group", iter.key.str)) {
          consumer_group_string = iter.value.str;
        }
        else if (!strcasecmp("protocol", iter.key.str)) {
          protocol_string = iter.value.str;
        }
        else if (!strncasecmp(iter.key.str, VARIABLE_PARAMETER_PREFIX,
                              VARIABLE_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + VARIABLE_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(extra_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(nlerr, "WARNING: Duplicate config key found (key %s, value %s)... discarding\n",
                  key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
      }
      mtev_hash_destroy(entries, free, free);
      free(entries);

      try {
        auto conn =
          std::make_unique<kafka_connection>(host_string, port, topic_string, consumer_group_string,
                                             protocol_string, std::move(extra_configs));
        _conns.push_back(std::move(conn));
      }
      catch (std::exception &exception) {
        mtevL(nlerr, "ERROR: Couldn't connect to %s:%d, topic %s (Exception: %s) - skipping\n",
              host_string.c_str(), port, topic_string.c_str(), exception.what());
      }
      catch (...) {
        mtevL(nlerr, "ERROR: Couldn't connect to %s:%d, topic %s (unknown exception) - skipping\n",
              host_string.c_str(), port, topic_string.c_str());
      }
    }
    mtev_conf_release_sections_read(mqs, number_of_conns);
  }
  ~kafka_module_config() = default;
  void set_poll_timeout(const std::chrono::milliseconds poll_timeout)
  {
    _poll_timeout = poll_timeout;
  }
  void set_poll_limit(const int32_t poll_limit) { _poll_limit = poll_limit; }
  int poll()
  {
    for (const auto &conn : _conns) {
      int32_t per_conn_cnt = 0;
      rd_kafka_message_t *msg = nullptr;
      while (
        (_poll_limit == 0 || per_conn_cnt < _poll_limit) &&
        (nullptr != (msg = rd_kafka_consumer_poll(conn->rd_consumer, _poll_timeout.count())))) {
        conn->stats.msgs_in++;
        per_conn_cnt++;
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
          mtev_rd_kafka_message_t *m = mtev_rd_kafka_message_alloc(
            msg, conn->protocol.c_str(), conn->extra_configs, mtev_rd_kafka_message_free);
          mtev_kafka_handle_message_dyn_hook_invoke(m);
          mtev_rd_kafka_message_deref(m);
        }
        else {
          mtevL(nlerr, "ERROR: Got error reading from %s, topic %s: %s\n",
                conn->broker_with_port.c_str(), conn->topic.c_str(), rd_kafka_err2str(msg->err));
          conn->stats.errors++;
          rd_kafka_message_destroy(msg);
        }
      }
    }
    return 0;
  }
  int show_console(const mtev_console_closure_t &ncct)
  {
    for (const auto &conn : _conns) {
      conn->write_to_console(ncct);
    }
    return 0;
  }

private:
  std::vector<std::unique_ptr<kafka_connection>> _conns;
  std::chrono::milliseconds _poll_timeout;
  int32_t _poll_limit;
};

static kafka_module_config *the_conf = nullptr;

static kafka_module_config *get_or_load_config(mtev_dso_generic_t *self)
{
  if (the_conf) {
    return the_conf;
  }
  the_conf = static_cast<kafka_module_config *>(mtev_image_get_userdata(&self->hdr));
  if (the_conf) {
    return the_conf;
  }
  the_conf = new kafka_module_config{};
  mtev_image_set_userdata(&self->hdr, the_conf);
  return the_conf;
}

void
mtev_kafka_send_function(const void *payload, size_t payload_len) {
}

void
mtev_kafka_send_data_function(const void *payload, size_t payload_len) {
  mtev_kafka_send_function(payload, payload_len);
}

static int kafka_logio_open(mtev_log_stream_t ls)
{
  (void) ls;
  return -1;
}

static int
  kafka_logio_write(mtev_log_stream_t ls, const struct timeval *whence, const void *buf, size_t len)
{
  mtev_kafka_send_data(buf, len);
  return -1;
}

static logops_t kafka_logio_ops = {mtev_false,        kafka_logio_open, nullptr,
                                   kafka_logio_write, nullptr,          nullptr,
                                   nullptr,           nullptr,          nullptr};

static int mtev_console_show_kafka(
  mtev_console_closure_t ncct, int argc, char **argv, mtev_console_state_t *dstate, void *closure)
{
  (void) argc;
  (void) argv;
  (void) dstate;
  auto conf = static_cast<kafka_module_config *>(closure);
  return conf->show_console(ncct);
}

static int kafka_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options)
{
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while (mtev_hash_adv(options, &iter)) {
    if (!strcmp("poll_timeout_ms", iter.key.str)) {
      auto poll_timeout_ms = atoi(iter.value.str);
      if (poll_timeout_ms < 0) {
        poll_timeout_ms = DEFAULT_POLL_TIMEOUT_MS;
      }
      auto config = get_or_load_config(img);
      config->set_poll_timeout(std::chrono::milliseconds{poll_timeout_ms});
    }
    else if (!strcmp("poll_limit", iter.key.str)) {
      auto poll_limit = atoi(iter.value.str);
      if (poll_limit < 0) {
        poll_limit = DEFAULT_POLL_TIMEOUT_MS;
      }
      auto config = get_or_load_config(img);
      config->set_poll_limit(poll_limit);
    }
    else {
      mtevL(nlerr, "Kafka module config got unknown value: %s=%s\n", iter.key.str, iter.value.str);
    }
  }

  return 0;
}

static int kafka_driver_init(mtev_dso_generic_t *img)
{
  constexpr auto poll_kafka = [](eventer_t e, int mask, void *c, struct timeval *now) {
    (void) e;
    (void) mask;
    (void) now;
    auto conf = static_cast<kafka_module_config *>(c);
    conf->poll();
    return EVENTER_RECURRENT;
  };
  nlerr = mtev_log_stream_find("error/kafka");
  nldeb = mtev_log_stream_find("debug/kafka");
  auto config = get_or_load_config(img);
  mtev_register_logops("kafka", &kafka_logio_ops);

  mtev_console_state_t *tl = mtev_console_state_initial();
  cmd_info_t *showcmd = mtev_console_state_get_cmd(tl, "show");
  mtevAssert(showcmd && showcmd->dstate);
  mtev_console_state_add_cmd(showcmd->dstate,
                             NCSCMD("", mtev_console_show_kafka, nullptr, nullptr, config));

  auto e = eventer_alloc_recurrent(poll_kafka, config);
  eventer_add(e);
  return 0;
}

#include "kafka.xmlh"
mtev_dso_generic_t kafka = {{
                              .magic = MTEV_GENERIC_MAGIC,
                              .version = MTEV_GENERIC_ABI_VERSION,
                              .name = "kafka",
                              .description = "A Kafka subscriber and publisher",
                              .xml_description = kafka_xml_description,
                            },
                            kafka_driver_config,
                            kafka_driver_init};
