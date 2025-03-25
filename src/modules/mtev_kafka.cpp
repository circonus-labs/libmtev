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

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#define CONFIG_KAFKA_MQ_CONSUMER "//network/in/mq[@type='kafka']"
#define CONFIG_KAFKA_MQ_PRODUCER "//network/out/mq[@type='kafka']"

static constexpr const char *VARIABLE_PARAMETER_PREFIX = "override_";
static constexpr size_t VARIABLE_PARAMETER_PREFIX_LEN = strlen(VARIABLE_PARAMETER_PREFIX);
static constexpr const char *KAFKA_CONFIG_PARAMETER_PREFIX = "rdkafka_config_setting_";
static constexpr size_t KAFKA_CONFIG_PARAMETER_PREFIX_LEN = strlen(KAFKA_CONFIG_PARAMETER_PREFIX);

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;

constexpr int32_t DEFAULT_POLL_TIMEOUT_MS = 10;
constexpr int32_t DEFAULT_POLL_LIMIT = 10000;
constexpr int32_t DEFAULT_PRODUCER_POLL_INTERVAL_MS = 10000;

eventer_jobq_t *poll_producers_jobq = NULL;

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

struct kafka_producer_stats_t {
  kafka_producer_stats_t() : msgs_out{0}, errors{0} {}
  ~kafka_producer_stats_t() = default;

  std::atomic<uint64_t> msgs_out;
  std::atomic<uint64_t> errors;
};
struct kafka_consumer_stats_t {
  kafka_consumer_stats_t() : msgs_in{0}, errors{0} {}
  ~kafka_consumer_stats_t() = default;

  std::atomic<uint64_t> msgs_in;
  std::atomic<uint64_t> errors;
};

struct kafka_common_fields {
  std::string host;
  int32_t port;
  std::string broker_with_port;
  std::string topic;
};

enum class connection_type_e {CONSUMER, PRODUCER};
static kafka_common_fields set_common_connection_fields(mtev_hash_table *options)
{
  kafka_common_fields ret;
  void *vptr = nullptr;
  if (mtev_hash_retrieve(options, "host", strlen("host"), &vptr)) {
    ret.host = static_cast<char *>(vptr);
  }
  else {
    ret.host = "localhost";
  }
  if (mtev_hash_retrieve(options, "port", strlen("port"), &vptr)) {
    ret.port = atoi(static_cast<char *>(vptr));
  }
  else {
    ret.port = 9112;
  }
  if (mtev_hash_retrieve(options, "topic", strlen("topic"), &vptr)) {
    ret.topic = static_cast<char *>(vptr);
  }
  else {
    ret.topic = "mtev_default_topic";
  }
  ret.broker_with_port = ret.host + ":" + std::to_string(ret.port);
  return ret;
}
static std::unordered_map<std::string, std::string> set_kafka_config_values_from_hash(
  rd_kafka_conf_t *kafka_conf, mtev_hash_table *config_hash)
{
  constexpr size_t error_string_size = 256;
  constexpr const char *bootstrap_str = "bootstrap.servers";
  constexpr size_t bootstrap_str_len = strlen(bootstrap_str);
  std::unordered_map<std::string, std::string> errors;
  char error_string[error_string_size];
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while (mtev_hash_adv(config_hash, &iter)) {
    auto key = iter.key.str;
    auto value = iter.value.str;
    if (!strncmp(key, bootstrap_str, bootstrap_str_len)) {
      std::string error =
        "kafka config error: field bootstrap.servers is not allowed. Use host and port settings";
      errors[key] = error;
      continue;
    }
    if (rd_kafka_conf_set(kafka_conf, key, value, error_string,
      error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting value " + std::string{value} + " for field " +
        std::string{key} + ": kafka reported error |" + error_string + "|" + "...skipping";
      errors[key] = error_string;
      mtevL(nlerr, "%s\n", error.c_str());
      continue;
    }
  }
  // We may want to display all of the extra parameters that were manually set at some point...
  // this loops through and removes all of the ones that failed from the config so we have a clean
  // picture of what was successfully set
  for (const auto& pair : errors) {
    mtev_hash_delete(config_hash, pair.first.c_str(), pair.first.size(), free, free);
  }
  return errors;
}
struct kafka_producer {
  kafka_producer(mtev_hash_table *config,
                 mtev_hash_table *&&kafka_configs_in,
                 mtev_hash_table *&&extra_configs_in)
  {
    common_fields = set_common_connection_fields(config);
    kafka_configs = kafka_configs_in;
    extra_configs = extra_configs_in;

    constexpr size_t error_string_size = 256;
    char error_string[error_string_size];

    rd_producer_conf = rd_kafka_conf_new();
    set_kafka_config_values_from_hash(rd_producer_conf, kafka_configs);
    if (rd_kafka_conf_set(rd_producer_conf, "bootstrap.servers", common_fields.broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting bootstrap.servers field on producer for " +
        common_fields.broker_with_port + ", topic " + common_fields.topic + ": kafka reported error |" +
        error_string + "|";
      rd_kafka_conf_destroy(rd_producer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }
    rd_kafka_conf_set_dr_msg_cb(rd_producer_conf, +[](rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *closure) {
      auto producer = static_cast<kafka_producer *>(closure);
      if (rkmessage->err) {
        mtevL(nlerr, "Error producing message (callback): %s\n", rd_kafka_err2str(rkmessage->err));
        producer->stats.errors++;
      }
      else {
        producer->stats.msgs_out++;
      }
    });
    rd_kafka_conf_set_opaque(rd_producer_conf, this);
    rd_producer =
      rd_kafka_new(RD_KAFKA_PRODUCER, rd_producer_conf, error_string, error_string_size);
    rd_topic_producer_conf = rd_kafka_topic_conf_new();
    rd_topic_producer = rd_kafka_topic_new(rd_producer, common_fields.topic.c_str(), rd_topic_producer_conf);
  }
  kafka_producer() = delete;
  ~kafka_producer()
  {
    rd_kafka_topic_conf_destroy(rd_topic_producer_conf);
    rd_kafka_topic_destroy(rd_topic_producer);
    rd_kafka_conf_destroy(rd_producer_conf);
    rd_kafka_destroy(rd_producer);
    mtev_hash_destroy(extra_configs, free, free);
    free(extra_configs);
    mtev_hash_destroy(kafka_configs, free, free);
    free(kafka_configs);
  }
  void write_to_console(const mtev_console_closure_t &ncct)
  {
    nc_printf(ncct,
              "== %s ==\n"
              "  mq type: kafka\n"
              "  connection type: producer\n"
              "  topic: %s\n"
              "  (s) msgs out: %zu\n  (s) errors: %zu\n",
              common_fields.broker_with_port.c_str(), common_fields.topic.c_str(), stats.msgs_out.load(),
              stats.errors.load());
  }
  kafka_common_fields common_fields;
  std::string protocol;
  mtev_hash_table *extra_configs;
  mtev_hash_table *kafka_configs;
  rd_kafka_conf_t *rd_producer_conf;
  rd_kafka_t *rd_producer;
  rd_kafka_topic_conf_t *rd_topic_producer_conf;
  rd_kafka_topic_t *rd_topic_producer;
  kafka_producer_stats_t stats;
};

struct kafka_consumer {
  kafka_consumer(mtev_hash_table *config,
                 mtev_hash_table *&&kafka_configs_in,
                 mtev_hash_table *&&extra_configs_in)
  {
    common_fields = set_common_connection_fields(config);
    kafka_configs = kafka_configs_in;
    extra_configs = extra_configs_in;

    void *vptr = nullptr;
    if (mtev_hash_retrieve(config, "consumer_group", strlen("consumer_group"), &vptr)) {
      consumer_group = static_cast<char *>(vptr);
    }
    else {
      consumer_group = "mtev_default_group";
    }
    if (mtev_hash_retrieve(config, "protocol", strlen("protocol"), &vptr)) {
      protocol = static_cast<char *>(vptr);
    }
    else {
      protocol = "not_provided";
    }

    constexpr size_t error_string_size = 256;
    char error_string[error_string_size];

    rd_consumer_conf = rd_kafka_conf_new();
    set_kafka_config_values_from_hash(rd_consumer_conf, kafka_configs);
    if (rd_kafka_conf_set(rd_consumer_conf, "bootstrap.servers", common_fields.broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error =
        "kafka config error: error setting bootstrap.servers field on consumer for " +
        common_fields.broker_with_port + ", topic " + common_fields.topic + ": kafka reported error |" +
        error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_consumer_conf, "group.id", consumer_group.c_str(), error_string,
                          error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "kafka config error: error setting group.id field on consumer for " +
        common_fields.broker_with_port + ", topic " + common_fields.topic + ": kafka reported error |" +
        error_string + "|";
      rd_kafka_conf_destroy(rd_consumer_conf);
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      throw std::runtime_error(error.c_str());
    }

    rd_consumer =
      rd_kafka_new(RD_KAFKA_CONSUMER, rd_consumer_conf, error_string, error_string_size);

    rd_consumer_topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(rd_consumer_topics, common_fields.topic.c_str(), RD_KAFKA_PARTITION_UA);
    rd_kafka_subscribe(rd_consumer, rd_consumer_topics);
  }
  kafka_consumer() = delete;
  ~kafka_consumer()
  {
    rd_kafka_topic_partition_list_destroy(rd_consumer_topics);
    rd_kafka_unsubscribe(rd_consumer);
    rd_kafka_conf_destroy(rd_consumer_conf);
    rd_kafka_destroy(rd_consumer);
    mtev_hash_destroy(extra_configs, free, free);
    free(extra_configs);
    mtev_hash_destroy(kafka_configs, free, free);
    free(kafka_configs);
  }
  void write_to_console(const mtev_console_closure_t &ncct)
  {
    nc_printf(ncct,
              "== %s ==\n"
              "  mq type: kafka\n"
              "  connection type: consumer\n"
              "  topic: %s\n"
              "  consumer_group: %s\n"
              "  (s) msgs in: %zu\n  (s) errors: %zu\n",
              common_fields.broker_with_port.c_str(), common_fields.topic.c_str(), consumer_group.c_str(),
              stats.msgs_in.load(), stats.errors.load());
  }

  kafka_common_fields common_fields;
  std::string consumer_group;
  std::string protocol;
  mtev_hash_table *extra_configs;
  mtev_hash_table *kafka_configs;
  rd_kafka_conf_t *rd_consumer_conf;
  rd_kafka_t *rd_consumer;
  rd_kafka_topic_partition_list_t *rd_consumer_topics;
  kafka_consumer_stats_t stats;
};

class kafka_module_config {
public:
  kafka_module_config()
    : _poll_timeout{std::chrono::milliseconds{DEFAULT_POLL_TIMEOUT_MS}}, _poll_limit{
                                                                           DEFAULT_POLL_LIMIT},
                                                                          _producer_poll_interval_ms{
                                                                            DEFAULT_PRODUCER_POLL_INTERVAL_MS}
  {
    auto make_kafka_connection = [&](connection_type_e conn_type,
      mtev_conf_section_t *mqs,
      int section_id) -> bool {
      std::string host_string = "localhost";
      int32_t port = 9092;
      std::string topic_string = "mtev_default_topic";
      std::string consumer_group_string = "mtev_default_group";
      std::string protocol_string = "not_provided";
      mtev_hash_table *extra_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));
      mtev_hash_table *kafka_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));
      mtev_hash_init(extra_configs);
      mtev_hash_init(kafka_configs);

      auto entries = mtev_conf_get_hash(mqs[section_id], "self::node()");
      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      while (mtev_hash_adv(entries, &iter)) {
        if (!strncasecmp(iter.key.str, VARIABLE_PARAMETER_PREFIX,
                              VARIABLE_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + VARIABLE_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(extra_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(nlerr, "WARNING: Duplicate override config key found (key %s, value %s)... discarding\n",
                  key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
        else if (!strncasecmp(iter.key.str, KAFKA_CONFIG_PARAMETER_PREFIX,
                                   KAFKA_CONFIG_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + KAFKA_CONFIG_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(kafka_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(nlerr, "WARNING: Duplicate kafka config key found (key %s, value %s)... discarding\n",
                  key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
      }
      switch(conn_type) {
        case connection_type_e::CONSUMER:
        {
          auto consumer =
            std::make_unique<kafka_consumer>(entries,
                                             std::move(kafka_configs),
                                             std::move(extra_configs));
          _consumers.push_back(std::move(consumer));
          break;
        }
        case connection_type_e::PRODUCER:
        {
          auto producer =
            std::make_unique<kafka_producer>(entries,
                                             std::move(kafka_configs),
                                             std::move(extra_configs));
          _producers.push_back(std::move(producer));
          break;
        }
      }
      mtev_hash_destroy(entries, free, free);
      free(entries);
      return true;
    };

    int number_of_conns = 0;
    mtev_conf_section_t *mqs =
      mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_MQ_CONSUMER, &number_of_conns);

    if (number_of_conns > 0) {
      for (int section_id = 0; section_id < number_of_conns; section_id++) {
        make_kafka_connection(connection_type_e::CONSUMER, mqs, section_id);
      }
    }
    mtev_conf_release_sections_read(mqs, number_of_conns);

    number_of_conns = 0;
    mqs =
      mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_MQ_PRODUCER, &number_of_conns);

    if (number_of_conns > 0) {
      for (int section_id = 0; section_id < number_of_conns; section_id++) {
        make_kafka_connection(connection_type_e::PRODUCER, mqs, section_id);
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
  void set_producer_poll_interval(const int64_t producer_poll_interval)
  {
    _producer_poll_interval_ms = producer_poll_interval;
  }
  int poll()
  {
    for (const auto &consumer : _consumers) {
      int32_t per_conn_cnt = 0;
      rd_kafka_message_t *msg = nullptr;
      while (
        (_poll_limit == 0 || per_conn_cnt < _poll_limit) &&
        (nullptr != (msg = rd_kafka_consumer_poll(consumer->rd_consumer, _poll_timeout.count())))) {
        consumer->stats.msgs_in++;
        per_conn_cnt++;
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
          mtev_rd_kafka_message_t *m = mtev_rd_kafka_message_alloc(
            msg, consumer->protocol.c_str(), consumer->extra_configs, mtev_rd_kafka_message_free);
          mtev_kafka_handle_message_dyn_hook_invoke(m);
          mtev_rd_kafka_message_deref(m);
        }
        else {
          mtevL(nlerr, "ERROR: Got error reading from %s, topic %s: %s\n",
            consumer->common_fields.broker_with_port.c_str(), consumer->common_fields.topic.c_str(),
            rd_kafka_err2str(msg->err));
          consumer->stats.errors++;
          rd_kafka_message_destroy(msg);
        }
      }
    }
    return 0;
  }
  void publish_to_producers(const void *payload, size_t payload_len)
  {
    for (const auto &producer : _producers) {
      if (!rd_kafka_produce(producer->rd_topic_producer, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
        const_cast<void *>(payload), payload_len, nullptr, 0, nullptr) == 0) {
        mtevL(nlerr, "%s: Error producing message (send): %s\n", __func__, rd_kafka_err2str(rd_kafka_last_error()));
        producer->stats.errors++;
      }
    }
  }
  void poll_producers()
  {
    for (const auto &producer : _producers) {
      rd_kafka_poll(producer->rd_producer, 10);
    }
  }
  int get_num_producers()
  {
    return _producers.size();
  }
  int32_t get_producer_poll_interval()
  {
    return _producer_poll_interval_ms;
  }
  int show_console(const mtev_console_closure_t &ncct)
  {
    for (const auto &producer : _producers) {
      producer->write_to_console(ncct);
    }
    for (const auto &consumer : _consumers) {
      consumer->write_to_console(ncct);
    }
    return 0;
  }

private:
  std::vector<std::unique_ptr<kafka_consumer>> _consumers;
  std::vector<std::unique_ptr<kafka_producer>> _producers;
  std::chrono::milliseconds _poll_timeout;
  int32_t _poll_limit;
  int64_t _producer_poll_interval_ms;
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

// These functions are invoked by the write hooks..... need to be in
// an extern "C" block so their names don't get mangled, otherwise the
// runtime resolution will fail
extern "C" {
void
mtev_kafka_broadcast_function(const void *payload, size_t payload_len) {
  if (the_conf) {
    the_conf->publish_to_producers(payload, payload_len);
  }
}
}

static int kafka_logio_open(mtev_log_stream_t ls)
{
  (void) ls;
  return -1;
}

static int
  kafka_logio_write(mtev_log_stream_t ls, const struct timeval *whence, const void *buf, size_t len)
{
  mtev_kafka_broadcast(buf, len);
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
    else if (!strcmp("producer_poll_interval_ms", iter.key.str)) {
      auto producer_poll_interval_ms = std::stoll(iter.value.str);
      if (producer_poll_interval_ms < 0) {
        producer_poll_interval_ms = DEFAULT_PRODUCER_POLL_INTERVAL_MS;
      }
      auto config = get_or_load_config(img);
      config->set_producer_poll_interval(producer_poll_interval_ms);
    }
    else {
      mtevL(nlerr, "Kafka module config got unknown value: %s=%s\n", iter.key.str, iter.value.str);
    }
  }

  return 0;
}

static int schedule_poll_producers (eventer_t e, int mask, void *c, struct timeval *now) {
  auto asynch_e = eventer_alloc_asynch(+[](eventer_t e, int mask, void *c, struct timeval *now) {
    auto config = static_cast<kafka_module_config *>(c);
    if (mask == EVENTER_ASYNCH_WORK) {
      config->poll_producers();
    }
    if (mask == EVENTER_ASYNCH_COMPLETE) {
      auto timeout_ms = config->get_producer_poll_interval();
      eventer_add_in_s_us(schedule_poll_producers, c, timeout_ms/1000, (timeout_ms % 1000) * 1000);
    }
    return 0;
  }, c);
  eventer_add_asynch(poll_producers_jobq, asynch_e);
  return 0;
};

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
  if (config->get_num_producers()) {
    poll_producers_jobq = eventer_jobq_create("poll_kafka_producers");
    eventer_jobq_set_concurrency(poll_producers_jobq, 1);
    auto timeout_ms = config->get_producer_poll_interval();
    eventer_add_in_s_us(schedule_poll_producers, config, timeout_ms/1000, (timeout_ms % 1000) * 1000);
  }
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
