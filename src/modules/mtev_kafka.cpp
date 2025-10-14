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
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define CONFIG_KAFKA_MQ_CONSUMER "//network/in/mq[@type='kafka']"
#define CONFIG_KAFKA_MQ_PRODUCER "//network/out/mq[@type='kafka']"

static constexpr const char *VARIABLE_PARAMETER_PREFIX = "override_";
static constexpr size_t VARIABLE_PARAMETER_PREFIX_LEN = strlen(VARIABLE_PARAMETER_PREFIX);
static constexpr const char *KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX =
  "rdkafka_global_config_setting_";
static constexpr size_t KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX_LEN =
  strlen(KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX);
static constexpr const char *KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX = "rdkafka_topic_config_setting_";
static constexpr size_t KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX_LEN =
  strlen(KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX);

constexpr const char *bootstrap_str = "bootstrap.servers";
constexpr size_t bootstrap_str_len = strlen(bootstrap_str);
constexpr const char *group_id_str = "group.id";
constexpr size_t group_id_str_len = strlen(group_id_str);
constexpr const char *auto_commit_str = "enable.auto.commit";
constexpr size_t auto_commit_str_len = strlen(auto_commit_str);

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;
static mtev_log_stream_t nlnotice = nullptr;

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
                              const char *topic,
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
  m->topic = topic;
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
  uuid_t id;
  std::string id_str;
  std::string host;
  int32_t port;
  std::string broker_with_port;
  std::unordered_set<std::string> topics;
};

enum class connection_type_e { CONSUMER, PRODUCER };
static kafka_common_fields set_common_connection_fields(const uuid_t &id,
                                                        mtev_hash_table *options,
                                                        const std::vector<std::string> &topics)
{
  kafka_common_fields ret;

  char uuid_str[UUID_PRINTABLE_STRING_LENGTH];
  mtev_uuid_unparse_lower(id, uuid_str);
  mtev_uuid_copy(ret.id, id);
  ret.id_str = uuid_str;

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
    ret.port = 9092;
  }
  if (mtev_hash_retrieve(options, "topic", strlen("topic"), &vptr)) {
    mtevL(
      nlerr,
      "WARNING: Use of \"topic\" in the kafka module config is deprecated. Please use <topics>\n");
    ret.topics.insert(static_cast<char *>(vptr));
  }
  for (const auto &topic : topics) {
    ret.topics.insert(topic);
  }
  if (ret.topics.size() == 0) {
    ret.topics.insert("mtev_default_topic");
  }
  ret.broker_with_port = ret.host + ":" + std::to_string(ret.port);
  return ret;
}
static std::unordered_map<std::string, std::string>
  set_kafka_global_config_values_from_hash(rd_kafka_conf_t *kafka_conf,
                                           mtev_hash_table *config_hash)
{
  constexpr size_t error_string_size = 256;

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
    if (!strncmp(key, group_id_str, group_id_str_len)) {
      std::string error =
        "kafka config error: field group.id is not allowed. Use consumer_group setting";
      errors[key] = error;
      continue;
    }
    if (!strncmp(key, auto_commit_str, auto_commit_str_len)) {
      std::string error = "kafka config error: field" + std::string{auto_commit_str} +
        " is not allowed. Use manual_commit setting";
      errors[key] = error;
      continue;
    }
    if (rd_kafka_conf_set(kafka_conf, key, value, error_string, error_string_size) !=
        RD_KAFKA_CONF_OK) {
      errors[key] = error_string;
      continue;
    }
  }
  // We may want to display all of the extra parameters that were manually set at some point...
  // this loops through and removes all of the ones that failed from the config so we have a clean
  // picture of what was successfully set
  for (const auto &pair : errors) {
    mtev_hash_delete(config_hash, pair.first.c_str(), pair.first.size(), free, free);
  }
  return errors;
}
static std::unordered_map<std::string, std::string>
  set_kafka_topic_config_values_from_hash(rd_kafka_topic_conf_t *kafka_conf,
                                          mtev_hash_table *config_hash)
{
  constexpr size_t error_string_size = 256;
  std::unordered_map<std::string, std::string> errors;
  char error_string[error_string_size];
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while (mtev_hash_adv(config_hash, &iter)) {
    auto key = iter.key.str;
    auto value = iter.value.str;
    if (rd_kafka_topic_conf_set(kafka_conf, key, value, error_string, error_string_size) !=
        RD_KAFKA_CONF_OK) {
      errors[key] = error_string;
      continue;
    }
  }
  // We may want to display all of the extra parameters that were manually set at some point...
  // this loops through and removes all of the ones that failed from the config so we have a clean
  // picture of what was successfully set
  for (const auto &pair : errors) {
    mtev_hash_delete(config_hash, pair.first.c_str(), pair.first.size(), free, free);
  }
  return errors;
}
struct shutdown_request {
  enum Type { PRODUCER, CONSUMER };
  Type type;
  std::string id;
  mtev_kafka_shutdown_callback_t callback;
  void *closure;
};
struct kafka_producer {
  kafka_producer(const uuid_t &id,
                 mtev_hash_table *config,
                 const std::vector<std::string> &topics,
                 mtev_hash_table *&&kafka_global_configs_in,
                 mtev_hash_table *&&kafka_topic_configs_in,
                 mtev_hash_table *&&extra_configs_in)
  {
    common_fields = set_common_connection_fields(id, config, topics);
    kafka_global_configs = kafka_global_configs_in;
    kafka_topic_configs = kafka_topic_configs_in;
    extra_configs = extra_configs_in;

    constexpr size_t error_string_size = 256;
    char error_string[error_string_size];

    auto rd_producer_conf = rd_kafka_conf_new();
    auto global_config_errors =
      set_kafka_global_config_values_from_hash(rd_producer_conf, kafka_global_configs);

    if (global_config_errors.size()) {
      mtevL(nlerr,
            "%s: encountered the following %zd errors setting global configuration values for "
            "host %s\n",
            __func__, global_config_errors.size(), common_fields.broker_with_port.c_str());
      for (const auto &pair : global_config_errors) {
        mtevL(nlerr, "%s: %s\n", pair.first.c_str(), pair.second.c_str());
      }
      cleanup();
      throw(std::runtime_error(std::string("Failed to configure producer for host " +
                                           common_fields.broker_with_port +
                                           ": invalid configuration")));
    }
    if (rd_kafka_conf_set(rd_producer_conf, bootstrap_str, common_fields.broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "Failed to configure producer for host " +
        common_fields.broker_with_port + ": error " + error_string;
      cleanup();
      throw std::runtime_error(error.c_str());
    }
    rd_kafka_conf_set_dr_msg_cb(
      rd_producer_conf, +[](rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *closure) {
        auto producer = static_cast<kafka_producer *>(closure);
        if (rkmessage->err) {
          mtevL(nlerr, "Error producing message (callback): %s\n",
                rd_kafka_err2str(rkmessage->err));
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
    auto topic_config_errors =
      set_kafka_topic_config_values_from_hash(rd_topic_producer_conf, kafka_topic_configs);
    if (topic_config_errors.size()) {
      mtevL(nlerr,
            "%s: encountered the following %zd errors setting topic configuration values for "
            "host %s\n",
            __func__, topic_config_errors.size(), common_fields.broker_with_port.c_str());
      for (const auto &pair : topic_config_errors) {
        mtevL(nlerr, "%s: %s\n", pair.first.c_str(), pair.second.c_str());
      }
      cleanup();
      throw(std::runtime_error(std::string("Failed to configure producer for host " +
                                           common_fields.broker_with_port +
                                           ": invalid configuration")));
    }
    for (const auto &topic : common_fields.topics) {
      rd_topic_producers.emplace_back(
        rd_kafka_topic_new(rd_producer, topic.c_str(), rd_topic_producer_conf));
    }
  }
  kafka_producer() = delete;
  ~kafka_producer() { cleanup(); }
  void write_to_console(const mtev_console_closure_t &ncct)
  {
    nc_printf(ncct,
              "== %s ==\n"
              "  mq type: kafka\n"
              "  connection type: producer\n"
              "  topics:\n",
              common_fields.broker_with_port.c_str());
    for (const auto &topic : common_fields.topics) {
      nc_printf(ncct, "    %s\n", topic.c_str());
    }
    nc_printf(ncct, "  (s) msgs out: %zu\n  (s) errors: %zu\n", stats.msgs_out.load(),
              stats.errors.load());
  }

private:
  void cleanup()
  {
    if (rd_topic_producer_conf) {
      rd_kafka_topic_conf_destroy(rd_topic_producer_conf);
      rd_topic_producer_conf = nullptr;
    }
    for (const auto &producer : rd_topic_producers) {
      rd_kafka_topic_destroy(producer);
    }
    rd_topic_producers.clear();
    if (rd_producer) {
      rd_kafka_destroy(rd_producer);
      rd_producer = nullptr;
    }
    if (extra_configs) {
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      extra_configs = nullptr;
    }
    if (kafka_global_configs) {
      mtev_hash_destroy(kafka_global_configs, free, free);
      free(kafka_global_configs);
      kafka_global_configs = nullptr;
    }
    if (kafka_topic_configs) {
      mtev_hash_destroy(kafka_topic_configs, free, free);
      free(kafka_topic_configs);
      kafka_topic_configs = nullptr;
    }
  }

public:
  kafka_common_fields common_fields;
  std::string protocol;
  mtev_hash_table *extra_configs{nullptr};
  mtev_hash_table *kafka_global_configs{nullptr};
  mtev_hash_table *kafka_topic_configs{nullptr};
  rd_kafka_t *rd_producer{nullptr};
  rd_kafka_topic_conf_t *rd_topic_producer_conf{nullptr};
  std::vector<rd_kafka_topic_t *> rd_topic_producers;
  kafka_producer_stats_t stats;
};

struct kafka_consumer {
  kafka_consumer(const uuid_t &id,
                 mtev_hash_table *config,
                 const std::vector<std::string> &topics,
                 mtev_hash_table *&&kafka_global_configs_in,
                 mtev_hash_table *&&extra_configs_in)
  {
    common_fields = set_common_connection_fields(id, config, topics);
    kafka_global_configs = kafka_global_configs_in;
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
    if (mtev_hash_retrieve(config, "manual_commit", strlen("manual_commit"), &vptr)) {
      std::string val = static_cast<char *>(vptr);
      std::transform(val.begin(), val.end(), val.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (val == "true") {
        manual_commit = true;
      }
      else if (val == "false") {
        manual_commit = false;
      }
      else {
        mtevL(nlerr,
              "invalid value (%s) provided for manual_commit.... defaulting to "
              "false\n",
              val.c_str());
        manual_commit = false;
      }
    }
    else {
      manual_commit = false;
    }
    if (mtev_hash_retrieve(config, "manual_commit_asynch", strlen("manual_commit_asynch"), &vptr)) {
      std::string val = static_cast<char *>(vptr);
      std::transform(val.begin(), val.end(), val.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (val == "true") {
        manual_commit_asynch = true;
      }
      else if (val == "false") {
        manual_commit_asynch = false;
      }
      else {
        mtevL(nlerr,
              "invalid value (%s) provided for manual_commit_asynch.... defaulting to "
              "true\n",
              val.c_str());
        manual_commit_asynch = true;
      }
    }
    else {
      manual_commit_asynch = true;
    }

    constexpr size_t error_string_size = 256;
    char error_string[error_string_size];

    auto rd_consumer_conf = rd_kafka_conf_new();
    auto global_config_errors =
      set_kafka_global_config_values_from_hash(rd_consumer_conf, kafka_global_configs);
    if (global_config_errors.size()) {
      mtevL(nlerr,
            "%s: encountered the following %zd errors setting global configuration values for "
            "host %s\n",
            __func__, global_config_errors.size(), common_fields.broker_with_port.c_str());
      for (const auto &pair : global_config_errors) {
        mtevL(nlerr, "%s: %s\n", pair.first.c_str(), pair.second.c_str());
      }
      cleanup();
      throw(std::runtime_error(std::string("Failed to configure consumer for host " +
                                           common_fields.broker_with_port +
                                           ": invalid configuration")));
    }
    if (rd_kafka_conf_set(rd_consumer_conf, bootstrap_str, common_fields.broker_with_port.c_str(),
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "Failed to configure consumer for host " +
        common_fields.broker_with_port + ": error " + error_string;
      cleanup();
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_consumer_conf, group_id_str, consumer_group.c_str(), error_string,
                          error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "Failed to configure consumer for host " +
        common_fields.broker_with_port + ": error " + error_string;
      cleanup();
      throw std::runtime_error(error.c_str());
    }
    if (rd_kafka_conf_set(rd_consumer_conf, auto_commit_str, (manual_commit) ? "false" : "true",
                          error_string, error_string_size) != RD_KAFKA_CONF_OK) {
      std::string error = "Failed to configure manual_commit for host " +
        common_fields.broker_with_port + ": error " + error_string;
      cleanup();
      throw std::runtime_error(error.c_str());
    }
    rd_kafka_conf_set_error_cb(
      rd_consumer_conf, +[](rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        mtevL(nlerr, "Kafka error: %s (%d): %s\n",
              rd_kafka_err2str(static_cast<rd_kafka_resp_err_t>(err)), err, reason);
      });

    rd_consumer =
      rd_kafka_new(RD_KAFKA_CONSUMER, rd_consumer_conf, error_string, error_string_size);

    rd_consumer_topics = rd_kafka_topic_partition_list_new(common_fields.topics.size());
    for (const auto &topic : common_fields.topics) {
      rd_kafka_topic_partition_list_add(rd_consumer_topics, topic.c_str(), RD_KAFKA_PARTITION_UA);
    }
    rd_kafka_subscribe(rd_consumer, rd_consumer_topics);
  }
  kafka_consumer() = delete;
  ~kafka_consumer() { cleanup(); }
  void write_to_console(const mtev_console_closure_t &ncct)
  {
    nc_printf(ncct,
              "== %s ==\n"
              "  mq type: kafka\n"
              "  connection type: consumer\n"
              "  topics:\n",
              common_fields.broker_with_port.c_str());
    for (const auto &topic : common_fields.topics) {
      nc_printf(ncct, "    %s\n", topic.c_str());
    }
    nc_printf(ncct,
              "  consumer_group: %s\n"
              "  manual_commit: %s\n"
              "  (s) msgs in: %zu\n  (s) errors: %zu\n",
              consumer_group.c_str(), manual_commit ? "true" : "false", stats.msgs_in.load(),
              stats.errors.load());
  }

private:
  void cleanup()
  {
    if (rd_consumer_topics) {
      rd_kafka_topic_partition_list_destroy(rd_consumer_topics);
      rd_consumer_topics = nullptr;
    }
    if (rd_consumer) {
      rd_kafka_unsubscribe(rd_consumer);
    }
    if (rd_consumer) {
      rd_kafka_destroy(rd_consumer);
      rd_consumer = nullptr;
    }
    if (extra_configs) {
      mtev_hash_destroy(extra_configs, free, free);
      free(extra_configs);
      extra_configs = nullptr;
    }
    if (kafka_global_configs) {
      mtev_hash_destroy(kafka_global_configs, free, free);
      free(kafka_global_configs);
      kafka_global_configs = nullptr;
    }
  }

public:
  kafka_common_fields common_fields;
  std::string consumer_group;
  std::string protocol;
  bool manual_commit{false};
  bool manual_commit_asynch{true};
  mtev_hash_table *extra_configs{nullptr};
  mtev_hash_table *kafka_global_configs{nullptr};
  rd_kafka_t *rd_consumer{nullptr};
  rd_kafka_topic_partition_list_t *rd_consumer_topics{nullptr};
  kafka_consumer_stats_t stats;
};

class kafka_module_config {
public:
  kafka_module_config()
    : _poll_timeout{std::chrono::milliseconds{DEFAULT_POLL_TIMEOUT_MS}},
      _poll_limit{DEFAULT_POLL_LIMIT},
      _producer_poll_interval_ms{DEFAULT_PRODUCER_POLL_INTERVAL_MS}, _shutdown_jobq{nullptr}
  {
    auto make_kafka_connection = [&](connection_type_e conn_type, mtev_conf_section_t *mqs,
                                     int section_id) -> bool {
      auto mq = mqs[section_id];
      std::string host_string = "localhost";
      int32_t port = 9092;
      std::string topic_string = "mtev_default_topic";
      std::string consumer_group_string = "mtev_default_group";
      std::string protocol_string = "not_provided";
      mtev_hash_table *extra_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));
      mtev_hash_table *kafka_global_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));
      mtev_hash_table *kafka_topic_configs =
        static_cast<mtev_hash_table *>(calloc(1, sizeof(mtev_hash_table)));

      mtev_hash_init(extra_configs);
      mtev_hash_init(kafka_global_configs);
      mtev_hash_init(kafka_topic_configs);

      auto entries = mtev_conf_get_hash(mq, "self::node()");
      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      while (mtev_hash_adv(entries, &iter)) {
        if (!strncasecmp(iter.key.str, VARIABLE_PARAMETER_PREFIX, VARIABLE_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + VARIABLE_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(extra_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(nlerr,
                  "WARNING: Duplicate override config key found (key %s, value %s)... discarding\n",
                  key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
        else if (!strncasecmp(iter.key.str, KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX,
                              KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + KAFKA_GLOBAL_CONFIG_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(kafka_global_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(
              nlerr,
              "WARNING: Duplicate kafka global config key found (key %s, value %s)... discarding\n",
              key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
        else if (!strncasecmp(iter.key.str, KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX,
                              KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX_LEN)) {
          char *val_copy = strdup(iter.value.str);
          const char *name = iter.key.str + KAFKA_TOPIC_CONFIG_PARAMETER_PREFIX_LEN;
          if (strlen(name) == 0) {
            free(val_copy);
            continue;
          }
          char *key_copy = strdup(name);
          if (!mtev_hash_store(kafka_topic_configs, key_copy, strlen(key_copy), val_copy)) {
            mtevL(
              nlerr,
              "WARNING: Duplicate kafka topic config key found (key %s, value %s)... discarding\n",
              key_copy, val_copy);
            free(key_copy);
            free(val_copy);
            continue;
          }
        }
      }
      int num_topics = 0;
      auto topics = mtev_conf_get_sections_read(mq, "topics/topic", &num_topics);
      std::vector<std::string> topics_vector;
      for (int i = 0; i < num_topics; i++) {
        char *name = NULL;
        if (mtev_conf_get_string(topics[i], "@name", &name) && name) {
          topics_vector.emplace_back(name);
          free(name);
        }
      }
      mtev_conf_release_sections_read(topics, num_topics);

      char *uuid_str = NULL;
      uuid_t id;

      if (mtev_conf_get_string(mq, "@id", &uuid_str)) {
        if (mtev_uuid_parse(uuid_str, id)) {
          mtevFatal(mtev_error,
                    "Provided ID field in Kafka module config (%s) is not a valid UUID.\n",
                    uuid_str);
        }
        free(uuid_str);
      }
      else {
        mtev_uuid_generate(id);
      }

      switch (conn_type) {
      case connection_type_e::CONSUMER: {
        try {
          auto consumer = std::make_unique<kafka_consumer>(
            id, entries, topics_vector, std::move(kafka_global_configs), std::move(extra_configs));
          auto id_str = consumer->common_fields.id_str;
          auto broker = consumer->common_fields.broker_with_port;
          auto result = _consumers.insert({id_str, std::move(consumer)});
          if (!result.second) {
            throw std::runtime_error("duplicate UUID on Kafka consumer ids (" + id_str +
                                     "): id must be unique");
          }
          mtevL(nlnotice, "Added Kafka consumer: Host %s\n", broker.c_str());
        }
        catch (const std::exception &e) {
          mtevFatal(nlerr, "EXCEPTION: %s... aborting\n", e.what());
        }
        break;
      }
      case connection_type_e::PRODUCER: {
        try {
          auto producer = std::make_unique<kafka_producer>(
            id, entries, topics_vector, std::move(kafka_global_configs),
            std::move(kafka_topic_configs), std::move(extra_configs));
          auto id_str = producer->common_fields.id_str;
          auto broker = producer->common_fields.broker_with_port;
          auto result = _producers.insert({id_str, std::move(producer)});
          if (!result.second) {
            throw std::runtime_error("duplicate UUID on Kafka producer ids (" + id_str +
                                     "): id must be unique");
          }
          mtevL(nlnotice, "Added Kafka producer: Host %s\n", broker.c_str());
        }
        catch (const std::exception &e) {
          mtevFatal(nlerr, "EXCEPTION: %s... aborting\n", e.what());
        }
        break;
      }
      }
      mtev_hash_destroy(entries, free, free);
      free(entries);
      return true;
    };

    pthread_rwlock_init(&_list_lock, nullptr);

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
    mqs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_MQ_PRODUCER, &number_of_conns);

    if (number_of_conns > 0) {
      for (int section_id = 0; section_id < number_of_conns; section_id++) {
        make_kafka_connection(connection_type_e::PRODUCER, mqs, section_id);
      }
    }
    mtev_conf_release_sections_read(mqs, number_of_conns);
  }
  ~kafka_module_config()
  {
    // TODO: Should clean up all connections
    pthread_rwlock_destroy(&_list_lock);
  }
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
    for (const auto &[id, consumer] : _consumers) {
      int32_t per_conn_cnt = 0;
      rd_kafka_message_t *msg = nullptr;
      while (
        (_poll_limit == 0 || per_conn_cnt < _poll_limit) &&
        (nullptr != (msg = rd_kafka_consumer_poll(consumer->rd_consumer, _poll_timeout.count())))) {
        consumer->stats.msgs_in++;
        per_conn_cnt++;
        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
          const char *topic_name = rd_kafka_topic_name(msg->rkt);
          if (consumer->common_fields.topics.contains(topic_name)) {
            mtev_rd_kafka_message_t *m =
              mtev_rd_kafka_message_alloc(msg, consumer->protocol.c_str(), topic_name,
                                          consumer->extra_configs, mtev_rd_kafka_message_free);
            mtev_kafka_handle_message_dyn_hook_invoke(m);
            if (consumer->manual_commit) {
              if (auto err = rd_kafka_commit_message(consumer->rd_consumer, msg,
                                                     consumer->manual_commit_asynch ? 0 : 1)) {
                mtevL(nlerr, "failed to commit message: %s\n", rd_kafka_err2str(err));
              }
            }
            mtev_rd_kafka_message_deref(m);
          }
          else {
            mtevL(nlerr, "ERROR: Got message from unknown topic ('%s') from host %s - skipping\n",
                  topic_name, consumer->common_fields.broker_with_port.c_str());
            if (consumer->manual_commit) {
              if (auto err = rd_kafka_commit_message(consumer->rd_consumer, msg,
                                                     consumer->manual_commit_asynch ? 0 : 1)) {
                mtevL(nlerr, "failed to commit message: %s\n", rd_kafka_err2str(err));
              }
            }
          }
        }
        else {
          const char *topic_name = msg ? rd_kafka_topic_name(msg->rkt) : "(unknown topic)";
          mtevL(nlerr, "ERROR: Got error reading from %s, topic %s: %s\n",
                consumer->common_fields.broker_with_port.c_str(), topic_name,
                msg ? rd_kafka_err2str(msg->err) : "(unknown error)");
          consumer->stats.errors++;
          rd_kafka_message_destroy(msg);
        }
      }
    }
    process_pending_shutdowns();
    return 0;
  }
  void publish_to_producers(const void *payload, size_t payload_len)
  {
    for (const auto &[id, producer] : _producers) {
      for (const auto &individual_producer : producer->rd_topic_producers) {
        if (!rd_kafka_produce(individual_producer, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                              const_cast<void *>(payload), payload_len, nullptr, 0, nullptr) == 0) {
          mtevL(nlerr, "%s: Error producing message (send): %s\n", __func__,
                rd_kafka_err2str(rd_kafka_last_error()));
          producer->stats.errors++;
        }
      }
    }
  }
  void poll_producers()
  {
    for (const auto &[id, producer] : _producers) {
      rd_kafka_poll(producer->rd_producer, 10);
    }
  }
  int get_num_producers() { return _producers.size(); }
  int32_t get_producer_poll_interval() { return _producer_poll_interval_ms; }
  int show_console(const mtev_console_closure_t &ncct)
  {
    for (const auto &[id, producer] : _producers) {
      producer->write_to_console(ncct);
    }
    for (const auto &[id, consumer] : _consumers) {
      consumer->write_to_console(ncct);
    }
    return 0;
  }
  bool enqueue_shutdown_producer_request(const uuid_t id,
                                         mtev_kafka_shutdown_callback_t callback,
                                         void *closure)
  {
    char uuid_str[UUID_PRINTABLE_STRING_LENGTH];
    mtev_uuid_unparse_lower(id, uuid_str);

    std::lock_guard<std::mutex> lock(_shutdown_mutex);

    if (_producers.find(uuid_str) == _producers.end()) {
      return false;
    }
    _pending_shutdowns.push_back({shutdown_request::PRODUCER, uuid_str, callback, closure});

    return true;
  }

  bool enqueue_shutdown_consumer_request(const uuid_t id,
                                         mtev_kafka_shutdown_callback_t callback,
                                         void *closure)
  {
    char uuid_str[UUID_PRINTABLE_STRING_LENGTH];
    mtev_uuid_unparse_lower(id, uuid_str);

    std::lock_guard<std::mutex> lock(_shutdown_mutex);

    if (_consumers.find(uuid_str) == _consumers.end()) {
      return false;
    }
    _pending_shutdowns.push_back({shutdown_request::CONSUMER, uuid_str, callback, closure});

    return true;
  }

  void enqueue_shut_down_requests(mtev_kafka_shutdown_callback_t callback, void *closure)
  {
    struct shut_down_context {
      std::atomic<int> pending_count;
      mtev_kafka_shutdown_callback_t original_callback;
      void *original_closure;
    };

    auto ctx = new shut_down_context;
    ctx->original_callback = callback;
    ctx->original_closure = closure;

    std::lock_guard<std::mutex> lock(_shutdown_mutex);
    ctx->pending_count = _producers.size() + _consumers.size();

    if (ctx->pending_count == 0) {
      uuid_t null_id;
      mtev_uuid_clear(null_id);
      if (callback) {
        callback(closure, null_id, mtev_true, nullptr);
      }
      delete ctx;
      return;
    }

    auto wrapper_callback = [](void *closure, const uuid_t id, mtev_boolean success,
                               const char *error) {
      auto ctx = static_cast<shut_down_context *>(closure);

      if (ctx->original_callback) {
        ctx->original_callback(ctx->original_closure, id, success, error);
      }

      if (--ctx->pending_count == 0) {
        uuid_t null_id;
        mtev_uuid_clear(null_id);
        if (ctx->original_callback) {
          ctx->original_callback(ctx->original_closure, null_id, mtev_true, nullptr);
        }
        delete ctx;
      }
    };

    for (const auto &[id_str, producer] : _producers) {
      _pending_shutdowns.push_back({shutdown_request::PRODUCER, id_str, wrapper_callback, ctx});
    }

    for (const auto &[id_str, consumer] : _consumers) {
      _pending_shutdowns.push_back({shutdown_request::CONSUMER, id_str, wrapper_callback, ctx});
    }
  }

  mtev_kafka_connection_list_t *get_producer_list() const
  {
    pthread_rwlock_rdlock(&_list_lock);
    auto list = (mtev_kafka_connection_list_t *) calloc(1, sizeof(mtev_kafka_connection_list_t));
    list->count = _producers.size();

    if (list->count > 0) {
      list->connections =
        (mtev_kafka_connection_info_t *) calloc(list->count, sizeof(mtev_kafka_connection_info_t));
      size_t idx = 0;
      for (const auto &[id_str, producer] : _producers) {
        auto &info = list->connections[idx++];
        info.connection_type = MTEV_KAFKA_CONNECTION_TYPE_PRODUCER;
        mtev_uuid_copy(info.id, producer->common_fields.id);
        info.host = strdup(producer->common_fields.host.c_str());
        info.port = producer->common_fields.port;
      }
    }
    pthread_rwlock_unlock(&_list_lock);
    return list;
  }

  mtev_kafka_connection_list_t *get_consumer_list() const
  {
    pthread_rwlock_rdlock(&_list_lock);
    auto list = (mtev_kafka_connection_list_t *) calloc(1, sizeof(mtev_kafka_connection_list_t));
    list->count = _consumers.size();

    if (list->count > 0) {
      list->connections =
        (mtev_kafka_connection_info_t *) calloc(list->count, sizeof(mtev_kafka_connection_info_t));
      size_t idx = 0;
      for (const auto &[id_str, consumer] : _consumers) {
        auto &info = list->connections[idx++];
        info.connection_type = MTEV_KAFKA_CONNECTION_TYPE_CONSUMER;
        mtev_uuid_copy(info.id, consumer->common_fields.id);
        info.host = strdup(consumer->common_fields.host.c_str());
        info.port = consumer->common_fields.port;
      }
    }
    pthread_rwlock_unlock(&_list_lock);
    return list;
  }

private:
  void process_pending_shutdowns()
  {
    std::vector<shutdown_request> to_process;
    {
      std::lock_guard<std::mutex> lock(_shutdown_mutex);
      if (_pending_shutdowns.empty()) {
        return;
      }
      to_process.swap(_pending_shutdowns);
    }
    pthread_rwlock_wrlock(&_list_lock);
    for (const auto &req : to_process) {
      if (req.type == shutdown_request::PRODUCER) {
        if (auto it = _producers.find(req.id); it != _producers.end()) {
          schedule_producer_cleanup(std::move(it->second), req.callback, req.closure);
          _producers.erase(it);
        }
      }
      else {
        if (auto it = _consumers.find(req.id); it != _consumers.end()) {
          schedule_consumer_cleanup(std::move(it->second), req.callback, req.closure);
          _consumers.erase(it);
        }
      }
    }
    pthread_rwlock_unlock(&_list_lock);
  }

  void schedule_producer_cleanup(std::unique_ptr<kafka_producer> producer,
                                 mtev_kafka_shutdown_callback_t callback,
                                 void *closure)
  {
    if (!_shutdown_jobq) {
      _shutdown_jobq = eventer_jobq_create("kafka_shutdown");
      eventer_jobq_set_concurrency(_shutdown_jobq, 1);
    }

    struct cleanup_context {
      std::unique_ptr<kafka_producer> producer;
      mtev_kafka_shutdown_callback_t callback;
      void *closure;
      uuid_t id;
    };

    auto ctx = new cleanup_context{std::move(producer), callback, closure};
    mtev_uuid_copy(ctx->id, ctx->producer->common_fields.id);

    eventer_t e = eventer_alloc_asynch(
      +[](eventer_t e, int mask, void *c, struct timeval *now) -> int {
        auto ctx = static_cast<cleanup_context *>(c);

        if (mask == EVENTER_ASYNCH_WORK) {
          rd_kafka_flush(ctx->producer->rd_producer, 5000);
        }

        if (mask == EVENTER_ASYNCH_CLEANUP) {
          if (ctx->callback) {
            ctx->callback(ctx->closure, ctx->id, mtev_true, nullptr);
          }
          delete ctx;
        }

        return 0;
      },
      ctx);

    eventer_add_asynch(_shutdown_jobq, e);
  }

  void schedule_consumer_cleanup(std::unique_ptr<kafka_consumer> consumer,
                                 mtev_kafka_shutdown_callback_t callback,
                                 void *closure)
  {
    if (!_shutdown_jobq) {
      _shutdown_jobq = eventer_jobq_create("kafka_shutdown");
      eventer_jobq_set_concurrency(_shutdown_jobq, 1);
    }

    struct cleanup_context {
      std::unique_ptr<kafka_consumer> consumer;
      mtev_kafka_shutdown_callback_t callback;
      void *closure;
      uuid_t id;
    };

    auto ctx = new cleanup_context{std::move(consumer), callback, closure};
    mtev_uuid_copy(ctx->id, ctx->consumer->common_fields.id);

    eventer_t e = eventer_alloc_asynch(
      +[](eventer_t e, int mask, void *c, struct timeval *now) -> int {
        auto ctx = static_cast<cleanup_context *>(c);

        if (mask == EVENTER_ASYNCH_WORK) {
          rd_kafka_consumer_close(ctx->consumer->rd_consumer);
        }

        if (mask == EVENTER_ASYNCH_CLEANUP) {
          if (ctx->callback) {
            ctx->callback(ctx->closure, ctx->id, mtev_true, nullptr);
          }
          delete ctx;
        }
        return 0;
      },
      ctx);

    eventer_add_asynch(_shutdown_jobq, e);
  }

  std::map<std::string, std::unique_ptr<kafka_consumer>> _consumers;
  std::map<std::string, std::unique_ptr<kafka_producer>> _producers;
  std::chrono::milliseconds _poll_timeout;
  int32_t _poll_limit;
  int64_t _producer_poll_interval_ms;
  std::mutex _shutdown_mutex;
  std::vector<shutdown_request> _pending_shutdowns;
  eventer_jobq_t *_shutdown_jobq{nullptr};
  mutable pthread_rwlock_t _list_lock;
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
void mtev_kafka_broadcast_function(const void *payload, size_t payload_len)
{
  if (the_conf) {
    the_conf->publish_to_producers(payload, payload_len);
  }
}

mtev_kafka_connection_list_t *mtev_kafka_get_all_consumers_function()
{
  mtev_kafka_connection_list_t *connections = nullptr;
  if (the_conf) {
    connections = the_conf->get_consumer_list();
  }
  return connections;
}

void mtev_kafka_free_connection_list_function(mtev_kafka_connection_list_t *list)
{
  if (!list) {
    return;
  }
  for (size_t i = 0; i < list->count; i++) {
    free(list->connections[i].host);
  }
  free(list->connections);
  free(list);
}

mtev_kafka_connection_list_t *mtev_kafka_get_all_producers_function()
{
  mtev_kafka_connection_list_t *connections = nullptr;
  if (the_conf) {
    connections = the_conf->get_producer_list();
  }
  return connections;
}

mtev_boolean mtev_kafka_shutdown_producer_function(const uuid_t id,
                                                   mtev_kafka_shutdown_callback_t callback,
                                                   void *closure)
{
  if (!the_conf) {
    return mtev_false;
  }
  return the_conf->enqueue_shutdown_producer_request(id, callback, closure) ? mtev_true :
                                                                              mtev_false;
}

mtev_boolean mtev_kafka_shutdown_consumer_function(const uuid_t id,
                                                   mtev_kafka_shutdown_callback_t callback,
                                                   void *closure)
{
  if (!the_conf) {
    return mtev_false;
  }
  return the_conf->enqueue_shutdown_consumer_request(id, callback, closure) ? mtev_true :
                                                                              mtev_false;
}

void mtev_kafka_shut_down_function(mtev_kafka_shutdown_callback_t callback, void *closure)
{
  if (!the_conf) {
    uuid_t null_id;
    mtev_uuid_clear(null_id);
    if (callback) {
      callback(closure, null_id, mtev_true, nullptr);
    }
    return;
  }

  the_conf->enqueue_shut_down_requests(callback, closure);
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
        poll_limit = DEFAULT_POLL_LIMIT;
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

static int schedule_poll_producers(eventer_t e, int mask, void *c, struct timeval *now)
{
  auto asynch_e = eventer_alloc_asynch(
    +[](eventer_t e, int mask, void *c, struct timeval *now) {
      auto config = static_cast<kafka_module_config *>(c);
      if (mask == EVENTER_ASYNCH_WORK) {
        config->poll_producers();
      }
      if (mask == EVENTER_ASYNCH_COMPLETE) {
        auto timeout_ms = config->get_producer_poll_interval();
        eventer_add_in_s_us(schedule_poll_producers, c, timeout_ms / 1000,
                            (timeout_ms % 1000) * 1000);
      }
      return 0;
    },
    c);
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
  nlnotice = mtev_log_stream_find("notice/kafka");
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
    eventer_add_in_s_us(schedule_poll_producers, config, timeout_ms / 1000,
                        (timeout_ms % 1000) * 1000);
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
