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

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"
#include "mtev_conf.h"
#include "mtev_rand.h"
#include "mtev_thread.h"
#include "mtev_kafka.hpp"

#include <kafka/KafkaConsumer.h>
#include <kafka/KafkaProducer.h>

#define CONFIG_KAFKA_IN_MQ "//network//mq[@type='kafka']"
#define CONFIG_KAFKA_HOST "self::node()/host"
#define CONFIG_KAFKA_PORT "self::node()/port"
#define CONFIG_KAFKA_TOPIC "self::node()/topic"

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;

constexpr int32_t DEFAULT_POLL_TIMEOUT_MS = 10;

struct kafka_stats_t {
  kafka_stats_t() : msgs_in{0}, msgs_out{0} {}
  ~kafka_stats_t() = default;

  uint64_t msgs_in;
  uint64_t msgs_out;
};

struct kafka_connection {
  kafka_connection(const std::string &host_in, const int32_t port_in, const std::string &topic_str) {
    host = host_in;
    port = port_in;
    broker_with_port = host + ":" + std::to_string(port);

    props.put("enable.idempotence", "true");
    props.put("bootstrap.servers", broker_with_port);
    producer = std::make_unique<kafka::clients::producer::KafkaProducer>(props);
    consumer = std::make_unique<kafka::clients::consumer::KafkaConsumer>(props);
    const kafka::Topic topic = topic_str;
    consumer->subscribe({topic});
  }
  kafka_connection() = delete;
  ~kafka_connection() = default;
  void write_to_console(const mtev_console_closure_t &ncct) {
    nc_printf(ncct, "== %s:%d ==\n"
                    "  (s) msgs tx: %zu\n  (s) msgs rx: %zu\n",
        host.c_str(),port, stats.msgs_in, stats.msgs_out);
  }

  std::string host;
  int32_t port;
  std::string broker_with_port;
  kafka::Properties props;
  std::unique_ptr<kafka::clients::producer::KafkaProducer> producer;
  std::unique_ptr<kafka::clients::consumer::KafkaConsumer> consumer;
  kafka_stats_t stats;
};

class kafka_module_config {
  public:
  kafka_module_config(): _poll_timeout(std::chrono::milliseconds{DEFAULT_POLL_TIMEOUT_MS}) {
    int number_of_conns = 0;
    mtev_conf_section_t *mqs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_IN_MQ,
      &number_of_conns);

    if(number_of_conns == 0) {
      mtev_conf_release_sections_read(mqs, number_of_conns);
      return;
    }
    for (int section_id = 0; section_id < number_of_conns; section_id++) {
      std::string host_string;
      if(char *host; !mtev_conf_get_string(mqs[section_id], CONFIG_KAFKA_HOST, &host)) {
        host_string = "localhost";
      }
      else {
        host_string = host;
        free(host);
      }
      int32_t port = 0;
      if(!mtev_conf_get_int32(mqs[section_id], CONFIG_KAFKA_PORT, &port)) {
        port = 9092;
      }
      std::string topic_string;
      if(char *topic; !mtev_conf_get_string(mqs[section_id], CONFIG_KAFKA_TOPIC, &topic)) {
        topic_string = "TODO";
      }
      else {
        topic_string = topic;
        free(topic);
      }
      try {
        auto conn = std::make_unique<kafka_connection>(host_string, port, topic_string);
        _conns.push_back(std::move(conn));
      }
      catch (std::exception& exception) {
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
  void set_poll_timeout(std::chrono::milliseconds poll_timeout) {
    _poll_timeout = poll_timeout;
  }
  int poll() {
    for (const auto &conn: _conns) {
      auto records = conn->consumer->poll(_poll_timeout);
      for (const auto& record: records) {
        // TODO
      }
    }
    return 0;
  }
  int show_console(const mtev_console_closure_t &ncct) {
    for (const auto &conn: _conns) {
      conn->write_to_console(ncct);
    }
    return 0;
  }
  private:
  std::vector<std::unique_ptr<kafka_connection>> _conns;
  std::chrono::milliseconds _poll_timeout;
};

static kafka_module_config *the_conf = nullptr;

static kafka_module_config *get_or_load_config(mtev_dso_generic_t *self) {
  if(the_conf) {
    return the_conf;
  }
  the_conf = static_cast<kafka_module_config *>(mtev_image_get_userdata(&self->hdr));
  if(the_conf) {
    return the_conf;
  }
  the_conf = new kafka_module_config{};
  mtev_image_set_userdata(&self->hdr, the_conf);
  return the_conf;
}

static int
kafka_logio_open(mtev_log_stream_t ls) {
  (void)ls;
  return 0;
}

static int
kafka_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                  const void *buf, size_t len) {
// TODO: Fill this in
#if 0
  (void)whence;
  char exchange[127], route[127], *prefix, *path;
  path = (char *)mtev_log_stream_get_path(ls);
  prefix = strchr(path, '/');
  if(!prefix) {
    strlcpy(exchange, path, sizeof(exchange));
    snprintf(route, sizeof(route), "mtev.log.%s", mtev_log_stream_get_name(ls));
  } else {
    prefix++;
    strlcpy(exchange, path, MIN(sizeof(exchange), (size_t)(prefix - path)));
    snprintf(route, sizeof(route), "%s.%s", prefix, mtev_log_stream_get_name(ls));
  }
  mtev_amqp_send_data(exchange, route, false, false, (void *)buf, len, -1);
#endif
  return len;
}

static logops_t kafka_logio_ops = {
  mtev_false,
  kafka_logio_open,
  NULL,
  kafka_logio_write,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

static int
mtev_console_show_kafka(mtev_console_closure_t ncct,
                        int argc, char **argv,
                        mtev_console_state_t *dstate,
                        void *closure) {
  (void)argc;
  (void)argv;
  (void)dstate;
  auto conf = static_cast<kafka_module_config *>(closure);
  return conf->show_console(ncct);
}

static int
kafka_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    if (!strcmp("poll_timeout_ms", iter.key.str)) {
      auto poll_timeout_ms = atoi(iter.value.str);
      if (poll_timeout_ms < 0) {
        poll_timeout_ms = DEFAULT_POLL_TIMEOUT_MS;
      }
      auto config = get_or_load_config(img);
      config->set_poll_timeout(std::chrono::milliseconds{poll_timeout_ms});
    }
    else {
      mtevL(nlerr, "Kafka module config got unknown value: %s=%s\n", iter.key.str, iter.value.str);
    }
  }

  return 0;
}

static int
kafka_driver_init(mtev_dso_generic_t *img) {
  constexpr auto poll_kafka = [](eventer_t e, int mask, void *c, struct timeval *now) {
    (void)e;
    (void)mask;
    (void)now;
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
    NCSCMD("", mtev_console_show_kafka, NULL, NULL, config));

  auto e = eventer_alloc_recurrent(poll_kafka, config);
  eventer_add(e);
  return 0;
}

#include "kafka.xmlh"
// There's a conflict with the kafka library with the name "kafka" that won't
// allow us to export the name of the module as "kafka". The extern "C" and namespacee
// here is a workaround that allows us to use the name
extern "C" {
namespace {
mtev_dso_generic_t kafka = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "kafka",
    .description = "A Kafka subscriber and publisher",
    .xml_description = kafka_xml_description,
  },
  kafka_driver_config,
  kafka_driver_init
};
}
}
