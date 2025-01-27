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

struct kafka_connection {
  kafka_connection(const std::string &host, const int32_t port, const std::string &topic_str) {
    std::string broker_with_port = host + ":" + std::to_string(port);
    props.put("enable.idempotence", "true");
    props.put("bootstrap.servers", broker_with_port);
    producer = std::make_unique<kafka::clients::producer::KafkaProducer>(props);
    consumer = std::make_unique<kafka::clients::consumer::KafkaConsumer>(props);
    const kafka::Topic topic = topic_str;
    consumer->subscribe({topic});
  }
  kafka_connection() = delete;
  ~kafka_connection() = default;

  kafka::Properties props;
  std::unique_ptr<kafka::clients::producer::KafkaProducer> producer;
  std::unique_ptr<kafka::clients::consumer::KafkaConsumer> consumer;
};

class kafka_module_config {
  public:
  kafka_module_config() {
    int local_number_of_conns = 0;
    mtev_conf_section_t *mqs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_IN_MQ,
      &local_number_of_conns);

    if(local_number_of_conns == 0) {
      mtev_conf_release_sections_read(mqs, local_number_of_conns);
      return;
    }
    for (int section_id = 0; section_id < local_number_of_conns; section_id++) {
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
      _conns.emplace_back(std::make_unique<kafka_connection>(host_string, port, topic_string));
      _number_of_conns++;
    }
    mtev_conf_release_sections_read(mqs, local_number_of_conns);
    _receiver = eventer_alloc_recurrent(poll_kafka, this);
    eventer_add(_receiver);
  }
  ~kafka_module_config() = default;
  private:
  static int poll_kafka(eventer_t e, int mask, void *c, struct timeval *now) {
    (void)e;
    (void)mask;
    (void)now;
    auto self = static_cast<kafka_module_config *>(c);
    for (int client = 0; client < self->_number_of_conns; client++) {
      auto records = self->_conns[client]->consumer->poll(std::chrono::milliseconds(10));
      for (const auto& record: records) {
        // TODO
      }
    }
    return EVENTER_RECURRENT;
  }
  int _number_of_conns;
  eventer_t _receiver;
  std::vector<std::unique_ptr<kafka_connection>> _conns;
};

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;
static kafka_module_config *the_conf = nullptr;

static kafka_module_config *get_config(mtev_dso_generic_t *self) {
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
kafka_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  return 0;
}

static int
kafka_driver_init(mtev_dso_generic_t *img) {
  auto conf = get_config(img);
  mtev_register_logops("kafka", &kafka_logio_ops);
  nlerr = mtev_log_stream_find("error/kafka");
  nldeb = mtev_log_stream_find("debug/kafka");
  return 0;
}

#include "kafka.xmlh"
mtev_dso_generic_t kafka_module = {
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