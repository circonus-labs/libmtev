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

/*
 * The Kafka module is used to handle both consuming from and publishing to
 * kafka instances. All consumers and producers must be configured separately.
 * The configuration will look like this:
 * <network>
 *   <in>
 *     <mq type="kafka">
 *       <host>localhost</host>
 *       <port>9092</port>
 *       <topic>test_topic_one</topic>
 *       <consumer_group>sample_consumer_group_id</consumer_group>
 *       <protocol>prometheus</protocol>
 *       <override_custom_parameter_one>custom_value</override_custom_parameter_one>
 *       <override_custom_parameter_two>another_custom_value</override_custom_parameter_two>
 *       <override_another_custom_parameter>yet_another_custom_value</override_another_custom_parameter>
 *       <rdkafka_global_config_setting_fetch.error.backoff.ms>500</rdkafka_global_config_setting_fetch.error.backoff.ms>
 *     </mq>
 *   </in>
 *   <out>
 *     <mq type="kafka">
 *       <host>localhost</host>
 *       <port>9092</port>
 *       <topic>test_topic_two</topic>
 *       <rdkafka_global_config_setting_enable.idempotence>true</rdkafka_global_config_setting_enable.idempotence>
 *       <rdkafka_topic_config_setting_request.timeout.ms>30000</rdkafka_topic_config_setting_request.timeout.ms>
 *     </mq>
 *   </out>
 * </network>
 *
 * The <in> stanza will contain all consumers. The <out> standza will contain all producers.
 * Multiple mq stanzas can be defined for each.
 *
 * The individual fields for each config are:
 * <host>           - The host to connect to.
 * <port>           - The port to connect to.
 * <topic>          - The topic to interact with
 * <consumer_group> - The consumer group to use. Only for consumers.
 * <protocol>       - The format of the consumed messages. Only for consumers.
 *
 * <override_*> allows setting arbitrary fields that can be read by the hooks
 * so that fields outside of this exact spec can be set and used. It's up to the hook to
 * handle these if specified.
 * <rdkafka_global_config_setting_*> allows setting global configuration parameters from rdkafka.
 * Start the XML element with `rdkafka_global_config_setting_`, then fill in the parameter you wish
 * to set. The official list of legal parameters from Confluent is available here:
 * https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md
 * Use of the following fields are not allowed:
 * `bootstrap.servers`: Use `host` and `port`.
 * `group.id`: Use `consumer_group`.
 * <rdkafka_topic_config_setting_*> allows setting topic configuration properties on Kafka
 * producers. Start the XML element with `rdkafka_global_topic_setting_`, then fill in the
 * parameter you wish to set.
 */

#ifndef _MTEV_KAFKA_HPP
#define _MTEV_KAFKA_HPP

#include "mtev_defines.h"
#include "mtev_hooks.h"
#include "mtev_log.h"

#include <ck_pr.h>

#ifndef _RDKAFKA_H_
typedef void rd_kafka_message_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mtev_kafka_shutdown_callback_t)(void *closure,
                                               const uuid_t id,
                                               mtev_boolean success,
                                               const char *error);

typedef struct mtev_rd_kafka_message {
  rd_kafka_message_t *msg;
  uint32_t refcnt;
  const void *key;
  size_t key_len;
  const void *payload;
  size_t payload_len;
  int64_t offset;
  int32_t partition;
  const char *protocol;
  const char *topic;
  const mtev_hash_table *extra_configs;
  void (*free_fn)(struct mtev_rd_kafka_message *m);
} mtev_rd_kafka_message_t;

static inline void mtev_rd_kafka_message_ref(mtev_rd_kafka_message_t *msg)
{
  ck_pr_inc_uint(&msg->refcnt);
}

static inline void mtev_rd_kafka_message_deref(mtev_rd_kafka_message_t *msg)
{
  bool zero;
  ck_pr_dec_uint_zero(&msg->refcnt, &zero);
  if (zero) {
    if (msg->free_fn) {
      msg->free_fn(msg);
    }
  }
}

/*! \fn void mtev_kafka_broadcast(const void *payload, size_t payload_len)
    \brief Publish a Kafka message to all conifigurd Kafka publishers.
    \param payload The payload to publish.
    \param payload_len The size of the payload.
 */
MTEV_RUNTIME_RESOLVE(mtev_kafka_broadcast,
                     mtev_kafka_broadcast_function,
                     void,
                     (const void *payload, size_t payload_len),
                     (payload, payload_len))
MTEV_RUNTIME_AVAIL(mtev_kafka_broadcast, mtev_kafka_broadcast_function)

MTEV_RUNTIME_RESOLVE(mtev_kafka_get_all_producers,
                     mtev_kafka_get_all_producers_function,
                     void,
                     (void *closure),
                     (closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_get_all_producers, mtev_kafka_get_all_producers_function)

MTEV_RUNTIME_RESOLVE(mtev_kafka_get_all_consumers,
                     mtev_kafka_get_all_consumers_function,
                     void,
                     (void *closure),
                     (closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_get_all_consumers, mtev_kafka_get_all_consumers_function)

MTEV_RUNTIME_RESOLVE(mtev_kafka_shutdown_producer,
                     mtev_kafka_shutdown_producer_function,
                     mtev_boolean,
                     (const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure),
                     (id, callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_shutdown_producer, mtev_kafka_shutdown_producer_function)

MTEV_RUNTIME_RESOLVE(mtev_kafka_shutdown_consumer,
                     mtev_kafka_shutdown_consumer_function,
                     mtev_boolean,
                     (const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure),
                     (id, callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_shutdown_consumer, mtev_kafka_shutdown_consumer_function)

MTEV_RUNTIME_RESOLVE(mtev_kafka_shutdown_all,
                     mtev_kafka_shutdown_all_function,
                     void,
                     (mtev_kafka_shutdown_callback_t callback, void *closure),
                     (callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_shutdown_all, mtev_kafka_shutdown_all_function)

MTEV_HOOK_PROTO(mtev_kafka_handle_message_dyn,
                (mtev_rd_kafka_message_t * msg),
                void *,
                closure,
                (void *closure, mtev_rd_kafka_message_t *msg))

MTEV_RUNTIME_AVAIL(mtev_kafka_handle_message_hook_register,
                   mtev_kafka_handle_message_dyn_hook_register)
MTEV_RUNTIME_RESOLVE(mtev_kafka_handle_message_hook_register,
                     mtev_kafka_handle_message_dyn_hook_register,
                     mtev_hook_return_t,
                     (const char *name,
                      mtev_hook_return_t (*func)(void *closure, mtev_rd_kafka_message_t *msg),
                      void *closure),
                     (name, func, closure))

#ifdef __cplusplus
}
#endif

#endif
