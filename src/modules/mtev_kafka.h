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
 * The <in> stanza will contain all consumers. The <out> stanza will contain all producers.
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
 * producers. Start the XML element with `rdkafka_topic_config_setting_`, then fill in the
 * parameter you wish to set.
 */

#ifndef _MTEV_KAFKA_HPP
#define _MTEV_KAFKA_HPP

#include "mtev_defines.h"
#include "mtev_hooks.h"
#include "mtev_log.h"
#include "mtev_uuid.h"

#include <ck_pr.h>

#ifndef _RDKAFKA_H_
typedef void rd_kafka_message_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MTEV_KAFKA_CONNECTION_TYPE_PRODUCER = 0,
  MTEV_KAFKA_CONNECTION_TYPE_CONSUMER,
  MTEV_KAFKA_CONNECTION_TYPE_INVALID
} mtev_kafka_connection_type_e;

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

typedef struct mtev_kafka_connection_info mtev_kafka_connection_info_t;
typedef struct mtev_kafka_connection_list mtev_kafka_connection_list_t;

// clang-format off
/*! \fn mtev_kafka_connection_type_e mtev_kafka_connection_info_get_type(const mtev_kafka_connection_info_t *info)
    \brief Get the connection type from a Kafka connection info structure.
    \param info The connection info structure to query.
    \return The connection type, or MTEV_KAFKA_CONNECTION_TYPE_INVALID if info is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_type,
                     mtev_kafka_connection_info_get_type_function,
                     mtev_kafka_connection_type_e,
                     (const mtev_kafka_connection_info_t *info),
                     (info))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_type,
                   mtev_kafka_connection_info_get_type_function)

// clang-format off
/*! \fn void mtev_kafka_connection_info_get_id(const mtev_kafka_connection_info_t *info, uuid_t out_id)
    \brief Get the UUID of a Kafka connection.
    \param info The connection info structure to query.
    \param out_id Output parameter where the UUID will be copied.
    \return 0 if the call was succcessful, or -1 if info is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_id,
                     mtev_kafka_connection_info_get_id_function,
                     int,
                     (const mtev_kafka_connection_info_t *info, uuid_t out_id),
                     (info, out_id))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_id, mtev_kafka_connection_info_get_id_function)

// clang-format off
/*! \fn const char *mtev_kafka_connection_info_get_host(const mtev_kafka_connection_info_t *info)
    \brief Get the host name of a Kafka connection.
    \param info The connection info structure to query.
    \return The host name string, or NULL if info is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_host,
                     mtev_kafka_connection_info_get_host_function,
                     const char *,
                     (const mtev_kafka_connection_info_t *info),
                     (info))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_host,
                   mtev_kafka_connection_info_get_host_function)

// clang-format off
/*! \fn int32_t mtev_kafka_connection_info_get_port(const mtev_kafka_connection_info_t *info)
    \brief Get the port number of a Kafka connection.
    \param info The connection info structure to query.
    \return The port number, or 0 if info is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_port,
                     mtev_kafka_connection_info_get_port_function,
                     int32_t,
                     (const mtev_kafka_connection_info_t *info),
                     (info))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_port,
                   mtev_kafka_connection_info_get_port_function)

// clang-format off
/*! \fn size_t mtev_kafka_connection_info_get_topic_count(const mtev_kafka_connection_info_t *info)
    \brief Get the number of topics associated with a Kafka connection.
    \param info The connection info structure to query.
    \return The number of topics, or 0 if info is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_topic_count,
                     mtev_kafka_connection_info_get_topic_count_function,
                     ssize_t,
                     (const mtev_kafka_connection_info_t *info),
                     (info))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_topic_count,
                   mtev_kafka_connection_info_get_topic_count_function)

// clang-format off
/*! \fn const char *mtev_kafka_connection_info_get_topic(const mtev_kafka_connection_info_t *info, size_t index)
    \brief Get a specific topic name from a Kafka connection.
    \param info The connection info structure to query.
    \param index The index of the topic to retrieve (0-based).
    \return The topic name string, or NULL if info is NULL or index is out of bounds.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_info_get_topic,
                     mtev_kafka_connection_info_get_topic_function,
                     const char *,
                     (const mtev_kafka_connection_info_t *info, size_t index),
                     (info, index))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_info_get_topic,
                   mtev_kafka_connection_info_get_topic_function)

// clang-format off
/*! \fn size_t mtev_kafka_connection_list_get_count(const mtev_kafka_connection_list_t *list)
    \brief Get the number of connections in a Kafka connection list.
    \param list The connection list to query.
    \return The number of connections in the list, or -1 if list is NULL.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_list_get_count,
                     mtev_kafka_connection_list_get_count_function,
                     ssize_t,
                     (const mtev_kafka_connection_list_t *list),
                     (list))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_list_get_count,
                   mtev_kafka_connection_list_get_count_function)

// clang-format off
/*! \fn const mtev_kafka_connection_info_t *mtev_kafka_connection_list_get_connection(const mtev_kafka_connection_list_t *list, size_t index)
    \brief Get a specific connection from a Kafka connection list.
    \param list The connection list to query.
    \param index The index of the connection to retrieve (0-based).
    \return A pointer to the connection info structure, or NULL if list is NULL or index is out of bounds.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_connection_list_get_connection,
                     mtev_kafka_connection_list_get_connection_function,
                     const mtev_kafka_connection_info_t *,
                     (const mtev_kafka_connection_list_t *list, size_t index),
                     (list, index))
MTEV_RUNTIME_AVAIL(mtev_kafka_connection_list_get_connection,
                   mtev_kafka_connection_list_get_connection_function)

// clang-format off
/*! \fn void mtev_kafka_free_connection_list(mtev_kafka_connection_list_t *list)
    \brief Free a Kafka connection list and all associated memory.
    \param list The connection list to free.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_free_connection_list,
                     mtev_kafka_free_connection_list_function,
                     void,
                     (mtev_kafka_connection_list_t * list),
                     (list))
MTEV_RUNTIME_AVAIL(mtev_kafka_free_connection_list, mtev_kafka_free_connection_list_function)

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
    \brief Publish a Kafka message to all configured Kafka publishers.
    \param payload The payload to publish.
    \param payload_len The size of the payload.
 */
MTEV_RUNTIME_RESOLVE(mtev_kafka_broadcast,
                     mtev_kafka_broadcast_function,
                     void,
                     (const void *payload, size_t payload_len),
                     (payload, payload_len))
MTEV_RUNTIME_AVAIL(mtev_kafka_broadcast, mtev_kafka_broadcast_function)

/*! \fn mtev_kafka_connection_list_t *mtev_kafka_get_all_producers(void)
    \brief Get a list of all active Kafka producers.
    \return A list of producers in a mtev_kafka_connection_list_t struct.
 */
MTEV_RUNTIME_RESOLVE(mtev_kafka_get_all_producers,
                     mtev_kafka_get_all_producers_function,
                     mtev_kafka_connection_list_t *,
                     (),
                     ())
MTEV_RUNTIME_AVAIL(mtev_kafka_get_all_producers, mtev_kafka_get_all_producers_function)

/*! \fn mtev_kafka_connection_list_t *mtev_kafka_get_all_consumers(void)
    \brief Get a list of all active Kafka consumers.
    \return A list of consumers in a mtev_kafka_connection_list_t struct.
 */
MTEV_RUNTIME_RESOLVE(mtev_kafka_get_all_consumers,
                     mtev_kafka_get_all_consumers_function,
                     mtev_kafka_connection_list_t *,
                     (),
                     ())
MTEV_RUNTIME_AVAIL(mtev_kafka_get_all_consumers, mtev_kafka_get_all_consumers_function)

// clang-format off
/*! \fn mtev_boolean mtev_kafka_close_producer(const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure)
    \brief Enqueues a request to shut down the producer with the given uuid
    \param id The UUID of the producer to shut down.
    \param callback The callback function that will get called when the connection is closed.
    \param closure A closure containing user data.
    \return mtev_true if the connection was enqueued to be shut down, mtev_false otherwise.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_close_producer,
                     mtev_kafka_close_producer_function,
                     mtev_boolean,
                     (const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure),
                     (id, callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_close_producer, mtev_kafka_close_producer_function)

// clang-format off
/*! \fn mtev_boolean mtev_kafka_close_consumer(const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure)
    \brief Enqueues a request to shut down the consumer with the given uuid
    \param id The UUID of the consumer to shut down.
    \param callback The callback function that will get called when the connection is closed.
    \param closure A closure containing user data.
    \return mtev_true if the connection was enqueued to be shut down, mtev_false otherwise.
 */
// clang-format on
MTEV_RUNTIME_RESOLVE(mtev_kafka_close_consumer,
                     mtev_kafka_close_consumer_function,
                     mtev_boolean,
                     (const uuid_t id, mtev_kafka_shutdown_callback_t callback, void *closure),
                     (id, callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_close_consumer, mtev_kafka_close_consumer_function)

/*! \fn void mtev_kafka_shut_down(mtev_kafka_shutdown_callback_t callback, void *closure)
    \brief Shuts down all Kafka connections.
    \param callback The callback function that will get called when all connections are closed.
    \param closure A closure containing user data.
 */
MTEV_RUNTIME_RESOLVE(mtev_kafka_shut_down,
                     mtev_kafka_shut_down_function,
                     void,
                     (mtev_kafka_shutdown_callback_t callback, void *closure),
                     (callback, closure))
MTEV_RUNTIME_AVAIL(mtev_kafka_shut_down, mtev_kafka_shut_down_function)

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
