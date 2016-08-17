/*
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
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

#ifndef MTEV_CLUSTER_H
#define MTEV_CLUSTER_H

#include "mtev_defines.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mtev_conf.h>

typedef struct mtev_cluster_t mtev_cluster_t;

typedef struct {
  uuid_t id;
  char cn[256];
  union {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } addr;
  socklen_t address_len;
  struct timeval last_contact;
  struct timeval boot_time;
  u_int64_t config_seq;
  void *payload;
  uint16_t payload_length;
  uint8_t number_of_payloads;
} mtev_cluster_node_t;

typedef void (*mtev_cluster_node_update_cb)(mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster);

/*! \fn void mtev_cluster_init()
    \brief Initialize the mtev cluster configuration.

    Initializes the mtev cluster configuration.
 */
API_EXPORT(void)
  mtev_cluster_init();

/*! \fn mtev_boolean mtev_cluster_enabled()
    \brief Report on the availability of the clusters feature.

    Returns mtev_true if clusters can be configured.
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_enabled();

/*! \fn int mtev_cluster_update(mtev_conf_section_t cluster)
    \brief Add or update an mtev cluster.
    \param cluster The '<cluster>' node configuration.
    \return Returns -1 on error, 0 on insert, or 1 on update.

    Takes a configuration section representing a cluster and registers
    it in the global cluster configuration.
 */
API_EXPORT(int)
  mtev_cluster_update(mtev_conf_section_t cluster);

/*! \fn mtev_cluster_t *mtev_cluster_by_name(const char *name)
    \brief Find the cluster with the registered name.
    \param name The name of the cluster.
    \return Returns a pointer to the cluster or NULL is not found.

    Takes a name and finds a globally registered cluster by that name.
 */
API_EXPORT(mtev_cluster_t *) mtev_cluster_by_name(const char *);

/*! \fn mtev_cluster_node_t *mtev_cluster_find_node(mtev_cluster_t *cluster, uuid_t nodeid)
    \brief Find a node by uuid within a cluster.
    \param cluster The '<cluster>' containing the node.
    \param nodeid The nodeid being searched for.
    \return Returns a pointer to the mtev_cluster_node_t or NULL if not found.

    Takes a cluster and a node UUID and returns a pointer to the 
    corresponding mtev_cluster_node_t.
 */
API_EXPORT(mtev_cluster_node_t *)
  mtev_cluster_find_node(mtev_cluster_t *cluster, uuid_t nodeid);

/*! \fn int mtev_cluster_size(mtev_cluster_t *cluster)
    \brief Report the number of nodes in the cluster.
    \param cluster The cluster.
    \return The number of nodes in the cluster.

    Determines the number of nodes in the given cluster.
 */
API_EXPORT(int) mtev_cluster_size(mtev_cluster_t *);

/* \fn void mtev_cluster_set_self(uuid_t id)
   \brief Sets the UUID of the local node.
   \param id The UUID.

   Sets the local node's cluster identity, potentially updating the
   on-disk condifuration.
 */
API_EXPORT(void) mtev_cluster_set_self(uuid_t);

/* \fn void mtev_cluster_get_self(uuid_t id)
   \brief Reports the UUID of the local node.
   \param id The UUID to be updated.

   Pouplates the passed uuid_t with the local node's UUID.
 */
API_EXPORT(void) mtev_cluster_get_self(uuid_t);

/* \fn int mtev_cluster_get_nodes(mtev_cluster_t *cluster, mtev_cluster_node_t **nodes, int n, mtev_boolean includeme)
   \brief Reports all nodes in the cluster (possible excluding the local node)
   \param cluster The cluster in question.
   \param nodes The destination array to which a node list will be written.
   \param n The number of positions available in the passed nodes array.
   \param includeme Whether the local node should included in the list.
   \return Returns the number of nodes populated in the supplied nodes array.
           If insufficient space is available, a negative value is returned whose
           absolute value indicates the required size of the input array.

   Enumerates the nodes in a cluster into a provided nodes array.
 */
API_EXPORT(int)
  mtev_cluster_get_nodes(mtev_cluster_t *,
                         mtev_cluster_node_t **, int n,
                         mtev_boolean includeme);

/* \fn mtev_boolean mtev_cluster_do_i_own(mtev_cluster_t *cluster, void *key, size_t klen, int w)
   \brief Determines if the local node should possess a given key based on internal CHTs.
   \param cluster The cluster in question.
   \param key A pointer to the key.
   \param klen The length, in bytes, of the key.
   \param w The number of nodes that are supposed to own this key.
   \return Returns mtev_true or mtev_false based on ownership status.

   This function determines if the local node is among the w nodes in this
   cluster that should own the specified key.
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_do_i_own(mtev_cluster_t *, void *key, size_t klen, int w);

/* \fn void mtev_cluster_enable_payload(mtev_cluster_t *cluster, void* payload, uint8_t payload_length)
   \brief Triggers the attachment of an arbitrary payload to the cluster heartbeats (see mtev_cluster_handle_node_update)
   \param cluster The cluster in question, may not be NULL.
   \param app_id Used to identify the application that attached the payload.
   \param key Used to identify the payload amongst other payloads from the application.
   \param payload A pointer to the payload that should be attached to every heartbeat message.
   \param payload_length The number of bytes to be read from payload.
   \return Returns mtev_true if the payload was not enabled yet

   This function triggers the attachment of an arbitrary payload to the cluster heartbeats (see mtev_cluster_get_payload)
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_set_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id,
    uint8_t key, void *payload, uint8_t payload_length);

API_EXPORT(mtev_boolean)
  mtev_cluster_unset_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key);

API_EXPORT(int)
  mtev_cluster_get_heartbeat_payload(mtev_cluster_node_t *node, uint8_t app_id,
    uint8_t key, void **payload);

/* \fn int64_t mtev_cluster_get_config_seq(mtev_cluster_t *cluster)
   \brief Returns the current config sequence of the given cluster
   \param cluster The cluster in question, may not be NULL.

   This function returns the current config sequence of the given cluster
 */
API_EXPORT(int64_t)
  mtev_cluster_get_config_seq(mtev_cluster_t *cluster);

/* \fn  mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster)
   \brief Returns the oldest node within the given cluster.
   \param cluster The cluster in question.
   \return Returns the node in the given cluster with the highest up-time.
 */
API_EXPORT(mtev_cluster_node_t*)
  mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster);

/* \fn mtev_boolean mtev_cluster_am_i_oldest_node(const mtev_cluster_t *cluster)
   \brief Determines if the local node is the oldest node within the cluster.
   \param cluster The cluster in question.
   \return Returns mtev_true if there is no node in the cluster with a higher up-time than this one.
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_am_i_oldest_node(const mtev_cluster_t *cluster);

/* \fn struct timeval mtev_cluster_get_my_boot_time()
   \brief Returns the boot time of the local node.
   \return The boot time of the local node.
 */
API_EXPORT(struct timeval)
  mtev_cluster_get_my_boot_time();

/* \fn int mtev_cluster_set_node_update_callback(mtev_cluster_t *cluster, mtev_cluster_node_update_cb callback)
   \brief Sets a callback which is called everytime a node in the cluster changes it's up-time.
   \param cluster The cluster in question.
   \param callback Function pointer to the function that should be called.
   \return Returns mtev_true if the cluster is not NULL, mtev_false otherwise
 */
MTEV_HOOK_PROTO(mtev_cluster_handle_node_update,
                (mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
                    struct timeval old_boot_time),
                void *, closure,
                (void *closure, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
                    struct timeval old_boot_time));


#endif
