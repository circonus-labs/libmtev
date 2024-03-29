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

#include <mtev_defines.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libxml/tree.h>
#include <mtev_conf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtev_cluster_t mtev_cluster_t;

typedef struct mtev_cluster_node_t mtev_cluster_node_t;

#define MTEV_CLUSTER_NODE_DIED 1 << 0
#define MTEV_CLUSTER_NODE_REBOOTED 1 << 1
#define MTEV_CLUSTER_NODE_CHANGED_SEQ 1 << 2
#define MTEV_CLUSTER_NODE_CHANGED_PAYLOAD 1 << 3
typedef uint8_t mtev_cluster_node_changes_t;

typedef void (*mtev_cluster_node_update_cb)(mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster);

/*! \fn void mtev_cluster_init()
    \brief Initialize the mtev cluster configuration.

    Initializes the mtev cluster configuration.
 */
API_EXPORT(void)
  mtev_cluster_init(void);

/*! \fn mtev_boolean mtev_cluster_enabled()
    \brief Report on the availability of the clusters feature.
    \return mtev_true if clusters can be configured, otherwise mtev_false.
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_enabled(void);

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

/*! \fn void mtev_cluster_set_self(uuid_t id)
    \brief Sets the UUID of the local node.
    \param id The UUID.

    Sets the local node's cluster identity, potentially updating the on-disk configuration.
*/
API_EXPORT(int) mtev_cluster_set_self(uuid_t);

/*! \fn void mtev_cluster_get_self(uuid_t id)
    \brief Reports the UUID of the local node.
    \param id The UUID to be updated.
    \return Returns -1 on error

    Pouplates the passed uuid_t with the local node's UUID.
*/
API_EXPORT(void) mtev_cluster_get_self(uuid_t);

API_EXPORT(mtev_boolean) mtev_cluster_is_that_me(mtev_cluster_node_t *node);

/*! \fn mtev_cluster_node_t * mtev_cluster_get_node(mtev_cluster_t *cluster, uuid_t id)
    \brief Find a node in a cluster by id.
    \param cluster The cluster in question.
    \param id The uuid of the node in question.
    \return An `mtev_cluster_node_t *` if one is found with the provided id, otherwise NULL,
*/
API_EXPORT(mtev_cluster_node_t *) mtev_cluster_get_node(mtev_cluster_t *c, uuid_t id);

/*! \fn int mtev_cluster_get_nodes(mtev_cluster_t *cluster, mtev_cluster_node_t **nodes, int n, mtev_boolean includeme)
    \brief Reports all nodes in the cluster (possible excluding the local node)
    \param cluster The cluster in question.
    \param nodes The destination array to which a node list will be written.
    \param n The number of positions available in the passed nodes array.
    \param includeme Whether the local node should included in the list.
    \return Returns the number of nodes populated in the supplied nodes array.  If insufficient space is available, a negative value is returned whose absolute value indicates the required size of the input array.

    Enumerates the nodes in a cluster into a provided nodes array.
*/
API_EXPORT(int)
  mtev_cluster_get_nodes(mtev_cluster_t *,
                         mtev_cluster_node_t **, int n,
                         mtev_boolean includeme);

/*! \fn mtev_boolean mtev_cluster_do_i_own(mtev_cluster_t *cluster, void *key, size_t klen, int w)
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

typedef mtev_boolean (*mtev_cluster_node_filter_func_t)(mtev_cluster_node_t *, mtev_boolean, void *);

/*! \var mtev_cluster_node_filter_func_t mtev_cluster_alive_filter
    \brief A `mtev_cluster_node_filter_func_t` for alive nodes.

    This function is available to be passed as the `filter` argument to `mtev_cluster_filter_owners`.
*/

API_EXPORT(mtev_boolean)
  mtev_cluster_alive_filter(mtev_cluster_node_t *node, mtev_boolean me, void *closure);

/*! \fn mtev_boolean mtev_cluster_filter_owners(mtev_cluster_t *cluster, void *key, size_t klen, mtev_cluster_node_t **set, int *w, mtev_cluster_node_filter_func_t filter, void *closure)
    \brief Determines if the local node should possess a given key based on internal CHTs.
    \param cluster The cluster in question.
    \param key A pointer to the key.
    \param klen The length, in bytes, of the key.
    \param set A caller allocated array of at least *w length.
    \param w The number of nodes that are supposed to own this key, updated to set length that matches filter.
    \param filter The function used to qualify nodes.
    \param closure A user supplied value that is passed to the filter function.
    \return Returns mtev_true or mtev_false if set[0] is this node.

    This function populates a set of owners for a key, but first filters them according to a user-specified function.
*/
API_EXPORT(mtev_boolean)
  mtev_cluster_filter_owners(mtev_cluster_t *c, void *key, size_t len,
                             mtev_cluster_node_t **set, int *w,
                             mtev_cluster_node_filter_func_t filter,
                             void *closure);

/*! \fn void mtev_cluster_set_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key, void* payload, uint8_t payload_length)
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

/*! \fn void mtev_cluster_unset_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key)
    \brief Detaches (clears) an arbitrary payload to the cluster heartbeats (see mtev_cluster_handle_node_update)
    \param cluster The cluster in question, may not be NULL.
    \param app_id Used to identify the application that attached the payload.
    \param key Used to identify the payload amongst other payloads from the application.
*/
API_EXPORT(mtev_boolean)
  mtev_cluster_unset_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key);

/*! \fn int mtev_cluster_get_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key, void **payload)
    \brief Gets the current value of a payload segment from a node.
    \param cluster The cluster in question, may not be NULL.
    \param app_id Used to identify the application that attached the payload.
    \param key Used to identify the payload amongst other payloads from the application.
    \param payload Pointer to a payload pointer.
    \return The length of the payload, -1 if that payload segment does not exist.
*/
API_EXPORT(int)
  mtev_cluster_get_heartbeat_payload(mtev_cluster_node_t *node, uint8_t app_id,
    uint8_t key, void **payload);

/*! \fn int64_t mtev_cluster_get_config_seq(mtev_cluster_t *cluster)
    \brief Returns the current config sequence of the given cluster
    \param cluster The cluster in question, may not be NULL.

    This function returns the current config sequence of the given cluster
 */
API_EXPORT(int64_t)
  mtev_cluster_get_config_seq(mtev_cluster_t *cluster);

/*! \fn int mtev_cluster_node_get_idx(mtev_cluster_node_t *node)
    \brief Get the unique integer idx of the node within it's cluster.
    \param node The node in question
    \return A number between 0 and cluster_size - 1.
 */
API_EXPORT(int)
  mtev_cluster_node_get_idx(mtev_cluster_node_t *node);

/*! \fn  mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster)
    \brief Returns the oldest node within the given cluster.
    \param cluster The cluster in question.
    \return Returns the node in the given cluster with the highest up-time.
 */
API_EXPORT(mtev_cluster_node_t*)
  mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster);

/*! \fn mtev_boolean mtev_cluster_am_i_oldest_node(const mtev_cluster_t *cluster)
    \brief Determines if the local node is the oldest node within the cluster.
    \param cluster The cluster in question.
    \return Returns mtev_false if there is a node in the cluster with a higher up-time than this one.
 */
API_EXPORT(mtev_boolean)
  mtev_cluster_am_i_oldest_visible_node(const mtev_cluster_t *cluster);

/*! \fn mtev_boolean mtev_cluster_node_is_dead(mtev_cluster_node_t *node)
    \brief Detrmines if the node in question is dead.
    \param node The node in question.
    \return Returns true if the node is dead.
*/
API_EXPORT(mtev_boolean)
  mtev_cluster_node_is_dead(mtev_cluster_node_t *node);

/*! \fn void mtev_cluster_node_get_id(mtev_cluster_node_t *node, uuid_t out)
    \brief Retrieve the ID of a cluster node.
    \param node The node in question.
    \param out A `uuid_t` to fill in.
*/
API_EXPORT(void)
  mtev_cluster_node_get_id(mtev_cluster_node_t *node, uuid_t out);

/*! \fn mtev_boolean mtev_cluster_node_has_payload(mtev_cluster_node_t *node)
    \brief Determine a cluster node has a custom payload attached.
    \param node The node in question.
    \return True if there is a payload, false otherwise.
*/
API_EXPORT(mtev_boolean)
  mtev_cluster_node_has_payload(mtev_cluster_node_t *node);

/*! \fn int8_t mtev_cluster_node_get_addr(mtev_cluster_node_t *node, struct sockaddr **addr, socklen_t *addrlen)
 */
API_EXPORT(int8_t)
  mtev_cluster_node_get_addr(mtev_cluster_node_t *node, struct sockaddr **addr, socklen_t *addrlen);

/*! \fn const char* mtev_cluster_node_get_cn(mtev_cluster_node_t *node)
    \return cn (canonical name) of the cluster node
 */
API_EXPORT(const char *)
  mtev_cluster_node_get_cn(mtev_cluster_node_t *node);

/*! \fn struct timeval mtev_cluster_node_get_boot_time(mtev_cluster_node_t *node)
  \return boot time as timeval struct
 */
API_EXPORT(struct timeval)
  mtev_cluster_node_get_boot_time(mtev_cluster_node_t *node);

/*! \fn struct timeval mtev_cluster_node_get_last_contact(mtev_cluster_node_t *node)
\return time of last contact to the given node
*/
API_EXPORT(struct timeval)
  mtev_cluster_node_get_last_contact(mtev_cluster_node_t *node);

/*! \fn int64_t mtev_cluster_node_get_config_seq(mtev_cluster_node_t *node)
*/
API_EXPORT(int64_t)
  mtev_cluster_node_get_config_seq(mtev_cluster_node_t *node);

/*! \fn const char *mtev_cluster_get_name(mtev_cluster_t *cluster)
    \brief Returns the name of the cluster.
    \param cluster a cluster
    \return A pointer to the cluster's name.
*/
API_EXPORT(const char *)
  mtev_cluster_get_name(mtev_cluster_t *);

/*! \fn struct timeval mtev_cluster_get_my_boot_time()
    \brief Returns the boot time of the local node.
    \return The boot time of the local node.
*/
API_EXPORT(struct timeval)
  mtev_cluster_get_my_boot_time(void);

/*! \fn int mtev_cluster_set_node_update_callback(mtev_cluster_t *cluster, mtev_cluster_node_update_cb callback)
    \brief Sets a callback which is called everytime a node in the cluster changes it's up-time.
    \param cluster The cluster in question.
    \param callback Function pointer to the function that should be called.
    \return Returns mtev_true if the cluster is not NULL, mtev_false otherwise
*/

MTEV_HOOK_PROTO(mtev_cluster_update,
                (mtev_cluster_t *cluster, mtev_boolean created),
                void *, closure,
                (void *closure, mtev_cluster_t *cluster, mtev_boolean created));

MTEV_HOOK_PROTO(mtev_cluster_handle_node_update,
                (mtev_cluster_node_changes_t node_changes, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
                    struct timeval old_boot_time),
                void *, closure,
                (void *closure, mtev_cluster_node_changes_t node_changes, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
                    struct timeval old_boot_time));

MTEV_HOOK_PROTO(mtev_cluster_on_write_extra_cluster_config_cleanup,
                (mtev_cluster_t *cluster, xmlNodePtr node), void *, closure,
                (void *closure, mtev_cluster_t *cluster, xmlNodePtr node));

MTEV_HOOK_PROTO(mtev_cluster_write_extra_cluster_config_xml,
                (mtev_cluster_t *cluster, xmlNodePtr node), void *, closure,
                (void *closure, mtev_cluster_t *cluster, xmlNodePtr node));

MTEV_HOOK_PROTO(mtev_cluster_write_extra_node_config_xml,
                (mtev_cluster_t *cluster, uuid_t node_id, xmlNodePtr node), void *, closure,
                (void *closure, mtev_cluster_t *cluster, uuid_t node_id, xmlNodePtr node));

MTEV_HOOK_PROTO(mtev_cluster_write_extra_cluster_config_json,
                (mtev_cluster_t *cluster, struct json_object *obj), void *, closure,
                (void *closure, mtev_cluster_t *cluster, struct json_object *obj));

MTEV_HOOK_PROTO(mtev_cluster_write_extra_node_config_json,
                (mtev_cluster_t *cluster, uuid_t node_id, struct json_object *obj), void *, closure,
                (void *closure, mtev_cluster_t *cluster, uuid_t node_id, struct json_object *obj));

MTEV_HOOK_PROTO(mtev_cluster_read_extra_cluster_config,
                (mtev_cluster_t *cluster, mtev_conf_section_t *conf), void *, closure,
                (void *closure, mtev_cluster_t *cluster, mtev_conf_section_t *conf));

MTEV_HOOK_PROTO(mtev_cluster_read_extra_node_config,
                (mtev_cluster_t *cluster, uuid_t node_uuid, mtev_conf_section_t *conf), void *, closure,
                (void *closure, mtev_cluster_t *cluster, uuid_t node_uuid, mtev_conf_section_t *conf));

#ifdef __cplusplus
}
#endif

#endif
