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

#include "mtev_defines.h"

#include <libxml/tree.h>
#include <inttypes.h>

#include "mtev_uuid.h"
#include "mtev_rest.h"
#include "mtev_conf.h"
#include "mtev_hash.h"
#include "mtev_rand.h"
#include "mtev_memory.h"
#include "mtev_cluster.h"
#include "mtev_cht.h"
#include "mtev_net_heartbeat.h"

static pthread_mutex_t c_lock = PTHREAD_MUTEX_INITIALIZER;
static uuid_t my_cluster_id;
static struct timeval my_boot_time;
static mtev_boolean have_clusters;
static mtev_hash_table global_clusters;

static const struct timeval boot_time_of_dead_node = { 0, 0 };

static mtev_log_stream_t cerror = NULL;
static mtev_log_stream_t cdebug = NULL;

#define HEART_BEAT_HDR_LEN 1 + UUID_SIZE + sizeof(uint64_t) + sizeof(uint64_t) + 1
#define MAX_PAYLOAD_LEN_SUM  1518 - 14/*ETH*/ - 20 /*IP*/ - HEART_BEAT_HDR_LEN - 4 /*FCS*/

#define HEARTBEAT_MESSAGE_VERSION 1
static const uint8_t HEARTBEAT_MESSAGE_VERSION_AND_UNDERSTOOD = (HEARTBEAT_MESSAGE_VERSION << 4) | HEARTBEAT_MESSAGE_VERSION;

typedef struct {
  uint8_t app_id;
  uint8_t key;
  uint8_t data_len;
} __attribute__ ((__packed__)) hb_payload_hdr_t;

typedef struct {
  uint8_t app_id;
  uint8_t key;
  uint8_t data_len;
  void* data;
} hb_payload_t;

struct mtev_cluster_node_t {
  uuid_t id;
  char cn[256];
  union {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } addr;
  socklen_t address_len;
  struct timeval last_contact;
  struct timeval boot_time;
  uint64_t config_seq;
  void *payload;
  uint16_t payload_length;
  uint8_t number_of_payloads;
  int idx; /* This is just the offset into the cluster's nodes array */
};

void
mtev_cluster_node_get_id(mtev_cluster_node_t *node, uuid_t out) {
  mtev_uuid_copy(out, node->id);
}
int8_t
mtev_cluster_node_get_addr(mtev_cluster_node_t *node, struct sockaddr **addr, socklen_t *addrlen) {
  if(addr) *addr = (struct sockaddr *)&node->addr.addr4;
  if(addrlen) *addrlen = node->address_len;
  return node->addr.addr4.sin_family;
}
mtev_boolean
mtev_cluster_node_has_payload(mtev_cluster_node_t *node) {
  return node->payload != NULL;
}
const char *
mtev_cluster_node_get_cn(mtev_cluster_node_t *node) {
  return node->cn;
}
struct timeval
mtev_cluster_node_get_boot_time(mtev_cluster_node_t *node) {
  return node->boot_time;
}
struct timeval
mtev_cluster_node_get_last_contact(mtev_cluster_node_t *node) {
  return node->last_contact;
}
int64_t
mtev_cluster_node_get_config_seq(mtev_cluster_node_t *node) {
  return node->config_seq;
}
int
mtev_cluster_node_get_idx(mtev_cluster_node_t *node) {
  return node->idx;
}


/* All allocated with mtev_memory_safe commands */
struct mtev_cluster_t {
  char *name;
  unsigned short port;
  int period;
  int timeout;
  int maturity;
  char *key;
  int64_t config_seq;
  int node_cnt;
  mtev_cluster_node_t *nodes;
  mtev_cht_t **cht;
  mtev_net_heartbeat_ctx *hbctx;
  mtev_cluster_node_t *oldest_node;
  mtev_hash_table hb_payloads;
};


MTEV_HOOK_IMPL(mtev_cluster_handle_node_update,
  (mtev_cluster_node_changes_t node_change, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
      struct timeval old_boot_time),
  void *, closure,
  (void *closure, mtev_cluster_node_changes_t node_change, mtev_cluster_node_t *updated_node, mtev_cluster_t *cluster,
      struct timeval old_boot_time),
  (closure,node_change,updated_node,cluster,old_boot_time))

mtev_boolean
mtev_cluster_node_is_dead(mtev_cluster_node_t *node) {
  return compare_timeval(node->boot_time, boot_time_of_dead_node) == 0;
}

static int
mtev_cluster_node_compare(const void *a, const void *b) {
  const mtev_cluster_node_t *node_a = a;
  const mtev_cluster_node_t *node_b = b;
  return mtev_uuid_compare(node_a->id, node_b->id);
}

mtev_cluster_node_t *
mtev_cluster_find_node(mtev_cluster_t *cluster, uuid_t nodeid) {
  int i;
  for(i=0; i<cluster->node_cnt; i++) {
    if(!mtev_uuid_compare(cluster->nodes[i].id, nodeid))
      return &cluster->nodes[i];
  }
  return NULL;
}

mtev_boolean
mtev_cluster_enabled(void) {
  return have_clusters;
}

static void
mtev_cluster_free(void *vc) {
  mtev_cluster_t *c = vc;
  if(c) {
    if(c->name) mtev_memory_safe_free(c->name);
    if(c->key) mtev_memory_safe_free(c->key);
    if(c->nodes) mtev_memory_safe_free(c->nodes);
    if(c->cht) mtev_memory_safe_free(c->cht);
    if(c->hbctx) mtev_net_heartbeat_destroy(c->hbctx);
    c->hbctx = NULL;
    mtev_memory_safe_free(c);
  }
}

/* the CHT doesn't use safe reclamation, so we wrap it here */
static void
deferred_cht_free(void *vptr) {
  mtev_cht_t **chtp;
  if(!vptr) return;
  chtp = vptr;
  if(*chtp) mtev_cht_free(*chtp);
}

#define MEMWRITE_DECL(p, len) void *mw_wp = (p); int mw_wa = (len); int mw_wn=0
#define MEMWRITE(what,n) do { \
  if(mw_wn + (int)(n) > mw_wa) return -(mw_wn + (n)); \
  memcpy(mw_wp, what, n); \
  mw_wn += (n); \
  mw_wp = payload + mw_wn; \
} while(0)
#define MEMWRITE_WRITTEN mw_wn
#define MEMREAD_DECL(p, len) void *mw_rp = (p); int mw_ra = (len); int mw_rn=0
#define MEMGET(what, n) do { \
  if(mw_rn + (int)(n) > mw_ra) return -(mw_rn); \
  what = mw_rp; \
  mw_rn += (n); \
  mw_rp += (n); \
} while(0)
#define MEMREAD(what, n) do { \
  if(mw_rn + (int)(n) > mw_ra) return -(mw_rn); \
  memcpy(what, mw_rp, n); \
  mw_rn += (n); \
  mw_rp += (n); \
} while(0)
#define MEMREAD_BYTES_READ mw_rn

static void
mtev_cluster_node_to_string(mtev_cluster_node_t *node, char *buff,
    size_t buff_len) {
  if (node->addr.addr4.sin_family == AF_INET) {
    inet_ntop(AF_INET, &node->addr.addr4.sin_addr, buff, buff_len);
  } else if (node->addr.addr6.sin6_family == AF_INET6) {
    inet_ntop(AF_INET6, &node->addr.addr6.sin6_addr, buff, buff_len);
  }
}

static void
mtev_cluster_find_oldest_node(mtev_cluster_t *cluster) {
  cluster->oldest_node = &cluster->nodes[0];
  for (int i = 1; i < cluster->node_cnt; i++) {
    mtev_cluster_node_t *node = &cluster->nodes[i];

    if(mtev_cluster_node_is_dead(cluster->oldest_node) == mtev_true
        || (compare_timeval(node->boot_time, cluster->oldest_node->boot_time)
            == -1 && mtev_cluster_node_is_dead(node) == mtev_false)) {
      cluster->oldest_node = node;
    }
  }
}

static void
mtev_cluster_on_node_changed(mtev_cluster_t *cluster,
    mtev_cluster_node_t *sender, const struct timeval *new_boot_time,
    int64_t seq, mtev_cluster_node_changes_t node_change) {
  struct timeval old_boot_time = sender->boot_time;
  sender->boot_time = *new_boot_time;
  sender->config_seq = seq;

  if (mtev_uuid_compare(my_cluster_id, sender->id) != 0) {
    if (compare_timeval(*new_boot_time, my_boot_time) == 0) {
      char node_name[128];
      mtev_cluster_node_to_string(sender, node_name, sizeof(node_name));
      mtevL(cdebug,
          "The following node in the cluster %s had the same startup time we have: '%s'\n",
          cluster->name, node_name);
      my_boot_time.tv_usec = mtev_rand() % 1000000;
      return;
    }
  }

  if (mtev_cluster_node_is_dead(sender) == mtev_true || cluster->oldest_node == sender) {
    mtev_cluster_find_oldest_node(cluster);
  } else if (cluster->oldest_node == NULL || compare_timeval(*new_boot_time, cluster->oldest_node->boot_time) == -1) {
    cluster->oldest_node = sender;

    char node_name[128];
    mtev_cluster_node_to_string(sender, node_name, sizeof(node_name));
    mtevL(cdebug, "Oldest node of mtev_cluster '%s' is now '%s' \n",
        cluster->name, node_name);
  }

  mtev_cluster_handle_node_update_hook_invoke(node_change, sender, cluster, old_boot_time);
}
static void
mtev_cluster_check_timeout(mtev_cluster_t *cluster, struct timeval now) {
  for (int i = 0; i < cluster->node_cnt; i++) {
    mtev_cluster_node_t *node = &cluster->nodes[i];
    if(sub_timeval_ms(now, node->last_contact) > cluster->timeout) {
      if(mtev_cluster_node_is_dead(node) ==  mtev_false) {
        // ignore nodes that have just been booted
        if(node->boot_time.tv_sec > 0
            && sub_timeval_ms(now, node->boot_time) > cluster->maturity) {
          char node_name[128];
          mtev_cluster_node_to_string(node, node_name, sizeof(node_name));
          mtevL(cdebug, "Heartbeat timeout of cluster node %s\n",
              node_name);
          mtev_cluster_on_node_changed(cluster, node, &boot_time_of_dead_node, node->config_seq, MTEV_CLUSTER_NODE_DIED);
        }
      }
    }
  }
}
static void
mtev_cluster_check_timeouts(void) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

  struct timeval now;
  mtev_gettimeofday (&now, NULL);

  while(mtev_hash_adv(&global_clusters, &iter)) {
    mtev_cluster_check_timeout(iter.value.ptr, now);
  }
}

static int
mtev_cluster_info_compose(void *payload, int len, void *c) {
  hb_payload_t *hb_payload;

  mtev_cluster_check_timeouts();

  MEMWRITE_DECL(payload, len);
  uint64_t packed_time;
  uint64_t my_seq;
  mtev_cluster_t *cluster = c;
  mtev_hash_iter payload_iter = MTEV_HASH_ITER_ZERO;
  mtev_hash_iter payload_iter2 = MTEV_HASH_ITER_ZERO;
  uint8_t number_of_payloads;

  number_of_payloads = mtev_hash_size(&cluster->hb_payloads);

  /* payload about the local cluster goes here */
  /* The header is always the same: <version:4><understood_version:4><uuid:128><boottime_sec:40><boottiime_usec:24><seq:64><number_of_payloads:8> */
  MEMWRITE(&HEARTBEAT_MESSAGE_VERSION_AND_UNDERSTOOD, 1);
  MEMWRITE(my_cluster_id, UUID_SIZE);
  packed_time = (my_boot_time.tv_sec & 0x000000ffffffffffULL) << 24; /* 5 bytes << 3 bytes */
  packed_time |= (my_boot_time.tv_usec & 0xffffff); /* 3 bytes */
  packed_time = htonll(packed_time);
  MEMWRITE(&packed_time, sizeof(packed_time));
  my_seq = htonll(cluster->config_seq);
  MEMWRITE(&my_seq, sizeof(my_seq));
  MEMWRITE(&number_of_payloads, 1);

  assert(HEART_BEAT_HDR_LEN == MEMWRITE_WRITTEN);

  if(number_of_payloads != 0) {
    // write header (pointer table)
    while(mtev_hash_adv(&cluster->hb_payloads, &payload_iter)) {
      hb_payload = payload_iter.value.ptr;
      MEMWRITE(&hb_payload->app_id, 1);
      MEMWRITE(&hb_payload->key, 1);
      MEMWRITE(&hb_payload->data_len, 1);
    }
    // write payload
    while(mtev_hash_adv(&cluster->hb_payloads, &payload_iter2)) {
      hb_payload = payload_iter2.value.ptr;
      MEMWRITE(hb_payload->data, hb_payload->data_len);
    }
  }

  /* TODO: Support registered composers */
  return MEMWRITE_WRITTEN;
}
static mtev_boolean
mtev_cluster_store_payload(mtev_cluster_node_t *node, const void* payload, uint16_t payload_length, uint8_t number_of_payloads) {
  assert(payload != NULL);
  node->number_of_payloads = number_of_payloads;
  if(node->payload && node->payload_length < payload_length) {
    node->payload = realloc(node->payload, payload_length);
  } else if(node->payload == NULL) {
    node->payload = calloc(1,payload_length);
  }
  if(node->payload == NULL || payload == NULL) {
    return mtev_false;
  }
  node->payload_length = payload_length;
  memcpy(node->payload, payload, payload_length);

  return mtev_true;
}
static int
mtev_cluster_info_process(void *msg, int len, void *c) {
  uint8_t version;
  uint8_t understood_version;
  mtev_cluster_node_t *sender;
  MEMREAD_DECL(msg, len);
  mtev_cluster_t *cluster = c;
  uuid_t nodeid;
  struct timeval boot_time;
  uint64_t packed_time;
  uint64_t seq;
  void* payload = NULL;
  uint8_t number_of_payloads;
  uint16_t payload_len;
  mtev_boolean node_changed = mtev_false;
  mtev_cluster_node_changes_t node_changes = 0;

  /* messages from other cluster members (including me) arrive here */
  MEMREAD(&version, 1);
  understood_version = version & 0x0F;
  version = version >> 4;
  MEMREAD(nodeid, UUID_SIZE);
  MEMREAD(&packed_time, sizeof(packed_time));
  packed_time = ntohll(packed_time);
  boot_time.tv_sec = ((packed_time >> 24) & 0x000000ffffffffffULL);
  boot_time.tv_usec = (packed_time & 0xffffff);
  MEMREAD(&seq, sizeof(seq));
  seq = ntohll(seq);
  MEMREAD(&number_of_payloads, 1);

  payload_len = len-MEMREAD_BYTES_READ;
  MEMGET(payload, payload_len);

  // We currently support only one version
  if(understood_version < HEARTBEAT_MESSAGE_VERSION) {
    mtevL(cerror, "Received a cluster heartbeat message with an incompatible understood_version (%d)\n", understood_version);
    return 0;
  }

  if(version != HEARTBEAT_MESSAGE_VERSION) {
    mtevL(cerror, "Received a cluster heartbeat message with an incompatible header version (%d)\n", version);
    return 0;
  }

  /* Update our perspective */
  sender = mtev_cluster_find_node(cluster, nodeid);
  if(sender) {

    if(compare_timeval(sender->boot_time, boot_time) != 0) {
      node_changed = mtev_true;
      node_changes = MTEV_CLUSTER_NODE_REBOOTED;
    } else {
      if(seq != sender->config_seq) {
        node_changed = mtev_true;
        node_changes = MTEV_CLUSTER_NODE_CHANGED_SEQ;
      }
      if(payload_len != sender->payload_length
          || memcmp(payload, sender->payload, payload_len) != 0) {
        node_changed = mtev_true;
        node_changes |= MTEV_CLUSTER_NODE_CHANGED_PAYLOAD;
      }
    }

    if(node_changed) {
      mtev_cluster_store_payload(sender, payload, payload_len, number_of_payloads);
      mtev_cluster_on_node_changed(cluster, sender, &boot_time, seq, node_changes);
    }
    mtev_gettimeofday(&sender->last_contact, NULL);
  }
  return 0;
}
#undef MEMWRITE
#undef MEMREAD
static void
mtev_cluster_announce(mtev_cluster_t *cluster) {
  int i;
  unsigned char key[32] = { 0 };
  strlcpy((char *)key, cluster->key, sizeof(key));
  cluster->hbctx = mtev_net_heartbeat_context_create(cluster->port, key, cluster->period);
  if(!cluster->hbctx) {
    mtevL(cerror, "cluster '%s' cannot heartbeat\n", cluster->name);
    return;
  }
  for(i=0;i<cluster->node_cnt;i++) {
    union {
      struct sockaddr_in a4;
      struct sockaddr_in6 a6;
    } a;
    socklen_t alen;
    alen = cluster->nodes[i].address_len;
    memcpy(&a, &cluster->nodes[i].addr, sizeof(cluster->nodes[i].addr));
    mtev_net_heartbeat_add_target(cluster->hbctx, (struct sockaddr *) &a, alen);
  }
  mtev_net_heartbeat_set_out(cluster->hbctx, mtev_cluster_info_compose, cluster);
  mtev_net_heartbeat_set_in(cluster->hbctx, mtev_cluster_info_process, cluster);
  mtev_net_heartbeat_context_start(cluster->hbctx);
}

static void
mtev_cluster_compile(mtev_cluster_t *cluster) {
  int i;
  mtev_cht_node_t *nodes;

  if(cluster->cht) mtev_memory_safe_free(cluster->cht);
  if(cluster->node_cnt == 0) {
    cluster->cht = NULL;
    return;
  }
  cluster->cht =
    mtev_memory_safe_malloc_cleanup(sizeof(*cluster->cht),
                                    deferred_cht_free);
  *(cluster->cht) = mtev_cht_alloc();
  nodes = calloc(sizeof(*nodes), cluster->node_cnt);
  for(i=0; i<cluster->node_cnt; i++) {
    char uuid_str[UUID_STR_LEN+1];
    mtev_uuid_unparse_lower(cluster->nodes[i].id, uuid_str);
    nodes[i].name = strdup(uuid_str);
    nodes[i].userdata = &cluster->nodes[i];
  }
  mtev_cht_set_nodes(*(cluster->cht), cluster->node_cnt, nodes);
}

static int
mtev_cluster_write_config(mtev_cluster_t *cluster) {
  int i;
  char xpath_search[256], new_seq_str[32];
  char port[6], period[8], timeout[8], maturity[8];
  xmlNodePtr container = NULL, parent = NULL;
  mtev_conf_section_t n;
  n = mtev_conf_get_section(MTEV_CONF_ROOT, "//clusters");
  if(mtev_conf_section_is_empty(n)) {
    mtevL(cerror, "Cluster config attempted with no 'clusters' section.\n");
    mtev_conf_release_section(n);
    return 0;
  }
  mtev_conf_release_section(n);
  snprintf(xpath_search, sizeof(xpath_search), "//clusters//cluster[@name=\"%s\"]",
           cluster->name);
  n = mtev_conf_get_section(MTEV_CONF_ROOT, xpath_search);
  parent = mtev_conf_section_to_xmlnodeptr(n);
  if(parent) {
    // clear existing configuration
    xmlNodePtr child;
    xmlUnsetProp(parent, (xmlChar *)"name");
    xmlUnsetProp(parent, (xmlChar *)"port");
    xmlUnsetProp(parent, (xmlChar *)"period");
    xmlUnsetProp(parent, (xmlChar *)"timeout");
    xmlUnsetProp(parent, (xmlChar *)"maturity");
    xmlUnsetProp(parent, (xmlChar *)"key");
    xmlUnsetProp(parent, (xmlChar *)"seq");
    while(NULL != (child = parent->children)) {
      xmlUnlinkNode(child);
      xmlFreeNode(child);
    }
  }
  else {
    // create new node
    n = mtev_conf_get_section(MTEV_CONF_ROOT, "//clusters");
    container = mtev_conf_section_to_xmlnodeptr(n);
    parent = xmlNewNode(NULL, (xmlChar *)"cluster");
  }
  xmlSetProp(parent, (xmlChar *)"name", (xmlChar *)cluster->name);
  snprintf(port, sizeof(port), "%d", cluster->port);
  xmlSetProp(parent, (xmlChar *)"port", (xmlChar *)port);
  snprintf(period, sizeof(period), "%d", cluster->period);
  xmlSetProp(parent, (xmlChar *)"period", (xmlChar *)period);
  snprintf(timeout, sizeof(timeout), "%d", cluster->timeout);
  xmlSetProp(parent, (xmlChar *)"timeout", (xmlChar *)timeout);
  snprintf(maturity, sizeof(maturity), "%d", cluster->maturity);
  xmlSetProp(parent, (xmlChar *)"maturity", (xmlChar *)maturity);
  xmlSetProp(parent, (xmlChar *)"key", (xmlChar *)cluster->key);
  snprintf(new_seq_str, sizeof(new_seq_str), "%"PRId64, cluster->config_seq);
  xmlSetProp(parent, (xmlChar *)"seq", (xmlChar *)new_seq_str);
  if(cluster->node_cnt > 0) mtevAssert(cluster->nodes);
  for(i=0;i<cluster->node_cnt;i++) {
    xmlNodePtr node;
    char uuid_str[UUID_STR_LEN+1], port[6], ipstr[INET6_ADDRSTRLEN];
    node = xmlNewNode(NULL, (xmlChar *)"node");
    mtev_uuid_unparse_lower(cluster->nodes[i].id, uuid_str);
    xmlSetProp(node, (xmlChar *)"id", (xmlChar *)uuid_str);
    xmlSetProp(node, (xmlChar *)"cn", (xmlChar *)cluster->nodes[i].cn);
    if(cluster->nodes[i].addr.addr4.sin_family == AF_INET) {
      inet_ntop(AF_INET, &cluster->nodes[i].addr.addr4.sin_addr,
                ipstr, sizeof(ipstr));
      xmlSetProp(node, (xmlChar *)"address", (xmlChar *)ipstr);
      snprintf(port, sizeof(port), "%d", ntohs(cluster->nodes[i].addr.addr4.sin_port));
      xmlSetProp(node, (xmlChar *)"port", (xmlChar *)port);
    }
    else if(cluster->nodes[i].addr.addr6.sin6_family == AF_INET6) {
      inet_ntop(AF_INET6, &cluster->nodes[i].addr.addr6.sin6_addr,
                ipstr, sizeof(ipstr));
      xmlSetProp(node, (xmlChar *)"address", (xmlChar *)ipstr);
      snprintf(port, sizeof(port), "%d", ntohs(cluster->nodes[i].addr.addr6.sin6_port));
      xmlSetProp(node, (xmlChar *)"port", (xmlChar *)port);
    }
    xmlAddChild(parent, node);
  }
  if(container) xmlAddChild(container, parent);
  CONF_DIRTY(n);
  mtev_conf_mark_changed();
  mtev_conf_request_write();
  mtev_conf_release_section(n);

  return 1;
}

int mtev_cluster_update_internal(mtev_conf_section_t cluster) {
  int rv = -1, i, n_nodes = 0, port, period, timeout, maturity;
  int64_t seq;
  char bufstr[1024];
  mtev_conf_section_t *nodes = NULL;
  char *name = NULL, *key = NULL, *endptr;
  void *vcluster;
  mtev_cluster_t *new_cluster = NULL;
  mtev_cluster_node_t *nlist = NULL;

  if(!mtev_conf_get_stringbuf(cluster, "@name", bufstr, sizeof(bufstr))) {
    mtevL(cerror, "Cluster has no name, skipping.\n");
    goto bail;
  }
  name = mtev_memory_safe_strdup(bufstr);

  if(!mtev_conf_get_stringbuf(cluster, "@key", bufstr, sizeof(bufstr))) {
    mtevL(cerror, "Cluster has no key, skipping.\n");
    goto bail;
  }
  key = mtev_memory_safe_strdup(bufstr);

  if(!mtev_conf_get_stringbuf(cluster, "@seq", bufstr, sizeof(bufstr)) ||
     bufstr[0] == '\0') {
    mtevL(cerror, "Cluster '%s' has no seq, skipping.\n", name);
    goto bail;
  }
  seq = strtoll(bufstr, &endptr, 10);
  if(*endptr) {
    mtevL(cerror, "Cluster '%s' seq invalid.\n", name);
    goto bail;
  }

  if(!mtev_conf_get_stringbuf(cluster, "@port", bufstr, sizeof(bufstr)) ||
     bufstr[0] == '\0') {
    mtevL(cerror, "Cluster '%s' has no port, skipping.\n", name);
    goto bail;
  }
  port = strtoll(bufstr, &endptr, 10);
  if(*endptr || port <= 0 || port > 0xffff) {
    mtevL(cerror, "Cluster '%s' port invalid.\n", name);
    goto bail;
  }

  if(!mtev_conf_get_stringbuf(cluster, "@period", bufstr, sizeof(bufstr)) ||
     bufstr[0] == '\0') {
     strlcpy(bufstr, "200", sizeof(bufstr));
  }
  period = strtoll(bufstr, &endptr, 10);
  if(*endptr || period < 0 || period > 5000) {
    mtevL(cerror, "Cluster '%s' period invalid.\n", name);
    goto bail;
  }

  if(!mtev_conf_get_stringbuf(cluster, "@timeout", bufstr, sizeof(bufstr)) ||
     bufstr[0] == '\0') {
     strlcpy(bufstr, "5000", sizeof(bufstr));
  }
  timeout = strtoll(bufstr, &endptr, 10);
  if(*endptr || timeout < period) {
    mtevL(cerror, "Cluster '%s' timeout invalid.\n", name);
    goto bail;
  }

  if(!mtev_conf_get_stringbuf(cluster, "@maturity", bufstr, sizeof(bufstr)) ||
     bufstr[0] == '\0') {
     maturity = timeout;
  } else {
    maturity = strtoll(bufstr, &endptr, 10);
    if(*endptr || maturity < 0) {
      mtevL(cerror, "Cluster '%s' maturity invalid.\n", name);
      goto bail;
    }
  }

  nodes = mtev_conf_get_sections(cluster, "node", &n_nodes);
  if(n_nodes > 0) {
    nlist = mtev_memory_safe_calloc(n_nodes, sizeof(*nlist));
    for(i=0;i<n_nodes;i++) {
      int family;
      int32_t port;
      union {
        struct in_addr addr4;
        struct in6_addr addr6;
      } a;
      char uuid_str[UUID_STR_LEN+1];

      if(!mtev_conf_get_stringbuf(nodes[i], "@id", uuid_str, sizeof(uuid_str)) ||
         mtev_uuid_parse(uuid_str, nlist[i].id) != 0) {
        mtevL(cerror, "Cluster '%s' node %d has no (or bad) id\n", name, i);
        goto bail;
      }
      if(!mtev_conf_get_stringbuf(nodes[i], "@cn",
        nlist[i].cn, sizeof(nlist[i].cn))) {
        mtevL(cerror, "Cluster '%s' node %d has no cn\n", name, i);
        goto bail;
      }
      if(!mtev_conf_get_int32(nodes[i], "@port", &port) || port < 0 || port > 0xffff) {
        mtevL(cerror, "Cluster '%s' node %d has no (or bad) port\n", name, i);
        goto bail;
      }
      if(!mtev_conf_get_stringbuf(nodes[i], "@address", bufstr, sizeof(bufstr))) {
        mtevL(cerror, "Cluster '%s' node %d has no address\n", name, i);
        goto bail;
      }

      family = AF_INET;
      rv = inet_pton(family, bufstr, &a);
      if(rv != 1) {
        family = AF_INET6;
        rv = inet_pton(family, bufstr, &a);
        if(rv != 1) {
          mtevL(cerror, "Cluster '%s' node '%s' has bad address '%s'\n",
                name, uuid_str, bufstr);
          goto bail;
        }
        else {
          nlist[i].addr.addr6.sin6_family = AF_INET6;
          nlist[i].addr.addr6.sin6_addr = a.addr6;
          nlist[i].addr.addr6.sin6_port = htons((unsigned short)port);
          nlist[i].address_len = sizeof(nlist[i].addr.addr6);
        }
      }
      else {
        nlist[i].addr.addr4.sin_family = AF_INET;
        nlist[i].addr.addr4.sin_addr = a.addr4;
        nlist[i].addr.addr4.sin_port = htons((unsigned short)port);
        nlist[i].address_len = sizeof(nlist[i].addr.addr4);
      }
    }
  }

  new_cluster = mtev_memory_safe_calloc(1, sizeof(*new_cluster));
  new_cluster->name = name; name = NULL;
  new_cluster->key = key; key = NULL;
  new_cluster->config_seq = seq;
  new_cluster->port = port;
  new_cluster->period = period;
  new_cluster->timeout = timeout;
  new_cluster->maturity = maturity;
  if (nlist != NULL) {
    qsort(nlist, n_nodes, sizeof(*nlist), mtev_cluster_node_compare);
  }
  for(i=0; i<n_nodes; i++) nlist[i].idx = i;
  new_cluster->node_cnt = n_nodes;
  new_cluster->nodes = nlist; nlist = NULL;
  mtev_hash_init_locks(&new_cluster->hb_payloads, 8, MTEV_HASH_LOCK_MODE_NONE);

  pthread_mutex_lock(&c_lock);
  if(mtev_hash_retrieve(&global_clusters,
                        new_cluster->name, strlen(new_cluster->name),
                        &vcluster)) {
    // have a cluster of the same name
    mtev_cluster_t *old_cluster = NULL;
    old_cluster = vcluster;
    rv = 1;
    if(new_cluster->config_seq <= old_cluster->config_seq) {
      /* This is considered a successful update. We have something more recent */
      mtevL(cdebug, "Not applying config. Cluster '%s' is too old.\n", new_cluster->name);
      rv = 2;
      pthread_mutex_unlock(&c_lock);
      goto bail;
    }
    if(!mtev_cluster_write_config(new_cluster)) {
      mtevL(cerror, "Cluster '%s', failed to write to config.\n",
            new_cluster->name);
      rv = -1;
      pthread_mutex_unlock(&c_lock);
      goto bail;
    }
    mtev_cluster_compile(new_cluster);
    mtev_cluster_announce(new_cluster);
    mtev_hash_replace(&global_clusters,
                      new_cluster->name, strlen(new_cluster->name),
                      new_cluster, NULL, mtev_cluster_free);
    mtevL(cdebug, "Updated existing cluster '%s'.\n", new_cluster->name);
  }
  else {
    // new cluster
    if(!mtev_cluster_write_config(new_cluster)) {
      mtevL(cerror, "Cluster '%s', failed to write to config.\n",
            new_cluster->name);
      rv = -1;
      pthread_mutex_unlock(&c_lock);
      goto bail;
    }
    mtev_cluster_compile(new_cluster);
    mtev_cluster_announce(new_cluster);
    mtev_hash_store(&global_clusters,
                    new_cluster->name, strlen(new_cluster->name),
                    new_cluster);
    mtevL(cdebug, "Cluster '%s' loaded\n", new_cluster->name);
    rv = 0;
  }
  new_cluster = NULL;
  pthread_mutex_unlock(&c_lock);

 bail:
  mtev_conf_release_sections(nodes, n_nodes);
  if(name) mtev_memory_safe_free(name);
  if(key) mtev_memory_safe_free(key);
  if(new_cluster) mtev_memory_safe_free(new_cluster);
  if(nlist) mtev_memory_safe_free(nlist);
  return rv;
}

int
mtev_cluster_update(mtev_conf_section_t cluster) {
  return mtev_cluster_update_internal(cluster);
}

mtev_cluster_t *
mtev_cluster_by_name(const char *name) {
  void *vc;
  if(mtev_hash_retrieve(&global_clusters, name, strlen(name), &vc))
    return (mtev_cluster_t *)vc;
  return NULL;
}

int
mtev_cluster_size(mtev_cluster_t *c) {
  return c ? c->node_cnt : 0;
}

int
mtev_cluster_set_self(uuid_t id) {
  char old_uuid[UUID_STR_LEN+1],
       my_id_str[UUID_STR_LEN+1];
  mtev_conf_section_t c;
  c = mtev_conf_get_section(MTEV_CONF_ROOT, "//clusters");
  if(!have_clusters || mtev_conf_section_is_empty(c)) {
    mtevL(cerror, "Trying to set //clusters/@my_id but no clusters section is found.\n");
    mtev_conf_release_section(c);
    return -1;
  }
  mtev_uuid_copy(my_cluster_id, id);
  mtev_uuid_unparse_lower(my_cluster_id, my_id_str);
  xmlNodePtr cnode = mtev_conf_section_to_xmlnodeptr(c);
  if(!mtev_conf_get_stringbuf(MTEV_CONF_ROOT, "//clusters/@my_id",
                              old_uuid, sizeof(old_uuid)) ||
     strcmp(old_uuid, my_id_str)) {
    mtevL(cdebug, "Setting //clusters/@my_id to %s\n", my_id_str);
    xmlUnsetProp(cnode, (xmlChar *)"my_id");
    xmlSetProp(cnode, (xmlChar *)"my_id", (xmlChar *)my_id_str);
    CONF_DIRTY(c);
    mtev_conf_mark_changed();
    mtev_conf_request_write();
  }
  mtev_conf_release_section(c);
  return 0;
}

void
mtev_cluster_get_self(uuid_t id) {
  mtev_uuid_copy(id, my_cluster_id);
}

mtev_boolean
mtev_cluster_is_that_me(mtev_cluster_node_t *node) {
  if (node == NULL)
    return mtev_false;
  return mtev_uuid_compare(node->id, my_cluster_id) == 0;
}

mtev_cluster_node_t *
mtev_cluster_get_node(mtev_cluster_t *c, uuid_t id) {
  int i;
  for(i=0; i<c->node_cnt; i++) {
    if(mtev_uuid_compare(c->nodes[i].id, id) == 0) return &c->nodes[i];
  }
  return NULL;
}
int
mtev_cluster_get_nodes(mtev_cluster_t *c,
                       mtev_cluster_node_t **nodes, int n,
                       mtev_boolean includeme) {
  int i, o = 0;
  if(!c) return 0;
  if(n < c->node_cnt) return -(c->node_cnt);
  for(i=0;i<n && i<c->node_cnt; i++) {
    if(includeme || mtev_uuid_compare(c->nodes[i].id, my_cluster_id)) {
      nodes[o++] = &c->nodes[i];
    }
  }
  return o;
}

mtev_boolean
mtev_cluster_do_i_own(mtev_cluster_t *c, void *key, size_t klen, int w) {
  int i, wout;
  mtev_cht_node_t **owners;
  if(!c || !c->cht || !(*(c->cht))) return mtev_false;
  if(w < 0) w = 1;
  if(w > c->node_cnt) w = c->node_cnt;
  owners = malloc(sizeof(*owners) * c->node_cnt);
  wout = mtev_cht_vlookup_n(*(c->cht), key, klen, w, owners);
  for(i=0; i<wout; i++) {
    mtev_cluster_node_t *node;
    node = owners[i]->userdata;
    if(mtev_uuid_compare(node->id, my_cluster_id) == 0) {
      free(owners);
      return mtev_true;
    }
  }
  free(owners);
  return mtev_false;
}

mtev_boolean
mtev_cluster_alive_filter(mtev_cluster_node_t *node, mtev_boolean me, void *closure) {
  (void)me;
  (void)closure;
  return !mtev_cluster_node_is_dead(node);
}

mtev_boolean
mtev_cluster_filter_owners(mtev_cluster_t *c, void *key, size_t klen,
                           mtev_cluster_node_t **set, int *w,
                           mtev_cluster_node_filter_func_t filter,
                           void *closure) {
  int j = 0, i, wout;
  mtev_cht_node_t **owners;
  if(!c || !c->cht || !(*(c->cht))) return mtev_false;
  if(*w < 1) return false;
  if(*w > c->node_cnt) *w = c->node_cnt;
  owners = malloc(sizeof(*owners) * c->node_cnt);
  wout = mtev_cht_vlookup_n(*(c->cht), key, klen, *w, owners);
  for(i=0; i<wout; i++) {
    mtev_cluster_node_t *node;
    node = owners[i]->userdata;
    if(filter(node, mtev_uuid_compare(node->id, my_cluster_id) == 0, closure)) {
      set[j++] = node;
    }
  }
  free(owners);
  *w = j;
  if(*w <= 0) return mtev_false;
  if(mtev_uuid_compare(set[0]->id, my_cluster_id) == 0) return mtev_true;
  return mtev_false;
}

mtev_boolean
mtev_cluster_set_heartbeat_payload(mtev_cluster_t *cluster,
    uint8_t app_id, uint8_t key, void *payload, uint8_t payload_length) {
  assert(payload);

  unsigned int payload_len_sum = 0;
  hb_payload_t *hb_payload, *old_payload = NULL;
  uint16_t *hash_key = calloc(1,sizeof(uint16_t));
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

  *hash_key = (app_id << 8) | key;

  while(mtev_hash_adv(&cluster->hb_payloads, &iter)) {
    hb_payload = iter.value.ptr;
    if(hb_payload->app_id != app_id || hb_payload->key != key) {
      payload_len_sum += hb_payload->data_len;
    } else {
      old_payload = iter.value.ptr;
    }
  }

  if(payload_len_sum + payload_length > MAX_PAYLOAD_LEN_SUM) {
    free(hash_key);
    return mtev_false;
  }

  if(old_payload == NULL) {
    hb_payload = calloc(1, sizeof(hb_payload_t) + sizeof(payload));
    hb_payload->app_id = app_id;
    hb_payload->key = key;
  } else {
    hb_payload = old_payload;
  }

  hb_payload->data_len = payload_length;
  hb_payload->data = payload;

  return mtev_hash_replace(&cluster->hb_payloads, (const char*)hash_key, sizeof(*hash_key),
      hb_payload, free, NULL);
}


mtev_boolean
mtev_cluster_unset_heartbeat_payload(mtev_cluster_t *cluster,
    uint8_t app_id, uint8_t key) {
  uint16_t hash_key = (app_id << 8) | key;
  return mtev_hash_delete(&cluster->hb_payloads, (const char*)&hash_key, sizeof(hash_key),
                       free, free);
}

int
mtev_cluster_get_heartbeat_payload(mtev_cluster_node_t *node, uint8_t app_id,
    uint8_t key, void **payload) {
  hb_payload_hdr_t *hdr;
  int payload_len_sum =  0;
  if(node == NULL || node->payload == NULL) {
    return -1;
  }

  hdr = node->payload;

  while(payload_len_sum < node->payload_length) {
    if(hdr->app_id == app_id && hdr->key == key) {
      *payload = node->payload + node->number_of_payloads * sizeof(hb_payload_hdr_t) + payload_len_sum;
      return hdr->data_len;
    }
    ++hdr;
    payload_len_sum += hdr->data_len ;
  }

  return -1;
}

const char *
mtev_cluster_get_name(mtev_cluster_t *cluster) {
  return cluster->name;
}

int64_t
mtev_cluster_get_config_seq(mtev_cluster_t *cluster) {
  return cluster->config_seq;
}

static struct json_object *
mtev_cluster_to_json(mtev_cluster_t *c) {
  struct json_object *obj, *nodes;
  struct timeval now;
  obj = MJ_OBJ();
  int i;

  mtev_gettimeofday(&now, NULL);


  MJ_KV(obj, "name", MJ_STR(c->name));
  MJ_KV(obj, "seq", MJ_INT64(c->config_seq));
  MJ_KV(obj, "port", MJ_INT(c->port));
  MJ_KV(obj, "period", MJ_INT(c->period));
  MJ_KV(obj, "timeout", MJ_INT(c->timeout));
  MJ_KV(obj, "maturity", MJ_INT(c->maturity));

  char uuid_str[UUID_STR_LEN+1];
  if(c->oldest_node && !mtev_uuid_is_null(c->oldest_node->id)) {
    mtev_uuid_unparse_lower(c->oldest_node->id, uuid_str);
    MJ_KV(obj, "oldest_node", MJ_STR(uuid_str));
  }

  MJ_KV(obj, "nodes", (nodes = MJ_ARR()));
  for(i=0;i<c->node_cnt;i++) {
    mtev_cluster_node_t *n = &c->nodes[i];
    struct json_object *node;
    char uuid_str[UUID_STR_LEN+1], ipstr[INET6_ADDRSTRLEN];
    node = MJ_OBJ();
    mtev_uuid_unparse_lower(n->id, uuid_str);
    MJ_KV(node, "id", MJ_STR(uuid_str));
    MJ_KV(node, "cn", MJ_STR(n->cn));
    MJ_KV(node, "reference_time", MJ_UINT64(now.tv_sec));
    MJ_KV(node, "last_contact", MJ_UINT64(n->last_contact.tv_sec));
    MJ_KV(node, "boot_time", MJ_UINT64(n->boot_time.tv_sec));

    if(n->addr.addr4.sin_family == AF_INET) {
      inet_ntop(AF_INET, &n->addr.addr4.sin_addr,
                ipstr, sizeof(ipstr));
      MJ_KV(node, "address", MJ_STR(ipstr));
      MJ_KV(node, "port", MJ_INT(ntohs(n->addr.addr4.sin_port)));
    }
    else if(n->addr.addr6.sin6_family == AF_INET6) {
      inet_ntop(AF_INET6, &n->addr.addr6.sin6_addr,
                ipstr, sizeof(ipstr));
      MJ_KV(node, "address", MJ_STR(ipstr));
      MJ_KV(node, "port", MJ_INT(ntohs(n->addr.addr6.sin6_port)));
    }
    MJ_KV(node, "dead", MJ_BOOL(mtev_cluster_node_is_dead(n)));
    MJ_ADD(nodes, node);
  }
  return obj;
}

static int
rest_show_cluster_json(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  struct json_object *doc = NULL, *obj;

  doc = MJ_OBJ();

  if(!mtev_uuid_is_null(my_cluster_id)) {
    char uuid_str[UUID_STR_LEN+1];
    mtev_uuid_unparse_lower(my_cluster_id, uuid_str);
    MJ_KV(doc, "my_id", MJ_STR((const char *)uuid_str));
  }

  if(n >= 2 && strlen(p[1])) {
    mtev_cluster_t *c = mtev_cluster_by_name(p[1]);
    if(!c) goto notfound;
    obj = MJ_OBJ();
    MJ_KV(obj, c->name, mtev_cluster_to_json(c));
    MJ_KV(doc, "clusters", obj);
  }
  else {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    obj = MJ_OBJ();
    while(mtev_hash_adv(&global_clusters, &iter)) {
      mtev_cluster_t *c = (mtev_cluster_t *)iter.value.ptr;
      MJ_KV(obj, c->name, mtev_cluster_to_json(c));
    }
    MJ_KV(doc, "clusters", obj);
  }
  mtev_http_response_standard(ctx, 200, "OK", "application/json");
  mtev_http_response_append_json(ctx, doc);
  mtev_http_response_end(ctx);
  goto cleanup;

 notfound:
  mtev_http_response_standard(ctx, 404, "ERROR", "application/json");
  mtev_http_response_end(ctx);
  goto cleanup;

 cleanup:
  MJ_DROP(doc);
  return 0;
}

static xmlNodePtr
mtev_cluster_to_xmlnode(mtev_cluster_t *c) {
  int i;
  char str[32], port[6], period[8], timeout[8], maturity[8];
  xmlNodePtr cluster;
  cluster = xmlNewNode(NULL, (xmlChar *)"cluster");
  xmlSetProp(cluster, (xmlChar *)"name", (xmlChar *)c->name);
  snprintf(str, sizeof(str), "%"PRId64, c->config_seq);
  xmlSetProp(cluster, (xmlChar *)"seq", (xmlChar *)str);
  snprintf(port, sizeof(port), "%d", c->port);
  xmlSetProp(cluster, (xmlChar *)"port", (xmlChar *)port);
  snprintf(period, sizeof(period), "%d", c->period);
  xmlSetProp(cluster, (xmlChar *)"period", (xmlChar *)period);
  snprintf(timeout, sizeof(timeout), "%d", c->timeout);
  xmlSetProp(cluster, (xmlChar *)"timeout", (xmlChar *)timeout);
  snprintf(maturity, sizeof(maturity), "%d", c->maturity);
  xmlSetProp(cluster, (xmlChar *)"maturity", (xmlChar *)maturity);

  if(c->oldest_node && !mtev_uuid_is_null(c->oldest_node->id)) {
    xmlNodePtr node;
    char uuid_str[UUID_STR_LEN+1];
    mtev_uuid_unparse_lower(c->oldest_node->id, uuid_str);
    node = xmlNewNode(NULL, (xmlChar *)"oldest_node");
    xmlSetProp(node, (xmlChar *)"uuid", (xmlChar *)uuid_str);
    xmlAddChild(cluster, node);
  }

  for(i=0;i<c->node_cnt;i++) {
    mtev_cluster_node_t *n = &c->nodes[i];
    xmlNodePtr node;
    char uuid_str[UUID_STR_LEN+1], port[6], ipstr[INET6_ADDRSTRLEN], time[11];
    node = xmlNewNode(NULL, (xmlChar *)"node");
    mtev_uuid_unparse_lower(n->id, uuid_str);
    xmlSetProp(node, (xmlChar *)"id", (xmlChar *)uuid_str);
    xmlSetProp(node, (xmlChar *)"cn", (xmlChar *)n->cn);

    snprintf(time, sizeof(time), "%lu", (unsigned long)n->last_contact.tv_sec);
    xmlSetProp(node, (xmlChar *)"last_contact", (xmlChar *)time);
    snprintf(time, sizeof(time), "%lu", (unsigned long)n->boot_time.tv_sec);
    xmlSetProp(node, (xmlChar *)"boot_time", (xmlChar *)time);

    if(n->addr.addr4.sin_family == AF_INET) {
      inet_ntop(AF_INET, &n->addr.addr4.sin_addr,
                ipstr, sizeof(ipstr));
      xmlSetProp(node, (xmlChar *)"address", (xmlChar *)ipstr);
      snprintf(port, sizeof(port), "%d", ntohs(n->addr.addr4.sin_port));
      xmlSetProp(node, (xmlChar *)"port", (xmlChar *)port);
    }
    else if(n->addr.addr6.sin6_family == AF_INET6) {
      inet_ntop(AF_INET6, &n->addr.addr6.sin6_addr,
                ipstr, sizeof(ipstr));
      xmlSetProp(node, (xmlChar *)"address", (xmlChar *)ipstr);
      snprintf(port, sizeof(port), "%d", ntohs(n->addr.addr6.sin6_port));
      xmlSetProp(node, (xmlChar *)"port", (xmlChar *)port);
    }
    xmlAddChild(cluster, node);
  }
  return cluster;
}

#define FAIL(a) do { error = (a); goto error; } while(0)

static int
rest_show_cluster(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  xmlDocPtr doc;
  xmlNodePtr root;

  if(n == 3 && !strcmp(p[2], ".json"))
    return  rest_show_cluster_json(restc, n, p);

  doc = xmlNewDoc((xmlChar *)"1.0");
  root = xmlNewDocNode(doc, NULL, (xmlChar *)"clusters", NULL);
  xmlDocSetRootElement(doc, root);

  if (!mtev_uuid_is_null(my_cluster_id)) {
    char uuid_str[UUID_STR_LEN+1];
    mtev_uuid_unparse_lower(my_cluster_id, uuid_str);
    xmlSetProp(root, (xmlChar *)"my_id", (xmlChar *)uuid_str);
  }

  if(n >= 2) {
    mtev_cluster_t *c = mtev_cluster_by_name(p[1]);
    if(!c) goto notfound;
    xmlAddChild(root, mtev_cluster_to_xmlnode(c));
  }
  else {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    while(mtev_hash_adv(&global_clusters, &iter)) {
      xmlAddChild(root, mtev_cluster_to_xmlnode((mtev_cluster_t *)iter.value.ptr));
    }
  }
  mtev_http_response_standard(ctx, 200, "OK", "text/xml");
  mtev_http_response_xml(ctx, doc);
  mtev_http_response_end(ctx);
  goto cleanup;

 notfound:
  mtev_http_response_standard(ctx, 404, "ERROR", "text/xml");
  mtev_http_response_end(ctx);
  goto cleanup;

 cleanup:
  if(doc) xmlFreeDoc(doc);
  return 0;
}

static int
rest_update_cluster(mtev_http_rest_closure_t *restc, int n, char **p) {
  (void)n;
  (void)p;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  const char *error = "internal error";
  int complete = 0, mask = 0, error_code = 500, status;
  xmlDocPtr indoc, doc;
  xmlNodePtr root;

  indoc = rest_get_xml_upload(restc, &mask, &complete);
  if(!complete) return mask;
  if(indoc == NULL) FAIL("xml parse error");
  root = xmlDocGetRootElement(indoc);
  if(!root || strcmp((const char *)root->name, "cluster"))
    FAIL("bad root node: not cluster");
  status = mtev_cluster_update_internal(mtev_conf_section_from_xmlnodeptr(root));
  if(status < 0) {
    FAIL("failed to update");
  }
  mtev_http_response_standard(ctx, status == 2 ? 304 : 204, "OK", "none");
  mtev_http_response_end(ctx);
  return 0;

 error:
  mtev_http_response_standard(ctx, error_code, "ERROR", "text/xml");
  doc = xmlNewDoc((xmlChar *)"1.0");
  root = xmlNewDocNode(doc, NULL, (xmlChar *)"error", NULL);
  xmlDocSetRootElement(doc, root);
  xmlNodeAddContent(root, (xmlChar *)error);
  mtev_http_response_xml(ctx, doc);
  mtev_http_response_end(ctx);
  goto cleanup;

 cleanup:
  if(doc) xmlFreeDoc(doc);
  return 0;
}

void
mtev_cluster_init(void) {
  uuid_t my_id;
  char my_id_str[UUID_STR_LEN+1];
  int i, n_clusters;
  mtev_conf_section_t *clusters, parent;

  cerror = mtev_log_stream_find("error/cluster");
  cdebug = mtev_log_stream_find("debug/cluster");

  mtev_net_heartbeat_init();

  mtev_gettimeofday(&my_boot_time, NULL);
  mtev_hash_init_locks(&global_clusters, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);

  parent = mtev_conf_get_section(MTEV_CONF_ROOT, "//clusters");
  if(mtev_conf_section_is_empty(parent)) {
    mtev_conf_release_section(parent);
    return;
  }
  have_clusters = mtev_true;

  // set global cluster id
  if(mtev_conf_get_stringbuf(parent, "@my_id", my_id_str, sizeof(my_id_str))) {
    int rv = mtev_uuid_parse(my_id_str, my_id);
    if (rv != 0) {
      mtevL(cerror, "Invalid cluster configuration: my_id=%s\n", my_id_str);
      mtev_conf_release_section(parent);
      return;
    }
    else {
      mtevL(cdebug,"Found cluster configuration with my_id: %s\n", my_id_str);
      mtev_cluster_set_self(my_id);
    }
  }
  else {
    mtevL(cdebug,"//clusters/@my_id not set. Generating a new one\n");
    mtev_uuid_generate(my_id);
    mtev_cluster_set_self(my_id);
  }

  // register individual clusters
  clusters = mtev_conf_get_sections(MTEV_CONF_ROOT, "//clusters//cluster", &n_clusters);
  for(i=0;i<n_clusters;i++) {
    mtev_cluster_update_internal(clusters[i]);
  }
  mtev_conf_release_sections(clusters, n_clusters);
  mtev_conf_release_section(parent);

  // register REST endpoints
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/", "^cluster(/(..*?))?(\\.json)?$", rest_show_cluster,
             mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "POST", "/", "^cluster$", rest_update_cluster,
             mtev_http_rest_client_cert_auth
  ) == 0);
}
mtev_cluster_node_t*
mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster) {
  if (cluster == NULL) {
    return NULL;
  }
  return cluster->oldest_node;
}

mtev_boolean
mtev_cluster_am_i_oldest_visible_node(const mtev_cluster_t *cluster) {
  if (cluster == NULL || cluster->oldest_node == NULL)
    return mtev_true;
  return mtev_uuid_compare(cluster->oldest_node->id, my_cluster_id) == 0;
}

struct timeval
mtev_cluster_get_my_boot_time(void) {
  return my_boot_time;
}
