/*
 * Copyright (c) 2013-2015, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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

#ifndef MTEV_REVERSE_SOCKET_H
#define MTEV_REVERSE_SOCKET_H

#include "mtev_defines.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "mtev_listener.h"

typedef struct mtev_connection_ctx_t {
  mtev_atomic32_t refcnt;
  union {
    struct sockaddr remote;
    struct sockaddr_un remote_un;
    struct sockaddr_in remote_in;
    struct sockaddr_in6 remote_in6;
  } r;
  socklen_t remote_len;
  char *remote_str;
  char *remote_cn;
  uint32_t current_backoff;
  int wants_shutdown;
  int wants_permanent_shutdown;
  int max_silence;
  mtev_hash_table *config;
  mtev_hash_table *sslconfig;
  mtev_hash_table *tracker;
  pthread_mutex_t *tracker_lock;
  struct timeval last_connect;
  eventer_t timeout_event;
  eventer_t retry_event;
  eventer_t e;

  void (*schedule_reattempt)(struct mtev_connection_ctx_t *, struct timeval *now);
  void (*close)(struct mtev_connection_ctx_t *, eventer_t e);

  eventer_func_t consumer_callback;
  void (*consumer_free)(void *);
  void *consumer_ctx;
} mtev_connection_ctx_t;

typedef enum {
  MTEV_ACL_DENY,
  MTEV_ACL_ALLOW,
  MTEV_ACL_ABSTAIN
} mtev_reverse_acl_decision_t;

typedef mtev_reverse_acl_decision_t (*mtev_reverse_acl_decider_t)(const char *, acceptor_closure_t *);
API_EXPORT(void) mtev_reverse_socket_acl(mtev_reverse_acl_decider_t f);
API_EXPORT(mtev_reverse_acl_decision_t)
  mtev_reverse_socket_denier(const char *id, acceptor_closure_t *ac);

API_EXPORT(void) mtev_reverse_socket_init(const char *p, const char **cn_p);
API_EXPORT(int) mtev_reverse_socket_connect(const char *id, int existing_fd);
API_EXPORT(void) mtev_connection_ctx_ref(mtev_connection_ctx_t *ctx);
API_EXPORT(void) mtev_connection_ctx_deref(mtev_connection_ctx_t *ctx);
API_EXPORT(int)
  mtev_connection_update_timeout(mtev_connection_ctx_t *ctx);
API_EXPORT(int)
  mtev_connection_disable_timeout(mtev_connection_ctx_t *ctx);
API_EXPORT(void)
  mtev_connection_ctx_dealloc(mtev_connection_ctx_t *ctx);
API_EXPORT(int)
  mtev_connections_from_config(mtev_hash_table *tracker, pthread_mutex_t *tracker_lock,
                               const char *toplevel, const char *destination,
                               const char *type,
                               eventer_func_t handler,
                               void *(*handler_alloc)(void), void *handler_ctx,
                               void (*handler_free)(void *));

API_EXPORT(int)
  mtev_lua_help_initiate_mtev_connection(const char *address, int port,
                                         mtev_hash_table *sslconfig,
                                         mtev_hash_table *config);
API_EXPORT(int)
  mtev_reverse_socket_connection_shutdown(const char *address, int port);

API_EXPORT(void)
  mtev_reverse_socket_init_globals();

#endif
