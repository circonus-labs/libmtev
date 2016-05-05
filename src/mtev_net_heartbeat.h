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

#ifndef MTEV_NET_HEARTBEAT
#define MTEV_NET_HEARTBEAT

#include <mtev_defines.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

typedef struct mtev_net_heartbeat_context mtev_net_heartbeat_ctx;

API_EXPORT(void)
  mtev_net_heartbeat_init();

API_EXPORT(mtev_net_heartbeat_ctx *)
  mtev_net_heartbeat_from_conf(const char *basepath);

API_EXPORT(mtev_net_heartbeat_ctx *)
  mtev_net_heartbeat_context_create(unsigned short port,
                                    unsigned char key[32],
                                    int period_ms);

API_EXPORT(void)
  mtev_net_heartbeat_set_out(mtev_net_heartbeat_ctx *ctx,
                             int (*cf)(void *buf, int buflen, void *),
                             void *closure);

API_EXPORT(void)
  mtev_net_heartbeat_set_in(mtev_net_heartbeat_ctx *ctx,
                            int (*pf)(void *buf, int buflen, void *),
                            void *closure);

API_EXPORT(void)
  mtev_net_heartbeat_context_start(mtev_net_heartbeat_ctx *ctx);

API_EXPORT(void)
  mtev_net_heartbeat_destroy(mtev_net_heartbeat_ctx *ctx);

API_EXPORT(int)
  mtev_net_heartbeat_add_target(mtev_net_heartbeat_ctx *, struct sockaddr *, socklen_t);

API_EXPORT(int)
  mtev_net_heartbeat_add_broadcast(mtev_net_heartbeat_ctx *, struct sockaddr *, socklen_t);

API_EXPORT(int)
  mtev_net_heartbeat_add_multicast(mtev_net_heartbeat_ctx *, struct sockaddr *, socklen_t, unsigned char ttl);

#endif
