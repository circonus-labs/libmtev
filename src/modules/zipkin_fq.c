/*
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
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
#include "mtev_zipkin.h"
#include "mtev_b64.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"

#include <fq.h>

#include "zipkin_fq.xmlh"

static fq_client zc_client = NULL;
static char *zc_routing_prefix = "zipkin.thrift.";
static char *zc_exchange = "logging";
static char *zc_host = "127.0.0.1";
static unsigned short zc_port = 8765;
static char *zc_user = "mtev";
static char *zc_pass = "mtev";
static unsigned short zc_heartbeat = 5000;
static uint32_t zc_backlog = 2048;
static mtev_log_stream_t debugls = NULL;

static mtev_hook_return_t
zipkin_fq_publish(void *closure, int64_t traceid, int64_t spanid,
                  unsigned char *buf, size_t len) {
  (void)closure;
  (void)spanid;
  if(N_L_S_ON(debugls)) {
    int blen;
    char *b64buf;
    b64buf = malloc(len*2);
    blen = mtev_b64_encode(buf,len,b64buf,len*3);
    b64buf[blen] = '\0';
    mtevL(debugls,"%s\n", b64buf);
    free(b64buf);
  }
  if(zc_client != NULL) {
    char buff[128];
    fq_msg *msg;
    snprintf(buff, sizeof(buff), "%s%llx", zc_routing_prefix, (long long int)traceid);
    msg = fq_msg_alloc(buf, len);
    fq_msg_id(msg,NULL);
    fq_msg_route(msg, buff, strlen(buff));
    fq_msg_exchange(msg, zc_exchange, strlen(zc_exchange));
    fq_client_publish(zc_client, msg);
    fq_msg_free(msg);
  }
  return MTEV_HOOK_CONTINUE;
}

#define RCONFSTR(a) do { \
  const char *vstr; \
  if(mtev_hash_retr_str(options, #a, strlen(#a), &vstr)) { \
    zc_##a = strdup(vstr); \
  } \
} while(0)
#define RCONFINT(a) do { \
  const char *vstr; \
  if(mtev_hash_retr_str(options, #a, strlen(#a), &vstr)) { \
    zc_##a = atoi(vstr); \
  } \
} while(0)

static int
zipkin_fq_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  (void)img;
  RCONFSTR(host);
  RCONFSTR(exchange);
  RCONFSTR(routing_prefix);
  RCONFSTR(user);
  RCONFSTR(pass);
  RCONFINT(port);
  RCONFINT(backlog);
  RCONFINT(heartbeat);
  return 0;
}

static void
debug_logger(fq_client client, const char *str) {
  (void)client;
  mtevL(mtev_debug, "zipkin_fq: %s\n", str);
}
static int
zipkin_fq_driver_init(mtev_dso_generic_t *img) {
  (void)img;
  debugls = mtev_log_stream_find("debug/zipkin_fq");
  fq_client_init(&zc_client, 0, debug_logger);
  fq_client_creds(zc_client, zc_host, zc_port, zc_user, zc_pass);
  fq_client_heartbeat(zc_client, zc_heartbeat);
  fq_client_set_backlog(zc_client, zc_backlog, 100);
  fq_client_set_nonblock(zc_client, true);
  fq_client_connect(zc_client);
  zipkin_publish_hook_register("fq", zipkin_fq_publish, NULL);
  return 0;
}

mtev_dso_generic_t zipkin_fq = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "zipkin_fq",
    .description = "A Fq publisher for zipkin traces",
    .xml_description = zipkin_fq_xml_description,
  },
  zipkin_fq_driver_config,
  zipkin_fq_driver_init
};
