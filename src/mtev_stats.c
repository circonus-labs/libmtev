/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
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

#include "mtev_stats.h"

static stats_recorder_t *global_stats;

void
mtev_stats_init() {
  if(global_stats == NULL)
    global_stats = stats_recorder_alloc();
}

stats_recorder_t *
mtev_stats_recorder() {
  mtev_stats_init();
  return global_stats;
}

stats_ns_t *
mtev_stats_ns(stats_ns_t *parent, const char *name) {
  mtev_stats_init();
  return stats_register_ns(global_stats, parent, name);
}

static ssize_t
http_write_to_mtev(void *cl, const char *buf, size_t len) {
  mtev_http_session_ctx *ctx = cl;
  mtev_http_response_append(ctx, buf, len);
  return len;
}

int
mtev_rest_stats_handler(mtev_http_rest_closure_t *restc,
                        int npats, char **pats) {
  bool simple = false;
  const char *format;
  mtev_http_session_ctx *ctx = restc->http_ctx;

  format = mtev_http_request_querystring(mtev_http_session_request(ctx), "format");
  if(format && !strcmp(format, "simple")) simple = true;
  mtev_http_response_ok(ctx, "application/json");
  stats_recorder_output_json(global_stats, false, simple, http_write_to_mtev, ctx);
  mtev_http_response_end(ctx);
  return 0;
}

void
mtev_stats_rest_init() {
  mtev_stats_init();
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/mtev/", "^stats\\.json$", mtev_rest_stats_handler, mtev_http_rest_client_cert_auth
  ) == 0);
}
