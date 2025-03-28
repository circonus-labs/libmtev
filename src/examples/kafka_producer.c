/*
 * Copyright (c) 2025, Apica, Inc. All rights reserved.
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
 *     * Neither the name Apica, Inc. nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       specific prior written permission.
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

#include <stdio.h>
#include <stdlib.h>
#include "mtev_capabilities_listener.h"
#include "mtev_cluster.h"
#include "mtev_defines.h"
#include "mtev_dso.h"
#include "mtev_events_rest.h"
#include "mtev_kafka.h"
#include "mtev_listener.h"
#include "mtev_log.h"
#include "mtev_main.h"
#include "mtev_memory.h"
#include "mtev_rest.h"

#define APPNAME "kafka_producer"
static char *config_file = NULL;
static int debug = 0;
static int foreground = 1;

static int usage(const char *prog)
{
  fprintf(stderr, "%s <-c conffile> [-d]\n\n", prog);
  fprintf(stderr, "\t-c conffile\tthe configuration file to load\n");
  fprintf(stderr, "\t-d\t\tturn on debugging\n");
  return 2;
}

static void parse_cli_args(int argc, char *const *argv)
{
  int c;
  while ((c = getopt(argc, argv, "c:d")) != EOF) {
    switch (c) {
    case 'c':
      config_file = optarg;
      break;
    case 'd':
      debug = 1;
      break;
    }
  }
}
static int handle_post_data(mtev_http_rest_closure_t *restc, int npats, char **pats)
{
  (void) npats;
  (void) pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  int64_t size;
  int mask;
  if (!mtev_rest_complete_upload(restc, &mask)) {
    return mask;
  }
  const void *buffer = mtev_http_request_get_upload(mtev_http_session_request(ctx), &size);
  mtev_kafka_broadcast(buffer, size);

  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_appendf(ctx, "read %zd bytes...\n", size);
  mtev_http_response_end(ctx);
  return 0;
}

static int child_main(void)
{
  if (mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  eventer_init();
  mtev_console_init(APPNAME);
  mtev_http_rest_init();
  mtev_capabilities_listener_init();
  mtev_events_rest_init();
  mtev_listener_init(APPNAME);
  mtev_cluster_init();
  mtev_dso_init();
  mtev_dso_post_init();

  mtev_http_rest_register("POST", "/", "^(.*)$", handle_post_data);

  eventer_loop();
  return 0;
}

int main(int argc, char **argv)
{
  parse_cli_args(argc, argv);
  if (!config_file) {
    exit(usage(argv[0]));
  }
  mtev_memory_init();
  mtev_main(APPNAME, config_file, debug, foreground, MTEV_LOCK_OP_LOCK, NULL, NULL, NULL,
            child_main);
}