/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
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

#include "mtev_defines.h"
#include "mtev_listener.h"
#include "mtev_http.h"

#ifndef MTEV_REST_H
#define MTEV_REST_H

#define MTEV_CONTROL_GET    0x47455420 /* "GET " */
#define MTEV_CONTROL_HEAD   0x48454144 /* "HEAD" */
#define MTEV_CONTROL_POST   0x504f5354 /* "POST" */
#define MTEV_CONTROL_DELETE 0x44454c45 /* "DELE" */
#define MTEV_CONTROL_PUT    0x50555420 /* "PUT " */
#define MTEV_CONTROL_MERGE  0x4d455247 /* "MERG" */

typedef struct mtev_http_rest_closure mtev_http_rest_closure_t;

typedef int (*rest_request_handler)(mtev_http_rest_closure_t *,
                                    int npats, char **pats);
typedef mtev_boolean (*rest_authorize_func_t)(mtev_http_rest_closure_t *,
                                              int npats, char **pats);
struct mtev_http_rest_closure {
  mtev_http_session_ctx *http_ctx;
  acceptor_closure_t *ac;
  char *remote_cn;
  rest_request_handler fastpath;
  int nparams;
  char **params;
  int wants_shutdown;
  void *call_closure;
  void (*call_closure_free)(void *);
  void *closure;
};

API_EXPORT(void) mtev_http_rest_init();

API_EXPORT(void)
  mtev_http_rest_clean_request(mtev_http_rest_closure_t *restc);

API_EXPORT(mtev_boolean)
  mtev_http_rest_client_cert_auth(mtev_http_rest_closure_t *restc,
                                  int npats, char **pats);

API_EXPORT(int)
  mtev_http_rest_register(const char *method, const char *base,
                          const char *expression, rest_request_handler f);

API_EXPORT(int)
  mtev_http_rest_register_closure(const char *method, const char *base,
                                  const char *expression, rest_request_handler f,
                                  void *closure);

API_EXPORT(int)
  mtev_http_rest_register_auth(const char *method, const char *base,
                               const char *expression, rest_request_handler f,
                               rest_authorize_func_t auth);

API_EXPORT(int)
  mtev_http_rest_register_auth_closure(const char *method, const char *base,
                                       const char *expression, rest_request_handler f,
                                       rest_authorize_func_t auth, void *closure);

API_EXPORT(void)
  mtev_http_rest_disclose_endpoints(const char *base, const char *expr);

API_EXPORT(xmlDocPtr)
  rest_get_xml_upload(mtev_http_rest_closure_t *restc,
                      int *mask, int *complete);

API_EXPORT(void *)
  rest_get_raw_upload(mtev_http_rest_closure_t *restc,
                      int *mask, int *complete, int *size);

API_EXPORT(int)
  mtev_rest_simple_file_handler(mtev_http_rest_closure_t *restc,
                                int npats, char **pats);

#endif
