/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015-2019, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_HTTP1_H
#define _MTEV_HTTP1_H

#include <mtev_defines.h>
#include <mtev_http.h>
#include <mtev_compress.h>

typedef enum {
  MTEV_HTTP09, MTEV_HTTP10, MTEV_HTTP11
} mtev_http_protocol;

#define MTEV_HTTP_1            1

struct mtev_http1_connection;
typedef struct mtev_http1_connection mtev_http1_connection;
struct mtev_http1_request;
typedef struct mtev_http1_request mtev_http1_request;
struct mtev_http1_response;
typedef struct mtev_http1_response mtev_http1_response;

struct mtev_http1_session_ctx;
typedef struct mtev_http1_session_ctx mtev_http1_session_ctx;

typedef int (*mtev_http1_websocket_dispatch_func) (mtev_http_session_ctx *, uint8_t opcode, const unsigned char *msg, size_t msg_len);

API_EXPORT(mtev_http_session_ctx *)
  mtev_http1_session_ctx_new(mtev_http_dispatch_func, void *, eventer_t, mtev_acceptor_closure_t *);

API_EXPORT(mtev_http_session_ctx *)
  mtev_http1_session_ctx_websocket_new(mtev_http_dispatch_func, mtev_http1_websocket_dispatch_func,
                            void *, eventer_t, mtev_acceptor_closure_t *);

API_EXPORT(mtev_acceptor_closure_t *)
  mtev_http1_session_acceptor_closure(mtev_http1_session_ctx *);
API_EXPORT(void)
  mtev_http1_ctx_session_release(mtev_http1_session_ctx *ctx);
API_EXPORT(uint32_t)
  mtev_http1_session_ref_cnt(mtev_http1_session_ctx *);
API_EXPORT(mtev_boolean)
  mtev_http1_session_ref_dec(mtev_http1_session_ctx *);
API_EXPORT(void)
  mtev_http1_session_ref_inc(mtev_http1_session_ctx *);
API_EXPORT(void)
  mtev_http1_session_trigger(mtev_http1_session_ctx *, int state);

API_EXPORT(void)
  mtev_http1_session_set_aco(mtev_http1_session_ctx *, mtev_boolean nv);
API_EXPORT(mtev_boolean)
  mtev_http1_session_aco(mtev_http1_session_ctx *);
API_EXPORT(mtev_http1_request *)
  mtev_http1_session_request(mtev_http1_session_ctx *);
API_EXPORT(mtev_http1_response *)
  mtev_http1_session_response(mtev_http1_session_ctx *);
API_EXPORT(mtev_http1_connection *)
  mtev_http1_session_connection(mtev_http1_session_ctx *);
API_EXPORT(mtev_boolean)
  mtev_http1_is_websocket(mtev_http1_session_ctx *);

API_EXPORT(void *)
  mtev_http1_session_dispatcher_closure(mtev_http1_session_ctx *);
API_EXPORT(void)
  mtev_http1_session_set_dispatcher(mtev_http1_session_ctx *,
                                   int (*)(mtev_http_session_ctx *), void *);

API_EXPORT(eventer_t)
  mtev_http1_connection_event(mtev_http1_connection *);

/* Internally copies and returns the old one */
API_EXPORT(eventer_t)
  mtev_http1_connection_event_float(mtev_http1_connection *);
API_EXPORT(void)
  mtev_http1_connection_resume_after_float(mtev_http1_connection *);
API_EXPORT(void)
  mtev_http1_session_resume_after_float(mtev_http1_session_ctx *);

API_EXPORT(void)
  mtev_http1_request_start_time(mtev_http1_request *, struct timeval *);
API_EXPORT(int)
  mtev_http1_request_opts(mtev_http1_request *);
API_EXPORT(void)
  mtev_http1_request_set_opts(mtev_http1_request *, int);
API_EXPORT(const char *)
  mtev_http1_request_uri_str(mtev_http1_request *);
API_EXPORT(const char *)
  mtev_http1_request_method_str(mtev_http1_request *);
API_EXPORT(const char *)
  mtev_http1_request_protocol_str(mtev_http1_request *);
API_EXPORT(size_t)
  mtev_http1_request_content_length(mtev_http1_request *);
API_EXPORT(mtev_boolean)
  mtev_http1_request_payload_chunked(mtev_http1_request *);
API_EXPORT(mtev_boolean)
  mtev_http1_request_has_payload(mtev_http1_request *);
API_EXPORT(const char *)
  mtev_http1_request_querystring(mtev_http1_request *, const char *);
API_EXPORT(const char *)
  mtev_http1_request_orig_querystring(mtev_http1_request *);
API_EXPORT(mtev_hash_table *)
  mtev_http1_request_querystring_table(mtev_http1_request *);
API_EXPORT(mtev_hash_table *)
  mtev_http1_request_headers_table(mtev_http1_request *);
API_EXPORT(void)
  mtev_http1_request_set_upload(mtev_http1_request *,
                               void *data, int64_t size,
                               void (*freefunc)(void *, int64_t, void *),
                               void *closure);
API_EXPORT(const void *)
  mtev_http1_request_get_upload(mtev_http1_request *, int64_t *size);


API_EXPORT(mtev_boolean)
  mtev_http1_response_closed(mtev_http1_response *);
API_EXPORT(mtev_boolean)
  mtev_http1_response_complete(mtev_http1_response *);
API_EXPORT(size_t)
  mtev_http1_response_bytes_written(mtev_http1_response *);

API_EXPORT(void)
  mtev_http1_ctx_acceptor_free(void *); /* just calls mtev_http1_session_ctx_release */

API_EXPORT(void)
  mtev_http1_process_querystring(mtev_http1_request *);

API_EXPORT(int)
  mtev_http1_session_drive(eventer_t, int, void *, struct timeval *, int *done);

API_EXPORT(mtev_boolean)
  mtev_http1_session_prime_input(mtev_http1_session_ctx *, const void *, size_t);
API_EXPORT(int)
  mtev_http1_session_req_consume(mtev_http1_session_ctx *ctx,
                                void *buf, const size_t len,
                                const size_t blen, int *mask);

API_EXPORT(int)
  mtev_http1_response_status(mtev_http1_response *);
API_EXPORT(mtev_boolean)
  mtev_http1_response_status_set(mtev_http1_session_ctx *, int, const char *);
API_EXPORT(mtev_boolean)
  mtev_http1_response_header_set(mtev_http1_session_ctx *,
                                const char *, const char *);
API_EXPORT(mtev_boolean)
  mtev_http1_response_option_set(mtev_http1_session_ctx *, uint32_t);

API_EXPORT(mtev_boolean)
  mtev_http1_response_flush(mtev_http1_session_ctx *, mtev_boolean);
API_EXPORT(mtev_boolean)
  mtev_http1_response_flush_asynch(mtev_http1_session_ctx *, mtev_boolean);
API_EXPORT(mtev_boolean) mtev_http1_response_end(mtev_http1_session_ctx *);
API_EXPORT(size_t)
  mtev_http1_response_buffered(mtev_http1_session_ctx *);

API_EXPORT(mtev_boolean)
  mtev_http1_websocket_queue_msg(mtev_http1_session_ctx *, int opcode, const unsigned char *msg, size_t msg_len);

API_EXPORT(void)
  mtev_http1_create_websocket_accept_key(char *dest, size_t dest_len, const char *client_key);

API_EXPORT(void)
  mtev_http1_response_xml(mtev_http1_session_ctx *, xmlDocPtr);

API_EXPORT(void)
  mtev_http1_init(void);

MTEV_HOOK_PROTO(http1_post_request,
                (mtev_http1_session_ctx *ctx),
                void *, closure,
                (void *closure, mtev_http1_session_ctx *ctx))

#endif
