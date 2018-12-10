/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_HTTP2_H
#define _MTEV_HTTP2_H

#define MTEV_HTTP_2 2

#include <mtev_defines.h>
#include <mtev_http.h>
#include <mtev_listener.h>
#include <eventer/eventer.h>

struct mtev_http2_parent_session;
typedef struct mtev_http2_parent_session mtev_http2_parent_session;

struct mtev_http2_session_ctx;
typedef struct mtev_http2_session_ctx mtev_http2_session_ctx;
typedef int (*mtev_http2_dispatch_func) (mtev_http2_session_ctx *);

typedef struct mtev_http2_session_ctx mtev_http2_connection;
struct mtev_http2_request;
typedef struct mtev_http2_request mtev_http2_request;
struct mtev_http2_response;
typedef struct mtev_http2_response mtev_http2_response;


API_EXPORT(mtev_http2_parent_session *)
  mtev_http2_parent_session_new_ex(mtev_http_dispatch_func f,
                                   void *(closure_creator)(mtev_http_session_ctx *),
                                   void (*closure_free)(void *),
                                   eventer_t e, mtev_acceptor_closure_t *ac,
                                   int max_streams, int head_req,
                                   uint8_t *settings, size_t settings_len);
API_EXPORT(mtev_http2_parent_session *)
  mtev_http2_parent_session_new(mtev_http_dispatch_func f,
                                void *(closure_creator)(mtev_http_session_ctx *),
                                void (*closure_free)(void *),
                                eventer_t e, mtev_acceptor_closure_t *ac,
                                int max_streams);
API_EXPORT(void)
  mtev_http2_parent_session_ref(mtev_http2_parent_session *);
API_EXPORT(void)
  mtev_http2_parent_session_deref(mtev_http2_parent_session *, mtev_boolean drop_streams);

API_EXPORT(void *)
  mtev_http2_session_dispatcher_closure(mtev_http2_session_ctx *sess);
API_EXPORT(void)
  mtev_http2_session_set_dispatcher(mtev_http2_session_ctx *ctx,
                                   int (*d)(mtev_http_session_ctx *), void *dc);

API_EXPORT(void)
  mtev_http2_session_resume_aco(mtev_http2_session_ctx *ctx);
API_EXPORT(int)
  mtev_http2_session_drive(eventer_t e, int origmask, void *closure,
                           struct timeval *now, int *done);

API_EXPORT(mtev_http_session_ctx *)
  mtev_http2_session_new(mtev_http2_parent_session *, int32_t);
API_EXPORT(mtev_acceptor_closure_t *)
  mtev_http2_session_acceptor_closure(mtev_http2_session_ctx *);
API_EXPORT(void)
  mtev_http2_ctx_session_release(mtev_http2_session_ctx *);
API_EXPORT(uint32_t)
  mtev_http2_session_ref_cnt(mtev_http2_session_ctx *);
API_EXPORT(mtev_boolean)
  mtev_http2_session_ref_dec(mtev_http2_session_ctx *);
API_EXPORT(void)
  mtev_http2_session_ref_inc(mtev_http2_session_ctx *);
API_EXPORT(void)
  mtev_http2_session_trigger(mtev_http2_session_ctx *, int state);
API_EXPORT(void)
  mtev_http2_session_set_aco(mtev_http2_session_ctx *, mtev_boolean);
API_EXPORT(mtev_boolean)
  mtev_http2_session_aco(mtev_http2_session_ctx *);


API_EXPORT(mtev_http2_request *)
  mtev_http2_session_request(mtev_http2_session_ctx *);
API_EXPORT(mtev_http2_response *)
  mtev_http2_session_response(mtev_http2_session_ctx *);
API_EXPORT(mtev_http2_connection *)
  mtev_http2_session_connection(mtev_http2_session_ctx *);

API_EXPORT(eventer_t)
  mtev_http2_connection_event(mtev_http2_connection *);
API_EXPORT(eventer_t)
  mtev_http2_connection_event_float(mtev_http2_connection *);
API_EXPORT(void)
  mtev_http2_connection_resume_after_float(mtev_http2_connection *p);
API_EXPORT(void)
  mtev_http2_session_resume_after_float(mtev_http2_session_ctx *p);

API_EXPORT(void)
  mtev_http2_request_start_time(mtev_http2_request *req, struct timeval *t);
API_EXPORT(int)
  mtev_http2_request_opts(mtev_http2_request *req);
API_EXPORT(void)
  mtev_http2_request_set_opts(mtev_http2_request *req, int opts);
API_EXPORT(const char *)
  mtev_http2_request_uri_str(mtev_http2_request *req);
API_EXPORT(const char *)
  mtev_http2_request_method_str(mtev_http2_request *req);
API_EXPORT(const char *)
  mtev_http2_request_protocol_str(mtev_http2_request *req);
API_EXPORT(size_t)
  mtev_http2_request_content_length(mtev_http2_request *req);
API_EXPORT(mtev_boolean)
  mtev_http2_request_payload_chunked(mtev_http2_request *req);
API_EXPORT(mtev_boolean)
  mtev_http2_request_has_payload(mtev_http2_request *req);
API_EXPORT(const char *)
  mtev_http2_request_querystring(mtev_http2_request *req, const char *k);
API_EXPORT(const char *)
  mtev_http2_request_orig_querystring(mtev_http2_request *req);
API_EXPORT(mtev_hash_table *)
  mtev_http2_request_querystring_table(mtev_http2_request *req);
API_EXPORT(mtev_hash_table *)
  mtev_http2_request_headers_table(mtev_http2_request *req);


API_EXPORT(int)
  mtev_http2_response_status(mtev_http2_response *);
API_EXPORT(mtev_boolean)
  mtev_http2_response_status_set(mtev_http2_session_ctx *, int, const char *);
API_EXPORT(mtev_boolean)
  mtev_http2_response_header_set(mtev_http2_session_ctx *,
                                const char *, const char *);
API_EXPORT(mtev_boolean)
  mtev_http2_response_option_set(mtev_http2_session_ctx *, uint32_t);
API_EXPORT(mtev_boolean)
  mtev_http2_response_closed(mtev_http2_response *res);
API_EXPORT(mtev_boolean)
  mtev_http2_response_complete(mtev_http2_response *res);
API_EXPORT(size_t)
  mtev_http2_response_bytes_written(mtev_http2_response *res);
API_EXPORT(size_t)
  mtev_http2_response_buffered(mtev_http2_session_ctx *ctx);
API_EXPORT(mtev_boolean)
  mtev_http2_response_flush(mtev_http2_session_ctx *ctx,
                            mtev_boolean final);
API_EXPORT(mtev_boolean)
  mtev_http2_response_flush_asynch(mtev_http2_session_ctx *ctx,
                                   mtev_boolean final);
API_EXPORT(mtev_boolean)
  mtev_http2_response_end(mtev_http2_session_ctx *ctx);

API_EXPORT(int)
  mtev_http2_session_req_consume(mtev_http2_session_ctx *ctx,
                                 void *buf, const size_t user_len,
                                 const size_t blen, int *mask);

API_EXPORT(void)
  mtev_http2_request_set_upload(mtev_http2_request *,
                                void *data, int64_t size,
                                void (*freefunc)(void *, int64_t, void *),
                                void *closure);
API_EXPORT(const void *)
  mtev_http2_request_get_upload(mtev_http2_request *, int64_t *size);

API_EXPORT(void)
  mtev_http2_ctx_acceptor_free(void *);

/* This registers the npn/alpn stuff with the eventer */
API_EXPORT(void)
  mtev_http2_init(void);

#endif
