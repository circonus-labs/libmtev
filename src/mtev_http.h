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

#ifndef _MTEV_HTTP_H
#define _MTEV_HTTP_H

#include "mtev_defines.h"
#include <libxml/tree.h>
#include "eventer/eventer.h"
#include "mtev_compress.h"
#include "mtev_hash.h"
#include "mtev_atomic.h"
#include "mtev_hooks.h"
#include "mtev_listener.h"
#include "mtev_zipkin.h"

typedef enum {
  MTEV_HTTP_OTHER, MTEV_HTTP_GET, MTEV_HTTP_HEAD, MTEV_HTTP_POST
} mtev_http_method;
typedef enum {
  MTEV_HTTP09, MTEV_HTTP10, MTEV_HTTP11
} mtev_http_protocol;

#define MTEV_HTTP_CHUNKED      0x0001
#define MTEV_HTTP_CLOSE        0x0002
#define MTEV_HTTP_GZIP         0x0010
#define MTEV_HTTP_DEFLATE      0x0020
#define MTEV_HTTP_LZ4F         0x0100

typedef enum {
  BCHAIN_INLINE = 0,
  BCHAIN_MMAP
} bchain_type_t;

struct bchain;

struct mtev_http_connection;
typedef struct mtev_http_connection mtev_http_connection;
struct mtev_http_request;
typedef struct mtev_http_request mtev_http_request;
struct mtev_http_response;
typedef struct mtev_http_response mtev_http_response;

struct bchain {
  bchain_type_t type;
  struct bchain *next, *prev;
  size_t start; /* where data starts (buff + start) */
  size_t size;  /* data length (past start) */
  size_t allocd;/* total allocation */
  mtev_compress_type compression;
  char *buff;
  char _buff[1]; /* over allocate as needed */
};

struct mtev_http_session_ctx;
typedef struct mtev_http_session_ctx mtev_http_session_ctx;
typedef int (*mtev_http_dispatch_func) (mtev_http_session_ctx *);
typedef int (*mtev_http_websocket_dispatch_func) (mtev_http_session_ctx *, uint8_t opcode, const unsigned char *msg, size_t msg_len);

API_EXPORT(mtev_http_session_ctx *)
  mtev_http_session_ctx_new(mtev_http_dispatch_func, void *, eventer_t, acceptor_closure_t *);

API_EXPORT(mtev_http_session_ctx *)
  mtev_http_session_ctx_websocket_new(mtev_http_dispatch_func, mtev_http_websocket_dispatch_func,
                            void *, eventer_t, acceptor_closure_t *);

API_EXPORT(void)
  mtev_http_ctx_session_release(mtev_http_session_ctx *ctx);
API_EXPORT(uint32_t)
  mtev_http_session_ref_cnt(mtev_http_session_ctx *);
API_EXPORT(uint32_t)
  mtev_http_session_ref_dec(mtev_http_session_ctx *);
API_EXPORT(uint32_t)
  mtev_http_session_ref_inc(mtev_http_session_ctx *);
API_EXPORT(void)
  mtev_http_session_trigger(mtev_http_session_ctx *, int state);

API_EXPORT(mtev_http_request *)
  mtev_http_session_request(mtev_http_session_ctx *);
API_EXPORT(mtev_http_response *)
  mtev_http_session_response(mtev_http_session_ctx *);
API_EXPORT(mtev_http_connection *)
  mtev_http_session_connection(mtev_http_session_ctx *);
API_EXPORT(mtev_boolean)
  mtev_http_is_websocket(mtev_http_session_ctx *);

API_EXPORT(void *)
  mtev_http_session_dispatcher_closure(mtev_http_session_ctx *);
API_EXPORT(void)
  mtev_http_session_set_dispatcher(mtev_http_session_ctx *,
                                   int (*)(mtev_http_session_ctx *), void *);

API_EXPORT(eventer_t)
  mtev_http_connection_event(mtev_http_connection *);

/* Internally copies and returns the old one */
API_EXPORT(eventer_t)
  mtev_http_connection_event_float(mtev_http_connection *);

API_EXPORT(void)
  mtev_http_request_start_time(mtev_http_request *, struct timeval *);
API_EXPORT(const char *)
  mtev_http_request_uri_str(mtev_http_request *);
API_EXPORT(const char *)
  mtev_http_request_method_str(mtev_http_request *);
API_EXPORT(const char *)
  mtev_http_request_protocol_str(mtev_http_request *);
API_EXPORT(size_t)
  mtev_http_request_content_length(mtev_http_request *);
API_EXPORT(mtev_boolean)
  mtev_http_request_payload_chunked(mtev_http_request *);
API_EXPORT(mtev_boolean)
  mtev_http_request_has_payload(mtev_http_request *);
API_EXPORT(const char *)
  mtev_http_request_querystring(mtev_http_request *, const char *);
API_EXPORT(const char *)
  mtev_http_request_orig_querystring(mtev_http_request *);
API_EXPORT(mtev_hash_table *)
  mtev_http_request_querystring_table(mtev_http_request *);
API_EXPORT(mtev_hash_table *)
  mtev_http_request_headers_table(mtev_http_request *);
API_EXPORT(void)
  mtev_http_request_set_upload(mtev_http_request *,
                               void *data, int64_t size,
                               void (*freefunc)(void *, int64_t, void *),
                               void *closure);
API_EXPORT(const void *)
  mtev_http_request_get_upload(mtev_http_request *, int64_t *size);


API_EXPORT(mtev_boolean)
  mtev_http_response_closed(mtev_http_response *);
API_EXPORT(mtev_boolean)
  mtev_http_response_complete(mtev_http_response *);
API_EXPORT(size_t)
  mtev_http_response_bytes_written(mtev_http_response *);

API_EXPORT(void)
  mtev_http_ctx_acceptor_free(void *); /* just calls mtev_http_session_ctx_release */

API_EXPORT(void)
  mtev_http_process_querystring(mtev_http_request *);

API_EXPORT(int)
  mtev_http_session_drive(eventer_t, int, void *, struct timeval *, int *done);

API_EXPORT(mtev_boolean)
  mtev_http_session_prime_input(mtev_http_session_ctx *, const void *, size_t);
API_EXPORT(int)
  mtev_http_session_req_consume(mtev_http_session_ctx *ctx,
                                void *buf, size_t len, size_t blen, int *mask);
API_EXPORT(mtev_boolean)
  mtev_http_response_status_set(mtev_http_session_ctx *, int, const char *);
API_EXPORT(mtev_boolean)
  mtev_http_response_header_set(mtev_http_session_ctx *,
                                const char *, const char *);
API_EXPORT(mtev_boolean)
  mtev_http_response_option_set(mtev_http_session_ctx *, uint32_t);
API_EXPORT(mtev_boolean)
  mtev_http_response_appendf(mtev_http_session_ctx *ctx,
                             const char *format, ...);
API_EXPORT(mtev_boolean)
  mtev_http_response_vappend(mtev_http_session_ctx *ctx,
                             const char *format, va_list arg);
API_EXPORT(mtev_boolean)
  mtev_http_response_append_str(mtev_http_session_ctx *, const char *);
API_EXPORT(mtev_boolean)
  mtev_http_response_append(mtev_http_session_ctx *, const void *, size_t);
API_EXPORT(mtev_boolean)
  mtev_http_response_append_bchain(mtev_http_session_ctx *, struct bchain *);
API_EXPORT(mtev_boolean)
  mtev_http_response_append_mmap(mtev_http_session_ctx *,
                                 int fd, size_t len, int flags, off_t offset);

#define mtev_http_response_append_json(ctx, doc) (\
  mtev_http_response_append_str(ctx, mtev_json_object_to_json_string(doc)), \
  mtev_http_response_append_str(ctx, "\n") \
)

API_EXPORT(mtev_boolean)
  mtev_http_response_flush(mtev_http_session_ctx *, mtev_boolean);
API_EXPORT(mtev_boolean)
  mtev_http_response_flush_asynch(mtev_http_session_ctx *, mtev_boolean);
API_EXPORT(mtev_boolean) mtev_http_response_end(mtev_http_session_ctx *);
API_EXPORT(size_t)
  mtev_http_response_buffered(mtev_http_session_ctx *);

API_EXPORT(mtev_boolean)
  mtev_http_websocket_queue_msg(mtev_http_session_ctx *, int opcode, const unsigned char *msg, size_t msg_len);

API_EXPORT(void)
  mtev_http_create_websocket_accept_key(char *dest, size_t dest_len, const char *client_key);

#define mtev_http_response_server_error(ctx, type) \
  mtev_http_response_standard(ctx, 500, "ERROR", type)
#define mtev_http_response_ok(ctx, type) \
  mtev_http_response_standard(ctx, 200, "OK", type)
#define mtev_http_response_not_found(ctx, type) \
  mtev_http_response_standard(ctx, 404, "NOT FOUND", type)
#define mtev_http_response_denied(ctx, type) \
  mtev_http_response_standard(ctx, 403, "DENIED", type)

#define mtev_http_response_standard(ctx, code, name, type) do { \
  mtev_http_response_status_set(ctx, code, name); \
  mtev_http_response_header_set(ctx, "Content-Type", type); \
  if(mtev_http_response_option_set(ctx, MTEV_HTTP_CHUNKED) == mtev_false) \
    mtev_http_response_option_set(ctx, MTEV_HTTP_CLOSE); \
} while(0)

API_EXPORT(void)
  mtev_http_response_xml(mtev_http_session_ctx *, xmlDocPtr);

API_EXPORT(Zipkin_Span *)
  mtev_http_zipkip_span(mtev_http_session_ctx *);

API_EXPORT(void)
  mtev_http_init(void);

MTEV_HOOK_PROTO(http_request_log,
                (mtev_http_session_ctx *ctx),
                void *, closure,
                (void *closure, mtev_http_session_ctx *ctx))

#endif
