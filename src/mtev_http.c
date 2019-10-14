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
#include "mtev_http.h"
#include "mtev_http_private.h"
#include "mtev_zipkin.h"
#include "mtev_getip.h"
#include "libmtev_dtrace.h"

#include "mtev_http1.h"
#include "mtev_http2.h"

static const char *zipkin_http_uri = "http.uri";
static const char *zipkin_http_method = "http.method";
static const char *zipkin_http_hostname = "http.hostname";
static const char *zipkin_http_status = "http.status_code";
static const char *zipkin_http_bytes_in = "http.bytes_in";
static const char *zipkin_http_bytes_out = "http.bytes_out";
static struct in_addr zipkin_ip_host;
static mtev_log_stream_t http_access = NULL;

MTEV_HOOK_IMPL(http_request_log,
  (mtev_http_session_ctx *ctx),
  void *, closure,
  (void *closure, mtev_http_session_ctx *ctx),
  (closure,ctx))

MTEV_HOOK_IMPL(http_request_complete,
  (mtev_http_session_ctx *ctx),
  void *, closure,
  (void *closure, mtev_http_session_ctx *ctx),
  (closure, ctx))

MTEV_HOOK_IMPL(http_post_request_read_payload,
  (mtev_http_session_ctx *ctx),
  void *, closure,
  (void *closure, mtev_http_session_ctx *ctx),
  (closure, ctx))

MTEV_HOOK_IMPL(http_response_send,
  (mtev_http_session_ctx *ctx),
  void *, closure,
  (void *closure, mtev_http_session_ctx *ctx),
  (closure, ctx))

struct bchain *bchain_alloc(size_t size, int line) {
  (void)line;
  struct bchain *n;
  /* mmap is greater than 1MB, inline otherwise */
  if (size >= 1048576) {
    n = malloc(offsetof(struct bchain, _buff));
    if(!n) {
      mtevL(mtev_error, "failed to alloc bchain in bchain_alloc (size %zd)\n", size);
      return NULL;
    }
    n->type = BCHAIN_MMAP;
    n->buff = mmap(NULL, size, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (n->buff == MAP_FAILED) {
      mtevL(mtev_error, "failed to mmap bchain buffer in bchain_alloc (size %zd)\n", size);
      free(n);
      return NULL;
    }
    n->mmap_size = size;
  }
  else {
    n = malloc(size + offsetof(struct bchain, _buff));
    if(!n) {
      mtevL(mtev_error, "failed to alloc bchain in bchain_alloc (size %zd)\n", size);
      return NULL;
    }
    n->type = BCHAIN_INLINE;
    n->buff = n->_buff;
  }
  n->prev = n->next = NULL;
  n->start = n->size = 0;
  n->allocd = size;
  n->compression = MTEV_COMPRESS_NONE;

  return n;
}
struct bchain *bchain_mmap(int fd, size_t len, int flags, off_t offset) {
  struct bchain *n;
  void *buff;
  buff = mmap(NULL, len, PROT_READ, flags, fd, offset);
  if(buff == MAP_FAILED) return NULL;
  n = bchain_alloc(0, 0);
  n->type = BCHAIN_MMAP;
  n->buff = buff;
  n->size = len;
  n->mmap_size = len;
  n->allocd = len;
#if defined(HAVE_POSIX_MADVISE)
  posix_madvise(buff, len, POSIX_MADV_SEQUENTIAL);
#elif defined(HAVE_MADVISE)
  madvise((caddr_t) buff, len, MADV_SEQUENTIAL);
#endif
  return n;
}
void bchain_free(struct bchain *b, int line) {
  (void)line;
  /*mtevL(mtev_error, "bchain_free(%p) : %d\n", b, line);*/
  if(b->type == BCHAIN_MMAP) {
    munmap(b->buff, b->mmap_size);
  }
  free(b);
}

struct bchain *bchain_from_data(const void *d, size_t size) {
  struct bchain *n;
  n = ALLOC_BCHAIN(size);
  if(!n) return NULL;
  memcpy(n->buff, d, size);
  n->size = size;
  return n;
}

void
mtev_http_response_auto_flush(mtev_http_session_ctx *ctx, size_t newsize) {
  mtev_http_response *res = mtev_http_session_response(ctx);
  res->output_float_trigger = newsize;
  if(mtev_http_response_buffered(ctx) > (res->output_float_trigger ? res->output_float_trigger : DEFAULT_BCHAINSIZE))
    mtev_http_response_flush(ctx, false);
}

mtev_boolean
mtev_http_is_websocket(mtev_http_session_ctx *ctx) {
  if(ctx->http_type == MTEV_HTTP_1) return mtev_http1_is_websocket((mtev_http1_session_ctx *)ctx);
  return mtev_false;
}

#define HTTP_DIS(ret, func, type, a, params, callargs) \
ret mtev_http_##func params { \
  if((a)->http_type == MTEV_HTTP_1) { \
    mtev_http1_##type t_##a = (mtev_http1_##type)a; \
    return (ret)mtev_http1_##func callargs; \
  } \
  else if((a)->http_type == MTEV_HTTP_2) { \
    mtev_http2_##type t_##a = (mtev_http2_##type)a; \
    return (ret)mtev_http2_##func callargs; \
  } \
  abort(); \
}

HTTP_DIS(mtev_acceptor_closure_t *, session_acceptor_closure, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void, ctx_session_release, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(uint32_t, session_ref_cnt, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(mtev_boolean, session_ref_dec, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void, session_ref_inc, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void, session_trigger, session_ctx *, ctx, (mtev_http_session_ctx *ctx, int state), (t_ctx, state))
HTTP_DIS(void, session_set_aco, session_ctx *, ctx, (mtev_http_session_ctx *ctx, mtev_boolean nv), (t_ctx, nv))
HTTP_DIS(mtev_boolean, session_aco, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void *, session_dispatcher_closure, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void, session_set_dispatcher, session_ctx *, ctx,
         (mtev_http_session_ctx *ctx, int (*f)(mtev_http_session_ctx *), void *c), (t_ctx, f, c))

stats_handle_t *
mtev_http_session_latency(mtev_http_session_ctx *ctx) {
  return ctx->record;
}

void
mtev_http_session_track_latency(mtev_http_session_ctx *ctx, stats_handle_t *h) {
  ctx->record = h;
}


void mtev_http_ctx_acceptor_free(void *vctx) {
  mtev_http_session_ctx *ctx = vctx;
  if(ctx->http_type == MTEV_HTTP_1) return mtev_http1_ctx_acceptor_free(vctx);
  else if(ctx->http_type == MTEV_HTTP_2) return mtev_http2_ctx_acceptor_free(vctx);
  abort();
}
int mtev_http_session_drive(eventer_t e, int o, void *vctx, struct timeval *now, int *done) {
  mtev_http_session_ctx *ctx = vctx;
  if(ctx->http_type == MTEV_HTTP_1) return mtev_http1_session_drive(e, o, vctx, now, done);
  else if(ctx->http_type == MTEV_HTTP_2) return mtev_http2_session_drive(e, o, vctx, now, done);
  abort();
  return 0;
}

HTTP_DIS(mtev_http_request *, session_request, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(mtev_http_response *, session_response, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(mtev_http_connection *, session_connection, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(eventer_t, connection_event, connection *, c, (mtev_http_connection *c), (t_c))
HTTP_DIS(eventer_t, connection_event_float, connection *, c, (mtev_http_connection *c), (t_c))
HTTP_DIS(void, connection_resume_after_float, connection *, c, (mtev_http_connection *c), (t_c))
HTTP_DIS(void, session_resume_after_float, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(void, request_start_time, request *, r, (mtev_http_request *r, struct timeval *t), (t_r, t))
HTTP_DIS(int, request_opts, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(void, request_set_opts, request *, r, (mtev_http_request *r, int v), (t_r, v))
HTTP_DIS(const char *, request_uri_str, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(const char *, request_method_str, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(const char *, request_protocol_str, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(size_t, request_content_length, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(size_t, request_content_length_read, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(mtev_boolean, request_payload_chunked, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(mtev_boolean, request_has_payload, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(mtev_boolean, request_payload_complete, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(const char *, request_querystring, request *, r, (mtev_http_request *r, const char *k), (t_r, k))
HTTP_DIS(const char *, request_orig_querystring, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(mtev_hash_table *, request_querystring_table, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(mtev_hash_table *, request_headers_table, request *, r, (mtev_http_request *r), (t_r))
HTTP_DIS(void, request_set_upload, request *, r,
         (mtev_http_request *r, void *d, int64_t s, void (*ff)(void *, int64_t, void *), void *c),
         (t_r, d, s, ff, c))
HTTP_DIS(const void *, request_get_upload, request *, r, (mtev_http_request *r, int64_t *s), (t_r, s))
HTTP_DIS(int, session_req_consume, session_ctx *, ctx,
         (mtev_http_session_ctx *ctx, void *buf, const size_t len, const size_t blen, int *mask),
         (t_ctx, buf, len, blen, mask))
HTTP_DIS(mtev_boolean, response_option_set, session_ctx *, ctx, (mtev_http_session_ctx *ctx, uint32_t o), (t_ctx, o))
HTTP_DIS(mtev_boolean, response_closed, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(mtev_boolean, response_complete, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(size_t, response_bytes_written, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(mtev_boolean, response_flush, session_ctx *, ctx, (mtev_http_session_ctx *ctx, mtev_boolean f), (t_ctx, f))
HTTP_DIS(mtev_boolean, response_flush_asynch, session_ctx *, ctx, (mtev_http_session_ctx *ctx, mtev_boolean f), (t_ctx, f))
HTTP_DIS(mtev_boolean, response_end, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(size_t, response_buffered, session_ctx *, ctx, (mtev_http_session_ctx *ctx), (t_ctx))
HTTP_DIS(mtev_hash_table *, response_headers_table, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(mtev_hash_table *, response_trailers_table, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(int, response_status, response *, r, (mtev_http_response *r), (t_r))
HTTP_DIS(mtev_boolean, response_status_set, session_ctx *, ctx,
         (mtev_http_session_ctx *ctx, int c, const char *r), (t_ctx, c, r))
HTTP_DIS(mtev_boolean, response_header_set, session_ctx *, ctx,
         (mtev_http_session_ctx *ctx, const char *k, const char *v), (t_ctx, k, v))

mtev_boolean
mtev_http_websocket_queue_msg(mtev_http_session_ctx *ctx, int opcode,
                              const unsigned char *msg, size_t msg_len) {
  mtev_boolean status;
  if(ctx->http_type != MTEV_HTTP_1) return mtev_false;
  status = mtev_http1_websocket_queue_msg((mtev_http1_session_ctx *)ctx, opcode, msg, msg_len);
  return status;
}

mtev_boolean
mtev_http_response_append(mtev_http_session_ctx *ctx,
                          const void *b, size_t l) {
  struct bchain *o;
  int boff = 0;
  mtev_boolean success = mtev_false;
  mtev_http_response *res = mtev_http_session_response(ctx);
  pthread_mutex_lock(&res->output_lock);
  if(res->closed == mtev_true) goto out;
  if(res->output_started == mtev_true &&
     !(res->output_options & (MTEV_HTTP_CLOSE | MTEV_HTTP_CHUNKED)))
    goto out;
  if(!res->output)
    res->output_last = res->output = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
  mtevAssert(res->output != NULL);
  mtevAssert(res->output_last != NULL);
  o = res->output_last;
  res->output_chain_bytes += l;
  while(l > 0) {
    if(o->allocd == o->start + o->size) {
      /* Filled up, need another */
      o->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      o->next->prev = o->next;
      o = o->next;
      res->output_last = o;
    }
    if(o->allocd > o->start + o->size) {
      int tocopy = MIN(l, o->allocd - o->start - o->size);
      memcpy(o->buff + o->start + o->size, (const char *)b + boff, tocopy);
      o->size += tocopy;
      boff += tocopy;
      l -= tocopy;
    }
  }
  success = mtev_true;
  if(mtev_http_response_buffered(ctx) > (res->output_float_trigger ? res->output_float_trigger : DEFAULT_BCHAINSIZE))
    mtev_http_response_flush(ctx, false);
out:
  pthread_mutex_unlock(&res->output_lock);
  http_response_send_hook_invoke(ctx);
  return success;
}
mtev_boolean
mtev_http_response_append_bchain(mtev_http_session_ctx *ctx,
                                 struct bchain *b) {
  struct bchain *o;
  mtev_boolean success = mtev_false;
  mtev_http_response *res = mtev_http_session_response(ctx);
  pthread_mutex_lock(&res->output_lock);
  if(res->closed == mtev_true) goto out;
  if(res->output_started == mtev_true &&
     !(res->output_options & (MTEV_HTTP_CHUNKED | MTEV_HTTP_CLOSE)))
    goto out;
  if(!res->output_last)
    res->output_last = res->output = b;
  else {
    mtevAssert(res->output !=  NULL);
    mtevAssert(res->output_last !=  NULL);
    o = res->output_last;
    o->allocd = o->size; /* so we know it is full */
    o->next = b;
    b->prev = o;
    res->output_last = b;
  }
  res->output_chain_bytes += b->size;
  success = mtev_true;
  if(mtev_http_response_buffered(ctx) > (res->output_float_trigger ? res->output_float_trigger : DEFAULT_BCHAINSIZE))
    mtev_http_response_flush(ctx, false);
out:
  pthread_mutex_unlock(&res->output_lock);
  http_response_send_hook_invoke(ctx);
  return success;
}
mtev_boolean
mtev_http_response_append_mmap(mtev_http_session_ctx *ctx,
                               int fd, size_t len, int flags, off_t offset) {
  struct bchain *n;
  n = bchain_mmap(fd, len, flags, offset);
  if(n == NULL) return mtev_false;
  return mtev_http_response_append_bchain(ctx, n);
}
mtev_boolean
mtev_http_response_append_str(mtev_http_session_ctx *ctx, const char *b) {
  return mtev_http_response_append(ctx, b, strlen(b));
}
mtev_boolean
mtev_http_response_appendf(mtev_http_session_ctx *ctx,
                           const char *format, ...) {
  mtev_boolean rv;
  va_list arg;
  va_start(arg, format);
  rv = mtev_http_response_vappend(ctx, format, arg);
  va_end(arg);
  return rv;
}
mtev_boolean
mtev_http_response_vappend(mtev_http_session_ctx *ctx,
                           const char *format, va_list arg) {
  mtev_boolean rv;
  int len;
  char buffer[8192], *dynbuff = NULL;
#ifdef va_copy
  va_list copy;
#endif

#ifdef va_copy
  va_copy(copy, arg);
  len = vsnprintf(buffer, sizeof(buffer), format, copy);
  va_end(copy);
#else
  len = vsnprintf(buffer, sizeof(buffer), format, arg);
#endif
  if(len >= (int)sizeof(buffer)) {
    int allocd = sizeof(buffer);
    while(len >= allocd) { /* guaranteed true the first time */
      if(len >= allocd) allocd = len + 1;
      if(dynbuff) free(dynbuff);
      dynbuff = malloc(allocd);
      assert(dynbuff);
#ifdef va_copy
      va_copy(copy, arg);
      len = vsnprintf(dynbuff, allocd, format, copy);
      va_end(copy);
#else
      len = vsnprintf(dynbuff, allocd, format, arg);
#endif
    }
  }

  rv = mtev_http_response_append(ctx, dynbuff ? dynbuff : buffer, len);
  free(dynbuff);
  return rv;
}
static int
mtev_http_write_xml(void *vctx, const char *buffer, int len) {
  if(mtev_http_response_append((mtev_http_session_ctx *)vctx, buffer, len))
    return len;
  return -1;
}
static int
mtev_http_close_xml(void *vctx) {
  mtev_http_response_end((mtev_http_session_ctx *)vctx);
  return 0;
}
void
mtev_http_response_xml(mtev_http_session_ctx *ctx, xmlDocPtr doc) {
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;
  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateIO(mtev_http_write_xml,
                                mtev_http_close_xml,
                                ctx, enc);
  xmlSaveFormatFileTo(out, doc, "utf8", 1);
}

static void
set_endpoint(mtev_http_session_ctx *ctx) {
  union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
  } addr;
  struct in_addr *ip = &zipkin_ip_host;
  unsigned short port = 0;
  socklen_t addrlen = sizeof(addr);
  mtev_http_connection *conn = mtev_http_session_connection(ctx);
  if(conn) {
    eventer_t e = mtev_http_connection_event(conn);
    if(e) {
      if(getsockname(eventer_get_fd(e), &addr.addr, &addrlen) == 0) {
        if(addr.addr4.sin_family == AF_INET) {
          ip = &addr.addr4.sin_addr;
          port = ntohs(addr.addr4.sin_port);
        }
        else if(addr.addr6.sin6_family == AF_INET6) {
          port = ntohs(addr.addr6.sin6_port);
        }
      }
    }
  }
  mtev_zipkin_span_default_endpoint(ctx->zipkin_span, NULL, 0, *ip, port);
}
void
mtev_http_begin_span(mtev_http_session_ctx *ctx) {
  mtev_http_request *req = mtev_http_session_request(ctx);
  const char *trace_hdr = NULL, *parent_span_hdr = NULL, *span_hdr = NULL,
             *sampled_hdr = NULL, *host_hdr, *mtev_event_hdr = NULL,
             *mtev_log_hdr = NULL;
  char *endptr = NULL;
  int64_t trace_id_buf, parent_span_id_buf, span_id_buf;
  int64_t *trace_id, *parent_span_id, *span_id;
  bool sampled_value = false;
  bool *sampled = NULL;
  mtev_zipkin_event_trace_level_t _trace_events = ZIPKIN_TRACE_EVENT_NONE,
                                  *trace_events = NULL;

  mtev_hash_table *headers = mtev_http_request_headers_table(req);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_MTEV_EVENT_L,
                           strlen(HEADER_ZIPKIN_MTEV_EVENT_L), &mtev_event_hdr);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_MTEV_LOGS_L,
                           strlen(HEADER_ZIPKIN_MTEV_LOGS_L), &mtev_log_hdr);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_TRACEID_L,
                           strlen(HEADER_ZIPKIN_TRACEID_L), &trace_hdr);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_PARENTSPANID_L,
                           strlen(HEADER_ZIPKIN_PARENTSPANID_L), &parent_span_hdr);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_SPANID_L,
                           strlen(HEADER_ZIPKIN_SPANID_L), &span_hdr);
  (void)mtev_hash_retr_str(headers, HEADER_ZIPKIN_SAMPLED_L,
                           strlen(HEADER_ZIPKIN_SAMPLED_L), &sampled_hdr);
  trace_id = mtev_zipkin_str_to_id(trace_hdr, &trace_id_buf);
  parent_span_id = mtev_zipkin_str_to_id(parent_span_hdr, &parent_span_id_buf);
  span_id = mtev_zipkin_str_to_id(span_hdr, &span_id_buf);
  if(sampled_hdr) {
    sampled_value = ((1 == strtoll(sampled_hdr, &endptr, 10)) && endptr != NULL);
    sampled = &sampled_value;
  }
  if(mtev_event_hdr) {
    unsigned long long lvl = strtoll(mtev_event_hdr, NULL, 10);
    if(lvl == 1) _trace_events = ZIPKIN_TRACE_EVENT_LIFETIME;
    if(lvl > 1) _trace_events = ZIPKIN_TRACE_EVENT_CALLBACKS;
    trace_events = &_trace_events;
  }
  ctx->zipkin_span =
    mtev_zipkin_span_new(trace_id, parent_span_id, span_id,
                         mtev_http_request_uri_str(req), true, sampled, false);
  mtev_http_connection *conn = mtev_http_session_connection(ctx);
  if(conn) {
    eventer_t e = mtev_http_connection_event(conn);
    if(e) {
      mtev_zipkin_attach_to_eventer(e, ctx->zipkin_span, false, trace_events);
    }
  }
  if(mtev_log_hdr) {
    bool on = (1 == strtoll(mtev_log_hdr, NULL, 10));
    mtev_zipkin_span_attach_logs(ctx->zipkin_span, on);
  }
  set_endpoint(ctx);
  mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, ZIPKIN_SERVER_RECV, false);
  mtev_zipkin_span_bannotate_str(ctx->zipkin_span,
                                 zipkin_http_uri, false,
                                 mtev_http_request_uri_str(req), true);
  mtev_zipkin_span_bannotate_str(ctx->zipkin_span,
                                 zipkin_http_method, false,
                                 mtev_http_request_method_str(req), true);
  if(mtev_hash_retr_str(headers, "host", 4, &host_hdr)) {
    /* someone could screw with the host header, so we indicate a copy */
    mtev_zipkin_span_bannotate_str(ctx->zipkin_span,
                                   zipkin_http_hostname, false,
                                   host_hdr, true);
  }
}
void
mtev_http_end_span(mtev_http_session_ctx *ctx) {
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_http_response *res = mtev_http_session_response(ctx);
  if(!ctx->zipkin_span) return;

  mtev_zipkin_span_bannotate_i32(ctx->zipkin_span,
                                 zipkin_http_status, false,
                                 mtev_http_response_status(res));

  size_t clr = mtev_http_request_content_length(req);
  if(clr) {
    mtev_zipkin_span_bannotate_i64(ctx->zipkin_span,
                                   zipkin_http_bytes_in, false,
                                   clr);
  }
  mtev_zipkin_span_bannotate_i64(ctx->zipkin_span,
                                 zipkin_http_bytes_out, false,
                                 mtev_http_response_bytes_written(res));

  mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, ZIPKIN_SERVER_SEND_DONE, false);
  mtev_zipkin_span_publish(ctx->zipkin_span);
  ctx->zipkin_span = NULL;
}

void
mtev_http_log_request(mtev_http_session_ctx *ctx) {
  char ip[64], timestr[64];
  double time_ms;
  struct tm *tm, tbuf;
  time_t now;
  struct timeval end_time, diff, start_time;
  mtev_http_request *req = mtev_http_session_request(ctx);

  mtev_http_request_start_time(req, &start_time);
  if(start_time.tv_sec == 0) return;

  const char *orig_qs = mtev_http_request_orig_querystring(req);
  mtev_http_response *res = mtev_http_session_response(ctx);
  mtev_gettimeofday(&end_time, NULL);
  now = end_time.tv_sec;
  sub_timeval(end_time, start_time, &diff);

  stats_handle_t *handle = mtev_http_session_latency(ctx);
  if(handle)
    stats_set_hist_intscale(handle, diff.tv_sec * 1000000UL + diff.tv_usec, -6, 1);
  if(http_request_log_hook_invoke(ctx) != MTEV_HOOK_CONTINUE) return;

  tm = gmtime_r(&now, &tbuf);
  strftime(timestr, sizeof(timestr), "%d/%b/%Y:%H:%M:%S -0000", tm);
  time_ms = diff.tv_sec * 1000 + (double)diff.tv_usec / 1000.0;
  mtev_acceptor_closure_t *ac = mtev_http_session_acceptor_closure(ctx);
  struct sockaddr *remote = mtev_acceptor_closure_remote(ac);
  mtev_convert_sockaddr_to_buff(ip, sizeof(ip), remote);
  if(LIBMTEV_HTTP_LOG_ENABLED()) {
    char logline_static[4096], *logline_dynamic = NULL;
    char *logline = logline_static;
    int logline_len = sizeof(logline_static);
    int len;
    while(1) {
      len = snprintf(logline_static, logline_len,
        "%s - - [%s] \"%s %s%s%s %s\" %d %llu|%llu %.3f\n",
        ip, timestr,
        mtev_http_request_method_str(req), mtev_http_request_uri_str(req),
        orig_qs ? "?" : "", orig_qs ? orig_qs : "",
        mtev_http_request_protocol_str(req),
        mtev_http_response_status(res),
        (long long unsigned)mtev_http_response_bytes_written(res),
        (long long unsigned)mtev_http_request_content_length_read(req),
        time_ms);
      if(len <= logline_len) break;
      free(logline_dynamic);
      logline = logline_dynamic = malloc(len+1);
      logline_len = len+1;
    }
    int fd = -1;
    (void)fd;
    mtev_http_connection *conn = mtev_http_session_connection(ctx);
    if(conn) {
      eventer_t e = mtev_http_connection_event(conn);
      if(e) {
        fd = eventer_get_fd(e);
      }
    }

    LIBMTEV_HTTP_LOG(fd, ctx, logline);
    (void)logline; /* the above line might be CPP'd away */
    free(logline_dynamic);
  }
  mtevL(http_access, "%s - - [%s] \"%s %s%s%s %s\" %d %llu|%llu %.3f\n",
        ip, timestr,
        mtev_http_request_method_str(req), mtev_http_request_uri_str(req),
        orig_qs ? "?" : "", orig_qs ? orig_qs : "",
        mtev_http_request_protocol_str(req),
        mtev_http_response_status(res),
        (long long unsigned)mtev_http_response_bytes_written(res),
        (long long unsigned)mtev_http_request_content_length_read(req),
        time_ms);
}

Zipkin_Span *
mtev_http_zipkip_span(mtev_http_session_ctx *ctx) {
  return ctx->zipkin_span;
}

void
mtev_http_init(void) {
  struct in_addr remote = { .s_addr = 0x08080808 };
  mtev_getip_ipv4(remote, &zipkin_ip_host);
  http_access = mtev_log_stream_find("http/access");
  mtev_http1_init();
  mtev_http2_init();
}

  /*


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
  mtev_http_response_append_mmap(mtev_http_session_ctx *,
                                 int fd, size_t len, int flags, off_t offset);


API_EXPORT(void)
  mtev_http_response_xml(mtev_http_session_ctx *, xmlDocPtr);

API_EXPORT(Zipkin_Span *)
  mtev_http_zipkip_span(mtev_http_session_ctx *);
  */
