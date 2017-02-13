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
#include "mtev_b64.h"
#include "mtev_http.h"
#include "mtev_str.h"
#include "mtev_getip.h"
#include "mtev_zipkin.h"
#include "mtev_conf.h"
#include "mtev_compress.h"

#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include <libxml/tree.h>
#include <pthread.h>

#include <openssl/hmac.h>

#ifdef HAVE_WSLAY
#include <wslay/wslay.h>
#endif

#define DEFAULT_MAXWRITE 1<<14 /* 32k */
#define DEFAULT_BCHAINSIZE ((1 << 15)-(offsetof(struct bchain, _buff)))
/* 64k - delta */
#define DEFAULT_BCHAINMINREAD (DEFAULT_BCHAINSIZE/4)
#define BCHAIN_SPACE(a) ((a)->allocd - (a)->size - (a)->start)

#define REQ_PAT "\r\n\r\n"
#define REQ_PATSIZE 4
#define HEADER_CONTENT_LENGTH "content-length"
#define HEADER_TRANSFER_ENCODING "transfer-encoding"
#define HEADER_EXPECT "expect"

MTEV_HOOK_IMPL(http_request_log,
  (mtev_http_session_ctx *ctx),
  void *, closure,
  (void *closure, mtev_http_session_ctx *ctx),
  (closure,ctx))

struct mtev_http_connection {
  eventer_t e;
  int needs_close;
};

struct mtev_http_request {
  struct bchain *first_input; /* The start of the input chain */
  struct bchain *last_input;  /* The end of the input chain */
  struct bchain *current_input;  /* The point of the input where we are */
  struct bchain *user_data;  /* user consumption reads from this which holds dechunked data */
  struct bchain *user_data_last;  /* end of the user_data chain */
  size_t         current_offset; /* analyzing. */
  mtev_boolean freed;

  enum { MTEV_HTTP_REQ_HEADERS = 0,
         MTEV_HTTP_REQ_EXPECT,
         MTEV_HTTP_REQ_PAYLOAD } state;
  struct bchain *current_request_chain;
  mtev_boolean has_payload;
  mtev_boolean payload_chunked;
  struct {
    int64_t size;
    void *data;
    void (*freefunc)(void *data, int64_t size, void *closure);
    void *freeclosure;
  } upload;  /* This is optionally set */
  int64_t content_length;
  int64_t content_length_read;
  mtev_boolean read_last_chunk;
  char *method_str;
  char *uri_str;
  char *protocol_str;
  mtev_hash_table querystring;
  uint32_t opts;
  mtev_http_method method;
  mtev_http_protocol protocol;
  mtev_hash_table headers;
  mtev_boolean complete;
  struct timeval start_time;
  char *orig_qs;
  mtev_stream_decompress_ctx_t *decompress_ctx;
};

struct mtev_http_response {
  mtev_http_protocol protocol;
  int status_code;
  char *status_reason;

  mtev_hash_table headers;
  struct bchain *leader; /* serialization of status line and headers */

  uint32_t output_options;
  struct bchain *output;       /* data is pushed in here */
  struct bchain *output_last;  /* tail ptr */
  struct bchain *output_raw;   /* internally transcoded here for output */
  struct bchain *output_raw_last; /* tail ptr */
  size_t output_raw_offset;    /* tracks our offset */
  mtev_boolean output_started; /* locks the options and leader */
                               /*   and possibly output. */
  mtev_boolean closed;         /* set by _end() */
  mtev_boolean complete;       /* complete, drained and disposable */
  size_t bytes_written;        /* tracks total bytes written */
  mtev_stream_compress_ctx_t *compress_ctx;
  size_t output_chain_bytes;
  size_t output_raw_chain_bytes;
  mtev_boolean freed;
};

struct mtev_http_session_ctx {
  mtev_atomic32_t ref_cnt;
  int64_t drainage;
  pthread_mutex_t write_lock;
  int max_write;
  mtev_http_connection conn;
  mtev_http_request req;
  mtev_http_response res;
  mtev_http_dispatch_func dispatcher;
  mtev_http_websocket_dispatch_func websocket_dispatcher;
  void *dispatcher_closure;
  acceptor_closure_t *ac;
  Zipkin_Span *zipkin_span;
  mtev_boolean is_websocket;
#ifdef HAVE_WSLAY
  mtev_boolean did_handshake;
  wslay_event_context_ptr wslay_ctx;
  int wanted_eventer_mask;
#endif
};

#ifdef HAVE_WSLAY
static ssize_t wslay_send_callback(wslay_event_context_ptr ctx,
                            const uint8_t *data, size_t len, int flags,
                            void *user_data);

static ssize_t wslay_recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
                                   int flags, void *user_data);

static void wslay_on_msg_recv_callback(wslay_event_context_ptr ctx,
                                       const struct wslay_event_on_msg_recv_arg *arg,
                                       void *user_data);

struct wslay_event_callbacks wslay_callbacks = {
  wslay_recv_callback,
  wslay_send_callback,
  NULL,
  NULL,
  NULL,
  NULL,
  wslay_on_msg_recv_callback
};
#endif

static mtev_log_stream_t http_debug = NULL;
static mtev_log_stream_t http_io = NULL;
static mtev_log_stream_t http_access = NULL;
//static const char *zipkin_http_uri = "http.uri";
static const char *zipkin_http_method = "http.method";
static const char *zipkin_http_hostname = "http.hostname";
static const char *zipkin_http_status = "http.status";
static const char *zipkin_http_bytes_in = "http.bytes_in";
static const char *zipkin_http_bytes_out = "http.bytes_out";
static const char *zipkin_ss_done = "ss_done";
static struct in_addr zipkin_ip_host;

#define CTX_ADD_HEADER(a,b) \
    mtev_hash_replace(&ctx->res.headers, \
                      strdup(a), strlen(a), strdup(b), free, free)
static const char _hexchars[16] =
  {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static void inplace_urldecode(char *c) {
  char *o = c;
  while(*c) {
    if(*c == '%') {
      int i, ord = 0;
      for(i = 1; i < 3; i++) {
        if(c[i] >= '0' && c[i] <= '9') ord = (ord << 4) | (c[i] - '0');
        else if (c[i] >= 'a' && c[i] <= 'f') ord = (ord << 4) | (c[i] - 'a' + 0xa);
        else if (c[i] >= 'A' && c[i] <= 'F') ord = (ord << 4) | (c[i] - 'A' + 0xa);
        else break;
      }
      if(i==3) {
        *((unsigned char *)o++) = ord;
        c+=3;
        continue;
      }
    }
    *o++ = *c++;
  }
  *o = '\0';
}

/* We can free a response, but still try to use it.... make sure
 * we reinitialize here so we don't use trash
 * TODO: Audit all this code to make sure we don't try to use
 * the response after we free at all - need to audit use of 
 * reference count in particular */
static void check_realloc_response(mtev_http_response *res) {
  if (res->freed == mtev_true) {
    mtev_hash_init(&res->headers);
    res->freed = mtev_false;
  }
}
/* Same deal for requests.
 * TODO: Audit code to avoid having to use this */
static void check_realloc_request(mtev_http_request *req) {
  if (req->freed == mtev_true) {
    mtev_hash_init(&req->headers);
    mtev_hash_init(&req->querystring);
    req->freed = mtev_false;
  }
}

struct bchain *bchain_alloc(size_t size, int line) {
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
  n->allocd = len;
#if defined(HAVE_POSIX_MADVISE)
  posix_madvise(buff, len, POSIX_MADV_SEQUENTIAL);
#elif defined(HAVE_MADVISE)
  madvise((caddr_t) buff, len, MADV_SEQUENTIAL);
#endif
  return n;
}
void bchain_free(struct bchain *b, int line) {
  /*mtevL(mtev_error, "bchain_free(%p) : %d\n", b, line);*/
  if(b->type == BCHAIN_MMAP) {
    munmap(b->buff, b->allocd);
  }
  free(b);
}
#define ALLOC_BCHAIN(s) bchain_alloc(s, __LINE__)
#define FREE_BCHAIN(a) bchain_free(a, __LINE__)
#define RELEASE_BCHAIN(a) do { \
  while(a) { \
    struct bchain *__b; \
    __b = a; \
    a = __b->next; \
    bchain_free(__b, __LINE__); \
  } \
} while(0)
struct bchain *bchain_from_data(const void *d, size_t size) {
  struct bchain *n;
  n = ALLOC_BCHAIN(size);
  if(!n) return NULL;
  memcpy(n->buff, d, size);
  n->size = size;
  return n;
}

static mtev_compress_type
request_compression_type(mtev_http_request *req)
{
  const char *content_encoding = NULL;
  if (req == NULL || req->freed) return MTEV_COMPRESS_NONE;
  
  mtev_hash_table *headers = mtev_http_request_headers_table(req);
  mtev_hash_retr_str(headers, "content-encoding", strlen("content-encoding"), 
                     &content_encoding);

  if (content_encoding == NULL) {
    return MTEV_COMPRESS_NONE;
  }
  
  /* there is no official mime-type for LZ4 check for anything containing lzf4 */
  if (strstr(content_encoding, "lz4f") != NULL) {
    /* check for lz4f and x-lz4f */
    return MTEV_COMPRESS_LZ4F;
  } else if (strstr(content_encoding, "gzip") != NULL) {    
    /* gzip and x-gzip */
    return MTEV_COMPRESS_GZIP;
  }

  return MTEV_COMPRESS_NONE;
}

mtev_http_request *
mtev_http_session_request(mtev_http_session_ctx *ctx) {
  return &ctx->req;
}
mtev_http_response *
mtev_http_session_response(mtev_http_session_ctx *ctx) {
  return &ctx->res;
}
mtev_http_connection *
mtev_http_session_connection(mtev_http_session_ctx *ctx) {
  return &ctx->conn;
}
mtev_boolean
mtev_http_is_websocket(mtev_http_session_ctx *ctx) {
  return ctx->is_websocket;
}

void
mtev_http_session_set_dispatcher(mtev_http_session_ctx *ctx,
                                 int (*d)(mtev_http_session_ctx *), void *dc) {
  ctx->dispatcher = d;
  ctx->dispatcher_closure = dc;
}
void *mtev_http_session_dispatcher_closure(mtev_http_session_ctx *ctx) {
  return ctx->dispatcher_closure;
}
void mtev_http_session_trigger(mtev_http_session_ctx *ctx, int state) {
  if(ctx->conn.e) eventer_trigger(ctx->conn.e, state);
}
uint32_t mtev_http_session_ref_cnt(mtev_http_session_ctx *ctx) {
  return ctx->ref_cnt;
}
uint32_t mtev_http_session_ref_dec(mtev_http_session_ctx *ctx) {
  return mtev_atomic_dec32(&ctx->ref_cnt);
}
uint32_t mtev_http_session_ref_inc(mtev_http_session_ctx *ctx) {
  return mtev_atomic_inc32(&ctx->ref_cnt);
}
eventer_t mtev_http_connection_event(mtev_http_connection *conn) {
  return conn ? conn->e : NULL;
}
eventer_t mtev_http_connection_event_float(mtev_http_connection *conn) {
  eventer_t e = conn ? conn->e : NULL;
  if(e) {
    conn->e = eventer_alloc();
    memcpy(conn->e, e, sizeof(*e));
    conn->e->refcnt = 1;
  }
  return e;
}
void mtev_http_request_start_time(mtev_http_request *req, struct timeval *t) {
  memcpy(t, &req->start_time, sizeof(*t));
}
const char *mtev_http_request_uri_str(mtev_http_request *req) {
  return req->uri_str;
}
const char *mtev_http_request_method_str(mtev_http_request *req) {
  return req->method_str;
}
const char *mtev_http_request_protocol_str(mtev_http_request *req) {
  return req->protocol_str;
}
size_t mtev_http_request_content_length(mtev_http_request *req) {
  return req->content_length;
}
mtev_boolean mtev_http_request_payload_chunked(mtev_http_request *req) {
  return req->payload_chunked;
}
mtev_boolean mtev_http_request_has_payload(mtev_http_request *req) {
  return req->has_payload;
}
const char *mtev_http_request_querystring(mtev_http_request *req, const char *k) {
  void *vv;
  const char *v = NULL;
  if(mtev_hash_retrieve(&req->querystring, k, strlen(k), &vv))
    v = vv;
  return v;
}
const char *mtev_http_request_orig_querystring(mtev_http_request *req) {
  return req->orig_qs;
}
mtev_hash_table *mtev_http_request_querystring_table(mtev_http_request *req) {
  return &req->querystring;
}
mtev_hash_table *mtev_http_request_headers_table(mtev_http_request *req) {
  return &req->headers;
}
void
mtev_http_request_set_upload(mtev_http_request *req,
                             void *data, int64_t size,
                             void (*freefunc)(void *, int64_t, void *),
                             void *closure) {
  if(req->upload.freefunc)
    req->upload.freefunc(req->upload.data, req->upload.size,
                             req->upload.freeclosure);
  req->upload.freefunc = freefunc;
  req->upload.freeclosure = closure;
  req->upload.data = data;
  req->upload.size = size;
}
const void *
mtev_http_request_get_upload(mtev_http_request *req, int64_t *size) {
  if(size) *size = req->upload.size;
  return req->upload.data;
}

mtev_boolean mtev_http_response_closed(mtev_http_response *res) {
  return res->closed;
}
mtev_boolean mtev_http_response_complete(mtev_http_response *res) {
  return res->complete;
}
size_t mtev_http_response_bytes_written(mtev_http_response *res) {
  return res->bytes_written;
}

static mtev_http_method
_method_enum(const char *s) {
  switch(*s) {
   case 'G':
    if(!strcasecmp(s, "GET")) return MTEV_HTTP_GET;
    break;
   case 'H':
    if(!strcasecmp(s, "HEAD")) return MTEV_HTTP_HEAD;
    break;
   case 'P':
    if(!strcasecmp(s, "POST")) return MTEV_HTTP_POST;
    break;
   default:
    break;
  }
  return MTEV_HTTP_OTHER;
}
static mtev_http_protocol
_protocol_enum(const char *s) {
  if(!strcasecmp(s, "HTTP/1.1")) return MTEV_HTTP11;
  if(!strcasecmp(s, "HTTP/1.0")) return MTEV_HTTP10;
  return MTEV_HTTP09;
}
static mtev_boolean
_fixup_bchain(struct bchain *b) {
  /* make sure lines (CRLF terminated) don't cross chain boundaries */
  while(b) {
    struct bchain *f;
    ssize_t start_in_b, end_in_f;
    size_t new_size;
    const char *str_in_f;

    start_in_b = b->start;
    if(b->size > 2) {
      if(memcmp(b->buff + b->start + b->size - 2, "\r\n", 2) == 0) {
        b = b->next;
        continue;
      }
      start_in_b = b->start + b->size - 3; /* we already checked -2 */
      while(start_in_b >= (ssize_t) b->start) {
        if(b->buff[start_in_b] == '\r' && b->buff[start_in_b+1] == '\n') {
          start_in_b += 2;
          break;
        }
        start_in_b--;
      }
    }

    /* start_in_b points to the beginning of the string we need to build
     * into a new buffer.
     */
    f = b->next;
    if(!f) return mtev_false; /* Nothing left, can't complete the line */
    str_in_f = strnstrn("\r\n", 2, f->buff + f->start, f->size);
    if(!str_in_f) return mtev_false; /* nothing in next chain -- too long */
    str_in_f += 2;
    end_in_f = (str_in_f - f->buff - f->start);
    new_size = end_in_f + (b->start + b->size - start_in_b);
    if(new_size > DEFAULT_BCHAINSIZE) return mtev_false; /* string too long */
    f = ALLOC_BCHAIN(new_size);
    f->prev = b;
    f->next = b->next;
    f->start = 0;
    f->size = new_size;
    memcpy(f->buff, b->buff + start_in_b, b->start + b->size - start_in_b);
    memcpy(f->buff + b->start + b->size - start_in_b,
           f->buff + f->start, end_in_f);
    f->next->prev = f;
    f->prev->next = f;
    f->prev->size -= start_in_b - b->start;
    f->next->size -= end_in_f;
    f->next->start += end_in_f;
    b = f->next; /* skip f, we know it is right */
  }
  return mtev_true;
}
static mtev_boolean
_extract_header(char *l, const char **n, const char **v) {
  *n = NULL;
  if(*l == ' ' || *l == '\t') {
    while(*l == ' ' || *l == '\t') l++;
    *v = l;
    return mtev_true;
  }
  *n = l;
  while(*l != ':' && *l) { *l = tolower(*l); l++; }
  if(!*l) return mtev_false;
  *v = l+1;
  /* Right trim the name */
  *l-- = '\0';
  while(*l == ' ' || *l == '\t') *l-- = '\0';
  while(**v == ' ' || **v == '\t') (*v)++;
  return mtev_true;
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
  if(ctx->conn.e) {
    if(getsockname(ctx->conn.e->fd, &addr.addr, &addrlen) == 0) {
      if(addr.addr4.sin_family == AF_INET) {
        addr.addr4.sin_addr.s_addr = ntohl(addr.addr4.sin_addr.s_addr);
        ip = &addr.addr4.sin_addr;
        port = ntohs(addr.addr4.sin_port);
      }
      else if(addr.addr6.sin6_family == AF_INET6) {
        port = ntohs(addr.addr6.sin6_port);
      }
    }
  }
  mtev_zipkin_span_default_endpoint(ctx->zipkin_span, NULL, 0, *ip, port);
}
static void
begin_span(mtev_http_session_ctx *ctx) {
  mtev_http_request *req = &ctx->req;
  const char *trace_hdr = NULL, *parent_span_hdr = NULL, *span_hdr = NULL,
             *sampled_hdr = NULL, *host_hdr;
  char *endptr = NULL;
  int64_t trace_id_buf, parent_span_id_buf, span_id_buf;
  int64_t *trace_id, *parent_span_id, *span_id;
  bool sampled = false;

  (void)mtev_hash_retr_str(&req->headers, HEADER_ZIPKIN_TRACEID_L,
                           strlen(HEADER_ZIPKIN_TRACEID_L), &trace_hdr);
  (void)mtev_hash_retr_str(&req->headers, HEADER_ZIPKIN_PARENTSPANID_L,
                           strlen(HEADER_ZIPKIN_PARENTSPANID_L), &parent_span_hdr);
  (void)mtev_hash_retr_str(&req->headers, HEADER_ZIPKIN_SPANID_L,
                           strlen(HEADER_ZIPKIN_SPANID_L), &span_hdr);
  (void)mtev_hash_retr_str(&req->headers, HEADER_ZIPKIN_SAMPLED_L,
                           strlen(HEADER_ZIPKIN_SAMPLED_L), &sampled_hdr);
  trace_id = mtev_zipkin_str_to_id(trace_hdr, &trace_id_buf);
  parent_span_id = mtev_zipkin_str_to_id(parent_span_hdr, &parent_span_id_buf);
  span_id = mtev_zipkin_str_to_id(span_hdr, &span_id_buf);
  if(sampled_hdr && (0 == strtoll(sampled_hdr, &endptr, 10)) && endptr != NULL)
    sampled = true;
  ctx->zipkin_span =
    mtev_zipkin_span_new(trace_id, parent_span_id, span_id,
                         req->uri_str, false, NULL, sampled);
  set_endpoint(ctx);
  mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, ZIPKIN_SERVER_RECV, false);
  mtev_zipkin_span_bannotate(ctx->zipkin_span, ZIPKIN_STRING,
                             zipkin_http_method, false,
                             req->method_str, strlen(req->method_str), false);
  if(mtev_hash_retr_str(&req->headers, "host", 4, &host_hdr)) {
    /* someone could screw with the host header, so we indicate a copy */
    mtev_zipkin_span_bannotate(ctx->zipkin_span, ZIPKIN_STRING,
                               zipkin_http_hostname, false,
                               host_hdr, strlen(host_hdr), true);
  }
}
static void
end_span(mtev_http_session_ctx *ctx) {
  mtev_http_request *req = &ctx->req;
  mtev_http_response *res = &ctx->res;
  char status_str[4];
  int64_t nbytesout, nbytesin;
  if(!ctx->zipkin_span) return;

  snprintf(status_str, sizeof(status_str), "%03d", res->status_code);
  mtev_zipkin_span_bannotate(ctx->zipkin_span, ZIPKIN_STRING,
                             zipkin_http_status, false,
                             status_str, strlen(status_str), false);

  if(req->content_length_read) {
    nbytesin = htonll(req->content_length_read);
    mtev_zipkin_span_bannotate(ctx->zipkin_span, ZIPKIN_I64,
                               zipkin_http_bytes_in, false,
                               &nbytesin, 8, false);
  }
  nbytesout = htonll(res->bytes_written);
  mtev_zipkin_span_bannotate(ctx->zipkin_span, ZIPKIN_I64,
                             zipkin_http_bytes_out, false,
                             &nbytesout, 8, false);

  mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, zipkin_ss_done, false);
  mtev_zipkin_span_publish(ctx->zipkin_span);
  ctx->zipkin_span = NULL;
}

static void
mtev_http_log_request(mtev_http_session_ctx *ctx) {
  char ip[64], timestr[64];
  double time_ms;
  struct tm *tm, tbuf;
  time_t now;
  struct timeval end_time, diff;

  if(ctx->req.start_time.tv_sec == 0) return;
  if(http_request_log_hook_invoke(ctx) != MTEV_HOOK_CONTINUE) return;

  mtev_gettimeofday(&end_time, NULL);
  now = end_time.tv_sec;
  tm = gmtime_r(&now, &tbuf);
  strftime(timestr, sizeof(timestr), "%d/%b/%Y:%H:%M:%S -0000", tm);
  sub_timeval(end_time, ctx->req.start_time, &diff);
  time_ms = diff.tv_sec * 1000 + (double)diff.tv_usec / 1000.0;
  mtev_convert_sockaddr_to_buff(ip, sizeof(ip), &ctx->ac->remote.remote_addr);
  mtevL(http_access, "%s - - [%s] \"%s %s%s%s %s\" %d %llu %.3f\n",
        ip, timestr,
        ctx->req.method_str, ctx->req.uri_str,
        ctx->req.orig_qs ? "?" : "", ctx->req.orig_qs ? ctx->req.orig_qs : "",
        ctx->req.protocol_str,
        ctx->res.status_code,
        (long long unsigned)ctx->res.bytes_written,
        time_ms);
}

static int
_http_perform_write(mtev_http_session_ctx *ctx, int *mask) {
  int len, tlen = 0;
  size_t attempt_write_len;
  struct bchain **head, *b;
  pthread_mutex_lock(&ctx->write_lock);
 choose_bucket:
  head = ctx->res.leader ? &ctx->res.leader : &ctx->res.output_raw;
  b = *head;

  if(!ctx->conn.e) {
    pthread_mutex_unlock(&ctx->write_lock);
    return 0;
  }
  if(!b) {
    if(ctx->res.closed) ctx->res.complete = mtev_true;
    *mask = EVENTER_EXCEPTION;
    pthread_mutex_unlock(&ctx->write_lock);
    return tlen;
  }

  if(ctx->res.output_raw_offset >= b->size) {
    *head = b->next;
    if(ctx->res.output_raw_last == b)
      ctx->res.output_raw_last = NULL;
    mtevAssert((ctx->res.output_raw_last == NULL && ctx->res.output_raw == NULL) ||
           (ctx->res.output_raw_last != NULL && ctx->res.output_raw != NULL));
    ctx->res.output_raw_chain_bytes -= b->size;
    FREE_BCHAIN(b);
    b = *head;
    if(b) b->prev = NULL;
    ctx->res.output_raw_offset = 0;
    goto choose_bucket;
  }

  attempt_write_len = b->size - ctx->res.output_raw_offset;
  attempt_write_len = MIN(attempt_write_len, ctx->max_write);

  len = ctx->conn.e->opset->
          write(ctx->conn.e->fd,
                b->buff + b->start + ctx->res.output_raw_offset,
                attempt_write_len, mask, ctx->conn.e);
  if(len == -1 && errno == EAGAIN) {
    *mask |= EVENTER_EXCEPTION;
    pthread_mutex_unlock(&ctx->write_lock);
    return tlen;
  }
  if(len == -1) {
    /* socket error */
    ctx->res.complete = mtev_true;
    ctx->conn.needs_close = mtev_true;
    mtev_http_log_request(ctx);
    *mask |= EVENTER_EXCEPTION;
    pthread_mutex_unlock(&ctx->write_lock);
    return -1;
  }
  mtevL(http_io, " http_write(%d) => %d [\n%.*s\n]\n", ctx->conn.e->fd,
        len, len, b->buff + b->start + ctx->res.output_raw_offset);
  ctx->res.output_raw_offset += len;
  ctx->res.bytes_written += len;
  tlen += len;
  goto choose_bucket;
}
static mtev_boolean
mtev_http_request_finalize_headers(mtev_http_request *req, mtev_boolean *err) {
  int start;
  void *vval;
  const char *mstr, *last_name = NULL;
  struct bchain *b;

  if(req->state != MTEV_HTTP_REQ_HEADERS) return mtev_false;
  if(!req->current_input) req->current_input = req->first_input;
  if(!req->current_input) return mtev_false;
  check_realloc_request(req);
  if(req->start_time.tv_sec == 0) mtev_gettimeofday(&req->start_time, NULL);
 restart:
  while(req->current_input->prev &&
        (req->current_offset < (req->current_input->start + REQ_PATSIZE - 1))) {
    int inset;
    /* cross bucket */
    if(req->current_input == req->last_input &&
       req->current_offset >= (req->last_input->start + req->last_input->size))
      return mtev_false;
    req->current_offset++;
    inset = req->current_offset - req->current_input->start;
    if(memcmp(req->current_input->buff + req->current_input->start,
              &REQ_PAT[REQ_PATSIZE - inset], inset) == 0 &&
       memcmp(req->current_input->prev->buff +
                req->current_input->prev->start +
                req->current_input->prev->size - REQ_PATSIZE + inset,
              &REQ_PAT[inset],
              REQ_PATSIZE - inset) == 0) goto match;
  }
  start = MAX((ssize_t)(req->current_offset) - REQ_PATSIZE, (ssize_t)(req->current_input->start));
  mstr = strnstrn(REQ_PAT, REQ_PATSIZE,
                  req->current_input->buff + start,
                  req->current_input->size -
                    (start - req->current_input->start));
  if(!mstr && req->current_input->next) {
    req->current_input = req->current_input->next;
    req->current_offset = req->current_input->start;
    goto restart;
  }
  if(!mstr) return mtev_false;
  req->current_offset = mstr - req->current_input->buff + REQ_PATSIZE;
 match:
  req->current_request_chain = req->first_input;
  mtevL(http_debug, " mtev_http_request_finalize : match(%d in %d)\n",
        (int)(req->current_offset - req->current_input->start),
        (int)req->current_input->size);
  if(req->current_offset <
     req->current_input->start + req->current_input->size) {
    /* There are left-overs */
    int lsize = req->current_input->size - req->current_offset;
    mtevL(http_debug, " mtev_http_request_finalize -- leftovers: %d\n", lsize);
    req->first_input = ALLOC_BCHAIN(lsize);
    req->first_input->prev = NULL;
    req->first_input->next = req->current_input->next;
    req->first_input->start = 0;
    req->first_input->size = lsize;
    memcpy(req->first_input->buff,
           req->current_input->buff + req->current_offset,
           req->first_input->size);
    req->current_input->size -= lsize;
    if(req->last_input == req->current_input)
      req->last_input = req->first_input;
    else {
      mtevAssert(req->current_input != req->current_request_chain);
      FREE_BCHAIN(req->current_input);
    }
  }
  else {
    req->first_input = req->last_input = NULL;
  }
  req->current_input = NULL;
  req->current_offset = 0;

  /* Now we need to dissect the current_request_chain into an HTTP request */
  /* First step: make sure that no line crosses a chain boundary by
   * inserting new chains as necessary.
   */
  if(!_fixup_bchain(req->current_request_chain)) {
    *err = mtev_true;
    return mtev_false;
  }
  /* Second step is to parse out the request itself */
  for(b = req->current_request_chain; b; b = b->next) {
    char *curr_str, *next_str;
    b->buff[b->start + b->size - 2] = '\0';
    curr_str = b->buff + b->start;
    do {
      next_str = strstr(curr_str, "\r\n");
      if(next_str) {
        *((char *)next_str) = '\0';
        next_str += 2;
      }
      if(req->method_str && *curr_str == '\0')
        break; /* our CRLFCRLF... end of req */
#define FAIL do { *err = mtev_true; return mtev_false; } while(0)
      if(!req->method_str) { /* request line */
        req->method_str = (char *)curr_str;
        req->uri_str = strchr(curr_str, ' ');
        if(!req->uri_str) FAIL;
        *(req->uri_str) = '\0';
        req->uri_str++;
        req->protocol_str = strchr(req->uri_str, ' ');
        if(!req->protocol_str) FAIL;
        *(req->protocol_str) = '\0';
        req->protocol_str++;
        req->method = _method_enum(req->method_str);
        req->protocol = _protocol_enum(req->protocol_str);
        req->opts |= MTEV_HTTP_CLOSE;
        if(req->protocol == MTEV_HTTP11) req->opts |= MTEV_HTTP_CHUNKED;
      }
      else { /* request headers */
        const char *name, *value;
        if(_extract_header(curr_str, &name, &value) == mtev_false) FAIL;
        if(!name && !last_name) FAIL;
        if(!strcmp(name ? name : last_name, "accept-encoding")) {
          if(strstr(value, "gzip")) req->opts |= MTEV_HTTP_GZIP;
          if(strstr(value, "deflate")) req->opts |= MTEV_HTTP_DEFLATE;
          if(strstr(value, "lz4f")) req->opts |= MTEV_HTTP_LZ4F;
        }
        if(name)
          mtev_hash_replace(&req->headers, name, strlen(name), (void *)value,
                            NULL, NULL);
        else {
          struct bchain *b;
          const char *prefix = NULL;
          int l1, l2;
          mtev_hash_retr_str(&req->headers, last_name, strlen(last_name),
                             &prefix);
          if(!prefix) FAIL;
          l1 = strlen(prefix);
          l2 = strlen(value);
          b = ALLOC_BCHAIN(l1 + l2 + 2);
          b->compression = request_compression_type(req);
          b->next = req->current_request_chain;
          b->next->prev = b;
          req->current_request_chain = b;
          b->size = l1 + l2 + 2;
          memcpy(b->buff, prefix, l1);
          b->buff[l1] = ' ';
          memcpy(b->buff + l1 + 1, value, l2);
          b->buff[l1 + 1 + l2] = '\0';
          mtev_hash_replace(&req->headers, last_name, strlen(last_name),
                            b->buff, NULL, NULL);
        }
        if(name) last_name = name;
      }
      curr_str = next_str;
    } while(next_str);
  }

  /* headers are done... we could need to read a payload */
  if(mtev_hash_retrieve(&req->headers,
                        HEADER_TRANSFER_ENCODING,
                        sizeof(HEADER_TRANSFER_ENCODING)-1, &vval)) {
    req->has_payload = mtev_true;
    req->payload_chunked = mtev_true;
    req->read_last_chunk = mtev_false;
    req->content_length = 0;
  }
  else if(mtev_hash_retrieve(&req->headers,
                        HEADER_CONTENT_LENGTH,
                        sizeof(HEADER_CONTENT_LENGTH)-1, &vval)) {
    const char *val = vval;
    req->has_payload = mtev_true;
    req->content_length = strtoll(val, NULL, 10);
  }

  if(mtev_hash_retrieve(&req->headers, HEADER_EXPECT,
                        sizeof(HEADER_EXPECT)-1, &vval)) {
    const char *val = vval;
    if(strncmp(val, "100-", 4) || /* Bad expect header */
       req->has_payload == mtev_false) /* expect, but no content length */
      FAIL;
    /* We need to tell the client to "go-ahead" -- HTTP sucks */
    req->state = MTEV_HTTP_REQ_EXPECT;
    return mtev_false;
  }
  if(req->has_payload) {
    /* switch modes... let's go read the payload */
    req->state = MTEV_HTTP_REQ_PAYLOAD;
    return mtev_false;
  }

  req->complete = mtev_true;
  return mtev_true;
}
void
mtev_http_process_querystring(mtev_http_request *req) {
  char *cp, *interest, *brk = NULL;
  cp = strchr(req->uri_str, '?');
  if(!cp) return;
  *cp++ = '\0';
  req->orig_qs = strdup(cp);
  for (interest = strtok_r(cp, "&", &brk);
       interest;
       interest = strtok_r(NULL, "&", &brk)) {
    char *eq;
    eq = strchr(interest, '=');
    if(!eq) {
      inplace_urldecode(interest);
      mtev_hash_store(&req->querystring, interest, strlen(interest), NULL);
    }
    else {
      *eq++ = '\0';
      inplace_urldecode(interest);
      inplace_urldecode(eq);
      mtev_hash_store(&req->querystring, interest, strlen(interest), eq);
    }
  }
}
static mtev_boolean
mtev_http_request_finalize_payload(mtev_http_request *req, mtev_boolean *err) {
  req->complete = mtev_true;
  return mtev_true;
}
static mtev_boolean
mtev_http_request_finalize(mtev_http_request *req, mtev_boolean *err) {
  if(req->state == MTEV_HTTP_REQ_HEADERS)
    if(mtev_http_request_finalize_headers(req, err)) return mtev_true;
  if(req->state == MTEV_HTTP_REQ_EXPECT) return mtev_false;
  if(req->state == MTEV_HTTP_REQ_PAYLOAD)
    if(mtev_http_request_finalize_payload(req, err)) return mtev_true;
  return mtev_false;
}
static int
mtev_http_complete_request(mtev_http_session_ctx *ctx, int mask) {
  struct bchain *in;
  mtev_boolean rv, err = mtev_false;

  if(mask & EVENTER_EXCEPTION) {
   full_error:
    ctx->conn.e->opset->close(ctx->conn.e->fd, &mask, ctx->conn.e);
    ctx->conn.e = NULL;
    return 0;
  }
  if(ctx->req.complete == mtev_true) return EVENTER_EXCEPTION;

  /* We could have a complete request in the tail of a previous request */
  rv = mtev_http_request_finalize(&ctx->req, &err);
  if(rv == mtev_true) return EVENTER_WRITE | EVENTER_EXCEPTION;
  if(err == mtev_true) goto full_error;

  while(1) {
    int len;

    in = ctx->req.last_input;
    if(!in) {
      in = ctx->req.first_input = ctx->req.last_input =
        ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      if(!in) goto full_error;
    }
    if(in->size > 0 && /* we've read something */
       DEFAULT_BCHAINMINREAD > BCHAIN_SPACE(in) && /* we'd like read more */
       DEFAULT_BCHAINMINREAD < DEFAULT_BCHAINSIZE) { /* and we can */
      in->next = ctx->req.last_input =
        ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      in->next->prev = in;
      in = in->next;
      if(!in) goto full_error;
    }

    len = ctx->conn.e->opset->read(ctx->conn.e->fd,
                                   in->buff + in->start + in->size,
                                   in->allocd - in->size - in->start,
                                   &mask, ctx->conn.e);
    mtevL(http_debug, " mtev_http -> read(%d) = %d\n", ctx->conn.e->fd, len);
    if(len > 0)
      mtevL(http_io, " mtev_http:read(%d) => %d [\n%.*s\n]\n", ctx->conn.e->fd, len, len, in->buff + in->start + in->size);
    else
      mtevL(http_io, " mtev_http:read(%d) => %d\n", ctx->conn.e->fd, len);
    if(len == -1 && errno == EAGAIN) return mask;
    if(len <= 0) goto full_error;
    if(len > 0) in->size += len;
    rv = mtev_http_request_finalize(&ctx->req, &err);
    /* walk the bchain and set the compression */
    if (rv == mtev_true) {
      struct bchain *x = ctx->req.first_input;
      while (x) {
        x->compression = request_compression_type(&ctx->req);
        x = x->next;
      }
    }
    if(len == -1 || err == mtev_true) goto full_error;
    if(ctx->req.state == MTEV_HTTP_REQ_EXPECT) {
      const char *expect;
      ctx->req.state = MTEV_HTTP_REQ_PAYLOAD;
      mtevAssert(ctx->res.leader == NULL);
      expect = "HTTP/1.1 100 Continue\r\n\r\n";
      ctx->res.leader = bchain_from_data(expect, strlen(expect));
      ctx->res.output_raw_chain_bytes += ctx->res.leader->size;
      _http_perform_write(ctx, &mask);
      ctx->req.complete = mtev_true;
      if(ctx->res.leader != NULL) return mask;
    }
    if(rv == mtev_true) return mask | EVENTER_WRITE | EVENTER_EXCEPTION;
  }
  /* Not reached:
   * return EVENTER_READ | EVENTER_EXCEPTION;
   */
}
mtev_boolean
mtev_http_session_prime_input(mtev_http_session_ctx *ctx,
                              const void *data, size_t len) {
  if(ctx->req.first_input != NULL) return mtev_false;
  if(len > DEFAULT_BCHAINSIZE) return mtev_false;
  ctx->req.first_input = ctx->req.last_input =
      ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
  memcpy(ctx->req.first_input->buff, data, len);
  ctx->req.first_input->size = len;
  return mtev_true;
}

void
mtev_http_request_release(mtev_http_session_ctx *ctx) {
  if (ctx->req.freed == mtev_false) {
    mtev_hash_destroy(&ctx->req.querystring, NULL, NULL);
    mtev_hash_destroy(&ctx->req.headers, NULL, NULL);
    ctx->req.freed = mtev_true;
  }
  /* If we expected a payload, we expect a trailing \r\n */
  if(ctx->req.has_payload) {
    int drained, mask;
    ctx->drainage = ctx->req.content_length - ctx->req.content_length_read;
    /* best effort, we'll drain it before the next request anyway */
    drained = mtev_http_session_req_consume(ctx, NULL, ctx->drainage, 0, &mask);
    ctx->drainage -= drained;
  }
  RELEASE_BCHAIN(ctx->req.current_request_chain);
  if(ctx->req.orig_qs) free(ctx->req.orig_qs);
  /* If someone has jammed in a payload, clean that up too */
  if(ctx->req.upload.freefunc) {
    ctx->req.upload.freefunc(ctx->req.upload.data, ctx->req.upload.size,
                             ctx->req.upload.freeclosure);
  }

  /* free compression related things */
  if (ctx->req.decompress_ctx != NULL) {
    mtev_stream_decompress_finish(ctx->req.decompress_ctx);
    mtev_destroy_stream_decompress_ctx(ctx->req.decompress_ctx);
    ctx->req.decompress_ctx = NULL;
  }
  memset(&ctx->req.state, 0,
         sizeof(ctx->req) - (unsigned long)&(((mtev_http_request *)0)->state));
  
  ctx->req.freed = mtev_true;
}
void
mtev_http_response_release(mtev_http_session_ctx *ctx) {
  if (ctx->res.freed == mtev_false) {
    mtev_hash_destroy(&ctx->res.headers, free, free);
  }
  if(ctx->res.status_reason) free(ctx->res.status_reason);
  RELEASE_BCHAIN(ctx->res.leader);
  RELEASE_BCHAIN(ctx->res.output);
  RELEASE_BCHAIN(ctx->res.output_raw);
  if(ctx->res.compress_ctx) {
    mtev_stream_compress_finish(ctx->res.compress_ctx);
    mtev_destroy_stream_compress_ctx(ctx->res.compress_ctx);
  }
  memset(&ctx->res, 0, sizeof(ctx->res));
  ctx->res.freed = mtev_true;
}
void
mtev_http_ctx_session_release(mtev_http_session_ctx *ctx) {
  if(mtev_atomic_dec32(&ctx->ref_cnt) == 0) {
    mtev_http_request_release(ctx);
    if(ctx->req.user_data) RELEASE_BCHAIN(ctx->req.user_data);
    if(ctx->req.first_input) RELEASE_BCHAIN(ctx->req.first_input);
    mtev_http_response_release(ctx);
    pthread_mutex_destroy(&ctx->write_lock);
#ifdef HAVE_WSLAY
    if (ctx->is_websocket == mtev_true) {
      wslay_event_context_free(ctx->wslay_ctx);
    }
#endif
    free(ctx);
  }
}
void
mtev_http_ctx_acceptor_free(void *v) {
  mtev_http_ctx_session_release((mtev_http_session_ctx *)v);
}
static int
mtev_http_session_req_consume_read(mtev_http_session_ctx *ctx, 
                                      mtev_compress_type compression_type,
                                      int *mask) {
  /* chunked encoding read */
  int next_chunk = ctx->req.payload_chunked ? -1 : 0;
  /* We attempt to consume from the first_input */
  struct bchain *in, *tofree;
  const char *str_in_f;
  while(1) {
    int rlen;
    in = ctx->req.first_input;
    if(!in) {
      in = ctx->req.first_input = ctx->req.last_input =
        ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
    }

    if (ctx->req.payload_chunked == mtev_false) {
      if (in->size == in->allocd) {
        next_chunk = in->size;
        goto successful_chunk_size;
      }
    } else {
      str_in_f = strnstrn("\r\n", 2, in->buff + in->start, in->size);
      if(str_in_f) {
        unsigned int clen = 0;
        const char *cp = in->buff + in->start;
        const char *cp_begin = in->buff + in->start;
        while(cp <= str_in_f) {
          if(*cp >= '0' && *cp <= '9') clen = (clen << 4) | (*cp - '0');
          else if(*cp >= 'a' && *cp <= 'f') clen = (clen << 4) | (*cp - 'a' + 10);
          else if(*cp >= 'A' && *cp <= 'F') clen = (clen << 4) | (*cp - 'A' + 10);
          else if(*cp == '\r' && cp[1] == '\n') {
            mtevL(http_debug, "Found for chunk length(%d)\n", clen);
            if (in->size - 2 >= clen) {
              next_chunk = clen;
              in->start += cp - cp_begin + 2;
              in->size -= cp - cp_begin + 2;
              goto successful_chunk_size;
            } else {
              /**
               * we have decoded a chunk length but the current bchain
               * is not large enough to handle the entire chunk.
               * 
               * In this case we allocate a new bchain which is large
               * enough to hold the entire chunk, copy in the chunk data that
               * we have already read and then keep reading.
               */
              struct bchain *new_in = ALLOC_BCHAIN(MAX(clen + (cp - cp_begin + 2), 
                                                       DEFAULT_BCHAINSIZE));
              memcpy(new_in->buff, cp_begin, in->size);
              new_in->size = in->size;
              new_in->start = 0;
              new_in->compression = in->compression;
              new_in->next = in->next;
            
              /* the current 'in' buffer must be consumed as it's data was copied */
              ctx->req.first_input = ctx->req.last_input = new_in;
              in->next = NULL;
              RELEASE_BCHAIN(in);
              break;
            }
          }
          else {
            mtevL(mtev_error, "chunked input encoding error: '%02x'\n", *cp);
            return -2;
          }
          cp++;
        }
      }
    }

    in = ctx->req.last_input;
    if (!in) {
      in = ctx->req.first_input = ctx->req.last_input =
          ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
    }
    else if (in->start + in->size >= in->allocd) {
      in->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      in = ctx->req.last_input = in->next;
    }
    /* pull next chunk */
    if (ctx->conn.e == NULL) return -1;
    rlen = ctx->conn.e->opset->read(ctx->conn.e->fd,
                                    in->buff + in->start + in->size,
                                    in->allocd - in->size - in->start,
                                    mask, ctx->conn.e);
    mtevL(http_debug, " mtev_http -> read(%d) = %d\n", ctx->conn.e->fd, rlen);
    if(rlen > 0)
      mtevL(http_io, " mtev_http:read(%d) => %d [\n%.*s\n]\n", ctx->conn.e->fd, rlen, rlen, in->buff + in->start + in->size);
    else
      mtevL(http_io, " mtev_http:read(%d) => %d\n", ctx->conn.e->fd, rlen);
    if(rlen == -1 && errno == EAGAIN) {
      /* We'd block to read more, but we have data,
       * so do a short read */
      if(ctx->req.first_input && ctx->req.first_input->size) break;
      /* We've got nothing... */
      mtevL(http_debug, " ... mtev_http_session_req_consume = -1 (EAGAIN)\n");
      return -1;
    }
    if(rlen <= 0) {
      mtevL(http_debug, " ... mtev_http_session_req_consume = -1 (error)\n");
      return -2;
    }
    in->size += rlen;
    if (ctx->req.payload_chunked == mtev_false) {
      next_chunk += rlen;
    }
  }

 successful_chunk_size:
  {
    if (next_chunk > 0) {
      mtevL(http_debug, " ... have chunk (%d)\n", next_chunk);
      struct bchain *data = ALLOC_BCHAIN(next_chunk);
      data->compression = compression_type;
      if (ctx->req.user_data_last != NULL) {
        ctx->req.user_data_last->next = data;
      }
      ctx->req.user_data_last = data;
      if (ctx->req.user_data == NULL) {
        ctx->req.user_data = data;
      }
      memcpy(data->buff + data->size, in->buff + in->start, MIN(in->size, next_chunk));
      data->size = MIN(in->size, next_chunk);
      in->start += data->size;
      in->size -= data->size;
      ctx->req.user_data_last = data;
      if (ctx->req.payload_chunked) {
        /* there must be a \r\n at the end of this block */
        str_in_f = strnstrn("\r\n", 2, in->buff + in->start, in->size);
        if(in->size < 2 || strncmp(in->buff + in->start, "\r\n", 2) != 0) {
          mtevL(mtev_error, "HTTP chunked encoding error, no trailing CRLF.\n");
          return -2;
        }
        /* skip the \r\n framing */
        in->size-=2;
        in->start+=2;
      }
    } else if (next_chunk == 0 && ctx->req.payload_chunked) {
      mtevL(http_debug, " ... last chunked chunk\n");
      /* all that's left is \r\n, just consume this framing */
      in->size -= 2;
    }

    if(in->size == 0) {
      tofree = in;
      ctx->req.first_input = in = in->next;
      if(ctx->req.last_input == tofree) ctx->req.last_input = in;
      tofree->next = NULL;
      RELEASE_BCHAIN(tofree);
    }
  }
  return next_chunk;
}

/* will uncompress the chain at 'in' and write uncompressed chain at 'out' with
 * the last member of the out chain in 'last_out'
 * 
 * return -1 on error
 * otherwise return total_uncompressed_size 
 * */
static ssize_t
mtev_http_session_decompress(mtev_compress_type type, struct bchain *in, 
                             mtev_http_session_ctx *ctx, 
                             struct bchain **out, struct bchain **last_out)
{
  ssize_t total_decompressed_size = 0;
  mtev_stream_decompress_ctx_t *dctx = ctx->req.decompress_ctx;
  if (dctx == NULL) {
    dctx = ctx->req.decompress_ctx = mtev_create_stream_decompress_ctx();
    if (mtev_stream_decompress_init(dctx, type) < 0) {
      mtev_destroy_stream_decompress_ctx(dctx);
      ctx->req.decompress_ctx = NULL;
      return -1;
    }
  }

  if (*out == NULL) {
    *out = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
  }
  struct bchain *o = *out;
  *last_out = *out;
  while (in && in->size) {
    size_t out_size = o->allocd - o->size;
    if (out_size == 0) {
      struct bchain *temp = o;
      o = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      temp->next = o;
      *last_out = o;
      out_size = o->allocd;
    }
    size_t in_size = in->size;
    int x = mtev_stream_decompress(dctx, (const unsigned char *)(in->buff + in->start),
                                   &in_size, (unsigned char *)(o->buff + o->size),
                                   &out_size);
    if (x != 0) {
      mtevL(mtev_error, "Error decompressing: %d\n", x);
      mtev_stream_decompress_finish(dctx);
      mtev_destroy_stream_decompress_ctx(dctx);
      ctx->req.decompress_ctx = NULL;
      RELEASE_BCHAIN(*out);
      *out = NULL;
      errno = -errno;
      return -1;
    }
    o->size += out_size;
    total_decompressed_size += out_size;
    in->size -= in_size;
    in->start += in_size;
  }
  (*last_out)->next = NULL;
  return total_decompressed_size;
}

/**
 * strategy here is to:
 * 
 * 1. read from socket into ctx->req.last_input
 * 2a. if chunked, process chunks into ctx->req.user_data_last
 * 2b. if not chunked, process raw buffers into ctx->req.user_data_last
 * 
 * As an optimization in this step we can move the chain links to the other list
 * but have to tread carefully.
 * 
 * The above 3 steps are implemented in \sa mtev_http_session_req_consume_chunked
 * 
 * 3a. if compressed, decompress chain links and append to ctx->req.user_data_last
 * 
 * This leaves a chain that looks like "CCCCCDDDDDDDDDDDDDDDCCCC" where
 * C == compressed and D == decompressed.  We read through all C blocks, creating
 * D blocks and then goto 4 if we hit a D block.
 * 
 * \sa mtev_http_session_decompress
 * 
 * 4. if uncompressed block, read out into user buffer
 * 5. goto 1
 * 
 * We know we are done when:
 * 
 * chunked: we have read the zero length end chunk and there is nothing left in user_data
 * non-chunked: we have read ctx->req.content_length bytes and there is nothing left in user_data
 */
int
mtev_http_session_req_consume(mtev_http_session_ctx *ctx,
                              void *buf, size_t user_len, size_t blen,
                              int *mask) 
{
  struct bchain *in, *tofree;
  size_t bytes_read = 0;
  mtev_compress_type compression_type = request_compression_type(&ctx->req);

  if(ctx->req.payload_chunked) {
    if (ctx->req.read_last_chunk == mtev_false) {
      int chunk_size = mtev_http_session_req_consume_read(ctx, compression_type, mask);
      mtevL(http_debug, " ... mtev_http_session_req_consume(%d) chunked -> %d\n",
            ctx->conn.e->fd, chunk_size);
      if(chunk_size == 0) {
        mtevL(http_debug, " ... mtev_http_session_req_consume(%d) read last chunk.\n",
              ctx->conn.e->fd);
        /* we have reached the end of the chunked input.  
         * switch off chunked reading and set the content length */
        ctx->req.read_last_chunk = mtev_true;
        ctx->req.content_length = ctx->req.content_length_read;
      }
      else if(chunk_size < 0) {
        mtevL(http_debug, " ... couldn't read chunk size\n");
        if (chunk_size == -2) {
          /* need something that is not EAGAIN to deal with unrecoverable error ENOTSUP? */
          errno = ENOTSUP;
        }
        return -1;
      } 
      else {
        ctx->req.content_length_read += chunk_size;
      }
    }
  } 
  else {
    if (ctx->req.content_length_read < ctx->req.content_length) {
      int rlen = mtev_http_session_req_consume_read(ctx, compression_type, mask);
      if (rlen >= 0) {
        ctx->req.content_length_read += rlen;
      } else if (rlen == -2) {
        errno = ENOTSUP;
        return -1;
      }
    }
  }
  while(bytes_read < user_len) {
    in = ctx->req.user_data;

    if (ctx->req.payload_chunked) {
      if (ctx->req.read_last_chunk == mtev_true && (in == NULL || in->size == 0)) {
        /* we have read all the chunks and there is nothing in the user_data list
         * we must be done */
        return 0;
      } else if (in == NULL || in->size == 0) {
        /* we haven't read the last_chunk but nothing in user data, retry on next call */
        errno = EAGAIN;
        return -1;
      }
    } else {
      if (ctx->req.content_length_read == ctx->req.content_length) {
        if (in == NULL || in->size == 0) {
          /* we read all input and nothing in user_data list, we must be done. */
          return 0;
        }
      } else {
        if (in == NULL || in->size == 0) {
          /* haven't consumed all content-length, try again on next call */
          errno = EAGAIN;
          return -1;
        }
      }
    }

    while(in && in->size && bytes_read < user_len) {

      if (in->compression != MTEV_COMPRESS_NONE) {
        mtevL(http_debug, " ... decompress bchain\n");
        size_t total_decompressed_size = 0;
        size_t total_compressed_size = 0;

        struct bchain *out = NULL;

        /* if we haven't fully consumed the last uncompressed block, use it up */
        if (ctx->req.user_data_last != NULL && 
            ctx->req.user_data_last->compression == MTEV_COMPRESS_NONE && 
            ctx->req.user_data_last->size < ctx->req.user_data_last->allocd) {
          out = ctx->req.user_data_last;
        }          
        struct bchain *last_out = NULL;
        total_compressed_size += in->size;
        ssize_t s = mtev_http_session_decompress(in->compression, in, ctx, 
                                                 &out, &last_out);
        if (s < 0) {
          errno = s;
          return -1;
        }
        total_decompressed_size += s;

        /* our newly produced uncompressed chain gets stuck on the end 
         * after we are through uncompressing we will read this out as normal */
        if (out && ctx->req.user_data_last && ctx->req.user_data_last != out) {
          ctx->req.user_data_last->next = out;
        }
        ctx->req.user_data_last = last_out;

        if (in->size == 0) {
          /* we have consumed this compressed input link, delete it */
          struct bchain *tofree = in;
          ctx->req.user_data = in = in->next;
          tofree->next = NULL;
          RELEASE_BCHAIN(tofree);
        }

        if (total_decompressed_size > 0) {
          /* rewrite expected read size based on decompressed size */
          user_len = MIN(user_len, total_decompressed_size);
        }
      }

      if (in && in->compression == MTEV_COMPRESS_NONE) {
        /* read uncompressed data into the user buffer */
        int partial_len = MIN(in->size, user_len - bytes_read);

        if(buf) memcpy((char *)buf+bytes_read, in->buff+in->start, partial_len);
        bytes_read += partial_len;
        mtevL(http_debug, " ... filling %d bytes (read through %d/%d)\n",
              (int)bytes_read, (int)ctx->req.content_length_read,
              (int)ctx->req.content_length);
        in->start += partial_len;
        in->size -= partial_len;
        if(in->size == 0) {
          tofree = in;
          ctx->req.user_data = in = in->next;
          tofree->next = NULL;
          RELEASE_BCHAIN(tofree);
          if(in == NULL) {
            ctx->req.user_data_last = NULL;
            if (bytes_read != 0) {
              mtevL(http_debug, " ... mtev_http_session_req_consume = %d\n",
                    (int)bytes_read);
              return bytes_read;
            }
          }
        }
      }
    }
    
    /* short circuit and read the rest off the wire later */
    if (bytes_read > 0 && bytes_read == user_len) {
      return bytes_read;
    }
  }
  /* NOT REACHED */
  return bytes_read;
}

/* this magic GUID is defined in the websocket specification and must
 * be what is used to create the accept key
 *
 * See: https://tools.ietf.org/html/rfc6455#page-6
 */
#define WS_ACCEPT_KEY_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_CLIENT_KEY_LEN 24

void
mtev_http_create_websocket_accept_key(char *dest, size_t dest_len, const char *client_key)
{
  SHA_CTX ctx;
  unsigned char sha1[SHA_DIGEST_LENGTH], key_src[UUID_STR_LEN + WS_CLIENT_KEY_LEN];

  mtevAssert(dest_len >= mtev_b64_encode_len(SHA_DIGEST_LENGTH) + 1);

  memcpy(key_src, client_key, WS_CLIENT_KEY_LEN);
  memcpy(key_src + WS_CLIENT_KEY_LEN, WS_ACCEPT_KEY_GUID, UUID_STR_LEN);

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, (const void *)key_src, (unsigned long)sizeof(key_src));
  SHA1_Final(sha1, &ctx);

  mtev_b64_encode(sha1, SHA_DIGEST_LENGTH, dest, dest_len);
  dest[mtev_b64_encode_len(SHA_DIGEST_LENGTH)] = '\0';
}

#ifdef HAVE_WSLAY
mtev_boolean
mtev_http_websocket_handshake(mtev_http_session_ctx *ctx)
{
  char accept_key[mtev_b64_encode_len(SHA_DIGEST_LENGTH) + 1];
  const char *upgrade = NULL, *connection = NULL, *sec_ws_key = NULL, *protocol = NULL;

  if (ctx->req.complete == mtev_false) {
    return mtev_false;
  }

  if (ctx->did_handshake == mtev_true) {
    return ctx->is_websocket;
  }

  ctx->did_handshake = mtev_true;

  mtev_hash_table *headers = mtev_http_request_headers_table(&ctx->req);
  if (headers == NULL) {
    ctx->is_websocket = mtev_false;
    return ctx->is_websocket;
  }

  (void)mtev_hash_retr_str(headers, "upgrade", strlen("upgrade"), &upgrade);
  (void)mtev_hash_retr_str(headers, "connection", strlen("connection"), &connection);
  (void)mtev_hash_retr_str(headers, "sec-websocket-key", strlen("sec-websocket-key"), &sec_ws_key);
  (void)mtev_hash_retr_str(headers, "sec-websocket-protocol", strlen("sec-websocket-protocol"), &protocol);

  if (upgrade == NULL || connection == NULL || sec_ws_key == NULL || protocol == NULL) {
    ctx->is_websocket = mtev_false;
    return ctx->is_websocket;
  }

  if (strlen(sec_ws_key) != 24) {
    ctx->is_websocket = mtev_false;
    mtevL(mtev_error, "Incoming sec-websocket-key is invalid length, expected 24, got: %ul\n", (unsigned int)strlen(sec_ws_key));
    return ctx->is_websocket;
  }

  mtev_http_create_websocket_accept_key(accept_key, sizeof(accept_key), sec_ws_key);

  /* now we upgrade their socket */
  mtev_http_response_header_set(ctx, "Upgrade", "websocket");
  mtev_http_response_header_set(ctx, "Connection", "Upgrade");
  mtev_http_response_header_set(ctx, "Sec-WebSocket-Accept", accept_key);
  mtev_http_response_header_set(ctx, "Sec-WebSocket-Protocol", protocol);
  mtev_http_response_status_set(ctx, 101, "Switching Protocols");

  /* there is no body and this is not the final */
  ctx->is_websocket = mtev_http_response_flush(ctx, false);
  return ctx->is_websocket;
}

static ssize_t
wslay_send_callback(wslay_event_context_ptr ctx,
                    const uint8_t *data, size_t len, int flags,
                    void *user_data)
{
  ssize_t r;
  mtev_http_session_ctx *session_ctx = user_data;
  session_ctx->wanted_eventer_mask = 0;

  pthread_mutex_lock(&session_ctx->write_lock);
  if(!session_ctx->conn.e || session_ctx->is_websocket == mtev_false) {
    pthread_mutex_unlock(&session_ctx->write_lock);
    wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }


  while((r = session_ctx->conn.e->opset->
         write(session_ctx->conn.e->fd,
               data, len, &session_ctx->wanted_eventer_mask, session_ctx->conn.e)) == -1 && errno == EINTR);
  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  }
  mtevL(http_io, "   <- wslay_send_callback, sent (%d)\n", (int)r);

  pthread_mutex_unlock(&session_ctx->write_lock);
  return r;
}

static ssize_t
wslay_recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
                    int flags, void *user_data)
{
  ssize_t r;
  mtev_http_session_ctx *session_ctx = user_data;
  session_ctx->wanted_eventer_mask = 0;

  if(!session_ctx->conn.e || session_ctx->is_websocket == mtev_false) {
    wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }

  while((r = session_ctx->conn.e->opset->read(session_ctx->conn.e->fd,
                                              buf, len, &session_ctx->wanted_eventer_mask,
                                              session_ctx->conn.e)) == -1
        && errno == EINTR);
  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (r == 0) {
    wslay_event_set_error(session_ctx->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    r = -1;
  }
  mtevL(http_io, "   -> wslay_recv_callback, read (%d)\n", (int) r);
  return r;
}

static void
wslay_on_msg_recv_callback(wslay_event_context_ptr ctx,
                           const struct wslay_event_on_msg_recv_arg *arg,
                           void *user_data)
{
  mtev_http_session_ctx *session_ctx = user_data;
  int rv = 0;

  if (!wslay_is_ctrl_frame(arg->opcode)) {
    if (session_ctx->websocket_dispatcher != NULL) {
      mtevL(http_debug, "   <- websocket_dispatch (%d)\n", session_ctx->conn.e->fd);
      rv = session_ctx->websocket_dispatcher(session_ctx, arg->opcode, arg->msg, arg->msg_length);
      mtevL(http_debug, "   <- websocket_dispatch (%d) == %d\n", session_ctx->conn.e->fd, rv);
      if (rv != 0) {
        /* force the drive loop to abandon this as a websocket */
        session_ctx->is_websocket = mtev_false;
      }
    } else {
       mtevL(mtev_error, "session_ctx has no websocket_dispatcher function set\n");
       session_ctx->is_websocket = mtev_false;
    }
  }
}
#endif //HAVE_WSLAY

int
mtev_http_session_drive(eventer_t e, int origmask, void *closure,
                        struct timeval *now, int *done) {
  mtev_http_session_ctx *ctx = closure;
  int rv = 0;
  int mask = origmask;

  if(origmask & EVENTER_EXCEPTION)
    goto abort_drive;

  /* Drainage -- this is as nasty as it sounds
   * The last request could have unread upload content, we would have
   * noted that in mtev_http_request_release.
   */
  mtevL(http_debug, " -> mtev_http_session_drive(%d) [%x]\n", e->fd, origmask);
  while(ctx->drainage > 0) {
    int len;
    mtevL(http_debug, "   ... draining last request(%d)\n", e->fd);
    len = mtev_http_session_req_consume(ctx, NULL, ctx->drainage, 0, &mask);
    if(len == -1 && errno == EAGAIN) {
      mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd, mask);
      return mask;
    }
    if(len <= 0) goto abort_drive;
    ctx->drainage -= len;
  }

 next_req:
  if(ctx->req.complete != mtev_true) {
    int maybe_write_mask;
    mtevL(http_debug, "   -> mtev_http_complete_request(%d)\n", e->fd);
    mask = mtev_http_complete_request(ctx, origmask);
    mtevL(http_debug, "   <- mtev_http_complete_request(%d) = %d\n",
          e->fd, mask);
    if(ctx->conn.e == NULL) goto release;

#ifdef HAVE_WSLAY
    if (ctx->did_handshake == mtev_false) {
      mtevL(http_debug, "   -> checking for websocket(%d)\n", e->fd);
      mtev_http_websocket_handshake(ctx);
    }

    if (ctx->is_websocket == mtev_true) {
      mtevL(http_debug, "   ... *is* websocket(%d)\n", e->fd);
      /* init the wslay library for websocket communication */
      wslay_event_context_server_init(&ctx->wslay_ctx, &wslay_callbacks, ctx);
    } else {
#endif
      _http_perform_write(ctx, &maybe_write_mask);
      if(ctx->req.complete != mtev_true) {
        mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd,
              mask|maybe_write_mask);
        return mask | maybe_write_mask;
      }
#ifdef HAVE_WSLAY
    }
#endif

    mtevL(http_debug, "HTTP start request (%s)\n", ctx->req.uri_str);
    mtev_http_process_querystring(&ctx->req);
    inplace_urldecode(ctx->req.uri_str);

    /* do zipkin spans make sense for websockets? */
    if (ctx->is_websocket == mtev_false) {
      begin_span(ctx);
    }
  }

  if (ctx->is_websocket == mtev_true) {
    /* dispatcher is called differently under websockets, it is handled
     * by the wslay event callbacks.
     *
     * In addition, since websockets are meant for message passing, we call a special
     * dispatch function when we have fully received a websocket message.
     */
#ifdef HAVE_WSLAY
    if (wslay_event_want_read(ctx->wslay_ctx) == 0 && wslay_event_want_write(ctx->wslay_ctx) == 0) {
      /* this is a serious wslay error, abort */
      goto abort_drive;
    }

    mtevL(http_debug, "   -> mtev_http_session_drive, websocket recv(%d)\n", e->fd);
    if (wslay_event_recv(ctx->wslay_ctx) != 0) {
      /* serious error on the `recv` side, abort */
      goto abort_drive;
    }

    mtevL(http_debug, "   <- mtev_http_session_drive, websocket send(%d)\n", e->fd);
    if (wslay_event_send(ctx->wslay_ctx) != 0) {
      goto abort_drive;
    }

    /* this could be a very long lived socket
     * return for now and await another IO event to trigger
     * more communication
     */
    *done = 0;
    return ctx->wanted_eventer_mask | EVENTER_EXCEPTION | EVENTER_WRITE;
#endif

  } else {
    /* only dispatch if the response is not closed */
    if(ctx->res.closed == mtev_false) {
      mtevL(http_debug, "   -> dispatch(%d)\n", e->fd);
      rv = ctx->dispatcher(ctx);
      mtevL(http_debug, "   <- dispatch(%d) = %d\n", e->fd, rv);
    }
  }
  if(ctx->conn.e) {
    eventer_t registered_e = eventer_find_fd(e->fd);
    if(registered_e != ctx->conn.e) {
      mtevL(http_debug, " <- mtev_http_session_drive(%d) [handsoff:%x]\n", e->fd, rv);
      return rv;
    }
  }

  _http_perform_write(ctx, &mask);
  if(ctx->res.complete == mtev_true &&
     ctx->conn.e &&
     ctx->conn.needs_close == mtev_true) {
   abort_drive:
    mtev_http_log_request(ctx);
    if(ctx->conn.e) {
      ctx->conn.e->opset->close(ctx->conn.e->fd, &mask, ctx->conn.e);
      ctx->conn.e = NULL;
    }
    goto release;
  }
  if(ctx->res.complete == mtev_true) {
    end_span(ctx);
    mtev_http_log_request(ctx);
    mtev_http_request_release(ctx);
    mtev_http_response_release(ctx);
  }
  if(ctx->req.complete == mtev_false) goto next_req;
  if(ctx->conn.e) {
    mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd, mask|rv);
    return mask | rv;
  }
  mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd, 0);
  goto abort_drive;

 release:
  *done = 1;
  /* We're about to release, unhook us from the acceptor_closure so we
   * don't get double freed */
  if(ctx->ac->service_ctx == ctx) ctx->ac->service_ctx = NULL;
  mtev_http_ctx_session_release(ctx);
  mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd, 0);
  return 0;
}

mtev_http_session_ctx *
mtev_http_session_ctx_new(mtev_http_dispatch_func f, void *c, eventer_t e, acceptor_closure_t *ac)
{
  return mtev_http_session_ctx_websocket_new(f, NULL, c, e, ac);
}

mtev_http_session_ctx *
mtev_http_session_ctx_websocket_new(mtev_http_dispatch_func f, mtev_http_websocket_dispatch_func wf,
                                    void *c, eventer_t e, acceptor_closure_t *ac)
{
  mtev_http_session_ctx *ctx;
  ctx = calloc(1, sizeof(*ctx));
  ctx->ref_cnt = 1;
  pthread_mutex_init(&ctx->write_lock, NULL);
  ctx->req.complete = mtev_false;
  mtev_hash_init(&ctx->req.headers);
  mtev_hash_init(&ctx->req.querystring);
  mtev_hash_init(&ctx->res.headers);
  ctx->conn.e = e;
  ctx->max_write = DEFAULT_MAXWRITE;
  ctx->dispatcher = f;
  ctx->dispatcher_closure = c;
  ctx->websocket_dispatcher = wf;
  ctx->ac = ac;
  ctx->is_websocket = mtev_false;
#ifdef HAVE_WSLAY
  ctx->did_handshake = mtev_false;
  ctx->wslay_ctx = NULL;
#endif
  return ctx;
}

mtev_boolean
mtev_http_response_status_set(mtev_http_session_ctx *ctx,
                              int code, const char *reason) {
  check_realloc_response(&ctx->res);
  if(ctx->res.output_started == mtev_true) return mtev_false;
  ctx->res.protocol = ctx->req.protocol;
  if(code < 100 || code > 999) return mtev_false;
  ctx->res.status_code = code;
  if(ctx->res.status_reason) free(ctx->res.status_reason);
  ctx->res.status_reason = strdup(reason);
  return mtev_true;
}
mtev_boolean
mtev_http_response_header_set(mtev_http_session_ctx *ctx,
                              const char *name, const char *value) {
  check_realloc_response(&ctx->res);
  if(ctx->res.output_started == mtev_true) return mtev_false;
  mtev_hash_replace(&ctx->res.headers, strdup(name), strlen(name),
                    strdup(value), free, free);
  return mtev_true;
}
mtev_boolean
mtev_http_response_option_set(mtev_http_session_ctx *ctx, uint32_t opt) {
  check_realloc_response(&ctx->res);
  if(ctx->res.output_started == mtev_true) return mtev_false;
  /* transfer and content encodings only allowed in HTTP/1.1 */
  if(ctx->res.protocol != MTEV_HTTP11 &&
     (opt & MTEV_HTTP_CHUNKED))
    return mtev_false;
  if(ctx->res.protocol != MTEV_HTTP11 &&
     (opt & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)))
    return mtev_false;
  if(((ctx->res.output_options | opt) &
      (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)) ==
        (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F))
    return mtev_false;

  /* Check out "accept" set */
  if(!(opt & ctx->req.opts)) return mtev_false;

  ctx->res.output_options |= opt;
  if(ctx->res.output_options & MTEV_HTTP_CHUNKED)
    CTX_ADD_HEADER("Transfer-Encoding", "chunked");
  if(ctx->res.output_options & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)) {
    CTX_ADD_HEADER("Vary", "Accept-Encoding");
    if(ctx->res.output_options & MTEV_HTTP_GZIP)
      CTX_ADD_HEADER("Content-Encoding", "gzip");
    else if(ctx->res.output_options & MTEV_HTTP_DEFLATE)
      CTX_ADD_HEADER("Content-Encoding", "deflate");
    else if(ctx->res.output_options & MTEV_HTTP_LZ4F)
      CTX_ADD_HEADER("Content-Encoding", "lz4f");
  }
  if(ctx->res.output_options & MTEV_HTTP_CLOSE) {
    CTX_ADD_HEADER("Connection", "close");
    ctx->conn.needs_close = mtev_true;
  }
  return mtev_true;
}
mtev_boolean
mtev_http_response_append(mtev_http_session_ctx *ctx,
                          const void *b, size_t l) {
  struct bchain *o;
  int boff = 0;
  if(ctx->res.closed == mtev_true) return mtev_false;
  check_realloc_response(&ctx->res);
  if(ctx->res.output_started == mtev_true &&
     !(ctx->res.output_options & (MTEV_HTTP_CLOSE | MTEV_HTTP_CHUNKED)))
    return mtev_false;
  if(!ctx->res.output)
    ctx->res.output_last = ctx->res.output = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
  mtevAssert(ctx->res.output != NULL);
  mtevAssert(ctx->res.output_last != NULL);
  o = ctx->res.output_last;
  ctx->res.output_chain_bytes += l;
  while(l > 0) {
    if(o->allocd == o->start + o->size) {
      /* Filled up, need another */
      o->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      o->next->prev = o->next;
      o = o->next;
      ctx->res.output_last = o;
    }
    if(o->allocd > o->start + o->size) {
      int tocopy = MIN(l, o->allocd - o->start - o->size);
      memcpy(o->buff + o->start + o->size, (const char *)b + boff, tocopy);
      o->size += tocopy;
      boff += tocopy;
      l -= tocopy;
    }
  }
  return mtev_true;
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
  if(len > sizeof(buffer)) {
    int allocd = sizeof(buffer);
    while(len > allocd) { /* guaranteed true the first time */
      if(len > allocd) allocd = len;
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
mtev_boolean
mtev_http_response_append_bchain(mtev_http_session_ctx *ctx,
                                 struct bchain *b) {
  struct bchain *o;
  if(ctx->res.closed == mtev_true) return mtev_false;
  check_realloc_response(&ctx->res);
  if(ctx->res.output_started == mtev_true &&
     !(ctx->res.output_options & (MTEV_HTTP_CHUNKED | MTEV_HTTP_CLOSE)))
    return mtev_false;
  if(!ctx->res.output_last)
    ctx->res.output_last = ctx->res.output = b;
  else {
    mtevAssert(ctx->res.output !=  NULL);
    mtevAssert(ctx->res.output_last !=  NULL);
    o = ctx->res.output_last;
    o->allocd = o->size; /* so we know it is full */
    o->next = b;
    b->prev = o;
    ctx->res.output_last = b;
  }
  ctx->res.output_chain_bytes += b->size;
  return mtev_true;
}
mtev_boolean
mtev_http_response_append_mmap(mtev_http_session_ctx *ctx,
                               int fd, size_t len, int flags, off_t offset) {
  struct bchain *n;
  check_realloc_response(&ctx->res);
  n = bchain_mmap(fd, len, flags, offset);
  if(n == NULL) return mtev_false;
  return mtev_http_response_append_bchain(ctx, n);
}
static int casesort(const void *a, const void *b) {
  return strcasecmp(*((const char **)a), *((const char **)b));
}
static int
_http_construct_leader(mtev_http_session_ctx *ctx) {
  int len = 0, tlen, kcnt;
  struct bchain *b;
  const char *protocol_str;
  int i;
  const char **keys;
  char *static_key_array[16];
  mtev_boolean cl_present = mtev_false;

  mtevAssert(!ctx->res.leader);
  ctx->res.leader = b = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);

  protocol_str = ctx->res.protocol == MTEV_HTTP11 ?
                   "HTTP/1.1" :
                   (ctx->res.protocol == MTEV_HTTP10 ?
                     "HTTP/1.0" :
                     "HTTP/0.9");
  tlen = snprintf(b->buff, b->allocd, "%s %03d %s\r\n",
                  protocol_str, ctx->res.status_code,
                  ctx->res.status_reason ? ctx->res.status_reason : "unknown");
  if(tlen < 0) return -1;
  len = b->size = tlen;

#define CTX_LEADER_APPEND(s, slen) do { \
  if(b->size + slen > DEFAULT_BCHAINSIZE) { \
    b->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE); \
    mtevAssert(b->next); \
    b->next->prev = b; \
    b = b->next; \
  } \
  mtevAssert(DEFAULT_BCHAINSIZE >= b->size + slen); \
  memcpy(b->buff + b->start + b->size, s, slen); \
  b->size += slen; \
} while(0)
  while(!cl_present) {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    i = 0;
    if (mtev_hash_size(&ctx->res.headers) < 16) {
      keys = (const char **)static_key_array;
    }
    else {
      keys = malloc(sizeof(*keys)*(mtev_hash_size(&ctx->res.headers)));
      mtevAssert(keys != NULL);
    }
    while(mtev_hash_adv(&ctx->res.headers, &iter)) {
      keys[i++] = iter.key.str;
      if(iter.klen == strlen(HEADER_CONTENT_LENGTH) &&
         !strncasecmp(iter.key.str, HEADER_CONTENT_LENGTH, strlen(HEADER_CONTENT_LENGTH))) {
        cl_present = mtev_true;
      }
    }
    /* One of these options will necessarily be set if we come through here
     * a second time.
     */
    if(ctx->res.output_options & (MTEV_HTTP_CHUNKED | MTEV_HTTP_CLOSE))
      cl_present = mtev_true;

    if(!cl_present) {
      if(mtev_http_response_option_set(ctx, MTEV_HTTP_CHUNKED) == mtev_false) {
        if(mtev_http_response_option_set(ctx, MTEV_HTTP_CLOSE) == mtev_false) {
          break; /* Something went horrible wrong, nothing we can do */
        }
      }
    }
    if (!cl_present && keys != (const char **)static_key_array) free(keys);
  }
  qsort(keys, i, sizeof(*keys), casesort);
  kcnt = i;
  for(i=0;i<kcnt;i++) {
    int vlen;
    const char *key = keys[i], *value;
    int klen = strlen(key);
    (void)mtev_hash_retr_str(&ctx->res.headers, key, klen, &value);
    vlen = strlen(value);
    CTX_LEADER_APPEND(key, klen);
    CTX_LEADER_APPEND(": ", 2);
    CTX_LEADER_APPEND(value, vlen);
    CTX_LEADER_APPEND("\r\n", 2);
  }
  CTX_LEADER_APPEND("\r\n", 2);
  ctx->res.output_raw_chain_bytes += b->size;
  if (keys != (const char **)static_key_array) free(keys);
  return len;
}

static mtev_boolean
_http_encode_chain(mtev_http_response *res,
                   struct bchain *out, void *inbuff, size_t *inlen,
                   mtev_boolean final, mtev_boolean *done) {
  int opts = res->output_options;
  if (done) *done = mtev_false;
  if (res->compress_ctx == NULL) {
    res->compress_ctx = mtev_create_stream_compress_ctx();
    if(opts & MTEV_HTTP_GZIP) {
      mtev_stream_compress_init(res->compress_ctx, MTEV_COMPRESS_GZIP);
    } else if(opts & MTEV_HTTP_DEFLATE) {
      mtev_stream_compress_init(res->compress_ctx, MTEV_COMPRESS_DEFLATE);
    } else if(opts & MTEV_HTTP_LZ4F) {
      mtev_stream_compress_init(res->compress_ctx, MTEV_COMPRESS_LZ4F);
    } else {
      mtev_stream_compress_init(res->compress_ctx, MTEV_COMPRESS_NONE);
    }
  }

  size_t olen;
  int err;
  olen = out->allocd - out->start - 2; /* leave 2 for the \r\n */
  if (inlen && *inlen > 0) {
    err = mtev_stream_compress(res->compress_ctx, inbuff, inlen,
                               (unsigned char *)(out->buff + out->start), &olen);
    if (err != 0) {
      return mtev_false;
    }
    out->size += olen;
  }

  if (final == mtev_true) {
    struct bchain *o = out;
    olen = o->allocd - o->start - 2;
    err = mtev_stream_compress_flush(res->compress_ctx, 
                                     (unsigned char *)(o->buff + o->start), 
                                     &olen);
    if (err != 0) {
      return mtev_false;
    }
    if (olen == 0) {
      if (done) *done = mtev_true;
    }
    o->size += olen;
  }
  return mtev_true;
}

static struct bchain *
mtev_http_process_output_bchain(mtev_http_session_ctx *ctx,
                                struct bchain *in,
                                size_t *leftover_size) {
  struct bchain *out;
  int ilen, maxlen = in->size, hexlen;
  int opts = ctx->res.output_options;

  if(in->type == BCHAIN_MMAP &&
     0 == (opts & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F | MTEV_HTTP_CHUNKED))) {
    out = ALLOC_BCHAIN(0);
    out->buff = in->buff;
    out->type = in->type;
    out->size = in->size;
    out->allocd = in->allocd;
    in->type = BCHAIN_INLINE;
    return out;
  }
  /* a chunked header looks like: hex*\r\ndata\r\n */
  /* let's assume that content never gets "larger" */
  if(opts & MTEV_HTTP_GZIP) maxlen = mtev_compress_bound(MTEV_COMPRESS_GZIP, in->size);
  else if(opts & MTEV_HTTP_DEFLATE) maxlen = mtev_compress_bound(MTEV_COMPRESS_DEFLATE, in->size);
  else if(opts & MTEV_HTTP_LZ4F) maxlen = mtev_compress_bound(MTEV_COMPRESS_LZ4F, in->size);

  /* So, the link size is the len(data) + 4 + ceil(log(len(data))/log(16)) */
  ilen = maxlen;
  hexlen = 0;
  while(ilen) { ilen >>= 4; hexlen++; }
  if(hexlen == 0) hexlen = 1;

  out = ALLOC_BCHAIN(hexlen + 4 + maxlen);
  /* if we're chunked, let's give outselved hexlen + 2 prefix space */
  if(opts & MTEV_HTTP_CHUNKED) out->start = hexlen + 2;
  *leftover_size = in->size;
  if(_http_encode_chain(&ctx->res, out, in->buff + in->start, leftover_size,
                        mtev_false, NULL) == mtev_false) {
    free(out);
    return NULL;
  }
  if(out->size == 0) {
    FREE_BCHAIN(out);
    out = ALLOC_BCHAIN(0);
  }
  if((out->size > 0) && (opts & MTEV_HTTP_CHUNKED)) {
    ilen = out->size;
    mtevAssert(out->start+out->size+2 <= out->allocd);
    out->buff[out->start + out->size++] = '\r';
    out->buff[out->start + out->size++] = '\n';
    out->start = 0;
    /* terminate */
    out->size += 2;
    out->buff[hexlen] = '\r';
    out->buff[hexlen+1] = '\n';
    /* backfill */
    out->size += hexlen;
    while(hexlen > 0) {
      out->buff[hexlen - 1] = _hexchars[ilen & 0xf];
      ilen >>= 4;
      hexlen--;
    }
    while(out->buff[out->start] == '0') {
      out->start++;
      out->size--;
    }
  }
  return out;
}
void
raw_finalize_encoding(mtev_http_response *res) {
  if(res->output_options & MTEV_HTTP_GZIP) {
    mtev_boolean finished = mtev_false;
    struct bchain *r = res->output_raw_last;
    mtevAssert((r == NULL && res->output_raw == NULL) ||
           (r != NULL && res->output_raw != NULL));
    while(finished == mtev_false) {
      int hexlen, ilen;
      struct bchain *out = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);

      /* The link size is the len(data) + 4 + ceil(log(len(data))/log(16)) */
      ilen = out->allocd;
      hexlen = 0;
      while(ilen) { ilen >>= 4; hexlen++; }
      if(hexlen == 0) hexlen = 1;

      out->start += hexlen + 2;
      if(_http_encode_chain(res, out, "", 0, mtev_true,
                            &finished) == mtev_false) {
        FREE_BCHAIN(out);
        break;
      }

      ilen = out->size;
      if (ilen > 0) {
        mtevAssert(out->start+out->size+2 <= out->allocd);
        out->buff[out->start + out->size++] = '\r';
        out->buff[out->start + out->size++] = '\n';
        out->start = 0;
        /* terminate */
        out->size += 2;
        out->buff[hexlen] = '\r';
        out->buff[hexlen+1] = '\n';
        /* backfill */
        out->size += hexlen;
        while(hexlen > 0) {
          out->buff[hexlen - 1] = _hexchars[ilen & 0xf];
          ilen >>= 4;
          hexlen--;
        }
        while(out->buff[out->start] == '0') {
          out->start++;
          out->size--;
        }
        if(r == NULL)
          res->output_raw = out;
        else {
          mtevAssert(r == res->output_raw_last);
          r->next = out;
          out->prev = r;
        }
        res->output_raw_last = r = out;
        res->output_raw_chain_bytes += out->size;
      } 
      else {
        FREE_BCHAIN(out);
      }
    }

    mtev_stream_compress_finish(res->compress_ctx);
    mtev_destroy_stream_compress_ctx(res->compress_ctx);
    res->compress_ctx = NULL;
  }
}
static mtev_boolean
_mtev_http_response_flush(mtev_http_session_ctx *ctx,
                          mtev_boolean final,
                          mtev_boolean update_eventer) {
  struct bchain *o, *r;
  int mask, rv;

  if(ctx->res.closed == mtev_true) return mtev_false;
  if(ctx->res.output_started == mtev_false) {
    _http_construct_leader(ctx);
    ctx->res.output_started = mtev_true;
    mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, ZIPKIN_SERVER_SEND, false);
  }
  /* encode output to output_raw */
  r = ctx->res.output_raw_last;
  mtevAssert((r == NULL && ctx->res.output_raw == NULL) ||
         (r != NULL && ctx->res.output_raw != NULL));
  /* r is the last raw output link */
  o = ctx->res.output;
  /* o is the first output link to process */
  while(o) {
    struct bchain *tofree, *n;
    size_t leftover_size = 0;
    n = mtev_http_process_output_bchain(ctx, o, &leftover_size);
    if(!n) {
      /* Bad, response stops here! */
      mtevL(mtev_error, "mtev_http_process_output_bchain: NULL\n");
      while(o) {
        tofree = o;
        o = o->next;
        ctx->res.output_chain_bytes -= tofree->size;
        free(tofree);
      }
      final = mtev_true;
      break;
    }
    if (n->size > 0) {
      if(r) {
        r->next = n;
        n->prev = r;
        r = ctx->res.output_raw_last = n;
      }
      else {
        r = ctx->res.output_raw = ctx->res.output_raw_last = n;
      }
    }
    ctx->res.output_raw_chain_bytes += n->size;
    ctx->res.output_chain_bytes -= o->size - leftover_size;
    o->start = o->size - leftover_size;
    o->size = leftover_size;
    if (o->size == 0) {
      tofree = o; 
      o = o->next;
      tofree->next = NULL;
      FREE_BCHAIN(tofree); /* advance and free */
    }
    if (n->size == 0) {
      RELEASE_BCHAIN(n);
    }
  }
  ctx->res.output = NULL;
  ctx->res.output_last = NULL;
  ctx->res.output_chain_bytes = 0;
  if(final) {
    struct bchain *n;
    ctx->res.closed = mtev_true;
    raw_finalize_encoding(&ctx->res);
    r = ctx->res.output_raw_last;
    /* Create an ending */
    if(ctx->res.output_options & MTEV_HTTP_CHUNKED)
      n = bchain_from_data("0\r\n\r\n", 5);
    else
      n = NULL;
    /* Append an ending (chunked) */
    if(r) {
      r->next = n;
      if(n) {
        ctx->res.output_raw_last = n;
        n->prev = r;
      }
    }
    else {
      ctx->res.output_raw = ctx->res.output_raw_last = n;
    }
    if(n) ctx->res.output_raw_chain_bytes += n->size;
  }

  rv = _http_perform_write(ctx, &mask);
  if(update_eventer && ctx->conn.e &&
     eventer_find_fd(ctx->conn.e->fd) == ctx->conn.e) {
      eventer_update(ctx->conn.e, mask);
  }
  if(rv < 0) return mtev_false;
  /* If the write fails completely, the event will not be closed,
   * the following should not trigger the false case.
   */
  return ctx->conn.e ? mtev_true : mtev_false;
}

size_t
mtev_http_response_buffered(mtev_http_session_ctx *ctx) {
  return ctx->res.output_raw_chain_bytes + ctx->res.output_chain_bytes;
}
mtev_boolean
mtev_http_response_flush(mtev_http_session_ctx *ctx,
                         mtev_boolean final) {
  return _mtev_http_response_flush(ctx, final, mtev_true);
}
mtev_boolean
mtev_http_response_flush_asynch(mtev_http_session_ctx *ctx,
                                mtev_boolean final) {
  return _mtev_http_response_flush(ctx, final, mtev_false);
}

mtev_boolean
mtev_http_response_end(mtev_http_session_ctx *ctx) {
  if(!mtev_http_response_flush(ctx, mtev_true)) {
    return mtev_false;
  }
  return mtev_true;
}

mtev_boolean
mtev_http_websocket_queue_msg(mtev_http_session_ctx *ctx, int opcode,
                              const unsigned char *msg, size_t msg_len)
{
#ifdef HAVE_WSLAY
  if (ctx->is_websocket == mtev_false || ctx->wslay_ctx == NULL) {
    return mtev_false;
  }
  struct wslay_event_msg msgarg = {
    opcode, msg, msg_len
  };
  return !wslay_event_queue_msg(ctx->wslay_ctx, &msgarg);
#else
  return mtev_false;
#endif
}

/* Helper functions */

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

Zipkin_Span *
mtev_http_zipkip_span(mtev_http_session_ctx *ctx) {
  return ctx->zipkin_span;
}

void
mtev_http_init() {
  struct in_addr remote = { .s_addr = 0xffffffff };
  double np = 0.0, pp = 1.0, dp = 1.0;
  mtev_getip_ipv4(remote, &zipkin_ip_host);

  zipkin_ip_host.s_addr = ntohl(zipkin_ip_host.s_addr);
  (void)mtev_conf_get_double(NULL, "//zipkin//probability/@new", &np);
  (void)mtev_conf_get_double(NULL, "//zipkin//probability/@parented", &pp);
  (void)mtev_conf_get_double(NULL, "//zipkin//probability/@debug", &dp);
  mtev_zipkin_sampling(np,pp,dp);

  http_debug = mtev_log_stream_find("debug/http");
  http_access = mtev_log_stream_find("http/access");
  http_io = mtev_log_stream_find("http/io");
}
