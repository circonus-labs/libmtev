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
#include "mtev_str.h"
#include "mtev_getip.h"
#include "mtev_zipkin.h"
#include "mtev_conf.h"

#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <zlib.h>
#include <sys/mman.h>
#include <libxml/tree.h>
#include <pthread.h>

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
  struct bchain *current_input;  /* The point of the input where we */
  size_t         current_offset; /* analyzing. */

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
  int32_t next_chunk;
  int32_t next_chunk_read;
  char *method_str;
  char *uri_str;
  char *protocol_str;
  mtev_hash_table querystring;
  u_int32_t opts;
  mtev_http_method method;
  mtev_http_protocol protocol;
  mtev_hash_table headers;
  mtev_boolean complete;
  struct timeval start_time;
  char *orig_qs;
};

struct mtev_http_response {
  mtev_http_protocol protocol;
  int status_code;
  char *status_reason;

  mtev_hash_table headers;
  struct bchain *leader; /* serialization of status line and headers */

  u_int32_t output_options;
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
  z_stream *gzip;
  size_t output_chain_bytes;
  size_t output_raw_chain_bytes;
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
  void *dispatcher_closure;
  acceptor_closure_t *ac;
  Zipkin_Span *zipkin_span;
};

static mtev_log_stream_t http_debug = NULL;
static mtev_log_stream_t http_io = NULL;
static mtev_log_stream_t http_access = NULL;
static const char *zipkin_http_uri = "http.uri";
static const char *zipkin_http_method = "http.method";
static const char *zipkin_http_hostname = "http.hostname";
static const char *zipkin_http_status = "http.status";
static const char *zipkin_http_bytes_in = "http.bytes_in";
static const char *zipkin_http_bytes_out = "http.bytes_out";
static const char *zipkin_ss_done = "ss_done";
static struct in_addr zipkin_ip_host;

static const char gzip_header[10] =
  { '\037', '\213', Z_DEFLATED, 0, 0, 0, 0, 0, 0, 0x03 };

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

struct bchain *bchain_alloc(size_t size, int line) {
  struct bchain *n;
  if (size >= 16384) {
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
    int start_in_b, end_in_f;
    size_t new_size;
    const char *str_in_f;

    start_in_b = b->start;
    if(b->size > 2) {
      if(memcmp(b->buff + b->start + b->size - 2, "\r\n", 2) == 0) {
        b = b->next;
        continue;
      }
      start_in_b = b->start + b->size - 3; /* we already checked -2 */
      while(start_in_b >= b->start) {
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
  mtev_hrtime_t now;
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

  gettimeofday(&end_time, NULL);
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
    assert((ctx->res.output_raw_last == NULL && ctx->res.output_raw == NULL) ||
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
  if(req->start_time.tv_sec == 0) gettimeofday(&req->start_time, NULL);
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
      assert(req->current_input != req->current_request_chain);
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
    if(len == -1 || err == mtev_true) goto full_error;
    if(ctx->req.state == MTEV_HTTP_REQ_EXPECT) {
      const char *expect;
      ctx->req.state = MTEV_HTTP_REQ_PAYLOAD;
      assert(ctx->res.leader == NULL);
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
  mtev_hash_destroy(&ctx->req.querystring, NULL, NULL);
  mtev_hash_destroy(&ctx->req.headers, NULL, NULL);
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
  memset(&ctx->req.state, 0,
         sizeof(ctx->req) - (unsigned long)&(((mtev_http_request *)0)->state));
}
void
mtev_http_response_release(mtev_http_session_ctx *ctx) {
  mtev_hash_destroy(&ctx->res.headers, free, free);
  if(ctx->res.status_reason) free(ctx->res.status_reason);
  RELEASE_BCHAIN(ctx->res.leader);
  RELEASE_BCHAIN(ctx->res.output);
  RELEASE_BCHAIN(ctx->res.output_raw);
  if(ctx->res.gzip) {
    deflateEnd(ctx->res.gzip);
    free(ctx->res.gzip);
  }
  memset(&ctx->res, 0, sizeof(ctx->res));
}
void
mtev_http_ctx_session_release(mtev_http_session_ctx *ctx) {
  if(mtev_atomic_dec32(&ctx->ref_cnt) == 0) {
    mtev_http_request_release(ctx);
    if(ctx->req.first_input) RELEASE_BCHAIN(ctx->req.first_input);
    mtev_http_response_release(ctx);
    pthread_mutex_destroy(&ctx->write_lock);
    free(ctx);
  }
}
void
mtev_http_ctx_acceptor_free(void *v) {
  mtev_http_ctx_session_release((mtev_http_session_ctx *)v);
}
static int
mtev_http_session_req_consume_chunked(mtev_http_session_ctx *ctx,
                                      int *mask) {
  /* chunked encoding read */
  int next_chunk = -1;
  /* We attempt to consume from the first_input */
  struct bchain *in, *tofree;
  while(1) {
    const char *str_in_f;
    int rlen;
    in = ctx->req.first_input;
    if(!in)
      in = ctx->req.first_input = ctx->req.last_input =
          ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
    _fixup_bchain(in);
    str_in_f = strnstrn("\r\n", 2, in->buff + in->start, in->size);
    if(str_in_f && ctx->req.next_chunk_read) {
      if(str_in_f != (in->buff + in->start)) {
        mtevL(http_debug, "HTTP chunked encoding error, no trailing CRLF.\n");
        return -1;
      }
      in->start += 2;
      in->size -= 2;
      ctx->req.next_chunk_read = 0;
      ctx->req.next_chunk = 0;
      str_in_f = strnstrn("\r\n", 2, in->buff + in->start, in->size);
    }
    if(str_in_f) {
      unsigned int clen = 0;
      const char *cp = in->buff + in->start;
      while(cp <= str_in_f) {
        if(*cp >= '0' && *cp <= '9') clen = (clen << 4) | (*cp - '0');
        else if(*cp >= 'a' && *cp <= 'f') clen = (clen << 4) | (*cp - 'a' + 10);
        else if(*cp >= 'A' && *cp <= 'F') clen = (clen << 4) | (*cp - 'A' + 10);
        else if(*cp == '\r' && cp[1] == '\n') {
          mtevL(http_debug, "Found for chunk length(%d)\n", clen);
          next_chunk = clen;
          in->start += 2;
          in->size -= 2;
          goto successful_chunk_size;
        }
        else {
          mtevL(http_debug, "chunked input encoding error: '%02x'\n", *cp);
          return -1;
        }
        in->start++;
        in->size--;
        cp++;
      }
    }

    in = ctx->req.last_input;
    if(!in)
      in = ctx->req.first_input = ctx->req.last_input =
          ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
    else if(in->start + in->size >= in->allocd) {
      in->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      in = ctx->req.last_input = in->next;
    }
    /* pull next chunk */
    if(ctx->conn.e == NULL) return -1;
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
      return -1;
    }
    in->size += rlen;
  }

 successful_chunk_size:
  if(in->size == 0) {
    tofree = in;
    ctx->req.first_input = in = in->next;
    if(ctx->req.last_input == tofree) ctx->req.last_input = in;
    tofree->next = NULL;
    RELEASE_BCHAIN(tofree);
  }

  return next_chunk;
}
int
mtev_http_session_req_consume(mtev_http_session_ctx *ctx,
                              void *buf, size_t len, size_t blen,
                              int *mask) {
  size_t bytes_read = 0,
         expected = ctx->req.content_length - ctx->req.content_length_read;
  /* We attempt to consume from the first_input */
  struct bchain *in, *tofree;
  if(ctx->req.payload_chunked) {
    if(ctx->req.next_chunk_read >= ctx->req.next_chunk) {
      int needed;
      needed = mtev_http_session_req_consume_chunked(ctx, mask);
      mtevL(http_debug, " ... mtev_http_session_req_consume(%d) chunked -> %d\n",
            ctx->conn.e->fd, (int)needed);
      if(needed == 0) {
        ctx->req.content_length = ctx->req.content_length_read;
        return 0;
      }
      else if(needed < 0) {
        mtevL(http_debug, " ... couldn't read chunk size\n");
        return -1;
      }
      else {
        ctx->req.next_chunk_read = 0;
        ctx->req.next_chunk = needed;
      }
      len = blen;
    }
    expected = ctx->req.next_chunk - ctx->req.next_chunk_read;
    mtevL(http_debug, " ... need to read %d/%d more of a chunk\n", (int)expected,
          (int)ctx->req.next_chunk);
  }
  mtevL(http_debug, " ... mtev_http_session_req_consume(%d) %d of %d\n",
        ctx->conn.e->fd, (int)len, (int)expected);
  len = MIN(len, expected);
  while(bytes_read < len) {
    int crlen = 0;
    in = ctx->req.first_input;
    while(in && bytes_read < len) {
      int partial_len = MIN(in->size, len - bytes_read);
      if(buf) memcpy((char *)buf+bytes_read, in->buff+in->start, partial_len);
      bytes_read += partial_len;
      ctx->req.content_length_read += partial_len;
      if(ctx->req.payload_chunked) ctx->req.next_chunk_read += partial_len;
      mtevL(http_debug, " ... filling %d bytes (read through %d/%d)\n",
            (int)bytes_read, (int)ctx->req.content_length_read,
            (int)ctx->req.content_length);
      in->start += partial_len;
      in->size -= partial_len;
      if(in->size == 0) {
        tofree = in;
        ctx->req.first_input = in = in->next;
        tofree->next = NULL;
        RELEASE_BCHAIN(tofree);
        if(in == NULL) {
          ctx->req.last_input = NULL;
          mtevL(http_debug, " ... mtev_http_session_req_consume = %d\n",
                (int)bytes_read);
          return bytes_read;
        }
      }
    }
    while(bytes_read + crlen < len) {
      int rlen;
      in = ctx->req.last_input;
      if(!in)
        in = ctx->req.first_input = ctx->req.last_input =
            ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
      else if(in->start + in->size >= in->allocd) {
        in->next = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
        in = ctx->req.last_input = in->next;
      }
      /* pull next chunk */
      if(ctx->conn.e == NULL) return -1;
      rlen = ctx->conn.e->opset->read(ctx->conn.e->fd,
                                      in->buff + in->start + in->size,
                                      in->allocd - in->size - in->start,
                                      mask, ctx->conn.e);
      mtevL(http_debug, " mtev_http -> read(%d) = %d\n", ctx->conn.e->fd, rlen);
    mtevL(http_io, " mtev_http:read(%d) => %d [\n%.*s\n]\n", ctx->conn.e->fd, rlen, rlen, in->buff + in->start + in->size);
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
        return -1;
      }
      in->size += rlen;
      crlen += rlen;
    }
  }
  /* NOT REACHED */
  return bytes_read;
}

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
    _http_perform_write(ctx, &maybe_write_mask);
    if(ctx->conn.e == NULL) goto release;
    if(ctx->req.complete != mtev_true) {
      mtevL(http_debug, " <- mtev_http_session_drive(%d) [%x]\n", e->fd,
            mask|maybe_write_mask);
      return mask | maybe_write_mask;
    }
    mtevL(http_debug, "HTTP start request (%s)\n", ctx->req.uri_str);
    mtev_http_process_querystring(&ctx->req);
    inplace_urldecode(ctx->req.uri_str);
    begin_span(ctx);
  }

  /* only dispatch if the response is not closed */
  if(ctx->res.closed == mtev_false) {
    mtevL(http_debug, "   -> dispatch(%d)\n", e->fd);
    rv = ctx->dispatcher(ctx);
    mtevL(http_debug, "   <- dispatch(%d) = %d\n", e->fd, rv);
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
mtev_http_session_ctx_new(mtev_http_dispatch_func f, void *c, eventer_t e,
                          acceptor_closure_t *ac) {
  mtev_http_session_ctx *ctx;
  ctx = calloc(1, sizeof(*ctx));
  ctx->ref_cnt = 1;
  pthread_mutex_init(&ctx->write_lock, NULL);
  ctx->req.complete = mtev_false;
  ctx->conn.e = e;
  ctx->max_write = DEFAULT_MAXWRITE;
  ctx->dispatcher = f;
  ctx->dispatcher_closure = c;
  ctx->ac = ac;
  return ctx;
}

mtev_boolean
mtev_http_response_status_set(mtev_http_session_ctx *ctx,
                              int code, const char *reason) {
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
  if(ctx->res.output_started == mtev_true) return mtev_false;
  mtev_hash_replace(&ctx->res.headers, strdup(name), strlen(name),
                    strdup(value), free, free);
  return mtev_true;
}
mtev_boolean
mtev_http_response_option_set(mtev_http_session_ctx *ctx, u_int32_t opt) {
  if(ctx->res.output_started == mtev_true) return mtev_false;
  /* transfer and content encodings only allowed in HTTP/1.1 */
  if(ctx->res.protocol != MTEV_HTTP11 &&
     (opt & MTEV_HTTP_CHUNKED))
    return mtev_false;
  if(ctx->res.protocol != MTEV_HTTP11 &&
     (opt & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE)))
    return mtev_false;
  if(((ctx->res.output_options | opt) &
      (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE)) ==
        (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE))
    return mtev_false;

  /* Check out "accept" set */
  if(!(opt & ctx->req.opts)) return mtev_false;

  ctx->res.output_options |= opt;
  if(ctx->res.output_options & MTEV_HTTP_CHUNKED)
    CTX_ADD_HEADER("Transfer-Encoding", "chunked");
  if(ctx->res.output_options & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE)) {
    CTX_ADD_HEADER("Vary", "Accept-Encoding");
    if(ctx->res.output_options & MTEV_HTTP_GZIP)
      CTX_ADD_HEADER("Content-Encoding", "gzip");
    else if(ctx->res.output_options & MTEV_HTTP_DEFLATE)
      CTX_ADD_HEADER("Content-Encoding", "deflate");
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
  if(ctx->res.output_started == mtev_true &&
     !(ctx->res.output_options & (MTEV_HTTP_CLOSE | MTEV_HTTP_CHUNKED)))
    return mtev_false;
  if(!ctx->res.output)
    ctx->res.output_last = ctx->res.output = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE);
  assert(ctx->res.output != NULL);
  assert(ctx->res.output_last != NULL);
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
mtev_http_response_append_bchain(mtev_http_session_ctx *ctx,
                                 struct bchain *b) {
  struct bchain *o;
  if(ctx->res.closed == mtev_true) return mtev_false;
  if(ctx->res.output_started == mtev_true &&
     !(ctx->res.output_options & (MTEV_HTTP_CHUNKED | MTEV_HTTP_CLOSE)))
    return mtev_false;
  if(!ctx->res.output_last)
    ctx->res.output_last = ctx->res.output = b;
  else {
    assert(ctx->res.output !=  NULL);
    assert(ctx->res.output_last !=  NULL);
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
  const char *key, *value;
  int klen, i;
  const char **keys;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

  assert(!ctx->res.leader);
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
    assert(b->next); \
    b->next->prev = b; \
    b = b->next; \
  } \
  assert(DEFAULT_BCHAINSIZE >= b->size + slen); \
  memcpy(b->buff + b->start + b->size, s, slen); \
  b->size += slen; \
} while(0)
  keys = alloca(sizeof(*keys)*mtev_hash_size(&ctx->res.headers));
  i = 0;
  while(mtev_hash_next_str(&ctx->res.headers, &iter,
                           &key, &klen, &value)) {
    keys[i++] = key;
  }
  qsort(keys, i, sizeof(*keys), casesort);
  kcnt = i;
  for(i=0;i<kcnt;i++) {
    int vlen;
    key = keys[i];
    klen = strlen(key);
    (void)mtev_hash_retr_str(&ctx->res.headers, key, klen, &value);
    vlen = strlen(value);
    CTX_LEADER_APPEND(key, klen);
    CTX_LEADER_APPEND(": ", 2);
    CTX_LEADER_APPEND(value, vlen);
    CTX_LEADER_APPEND("\r\n", 2);
  }
  CTX_LEADER_APPEND("\r\n", 2);
  ctx->res.output_raw_chain_bytes += b->size;
  return len;
}
static int memgzip2(mtev_http_response *res, Bytef *dest, uLongf *destLen,
                    const Bytef *source, uLong sourceLen, int level,
                    int deflate_option, mtev_boolean *done) {
  int err, skip=0, expect = Z_OK;
  if(!res->gzip) {
    res->gzip = calloc(1, sizeof(*res->gzip));
    err = deflateInit2(res->gzip, level, Z_DEFLATED, -15, 8,
                       Z_DEFAULT_STRATEGY);
    if (err != Z_OK) {
      mtevL(mtev_error, "memgzip2() -> deflateInit2: %d\n", err);
      return err;
    }

    memcpy(dest, gzip_header, sizeof(gzip_header));
    skip = sizeof(gzip_header);
    *destLen -= skip;
  }
  res->gzip->next_in = (Bytef*)source;
  res->gzip->avail_in = (uInt)sourceLen;
  res->gzip->next_out = dest + skip;
  res->gzip->avail_out = (uInt)*destLen;
  if ((uLong)res->gzip->avail_out != *destLen) return Z_BUF_ERROR;

  err = deflate(res->gzip, deflate_option);

  if(deflate_option == Z_FINISH) expect = Z_STREAM_END;
  if (err != Z_OK && err != expect) {
    mtevL(mtev_error, "memgzip2() -> deflate: got %d, need %d\n", err, expect);
    deflateEnd(res->gzip);
    free(res->gzip);
    res->gzip = NULL;
    return err == Z_OK ? Z_BUF_ERROR : err;
  }
  if(done) *done = (err == Z_STREAM_END) ? mtev_true : mtev_false;
  *destLen = (*destLen - res->gzip->avail_out) + skip;

  return Z_OK;
}
static mtev_boolean
_http_encode_chain(mtev_http_response *res,
                   struct bchain *out, void *inbuff, int inlen,
                   mtev_boolean final, mtev_boolean *done) {
  int opts = res->output_options;
  /* implement gzip and deflate! */
  if(done && final) *done = mtev_true;
  if(opts & MTEV_HTTP_GZIP) {
    uLongf olen;
    int err;
    olen = out->allocd - out->start - 2; /* leave 2 for the \r\n */
    err = memgzip2(res, (Bytef *)(out->buff + out->start), &olen,
                   (Bytef *)(inbuff), (uLong)inlen,
                   9, final ? Z_FINISH : Z_NO_FLUSH, done);
    if(Z_OK != err) {
      mtevL(mtev_error, "zlib compress2 error %d\n", err);
      return mtev_false;
    }
    out->size += olen;
  }
  else if(opts & MTEV_HTTP_DEFLATE) {
    uLongf olen;
    olen = out->allocd - out->start - 2; /* leave 2 for the \r\n */
    if(Z_OK != compress2((Bytef *)(out->buff + out->start), &olen,
                         (Bytef *)(inbuff), (uLong)inlen,
                         9)) {
      mtevL(mtev_error, "zlib compress2 error\n");
      return mtev_false;
    }
    out->size += olen;
  }
  else {
    /* leave 2 for the \r\n */
    if(inlen > out->allocd - out->start - 2) return mtev_false;
    memcpy(out->buff + out->start, inbuff, inlen);
    out->size += inlen;
  }
  return mtev_true;
}
struct bchain *
mtev_http_process_output_bchain(mtev_http_session_ctx *ctx,
                                struct bchain *in) {
  struct bchain *out;
  int ilen, maxlen = in->size, hexlen;
  int opts = ctx->res.output_options;

  if(in->type == BCHAIN_MMAP &&
     0 == (opts & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_CHUNKED))) {
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
  if(opts & MTEV_HTTP_GZIP) maxlen = deflateBound(NULL, in->size);
  else if(opts & MTEV_HTTP_DEFLATE) maxlen = compressBound(in->size);

  /* So, the link size is the len(data) + 4 + ceil(log(len(data))/log(16)) */
  ilen = maxlen;
  hexlen = 0;
  while(ilen) { ilen >>= 4; hexlen++; }
  if(hexlen == 0) hexlen = 1;

  out = ALLOC_BCHAIN(hexlen + 4 + maxlen);
  /* if we're chunked, let's give outselved hexlen + 2 prefix space */
  if(opts & MTEV_HTTP_CHUNKED) out->start = hexlen + 2;
  if(_http_encode_chain(&ctx->res, out, in->buff + in->start, in->size,
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
    assert(out->start+out->size+2 <= out->allocd);
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
    assert((r == NULL && res->output_raw == NULL) ||
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
      assert(out->start+out->size+2 <= out->allocd);
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
        assert(r == res->output_raw_last);
        r->next = out;
        out->prev = r;
      }
      res->output_raw_last = r = out;
      res->output_raw_chain_bytes += out->size;
    }

    deflateEnd(res->gzip);
    free(res->gzip);
    res->gzip = NULL;
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
  assert((r == NULL && ctx->res.output_raw == NULL) ||
         (r != NULL && ctx->res.output_raw != NULL));
  /* r is the last raw output link */
  o = ctx->res.output;
  /* o is the first output link to process */
  while(o) {
    struct bchain *tofree, *n;
    n = mtev_http_process_output_bchain(ctx, o);
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
    if(r) {
      r->next = n;
      n->prev = r;
      r = ctx->res.output_raw_last = n;
    }
    else {
      r = ctx->res.output_raw = ctx->res.output_raw_last = n;
    }
    ctx->res.output_raw_chain_bytes += n->size;
    tofree = o; o = o->next;
    ctx->res.output_chain_bytes -= tofree->size;
    FREE_BCHAIN(tofree); /* advance and free */
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
