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

#include "mtev_http2.h"
#include "eventer/eventer_SSL_fd_opset.h"
#include "mtev_http.h"
#include "mtev_http_private.h"
#include "mtev_str.h"
#include "mtev_b64.h"

#include <ctype.h>
#include <errno.h>

#include <nghttp2/nghttp2.h>

static const char *HTTP_2_STATUS_HDR = ":status";
static mtev_log_stream_t h2_debug;

/* The parent session is effective out connection,
 * so we can return a pointer to it as a connection.
 */
struct mtev_http2_parent_session {
  uint32_t http_type;
  uint32_t ref_cnt;
  nghttp2_session *session;
  mtev_http_dispatch_func dispatcher;
  void *(*closure_creator)(mtev_http_session_ctx *);
  void (*closure_free)(void *);
  mtev_acceptor_closure_t *ac;
  unsigned char *inbuff;
  size_t inbuff_wp;
  size_t inbuff_size;
  mtev_hash_table streams;
  eventer_t e;
};
struct mtev_http2_request {
  uint32_t http_type;
  mtev_hash_table querystring;
  mtev_hash_table headers;
  char *orig_qs;
  char *uri_str;
  char *method_str;
  size_t content_length;
  mtev_boolean complete;
  mtev_boolean payload_complete;
  mtev_boolean has_payload;
  mtev_boolean expect;
  struct timeval start_time;
  int opts;
  mtev_compress_type in_compression;
  struct bchain *user_data;
  struct bchain *user_data_last;
  size_t user_data_bytes;
  struct {
    int64_t size;
    void *data;
    void (*freefunc)(void *data, int64_t size, void *closure);
    void *freeclosure;
  } upload;  /* This is optionally set */
  mtev_stream_decompress_ctx_t *decompress_ctx;
};
struct mtev_http2_response {
  HTTP_RESPONSE_BASE;

  mtev_hash_table trailers;
  int code;
  char code_str[4];
};
struct mtev_http2_session_ctx {
  HTTP_SESSION_BASE;

  int32_t stream_id;
  enum { H2_NORMAL = 0, H2_PAUSED, H2_UNPAUSED } paused;
  enum { H2_SYNCH = 0, H2_ASYNCH } floated;
  uint32_t ref_cnt;
  mtev_boolean aco_enabled;
  mtev_http2_request req;
  mtev_http2_response res;
  void *dispatcher_closure;
  void (*dispatcher_closure_free)(void *);
  struct mtev_http2_parent_session *parent;
};

#define CTX_ADD_HEADER(a,b) do { \
  char *al = strdup(a); \
  for(char *cp = al; *cp; cp++) *cp = tolower(*cp); \
  mtev_hash_replace(&ctx->res.headers, \
                    al, strlen(al), strdup(b), free, free); \
} while(0)

void *
mtev_http2_session_dispatcher_closure(mtev_http2_session_ctx *sess) {
  return sess->dispatcher_closure;
}

void
mtev_http2_session_set_dispatcher(mtev_http2_session_ctx *ctx,
                                 int (*d)(mtev_http_session_ctx *), void *dc) {
  ctx->parent->dispatcher = d;
  ctx->dispatcher_closure = dc;
}
void mtev_http2_session_trigger(mtev_http2_session_ctx *ctx, int state) {
  if(ctx->parent->e) eventer_trigger(ctx->parent->e, state);
}
uint32_t mtev_http2_session_ref_cnt(mtev_http2_session_ctx *ctx) {
  return ck_pr_load_32(&ctx->ref_cnt);
}
mtev_boolean mtev_http2_session_ref_dec(mtev_http2_session_ctx *ctx) {
  bool zero;
  if(ctx->parent) {
    mtev_http2_parent_session_deref(ctx->parent, mtev_false);
  }
  ck_pr_dec_32_zero(&ctx->ref_cnt, &zero);
  if(zero) {
    mtevL(h2_debug, "http2 freeing stream(%p) <- %d\n", ctx->parent, ctx->stream_id);
    /* This is where we free the request and response */
    mtev_http_log_request((mtev_http_session_ctx *)ctx);
    mtev_http_end_span((mtev_http_session_ctx *)ctx);

    /* free request */
    RELEASE_BCHAIN(ctx->req.user_data);
    free(ctx->req.uri_str);
    free(ctx->req.method_str);
    free(ctx->req.orig_qs);
    if(ctx->req.upload.freefunc) {
      ctx->req.upload.freefunc(ctx->req.upload.data, ctx->req.upload.size,
                               ctx->req.upload.freeclosure);
    }
    mtev_hash_destroy(&ctx->req.querystring, NULL, NULL);
    mtev_hash_destroy(&ctx->req.headers, free, free);
    if (ctx->req.decompress_ctx != NULL) {
      mtev_stream_decompress_finish(ctx->req.decompress_ctx);
      mtev_destroy_stream_decompress_ctx(ctx->req.decompress_ctx);
      ctx->req.decompress_ctx = NULL;
    }

    /* free response */
    mtev_hash_destroy(&ctx->res.headers, free, free);
    mtev_hash_destroy(&ctx->res.trailers, free, free);
    RELEASE_BCHAIN(ctx->res.output);
    RELEASE_BCHAIN(ctx->res.output_raw);
    if(ctx->res.compress_ctx) {
      mtev_stream_compress_finish(ctx->res.compress_ctx);
      mtev_destroy_stream_compress_ctx(ctx->res.compress_ctx);
    }

    if(ctx->dispatcher_closure_free) {
      ctx->dispatcher_closure_free(ctx->dispatcher_closure);
    }
    free(ctx);
  }
  return zero;
}
void mtev_http2_session_ref_inc(mtev_http2_session_ctx *ctx) {
  if(ctx->parent) {
    mtev_http2_parent_session_ref(ctx->parent);
  }
  ck_pr_inc_32(&ctx->ref_cnt);
}

void mtev_http2_session_set_aco(mtev_http2_session_ctx *ctx, mtev_boolean nv) {
  ctx->aco_enabled = nv;
}
mtev_boolean mtev_http2_session_aco(mtev_http2_session_ctx *ctx) {
  return ctx->aco_enabled;
}

mtev_acceptor_closure_t *
mtev_http2_session_acceptor_closure(mtev_http2_session_ctx *ctx) {
  return ctx->parent->ac;
}
void
mtev_http2_ctx_session_release(mtev_http2_session_ctx *sess) {
  (void)mtev_http2_session_ref_dec(sess);
}

mtev_http2_request *
mtev_http2_session_request(mtev_http2_session_ctx *ctx) {
  return &ctx->req;
}

mtev_http2_response *
mtev_http2_session_response(mtev_http2_session_ctx *ctx) {
  return &ctx->res;
}

mtev_http2_connection *
mtev_http2_session_connection(mtev_http2_session_ctx *ctx) {
  /* connection is  like a stream... to float and resume */
  return ctx;
}

eventer_t
mtev_http2_connection_event(mtev_http2_connection *p) {
  /* people can't have this.. just too damn dangerous */
  (void)p;
  return NULL;
}

void mtev_http2_request_start_time(mtev_http2_request *req, struct timeval *t) {
  memcpy(t, &req->start_time, sizeof(*t));
}
int mtev_http2_request_opts(mtev_http2_request *req) {
  return req->opts;
}
void mtev_http2_request_set_opts(mtev_http2_request *req, int opts) {
  req->opts = opts;
}
const char *mtev_http2_request_uri_str(mtev_http2_request *req) {
  return req->uri_str;
}
const char *mtev_http2_request_method_str(mtev_http2_request *req) {
  return req->method_str;
}
const char *mtev_http2_request_protocol_str(mtev_http2_request *req) {
  (void)req;
  return "HTTP/2";
}
size_t mtev_http2_request_content_length(mtev_http2_request *req) {
  return req->content_length;
}
size_t mtev_http2_request_content_length_read(mtev_http2_request *req) {
  return req->user_data_bytes;
}
mtev_boolean mtev_http2_request_payload_chunked(mtev_http2_request *req) {
  (void)req;
  return mtev_false;
}
mtev_boolean mtev_http2_request_has_payload(mtev_http2_request *req) {
  return req->has_payload;
}
int
mtev_http2_session_req_consume(mtev_http2_session_ctx *ctx,
                              void *buf, const size_t user_len,
                              const size_t blen, int *mask) {
  (void)blen;
  struct bchain *in, *tofree;
  size_t bytes_read = 0;
  while(bytes_read < user_len) {
    in = ctx->req.user_data;

    if(in == NULL) {
      if(bytes_read > 0) return bytes_read;
      if(ctx->req.payload_complete) {
        /* Force the to be correct */
        ctx->req.content_length = ctx->req.user_data_bytes;
        return 0;
      }
      *mask = EVENTER_READ|EVENTER_WRITE; /* really ignored */
      errno = EAGAIN;
      return -1;
    }

    while(in && in->size && bytes_read < user_len) {

      if (in->compression != MTEV_COMPRESS_NONE) {
        mtevL(h2_debug, "http2 ... decompress bchain\n");
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
        ctx->req.user_data_bytes -= in->size;

        if(ctx->req.decompress_ctx == NULL) {
          ctx->req.decompress_ctx = mtev_create_stream_decompress_ctx();
          if (mtev_stream_decompress_init(ctx->req.decompress_ctx, in->compression) < 0) {
            mtev_destroy_stream_decompress_ctx(ctx->req.decompress_ctx);
            ctx->req.decompress_ctx = NULL;
            errno = EINVAL;
            return -1;
          }
        }

        ssize_t s = mtev_http_session_decompress(ctx->req.decompress_ctx, in,
                                                 &out, &last_out);
        if (s < 0) {
          errno = s;
          mtev_destroy_stream_decompress_ctx(ctx->req.decompress_ctx);
          ctx->req.decompress_ctx = NULL;
          return -1;
        }
        total_decompressed_size += s;
        ctx->req.user_data_bytes += s;

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
      }

      if (in && in->compression == MTEV_COMPRESS_NONE) {
        /* read uncompressed data into the user buffer */
        int partial_len = MIN(in->size, user_len - bytes_read);

        if(buf) memcpy((char *)buf+bytes_read, in->buff+in->start, partial_len);
        bytes_read += partial_len;
        mtevL(h2_debug, "http2 ... filling %d bytes (read through %d/%d)\n",
              (int)bytes_read, (int)ctx->req.user_data_bytes,
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
              mtevL(h2_debug, "http2 ... req_consume = %d\n",
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
  return 0;
}
void
mtev_http2_request_set_upload(mtev_http2_request *req,
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
mtev_http2_request_get_upload(mtev_http2_request *req, int64_t *size) {
  if(size) *size = req->upload.size;
  return req->upload.data;
}
mtev_boolean mtev_http2_response_closed(mtev_http2_response *res) {
  return res->closed;
}
mtev_boolean mtev_http2_response_complete(mtev_http2_response *res) {
  return res->complete;
}
size_t mtev_http2_response_bytes_written(mtev_http2_response *res) {
  return res->bytes_written;
}

const char *mtev_http2_request_querystring(mtev_http2_request *req, const char *k) {
  void *vv;
  const char *v = NULL;
  if(mtev_hash_retrieve(&req->querystring, k, strlen(k), &vv))
    v = vv;
  return v;
}
const char *mtev_http2_request_orig_querystring(mtev_http2_request *req) {
  return req->orig_qs;
}
mtev_hash_table *mtev_http2_request_querystring_table(mtev_http2_request *req) {
  return &req->querystring;
}
mtev_hash_table *mtev_http2_request_headers_table(mtev_http2_request *req) {
  return &req->headers;
}

eventer_t
mtev_http2_connection_event_float(mtev_http2_connection *p) {
  (void)p;
  if(p->floated == H2_SYNCH) {
    mtev_http2_session_ref_inc(p);
    p->floated = H2_ASYNCH;
  } else {
    mtevL(mtev_error, "Floated already floated http2 session %p\n", p);
  }
  return NULL;
}
void
mtev_http2_connection_resume_after_float(mtev_http2_connection *p) {
  if(p->floated == H2_ASYNCH) {
    p->floated = H2_SYNCH;
    if(p->parent->e) {
      eventer_trigger(p->parent->e, EVENTER_READ|EVENTER_WRITE);
    }
    mtev_http2_session_ref_dec(p);
  } else {
    mtevL(mtev_error, "Resumed already resumed http2 session %p\n", p);
  }
}
void
mtev_http2_session_resume_after_float(mtev_http2_session_ctx *p) {
  mtev_http2_connection_resume_after_float(p);
}

int
mtev_http2_response_status(mtev_http2_response *res) {
  return res->code;
}
mtev_boolean
mtev_http2_response_status_set(mtev_http2_session_ctx *ctx, int code, const char *status) {
  (void)status; /* unused in http/2 */
  if(ctx->res.output_started) return mtev_false;
  if(code < 100 || code > 999) return mtev_false;
  ctx->res.code = code;
  snprintf(ctx->res.code_str, sizeof(ctx->res.code_str), "%d", code);
  return mtev_http2_response_header_set(ctx, HTTP_2_STATUS_HDR, ctx->res.code_str);
}
mtev_hash_table *
mtev_http2_response_headers_table(mtev_http2_response *res) {
  return &res->headers;
}
mtev_hash_table *
mtev_http2_response_trailers_table(mtev_http2_response *res) {
  return &res->trailers;
}
mtev_boolean
mtev_http2_response_header_set(mtev_http2_session_ctx *ctx,
                               const char *key, const char *value) {
  if(ctx->res.complete || ctx->res.closed) return mtev_false;
  char *lkey = strdup(key);
  char *lval = strdup(value);
  for(char *cp = lkey; *cp; cp++) { *cp = tolower(*cp); }
  if(!ctx->res.output_started) {
    mtev_hash_replace(&ctx->res.headers, lkey, strlen(lkey), lval, free, free);
  } else {
    mtev_hash_replace(&ctx->res.trailers, lkey, strlen(lkey), lval, free, free);
  }
  return mtev_true;
}
size_t
mtev_http2_response_buffered(mtev_http2_session_ctx *ctx) {
  (void)ctx;
  return 0;
}
static ssize_t
mtev_http2_data_provider_read(nghttp2_session *session, int32_t stream_id,
                              uint8_t *buf, size_t length, uint32_t *data_flags,
                              nghttp2_data_source *source, void *user_data) {
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtev_http2_session_ctx *ctx = source->ptr;
  mtevAssert(p_session == ctx->parent);
  mtevAssert(ctx->parent->session == session);
  mtevAssert(ctx->stream_id == stream_id);

  mtevL(h2_debug, "http2 data_provider(%p -> %d)\n", ctx->parent, ctx->stream_id);
  /* Fill the buffer */
  size_t sofar = 0;
  while(sofar < length && ctx->res.output_raw && ctx->res.output_raw->size > 0) {
    /* Copy as much as will fit */
    size_t lentocopy = MIN(length - sofar, ctx->res.output_raw->size);
    memcpy(buf + sofar, ctx->res.output_raw->buff + ctx->res.output_raw->start, lentocopy);
    /* Accounting */
    sofar += lentocopy;
    ctx->res.output_raw->start += lentocopy;
    ctx->res.output_raw->size -= lentocopy;
    ctx->res.output_chain_bytes -= lentocopy;

    /* Advance the output_raw chain if consumed */
    if(ctx->res.output_raw->size == 0) {
      struct bchain *tofree = ctx->res.output_raw;
      ctx->res.output_raw = ctx->res.output_raw->next;
      if(ctx->res.output_raw == NULL) ctx->res.output_raw_last = NULL;
      FREE_BCHAIN(tofree);
    }
  }

  /* If we've copied nothing and are not "complete" we need to defer */
  if(sofar == 0 && ctx->res.complete == mtev_false) {
    mtevL(h2_debug, "http2 session suspending pending output data (%p -> %d)\n",
          ctx->parent, ctx->stream_id);
    ctx->paused = H2_PAUSED;
    return NGHTTP2_ERR_DEFERRED;
  }
  /* Determine if "this is it" and we should set the EOF flag */
  if(ctx->res.complete && ctx->res.output_raw == NULL) {
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
    mtevL(h2_debug, "http2 (%p -> %d) sending final data frame\n", ctx->parent, ctx->stream_id);
    if(mtev_hash_size(&ctx->res.trailers) > 0) {
      mtevL(h2_debug, "http2 (%p -> %d) has trailers\n", ctx->parent, ctx->stream_id);
      *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;

      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      int i = 0, nhdrs = mtev_hash_size(&ctx->res.trailers);
      nghttp2_nv hdrs[nhdrs];
      for(int j=0; j<2; j++) {
        memset(&iter, 0, sizeof(iter));
        while(mtev_hash_adv(&ctx->res.trailers, &iter)) {
          if((j == 0 && iter.key.str[0] == ':') ||
             (j == 1 && iter.key.str[0] != ':')) {
            nghttp2_nv nv = { iter.key.ptr, iter.value.ptr, iter.klen, strlen(iter.value.str),
                              NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
            hdrs[i++] = nv;
          }
        }
      }
      mtevAssert(i == nhdrs);
      nghttp2_submit_trailer(session, ctx->stream_id, hdrs, nhdrs);
    }
  }
  mtevL(h2_debug, "http2 (%p -> %d) fed ouput %zd bytes\n",
        ctx->parent, ctx->stream_id, sofar);
  ctx->res.bytes_written += sofar;
  return sofar;
}
static int
delayed_trigger(eventer_t e, int mask, void *cl, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  mtev_http2_session_ctx *ctx = cl;
  mtevL(h2_debug, "http2 aco delayed trigger (%p -> %d)\n", ctx->parent, ctx->stream_id);
  mtev_http2_session_trigger(ctx, EVENTER_READ|EVENTER_WRITE);
  mtev_http2_session_ref_dec(ctx);
  return 0;
}
mtev_boolean
mtev_http2_response_flush(mtev_http2_session_ctx *ctx,
                         mtev_boolean final) {
  int rv = 0;
  /* can't finalize twice */
  if(ctx->res.complete && !final) {
    mtevL(h2_debug, "http2 response flush attempt to re-finalize.\n");
    ctx->paused = H2_UNPAUSED;
    return mtev_false;
  }

  if (ctx->req.opts & MTEV_HTTP_GZIP) {
    mtev_http2_response_option_set(ctx, MTEV_HTTP_GZIP);
  }
  else if (ctx->req.opts & MTEV_HTTP_DEFLATE) {
    mtev_http2_response_option_set(ctx, MTEV_HTTP_DEFLATE);
  }
  else if (ctx->req.opts & MTEV_HTTP_LZ4F) {
    mtev_http2_response_option_set(ctx, MTEV_HTTP_LZ4F);
  }

  if(!ctx->res.output_started) {
    ctx->res.output_started = mtev_true;
    mtev_zipkin_span_annotate(ctx->zipkin_span, NULL, ZIPKIN_SERVER_SEND, false);
    /* compose out headers and status and start with that */
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    int i = 0, nhdrs = mtev_hash_size(&ctx->res.headers);
    nghttp2_nv hdrs[nhdrs];
    for(int j=0; j<2; j++) {
      memset(&iter, 0, sizeof(iter));
      while(mtev_hash_adv(&ctx->res.headers, &iter)) {
        if((j == 0 && iter.key.str[0] == ':') ||
           (j == 1 && iter.key.str[0] != ':')) {
          nghttp2_nv nv = { iter.key.ptr, iter.value.ptr, iter.klen, strlen(iter.value.str),
                            NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
          hdrs[i++] = nv;
          mtevL(h2_debug, "http2 header out(%p -> %d) %s : %s\n", ctx->parent,
                ctx->stream_id, iter.key.str, iter.value.str);
        }
      }
    }
    mtevAssert(i == nhdrs);
    mtevL(h2_debug, "http2 starting output (%p -> %d) %d headers\n",
          ctx->parent, ctx->stream_id, nhdrs);
    rv = nghttp2_submit_headers(ctx->parent->session, 0,
                                ctx->stream_id,
                                NULL, hdrs, nhdrs, ctx->parent);
    if(rv != 0) {
      mtevL(h2_debug, "https submit headers(%p -> %u) -> %s\n", ctx->parent, ctx->stream_id,
            nghttp2_strerror(rv));
      ctx->res.closed = mtev_true;
      ctx->res.complete = mtev_true;
    }
    else {
      nghttp2_data_provider data_prd = {
        .source = { .ptr = ctx },
        .read_callback = mtev_http2_data_provider_read
      };
      mtevL(h2_debug, "http2 start self data provider (%p -> %d)\n", ctx->parent, ctx->stream_id);
      rv = nghttp2_submit_data(ctx->parent->session, NGHTTP2_FLAG_END_STREAM, ctx->stream_id,
                               &data_prd);
      if(rv != 0) {
        mtevL(h2_debug, "http submit data(%p -> %u) -> %s\n", ctx->parent, ctx->stream_id,
              nghttp2_strerror(rv));
        rv = nghttp2_submit_rst_stream(ctx->parent->session, NGHTTP2_FLAG_NONE, ctx->stream_id, NGHTTP2_STREAM_CLOSED);
        ctx->res.closed = mtev_true;
        ctx->res.complete = mtev_true;
      }
    }
  }

  mtev_http_encode_output_raw((mtev_http_session_ctx *)ctx, &final);

  if(final) {
    mtevL(h2_debug, "http2 (%p -> %d) finalizing output chain\n", ctx->parent, ctx->stream_id);
    raw_finalize_encoding((mtev_http_response *)&ctx->res);
    ctx->res.complete = mtev_true;
  }

  ctx->paused = H2_UNPAUSED;

  if(ctx->aco_enabled) {
    /* We're not inside the connection event, we're outside... that means
     * we likely need to wake up the session.
     */
    if(ctx->parent->e == NULL) {
      rv = -1;
    }
    else {
      mtevL(h2_debug, "http2 aco flush, deferring\n");
      mtev_http2_session_ref_inc(ctx);
      eventer_add_timer_next_opportunity(delayed_trigger, ctx, eventer_get_owner(ctx->parent->e));
    }
  }

  return (rv == 0);
}
mtev_boolean
mtev_http2_response_flush_asynch(mtev_http2_session_ctx *ctx,
                                mtev_boolean final) {
  return mtev_http2_response_flush(ctx, final);
}

mtev_boolean
mtev_http2_response_end(mtev_http2_session_ctx *ctx) {
  if(!mtev_http2_response_flush(ctx, mtev_true)) {
    mtevL(h2_debug, "http2 response_end failed\n");
    return mtev_false;
  }
  return mtev_true;
}

mtev_boolean
mtev_http2_response_option_set(mtev_http2_session_ctx *ctx, uint32_t opt) {
  /* http2 is framed and cannot be combined with chunked encoding */
  opt &= ~MTEV_HTTP_CHUNKED;
  if(ctx->res.output_started == mtev_true) return mtev_false;
  /* We can set an encoding option, but not if it conflicts with another one */
  if(((ctx->res.output_options | opt) &
      (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)) !=
        (opt & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)))
    return mtev_false;

  /* Check out "accept" set */
  if(!(opt & ctx->req.opts)) return mtev_false;

  ctx->res.output_options |= opt;
  if(ctx->res.output_options & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)) {
    CTX_ADD_HEADER("Vary", "Accept-Encoding");
    if(ctx->res.output_options & MTEV_HTTP_GZIP)
      CTX_ADD_HEADER("Content-Encoding", "gzip");
    else if(ctx->res.output_options & MTEV_HTTP_DEFLATE)
      CTX_ADD_HEADER("Content-Encoding", "deflate");
    else if(ctx->res.output_options & MTEV_HTTP_LZ4F)
      CTX_ADD_HEADER("Content-Encoding", "lz4f");
  }
  return mtev_true;
}

void
mtev_http2_ctx_acceptor_free(void *v) {
  mtevL(h2_debug, "http2 session complete %p (via acceptor_free)\n", v);
  mtev_http2_parent_session_deref((mtev_http2_parent_session *)v, mtev_true);
}

void
mtev_http2_parent_session_ref(mtev_http2_parent_session *sess) {
  ck_pr_inc_32(&sess->ref_cnt);
}

void
mtev_http2_parent_session_deref(mtev_http2_parent_session *sess, mtev_boolean drop_streams) {
  bool zero;
  if(drop_streams) {
    mtev_hash_delete_all(&sess->streams, NULL, (NoitHashFreeFunc)mtev_http2_ctx_session_release);
  }
  ck_pr_dec_32_zero(&sess->ref_cnt, &zero);
  mtevL(h2_debug, "mtev_http2_parent_session_deref(%p) -> %u\n", sess, sess->ref_cnt);
  if(zero) {
    nghttp2_session_del(sess->session);
    mtevAssert(mtev_hash_size(&sess->streams) == 0);
    mtev_hash_destroy(&sess->streams, NULL, NULL);
    free(sess->inbuff);
    free(sess);
  }
}


static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  mtev_http2_parent_session *sess = (mtev_http2_parent_session *)user_data;
  (void)session;
  (void)flags;
  mtevL(h2_debug, "http2 write(%p) %zu bytes\n", sess, length);

  int mask;
  ssize_t len = eventer_write(sess->e, data, length, &mask);
  if(len < 0 && errno == EAGAIN) {
    mtevL(h2_debug, "http2 write(%p) -- eagain\n", sess);
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  mtevL(h2_debug, "http2 wrote(%p), %zd\n", sess, len);
  return len;
}

static int
on_begin_headers_callback(nghttp2_session *session,
                          const nghttp2_frame *frame, void *user_data) {
  (void)session;
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtev_http_session_ctx *stream;
  mtevL(h2_debug, "http2 begin headers(%p) -> %d\n", p_session, frame->hd.stream_id);

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream = mtev_http2_session_new(p_session, frame->hd.stream_id);
  if(!stream) {
    return -1;
  }
  return 0;
}

static int
on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                         uint32_t error_code, void *user_data) {
  (void)error_code;
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtev_http2_session_ctx *stream = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream) {
    return 0;
  }
  mtevAssert(stream_id == stream->stream_id);
  mtevAssert(p_session == stream->parent);
  mtevL(h2_debug, "http2 closing stream(%p) <- %d [%s]\n", p_session, stream_id,
        nghttp2_strerror(error_code));
  mtev_hash_delete(&p_session->streams, (void *)&stream_id, sizeof(stream_id),
                   NULL, (NoitHashFreeFunc)mtev_http2_ctx_session_release);
  return 0;
}

static void
mtev_http2_process_querystring(mtev_http2_request *req) {
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

static int
on_header_callback(nghttp2_session *session,
                   const nghttp2_frame *frame, const uint8_t *name,
                   size_t namelen, const uint8_t *value,
                   size_t valuelen, uint8_t flags, void *user_data) {
  (void)user_data;
  (void)flags;
  mtev_http2_session_ctx *stream = NULL;

#define HDR_NAME(s) ((namelen == strlen(s)) && 0 == memcmp(name, s, namelen))

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
   stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
   mtevL(h2_debug, "http2 headers(%.*s : %.*s)\n", (int)namelen, name, (int)valuelen, value);
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    if(HDR_NAME(":authority")) {
      mtev_hash_replace(&stream->req.headers, strdup("host"), 4,
                        mtev_strndup((const char *)value, valuelen), free, free);
    }
    else if(HDR_NAME(":method")) {
      free(stream->req.method_str);
      stream->req.method_str = mtev_strndup((const char *)value, valuelen);
    }
    else if(HDR_NAME(":path")) {
      free(stream->req.uri_str);
      stream->req.uri_str = mtev_strndup((const char *)value, valuelen);
      mtev_http2_process_querystring(&stream->req);
    } else if(HDR_NAME("host")) {
      /* A host header cannot replace an :authority header */
      void *dummy;
      if(mtev_hash_retrieve(&stream->req.headers, "host", 4, &dummy)) break;
    } else if(HDR_NAME("accept-encoding")) {
      if(strstr((const char *)value, "gzip")) stream->req.opts |= MTEV_HTTP_GZIP;
      if(strstr((const char *)value, "deflate")) stream->req.opts |= MTEV_HTTP_DEFLATE;
      if(strstr((const char *)value, "lz4f")) stream->req.opts |= MTEV_HTTP_LZ4F;
    } else if(HDR_NAME("content-length")) {
      stream->req.content_length = strtoull((const char *)value, NULL, 10);
    } else if(HDR_NAME("content-encoding")) {
      if(strstr((const char *)value, "lz4f")) {
        stream->req.in_compression = MTEV_COMPRESS_LZ4F;
      } else if(strstr((const char *)value, "gzip")) {
        stream->req.in_compression = MTEV_COMPRESS_GZIP;
      }
    } else if(HDR_NAME("expect")) {
      if(strncmp((const char *)value, "100-", 4)) {
        return -1;
      }
      /* We need to tell the client to "go-ahead" (once) -- HTTP sucks */
      if(!stream->req.expect) {
        stream->req.expect = mtev_true;
        nghttp2_nv nv = { (uint8_t *)HTTP_2_STATUS_HDR, (uint8_t *)"100",
                          sizeof(HTTP_2_STATUS_HDR)-1, 3,
                          NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
        int rv = nghttp2_submit_headers(session, 0,
                                        stream->stream_id,
                                        NULL, &nv, 1, stream->parent);
        if(rv != 0) return rv;
      }
    }

    if(name[0] != ':') {
      mtev_hash_replace(&stream->req.headers, mtev_strndup((const char *)name, namelen), namelen,
                        mtev_strndup((const char *)value, valuelen), free, free);
    }
    break;
  }
  return 0;
}

static int
before_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtevAssert(p_session->session == session);
  mtevL(h2_debug, "http2 debug frame(%p -> %d) %x\n", p_session, frame->hd.stream_id,
        frame->hd.type);
  return 0;
}
static int
on_frame_not_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           int lib_error_code, void *user_data) {
  (void)session;
  (void)frame;
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtevL(h2_debug, "http2 frame error (%p) => %s\n",
        p_session, nghttp2_strerror(lib_error_code));
  return 0;
}
static int
on_frame_recv_callback(nghttp2_session *session,
                       const nghttp2_frame *frame, void *user_data) {
  (void)user_data;
  mtev_http2_session_ctx *stream = NULL;
  /* We want to complete the request as soon as the stream ends OR a data frame
   * arrives.  This way we can get into the dispatch and have dispatcher consuming
   * the frames.
   */
  if(0 == (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) return 0;
  stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(!stream) return 0;

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    stream->req.payload_complete = mtev_true;
    stream->req.content_length = stream->req.user_data_bytes;
    /* fall through */
  case NGHTTP2_HEADERS:
    mtev_http_begin_span((mtev_http_session_ctx *)stream);
    http_request_complete_hook_invoke((mtev_http_session_ctx *)stream);
    stream->req.complete = mtev_true;
    mtevL(h2_debug, "http2 request end (%s) (%p -> %d)\n",
          frame->hd.type == NGHTTP2_DATA ? "data" : "headers",
          stream->parent, frame->hd.stream_id);
    break;
  default:
    break;
  }
  return 0;
}
static int
on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                            int32_t stream_id, const uint8_t *data, size_t len,
                            void *user_data) {
  (void)flags;
  mtev_http2_parent_session *p_session = (mtev_http2_parent_session *)user_data;
  mtev_http2_session_ctx *stream;
  stream = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!stream) return NGHTTP2_ERR_CALLBACK_FAILURE;
  if(stream->req.payload_complete) return NGHTTP2_ERR_CALLBACK_FAILURE;
  mtevAssert(stream->parent == p_session);
  /* If we're in ACO, we can't recover from an incomplete payload read
   * because there's no way we can singal a wakeup.  We'd need some sort
   * of go-channel style queue-wakeup mechanism.
   * So, until we support that, we don't mark the request as complete
   * until all the of the chunks are done and the end frame arrives
   * in on_frame_recv_callback.
   */
  if(stream->aco_enabled == mtev_false)
    stream->req.complete = mtev_true;
  stream->req.has_payload = mtev_true;
  mtevL(h2_debug, "http2 submission payload(%p -> %d) %zu bytes\n", p_session, stream_id, len);
  if(len) {
    struct bchain *chunk = bchain_from_data(data, len);
    chunk->compression = stream->req.in_compression;
    if(stream->req.user_data_last) stream->req.user_data_last->next = chunk;
    stream->req.user_data_last = chunk;
    if(!stream->req.user_data) stream->req.user_data = chunk;
    stream->req.user_data_bytes += len;
    (void)http_post_request_read_payload_hook_invoke((mtev_http_session_ctx *)stream);
  }
  return 0;
}

static void
initialize_nghttp2_session(struct mtev_http2_parent_session *ctx) {
  nghttp2_session_callbacks *callbacks;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks, on_frame_not_send_callback);
  nghttp2_session_callbacks_set_before_frame_send_callback(callbacks, before_frame_send_callback);
  nghttp2_option *option;
  mtevEvalAssert(nghttp2_option_new(&option) == 0);
  nghttp2_option_set_no_closed_streams(option, 1);
  nghttp2_session_server_new2(&ctx->session, callbacks, ctx, option);
  nghttp2_option_del(option);
  nghttp2_session_callbacks_del(callbacks);
}

mtev_http2_parent_session *
mtev_http2_parent_session_new_ex(mtev_http_dispatch_func f,
                                 void *(*closure_creator)(mtev_http_session_ctx *),
                                 void (*closure_free)(void *),
                                 eventer_t e, mtev_acceptor_closure_t *ac,
                                 int max_streams, int head_req,
                                 uint8_t *settings, size_t settings_len) {
  int rv;
  mtev_http2_parent_session *sess = calloc(1, sizeof(*sess));
  sess->ref_cnt = 1;
  sess->http_type = MTEV_HTTP_2;
  sess->e = e;
  sess->ac = ac;
  sess->dispatcher = f;
  sess->closure_creator = closure_creator;
  sess->closure_free = closure_free;
  sess->inbuff_size = 1 << 16;
  sess->inbuff = malloc(sess->inbuff_size);
  mtev_hash_init(&sess->streams);

  initialize_nghttp2_session(sess);

  if(settings && settings_len) {
    rv = nghttp2_session_upgrade2(sess->session, settings, settings_len,
                                  head_req, NULL);
    if(rv != 0) {
      mtevL(h2_debug, "http2 session upgrade failed: %s\n", nghttp2_strerror(rv));
      mtev_http2_parent_session_deref(sess, mtev_true);
      return NULL;
    }
  }

  nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, max_streams}};
  rv = nghttp2_submit_settings(sess->session, NGHTTP2_FLAG_NONE, iv, 1);
  if(rv == 0) {
    rv = nghttp2_session_send(sess->session);
    if(rv == 0) {
      mtevL(h2_debug, "http2 new session -> %p\n", sess);
      return sess;
    }
  }
  mtevL(h2_debug, "http2 session failed: %s\n", nghttp2_strerror(rv));
  mtev_http2_parent_session_deref(sess, mtev_true);
  return NULL;
}

mtev_http2_parent_session *
mtev_http2_parent_session_new(mtev_http_dispatch_func f,
                              void *(*closure_creator)(mtev_http_session_ctx *),
                              void (*closure_free)(void *),
                              eventer_t e, mtev_acceptor_closure_t *ac,
                              int max_streams) {
  return mtev_http2_parent_session_new_ex(f, closure_creator, closure_free, e, ac, max_streams, 0, NULL, 0);
}

mtev_http_session_ctx *
mtev_http2_session_new(mtev_http2_parent_session *parent, int32_t stream_id) {
  mtev_http2_session_ctx *sess = calloc(1, sizeof(*sess));
  sess->http_type = MTEV_HTTP_2;
  sess->ref_cnt = 1;
  sess->stream_id = stream_id;
  if(!mtev_hash_store(&parent->streams,
                      (void *)&sess->stream_id, sizeof(sess->stream_id), sess)) {
    mtevL(h2_debug, "http2 conflicts with existing stream %d\n", sess->stream_id);
    free(sess);
    return NULL;
  }
  mtev_http2_parent_session_ref(parent);
  sess->parent = parent;
  sess->dispatcher_closure = parent->closure_creator((mtev_http_session_ctx *)sess);
  sess->dispatcher_closure_free = parent->closure_free;

  sess->req.http_type = MTEV_HTTP_2;
  sess->res.http_type = MTEV_HTTP_2;
  mtev_gettimeofday(&sess->req.start_time, NULL);
  mtev_hash_init(&sess->req.headers);
  mtev_hash_init(&sess->req.querystring);
  sess->req.opts = MTEV_HTTP_CLOSE | MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE;
  mtev_hash_init(&sess->res.headers);
  mtev_hash_init(&sess->res.trailers);
  sess->res.output_options = MTEV_HTTP_CLOSE;

  mtevL(h2_debug, "http2 new stream(%p) -> %d\n", parent, stream_id);
  nghttp2_session_set_stream_user_data(parent->session, stream_id,
                                       sess);
  return (mtev_http_session_ctx *)sess;
}

void
mtev_http2_session_resume_aco(mtev_http2_session_ctx *ctx) {
  mtevAssert(mtev_http2_session_aco(ctx));
  (void)ctx->parent->dispatcher((mtev_http_session_ctx *)ctx);
}

void
mtev_http2_resume_all_unpaused_streams(mtev_http2_parent_session *ctx) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(&ctx->streams, &iter)) {
    mtev_http2_session_ctx *ctx = iter.value.ptr;
    /* If we're done, we're done. */
    if(ctx->res.closed) continue;
    /* We can only resume (dispatch) complete requests that are not ACO */
    if(ctx->req.complete && !ctx->res.complete && ctx->aco_enabled == mtev_false) {
      ctx->parent->dispatcher((mtev_http_session_ctx *)ctx);
    }
    if(ctx->paused == H2_UNPAUSED) {
      ctx->paused = H2_NORMAL;
      mtevL(h2_debug, "http2 session resuming with output data (%p -> %d)\n",
            ctx->parent, ctx->stream_id);
      nghttp2_session_resume_data(ctx->parent->session, ctx->stream_id);
    }
  }
}
int
mtev_http2_session_drive(eventer_t e, int origmask, void *closure,
                         struct timeval *now, int *done) {
  int mask;
  (void)now;
  mtev_http2_parent_session *ctx = closure;
  if (origmask & EVENTER_EXCEPTION) {
    mtevL(h2_debug, "http2 session ending %p (exception)\n", ctx);
    goto full_shutdown;
  }
  mask = 0;
  int rv = nghttp2_session_send(ctx->session);
  mtevL(h2_debug, "http2 drive -> %d\n", rv);
  if(rv != NGHTTP2_ERR_WOULDBLOCK && rv != 0) {
    mtevL(h2_debug, "http2 session_send(%p) %s\n", ctx, nghttp2_strerror(rv));
    goto full_shutdown;
  }
  if (origmask & EVENTER_READ) {
    while(1) {
      ssize_t len = eventer_read(e, ctx->inbuff + ctx->inbuff_wp, ctx->inbuff_size - ctx->inbuff_wp,
                                 &mask);
      if(len < 0) {
        if(errno == EAGAIN) {
          break;
        }
        goto full_shutdown; 
      }
      if(len == 0) {
        mtevL(h2_debug, "http session(%p) ended read->0\n", ctx);
        goto full_shutdown; 
      }
      ctx->inbuff_wp += len;
      ssize_t processed = nghttp2_session_mem_recv(ctx->session, ctx->inbuff, ctx->inbuff_wp);
      if(processed < 0) {
        mtevL(mtev_error, "http2 error: %s\n", nghttp2_strerror(processed));
        goto full_shutdown;
      }
      if((size_t)processed < ctx->inbuff_wp) {
        memmove(ctx->inbuff, ctx->inbuff + processed, ctx->inbuff_wp - processed);
      }
      ctx->inbuff_wp -= processed;
    }
  }
  mtevL(h2_debug, "http2 drive(%p) read done, submitting\n", ctx);
  mtev_http2_resume_all_unpaused_streams(ctx);
  rv = nghttp2_session_send(ctx->session);
  mtevL(h2_debug, "http2 drive -> %d\n", rv);
  if(rv == NGHTTP2_ERR_WOULDBLOCK) {
    mask |= EVENTER_WRITE;
  }
  else if(rv != 0) {
    mtevL(h2_debug, "http2 session_send(%p) %s\n", ctx, nghttp2_strerror(rv));
  }

  if(nghttp2_session_want_read(ctx->session) == 0 &&
     nghttp2_session_want_write(ctx->session) == 0) {
    mtevL(h2_debug, "http2 session complete %p (inline)\n", ctx);
    goto full_shutdown;
  }
  return (mask | EVENTER_READ | EVENTER_EXCEPTION);

 full_shutdown:
  ctx->e = NULL;
  *done = 1;
  /* We're done, but the accept closure free will take care of dropping
   * our lest reference to the parent session, so no need to deref here.
   */
  eventer_close(e, &mask);
  return 0;
}

int
mtev_http1_http2_upgrade(mtev_http1_session_ctx *ctx) {
  mtev_acceptor_closure_t *ac;
  const char *upgrade = NULL, *connection = NULL, *hdr_settings = NULL;
  char conn_lower[128], *cp;
  uint8_t settings[256];

  /* We have to rewire the whole world as a part of an upgrade...
   * We only know how to do this is the acceptor closure is within
   * the context of an mtev_rest handler... otherwise, you're just
   * out of luck, it is complexity we can't accomodate.
   */
  ac = mtev_http1_session_acceptor_closure(ctx);
  if(!mtev_rest_owns_accept_closure(ac))
    return 0;
  mtev_http_rest_closure_t *restc = mtev_acceptor_closure_ctx(ac);
  mtev_boolean aco_enabled = restc->aco_enabled;

  mtev_http1_request *req1 = mtev_http1_session_request(ctx);
  mtev_hash_table *headers = mtev_http1_request_headers_table(req1);
  if (headers == NULL) return 0;

  if(!mtev_hash_retr_str(headers, "connection", strlen("connection"), &connection))
    return 0;
  strlcpy(conn_lower, connection, sizeof(conn_lower));
  for(cp = conn_lower; *cp; cp++) *cp = tolower(*cp);
  if(!strstr(conn_lower, "upgrade")) return 0;
  if(!strstr(conn_lower, "http2-settings")) return 0;
  if(!mtev_hash_retr_str(headers, "upgrade", strlen("upgrade"), &upgrade))
    return 0;
  if(!mtev_hash_retr_str(headers, "http2-settings", strlen("http2-settings"), &hdr_settings))
    return 0;

  ssize_t settings_len = strlen(hdr_settings);
  if(settings_len > (ssize_t)sizeof(settings)) {
    return 0;
  }
  settings_len = mtev_b64_decode(hdr_settings, settings_len, settings, sizeof(settings));
  if(settings_len <= 0) {
    return 0;
  }

  /* Now we need to setup an http2 context */
  mtevL(h2_debug, "Upgrading http1 -> http2\n");
  mtev_http1_connection *conne = mtev_http1_session_connection(ctx);
  eventer_t e = mtev_http1_connection_event(conne);
#define UPGRADE_MESSAGE "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: HTTP/2.0\r\n\r\n"
  int mask = 0;
  ssize_t elen = eventer_write(e, UPGRADE_MESSAGE, sizeof(UPGRADE_MESSAGE)-1, &mask);
  if(elen != sizeof(UPGRADE_MESSAGE)-1) {
    return -1;
  }

  mtev_http1_session_ref_inc(ctx);
  mtev_http2_parent_session *sess =
    mtev_rest_http2_session_for_upgrade(ctx, settings, settings_len);
  if(sess == NULL) {
    mtev_http1_session_ref_dec(ctx);
    return -1;
  }

  mtev_http2_session_ctx *h2c = (mtev_http2_session_ctx *)mtev_http2_session_new(sess, 1);
  /* We need to move the request information over from the http1 req to this new one */
  const char *uri_str = mtev_http1_request_uri_str(req1);
  const char *orig_qs = mtev_http1_request_orig_querystring(req1);
  if(orig_qs) {
    int total_len = strlen(uri_str) + 1 + strlen(orig_qs) + 1;
    h2c->req.uri_str = malloc(total_len);
    snprintf(h2c->req.uri_str, total_len, "%s?%s", uri_str, orig_qs);
  } else {
    h2c->req.uri_str = strdup(mtev_http1_request_uri_str(req1));
  }
  mtev_http2_process_querystring(&h2c->req);
  h2c->req.method_str = strdup(mtev_http1_request_method_str(req1));
  h2c->req.opts = mtev_http1_request_opts(req1) & ~MTEV_HTTP_CHUNKED;
  h2c->req.opts |= MTEV_HTTP_CLOSE | MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE;
  mtev_hash_table *hdr1 = mtev_http1_request_headers_table(req1);
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(hdr1, &iter)) {
    mtev_hash_replace(&h2c->req.headers, strdup(iter.key.str), iter.klen,
                      strdup(iter.value.str), free, free);
  }

  /* mark the restc as aco, but not the session... it will fix itself correctly
   * in mtev_rest. */
  restc = h2c->dispatcher_closure;
  restc->aco_enabled = aco_enabled;

  mtev_http_begin_span((mtev_http_session_ctx *)h2c);
  h2c->req.complete = mtev_true;

  mtev_http1_session_ref_dec(ctx);
  return 1;
}

/* This registers the npn/alpn stuff with the eventer */
void
mtev_http2_init(void) {
  eventer_ssl_alpn_register("h2", (eventer_SSL_alpn_func_t)nghttp2_select_next_protocol);
  h2_debug = mtev_log_stream_find("debug/http2");
}
