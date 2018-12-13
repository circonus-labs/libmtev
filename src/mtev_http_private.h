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
 *     * Neither the name Circonus, Inc. nor the names
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

#ifndef _MTEV_HTTP_PRIVATE_H
#define _MTEV_HTTP_PRIVATE_H

#include "mtev_defines.h"
#include "mtev_http.h"
#include "mtev_rest.h"

#define HTTP_SESSION_BASE \
  uint32_t http_type; \
  Zipkin_Span *zipkin_span; \
  stats_handle_t *record 

#define HTTP_RESPONSE_BASE \
  uint32_t http_type; \
  mtev_hash_table headers; \
  uint32_t output_options; \
  struct bchain *output;       /* data is pushed in here */ \
  struct bchain *output_last;  /* tail ptr */ \
  struct bchain *output_raw;   /* internally transcoded here for output */ \
  struct bchain *output_raw_last; /* tail ptr */ \
  size_t output_raw_offset;    /* tracks our offset */ \
  mtev_boolean output_started; /* locks the options and leader */ \
                               /*   and possibly output. */ \
  mtev_boolean closed;         /* set by _end() */ \
  mtev_boolean complete;       /* complete, drained and disposable */ \
  size_t bytes_written;        /* tracks total bytes written */ \
  mtev_stream_compress_ctx_t *compress_ctx; \
  size_t output_chain_bytes; \
  size_t output_raw_chain_bytes

struct mtev_http_connection { uint32_t http_type; };
struct mtev_http_request { uint32_t http_type; };
struct mtev_http_response {
  HTTP_RESPONSE_BASE;
};
struct mtev_http_session_ctx {
  HTTP_SESSION_BASE;
};

void mtev_http_begin_span(mtev_http_session_ctx *ctx);
void mtev_http_end_span(mtev_http_session_ctx *ctx);
void mtev_http_log_request(mtev_http_session_ctx *ctx);
int mtev_http1_http2_upgrade(mtev_http1_session_ctx *ctx);

typedef enum {
  BCHAIN_INLINE = 0,
  BCHAIN_MMAP
} bchain_type_t;

struct bchain {
  bchain_type_t type;
  mtev_compress_type compression;
  struct bchain *next, *prev;
  size_t start; /* where data starts (buff + start) */
  size_t size;  /* data length (past start) */
  size_t allocd;/* total allocation */
  size_t mmap_size; /* size of original mmap */
  char *buff;
  char _buff[1]; /* over allocate as needed */
};

#define DEFAULT_MAXWRITE 1<<14 /* 32k */
#define DEFAULT_BCHAINSIZE ((1 << 15)-(offsetof(struct bchain, _buff)))
/* 64k - delta */
#define DEFAULT_BCHAINMINREAD (DEFAULT_BCHAINSIZE/4)
#define BCHAIN_SPACE(a) ((a)->allocd - (a)->size - (a)->start)

#define ALLOC_BCHAIN(s) bchain_alloc(s, __LINE__)
#define FREE_BCHAIN(a) bchain_free(a, __LINE__)
#define RELEASE_BCHAIN(a) do { \
  struct bchain *__n = a; \
  while(__n) { \
    struct bchain *__b; \
    __b = __n; \
    __n = __b->next; \
    bchain_free(__b, __LINE__); \
  } \
  a = NULL; \
} while(0)

struct bchain *bchain_alloc(size_t size, int line);
struct bchain *bchain_mmap(int fd, size_t len, int flags, off_t offset);
void bchain_free(struct bchain *b, int line);
struct bchain *bchain_from_data(const void *d, size_t size);

static const char _hexchars[16] =
  {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
static inline void inplace_urldecode(char *c) {
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

static inline mtev_boolean
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

static inline struct bchain *
mtev_http_process_output_bchain(mtev_http_session_ctx *ctx,
                                struct bchain *in,
                                size_t *leftover_size) {
  struct bchain *out;
  int ilen, maxlen = in->size, hexlen;
  mtev_http_response *res = mtev_http_session_response(ctx);
  int opts = res->output_options;

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
  if(_http_encode_chain(res, out, in->buff + in->start, leftover_size,
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

static inline void
raw_finalize_encoding(mtev_http_response *res) {
  if(res->output_options & (MTEV_HTTP_GZIP | MTEV_HTTP_DEFLATE | MTEV_HTTP_LZ4F)) {
    mtev_boolean finished = mtev_false;
    struct bchain *r = res->output_raw_last;
    mtevAssert((r == NULL && res->output_raw == NULL) ||
           (r != NULL && res->output_raw != NULL));
    while(finished == mtev_false) {
      int hexlen, ilen;

      /*
       * using DEFAULT_BCHAINSIZE * 3 to deal with compression possibly inflating
       * the size of the data over the original when flushing.
       */
      struct bchain *out = ALLOC_BCHAIN(DEFAULT_BCHAINSIZE * 3);

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
        if(res->http_type == MTEV_HTTP_1) {
          out->buff[out->start + out->size++] = '\r';
          out->buff[out->start + out->size++] = '\n';
        }
        if(res->output_options & MTEV_HTTP_CHUNKED) {
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

static inline void
mtev_http_encode_output_raw(mtev_http_session_ctx *ctx, mtev_boolean *final) {
  mtev_http_response *res = mtev_http_session_response(ctx);
  struct bchain *r = res->output_raw_last;
  mtevAssert((r == NULL && res->output_raw == NULL) ||
         (r != NULL && res->output_raw != NULL));
  /* r is the last raw output link */
  struct bchain *o = res->output;
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
        res->output_chain_bytes -= tofree->size;
        free(tofree);
      }
      *final = mtev_true;
      break;
    }
    if (n->size > 0) {
      if(r) {
        r->next = n;
        n->prev = r;
        r = res->output_raw_last = n;
      }
      else {
        r = res->output_raw = res->output_raw_last = n;
      }
    }
    res->output_raw_chain_bytes += n->size;
    res->output_chain_bytes -= o->size - leftover_size;
    o->start += o->size - leftover_size;
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
  res->output = NULL;
  res->output_last = NULL;
  res->output_chain_bytes = 0;
}

/* will uncompress the chain at 'in' and write uncompressed chain at 'out' with
 * the last member of the out chain in 'last_out'
 * 
 * return -1 on error
 * otherwise return total_uncompressed_size 
 * */
static inline ssize_t
mtev_http_session_decompress(mtev_stream_decompress_ctx_t *dctx, struct bchain *in, 
                             struct bchain **out, struct bchain **last_out)
{
  ssize_t total_decompressed_size = 0;

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
      *out = NULL;
      *last_out = NULL;
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

#endif
