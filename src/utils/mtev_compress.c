#include "mtev_compress.h"

#include "mtev_log.h"
#include <zlib.h>
#include <lz4frame.h>

struct mtev_stream_compress_ctx
{
  mtev_compress_type type;
  mtev_boolean begun;
  LZ4F_compressionContext_t lz4_compress_ctx;
  z_stream zlib_compress_ctx;
};

struct mtev_stream_decompress_ctx
{
  mtev_compress_type type;
  LZ4F_decompressionContext_t lz4_decompress_ctx;
  z_stream zlib_decompress_ctx;
};

size_t
mtev_compress_bound(mtev_compress_type type, size_t source_len)
{
  switch(type) {
  case MTEV_COMPRESS_LZ4F:
    return LZ4F_compressBound(source_len, NULL);
  case MTEV_COMPRESS_GZIP:
    return deflateBound(NULL, source_len);
  case MTEV_COMPRESS_DEFLATE:
    return compressBound(source_len);
  case MTEV_COMPRESS_NONE:
    return source_len;
  };
  return 0;
}

int 
mtev_compress_gzip(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len)
{
  z_stream stream;
  size_t max_compressed_len;
  int err;

  err = deflateInit2(&stream, 9, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
  if (err != Z_OK) {
    mtevL(mtev_error, "mtev_http_gzip -> deflateInit2: %d\n", err);
    return err;
  }
  
  stream.next_in = (Bytef *)data;
  stream.avail_in = len;
  max_compressed_len = deflateBound(&stream, len);

  *compressed = malloc(max_compressed_len);

  stream.next_out = (*compressed);
  stream.avail_out = max_compressed_len;

  err = deflate(&stream, Z_FINISH);
  if (err != Z_OK && err != Z_STREAM_END) {
    mtevL(mtev_error, "zlib deflate error: %d\n", err);
    deflateEnd(&stream);
    return err;
  }

  deflateEnd(&stream);
  *compressed_len = stream.total_out;
  return Z_OK;
}

int 
mtev_compress_lz4f(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len)
{
  LZ4F_compressionContext_t ctx;

  LZ4F_errorCode_t err = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
  if (LZ4F_isError(err)) {
    mtevL(mtev_error, "mtev_http_lz4f: Error creating compression context: %s\n",
            LZ4F_getErrorName(err));
    return err;
  }

  *compressed_len = LZ4F_compressBound(len, NULL) + 15;
  *compressed = malloc(*compressed_len);
  if (*compressed == NULL) {
    mtevL(mtev_error, "mtev_http_lz4f: Cannot allocate compression dest\n");
    return -1;
  }
  size_t s = LZ4F_compressBegin(ctx, *compressed, *compressed_len, NULL);
  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_http_lz4f: Error compressBegin: %s\n",
            LZ4F_getErrorName(s));
    return s;
  }
  s += LZ4F_compressUpdate(ctx, *compressed + s, *compressed_len - s, data, len, NULL);
  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_http_lz4f: Error compressUpdate: %s\n",
            LZ4F_getErrorName(s));
    return s;
  }
  s += LZ4F_compressEnd(ctx, *compressed + s, *compressed_len - s, NULL);
  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_http_lz4f: Error compressEnd: %s\n",
            LZ4F_getErrorName(s));
    return s;
  }
  *compressed_len = s;

  err = LZ4F_freeCompressionContext(ctx);
  if (LZ4F_isError(err)) {
    mtevL(mtev_error, "mtev_http_lz4f: Error freeing compression context: %s\n",
            LZ4F_getErrorName(err));
    return err;
  }

  return 0;
}

static int 
_mtev_compress_deflate(const char *data, size_t len, 
                       unsigned char *compressed, size_t *compressed_len)
{
  int err = compress2(compressed, compressed_len, (Bytef *)data, len, 9);
  if (err != Z_OK) {
    mtevL(mtev_error, "zlib compress2 error: %d\n", err);
    return err;
  }
  return 0;
}

int 
mtev_compress_deflate(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len)
{
  size_t max_compressed_len;
  int err;

  max_compressed_len = compressBound(len);
  *compressed = malloc(max_compressed_len);

  err = _mtev_compress_deflate(data, len, *compressed, &max_compressed_len);
  *compressed_len = max_compressed_len;
  return err;
}


int
mtev_compress(mtev_compress_type type, const char *data, size_t len, 
              unsigned char **compressed, size_t *compressed_len)
{
  switch(type) {
  case MTEV_COMPRESS_LZ4F:
    return mtev_compress_lz4f(data, len, compressed, compressed_len);
  case MTEV_COMPRESS_GZIP:
    return mtev_compress_gzip(data, len, compressed, compressed_len);
  case MTEV_COMPRESS_DEFLATE:
    return mtev_compress_deflate(data, len, compressed, compressed_len);
  case MTEV_COMPRESS_NONE:
    {
      *compressed = malloc(len);
      *compressed_len = len;
      memcpy(*compressed, data, len);
      return 0;
    }
  };
  /* unreached */
  return -1;
}

mtev_stream_compress_ctx_t *
mtev_create_stream_compress_ctx()
{
  mtev_stream_compress_ctx_t *rval = calloc(1, sizeof(mtev_stream_compress_ctx_t));
  return rval;
}

void
mtev_destroy_stream_compress_ctx(mtev_stream_compress_ctx_t *ctx)
{
  free(ctx);
}

mtev_stream_decompress_ctx_t *
mtev_create_stream_decompress_ctx()
{
  mtev_stream_decompress_ctx_t *rval = calloc(1, sizeof(mtev_stream_decompress_ctx_t));
  return rval;
}

void
mtev_destroy_stream_decompress_ctx(mtev_stream_decompress_ctx_t *ctx)
{
  free(ctx);
}

int
mtev_stream_compress_init(mtev_stream_compress_ctx_t *ctx, mtev_compress_type type)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->type = type;
  switch (type) {
  case MTEV_COMPRESS_GZIP:
    {
      int err = deflateInit2(&ctx->zlib_compress_ctx, 9, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
      if (err != Z_OK) {
        mtevL(mtev_error, "mtev_stream_compress_init: Error creating gzip compression context: %d\n", err);
      }
        
      return err;
    }   
  case MTEV_COMPRESS_LZ4F:
    {
      LZ4F_errorCode_t err = LZ4F_createCompressionContext(&ctx->lz4_compress_ctx, LZ4F_VERSION);
      if (LZ4F_isError(err)) {
        mtevL(mtev_error, "mtev_stream_compress_init: Error creating lz4f compression context: %s\n",
            LZ4F_getErrorName(err));
      }
      return err;
    }
  case MTEV_COMPRESS_DEFLATE:
    /* deflate has no stream init */
    return 0;
  default:
    return -1;
  };
  /* not reached */
  return -1;
}

static int
mtev_stream_compress_lz4f(mtev_stream_compress_ctx_t *ctx, const char *source_data,
                          size_t *source_len, unsigned char *out, size_t *out_len)
{
  size_t s = 0;
  if (ctx->begun == mtev_false) {
    s = LZ4F_compressBegin(ctx->lz4_compress_ctx, out, *out_len, NULL);
    if (LZ4F_isError(s)) {
      mtevL(mtev_error, "mtev_stream_compress_lz4f: Error compressBegin: %s\n",
              LZ4F_getErrorName(s));
      return -1;
    }
    ctx->begun = mtev_true;
  }

  size_t chunk = LZ4F_compressUpdate(ctx->lz4_compress_ctx, out + s, *out_len - s, 
                                     source_data, *source_len, NULL);
  if (LZ4F_isError(chunk)) {
    mtevL(mtev_error, "mtev_stream_compress_lz4f: Error compressupdate: %s\n",
          LZ4F_getErrorName(chunk));
    return -1;
  }
  s += chunk;
  *out_len = s;
  *source_len = 0;
  return 0;
}

static int
mtev_stream_compress_gzip(mtev_stream_compress_ctx_t *ctx, const char *source_data,
                          size_t *source_len, unsigned char *out, size_t *out_len)
{
  if (ctx->begun == mtev_false) {
    int x = deflateInit2(&ctx->zlib_compress_ctx, 9, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
    if (x != Z_OK) {
      mtevL(mtev_error, "mtev_stream_compress_gzip: error initing deflate stream: %d\n",
            x);
      return -1;
    }
    ctx->begun = mtev_true;
  }
  size_t in_len = *source_len;
  ctx->zlib_compress_ctx.next_in = (Bytef *)source_data;
  ctx->zlib_compress_ctx.avail_in = in_len;
  ctx->zlib_compress_ctx.next_out = out;
  ctx->zlib_compress_ctx.avail_out = *out_len;
  
  size_t t = ctx->zlib_compress_ctx.total_out;
  size_t ti = ctx->zlib_compress_ctx.total_in;
  int x = deflate(&ctx->zlib_compress_ctx, Z_NO_FLUSH);
  if (x != Z_OK) {
    mtevL(mtev_error, "mtev_stream_compress_gzip: error deflate stream: %d\n",
          x);
    return -1;    
  }
  /* order of operations matters here */
  *source_len = in_len - (ctx->zlib_compress_ctx.total_in - ti);
  *out_len = (ctx->zlib_compress_ctx.total_out - t);
  return 0;
}

int  
mtev_stream_compress(mtev_stream_compress_ctx_t *ctx, const char *source_data, 
                     size_t *len, unsigned char *out, size_t *out_len)
{
  switch (ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    return mtev_stream_compress_lz4f(ctx, source_data, len, out, out_len);
  case MTEV_COMPRESS_GZIP:
    return mtev_stream_compress_gzip(ctx, source_data, len, out, out_len);
  case MTEV_COMPRESS_DEFLATE:
    {
      int x = _mtev_compress_deflate(source_data, *len, out, out_len);
      *len = 0;
      return x;
    }
  case MTEV_COMPRESS_NONE:
    {
      if (*out_len < *len) {
        mtevL(mtev_error, "mtev_stream_compress: not enough space in out buffer\n");
        return -1;
      }
      memcpy(out, source_data, *len);
      *out_len = *len;
      *len = 0;
      return 0;
    }
  default:
    return -1;
  };
  return -1;
}

static int
mtev_stream_compress_flush_lz4f(mtev_stream_compress_ctx_t *ctx, 
                                unsigned char *out, size_t *out_len)
{
  if (ctx->begun == mtev_false) {
    return -1;
  }
  
  size_t s = LZ4F_flush(ctx->lz4_compress_ctx, out, *out_len, NULL);
  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_stream_compress_flush_lz4f: flush failed %s\n",
          LZ4F_getErrorName(s));
    return -1;
  }
  *out_len = s;
  return 0;
}

static int
mtev_stream_compress_flush_gzip(mtev_stream_compress_ctx_t *ctx, 
                                unsigned char *out, size_t *out_len)
{
  if (ctx->begun == mtev_false) {
    return -1;
  }

  size_t loop_out = 0;
  int x = 0;
  
  while (x != Z_STREAM_END && *out_len - loop_out > 0) {
    size_t total_out_pre_flush = ctx->zlib_compress_ctx.total_out;
    ctx->zlib_compress_ctx.next_out = out + loop_out;
    ctx->zlib_compress_ctx.avail_out = *out_len - loop_out;
    x = deflate(&ctx->zlib_compress_ctx, Z_FINISH);
    if (x != Z_OK && x != Z_STREAM_END) {
      mtevL(mtev_error, "mtev_stream_compress_flush_gzip: error flushing: %d\n", x);
      return x;
    }
    loop_out += ctx->zlib_compress_ctx.total_out - total_out_pre_flush;    
  }
  *out_len = loop_out;
  return 0;
}

int
mtev_stream_compress_flush(mtev_stream_compress_ctx_t *ctx, 
                           unsigned char *out, size_t *out_len)
{
  switch(ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    return mtev_stream_compress_flush_lz4f(ctx, out, out_len);
  case MTEV_COMPRESS_GZIP:
    return mtev_stream_compress_flush_gzip(ctx, out, out_len);
  case MTEV_COMPRESS_DEFLATE:
  case MTEV_COMPRESS_NONE:
    return 0;
  default:
    return -1;
  }
  return -1;
}

int
mtev_stream_compress_finish_lz4f(mtev_stream_compress_ctx_t *ctx)
{
  size_t s = LZ4F_compressEnd(ctx->lz4_compress_ctx, NULL, 0, NULL);
  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_stream_compress_finish_lz4f: finish failed %s\n",
          LZ4F_getErrorName(s));
    return -1;
  }
  LZ4F_freeCompressionContext(ctx->lz4_compress_ctx);
  return 0;
}

int 
mtev_stream_compress_finish_gzip(mtev_stream_compress_ctx_t *ctx)
{
  int x;
  ctx->zlib_compress_ctx.next_out = NULL;
  ctx->zlib_compress_ctx.avail_out = 0;
  ctx->zlib_compress_ctx.next_in = NULL;
  ctx->zlib_compress_ctx.avail_in = 0; 
  x = deflateEnd(&ctx->zlib_compress_ctx);
  return x;
}

int
mtev_stream_compress_finish(mtev_stream_compress_ctx_t *ctx) 
{
  switch(ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    return mtev_stream_compress_finish_lz4f(ctx);
  case MTEV_COMPRESS_GZIP:
    return mtev_stream_compress_finish_gzip(ctx);
  case MTEV_COMPRESS_DEFLATE:
  case MTEV_COMPRESS_NONE:
    return 0;
  default:
    return -1;
  }
  return -1;
}

int
mtev_stream_decompress_init(mtev_stream_decompress_ctx_t *ctx, 
                            mtev_compress_type type)
{
  ctx->type = type;
  switch(ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    {
      LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&ctx->lz4_decompress_ctx, 
                                                             LZ4F_VERSION);
      if (LZ4F_isError(err)) {
        mtevL(mtev_error, "mtev_stream_decompress_init: error create decompression context for lz4f: %s\n", LZ4F_getErrorName(err));
        return -1;
      }
      return 0;
    }
  case MTEV_COMPRESS_GZIP:
    {
      int err = inflateInit2(&ctx->zlib_decompress_ctx, 15 + 16);
      if (err != Z_OK) {
        mtevL(mtev_error, "mtev_stream_decompress_init: gzip error initing the zstream: %s\n",
            ctx->zlib_decompress_ctx.msg);
        return -1;
      }      
      return 0;
    }
  default:
    return -1;
  };
  return -1;
}

static int
mtev_stream_decompress_lz4f(mtev_stream_decompress_ctx_t *ctx, 
                            const unsigned char *compressed,
                            size_t *compressed_len,
                            unsigned char *decompressed,
                            size_t *decompressed_len)
{
  static LZ4F_decompressOptions_t opts = {
    .stableDst = 0
  };

  size_t in_size = *compressed_len;
  size_t out_size = *decompressed_len;
  size_t s = LZ4F_decompress(ctx->lz4_decompress_ctx,
                             decompressed, &out_size,
                             compressed, &in_size,
                             &opts);

  if (LZ4F_isError(s)) {
    mtevL(mtev_error, "mtev_stream_decompress_lz4f: error decompressing: %s\n",
          LZ4F_getErrorName(s));
    return -1;
  }  

  *compressed_len = in_size;
  *decompressed_len = out_size;
  return 0;
}

static int
mtev_stream_decompress_gzip(mtev_stream_decompress_ctx_t *ctx, 
                            const unsigned char *compressed,
                            size_t *compressed_len,
                            unsigned char *decompressed,
                            size_t *decompressed_len)
{
  size_t ti = ctx->zlib_decompress_ctx.total_in;
  size_t to = ctx->zlib_decompress_ctx.total_out;

  ctx->zlib_decompress_ctx.next_in = (Bytef *)compressed;
  ctx->zlib_decompress_ctx.avail_in = *compressed_len;
  ctx->zlib_decompress_ctx.next_out = decompressed;
  ctx->zlib_decompress_ctx.avail_out = *decompressed_len;
  
  int x = inflate(&ctx->zlib_decompress_ctx, 0);
  if (x != Z_OK && x != Z_STREAM_END) {
    mtevL(mtev_error, "mtev_stream_decompress_gzip: zlib error decompressing: %s\n",
          ctx->zlib_decompress_ctx.msg);
    return -1;
  }
  *compressed_len = ctx->zlib_decompress_ctx.total_in - ti;
  *decompressed_len = ctx->zlib_decompress_ctx.total_out - to;
  return 0;
}


int
mtev_stream_decompress(mtev_stream_decompress_ctx_t *ctx, 
                         const unsigned char *compressed,
                         size_t *compressed_len,
                         unsigned char *decompressed,
                         size_t *decompressed_len)
{
  switch(ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    return mtev_stream_decompress_lz4f(ctx, compressed, compressed_len,
                                       decompressed, decompressed_len);
  case MTEV_COMPRESS_GZIP:
    return mtev_stream_decompress_gzip(ctx, compressed, compressed_len,
                                       decompressed, decompressed_len);
  default:
    return -1;
  };
  return -1;
}

int
mtev_stream_decompress_finish(mtev_stream_decompress_ctx_t *ctx)
{
  switch (ctx->type) {
  case MTEV_COMPRESS_LZ4F:
    LZ4F_freeDecompressionContext(ctx->lz4_decompress_ctx);
    break;
  case MTEV_COMPRESS_GZIP:
    inflateEnd(&ctx->zlib_decompress_ctx);
    break;
  default:
    return 0;
  };
  return 0;
}
