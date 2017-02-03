/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_COMPRESS_H
#define _MTEV_COMPRESS_H

#include "mtev_defines.h"

typedef enum {
  MTEV_COMPRESS_NONE = 0,
  MTEV_COMPRESS_LZ4F,
  MTEV_COMPRESS_GZIP,
  MTEV_COMPRESS_DEFLATE
} mtev_compress_type;

typedef struct mtev_stream_compress_ctx mtev_stream_compress_ctx_t;
typedef struct mtev_stream_decompress_ctx mtev_stream_decompress_ctx_t;

/**
 * @return worst case destination size for source_len
 */
API_EXPORT(size_t)
  mtev_compress_bound(mtev_compress_type type, size_t source_len);

/**
 * Will gzip 'data' of size 'len' and fill 'compressed' with the
 * compressed version after it allocates space.  'compressed_len' will
 * hold the new length.
 * 
 * It is up to the caller to free compressed data.
 * 
 * Better compression than lz4f variant below at the cost of greater
 * CPU.
 * 
 * @return 0 on success
 * @return non-zero on error
 */
API_EXPORT(int)
  mtev_compress_gzip(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len);

/**
 * Will lz4f 'data' of size 'len' and fill 'compressed' with the
 * compressed version after it allocates space.  'compressed_len' will
 * hold the new length.
 * 
 * It is up to caller to free compressed data;
 * 
 * Choose this where you want some compression but don't want to pay
 * as much CPU cost as gzip.
 * 
 * @return 0 on success
 * @return non-zero on error
 */
API_EXPORT(int)
  mtev_compress_lz4f(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len);


/**
 * Will deflate (zlib compress2) 'data' of size 'len' and fill
 * 'compressed' with the compressed version after it allocates space.
 * 'compressed_len' will hold the new length.
 * 
 * It is up to caller to free compressed data;
 * 
 * Choose this where you want some compression but don't want to pay
 * as much CPU cost as gzip.
 * 
 * @return 0 on success
 * @return non-zero on error
 */
API_EXPORT(int)
  mtev_compress_deflate(const char *data, size_t len, unsigned char **compressed, size_t *compressed_len);


/** 
 * Wrapper function for the above.  If you pass MTEV_COMPRESS_NONE as type, 
 * this is effectively an allocation and memcpy.
 */
API_EXPORT(int)
  mtev_compress( mtev_compress_type type, const char *data, size_t len, unsigned char **compressed, size_t *compressed_len);

/**
 * Allocate a new stream compress context
 */
API_EXPORT(mtev_stream_compress_ctx_t *)
  mtev_create_stream_compress_ctx();

/**
 * Destroy previosly created stream compress context
 */
API_EXPORT(void)
  mtev_destroy_stream_compress_ctx(mtev_stream_compress_ctx_t *ctx);

/**
 * Allocate a new stream decompress context
 */
API_EXPORT(mtev_stream_decompress_ctx_t *)
  mtev_create_stream_decompress_ctx();

/**
 * Destroy previosly created stream decompress context
 */
API_EXPORT(void)
  mtev_destroy_stream_decompress_ctx(mtev_stream_decompress_ctx_t *ctx);

/**
 * Initialize a stream compression context for compressing of type.
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_compress_init(mtev_stream_compress_ctx_t *ctx, mtev_compress_type type);

/**
 * To be called multiple times to compress a stream of data.  You must first call
 * mtev_stream_compress_init to initialize the stream compression structure
 * 
 * The out_len param will be updated with amount written to output.
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_compress(mtev_stream_compress_ctx_t *ctx, const char *source_data, 
                         size_t len, unsigned char *out, size_t *out_len);

/**
 * Flush any internal data cached during the stream compress.  You might
 * have to call repeatedly until out_len contains zero.
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_compress_flush(mtev_stream_compress_ctx_t *ctx, 
                                unsigned char *out, size_t *out_len);

/**
 * Will destroy the internals of the stream compress context
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_compress_finish(mtev_stream_compress_ctx_t *ctx);

/**
 * initialize a streaming decompression session for type
 */
API_EXPORT(int)
  mtev_stream_decompress_init(mtev_stream_decompress_ctx_t *ctx, 
                              mtev_compress_type type);


/**
 * Decompress chunks of data in a stream.
 * 
 * The (de)compressed_len is an in/out param that will be updated
 * with the number of bytes used or filled from the (out|in)put.
 * 
 * Decompression is considered complete when this function returns success and
 * *decompressed_len == 0
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_decompress(mtev_stream_decompress_ctx_t *ctx, 
                         const unsigned char *compressed,
                         size_t *compressed_len,
                         unsigned char *decompressed,
                         size_t *decompressed_len);

/**
 * complete and free any internal structs for this stream decompression
 * 
 * @return 0 on success, non-zero on error
 */
API_EXPORT(int)
  mtev_stream_decompress_finish(mtev_stream_decompress_ctx_t *ctx);



#endif
