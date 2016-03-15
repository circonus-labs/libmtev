/*
 * Copyright (c) 2005-2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
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

#ifndef _MTEV_B64_H
#define _MTEV_B64_H

/*!  \file mtev_b64.h

     Interface to the mtev base64 encoding and decoding routines.
 */

#include "mtev_config.h"
#include "mtev_defines.h"

/*! \fn int mtev_b64_decode(const char *src, size_t src_len, unsigned char *dest, size_t dest_len)
    \brief Decode a base64 encoded input buffer into the provided output buffer.
    \param src The buffer containing the encoded content.
    \param src_len The size (in bytes) of the encoded data.
    \param dest The destination buffer to which the function will produce.
    \param dest_len The size of the destination buffer.
    \return The size of the decoded output.  Returns zero is dest_len is too small.
    
    mtev_b64_decode decodes input until an the entire input is consumed or until an invalid base64 character is encountered.
 */
API_EXPORT(int) mtev_b64_decode(const char *, size_t, unsigned char *, size_t);
/*! \fn size_t mtev_b64_max_decode_len(size_t src_len)
    \brief Calculate how large a buffer must be to contain a decoded base-64-encoded string of a given length.
    \param src_len The size (in bytes) of the base-64-encoded string that might be decoded.
    \return The size of the buffer that would be needed to decode the input string.
 */
API_EXPORT(size_t) mtev_b64_max_decode_len(size_t);
/*! \fn int mtev_b64_encode(const unsigned char *src, size_t src_len, char *dest, size_t dest_len)
    \brief Encode raw data as base64 encoded output into the provided buffer.
    \param src The buffer containing the raw data.
    \param src_len The size (in bytes) of the raw data.
    \param dest The destination buffer to which the function will produce.
    \param dest_len The size of the destination buffer.
    \return The size of the encoded output.  Returns zero is out_sz is too small.

    mtev_b64_encode encodes an input string into a base64 representation with no linefeeds.
 */
API_EXPORT(int) mtev_b64_encode(const unsigned char *, size_t, char *, size_t);
/*! \fn size_t mtev_b64_encode_len(size_t src_len)
    \brief Calculate how large a buffer must be to contain the base-64 encoding for a given number of bytes.
    \param src_len The size (in bytes) of the raw data buffer that might be encoded.
    \return The size of the buffer that would be needed to store an encoded version of an input string.
 */
API_EXPORT(size_t) mtev_b64_encode_len(size_t);

#endif
