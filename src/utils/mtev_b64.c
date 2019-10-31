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

#include "mtev_config.h"
#include "mtev_b64.h"
#include "aklomp-base64/include/libbase64.h"
#include <ctype.h>

int
mtev_b64_decode(const char *src, size_t src_len,
                unsigned char *dest, size_t dest_len) {
  const unsigned char *cp = (unsigned char *)src;
  unsigned char *dcp = dest;
  unsigned char ch, in[4], out[3];
  size_t ib = 0, ob = 3, needed = (((src_len + 3) / 4) * 3);
  /* Needed here is 2 bytes shy of what could be needed...
   * decoding can be "short" up to 2 bytes. */

  if(dest_len < needed - 2) return 0;
  else if(src_len > 1 && src[src_len-2] != '=' && src[src_len-1] == '=') {
    if(dest_len < needed - 1) return 0;
  }
  else if(src_len > 1 && src[src_len-2] != '=' && src[src_len-1] != '=') {
    if(dest_len < needed) return 0;
  }
  /* Attempt The aklomp fast decode */
  size_t used_len = dest_len;
  if(base64_decode(src, src_len, (char *)dest, &used_len, 0) == 1) {
    return used_len;
  }
  /* Otherwise fallback to the slow path */
  while(cp <= ((unsigned char *)src+src_len)) {
    if((*cp >= 'A') && (*cp <= 'Z')) ch = *cp - 'A';
    else if((*cp >= 'a') && (*cp <= 'z')) ch = *cp - 'a' + 26;
    else if((*cp >= '0') && (*cp <= '9')) ch = *cp - '0' + 52;
    else if(*cp == '+' || *cp == '-') ch = 62;
    else if(*cp == '/' || *cp == '_') ch = 63;
    else if(*cp == '=') ch = 0xff;
    else if(isspace((int)*cp)) { cp++; continue; }
    else break;
    cp++;
    if(ch == 0xff) {
      if(ib == 0) break;
      if(ib == 1 || ib == 2) ob = 1;
      else ob = 2;
      ib = 3;
    }
    in[ib++] = ch;
    if(ib == 4) {
      out[0] = (in[0] << 2) | ((in[1] & 0x30) >> 4);
      out[1] = ((in[1] & 0x0f) << 4) | ((in[2] & 0x3c) >> 2);
      out[2] = ((in[2] & 0x03) << 6) | (in[3] & 0x3f);
      for(ib = 0; ib < ob; ib++)
        *dcp++ = out[ib];
      ib = 0;
    }
  }
  return dcp - (unsigned char *)dest;
}

size_t
mtev_b64_max_decode_len(size_t src_len) {
  return ((src_len + 3) / 4) * 3;
}

int
mtev_b64_encode(const unsigned char *src, size_t src_len,
                char *dest, size_t dest_len) {
  struct iovec iov;

  iov.iov_base = (void *) src;
  iov.iov_len = src_len;
  return mtev_b64_encodev(&iov, 1, dest, dest_len);
}

int
mtev_b64_encodev(const struct iovec *iov, size_t iovcnt,
                 char *dest, size_t dest_len) {
  size_t iov_index;
  size_t src_len;
  char *eptr = dest;
  size_t n;

  src_len = 0;
  for (iov_index = 0; iov_index < iovcnt; iov_index++)
    src_len += iov[iov_index].iov_len;
  n = (((src_len + 2) / 3) * 4);

  if(dest_len < n) return 0;

  struct base64_state bstate;
  base64_stream_encode_init(&bstate, 0);
  size_t outlen = 0;
  for(iov_index = 0; iov_index < iovcnt; iov_index++) {
    base64_stream_encode(&bstate, iov[iov_index].iov_base, iov[iov_index].iov_len,
                         eptr, &outlen);
    eptr += outlen;
  }
  base64_stream_encode_final(&bstate, eptr, &outlen);
  eptr += outlen;
  return eptr - dest;
}

size_t
mtev_b64_encode_len(size_t src_len) {
  return 4 * ((src_len+2)/3);
}
