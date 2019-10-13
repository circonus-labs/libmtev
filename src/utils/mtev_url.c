/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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
 *    * Neither the name Circonus, Inc. nor the names
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
#include "mtev_url.h"
#include "mtev_log.h"
#include <ck_bitmap.h>

/* perl:
 * for($i=0;$i<8;$i++) {
 *   $b = 0;
 *   for($j=32;$j>=0;$j--) {
 *     $b <<= 1;
 *     if(chr($i*32+$j) =~ /[-_.~A-Za-z0-9]/) { $b |= 1; }
 *   }
 *   printf("%s0x%x", $i ? "," : "", $b);
 * }
 */
static const CK_BITMAP_INSTANCE(256) isallowed = { 
  .content = { .n_bits = 256,
               .map = { 0x0,0x3ff6000,0x87fffffe,0x47fffffe,0x0,0x0,0x0,0x0 }
  }
};
static const uint8_t hexval[256] = { 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15,
  0, 0,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static const char _hexchars[16] =
  {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

int
mtev_url_decode(const char *src, size_t src_len,
                unsigned char *dest, size_t dest_len) {
  if(dest_len < src_len + 1) return 0;
  const uint8_t *inp = (const uint8_t *)src;
  uint8_t *outp = dest;
  for(size_t i = 0; i < src_len; i++) {
    if(src[i] == '%') {
      if(i+2 >= src_len) return 0; /* ran out of input */
      if(!((hexval[inp[i+1]] || src[i+1] == '0') &&
           (hexval[inp[i+2]] || src[i+2] == '0'))) return 0; /* bad encoding */
      *outp++ = (hexval[inp[i+1]] << 4) | hexval[inp[i+2]];
      i+=2;
    }
    else if(ck_bitmap_test(&isallowed.bitmap, inp[i])) {
      *outp++ = inp[i];
    }
    else {
      mtevL(mtev_error, "CHAR %c is not allowed\n", src[i]);
      return 0; /* this character should have been encoded! */
    }
  }
  return outp-dest;
}

size_t
mtev_url_max_decode_len(size_t src_len) {
  return src_len + 1;
}

int
mtev_url_encode(const unsigned char *src, size_t src_len,
                char *dest, size_t dest_len) {
  char *outp = dest;
  if(src >= (unsigned char *)dest && src < (unsigned char *)dest + dest_len) {
    /* We're attempting to encode in place and must move the src so we don't
     * overwrite ourselves as we read.
     */
    memmove(dest + dest_len - src_len, src, src_len);
    src = (unsigned char *)dest + dest_len - src_len;
  }
  if(dest_len < src_len * 3) return 0;
  for(size_t i=0; i<src_len; i++) {
    if(ck_bitmap_test(&isallowed.bitmap, src[i])) {
      *outp++ = ((char *)src)[i];
    } else {
      *outp++ = '%';
      *outp++ = _hexchars[src[i] >> 4];
      *outp++ = _hexchars[src[i] & 0xf];
    }
  }
  *outp = '\0';
  return outp - dest;
}

size_t
mtev_url_encode_len(size_t src_len) {
  return src_len * 3 + 1;
}

int
mtev_html_encode(const char *src, size_t src_len, char *dest_in, size_t dest_len) {
  char *dest = dest_in;
  const char *srcend = src + src_len;
  char *dend = dest + dest_len;
  if(dest_len < 1) return 0;
  while(src < srcend && *src) {
    switch(*src) {
      case '<':
        if(dest >= dend - (1 + 4)) return 0;
        *dest++ = '&';
        *dest++ = 'l';
        *dest++ = 't';
        *dest++ = ';';
        break;
      case '>':
        if(dest >= dend - (1 + 4)) return 0;
        *dest++ = '&';
        *dest++ = 'g';
        *dest++ = 't';
        *dest++ = ';';
        break;
      case '&':
        if(dest >= dend - (1 + 5)) return 0;
        *dest++ = '&';
        *dest++ = 'a';
        *dest++ = 'm';
        *dest++ = 'p';
        *dest++ = ';';
        break;
      case '"':
        if(dest >= dend - (1 + 5)) return 0;
        *dest++ = '&';
        *dest++ = '#';
        *dest++ = '3';
        *dest++ = '4';
        *dest++ = ';';
        break;
      case '\'':
        if(dest >= dend - (1 + 5)) return 0;
        *dest++ = '&';
        *dest++ = '#';
        *dest++ = '3';
        *dest++ = '9';
        *dest++ = ';';
        break;
      default:
        if(dest >= dend - 2) return 0;
        *dest++ = *src;
        break;
    }
    src++;
  }
  *dest = '\0';
  return dest - dest_in;
}
size_t
mtev_html_encode_len(size_t len) {
  return len*5 + 1;
}
