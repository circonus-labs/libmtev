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

#include "mtev_defines.h"
#include "mtev_str.h"
#include "mtev_log.h"

#ifndef HAVE_STRNSTRN

#define GROWTH_FACTOR(a) (((a) + ((a) >> 1))+1)

#define KMPPATSIZE 256
static void kmp_precompute(const char *pattern, int pattern_len,
                           int *compile_buf) {
  int i=0, j=-1;

  compile_buf[0] = j;
  while (i < pattern_len) {
    while (j > -1 && pattern[i] != pattern[j])
      j = compile_buf[j];
    i++; j++;
    if (pattern[i] == pattern[j])
      compile_buf[i] = compile_buf[j];
    else
      compile_buf[i] = j;
  }
}

const char *strnstrn(const char *needle, int needle_len,
                     const char *haystack, int haystack_len) {
  int i=0, j=0, compiled[KMPPATSIZE];

  if(needle_len > KMPPATSIZE) {
    mtevFatal(mtev_error, "errorin strnstrn: needle_len (%d) < KMPPATSIZE (%d)\n",
            needle_len, KMPPATSIZE);
  }
  kmp_precompute(needle, needle_len, compiled);
  while (j < haystack_len) {
    while (i > -1 && needle[i] != haystack[j])
      i = compiled[i];
    i++; j++;
    if (i >= needle_len) {
      return haystack + j - i;
    }
  }
  return NULL;
}

char *
mtev__strndup(const char *src, size_t len) {
  int slen;
  char *dst;
  for(slen = 0; slen < len; slen++)
    if(src[slen] == '\0') break;
  dst = malloc(slen + 1);
  memcpy(dst, src, slen);
  dst[slen] = '\0';
  return dst;
}

void
mtev_prepend_str(mtev_prependable_str_buff_t *buff, const char* str,
    uint str_len) {
  if (buff->string - buff->buff < str_len) {
    int bytes_stored = buff->buff_len - (buff->string - buff->buff);
    int new_buff_len = GROWTH_FACTOR(buff->buff_len + str_len);
    char* tmp = calloc(1, new_buff_len);
    buff->buff_len = new_buff_len;
    memcpy(tmp + buff->buff_len - bytes_stored, buff->string, bytes_stored);
    free(buff->buff);
    buff->buff = tmp;
    buff->string = buff->buff + buff->buff_len - bytes_stored;
  }

  buff->string -= str_len;
  memcpy(buff->string, str, str_len);
}

mtev_prependable_str_buff_t *
mtev_prepend_str_alloc_sized(u_int initial_len) {
  mtev_prependable_str_buff_t* buff = calloc(1, sizeof(mtev_prependable_str_buff_t));

  buff->buff_len = initial_len;
  buff->buff = calloc(1, buff->buff_len);
  buff->string = buff->buff + buff->buff_len;

  return buff;
}

mtev_prependable_str_buff_t *
mtev_prepend_str_alloc() {
  return mtev_prepend_str_alloc_sized(8);
}

void
mtev_prepend_str_free(mtev_prependable_str_buff_t *buff) {
  if(buff->buff) {
    free(buff->buff);
  }
  free(buff);
}

int
mtev_prepend_strlen(mtev_prependable_str_buff_t *buff) {
  if(buff != NULL) {
    return buff->buff + buff->buff_len - buff->string;
  }
  return 0;
}

void mtev_append_str_buff(mtev_str_buff_t *buff, const char* str, uint str_len) {
  if (buff->end - buff->string - buff->buff_len < str_len) {
    int bytes_stored = buff->end - buff->string;
    int new_buff_len = GROWTH_FACTOR(buff->buff_len + str_len);
    char* tmp = calloc(1, new_buff_len);
    buff->buff_len = new_buff_len;
    memcpy(tmp, buff->string, bytes_stored);
    free(buff->string);
    buff->string = tmp;
    buff->end = buff->string + bytes_stored;
  }

  memcpy(buff->end, str, str_len);
  buff->end += str_len;
}

mtev_str_buff_t *
mtev_str_buff_alloc_sized(u_int initial_len) {
  mtev_str_buff_t* buff = calloc(1, sizeof(mtev_str_buff_t));

  buff->buff_len = initial_len;
  buff->string = calloc(1, buff->buff_len);
  buff->end = buff->string;

  return buff;
}

mtev_str_buff_t *
mtev_str_buff_alloc() {
  return mtev_str_buff_alloc_sized(8);
}

void
mtev_str_buff_free(mtev_str_buff_t *buff) {
  if(buff->string) {
    free(buff->string);
  }
  free(buff);
}

int
mtev_str_buff_len(mtev_str_buff_t *buff) {
  if(buff != NULL) {
    return buff->end - buff->string;
  }
  return 0;
}

#endif

