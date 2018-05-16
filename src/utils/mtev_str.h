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

#ifndef _UTILS_MTEV_STR_H
#define _UTILS_MTEV_STR_H

#include "mtev_defines.h"

typedef struct mtev_prependable_str_buff{
  char *buff;
  char *string;
  size_t buff_len;
} mtev_prependable_str_buff_t;

typedef struct mtev_str_buff{
  char *string;
  char *end;
  size_t buff_len;
} mtev_str_buff_t;

#ifndef HAVE_STRNSTRN
API_EXPORT(const char *) strnstrn(const char *, int, const char *, int) __attribute__((deprecated)); /*1.2.9*/
#endif

API_EXPORT(void *) mtev_memmem(const void *haystack, size_t haystacklen,
                               const void *needle, size_t needlelen);

API_EXPORT(char *) mtev__strndup(const char *src, size_t len);

API_EXPORT(mtev_prependable_str_buff_t *) mtev_prepend_str_alloc(void);
API_EXPORT(mtev_prependable_str_buff_t *) mtev_prepend_str_alloc_sized(size_t initial_len);
API_EXPORT(void) mtev_prepend_str(mtev_prependable_str_buff_t *buff, const char* str, size_t str_len);
API_EXPORT(void) mtev_prepend_str_free(mtev_prependable_str_buff_t *buff);
API_EXPORT(int) mtev_prepend_strlen(mtev_prependable_str_buff_t *buff);

API_EXPORT(mtev_str_buff_t *) mtev_str_buff_alloc(void);
API_EXPORT(mtev_str_buff_t *) mtev_str_buff_alloc_sized(size_t);
API_EXPORT(void) mtev_append_str_buff(mtev_str_buff_t *buff, const char* str, size_t str_len);
API_EXPORT(void) mtev_str_buff_free(mtev_str_buff_t *buff);
API_EXPORT(int) mtev_str_buff_len(mtev_str_buff_t *buff);
API_EXPORT(char*) mtev_str_buff_to_string(mtev_str_buff_t **buff);


#endif
