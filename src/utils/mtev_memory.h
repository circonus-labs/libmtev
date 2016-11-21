/*
 * Copyright (c) 2014-2016, Circonus, Inc. All rights reserved.
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
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
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

#ifndef _UTILS_MTEV_MEMORY_H
#define _UTILS_MTEV_MEMORY_H

#include "mtev_defines.h"
#include <stdbool.h>

typedef enum {
  MTEV_MM_BARRIER,
  MTEV_MM_TRY,
  MTEV_MM_BARRIER_ASYNCH
} mtev_memory_maintenance_method_t;

API_EXPORT(void) mtev_memory_init(); /* call once at process start */
API_EXPORT(void) mtev_memory_init_thread(); /* at subsequent thread start */
API_EXPORT(void) mtev_memory_maintenance(); /* Call to force reclamation */
API_EXPORT(int) mtev_memory_maintenance_ex(mtev_memory_maintenance_method_t method);
API_EXPORT(void) mtev_memory_begin(); /* being a block */
API_EXPORT(void) mtev_memory_end(); /* end a block */
API_EXPORT(mtev_boolean) mtev_memory_barriers(mtev_boolean *); /* do or try */
API_EXPORT(void *) mtev_memory_safe_malloc(size_t r);
API_EXPORT(void *) mtev_memory_safe_malloc_cleanup(size_t r, void (*)(void *));
API_EXPORT(void *) mtev_memory_safe_calloc(size_t nelem, size_t elsize);
API_EXPORT(char *) mtev_memory_safe_strdup(const char *in);
API_EXPORT(void) mtev_memory_safe_free(void *p);

/* Used to power ck functions requiring allocation */
API_EXPORT(void *) mtev_memory_ck_malloc(size_t r);
API_EXPORT(void) mtev_memory_ck_free(void *p, size_t b, bool r);

#define MTEV_ALLOC_HINT_SAMETHREAD 0x1
#define MTEV_ALLOC_HINT_NOCORE     0x2

typedef struct mtev_allocator_options *mtev_allocator_options_t;
typedef struct mtev_allocator *mtev_allocator_t;

API_EXPORT(mtev_allocator_options_t) mtev_allocator_options_create();
API_EXPORT(void) mtev_allocator_options_free(mtev_allocator_options_t);
API_EXPORT(void)
  mtev_allocator_options_alignment(mtev_allocator_options_t, size_t alignment);
API_EXPORT(void)
  mtev_allocator_options_fixed_size(mtev_allocator_options_t, size_t size);
API_EXPORT(void)
  mtev_allocator_options_fill(mtev_allocator_options_t, uint64_t fill);
API_EXPORT(void)
  mtev_allocator_options_freelist_perthreadlimit(mtev_allocator_options_t, int items);
API_EXPORT(void)
  mtev_allocator_options_hints(mtev_allocator_options_t, uint32_t hints);
API_EXPORT(mtev_allocator_t)
  mtev_allocator_create(mtev_allocator_options_t);

API_EXPORT(void *)
  mtev_malloc(mtev_allocator_t, size_t size);
API_EXPORT(void *)
  mtev_calloc(mtev_allocator_t, size_t nmemb, size_t elemsize);
API_EXPORT(void *)
  mtev_realloc(mtev_allocator_t, void *ptr, size_t size);
API_EXPORT(void)
  mtev_free(mtev_allocator_t, void *ptr);

#endif
