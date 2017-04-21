/*
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

#ifndef _UTILS_MTEV_CHT_H
#define _UTILS_MTEV_CHT_H

#include "mtev_defines.h"

typedef struct mtev_cht mtev_cht_t;

typedef struct {
  /* Caller supplied */
  char *name;
  void *userdata;
  void (*userdata_freefunc)(void *);

  /* CHT maintained */
  double owned;
} mtev_cht_node_t;

API_EXPORT(mtev_cht_t *) mtev_cht_alloc(void);
API_EXPORT(mtev_cht_t *)
  mtev_cht_alloc_custom(uint16_t vnodes_per_node, uint8_t nbits);
API_EXPORT(void) mtev_cht_free(mtev_cht_t *);
API_EXPORT(int)
  mtev_cht_set_nodes(mtev_cht_t *, int node_cnt, mtev_cht_node_t *nodes);

API_EXPORT(int)
  mtev_cht_lookup(mtev_cht_t *, const char *key, mtev_cht_node_t **node);
API_EXPORT(int)
  mtev_cht_vlookup(mtev_cht_t *, const void *key, size_t keylen, mtev_cht_node_t **node);
API_EXPORT(int)
  mtev_cht_lookup_n(mtev_cht_t *, const char *key, int w, mtev_cht_node_t **node);
API_EXPORT(int)
  mtev_cht_vlookup_n(mtev_cht_t *, const void *key, size_t keylen, int w, mtev_cht_node_t **nodes);

#endif
