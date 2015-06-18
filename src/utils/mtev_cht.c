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

#include "mtev_cht.h"
#include "mtev_hash.h"

#include <assert.h>

#define DEFAULT_CHT_BITS 32
#define DEFAULT_WEIGHT 32
#define CHT_INITVAL 20021010
#define CHT_MAX_W 16

struct ring_pos {
  u_int32_t pos;
  unsigned short node_idx;
  unsigned short vnode;
};
struct mtev_cht {
  u_int8_t nbits;
  u_int16_t weight;
  int node_cnt;
  int collisions;
  mtev_cht_node_t *nodes;
  struct ring_pos *ring;
};

static inline u_int32_t
mtev_cht_hash(mtev_cht_t *cht, const void *key, size_t keylen, int ival) {
  u_int32_t hv;
  u_int32_t mask;
  hv = mtev_hash__hash(key, (u_int32_t)keylen, ival);
  if(cht->nbits == 32) return hv;
  mask = (1 << cht->nbits) - 1;
  return hv & mask;
}

static inline int iarrcontains(int n, int *ids, int what) {
  int i;
  for(i=0;i<n;i++) if(ids[i] == what) return i;
  return -1;
}

static int ring_node_cmp(const void *a, const void *b) {
  const struct ring_pos *ar = a;
  const struct ring_pos *br = b;
  if(ar->pos < br->pos) return -1;
  if(ar->pos > br->pos) return 1;
  return 0;
}

static void
mtev_cht_calculate_ring(mtev_cht_t *cht) {
  int rsize = cht->node_cnt * cht->weight;
  int i, j, idx = 0;
  int collision = 1;
  u_int32_t max;
  struct ring_pos *s, *e;

  if(cht->nbits == 32) max = ~0U;
  else max = (1 << cht->nbits) - 1;

  /* HASH */
  for(i=0;i<cht->node_cnt;i++) {
    cht->nodes[i].owned = 0.0;
    for(j=0;j<cht->weight;j++) {
      cht->ring[idx].node_idx = i;
      cht->ring[idx].vnode = j;
      cht->ring[idx].pos =
        mtev_cht_hash(cht, cht->nodes[i].name, strlen(cht->nodes[i].name), j);
      idx++;
    }
  }

  /* SORT */
  qsort(cht->ring, rsize, sizeof(*cht->ring), ring_node_cmp);

  /* FIX POSSIBLE COLLISIONS */
  cht->collisions = 0;
  while(collision) {
    collision = 0;
    for(i=rsize-1;i>0;i--) {
      s = &cht->ring[i-1];
      e = &cht->ring[i];
      if(s->pos == e->pos && s->pos != 0) {
        i--;
        while(i > 0) {
          s = &cht->ring[i--];
          if(s->pos == e->pos && s->pos > 0) {
            s->pos--;
            collision = 1;
            cht->collisions++;
          }
        }
      }
    }
  }
  /* We could have collision at zero now */
  collision = 1;
  while(collision) {
    collision = 0;
    for(i=0;i<rsize-1;i++) {
      s = &cht->ring[i];
      e = &cht->ring[i+1];
      if(s->pos == e->pos && e->pos != max) {
        i++;
        while(i < rsize) {
          e = &cht->ring[i++];
          if(s->pos == e->pos && e->pos < max) {
            e->pos++;
            collision = 1;
            cht->collisions++;
          }
        }
      }
    }
  }

  /* CALCULATE OWNERSHIP */
  for(i=0;i<rsize-1;i++) {
    s = &cht->ring[i];
    e = &cht->ring[i+1];
    assert(s->pos <= max);
    cht->nodes[s->node_idx].owned +=
      (double)(e->pos - s->pos)/((double)max + 1.0);
  }
  /* the last element wraps */
  s = &cht->ring[rsize-1];
  e = &cht->ring[0];
  assert(s->pos <= max);
  cht->nodes[s->node_idx].owned +=
    ((double)(max - s->pos) + 1.0 + (double)(e->pos))/((double)max + 1.0);
}

mtev_cht_t *
mtev_cht_alloc_custom(u_int16_t weight, u_int8_t nbits) {
  mtev_cht_t *cht;
  cht = calloc(1, sizeof(*cht));
  if(nbits == 0) nbits = DEFAULT_CHT_BITS;
  if(nbits > 32) nbits = 32;
  if(nbits < 16) nbits = 16;
  cht->nbits = nbits;
  cht->weight = (weight < 1) ? 1 : weight;
  return cht;
}

mtev_cht_t *
mtev_cht_alloc() {
  return mtev_cht_alloc_custom(DEFAULT_WEIGHT, 0);
}
void
mtev_cht_free(mtev_cht_t *cht) {
  mtev_cht_set_nodes(cht, 0, NULL);
  free(cht);
}
int
mtev_cht_set_nodes(mtev_cht_t *cht, int node_cnt, mtev_cht_node_t *nodes) {
  int i;
  for(i=0; i<cht->node_cnt; i++) {
    if(cht->nodes[i].name) free(cht->nodes[i].name);
    if(cht->nodes[i].userdata_freefunc)
      cht->nodes[i].userdata_freefunc(cht->nodes[i].userdata);
  }
  if(cht->nodes) free(cht->nodes);

  if(node_cnt < 0) node_cnt = 0;
  if(cht->nbits < 32) while(node_cnt * cht->weight > (1 << cht->nbits)) node_cnt--;
  cht->node_cnt = node_cnt;
  cht->nodes = nodes;
  if(cht->ring) free(cht->ring);
  cht->ring = NULL;
  if(node_cnt) {
    cht->ring = calloc(node_cnt * cht->weight, sizeof(*cht->ring));
    mtev_cht_calculate_ring(cht);
  }
  return node_cnt;
}

int
mtev_cht_vlookup_n(mtev_cht_t *cht, const void *key, size_t keylen,
                   int w, mtev_cht_node_t **nodes) {
  int i, l, r, m, rsize = cht->node_cnt * cht->weight;
  int w_out = 0;
  int found[CHT_MAX_W];
  u_int32_t val, hash;

  if(w > CHT_MAX_W) w = CHT_MAX_W;
  if(w < 0) w = 0;
  if(cht->node_cnt < 1) return -1;
  hash = mtev_cht_hash(cht, key, keylen, CHT_INITVAL);

  /* binary search for the node */
  l = 0;
  r = rsize;
  while(l < r) {
    m = (l + r) / 2;
    val = cht->ring[m].pos;
    if(hash == val) break;
    if(hash < val) r = m;
    else if(l == m) break;
    else l = m;
  }

  /* handle wrap under */
  if(hash < cht->ring[m].pos) {
    assert(m == 0);
    m = rsize - 1;
  }
  for(i=m;w_out < cht->node_cnt && i < rsize+m;i++) {
    int id = cht->ring[i % rsize].node_idx;
    if(iarrcontains(w_out, found, id) < 0) {
      found[w_out++] = id;
    }
  }
  found[w_out++] = cht->ring[m].node_idx;
  for(i=0;i<w && i<w_out;i++)
    nodes[i] = &cht->nodes[found[i]];
  return i;
}
int
mtev_cht_lookup(mtev_cht_t *cht, const char *key, mtev_cht_node_t **node) {
  return mtev_cht_vlookup_n(cht, key, strlen(key), 1, node);
}
int
mtev_cht_vlookup(mtev_cht_t *cht, const void *key, size_t keylen,
                 mtev_cht_node_t **node) {
  return mtev_cht_vlookup_n(cht, key, keylen, 1, node);
}
int
mtev_cht_lookup_n(mtev_cht_t *cht, const char *key,
                  int w, mtev_cht_node_t **node) {
  return mtev_cht_vlookup_n(cht, key, strlen(key), w, node);
}
