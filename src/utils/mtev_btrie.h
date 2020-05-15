/*
 * Copyright (c) 2011, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
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
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
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

#ifndef UTILS_MTEV_BTRIE_H
#define UTILS_MTEV_BTRIE_H

#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct btrie_collapsed_node *mtev_btrie;

void mtev_btrie_drop_tree(mtev_btrie *, void (*)(void *));
void mtev_btrie_add_route(mtev_btrie *, uint32_t *, unsigned char, void *);
void mtev_btrie_add_route_ipv4(mtev_btrie *, struct in_addr *, unsigned char, void *);
void mtev_btrie_add_route_ipv6(mtev_btrie *, struct in6_addr *, unsigned char, void *);
int mtev_btrie_del_route_ipv4(mtev_btrie *, struct in_addr *, unsigned char,
                   void (*)(void *));
int mtev_btrie_del_route_ipv6(mtev_btrie *, struct in6_addr *, unsigned char,
                   void (*)(void *));
void *mtev_btrie_find_bpm_route_ipv4(mtev_btrie *tree, struct in_addr *a, unsigned char *);
void *mtev_btrie_find_bpm_route_ipv6(mtev_btrie *tree, struct in6_addr *a, unsigned char *);

#ifdef __cplusplus
}
#endif

#endif
