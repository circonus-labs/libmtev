/*
 * Copyright (c) 2019-2022, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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


#ifndef MTEV_MODULES_CONSUL_H
#define MTEV_MODULES_CONSUL_H

#include <mtev_defines.h>
#include <mtev_hooks.h>
#include <mtev_hash.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtev_consul_service mtev_consul_service;
typedef struct service_register service_register;

MTEV_RUNTIME_RESOLVE(mtev_consul_service_alloc, mtev_consul_service_alloc_f,
                     mtev_consul_service *,
                     (const char *name, const char *id,
                      const char *address, unsigned short port,
                      mtev_hash_table *tags, bool tags_owned,
                      mtev_hash_table *meta, bool meta_owned),
                     (name, id, address, port, tags, tags_owned, meta, meta_owned))
MTEV_RUNTIME_AVAIL(mtev_consul_service_alloc, mtev_consul_service_alloc_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_free, mtev_consul_service_free_f, void,
                     (mtev_consul_service *cs), (cs))
MTEV_RUNTIME_AVAIL(mtev_consul_service_free, mtev_consul_service_free_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_id, mtev_consul_service_id_f, char *,
                     (mtev_consul_service *cs), (cs))
MTEV_RUNTIME_AVAIL(mtev_consul_service_id, mtev_consul_service_id_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_registry, mtev_consul_service_registry_f,
                     service_register *,
                     (const char *tmplname),
                     (tmplname))
MTEV_RUNTIME_AVAIL(mtev_consul_service_registry, mtev_consul_service_registry_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_register_register, mtev_consul_service_register_register_f,
                     void,
                     (service_register *r), (r))
MTEV_RUNTIME_AVAIL(mtev_consul_service_register_register, mtev_consul_service_register_register_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_register_deregister, mtev_consul_service_register_deregister_f,
                     void,
                     (service_register *r), (r))
MTEV_RUNTIME_AVAIL(mtev_consul_service_register_deregister, mtev_consul_service_register_deregister_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_register_deref, service_register_deref, void,
                     (service_register *sr), (sr))
MTEV_RUNTIME_AVAIL(mtev_consul_service_register_defree, service_register_deref)

MTEV_RUNTIME_RESOLVE(mtev_consul_set_passing, mtev_consul_set_passing_f, void,
                     (service_register *sr, int idx, const char *msg), (sr, idx, msg))
MTEV_RUNTIME_AVAIL(mtev_consul_set_passing, mtev_consul_set_passing_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_set_warning, mtev_consul_set_warning_f, void,
                     (service_register *sr, int idx, const char *msg), (sr, idx, msg))
MTEV_RUNTIME_AVAIL(mtev_consul_set_warning, mtev_consul_set_warning_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_set_critical, mtev_consul_set_critical_f, void,
                     (service_register *sr, int idx, const char *msg), (sr, idx, msg))
MTEV_RUNTIME_AVAIL(mtev_consul_set_critical, mtev_consul_set_critical_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_set_address, mtev_consul_service_set_address_f, void,
                     (mtev_consul_service *cs, const char *arg), (cs, arg))
MTEV_RUNTIME_AVAIL(mtev_consul_service_set_address, mtev_consul_service_set_address_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_set_port, mtev_consul_service_set_port_f, void,
                     (mtev_consul_service *cs, unsigned short port), (cs, port))
MTEV_RUNTIME_AVAIL(mtev_consul_service_set_port, mtev_consul_service_set_port_f)


MTEV_RUNTIME_RESOLVE(mtev_consul_service_check_none, mtev_consul_service_check_none_f, void,
                     (mtev_consul_service *cs), (cs))
MTEV_RUNTIME_AVAIL(mtev_consul_service_check_none, mtev_consul_service_check_none_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_check_push, mtev_consul_service_check_push_f, int,
                     (mtev_consul_service *cs, const char *name, unsigned ttl, unsigned dac),
                     (cs, name, ttl, dac))
MTEV_RUNTIME_AVAIL(mtev_consul_service_check_push, mtev_consul_service_check_push_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_check_tcp, mtev_consul_service_check_tcp_f, int,
                     (mtev_consul_service *cs, const char *name, const char *tcp,
                      const unsigned interval, const unsigned *timeout, unsigned dac),
                     (cs, name, tcp, interval, timeout, dac))
MTEV_RUNTIME_AVAIL(mtev_consul_service_check_tcp, mtev_consul_service_check_tcp_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_check_http, mtev_consul_service_check_http_f, int,
                     (mtev_consul_service *cs, const char *name,
                      const char *url, const char *method,
                      const unsigned interval, const unsigned *timeout, unsigned dac),
                     (cs, name, url, method, interval, timeout, dac))
MTEV_RUNTIME_AVAIL(mtev_consul_service_check_http, mtev_consul_service_check_http_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_service_check_https, mtev_consul_service_check_https_f, int,
                     (mtev_consul_service *cs, const char *name,
                      const char *url, const char *method,
                      const char *tlsservername, bool tlsskipverify,
                      const unsigned interval, const unsigned *timeout, unsigned dac),
                     (cs, name, url, method, tlsservername, tlsskipverify, interval, timeout, dac))
MTEV_RUNTIME_AVAIL(mtev_consul_service_check_https, mtev_consul_service_check_https_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_register, mtev_consul_register_f, bool,
                     (mtev_consul_service *cs), (cs))
MTEV_RUNTIME_AVAIL(mtev_consul_register, mtev_consul_register_f)

MTEV_RUNTIME_RESOLVE(mtev_consul_kv_attach, mtev_consul_kv_attach_function, void *,
                     (const char *path, void (*witness)(const char *, uint8_t *, size_t, uint32_t)),
                     (path, witness))
MTEV_RUNTIME_AVAIL(mtev_consul_kv_attach, mtev_consul_kv_attach_function) 

MTEV_RUNTIME_RESOLVE(mtev_consul_kv_detach, mtev_consul_kv_detach_function, void *,
                     (void *handle), (handle))
MTEV_RUNTIME_AVAIL(mtev_consul_kv_detach, mtev_consul_kv_detach_function) 

#ifdef __cplusplus
}
#endif

#endif
