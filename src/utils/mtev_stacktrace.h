/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_STACKTRACE_H
#define _MTEV_STACKTRACE_H

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "aco/aco.h"

API_EXPORT(void)
  mtev_stacktrace(mtev_log_stream_t ls);

API_EXPORT(void)
  mtev_stacktrace_skip(mtev_log_stream_t ls, int ignore);

API_EXPORT(void)
  mtev_stacktrace_ucontext_skip(mtev_log_stream_t ls, ucontext_t *ucp, int ignore);

#if defined(__sun__)
#include <ucontext.h>
API_EXPORT(void)
  mtev_stacktrace_ucontext(mtev_log_stream_t ls, ucontext_t *);
#endif

API_EXPORT(int)
  mtev_aco_stacktrace(mtev_log_stream_t ls, aco_t *co);

API_EXPORT(int)
  mtev_aco_stacktrace_skip(mtev_log_stream_t ls, aco_t *co, int ignore);

API_EXPORT(int)
  mtev_backtrace(void **ips, int cnt);

API_EXPORT(int)
  mtev_backtrace_ucontext(void **ips, ucontext_t *, int cnt);

API_EXPORT(int)
  mtev_aco_backtrace(aco_t *co, void **addrs, int addrs_len);

API_EXPORT(const char *)
  mtev_function_name(uintptr_t);

API_EXPORT(void)
  mtev_dwarf_disable(void);

// Call this function after loading any modules.
API_EXPORT(void)
  mtev_dwarf_refresh(void);

API_EXPORT(void)
  mtev_dwarf_filter(mtev_boolean (*f)(const char *file));

API_EXPORT(void)
  mtev_dwarf_filter_symbols(mtev_boolean (*f)(const char *file));

MTEV_HOOK_PROTO(mtev_stacktrace_frame,
                (void (*cb)(void *, const char *, size_t), void *cb_closure,
                 uintptr_t pc, const char *file, const char *func, int frame, int nframes),
                void *, closure,
                (void *closure, void (*cb)(void *, const char *, size_t), void *cb_closure,
                 uintptr_t pc, const char *file, const char *func, int frame, int nframes))

#endif
