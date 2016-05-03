/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
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


#ifndef _MTEV_FQ_H
#define _MTEV_FQ_H

#include <mtev_defines.h>
#include <mtev_hooks.h>
#include <fq.h>

/* void mtev_fq_send(fq_msg *msg, int id); */
MTEV_RUNTIME_RESOLVE(mtev_fq_send, mtev_fq_send_function, void,
                     (fq_msg *msg, int id), (msg, id))

MTEV_HOOK_PROTO(mtev_fq_handle_message_dyn,
                (fq_client client, int id, fq_msg *msg),
                void *, closure,
                (void *closure, fq_client client, int id, fq_msg *msg))

/* This maps exposes a runtime resolved hook register function people should
 * use: mtev_fq_handle_message_hook_register
 */
MTEV_RUNTIME_RESOLVE(mtev_fq_handle_message_hook_register,
                     mtev_fq_handle_message_dyn_hook_register,
                     mtev_hook_return_t,
                     (const char *name,
                      mtev_hook_return_t (*func) (void *closure, fq_client client, int id, fq_msg *msg),
                      void *closure),
                     (name,func,closure))

#endif
