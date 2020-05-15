/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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


#ifndef _MTEV_AMQP_H
#define _MTEV_AMQP_H

#include <mtev_defines.h>
#include <mtev_hooks.h>

#ifdef __cplusplus
extern "C" {
#endif

struct amqp_connection_state_t_;
struct amqp_envelope_t_;

/*! \fn void mtev_amqp_send(struct amqp_envelope_t_ *env, int mandatory, int immediate, int id)
    \brief Publish an AMQP message to one of the configured amqp brokers.
    \param env An envelope with a valid message. The env pointer must be word aligned.
    \param mandatory Set to non-zero if the message should be sent with the mandatory flag.
    \param immediate Set to non-zero if the message should be sent with the immediate flag.
    \param id the ID of the connection: -1 to broadcast.
 */
MTEV_RUNTIME_RESOLVE(mtev_amqp_send, mtev_amqp_send_function, void,
                     (struct amqp_envelope_t_ *env, int mandatory, int immediate, int id), (env, mandatory, immediate, id))
MTEV_RUNTIME_AVAIL(mtev_amqp_send, mtev_amqp_send_function)

/*! \fn void mtev_amqp_send_data(char *exchange, char *route, int mandatory, int immediate, void *payload, int len, int id)
    \brief Publish an AMQP message to one of the configured amqp brokers.
    \param exchange The AMQP exchange to publish to.
    \param route The route to set on the message.
    \param mandatory Set to non-zero if the message should be sent with the mandatory flag.
    \param immediate Set to non-zero if the message should be sent with the immediate flag.
    \param payload the contents of the message.
    \param len the number of bytes present in payload.
    \param id the ID of the connection: -1 to broadcast.
 */
MTEV_RUNTIME_RESOLVE(mtev_amqp_send_data, mtev_amqp_send_data_function, void,
                     (char *exchange, char *route, int mandatory, int immediate, void *payload, int len, int id),
                     (exchange, route, mandatory, immediate, payload, len, id))
MTEV_RUNTIME_AVAIL(mtev_amqp_send_data, mtev_amqp_send_data_function)

MTEV_HOOK_PROTO(mtev_amqp_handle_message_dyn,
                (struct amqp_connection_state_t_ *client, int id, struct amqp_envelope_t_ *msg, void *payload, size_t payload_len),
                void *, closure,
                (void *closure, struct amqp_connection_state_t_ *client, int id, struct amqp_envelope_t_ *msg, void *payload, size_t payload_len))

/* This maps exposes a runtime resolved hook register function people should
 * use: mtev_amqp_handle_message_hook_register
 */
MTEV_RUNTIME_AVAIL(mtev_amqp_handle_message_hook_register,
                   mtev_amqp_handle_message_dyn_hook_register)
MTEV_RUNTIME_RESOLVE(mtev_amqp_handle_message_hook_register,
                     mtev_amqp_handle_message_dyn_hook_register,
                     mtev_hook_return_t,
                     (const char *name,
                      mtev_hook_return_t (*func) (void *closure, struct amqp_connection_state_t_ *client, int id, struct amqp_envelope_t_ *msg, void *payload, size_t payload_len),
                      void *closure),
                     (name,func,closure))


MTEV_HOOK_PROTO(mtev_amqp_handle_connection_dyn,
                (struct amqp_connection_state_t_ *client, int id, mtev_boolean connected),
                void *, closure,
                (void *closure, struct amqp_connection_state_t_ *client, int id, mtev_boolean connected))

/* This maps exposes a runtime resolved hook register function people should
 * use: mtev_amqp_handle_connection_hook_register
 */
MTEV_RUNTIME_AVAIL(mtev_amqp_handle_connection_hook_register,
                   mtev_amqp_handle_connection_dyn_hook_register)
MTEV_RUNTIME_RESOLVE(mtev_amqp_handle_connection_hook_register,
                     mtev_amqp_handle_connection_dyn_hook_register,
                     mtev_hook_return_t,
                     (const char *name,
                      mtev_hook_return_t (*func) (void *closure, struct amqp_connection_state_t_ *client, int id, mtev_boolean connected),
                      void *closure),
                     (name,func,closure))

#ifdef __cplusplus
}
#endif

#endif
