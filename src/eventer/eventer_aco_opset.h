/*
 * Copyright (c) 2018, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its
 *       contributors may be used to endorse or promote products
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

#ifndef _EVENTER_EVENTER_ACO_FD_OPSET_H
#define _EVENTER_EVENTER_ACO_FD_OPSET_H

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "aco/aco.h"

extern eventer_fd_opset_t eventer_aco_fd_opset;

/*! \fn eventer_aco_t eventer_set_eventer_aco_co(eventer_t e, aco_t *co)
    \brief Convert an eventer_t into an eventer_aco_t.
    \param e an event object
    \param co a coroutine to which the event should bound. NULL to revert.
    \return The converted event.

    The input event is modified in-place.  If the NULL is passed as co,
    then the event is reverted and NULL is returned.  You almost always
    want to be calling this on a brand-new object or a `eventer_alloc_copy`
    of a pre-existing object.
*/
API_EXPORT(eventer_aco_t)
  eventer_set_eventer_aco_co(eventer_t e, aco_t *co);

/*! \fn eventer_aco_t eventer_set_eventer_aco(eventer_t e)
    \brief Convert an eventer_t into an eventer_aco_t.
    \param e an event object
    \return The converted event.

    This calls `eventer_set_eventer_aco_co` with the current aco
    as the `co` argument.
*/
API_EXPORT(eventer_aco_t)
  eventer_set_eventer_aco(eventer_t e);

#endif
