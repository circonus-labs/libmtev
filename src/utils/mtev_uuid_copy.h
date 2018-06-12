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
 *    * Neither the name Circonus, Inc. nor the names
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


#ifndef UTILS_MTEV_UUID_COPY_H
#define UTILS_MTEV_UUID_COPY_H

#include <mtev_uuid.h>

static const uint8_t uuid_zero_uint8[16] = { 0 };

/*!
 \fn void mtev_uuid_copy(uuid_t dst, const uuid_t src)
 \brief Copy src to dst.

 Follows the same semantics of uuid_copy from libuuid
*/
static inline
void mtev_uuid_copy(uuid_t dst, const uuid_t src)
{
  memcpy((void *)dst, (const void *)src, sizeof(uuid_t));
}

/*!
 \fn int mtev_uuid_compare(const uuid_t uu1, const uuid_t uu2)
 \brief Compare to uuids
 \return 0 if equal, -1 if uu1 is less than uu2, 1 otherwise.

 Follows the same semantics of uuid_compare from libuuid
*/
static inline
int mtev_uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
  return memcmp((const void *)uu1, (const void *)uu2, sizeof(uuid_t));
}

/*!
 \fn void mtev_uuid_is_null(const uuid_t uu)
 \brief Determine if the supplied uuid is the null uuid.
 \return 0 if not null, 1 if null.

 Follows the same semantics of uuid_is_null from libuuid
*/
static inline
int mtev_uuid_is_null(const uuid_t uu) {
  return 0 == memcmp(uu, uuid_zero_uint8, 16);
}

/*!
 \fn void mtev_uuid_clear(uuid_t uu)
 \brief Set a uuid to the null uuid.

 Follows the same semantics of uuid_clear from libuuid
*/
static inline
void mtev_uuid_clear(uuid_t uu) {
  memset(uu, 0, 16);
}

#endif
