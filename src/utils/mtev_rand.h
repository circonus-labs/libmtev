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
 *     * Neither the name Circonus, Inc. nor the names
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

#ifndef MTEV_RAND_H
#define MTEV_RAND_H

#include "mtev_defines.h"

/* mtev rand no long requires initialization, this is a noop */
#define mtev_rand_init()

/*! \fn uint64_t mtev_rand(void)
    \brief Generate a pseudo-random number between [0,2^64)
    \return A pseudo-random number in the range [0,2^64)
 */
API_EXPORT(uint64_t)
  mtev_rand(void);

/*! \fn uint64_t mtev_rand_trysecure(void)
    \brief Generate a likely secure, but possibly pseudo-random number between [0,2^64)
    \return A random pseudo-random number in the range [0,2^64)
 */
API_EXPORT(uint64_t)
  mtev_rand_trysecure(void);

/*! \fn int mtev_rand_secure(uint64_t *out)
    \brief Generate a secure random number.
    \param out A pointer to a `uint64_t` in which a securely generated random number will be stored.
    \return 0 on success, -1 on failure (not enough entropy available).
 */
API_EXPORT(int)
  mtev_rand_secure(uint64_t *);

/*! \fn size_t mtev_rand_buf(void *buf, size_t len)
    \brief Fill a buffer with pseudo-random bytes.
    \param buf A buffer to fill.
    \param len The number of bytes to populate.
    \return The number of bytes written to `buf` (always `len`).
 */
API_EXPORT(size_t)
  mtev_rand_buf(void *, size_t);

/*! \fn size_t mtev_rand_buf_trysecure(void *buf, size_t len)
    \brief Fill a buffer with likely secure, but possibly pseudo-random bytes.
    \param buf A buffer to fill.
    \param len The number of bytes to populate.
    \return The number of bytes written to `buf` (always `len`).
 */
API_EXPORT(size_t)
  mtev_rand_buf_trysecure(void *, size_t);

/*! \fn size_t mtev_rand_buf_secure(void *buf, size_t len)
    \brief Fill a buffer with securely random bytes.
    \param buf A buffer to fill.
    \param len The number of bytes to populate.
    \return The number of bytes written to `buf` (< len if insufficient entropy).
 */
API_EXPORT(size_t)
  mtev_rand_buf_secure(void *, size_t);

#endif /* MTEV_RAND_H */
