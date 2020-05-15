/*
 * Copyright (c) 2010, OmniTI Computer Consulting, Inc.
 * All rights reserved.
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
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
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

#ifndef _UTILS_MTEV_LOCKFILE_H
#define _UTILS_MTEV_LOCKFILE_H

#include "mtev_config.h"
#include "mtev_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int mtev_lockfile_t;

/*! \fn mtev_lockfile_t mtev_lockfile_acquire(const char *fp)
    \brief lock the file immediately if possible, return -1 otherwise.
    \param fp the path to the lock file
    \return >= 0 on success, -1 on failure
 */

API_EXPORT(mtev_lockfile_t)
  mtev_lockfile_acquire(const char *fp);

/*! \fn mtev_lockfile_t mtev_lockfile_acquire_owner(const char *fp, pid_t *owner)
    \brief lock the file immediately if possible, return -1 otherwise.
    \param fp the path to the lock file
    \param owner is a pointer to a pid.  If the lock is owned by another process, this will be set to that pid, otherwise it will be set to -1.
    \return >= 0 on success, -1 on failure
 */

API_EXPORT(mtev_lockfile_t)
  mtev_lockfile_acquire_owner(const char *fp, pid_t *owner);

/*! \fn int mtev_lockfile_release(mtev_lockfile_t fd)
    \brief release a held file lock
    \param fd the file lock to release
    \return -1 on failure, 0 on success
 */

API_EXPORT(int)
  mtev_lockfile_release(mtev_lockfile_t lf);

#ifdef __cplusplus
}
#endif

#endif
