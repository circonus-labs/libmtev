/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
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

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "libmtev_dtrace.h"

#include <sys/socket.h>
#include <unistd.h>

static int
POSIX_accept(int fd, struct sockaddr *addr, socklen_t *len,
             int *mask, void *closure) {
  int rv;
  LIBMTEV_EVENTER_ACCEPT_ENTRY(fd, (void *)addr, *len, *mask, closure);
  *mask = EVENTER_READ | EVENTER_EXCEPTION;
  rv = accept(fd, addr, len);
  LIBMTEV_EVENTER_ACCEPT_RETURN(fd, (void *)addr, *len, *mask, closure, rv);
  return rv;
}

static int
POSIX_read(int fd, void *buffer, size_t len,
           int *mask, void *closure) {
  int rv;
  LIBMTEV_EVENTER_READ_ENTRY(fd, buffer, len, *mask, closure);
  *mask = EVENTER_READ | EVENTER_EXCEPTION;
  rv = read(fd, buffer, len);
  LIBMTEV_EVENTER_READ_RETURN(fd, buffer, len, *mask, closure, rv);
  return rv;
}

static int
POSIX_write(int fd, const void *buffer, size_t len,
            int *mask, void *closure) {
  int rv;
  LIBMTEV_EVENTER_WRITE_ENTRY(fd, (char *)buffer, len, *mask, closure);
  *mask = EVENTER_WRITE | EVENTER_EXCEPTION;
  rv = write(fd, buffer, len);
  LIBMTEV_EVENTER_WRITE_RETURN(fd, (char *)buffer, len, *mask, closure, rv);
  return rv;
}

static int
POSIX_close(int fd, int *mask, void *closure) {
  int rv;
  *mask = 0;
  LIBMTEV_EVENTER_CLOSE_ENTRY(fd, *mask, closure);
  rv = close(fd);
  LIBMTEV_EVENTER_CLOSE_RETURN(fd, *mask, closure, rv);
  mtevL(eventer_deb, "POSIX_close(%d) -> %d\n", fd, rv);
  return rv;
}

static void
POSIX_set_opset(void *closure, struct _fd_opset *v) {
  eventer_t e = closure;
  e->opset = v;
}

static void *
POSIX_get_opset_ctx(void *closure) {
  eventer_t e = closure;
  return e->opset_ctx;
}

static void
POSIX_set_opset_ctx(void *closure, void *v) {
  eventer_t e = closure;
  e->opset_ctx = v;
}

struct _fd_opset _eventer_POSIX_fd_opset = {
  POSIX_accept,
  POSIX_read,
  POSIX_write,
  POSIX_close,
  POSIX_set_opset,
  POSIX_get_opset_ctx,
  POSIX_set_opset_ctx,
  "POSIX"
};

eventer_fd_opset_t eventer_POSIX_fd_opset = &_eventer_POSIX_fd_opset;
