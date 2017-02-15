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

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_stacktrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <execinfo.h>
#if defined(__sun__)
#include <ucontext.h>
#include <sys/lwp.h>
#endif
#if defined(__MACH__) && defined(__APPLE__)
#include <libproc.h>
#endif

#if defined(__sun__)
int mtev_simple_stack_print(uintptr_t pc, int sig, void *usrarg) {
  lwpid_t self;
  mtev_log_stream_t ls = usrarg;
  char addrline[128];
  self = _lwp_self();
  addrtosymstr((void *)pc, addrline, sizeof(addrline));
  mtevL(ls, "t@%d> %s\n", self, addrline);
  return 0;
}
#else
static int _global_stack_trace_fd = -1;
#endif

void mtev_stacktrace(mtev_log_stream_t ls) {
#if defined(__sun__)
  ucontext_t ucp;
  getcontext(&ucp);
  walkcontext(&ucp, mtev_simple_stack_print, ls);
#else
  if(_global_stack_trace_fd < 0) {
    /* Last ditch effort to open this up */
    /* This is Async-Signal-Safe (at least on Illumos) */
    char tmpfilename[MAXPATHLEN];
    snprintf(tmpfilename, sizeof(tmpfilename), "/var/tmp/mtev_%d_XXXXXX", (int)getpid());
    _global_stack_trace_fd = mkstemp(tmpfilename);
    if(_global_stack_trace_fd >= 0) unlink(tmpfilename);
  }
  if(_global_stack_trace_fd >= 0) {
    struct stat sb;
    char stackbuff[4096];
    void* callstack[128];
    int unused __attribute__((unused));
    int i, frames = backtrace(callstack, 128);
    lseek(_global_stack_trace_fd, 0, SEEK_SET);
    unused = ftruncate(_global_stack_trace_fd, 0);
    backtrace_symbols_fd(callstack, frames, _global_stack_trace_fd);
    memset(&sb, 0, sizeof(sb));
    while((i = fstat(_global_stack_trace_fd, &sb)) == -1 && errno == EINTR);
    if(i != 0 || sb.st_size == 0) mtevL(ls, "error writing stacktrace\n");
    lseek(_global_stack_trace_fd, SEEK_SET, 0);
    i = read(_global_stack_trace_fd, stackbuff, MIN(sizeof(stackbuff), sb.st_size));
    mtevL(ls, "STACKTRACE:\n%.*s\n", i, stackbuff);
  }
  else {
    mtevL(ls, "stacktrace unavailable\n");
  }
#endif
}
