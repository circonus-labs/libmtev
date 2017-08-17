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
#if defined(linux) || defined(__linux) || defined(__linux__)
#include <sys/types.h>
#include <sys/syscall.h>
#endif
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
#include "android-demangle/demangle.h"
#include "android-demangle/cp-demangle.h"

static void
mtev_print_stackline(mtev_log_stream_t ls, uintptr_t self, const char *addrline) {
  char *tick;
  char addrpostline[16384], scratch[8192], postfix_copy[32], trailer_copy[32];
  strlcpy(addrpostline, addrline, sizeof(addrpostline));
  tick = strchr(addrpostline, '\'');
  if(!tick) tick = strchr(addrpostline, '(');
  if(tick) {
    char *trailer = NULL;
    char *postfix;
    if(*tick == '(') {
      postfix = strchr(tick, ')');
      if(postfix) {
        *postfix++ = '\0';
        trailer = postfix;
        strlcpy(trailer_copy, trailer, sizeof(trailer_copy));
      }
    }
    *tick++ = '\'';
    postfix = strrchr(tick, '+');
    if(postfix) {
     if(strlen(postfix) > sizeof(postfix_copy)-1) goto print;
     *postfix++ = '\0';
     strlcpy(postfix_copy, postfix, sizeof(postfix_copy));
    }
    scratch[0] = '\0';
    cplus_demangle_set_buf(scratch, sizeof(scratch));
    char *decoded = cplus_demangle_v3(tick, DMGL_PARAMS|DMGL_ANSI|DMGL_TYPES);
    if(decoded != NULL) {
      snprintf(tick, sizeof(addrpostline) - (int)(tick-addrpostline), "%s%s%s%s%s",
               decoded, postfix?"+":"", postfix_copy, trailer ? " " : "", trailer_copy);
    }
    else {
      if(postfix) *(postfix-1) = '+';
    }
  }
 print:
  mtevL(ls, "t@%"PRIu64"> %s\n", self, addrpostline);
}
#if defined(__sun__)
int mtev_simple_stack_print(uintptr_t pc, int sig, void *usrarg) {
  lwpid_t self;
  mtev_log_stream_t ls = usrarg;
  char addrpreline[16384];
  self = _lwp_self();
  addrtosymstr((void *)pc, addrpreline, sizeof(addrpreline));
  mtev_print_stackline(ls, self, addrpreline);
  return 0;
}
#else
static int _global_stack_trace_fd = -1;
#endif

void mtev_stacktrace(mtev_log_stream_t ls) {
#if defined(__sun__)
  ucontext_t ucp;
  getcontext(&ucp);
  mtevL(ls, "STACKTRACE(%d):\n", getpid());
  walkcontext(&ucp, mtev_simple_stack_print, ls);
#else
  if(_global_stack_trace_fd < 0) {
    /* Last ditch effort to open this up */
    /* This is Async-Signal-Safe (at least on Illumos) */
    char tmpfilename[MAXPATHLEN];
    snprintf(tmpfilename, sizeof(tmpfilename), "/var/tmp/mtev_%d_XXXXXX", (int)getpid());
    int oldmask = umask(0600);
    _global_stack_trace_fd = mkstemp(tmpfilename);
    umask(oldmask);
    if(_global_stack_trace_fd >= 0) unlink(tmpfilename);
  }
  if(_global_stack_trace_fd >= 0) {
    struct stat sb;
    char stackbuff[65536];
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
    i = read(_global_stack_trace_fd, stackbuff, MIN(sizeof(stackbuff)-1, sb.st_size));
    if (i >= 0) {
      stackbuff[i] = '\0';
    } else {
      snprintf(stackbuff, sizeof(stackbuff) - 1, "*** Cannot read stacktrace from %d ***", _global_stack_trace_fd);
    }
    char *prevcp = stackbuff, *cp;
    mtevL(ls, "STACKTRACE(%d):\n", getpid());
#if defined(linux) || defined(__linux) || defined(__linux__)
    uintptr_t self = syscall(SYS_gettid);
#else
    pthread_t self = pthread_self();
#endif
    while(NULL != (cp = strchr(prevcp, '\n'))) {
      *cp++ = '\0';
      mtev_print_stackline(ls, self, prevcp);
      prevcp = cp;
    }
    mtev_print_stackline(ls, self, prevcp);
  }
  else {
    mtevL(ls, "stacktrace unavailable\n");
  }
#endif
}
