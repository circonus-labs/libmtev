/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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

#ifndef _MTEV_CONSOLE_SOCKET_H
#define _MTEV_CONSOLE_SOCKET_H

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "noitedit/histedit.h"
#include "mtev_console_telnet.h"
#include "mtev_dyn_buffer.h"
#include "mtev_hash.h"
#include "mtev_skiplist.h"
#include <stdarg.h>

struct mtev_console_socket_t {
  eventer_t e;           /* The event it is attached to.  This
                          * is needed so it can write itself out */

  /* nice console support */
  EditLine *el;
  History *hist;
  /* This is console completion magic */
  int mtev_edit_complete_cmdnum;
  int rl_point;
  int rl_end;

  mtev_boolean isatty;
  mtev_dyn_buffer_t *dbuf; /* to fill when not a tty */
  int   pty_master;
  int   pty_slave;

  /* Output buffer for non-blocking sends */
  pthread_mutex_t outbuf_lock;
  char *outbuf;
  int   outbuf_allocd;
  int   outbuf_len;
  int   outbuf_cooked;
  int   outbuf_completed;

  /* This tracks telnet protocol state (if we're doing telnet) */
  mtev_console_telnet_closure_t telnet;
  void (*output_cooker)(struct __mtev_console_closure *);

  /* Storing history */
  pthread_mutex_t hist_file_lock;
  char *hist_file;
};

#endif
