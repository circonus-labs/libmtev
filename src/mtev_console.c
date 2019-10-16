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

#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#include <errno.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#elif HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#include <arpa/telnet.h>
#include <signal.h>

#include <yajl/yajl_gen.h>
extern void
yajl_string_encode(const yajl_print_t print, void * ctx,
                   const unsigned char * str, size_t len,
                   int escape_solidus);

#ifdef HAVE_WSLAY
#include <wslay/wslay.h>
#endif

#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_listener.h"
#include "mtev_console.h"
#include "mtev_console_socket.h"
#include "mtev_console_websocket.h"
#include "mtev_dyn_buffer.h"
#include "mtev_json.h"
#include "mtev_json_tokener.h"
#include "mtev_tokenizer.h"
#include "mtev_rest.h"

#include "noitedit/sys.h"
#include "noitedit/el.h"
#include "noitedit/fcns.h"
#include "noitedit/map.h"

static mtev_log_stream_t errorls, debugls;

MTEV_HOOK_IMPL(mtev_console_dispatch,
               (struct __mtev_console_closure *ncct, const char *buffer),
               void *, closure,
               (void *closure, struct __mtev_console_closure *ncct, const char *buffer),
               (closure, ncct, buffer));

#define OL(a) do { \
  pthread_mutex_lock(&(a)->simple->outbuf_lock); \
} while(0)
#define OUL(a) do { \
  pthread_mutex_unlock(&(a)->simple->outbuf_lock); \
} while(0)

static int
nc_write_with_lock(mtev_console_closure_t ncct, const void *buf, int len) {
  if(len <= 0) return 0;
  if(!ncct->simple->outbuf_allocd) {
    ncct->simple->outbuf = malloc(len);
    if(!ncct->simple->outbuf) return 0;
    ncct->simple->outbuf_allocd = len;
  }
  else if(ncct->simple->outbuf_allocd < ncct->simple->outbuf_len + len) {
    char *newbuf;
    newbuf = realloc(ncct->simple->outbuf, ncct->simple->outbuf_len + len);
    if(!newbuf) return 0;
    ncct->simple->outbuf = newbuf;
  }
  memcpy(ncct->simple->outbuf + ncct->simple->outbuf_len, buf, len);
  ncct->simple->outbuf_len += len;
  return len;
}

static void
nc_telnet_cooker(mtev_console_closure_t ncct) {
  char *tmpbuf, *p, *n;
  int r;

  OL(ncct);
  tmpbuf = ncct->simple->outbuf;
  if(ncct->simple->outbuf_len == 0) {
    OUL(ncct);
    return;
  }

  p = ncct->simple->outbuf + ncct->simple->outbuf_completed;
  r = ncct->simple->outbuf_len - ncct->simple->outbuf_completed;
  n = memchr(p, '\n', r);
  /* No '\n'? Nothin' to do */
  if(!n) {
    ncct->simple->outbuf_cooked = ncct->simple->outbuf_len;
    OUL(ncct);
    return;
  }

  /* Forget the outbuf -- it is now tmpbuf */
  ncct->simple->outbuf = NULL;
  ncct->simple->outbuf_allocd = 0;
  ncct->simple->outbuf_len = 0;
  ncct->simple->outbuf_completed = 0;
  ncct->simple->outbuf_cooked = 0;

  do {
    nc_write_with_lock(ncct, p, n-p);   r -= n-p;
    if(n == tmpbuf || *(n-1) != '\r')
      nc_write_with_lock(ncct, "\r", 1);
    p = n;
    n = memchr(p+1, '\n', r-1);
  } while(n);
  nc_write_with_lock(ncct, p, r);
  ncct->simple->outbuf_cooked = ncct->simple->outbuf_len;
  free(tmpbuf);
  OUL(ncct);
}

int
nc_printf(mtev_console_closure_t ncct, const char *fmt, ...) {
  int len;
  va_list arg;
  va_start(arg, fmt);
  len = nc_cmd_vprintf(ncct, 0, fmt, arg);
  va_end(arg);
  return len;
}

int
nc_cmd_printf(mtev_console_closure_t ncct, uint64_t cmdid, const char *fmt, ...) {
  int len;
  va_list arg;
  va_start(arg, fmt);
  len = nc_cmd_vprintf(ncct, cmdid, fmt, arg);
  va_end(arg);
  return len;
}

int
nc_vprintf(mtev_console_closure_t ncct, const char *fmt, va_list arg) {
  return nc_cmd_vprintf(ncct, 0, fmt, arg);
}

int
nc_cmd_vprintf(mtev_console_closure_t ncct, uint64_t cmdid, const char *fmt, va_list arg) {
  if(ncct->type == MTEV_CONSOLE_WEBSOCKET) {
    int rv = 0;
#ifdef HAVE_WSLAY
    mtev_dyn_buffer_t tbuf, buf;
    mtev_dyn_buffer_init(&buf);
    mtev_dyn_buffer_init(&tbuf);
    mtev_dyn_buffer_add_vprintf(&tbuf, fmt, arg);
    mtev_dyn_buffer_add_printf(&buf, "{\"cmdid\":\"%zu\",\"text\":\"", cmdid);
    mtev_dyn_buffer_add_json_string(&buf, 
                       (void *)mtev_dyn_buffer_data(&tbuf), mtev_dyn_buffer_used(&tbuf), 0);
    mtev_dyn_buffer_add(&buf, (uint8_t *)"\"}", 2);
    mtev_dyn_buffer_destroy(&tbuf);
    if(mtev_http_websocket_queue_msg(ncct->websocket->ctx, WSLAY_TEXT_FRAME,
                                     mtev_dyn_buffer_data(&buf), mtev_dyn_buffer_used(&buf))) {
      ncct->wants_shutdown = 1;
      rv = 1;
    }
    mtev_dyn_buffer_destroy(&buf);
#endif
    return rv;
  }
#ifdef va_copy
  va_list copy;
#endif
  int lenwanted;

  (void)cmdid;
  OL(ncct);  
  if(!ncct->simple->outbuf_allocd) {
    ncct->simple->outbuf = malloc(4096);
    if(!ncct->simple->outbuf) {
      OUL(ncct);
      return 0;
    }
    ncct->simple->outbuf_allocd = 4096;
  }
  while(1) {
    char *newbuf;
#ifdef va_copy
    va_copy(copy, arg);
    lenwanted = vsnprintf(ncct->simple->outbuf + ncct->simple->outbuf_len,
                          ncct->simple->outbuf_allocd - ncct->simple->outbuf_len,
                          fmt, copy);
    va_end(copy);
#else
    lenwanted = vsnprintf(ncct->simple->outbuf + ncct->simple->outbuf_len,
                          ncct->simple->outbuf_allocd - ncct->simple->outbuf_len,
                          fmt, arg);
#endif
    if(ncct->simple->outbuf_len + lenwanted < ncct->simple->outbuf_allocd) {
      /* All went well, things are as we want them. */
      ncct->simple->outbuf_len += lenwanted;
      OUL(ncct);
      return lenwanted;
    }

    /* We need to enlarge the buffer */
    lenwanted += ncct->simple->outbuf_len;
    lenwanted /= 4096;
    lenwanted += 1;
    lenwanted *= 4096;
    newbuf = realloc(ncct->simple->outbuf, lenwanted);
    if(!newbuf) {
      OUL(ncct);
      return 0;
    }
    ncct->simple->outbuf = newbuf;
    ncct->simple->outbuf_allocd = lenwanted;
  }
  /* NOTREACHED */
}

int
nc_write(mtev_console_closure_t ncct, const void *buf, int len) {
  int rv = 0;
  if(ncct->type == MTEV_CONSOLE_WEBSOCKET) {
    if(mtev_http_websocket_queue_msg(ncct->websocket->ctx, WSLAY_TEXT_FRAME,
                                     buf, len)) {
      ncct->wants_shutdown = 1;
      rv = 1;
    }
    return rv;
  }
  OL(ncct);
  rv = nc_write_with_lock(ncct, buf, len);
  OUL(ncct);
  return rv;
}

static void
mtev_console_userdata_free(void *data) {
  mtev_console_userdata_t *userdata = data;
  if(userdata) {
    if(userdata->name) free(userdata->name);
    if(userdata->freefunc)
      userdata->freefunc(userdata->data);
    free(userdata);
  }
}
void
mtev_console_closure_free(void *vncct) {
  mtev_console_closure_t ncct = (mtev_console_closure_t) vncct;
  mtev_log_stream_t lf;
  mtevL(mtev_debug, "ncct free(%p)\n", (void *)ncct);
  if(ncct->type == MTEV_CONSOLE_WEBSOCKET) {
    mtev_http_ctx_session_release(ncct->websocket->ctx);
    free(ncct->websocket);
  }
  if(ncct->type == MTEV_CONSOLE_SIMPLE) {
    if(ncct->simple->el) el_end(ncct->simple->el);
    if(ncct->simple->hist) {
      history_end(ncct->simple->hist);
      mtevL(mtev_debug, "ncct free->hist(%p)\n", (void *)ncct->simple->hist);
      free(ncct->simple->hist);
    }
    if(ncct->simple->pty_master >= 0) close(ncct->simple->pty_master);
    if(ncct->simple->pty_slave >= 0) close(ncct->simple->pty_slave);
    if(ncct->simple->outbuf) free(ncct->simple->outbuf);
    if(ncct->simple->telnet) mtev_console_telnet_free(ncct->simple->telnet);
    free(ncct->simple->hist_file);
    pthread_mutex_destroy(&ncct->simple->outbuf_lock);
    pthread_mutex_destroy(&ncct->simple->hist_file_lock);
    free(ncct->simple);
  }
  mtev_hash_destroy(&ncct->userdata, NULL, mtev_console_userdata_free);
  while(ncct->state_stack) {
    mtev_console_state_stack_t *tmp;
    tmp = ncct->state_stack;
    ncct->state_stack = tmp->last;
    if(tmp->name) free(tmp->name);
    free(tmp);
  }
  lf = mtev_log_stream_find(ncct->feed_path);
  mtev_log_stream_remove(ncct->feed_path);
  if(lf) {
    mtev_log_stream_free(lf);
  }
  free(ncct);
}

mtev_console_closure_t
mtev_console_closure_alloc(void) {
  mtev_console_closure_t new_ncct;
  new_ncct = calloc(1, sizeof(*new_ncct));
  mtev_hash_init(&new_ncct->userdata);
  mtev_console_state_push_state(new_ncct, mtev_console_state_initial());
  return new_ncct;
}
mtev_console_closure_t
mtev_console_simple_closure_alloc(void) {
  mtev_console_closure_t new_ncct = mtev_console_closure_alloc();
  new_ncct->type = MTEV_CONSOLE_SIMPLE;
  new_ncct->simple = calloc(1, sizeof(*new_ncct->simple));
  new_ncct->simple->pty_master = -1;
  new_ncct->simple->pty_slave = -1;
  pthread_mutex_init(&new_ncct->simple->outbuf_lock, NULL);
  pthread_mutex_init(&new_ncct->simple->hist_file_lock, NULL);
  return new_ncct;
}

mtev_console_closure_t
mtev_console_websocket_closure_alloc(void) {
  mtev_console_closure_t new_ncct = mtev_console_closure_alloc();
  new_ncct->type = MTEV_CONSOLE_WEBSOCKET;
  new_ncct->websocket = calloc(1, sizeof(*new_ncct->websocket));
  return new_ncct;
}

void
mtev_console_userdata_set(struct __mtev_console_closure *ncct,
                          const char *name, void *data,
                          state_userdata_free_func_t freefunc) {
  mtev_console_userdata_t *item;
  item = calloc(1, sizeof(*item));
  item->name = strdup(name);
  item->data = data;
  item->freefunc = freefunc;
  mtev_hash_replace(&ncct->userdata, item->name, strlen(item->name),
                    item, NULL, mtev_console_userdata_free);
}
  
void *
mtev_console_userdata_get(struct __mtev_console_closure *ncct,
                          const char *name) {
  void *vitem;
  if(mtev_hash_retrieve(&ncct->userdata, name, strlen(name),
                        &vitem))
    return ((mtev_console_userdata_t *)vitem)->data;
  return NULL;
}


int
mtev_console_continue_sending(mtev_console_closure_t ncct,
                              int *mask) {
  int len;
  if(ncct->type != MTEV_CONSOLE_SIMPLE) return 0;
  eventer_t e = ncct->simple->e;
  if(!ncct->simple->outbuf_len) return 0;
  if(ncct->simple->output_cooker) ncct->simple->output_cooker(ncct);
  OL(ncct);
  while(ncct->simple->outbuf_len > ncct->simple->outbuf_completed) {
    len = eventer_write(e, ncct->simple->outbuf + ncct->simple->outbuf_completed,
                        ncct->simple->outbuf_len - ncct->simple->outbuf_completed, mask);
    if(len < 0) {
      OUL(ncct);
      if(errno == EAGAIN) return -1;
      /* Do something else here? */
      return -1;
    }
    ncct->simple->outbuf_completed += len;
  }
  len = ncct->simple->outbuf_len;
  free(ncct->simple->outbuf);
  ncct->simple->outbuf = NULL;
  ncct->simple->outbuf_allocd = ncct->simple->outbuf_len =
    ncct->simple->outbuf_completed = ncct->simple->outbuf_cooked = 0;
  OUL(ncct);
  return len;
}

static void
mtev_console_dispatch(eventer_t e, char *buffer,
                      mtev_console_closure_t ncct) {
  (void)e;
  char **cmds;
  HistEvent ev;
  int i, cnt = 2048;
  mtev_boolean raw;

  if(mtev_console_dispatch_hook_invoke(ncct, buffer) != MTEV_HOOK_CONTINUE)
    return;

  cmds = malloc(2048 * sizeof(*cmds));
  i = mtev_tokenize(buffer, cmds, &cnt);

  /* < 0 is an error, that's fine.  We want it in the history to "fix" */
  /* > 0 means we had arguments, so let's put it in the history */
  /* 0 means nothing -- and that isn't worthy of history inclusion */
  if(i && strcmp(buffer, "exit")) {
    history(ncct->simple->hist, &ev, H_ENTER, buffer);
    if(ncct->simple->hist_file) {
      pthread_mutex_lock(&ncct->simple->hist_file_lock);
      history(ncct->simple->hist, &ev, H_SAVE, ncct->simple->hist_file);
      pthread_mutex_unlock(&ncct->simple->hist_file_lock);
    }
  }

  raw = (mtev_console_userdata_get(ncct, MTEV_CONSOLE_RAW_MODE) ==
         MTEV_CONSOLE_RAW_MODE_ON);

  if(raw) mtev_console_state_do(ncct, 1, &buffer);
  else if(i>cnt) nc_printf(ncct, "Command length too long.\n");
  else if(i<0) nc_printf(ncct, "Error at offset: %d\n", 0-i);
  else mtev_console_state_do(ncct, cnt, cmds);
  while(cnt>0) free(cmds[--cnt]);
  free(cmds);
}

void
mtev_console_motd(eventer_t e, mtev_acceptor_closure_t *ac,
                  mtev_console_closure_t ncct) {
  int ssl = eventer_get_eventer_ssl_ctx(e) ? 1 : 0;
  const char *remote_cn = mtev_acceptor_closure_remote_cn(ac);
  nc_printf(ncct, "mtev%s: %s\n",
            ssl ? "(secure)" : "",
            remote_cn ? remote_cn : "(no auth)");
}

int
allocate_pty(int *master, int *slave) {
#if defined(HAVE_OPENPTY) || (defined(HAVE_DECL_OPENPTY) && HAVE_DECL_OPENPTY != 0)
  if(openpty(master, slave, NULL, NULL, NULL)) return -1;
#else
  /* STREAMS... sigh */
  char   *slavename;

  *master = open("/dev/ptmx", O_RDWR);  /* open master */
  if(*master < 0) return -1;
  grantpt(*master);                     /* change permission of   slave */
  unlockpt(*master);                    /* unlock slave */
  slavename = ptsname(*master);         /* get name of slave */
  *slave = open(slavename, O_RDWR);    /* open slave */
  if(*slave < 0) {
    close(*master);
    *master = -1;
    return -1;
  }
  /* This is a bit backwards as we using the PTY backwards.
   * We want to make the master a tty instead of the slave... odd, I know.
   */
  ioctl(*master, I_PUSH, "ptem");       /* push ptem */
  ioctl(*master, I_PUSH, "ldterm");     /* push ldterm*/
#endif
  if(eventer_set_fd_nonblocking(*master)) return -1;
  mtevL(mtev_debug, "allocate_pty -> %d,%d\n", *master, *slave);
  return 0;
}

static int
mtev_console_initialize(mtev_console_closure_t ncct,
                        const char *line_protocol,
                        const char *hist_file,
                        eventer_t in, eventer_t out) {
  ncct->simple->e = out;
  if(allocate_pty(&ncct->simple->pty_master, &ncct->simple->pty_slave)) {
    nc_printf(ncct, "Failed to open pty: %s\n", strerror(errno));
    ncct->wants_shutdown = 1;
    return 1;
  }
  else {
    int i;
    HistEvent ev;

    ncct->simple->hist = history_init();
    ncct->simple->hist_file = hist_file ? strdup(hist_file) : NULL;
    history(ncct->simple->hist, &ev, H_SETSIZE, 500);
    if(ncct->simple->hist_file) {
      pthread_mutex_lock(&ncct->simple->hist_file_lock);
      history(ncct->simple->hist, &ev, H_LOAD, ncct->simple->hist_file);
      pthread_mutex_unlock(&ncct->simple->hist_file_lock);
    }
    ncct->simple->el = el_init("mtev", ncct->simple->pty_master, NULL,
                       eventer_get_fd(in), in, eventer_get_fd(out), out);
    if(!ncct->simple->el) return -1;
    if(el_set(ncct->simple->el, EL_USERDATA, ncct)) {
      mtevL(mtev_error, "Cannot set userdata on noitedit session\n");
      return -1;
    }
    if(el_set(ncct->simple->el, EL_EDITOR, "emacs")) 
      mtevL(mtev_error, "Cannot set emacs mode on console\n");
    if(el_set(ncct->simple->el, EL_HIST, history, ncct->simple->hist))
      mtevL(mtev_error, "Cannot set history on console\n");
    el_set(ncct->simple->el, EL_ADDFN, "mtev_complete",
           "auto completion functions for mtev", mtev_edit_complete);
    el_set(ncct->simple->el, EL_BIND, "^I", "mtev_complete", NULL);
    for(i=EL_NUM_FCNS; i < ncct->simple->el->el_map.nfunc; i++) {
      if(ncct->simple->el->el_map.func[i] == mtev_edit_complete) {
        ncct->simple->mtev_edit_complete_cmdnum = i;
        break;
      }
    }

    if(line_protocol && !strcasecmp(line_protocol, "telnet")) {
      ncct->simple->telnet = mtev_console_telnet_alloc(ncct);
      ncct->simple->output_cooker = nc_telnet_cooker;
    }
    mtev_console_state_init(ncct);
  }
  if(eventer_get_fd(in) != eventer_get_fd(out))
    snprintf(ncct->feed_path, sizeof(ncct->feed_path),
             "console/[%d:%d]", eventer_get_fd(in), eventer_get_fd(out));
  else
    snprintf(ncct->feed_path, sizeof(ncct->feed_path), "console/%d", eventer_get_fd(in));
  mtev_log_stream_new(ncct->feed_path, "mtev_console", ncct->feed_path,
                      ncct, NULL);
  ncct->initialized = 1;
  return 0;
}
static int
mtev_console_std(eventer_t e, int mask, void *closure,
                 struct timeval *now) {
  (void)now;
  int newmask;
  int keep_going;
  mtev_console_closure_t ncct = closure;
  if(mask & EVENTER_EXCEPTION || (ncct->wants_shutdown)) {
socket_error:
    /* Exceptions cause us to simply snip the connection */

    /* This removes the log feed which is important to do before calling close */
    eventer_remove_fde(e);
    eventer_close(e, &newmask);
    return 0;
  }

  int rv = mtev_console_continue_sending(ncct, &newmask);
  if(rv < 0) {
    if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
    return newmask | EVENTER_EXCEPTION;
  }

  for(keep_going=1 ; keep_going ; ) {
    int len, plen;
    char sbuf[4096];
    const char *buffer;

    keep_going = 0;

    buffer = el_gets(ncct->simple->el, &plen);
    if(!el_eagain(ncct->simple->el)) {
      if(!buffer) {
        buffer = "exit";
        plen = 4;
        nc_write(ncct, "\n", 1);
      }
      keep_going++;
    }

    len = eventer_read(e, sbuf, sizeof(sbuf)-1, &newmask);
    if(len == 0 || (len < 0 && errno != EAGAIN)) {
      eventer_remove_fde(e);
      eventer_close(e, &newmask);
      return 0;
    }
    if(len > 0) {
      keep_going++;
      sbuf[len] = '\0';
      if(ncct->simple->telnet) {
        mtev_console_telnet_telrcv(ncct, sbuf, len);
        ptyflush(ncct);
      }
      else {
        int written;
        written = write(ncct->simple->pty_slave, sbuf, len);
        if(written <= 0) goto socket_error;
        mtevAssert(written == len);
      }
    }
    if(buffer) {
      char *cmd_buffer;
      cmd_buffer = malloc(plen+1);
      memcpy(cmd_buffer, buffer, plen);
      /* chomp */
      cmd_buffer[plen] = '\0';
      if(cmd_buffer[plen-1] == '\n') cmd_buffer[plen-1] = '\0';
      mtevL(mtev_debug, "IN[%d]: '%s'\n", plen, cmd_buffer);
      mtev_console_dispatch(e, cmd_buffer, ncct);
      free(cmd_buffer);
    }
    rv = mtev_console_continue_sending(ncct, &newmask);
    if(rv == -1) {
      if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
      return newmask | EVENTER_EXCEPTION;
    }
    if(ncct->wants_shutdown) goto socket_error;
  }
  return newmask | EVENTER_EXCEPTION;
}
int mtev_console_std_init(int infd, int outfd) {
  mtev_console_closure_t ncct;
  eventer_t in, out;

  ncct = mtev_console_simple_closure_alloc();
  in = eventer_alloc_fd(mtev_console_std, ncct, infd, EVENTER_READ|EVENTER_EXCEPTION);
  out = eventer_alloc_fd(mtev_console_std, ncct, outfd, EVENTER_WRITE|EVENTER_EXCEPTION);
  if(mtev_console_initialize(ncct, NULL, NULL, in, out)) {
    return -1;
  }
  eventer_add(in);
  eventer_add(out);
  return 0;
}
int
mtev_console_handler(eventer_t e, int mask, void *closure,
                     struct timeval *now) {
  (void)now;
  int newmask = EVENTER_READ | EVENTER_EXCEPTION;
  int keep_going;
  mtev_acceptor_closure_t *ac = closure;
  mtev_console_closure_t ncct = mtev_acceptor_closure_ctx(ac);

  if(mask & EVENTER_EXCEPTION || (ncct && ncct->wants_shutdown)) {
socket_error:
    /* Exceptions cause us to simply snip the connection */

    /* This removes the log feed which is important to do before calling close */
    eventer_remove_fde(e);
    mtev_acceptor_closure_free(ac);
    eventer_close(e, &newmask);
    return 0;
  }

  if(!ncct) {
    ncct = mtev_console_simple_closure_alloc();
    mtevL(mtev_debug, "ncct alloc() -> %p\n", (void *)ncct);
    mtev_acceptor_closure_set_ctx(ac, ncct, mtev_console_closure_free);
  }
  if(!ncct->initialized) {
    const char *line_protocol = NULL;
    const char *hist_file = NULL;
    (void)mtev_hash_retr_str(mtev_acceptor_closure_config(ac),
                             "line_protocol", strlen("line_protocol"),
                             &line_protocol);
    (void)mtev_hash_retr_str(mtev_acceptor_closure_config(ac),
                             "history_file", strlen("history_file"),
                             &hist_file);
    if(mtev_console_initialize(ncct, line_protocol, hist_file, e, e)) goto socket_error;
    mtev_console_motd(e, ac, ncct);
  }

  /* If we still have data to send back to the client, this will take
   * care of that
   */
  int rv = mtev_console_continue_sending(ncct, &newmask);
  if(rv < 0) {
    if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
    mtev_acceptor_closure_mark_write(ac, now);
    return newmask | EVENTER_EXCEPTION;
  } else if(rv > 0) {
    mtev_acceptor_closure_mark_write(ac, now);
  }

  el_multi_set_el(ncct->simple->el);
  for(keep_going=1 ; keep_going ; ) {
    int len, plen;
    char sbuf[4096];
    const char *buffer;

    keep_going = 0;

    buffer = el_gets(ncct->simple->el, &plen);
    if(!el_eagain(ncct->simple->el)) {
      if(!buffer) {
        buffer = "exit";
        plen = 4;
        nc_write(ncct, "\n", 1);
      }
      keep_going++;
    }

    len = eventer_read(e, sbuf, sizeof(sbuf)-1, &newmask);
    if(len == 0 || (len < 0 && errno != EAGAIN)) {
      eventer_remove_fde(e);
      mtev_acceptor_closure_free(ac);
      eventer_close(e, &newmask);
      return 0;
    }
    if(len > 0) {
      mtev_acceptor_closure_mark_read(ac, now);
      keep_going++;
      sbuf[len] = '\0';
      if(ncct->simple->telnet) {
        mtev_console_telnet_telrcv(ncct, sbuf, len);
        ptyflush(ncct);
      }
      else {
        int written;
        written = write(ncct->simple->pty_slave, sbuf, len);
        if(written <= 0) goto socket_error;
        mtevAssert(written == len);
      }
    }
    if(buffer) {
      char *cmd_buffer;
      cmd_buffer = malloc(plen+1);
      memcpy(cmd_buffer, buffer, plen);
      /* chomp */
      cmd_buffer[plen] = '\0';
      if(cmd_buffer[plen-1] == '\n') cmd_buffer[plen-1] = '\0';
      mtevL(mtev_debug, "IN[%d]: '%s'\n", plen, cmd_buffer);
      mtev_console_dispatch(e, cmd_buffer, ncct);
      free(cmd_buffer);
    }
    rv = mtev_console_continue_sending(ncct, &newmask);
    if(rv == -1) {
      if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
      mtev_acceptor_closure_mark_write(ac, now);
      return newmask | EVENTER_EXCEPTION;
    } else if(rv > 0) {
      mtev_acceptor_closure_mark_write(ac, now);
    }
    if(ncct->wants_shutdown) goto socket_error;
  }
  return newmask | EVENTER_EXCEPTION;
}

static int
mtev_console_logio_open(mtev_log_stream_t ls) {
  (void)ls;
  return 0;
}
static int
mtev_console_logio_reopen(mtev_log_stream_t ls) {
  /* no op */
  (void)ls;
  return 0;
}

static int
mtev_console_continue_sending_when_convenient(eventer_t e, int mask, void *cl, struct timeval *now) {
  mtev_console_closure_t ncct = cl;
  (void)e;
  (void)now;
  int rv;
  while((rv = mtev_console_continue_sending(ncct, &mask)) == -1 && errno == EINTR);
  if(rv == -1 && errno == EAGAIN) {
    eventer_update(ncct->simple->e, mask | EVENTER_EXCEPTION);
  }
  return 0;
}

static int
mtev_console_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                         const void *buf, size_t len) {
  mtev_console_closure_t ncct = mtev_log_stream_get_ctx(ls);
  int rv, rlen = len, mask;
  (void)whence;
  if(!ncct) return 0;
  if(ncct->type == MTEV_CONSOLE_WEBSOCKET) {
    mtev_dyn_buffer_t ob;
    mtev_dyn_buffer_init(&ob);
    mtev_dyn_buffer_add_printf(&ob, "{\"id\":0,\"log\":");
    /* we know this to be json, so we can clip a trailing \n */
    mtev_dyn_buffer_add(&ob, (uint8_t *)buf, (len > 0 && ((char *)buf)[len-1] == '\n') ? len - 1 : len);
    mtev_dyn_buffer_add(&ob, (uint8_t *)"}", 1);
    if(!mtev_http_websocket_queue_msg(ncct->websocket->ctx, WSLAY_TEXT_FRAME,
                                      mtev_dyn_buffer_data(&ob), mtev_dyn_buffer_used(&ob))) {
      ncct->wants_shutdown = 1;
      rlen = 0;
    }
    mtev_dyn_buffer_destroy(&ob);
  }
  if(ncct->type == MTEV_CONSOLE_SIMPLE) {
    rlen = nc_write(ncct, buf, len);
    if(eventer_is_aco(NULL)) {
      eventer_add_in_s_us(mtev_console_continue_sending_when_convenient, ncct, 0, 0);
    } else {
      while((rv = mtev_console_continue_sending(ncct, &mask)) == -1 && errno == EINTR);
      if(rv == -1 && errno == EAGAIN) {
        eventer_update(ncct->simple->e, mask | EVENTER_EXCEPTION);
      }
    }
  }
  return rlen;
}
static int
mtev_console_logio_close(mtev_log_stream_t ls) {
  mtev_console_closure_t ncct = mtev_log_stream_get_ctx(ls);
  if(!ncct) return 0;
  if(ncct->type == MTEV_CONSOLE_SIMPLE) ncct->simple->e = NULL;
  mtev_log_stream_set_ctx(ls, NULL);
  return 0;
}
static logops_t mtev_console_logio_ops = {
  mtev_false,
  mtev_console_logio_open,
  mtev_console_logio_reopen,
  mtev_console_logio_write,
  NULL,
  mtev_console_logio_close,
  NULL,
  NULL,
  NULL
};

int
mtev_console_write_xml(void *vncct, const char *buffer, int len) {
  mtev_console_closure_t ncct = vncct;
  return nc_write(ncct, buffer, len);
}

int
mtev_console_close_xml(void *vncct) {
  (void)vncct;
  return 0;
}

static int
mtev_console_websocket_handler(mtev_http_rest_closure_t *restc, int opcode,
                               const unsigned char *msg, size_t msg_len) {
  int rv = 0;
  uint64_t cmdid = 0;
  const char *error = "unexpected error";
  (void)opcode;
  mtev_console_closure_t ncct = restc->call_closure;
  mtevAssert(mtev_http_is_websocket(restc->http_ctx));
  if(!ncct) {
    ncct = restc->call_closure = mtev_console_websocket_closure_alloc();
    ncct->websocket->ctx = restc->http_ctx;
    mtev_http_session_ref_inc(ncct->websocket->ctx);
    restc->call_closure_free = mtev_console_closure_free;
    mtev_http_connection *conn = mtev_http_session_connection(restc->http_ctx);
    if(conn) {
      eventer_t e = mtev_http_connection_event(conn);
      if(e) {
        mtev_log_stream_t ls;
        snprintf(ncct->feed_path, sizeof(ncct->feed_path),
                 "console/ws/[%d]", eventer_get_fd(e));
        ls = mtev_log_stream_new(ncct->feed_path, "mtev_console", ncct->feed_path,
                                 ncct, NULL);
        mtev_log_stream_set_format(ls, MTEV_LOG_FORMAT_JSON);
      }
    }
  }

#undef ERROR
#define ERROR(e) do { error = (e); goto error; } while(0)
  struct mtev_json_tokener *tok = mtev_json_tokener_new();
  struct mtev_json_object *request = mtev_json_tokener_parse_ex(tok, (const char *)msg, msg_len);
  enum mtev_json_tokener_error err = tok->err;
  mtev_json_tokener_free(tok);
  if(err != mtev_json_tokener_success || !request) {
    ERROR("could not parse json");
    return 0;
  }
  if(!mtev_json_object_is_type(request, mtev_json_type_object)) {
    ERROR("expected json object");
    return 0;
  }

  struct mtev_json_object *jid = mtev_json_object_object_get(request, "id");
  if(jid) {
    switch(mtev_json_object_get_type(jid)) {
      case mtev_json_type_int:
        switch(mtev_json_object_get_int_overflow(jid)) {
          case mtev_json_overflow_int:
            cmdid = mtev_json_object_get_int(jid);
            break;
          case mtev_json_overflow_int64:
            if(mtev_json_object_get_int64(jid) >= 0) {
              cmdid = (uint64_t)mtev_json_object_get_int64(jid);
            }
            break;
          case mtev_json_overflow_uint64:
            cmdid = mtev_json_object_get_uint64(jid);
            break;
        }
        break;
      case mtev_json_type_string:
        cmdid = strtoull(mtev_json_object_get_string(jid), NULL, 10);
        break;
      default:
        break;
    }
  }
  struct mtev_json_object *jcomplete = mtev_json_object_object_get(request, "complete");
  mtev_boolean complete = jcomplete ? mtev_json_object_get_boolean(jcomplete) : mtev_false;
  struct mtev_json_object *jcmd = mtev_json_object_object_get(request, "command");
  if(jcmd && mtev_json_object_get_type(jcmd) == mtev_json_type_array) {
    char *args[256];
    uint32_t nargs = mtev_json_object_array_length(jcmd);
    nargs = MIN(nargs, sizeof(args)/sizeof(*args));
    for(uint32_t i=0; i<nargs; i++) {
      args[i] = (char *)mtev_json_object_get_string(mtev_json_object_array_get_idx(jcmd, i));
      if(args[i] == NULL) ERROR("command not array of strings");
    }
    if(complete) {
      char *opt = NULL;
      int cidx = 0;
      mtev_dyn_buffer_t ob;
      mtev_dyn_buffer_init(&ob);
      mtev_dyn_buffer_add_printf(&ob, "{\"id\":\"%zu\",\"completion\":[", cmdid);
      while(NULL != (opt = mtev_console_completion(ncct, nargs, (const char **)args, cidx))) {
        if(cidx) {
          mtev_dyn_buffer_add(&ob, (uint8_t *)",\"", 2);
        } else {
          mtev_dyn_buffer_add(&ob, (uint8_t *)"\"", 1);
        }
        mtev_dyn_buffer_add_json_string(&ob, (uint8_t *)opt, strlen(opt), 0);
        mtev_dyn_buffer_add(&ob, (uint8_t *)"\"", 1);
        free(opt);
        cidx++;
      }
      mtev_dyn_buffer_add(&ob, (uint8_t *)"]}", 1);
      if(!mtev_http_websocket_queue_msg(ncct->websocket->ctx, WSLAY_TEXT_FRAME,
                                        mtev_dyn_buffer_data(&ob), mtev_dyn_buffer_used(&ob))) {
        ncct->wants_shutdown = 1;
        rv = -1;
      }
      mtev_dyn_buffer_destroy(&ob);
    } else {
      mtev_console_state_do(ncct, nargs, args);
    }
  }
  mtevL(debugls, "WS < (%.*s)\n", (int)msg_len, msg);
  mtev_json_object_put(request);
  return rv;

error:
  if(request) mtev_json_object_put(request);
  mtev_dyn_buffer_t ob;
  mtev_dyn_buffer_init(&ob);
  mtev_dyn_buffer_add_printf(&ob, "{\"id\":\"%zu\",\"error\":\"", cmdid);
  mtev_dyn_buffer_add_json_string(&ob, (uint8_t *)error, strlen(error), 0);
  mtev_dyn_buffer_add(&ob, (uint8_t *)"\"}", 2);
  if(!mtev_http_websocket_queue_msg(ncct->websocket->ctx, WSLAY_TEXT_FRAME,
                                    mtev_dyn_buffer_data(&ob), mtev_dyn_buffer_used(&ob))) {
    ncct->wants_shutdown = 1;
    rv = -1;
  }
  mtev_dyn_buffer_destroy(&ob);
  return rv;
}

void
mtev_console_telnet_init(void) {
  el_multi_init();
  signal(SIGTTOU, SIG_IGN);
  mtev_register_logops("mtev_console", &mtev_console_logio_ops);
  eventer_name_callback("mtev_console_send", mtev_console_continue_sending_when_convenient);
  eventer_name_callback("mtev_console", mtev_console_handler);
}

void
mtev_console_rest_init(void) {
  mtev_rest_mountpoint_t *rule;
  rule = mtev_http_rest_new_rule("WS", "/mtev/", "^console$", NULL);
  mtev_rest_mountpoint_set_auth(rule, mtev_http_rest_client_cert_auth);
  mtev_rest_mountpoint_set_websocket(rule, "mtev_console", mtev_console_websocket_handler);
}

void
mtev_console_init(const char *progname) {
  errorls = mtev_log_stream_find("error/console");
  debugls = mtev_log_stream_find("debug/console");
  if(progname) {
    char buff[32];
    snprintf(buff, sizeof(buff), "%s# ", progname);
    mtev_console_set_default_prompt(buff);
  }
  mtev_console_telnet_init();
  mtev_console_rest_init();
}
