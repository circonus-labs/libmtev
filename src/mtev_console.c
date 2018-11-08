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

#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_listener.h"
#include "mtev_console.h"
#include "mtev_tokenizer.h"

#include "noitedit/sys.h"
#include "noitedit/el.h"
#include "noitedit/fcns.h"
#include "noitedit/map.h"

#define OL(a) do { \
  pthread_mutex_lock(&(a)->outbuf_lock); \
} while(0)
#define OUL(a) do { \
  pthread_mutex_unlock(&(a)->outbuf_lock); \
} while(0)

static int
nc_write_with_lock(mtev_console_closure_t ncct, const void *buf, int len) {
  if(len <= 0) return 0;
  if(!ncct->outbuf_allocd) {
    ncct->outbuf = malloc(len);
    if(!ncct->outbuf) return 0;
    ncct->outbuf_allocd = len;
  }
  else if(ncct->outbuf_allocd < ncct->outbuf_len + len) {
    char *newbuf;
    newbuf = realloc(ncct->outbuf, ncct->outbuf_len + len);
    if(!newbuf) return 0;
    ncct->outbuf = newbuf;
  }
  memcpy(ncct->outbuf + ncct->outbuf_len, buf, len);
  ncct->outbuf_len += len;
  return len;
}

static void
nc_telnet_cooker(mtev_console_closure_t ncct) {
  char *tmpbuf, *p, *n;
  int r;

  OL(ncct);
  tmpbuf = ncct->outbuf;
  if(ncct->outbuf_len == 0) {
    OUL(ncct);
    return;
  }

  p = ncct->outbuf + ncct->outbuf_completed;
  r = ncct->outbuf_len - ncct->outbuf_completed;
  n = memchr(p, '\n', r);
  /* No '\n'? Nothin' to do */
  if(!n) {
    ncct->outbuf_cooked = ncct->outbuf_len;
    OUL(ncct);
    return;
  }

  /* Forget the outbuf -- it is now tmpbuf */
  ncct->outbuf = NULL;
  ncct->outbuf_allocd = 0;
  ncct->outbuf_len = 0;
  ncct->outbuf_completed = 0;
  ncct->outbuf_cooked = 0;

  do {
    nc_write_with_lock(ncct, p, n-p);   r -= n-p;
    if(n == tmpbuf || *(n-1) != '\r')
      nc_write_with_lock(ncct, "\r", 1);
    p = n;
    n = memchr(p+1, '\n', r-1);
  } while(n);
  nc_write_with_lock(ncct, p, r);
  ncct->outbuf_cooked = ncct->outbuf_len;
  free(tmpbuf);
  OUL(ncct);
}
int
nc_printf(mtev_console_closure_t ncct, const char *fmt, ...) {
  int len;
  va_list arg;
  va_start(arg, fmt);
  len = nc_vprintf(ncct, fmt, arg);
  va_end(arg);
  return len;
}

int
nc_vprintf(mtev_console_closure_t ncct, const char *fmt, va_list arg) {
#ifdef va_copy
  va_list copy;
#endif
  int lenwanted;

  OL(ncct);  
  if(!ncct->outbuf_allocd) {
    ncct->outbuf = malloc(4096);
    if(!ncct->outbuf) {
      OUL(ncct);
      return 0;
    }
    ncct->outbuf_allocd = 4096;
  }
  while(1) {
    char *newbuf;
#ifdef va_copy
    va_copy(copy, arg);
    lenwanted = vsnprintf(ncct->outbuf + ncct->outbuf_len,
                          ncct->outbuf_allocd - ncct->outbuf_len,
                          fmt, copy);
    va_end(copy);
#else
    lenwanted = vsnprintf(ncct->outbuf + ncct->outbuf_len,
                          ncct->outbuf_allocd - ncct->outbuf_len,
                          fmt, arg);
#endif
    if(ncct->outbuf_len + lenwanted < ncct->outbuf_allocd) {
      /* All went well, things are as we want them. */
      ncct->outbuf_len += lenwanted;
      OUL(ncct);
      return lenwanted;
    }

    /* We need to enlarge the buffer */
    lenwanted += ncct->outbuf_len;
    lenwanted /= 4096;
    lenwanted += 1;
    lenwanted *= 4096;
    newbuf = realloc(ncct->outbuf, lenwanted);
    if(!newbuf) {
      OUL(ncct);
      return 0;
    }
    ncct->outbuf = newbuf;
    ncct->outbuf_allocd = lenwanted;
  }
  /* NOTREACHED */
}

int
nc_write(mtev_console_closure_t ncct, const void *buf, int len) {
  int rv;
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
  if(ncct->el) el_end(ncct->el);
  if(ncct->hist) {
    history_end(ncct->hist);
    mtevL(mtev_debug, "ncct free->hist(%p)\n", (void *)ncct->hist);
    free(ncct->hist);
  }
  if(ncct->pty_master >= 0) close(ncct->pty_master);
  if(ncct->pty_slave >= 0) close(ncct->pty_slave);
  if(ncct->outbuf) free(ncct->outbuf);
  if(ncct->telnet) mtev_console_telnet_free(ncct->telnet);
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
  pthread_mutex_destroy(&ncct->outbuf_lock);
  free(ncct);
}

mtev_console_closure_t
mtev_console_closure_alloc(void) {
  mtev_console_closure_t new_ncct;
  new_ncct = calloc(1, sizeof(*new_ncct));
  mtev_hash_init(&new_ncct->userdata);
  mtev_console_state_push_state(new_ncct, mtev_console_state_initial());
  new_ncct->pty_master = -1;
  new_ncct->pty_slave = -1;
  pthread_mutex_init(&new_ncct->outbuf_lock, NULL);
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
  eventer_t e = ncct->e;
  if(!ncct->outbuf_len) return 0;
  if(ncct->output_cooker) ncct->output_cooker(ncct);
  OL(ncct);
  while(ncct->outbuf_len > ncct->outbuf_completed) {
    len = eventer_write(e, ncct->outbuf + ncct->outbuf_completed,
                        ncct->outbuf_len - ncct->outbuf_completed, mask);
    if(len < 0) {
      OUL(ncct);
      if(errno == EAGAIN) return -1;
      /* Do something else here? */
      return -1;
    }
    ncct->outbuf_completed += len;
  }
  len = ncct->outbuf_len;
  free(ncct->outbuf);
  ncct->outbuf = NULL;
  ncct->outbuf_allocd = ncct->outbuf_len =
    ncct->outbuf_completed = ncct->outbuf_cooked = 0;
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

  cmds = malloc(2048 * sizeof(*cmds));
  i = mtev_tokenize(buffer, cmds, &cnt);

  /* < 0 is an error, that's fine.  We want it in the history to "fix" */
  /* > 0 means we had arguments, so let's put it in the history */
  /* 0 means nothing -- and that isn't worthy of history inclusion */
  if(i) history(ncct->hist, &ev, H_ENTER, buffer);

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
                        eventer_t in, eventer_t out) {
  ncct->e = out;
  if(allocate_pty(&ncct->pty_master, &ncct->pty_slave)) {
    nc_printf(ncct, "Failed to open pty: %s\n", strerror(errno));
    ncct->wants_shutdown = 1;
    return 1;
  }
  else {
    int i;
    HistEvent ev;

    ncct->hist = history_init();
    history(ncct->hist, &ev, H_SETSIZE, 500);
    ncct->el = el_init("mtev", ncct->pty_master, NULL,
                       eventer_get_fd(in), in, eventer_get_fd(out), out);
    if(!ncct->el) return -1;
    if(el_set(ncct->el, EL_USERDATA, ncct)) {
      mtevL(mtev_error, "Cannot set userdata on noitedit session\n");
      return -1;
    }
    if(el_set(ncct->el, EL_EDITOR, "emacs")) 
      mtevL(mtev_error, "Cannot set emacs mode on console\n");
    if(el_set(ncct->el, EL_HIST, history, ncct->hist))
      mtevL(mtev_error, "Cannot set history on console\n");
    el_set(ncct->el, EL_ADDFN, "mtev_complete",
           "auto completion functions for mtev", mtev_edit_complete);
    el_set(ncct->el, EL_BIND, "^I", "mtev_complete", NULL);
    for(i=EL_NUM_FCNS; i < ncct->el->el_map.nfunc; i++) {
      if(ncct->el->el_map.func[i] == mtev_edit_complete) {
        ncct->mtev_edit_complete_cmdnum = i;
        break;
      }
    }

    if(line_protocol && !strcasecmp(line_protocol, "telnet")) {
      ncct->telnet = mtev_console_telnet_alloc(ncct);
      ncct->output_cooker = nc_telnet_cooker;
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

  if(mtev_console_continue_sending(ncct, &newmask) < 0) {
    if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
    return newmask | EVENTER_EXCEPTION;
  }

  for(keep_going=1 ; keep_going ; ) {
    int len, plen;
    char sbuf[4096];
    const char *buffer;

    keep_going = 0;

    buffer = el_gets(ncct->el, &plen);
    if(!el_eagain(ncct->el)) {
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
      if(ncct->telnet) {
        mtev_console_telnet_telrcv(ncct, sbuf, len);
        ptyflush(ncct);
      }
      else {
        int written;
        written = write(ncct->pty_slave, sbuf, len);
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
    if(mtev_console_continue_sending(ncct, &newmask) == -1) {
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

  ncct = mtev_console_closure_alloc();
  in = eventer_alloc_fd(mtev_console_std, ncct, infd, EVENTER_READ|EVENTER_EXCEPTION);
  out = eventer_alloc_fd(mtev_console_std, ncct, outfd, EVENTER_WRITE|EVENTER_EXCEPTION);
  if(mtev_console_initialize(ncct, NULL, in, out)) {
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
    ncct = mtev_console_closure_alloc();
    mtevL(mtev_debug, "ncct alloc() -> %p\n", (void *)ncct);
    mtev_acceptor_closure_set_ctx(ac, ncct, mtev_console_closure_free);
  }
  if(!ncct->initialized) {
    const char *line_protocol = NULL;
    (void)mtev_hash_retr_str(mtev_acceptor_closure_config(ac),
                             "line_protocol", strlen("line_protocol"),
                             &line_protocol);
    if(mtev_console_initialize(ncct, line_protocol, e, e)) goto socket_error;
    mtev_console_motd(e, ac, ncct);
  }

  /* If we still have data to send back to the client, this will take
   * care of that
   */
  if(mtev_console_continue_sending(ncct, &newmask) < 0) {
    if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
    return newmask | EVENTER_EXCEPTION;
  }

  el_multi_set_el(ncct->el);
  for(keep_going=1 ; keep_going ; ) {
    int len, plen;
    char sbuf[4096];
    const char *buffer;

    keep_going = 0;

    buffer = el_gets(ncct->el, &plen);
    if(!el_eagain(ncct->el)) {
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
      keep_going++;
      sbuf[len] = '\0';
      if(ncct->telnet) {
        mtev_console_telnet_telrcv(ncct, sbuf, len);
        ptyflush(ncct);
      }
      else {
        int written;
        written = write(ncct->pty_slave, sbuf, len);
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
    if(mtev_console_continue_sending(ncct, &newmask) == -1) {
      if(ncct->wants_shutdown || errno != EAGAIN) goto socket_error;
      return newmask | EVENTER_EXCEPTION;
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
mtev_console_logio_write(mtev_log_stream_t ls, const struct timeval *whence,
                         const void *buf, size_t len) {
  mtev_console_closure_t ncct;
  ncct = mtev_log_stream_get_ctx(ls);
  int rv, rlen, mask;
  (void)whence;
  if(!ncct) return 0;
  rlen = nc_write(ncct, buf, len);
  while((rv = mtev_console_continue_sending(ncct, &mask)) == -1 && errno == EINTR);
  if(rv == -1 && errno == EAGAIN) {
    eventer_update(ncct->e, mask | EVENTER_EXCEPTION);
  }
  return rlen;
}
static int
mtev_console_logio_close(mtev_log_stream_t ls) {
  mtev_console_closure_t ncct;
  ncct = mtev_log_stream_get_ctx(ls);
  if(!ncct) return 0;
  ncct->e = NULL;
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

void
mtev_console_init(const char *progname) {
  if(progname) {
    char buff[32];
    snprintf(buff, sizeof(buff), "%s# ", progname);
    mtev_console_set_default_prompt(buff);
  }
  el_multi_init();
  signal(SIGTTOU, SIG_IGN);
  mtev_register_logops("mtev_console", &mtev_console_logio_ops);
  eventer_name_callback("mtev_console", mtev_console_handler);
}

