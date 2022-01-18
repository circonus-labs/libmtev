/*
 * Copyright (c) 2022, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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
#include "mtev_conf.h"
#include "mtev_version.h"
#include "mtev_b64.h"
#include "mtev_confstr.h"
#include "mtev_dso.h"
#include "mtev_dyn_buffer.h"
#include "mtev_hash.h"
#include "mtev_maybe_alloc.h"
#include "mtev_rest.h"
#include "mtev_http.h"
#include "mtev_getip.h"
#include "mtev_capabilities_listener.h"
#include "mtev_zipkin_curl.h"

#include "mtev_curl.h"

static mtev_log_stream_t debug_ls, error_ls;
static __thread CURLM *_global_curl_handle;
static CURLM *first_assigned;
static __thread eventer_t _global_curl_timeout;
static CURLM *global_curl_handle_get(void);

static void process_global_curlm(void);

struct mtev_curl_handle_t {
  mtev_dyn_buffer_t dyn;
  void *userdata;
  mtev_curl_cb_func_t handler;
  Zipkin_Span *span;
  CURL *curl;
  CURLcode code;
  long httpcode;
  int ref; // no need for thread safety here
};

static void mtev_curl_handle_free(struct mtev_curl_handle_t *handle) {
  if(--handle->ref == 0) {
    mtev_dyn_buffer_destroy(&handle->dyn);
    free(handle);
  }
};
void mtev_curl_handle_free_aco(struct mtev_curl_handle_t *handle) {
  mtev_curl_handle_free(handle);
}

const void *mtev_curl_handle_get_buffer(mtev_curl_handle_t *h, size_t *len) {
  if(len) *len = mtev_dyn_buffer_used(&h->dyn);
  return mtev_dyn_buffer_data(&h->dyn);
}

CURL *mtev_curl_handle_get_easy_handle(mtev_curl_handle_t *h) {
  return h->curl;
}

CURLcode mtev_curl_handle_get_code(mtev_curl_handle_t *h) {
  return h->code;
}

long mtev_curl_handle_get_httpcode(mtev_curl_handle_t *h) {
  return h->httpcode;
}

static int
mtev_curl_debug_function(CURL *handle, curl_infotype type, char *data, size_t size, void *vl) {
  mtev_log_stream_t ls = vl;
  switch(type) {
    case CURLINFO_TEXT:
      if(size > 0 && data[size-1] == '\n') size--;
      mtevL(ls, "[%p] %s '%.*s'\n", handle, "INFO", (int)size, data);
      break;
    case CURLINFO_HEADER_IN:
      if(size > 0 && data[size-1] == '\n') size--;
      mtevL(ls, "[%p] %s '%.*s'\n", handle, "HEADER_IN", (int)size, data);
      break;
    case CURLINFO_HEADER_OUT:
      if(size > 0 && data[size-1] == '\n') size--;
      mtevL(ls, "[%p] %s '%.*s'\n", handle, "HEADER_OUT", (int)size, data);
      break;
    case CURLINFO_DATA_IN:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
    case CURLINFO_SSL_DATA_OUT:
      mtevL(ls, "[%p] %s data %s %zu bytes\n", handle,
            (type == CURLINFO_SSL_DATA_IN || type == CURLINFO_SSL_DATA_OUT) ? "SSL" : "PLAIN",
            (type == CURLINFO_DATA_IN || type == CURLINFO_SSL_DATA_IN) ? "IN" : "OUT", size);
      break;
    default:
      break;
  }
  return 0;
}

typedef struct {
  eventer_t e;
  curl_socket_t s;
} curl_context_t;

static void process_global_curlm(void) {
  char *done_url;
  CURLMsg *message;
  int pending;
  CURL *easy_handle;
  mtev_curl_handle_t *handle;
  CURLM *global_curl_handle = global_curl_handle_get();
  while((message = curl_multi_info_read(global_curl_handle, &pending))) {
    switch(message->msg) {
    case CURLMSG_DONE:
      easy_handle = message->easy_handle;

      curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
      long httpcode = 0;
      curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, (char **)&handle);
      curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &httpcode);
      handle->code = message->data.result;
      handle->httpcode = httpcode;
      if(handle->handler) {
        handle->handler(message->data.result, easy_handle, &handle->dyn, handle->userdata);
      }
      if(handle->span) mtev_zipkin_curl_record(easy_handle, handle->span);
      if(httpcode == 200) {
        mtevL(debug_ls, "%s DONE\n", done_url);
      } else {
        mtevL(debug_ls, "%s -> %d %.*s\n", done_url, (int)httpcode,
              (int)mtev_dyn_buffer_used(&handle->dyn),
              (const char *)mtev_dyn_buffer_data(&handle->dyn));
      }
 
      curl_multi_remove_handle(global_curl_handle, easy_handle);
      curl_easy_cleanup(easy_handle);
      if(handle) {
        mtev_curl_handle_free(handle);
      }
      break;
    default:
      mtevL(error_ls, "CURLMSG default\n");
      break;
    }
  }
}

static int
eventer_curl_perform(eventer_t e, int mask, void *vc, struct timeval *now) {
  (void)now;
  curl_context_t *c = vc;
  int flags = 0;
  int running_handles;
  if(mask & (EVENTER_EXCEPTION|EVENTER_READ)) flags |= CURL_CSELECT_IN;
  if(mask & (EVENTER_EXCEPTION|EVENTER_WRITE)) flags |= CURL_CSELECT_OUT;

  curl_multi_socket_action(global_curl_handle_get(), c->s, flags, &running_handles);

  process_global_curlm();

  return c->e == NULL ? 0 : eventer_get_mask(e);
}
static int
eventer_curl_on_timeout(eventer_t e, int mask, void *c, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)c;
  (void)now;
  mtevL(debug_ls, "curl_multi timeout\n");
  int running_handles;
  curl_multi_socket_action(global_curl_handle_get(), CURL_SOCKET_TIMEOUT, 0, &running_handles);
  _global_curl_timeout = NULL;
  process_global_curlm();
  return 0;
}
static int
eventer_curl_start_timeout(CURLM *multi, long timeout_ms, void *userp) {
  (void)multi;
  (void)userp;
  mtevL(debug_ls, "curl_multi start timeout %d\n", (int)timeout_ms);
  if(timeout_ms < 0) {
    if(_global_curl_timeout) {
      eventer_remove(_global_curl_timeout);
      _global_curl_timeout = NULL;
    }
  }
  else {
    if(timeout_ms == 0) timeout_ms = 1;
    _global_curl_timeout = eventer_in_s_us(eventer_curl_on_timeout, NULL,
                                           timeout_ms / 1000, 1000 * (timeout_ms % 1000));
    eventer_add(_global_curl_timeout);
  }
  return 0;
}
static int
eventer_curl_handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
  (void)easy;
  (void)userp;
  curl_context_t *c = socketp;
  switch(action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
      {
      int mask = EVENTER_EXCEPTION;
      if(!c) {
        c = calloc(1, sizeof(*c));
        c->s = s;
        curl_multi_assign(global_curl_handle_get(), s, c);
      }
      if(action != CURL_POLL_IN) mask |= EVENTER_WRITE;
      if(action != CURL_POLL_OUT) mask |= EVENTER_READ;
      mtevL(debug_ls, "curl wants %x\n", mask);
      if(c->e) {
        eventer_update(c->e, mask);
      } else {
        c->e = eventer_alloc_fd(eventer_curl_perform, c, s, mask);
        eventer_add(c->e);
      }
      }
      break;
    case CURL_POLL_REMOVE:
      if(!c) {
        eventer_t e = eventer_find_fd(s);
        if(e) c = eventer_get_closure(e);
        curl_multi_assign(global_curl_handle_get(), s, c);
      }
      if(c) {
        if(c->e) {
          eventer_t tofree = eventer_remove_fde(c->e);
          mtevL(debug_ls, "curl removed %p as %p\n", c->e, tofree);
          c->e = NULL;
        }
        free(c);
        curl_multi_assign(global_curl_handle_get(), s, NULL);
      } else {
        mtevL(debug_ls, "curl removal with no socket ptr\n");
        close(s);
      }
      break;
    default:
      mtevAssert(0);
  }
  return 0;
}

static CURLM *
global_curl_handle_get(void) {
  if(!_global_curl_handle) {
    if(!eventer_in_loop()) {
      mtevAssert(first_assigned);
      return first_assigned;
    }
    _global_curl_handle = curl_multi_init();
    curl_multi_setopt(_global_curl_handle, CURLMOPT_SOCKETFUNCTION, eventer_curl_handle_socket);
    curl_multi_setopt(_global_curl_handle, CURLMOPT_TIMERFUNCTION, eventer_curl_start_timeout);
    if(!first_assigned) first_assigned = _global_curl_handle;
  }
  return _global_curl_handle;
}


mtev_curl_handle_t *mtev_curl_easy(mtev_curl_cb_func_t handler, void *udata, bool use_zipkin) {
  CURL *curl;
  curl = curl_easy_init();

  mtev_curl_handle_t *ch = calloc(1, sizeof(*ch));
  ch->ref = 1;
  ch->handler = handler;
  ch->userdata = udata;
  ch->curl = curl;
  mtev_dyn_buffer_init(&ch->dyn);

  if(use_zipkin) ch->span = mtev_zipkin_client_span(NULL);

  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 300000); /* 5m */
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500); /* 500ms */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&ch->dyn);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mtev_dyn_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, (void *)ch);
  return ch;
}

void mtev_curl_handle_debug(mtev_curl_handle_t *handle, mtev_log_stream_t ls) {
   curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, mtev_curl_debug_function);
   curl_easy_setopt(handle, CURLOPT_DEBUGDATA, ls);
   curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
}

static void mtev_curl_aco_handler(CURLcode code, CURL *curl, mtev_dyn_buffer_t *dyn, void *udata) {
  (void)code;
  (void)curl;
  (void)dyn;
  eventer_aco_resume(udata);
}

mtev_curl_handle_t *mtev_curl_easy_aco(bool use_zipkin) {
  mtevAssert(eventer_is_aco(NULL));
  return mtev_curl_easy(mtev_curl_aco_handler, aco_get_co(), use_zipkin);
}

static void mtev_curl_perform_basic(mtev_curl_handle_t *h) {
  curl_multi_add_handle(global_curl_handle_get(), h->curl);
  int running_handles;
  curl_multi_socket_action(global_curl_handle_get(), CURL_SOCKET_TIMEOUT, 0, &running_handles);
  process_global_curlm();
}

void mtev_curl_perform(mtev_curl_handle_t *h) {
  mtevAssert(!eventer_is_aco(NULL));
  mtev_curl_perform_basic(h);
}

void mtev_curl_perform_aco(mtev_curl_handle_t *h) {
  mtevAssert(eventer_is_aco(NULL));
  mtev_curl_perform_basic(h);
  h->ref++;
  mtevAssert(h->handler == mtev_curl_aco_handler);
  mtevAssert(h->userdata == aco_get_co());
  aco_yield();
}
