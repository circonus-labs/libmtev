/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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
#include "mtev_b64.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_http.h"
#include "mtev_rest.h"
#include "mtev_dso.h"
#include "mtev_memory.h"

#include <ctype.h>
#include <ck_pr.h>
#include <pcre.h>

static mtev_log_stream_t debugls, errorls;
static uint32_t max_count = 10000, max_age = 30;
static uint64_t global_id;
static mtev_hash_table lookup, hdrin_extract, hdrout_extract;

static uint64_t timeofday_nanos(void) {
  struct timeval now;
  mtev_gettimeofday(&now, NULL);
  return now.tv_sec * 1000000000 + now.tv_usec * 1000;
}

typedef struct {
  mtev_http_session_ctx *ctx;
  uint64_t id;
  uint64_t request_start_ns;
  uint64_t request_complete_ns;
  uint64_t read_start_ns;
  uint64_t read_complete_ns;
  uint64_t response_start_ns;
  uint64_t response_complete_ns;
  uint64_t inbytes;
  uint64_t outbytes;
  mtev_hash_table info;
} http_entry_t;

static void http_entry_free(void *ve) {
  http_entry_t *e = ve;
  if(e == NULL) return;
  mtev_hash_destroy(&e->info, mtev_memory_safe_free, mtev_memory_safe_free);
}

static void http_entry_track(http_entry_t *e, const char *key, const char *val) {
  char *keycopy = mtev_memory_safe_strdup(key);
  char *valcopy = mtev_memory_safe_strdup(val);
  mtev_hash_replace(&e->info, keycopy, strlen(keycopy), valcopy,
                    mtev_memory_safe_free, mtev_memory_safe_free);
}

http_entry_t **cache;
uint32_t hptr = 0;

static http_entry_t *
allocate_entry(mtev_http_session_ctx *ctx) {
  void *vptr;
  if(mtev_hash_retrieve(&lookup, (const char *)&ctx, sizeof(ctx), &vptr)) {
    return (http_entry_t *)vptr;
  }
  http_entry_t *newe = mtev_memory_safe_malloc_cleanup(sizeof(*newe), http_entry_free);
  memset(newe, 0, sizeof(*newe));
  newe->ctx = ctx;
  newe->request_complete_ns = timeofday_nanos();
  newe->id = ck_pr_faa_64(&global_id, 1);
  mtev_hash_init(&newe->info);
  mtev_hash_replace(&lookup, (const char *)&newe->ctx, sizeof(newe->ctx), newe, NULL, mtev_memory_safe_free);
  return newe;
}

static void
http_entry_update(http_entry_t *entry, mtev_http_session_ctx *ctx) {
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_http_response *res = mtev_http_session_response(ctx);
  entry->inbytes = mtev_http_request_content_length_read(req);
  entry->outbytes = mtev_http_response_bytes_written(res);
}
static mtev_hook_return_t
http_observer_rc(void *closure, mtev_http_session_ctx *ctx) {
  (void)closure;
  mtev_memory_begin();
  http_entry_t *entry = allocate_entry(ctx);
  struct timeval rstart;
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_http_request_start_time(req, &rstart);
  entry->request_start_ns = rstart.tv_sec * 1000000000 + rstart.tv_usec * 1000;

  char ip[64];
  mtev_acceptor_closure_t *ac = mtev_http_session_acceptor_closure(ctx);

  const char *remote_cn = mtev_acceptor_closure_remote_cn(ac);
  if(remote_cn) http_entry_track(entry, "remote_tls_common_name", remote_cn);

  struct sockaddr *remote = mtev_acceptor_closure_remote(ac);
  mtev_convert_sockaddr_to_buff(ip, sizeof(ip), remote);

  http_entry_track(entry, "remote_address", ip);
  uint16_t hostport;
  char port[8];
  switch(remote->sa_family) {
    case AF_INET:
      hostport = ntohs(((struct sockaddr_in *)remote)->sin_port);
      snprintf(port, sizeof(port), "%u", hostport);
      http_entry_track(entry, "remote_port", port);
      break;
    case AF_INET6:
      hostport = ntohs(((struct sockaddr_in6 *)remote)->sin6_port);
      snprintf(port, sizeof(port), "%u", hostport);
      http_entry_track(entry, "remote_port", port);
      break;
    default:
      break;
  }
  http_entry_track(entry, "uri", mtev_http_request_uri_str(req));
  const char *qs = mtev_http_request_orig_querystring(req);
  if(qs) http_entry_track(entry, "querystring", qs);
  http_entry_track(entry, "method", mtev_http_request_method_str(req));
  http_entry_track(entry, "protocol", mtev_http_request_protocol_str(req));

  const char *hdrval;
  mtev_hash_table *hdrs = mtev_http_request_headers_table(req);
  if(mtev_hash_retr_str(hdrs, "host", strlen("host"), &hdrval)) http_entry_track(entry, "host", hdrval);

  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(&hdrin_extract, &iter)) {
    if(mtev_hash_retr_str(hdrs, iter.key.str, strlen(iter.key.str), &hdrval)) http_entry_track(entry, iter.value.str, hdrval);
  }

  http_entry_update(entry, ctx);
  mtev_memory_end();
  return MTEV_HOOK_CONTINUE;
}

static mtev_hook_return_t
http_observer_prrp(void *closure, mtev_http_session_ctx *ctx) {
  (void)closure;
  void *vptr;
  mtev_memory_begin();
  if(mtev_hash_retrieve(&lookup, (const char *)&ctx, sizeof(ctx), &vptr)) {
    http_entry_t *entry = vptr;
    entry->read_complete_ns = timeofday_nanos();
    if(entry->read_start_ns == 0) {
      entry->read_start_ns = entry->read_complete_ns;
    }
    http_entry_update(entry, ctx);
  }
  mtev_memory_end();
  return MTEV_HOOK_CONTINUE;
}

static mtev_hook_return_t
http_observer_rs(void *closure, mtev_http_session_ctx *ctx) {
  (void)closure;
  void *vptr;
  mtev_memory_begin();
  if(mtev_hash_retrieve(&lookup, (const char *)&ctx, sizeof(ctx), &vptr)) {
    http_entry_t *entry = vptr;
    mtev_http_response *res = mtev_http_session_response(ctx);
    if(entry->response_start_ns == 0) {
      entry->response_start_ns = timeofday_nanos();
      char status_string[4];
      snprintf(status_string, sizeof(status_string), "%d", mtev_http_response_status(res));
      http_entry_track(entry, "status", status_string);

      mtev_hash_table *hdrs = mtev_http_response_headers_table(res);
      if(hdrs) {
        char lower_copy[1024], *tcp;
        const char *hdrname;
        mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
        while(mtev_hash_adv(hdrs, &iter)) {
          strlcpy(lower_copy, iter.key.str, sizeof(lower_copy));
          for(tcp = lower_copy; *tcp; tcp++) *tcp = tolower(*tcp);
          if(mtev_hash_retr_str(&hdrout_extract, lower_copy, strlen(lower_copy), &hdrname)) {
            http_entry_track(entry, hdrname, iter.value.str);
          }
        }
      }
    }
    http_entry_update(entry, ctx);
  }
  mtev_memory_end();
  return MTEV_HOOK_CONTINUE;
}

static mtev_hook_return_t
http_observer_rl(void *closure, mtev_http_session_ctx *ctx) {
  (void)closure;
  void *vptr;
  mtev_memory_begin();
  if(mtev_hash_retrieve(&lookup, (const char *)&ctx, sizeof(ctx), &vptr) &&
     mtev_hash_delete(&lookup, (const char *)&ctx, sizeof(ctx), NULL, NULL)) {
    http_entry_t *entry = vptr;
    entry->ctx = NULL;
    http_entry_update(entry, ctx);
    mtev_http_response *res = mtev_http_session_response(ctx);
    mtev_hash_table *hdrs = mtev_http_response_trailers_table(res);
    if(hdrs) {
      char lower_copy[1024], *tcp;
      const char *hdrname;
      mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
      while(mtev_hash_adv(hdrs, &iter)) {
        strlcpy(lower_copy, iter.key.str, sizeof(lower_copy));
        for(tcp = lower_copy; *tcp; tcp++) *tcp = tolower(*tcp);
        if(mtev_hash_retr_str(&hdrout_extract, lower_copy, strlen(lower_copy), &hdrname)) {
          http_entry_track(entry, hdrname, iter.value.str);
        }
      }
    }
    entry->response_complete_ns = timeofday_nanos();
    if(entry->response_start_ns == 0) {
      entry->response_start_ns = entry->response_complete_ns;
      char status_string[4];
      snprintf(status_string, sizeof(status_string), "%d", mtev_http_response_status(res));
      http_entry_track(entry, "status", status_string);
    }

    uint32_t next = ck_pr_faa_32(&hptr, 1);
    http_entry_t *old;
    do {
      old = ck_pr_load_ptr(&cache[next % max_count]);
    } while(!ck_pr_cas_ptr(&cache[next % max_count], old, entry));
    if(old) mtev_memory_safe_free(old);
  }
  mtev_memory_end();
  return MTEV_HOOK_CONTINUE;
}

void
http_observer_note_dyn(mtev_http_session_ctx *ctx, const char *key, const char *value) {
  void *vptr = NULL;
  mtev_memory_begin();
  if(mtev_hash_retrieve(&lookup, (const char *)&ctx, sizeof(ctx), &vptr)) {
    http_entry_t *entry = vptr;
    http_entry_track(entry, key, value);
  }
  mtev_memory_end();
}

typedef struct {
  const char *field;
  const char *str;
  pcre *re;
} expect_t;

static bool row_want(http_entry_t *entry, expect_t **exp) {
  int i = 0;
  if(exp == NULL) return true;
  for(i=0; exp[i]; i++) {
    const char *str;
    int ovector[30];
    expect_t *e = exp[i];
    if(!mtev_hash_retr_str(&entry->info, e->field, strlen(e->field), &str)) {
      return false;
    }
    if(e->str && strcmp(e->str, str)) return false;
    else if(e->re && pcre_exec(e->re, NULL, str, strlen(str), 0, 0, ovector, 30) < 0) return false;
  }
  return true;
}

static void http_entry_json(mtev_http_session_ctx *ctx, http_entry_t *entry) {
  json_object *o = MJ_OBJ();
  MJ_KV(o, "request_id", MJ_INT64(entry->id));
  MJ_KV(o, "request_start_ms", MJ_INT64(entry->request_start_ns/1000000));
  if(entry->request_complete_ns)
    MJ_KV(o, "request_complete_offset_ns", MJ_INT64(entry->request_complete_ns - entry->request_start_ns));
  if(entry->read_start_ns)
    MJ_KV(o, "read_start_offset_ns", MJ_INT64(entry->read_start_ns - entry->request_start_ns));
  if(entry->read_complete_ns)
    MJ_KV(o, "read_complete_offset_ns", MJ_INT64(entry->read_complete_ns - entry->request_start_ns));
  if(entry->response_start_ns)
    MJ_KV(o, "response_start_offset_ns", MJ_INT64(entry->response_start_ns - entry->request_start_ns));
  if(entry->response_complete_ns)
    MJ_KV(o, "response_complete_offset_ns", MJ_INT64(entry->response_complete_ns - entry->request_start_ns));
  MJ_KV(o, "received_bytes", MJ_INT64(entry->inbytes));
  MJ_KV(o, "sent_bytes", MJ_INT64(entry->outbytes));
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv_spmc(&entry->info, &iter)) {
    MJ_KV(o, iter.key.str, MJ_STR(iter.value.str));
  }
  mtev_http_response_append_json(ctx, o);
  MJ_DROP(o);
}

static int requests_json_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  (void)npats;
  (void)pats;
  uint32_t i;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_hash_table *qs = mtev_http_request_querystring_table(req);
  uint64_t now_ns = timeofday_nanos();

  expect_t **exp;
  uint32_t cnt = 0;

  const uint32_t max_expressions = 16;
  exp = calloc(max_expressions+1, sizeof(*exp));
  while(mtev_hash_adv(qs, &iter) && cnt < max_expressions) {
    if(!strncmp(iter.key.str, "eq_", 3)) {
      exp[cnt] = calloc(1, sizeof(**exp));
      exp[cnt]->field = iter.key.str+3;
      exp[cnt]->str = iter.value.str;
      cnt++;
    }
    else if(!strncmp(iter.key.str, "re_", 3)) {
      const char *error;
      int erroffset;
      exp[cnt] = calloc(1, sizeof(**exp));
      exp[cnt]->field = iter.key.str+3;
      exp[cnt]->re = pcre_compile(iter.value.str, 0, &error, &erroffset, NULL);
      cnt++;
    }
  }

  mtev_memory_begin();
  cnt = 0;
  mtev_http_response_ok(ctx, "application/json");
  mtev_http_response_append(ctx, "[", 1);

  /* First live requests */
  memset(&iter, 0, sizeof(iter));
  while(mtev_hash_adv_spmc(&lookup, &iter)) {
    if(row_want((http_entry_t *)iter.value.ptr, exp)) {
      if(cnt++) mtev_http_response_append(ctx, ",", 1);
      http_entry_json(ctx, (http_entry_t *)iter.value.ptr);
    }
  }

  /* Then old requests */
  for(i=0; i<max_count; i++) {
    http_entry_t *entry = ck_pr_load_ptr(&cache[i]);
    if(entry) {
      if( ((now_ns - entry->response_complete_ns) / 1000000000) >= max_age ) {
        if(ck_pr_cas_ptr(&cache[i], entry, NULL)) {
          mtev_memory_safe_free(entry);
        }
      } else {
        if(row_want(entry, exp)) {
          if(cnt++) mtev_http_response_append(ctx, ",", 1);
          http_entry_json(ctx, entry);
        }
      }
    }
  }

  mtev_http_response_append(ctx, "]\n", 2);
  mtev_http_response_end(ctx);
  mtev_memory_end();

  for(i=0;i<max_expressions;i++) {
    if(exp[i]) {
      if(exp[i] && exp[i]->re) pcre_free(exp[i]->re);
      free(exp[i]);
    }
  }
  free(exp);
  return 0;
}

static int
http_observer_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  (void)img;
  const char *vstr;
  mtev_hash_init(&hdrin_extract);
  mtev_hash_init(&hdrout_extract);
  if(mtev_hash_retr_str(options, "max_count", strlen("max_count"), &vstr)) {
    max_count = atoi(vstr);
  }
  if(mtev_hash_retr_str(options, "max_age", strlen("max_age"), &vstr)) {
    max_age = atoi(vstr);
  }
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    if(!strncmp(iter.key.str, "header_in_", 10)) {
      mtev_hash_replace(&hdrin_extract, strdup(iter.key.str + 10), strlen(iter.key.str+10), strdup(iter.value.str), free, free);
    }
    if(!strncmp(iter.key.str, "header_out_", 11)) {
      mtev_hash_replace(&hdrout_extract, strdup(iter.key.str + 11), strlen(iter.key.str+11), strdup(iter.value.str), free, free);
    }
  }
  return 0;
}

static int
http_observer_driver_init(mtev_dso_generic_t *img) {
  (void)img;
  mtev_hash_init(&lookup);
  cache = calloc(max_count, sizeof(*cache));
  debugls = mtev_log_stream_find("debug/http_observer");
  errorls = mtev_log_stream_find("error/http_observer");
  http_request_complete_hook_register("http_observer", http_observer_rc, NULL);
  http_response_send_hook_register("http_observer", http_observer_rs, NULL);
  http_request_log_hook_register("http_observer", http_observer_rl, NULL);
  http_post_request_read_payload_hook_register("http_observer", http_observer_prrp, NULL);

  mtev_rest_mountpoint_t *rule = mtev_http_rest_new_rule(
    "GET", "/module/http_observer/", "^requests.json$", requests_json_handler
  );
  mtev_rest_mountpoint_set_auth(rule, mtev_http_rest_client_cert_auth);
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  return 0;
}

#include "http_observer.xmlh"

mtev_dso_generic_t http_observer = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "http_observer",
    .description = "An observer of live http traffic",
    .xml_description = http_observer_xml_description,
  },
  http_observer_driver_config,
  http_observer_driver_init
};
