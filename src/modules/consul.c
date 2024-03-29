/*
 * Copyright (c) 2019-2022, Circonus, Inc. All rights reserved.
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
#include "ck_spinlock.h"

#include "mtev_consul.h"

#include <sys/utsname.h>
#include <libxml/tree.h>
#include <curl/curl.h>

/* This module registers mtev apps with consul and provides KV config lookups. */

/*
        <consul>
          <services>
            <service id="{app}-{node}" port="12123">
              <check DeregisterCriticalServiceAfter="10m" Interval="5s" HTTP="/url" (or PUSH="5s" or TCP=":12123") />
              <weights passing="10" warning="1"/>
              <tags features="true">
                <foo/>
                <bar>baz</bar>
              </tags>
              <meta version="true">
                <key>value</key>
              </meta>
            </service>
          </services>
        </consul>
 */

typedef enum { PASSING_CODE = 204, WARNING_CODE = 429, CRITICAL_CODE = 502 } service_code_e;
typedef enum { CS_UNINIT = 0, CS_REGISTERED, CS_DEREGISTERED } service_state_e;

#define MAX_CHECKS 5

struct service_register {
  int refcnt;
  ck_spinlock_t lock;
  mtev_json_object *consul_object;
  char *service_id;
  service_state_e desired_state;
  service_state_e state;
  int period[MAX_CHECKS];
  char *service_msg[MAX_CHECKS];
  service_code_e service_code[MAX_CHECKS];
};

struct mtev_consul_service {
  char *id;
  char *name;
  char *address;
  unsigned short port;
  bool enabletagoverride;
  struct {
    enum { CHECK_NONE = 0, CHECK_PUSH, CHECK_TCP, CHECK_HTTP, CHECK_HTTPS } type;
    char *deregistercriticalserviceafter;
    union {
      struct { char *ttl; } push;
      struct { char *tcp; char *interval; char *timeout; } tcp;
      struct { char *url; char *interval; char *method; char *timeout; } http;
      struct { char *url; char *interval; char *method; char *timeout;
               char *tlsservername; bool tlsskipverify; } https;
    };
    char *name;
  } check[MAX_CHECKS];
  struct {
    int passing;
    int warning;
  } weights;
  mtev_hash_table *tags;
  mtev_hash_table *meta;
  bool tags_owned;
  bool meta_owned;
};

static eventer_jobq_t *consul_jobq;
static mtev_hash_table service_registry;
static char *consul_bearer_token = NULL;
static char *consul_kv_prefix = NULL;
static char *consul_service_endpoint = "http://localhost:8500";
static service_code_e default_service_code = PASSING_CODE;
static mtev_log_stream_t debug_ls, debug_curl_ls, error_ls;

static void mtev_consul_sync_services(void);

static const char *health_string(const service_register *sr, int idx) {
  if(idx >= 0 && idx < MAX_CHECKS) {
    switch(sr->service_code[idx]) {
      case PASSING_CODE: return "pass";
      case WARNING_CODE: return "warn";
      default: break;
    }
  }
  return "fail";
}

static const char *cs_state_name(service_state_e s) {
  switch(s) {
    case CS_UNINIT: return "uninitialized";
    case CS_REGISTERED: return "registered";
    case CS_DEREGISTERED: return "deregistered";
  }
  return "unknown";
}

void service_register_ref(service_register *sr) {
  ck_pr_inc_int(&sr->refcnt);
}
static void service_register_deref(void *vsr) {
  service_register *sr = vsr;
  if(ck_pr_dec_int_is_zero(&sr->refcnt)) {
    free(sr->service_id);
    if(sr->consul_object) MJ_DROP(sr->consul_object);
    for(int i=0; i<MAX_CHECKS; i++)
      free(sr->service_msg[i]);
    free(sr);
  }
}

void mtev_consul_set_passing_f(service_register *sr, int idx, const char *msg) {
  if(idx < 0 || idx >= MAX_CHECKS) return;
  ck_spinlock_lock(&sr->lock);
  sr->service_code[idx] = PASSING_CODE;
  free(sr->service_msg[idx]);
  sr->service_msg[idx] = msg ? strdup(msg) : NULL;
  ck_spinlock_unlock(&sr->lock);
}
void mtev_consul_set_warning_f(service_register *sr, int idx, const char *msg) {
  if(idx < 0 || idx >= MAX_CHECKS) return;
  ck_spinlock_lock(&sr->lock);
  sr->service_code[idx] = WARNING_CODE;
  free(sr->service_msg[idx]);
  sr->service_msg[idx] = msg ? strdup(msg) : NULL;
  ck_spinlock_unlock(&sr->lock);
}
void mtev_consul_set_critical_f(service_register *sr, int idx, const char *msg) {
  if(idx < 0 || idx >= MAX_CHECKS) return;
  ck_spinlock_lock(&sr->lock);
  sr->service_code[idx] = CRITICAL_CODE;
  free(sr->service_msg[idx]);
  sr->service_msg[idx] = msg ? strdup(msg) : NULL;
  ck_spinlock_unlock(&sr->lock);
}

static size_t kv_fetch_index(void *buff, size_t s, size_t n, void *vd) {
  char *cb = (char *)buff;
  uint32_t *index = vd;
  size_t data_len = s * n;
  if(!strncasecmp(cb, "X-Consul-Index:", strlen("X-Consul-Index:"))) {
    *index = strtoul(cb + strlen("X-Consul-Index:") + 1, NULL, 0);
  }
  return data_len;
}
struct kv_tree_read {
  bool done;
  char *path;
  uint32_t index;
  struct curl_slist *headers;
  char wait[12];
  uint32_t wait_ms;
  struct timeval last;
  void (*witness)(const char *key, uint8_t *value, size_t value_len, uint32_t index);
};
static void mtev_consul_stay_current_kv(struct kv_tree_read *udata);
static int restart_stay_current(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  mtev_consul_stay_current_kv(closure);
  return 0;
}
static void mtev_consul_kv_tree_reader(CURLcode code, CURL *easy, mtev_dyn_buffer_t *dyn,
                                       void *udata) {
  (void)easy;
  struct kv_tree_read *tree = udata;
  long httpcode = 0;
  curl_slist_free_all(tree->headers);
  tree->headers = NULL;
  MTEV_MAYBE_DECL(uint8_t, valbuf, 2048);
  if(code == CURLE_OK && CURLE_OK == curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &httpcode) &&
     httpcode == 200) {
    mtev_json_object *obj = mtev_json_tokener_parse((const char *)mtev_dyn_buffer_data(dyn), NULL);
    if(obj != NULL && mtev_json_object_get_type(obj) == mtev_json_type_array) {
      for(int i=0; i<mtev_json_object_array_length(obj); i++) {
        mtev_json_object *jitem = mtev_json_object_array_get_idx(obj, i);
        mtev_json_object *jkey = mtev_json_object_object_get(jitem, "Key");
        mtev_json_object *jval = mtev_json_object_object_get(jitem, "Value");

        if(jkey) {
          const char *key = mtev_json_object_get_string(jkey);
          ssize_t vlen = 0;
          uint8_t *val = NULL;
          if(jval) {
            val = (uint8_t *)mtev_json_object_get_string(jval);
            if(val) {
              size_t blen = strlen((char *)val);
              MTEV_MAYBE_REALLOC(valbuf, blen);
              vlen = mtev_b64_decode((char *)val, blen, valbuf, blen);
              if(vlen < 0) {
                vlen = 0;
                val = NULL;
              } else {
                val = valbuf;
              }
            }
          }
          if(tree->witness) tree->witness(key, val, vlen, tree->index);
        }
      }
      if(tree->witness) tree->witness(NULL, NULL, 0, tree->index);
    } else {
      mtevL(error_ls, "Failed to parse consul kv fetch\n");
      tree->index = 0;
    }
    if(obj) MJ_DROP(obj);
  }
  else if(code == CURLE_OPERATION_TIMEDOUT) {
    mtevL(debug_ls, "timeout\n");
  }
  else {
    mtevL(debug_ls, "Failed to fetch\n");
    tree->index = 0;
  }
  MTEV_MAYBE_FREE(valbuf);

  if(tree->done) {
    free(tree->path);
    free(tree);
    return;
  }
  struct timeval now, diff;
  mtev_gettimeofday(&now, NULL);
  sub_timeval(now, tree->last, &diff);
  if(diff.tv_sec <= 1) {
    now.tv_sec = 2;
    now.tv_usec = 0;
    sub_timeval(now, diff, &diff);
    eventer_add_in_s_us(restart_stay_current, tree, diff.tv_sec, diff.tv_usec);
  } else {
    mtev_consul_stay_current_kv(tree);
  }
}
static void mtev_consul_stay_current_kv(struct kv_tree_read *udata) {
  mtev_curl_handle_t *ch = mtev_curl_easy(mtev_consul_kv_tree_reader, udata, false);
  CURL *curl = mtev_curl_handle_get_easy_handle(ch);
  char header[256];
  char url[1024];
  char error[CURL_ERROR_SIZE] = "unknown error";
  if(consul_bearer_token) {
    snprintf(header, sizeof(header), "Authorization: Bearer %s", consul_bearer_token);
    udata->headers = curl_slist_append(udata->headers, header);
  }
  char *escaped_key = curl_easy_escape(curl, udata->path, 0); 
  snprintf(url, sizeof(url), "%s/v1/kv/%s%s%s?recurse=1&index=%u&wait=%s", consul_service_endpoint,
           consul_kv_prefix ? consul_kv_prefix : "", consul_kv_prefix ? "/" : "", escaped_key,
           udata->index, udata->wait);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, udata->headers);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, udata->wait_ms + 1000); /* + 1s */
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, kv_fetch_index);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&udata->index);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, (void *)ch);

  mtev_gettimeofday(&udata->last, NULL);
  mtev_curl_perform(ch);

  curl_free(escaped_key);
}
void *
mtev_consul_kv_attach_function(const char *path,
                               void (*witness)(const char *key, uint8_t *value, size_t value_len, uint32_t index)) {
  struct kv_tree_read *udata = calloc(1, sizeof(*udata));
  udata->path = strdup(path);
  strlcpy(udata->wait, "5m", sizeof(udata->wait));
  uint64_t wait_ms;
  (void)mtev_confstr_parse_duration(udata->wait, &wait_ms, mtev_get_durations_ms());
  udata->wait_ms = wait_ms;
  udata->witness = witness;
  mtev_consul_stay_current_kv(udata);
  return udata;
}
void
mtev_consul_kv_detach_function(void *handle) {
  struct kv_tree_read *udata = handle;
  udata->done = true;
}
static char *mtev_consul_fetch_config_kv(const char *key, uint32_t *index_ptr) {
  CURL *curl;
  curl = curl_easy_init();
  char header[256];
  char url[1024];
  char error[CURL_ERROR_SIZE] = "unknown error";
  mtev_dyn_buffer_t response;
  mtev_dyn_buffer_init(&response);
  struct curl_slist *slist = NULL;
  if(consul_bearer_token) {
    snprintf(header, sizeof(header), "Authorization: Bearer %s", consul_bearer_token);
    slist = curl_slist_append(slist, header);
  }
  uint32_t index = 0;
  char *escaped_key = curl_easy_escape(curl, key, 0);
  snprintf(url, sizeof(url), "%s/v1/kv/%s%s%s?raw=true", consul_service_endpoint,
           consul_kv_prefix ? consul_kv_prefix : "", consul_kv_prefix ? "/" : "", escaped_key);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mtev_dyn_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, kv_fetch_index);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&index);

  char *value = NULL;
  CURLcode code = mtev_zipkin_curl_easy_perform(curl);
  *index_ptr = index;
  long httpcode = 0;
  if(CURLE_OK == code) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
    if(httpcode != 200) {
      mtevL(error_ls, "Failed to get %s: [%d] %s\n", url, (int)httpcode, error);
    } else {
      value = strndup((const char *)mtev_dyn_buffer_data(&response),
                      mtev_dyn_buffer_used(&response));
    }
  } else {
    mtevL(error_ls, "Failed to get %s: %s\n", url, curl_easy_strerror(code));
  }
  mtev_dyn_buffer_destroy(&response);
  curl_free(escaped_key);
  curl_slist_free_all(slist);
  curl_easy_cleanup(curl); 
  return value;
}

static int curl_put_json(const char *url, mtev_json_object *o) {
  CURL *curl;
  curl = curl_easy_init();
  struct curl_slist *slist = NULL;
  char header[256];
  char error[CURL_ERROR_SIZE] = "unknown error";
  if(consul_bearer_token) {
    snprintf(header, sizeof(header), "Authorization: Bearer %s", consul_bearer_token);
    slist = curl_slist_append(slist, header);
  }
  slist = curl_slist_append(slist, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(curl, CURLOPT_URL, url);
  const char *payload = mtev_json_object_to_json_string(o);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);

  mtevL(debug_ls, "PUT (%s)\n", payload);

  CURLcode code = mtev_zipkin_curl_easy_perform(curl);
  long httpcode = 0;
  int rv = 0;
  if(CURLE_OK == code) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
    if(httpcode < 200 || httpcode >= 300) {
      mtevL(error_ls, "Failed to put %s: %s\n", url, error);
      rv = -1;
    }
  } else {
    mtevL(error_ls, "Failed to put %s: %s\n", url, curl_easy_strerror(code));
    rv = -1;
  }
  curl_slist_free_all(slist);
  curl_easy_cleanup(curl); 
  return rv;
} 

struct health_crutch {
  service_register *sr;
  int idx;
};
static struct health_crutch *health_crutch(service_register *sr, int idx) {
  struct health_crutch *hc = calloc(1, sizeof(*hc));
  hc->sr = sr;
  hc->idx = idx;
  return hc;
}

static int mtev_consul_push_health(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  struct health_crutch *hc = (struct health_crutch *)closure;
  service_register *sr = hc->sr;
  int idx = hc->idx;

  if(sr->state == CS_DEREGISTERED) {
    free(hc);
    return 0;
  }

  mtev_curl_handle_t *ch = mtev_curl_easy(NULL, NULL, false);

  char header[256];
  CURL *curl = mtev_curl_handle_get_easy_handle(ch);
  char url[1024];
  static struct curl_slist *slist = NULL;
  if(slist == NULL && consul_bearer_token) {
    snprintf(header, sizeof(header), "Authorization: Bearer %s", consul_bearer_token);
    slist = curl_slist_append(slist, header);
  }

  ck_spinlock_lock(&sr->lock);

  char *escaped_key = curl_easy_escape(curl, sr->service_id, 0); 
  if(sr->service_msg[idx]) {
    char *escaped_note = curl_easy_escape(curl, sr->service_msg[idx], 0);
    snprintf(url, sizeof(url), "%s/v1/agent/check/%s/service:%s:%d?note=%s",
            consul_service_endpoint, health_string(sr, idx), escaped_key, idx + 1, escaped_note);
    curl_free(escaped_note);
  } else {
    snprintf(url, sizeof(url), "%s/v1/agent/check/%s/service:%s:%d",
            consul_service_endpoint, health_string(sr, idx), escaped_key, idx + 1);
  }
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, sr->period[idx] * 1000);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 100);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  mtev_curl_handle_debug(ch, debug_curl_ls);
  curl_free(escaped_key);

  ck_spinlock_unlock(&sr->lock);

  mtevL(debug_ls, "health -> %s\n", url);
  mtev_curl_perform(ch);

  struct timeval next = *now;
  next.tv_sec += sr->period[idx];
  eventer_update_whence(e, next);
  return EVENTER_TIMER;
}
static void mtev_consul_complete_service_registration(service_register *sr) {
  if(sr->desired_state == sr->state) return;
  char url[1024];
  switch(sr->desired_state) {
    case CS_REGISTERED:
      snprintf(url, sizeof(url), "%s/v1/agent/service/register", consul_service_endpoint);
      if(curl_put_json(url, sr->consul_object) == 0) {
        sr->state = CS_REGISTERED;
        for(int i=0; i<MAX_CHECKS; i++) {
          if(sr->period[i]) {
            eventer_add_in_s_us(mtev_consul_push_health, health_crutch(sr, i), 0, 0);
          }
        }
      }
      break;
    case CS_DEREGISTERED:
      snprintf(url, sizeof(url), "%s/v1/agent/service/deregister/%s", consul_service_endpoint, sr->service_id);
      if(curl_put_json(url, NULL) == 0) {
        sr->state = CS_DEREGISTERED;
        for(int i=0; i<MAX_CHECKS; i++) {
          if(sr->period[i]) {
            eventer_add_in_s_us(mtev_consul_push_health, health_crutch(sr, i), 0, 0);
          }
        }
      }
      break;
    case CS_UNINIT:
      abort();
      break;
  }
  mtevL(mtev_notice, "consul: service [%s] service %s\n", sr->service_id, cs_state_name(sr->state));
}

static int mtev_consul_complete_service_registration_ef(eventer_t e, int mask, void *vsr, struct timeval *now) {
  (void)e;
  (void)now;
  service_register *sr = (service_register *)vsr;
  if(mask == EVENTER_ASYNCH_WORK) mtev_consul_complete_service_registration(sr);
  return 0;
}

static int
mtev_consul_config(mtev_dso_generic_t *self, mtev_hash_table *options) {
  (void)self;
  (void)options;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    if(!strcmp(iter.key.str, "boot_state")) {
      if(!strcmp(iter.value.str, "passing")) default_service_code = PASSING_CODE;
      else if(!strcmp(iter.value.str, "warning")) default_service_code = WARNING_CODE;
      else if(!strcmp(iter.value.str, "critical")) default_service_code = CRITICAL_CODE;
      else {
        mtevL(mtev_error, "consul boot_state invalid: %s\n", iter.value.str);
        return -1;
      }
    }
    else if(!strcmp(iter.key.str, "kv_prefix")) {
      free(consul_kv_prefix);
      consul_kv_prefix = strdup(iter.value.str);
    }
    else if(!strcmp(iter.key.str, "bearer_token")) {
      if(consul_bearer_token == NULL) consul_bearer_token = strdup(iter.value.str);
    }
  }
  return 0;
}

static mtev_hash_table *
populate_dict_from_conf(mtev_conf_section_t s, const char *name) {
  mtev_boolean on = mtev_false;
  char xpath[32];
  mtev_hash_table *h = mtev_conf_get_hash(s, name);
  snprintf(xpath, sizeof(xpath), "%s/@version", name);
  if(mtev_conf_get_boolean(s, xpath, &on) && on) {
    char ver[64], vbuff[128];
    snprintf(ver, sizeof(ver), "mtev_version");
    mtev_build_version(vbuff, sizeof(vbuff));
    mtev_hash_dict_replace(h, ver, vbuff);
    snprintf(ver, sizeof(ver), "%s_version", mtev_get_app_name());
    mtev_hash_dict_replace(h, ver, mtev_get_app_version());
  }
  snprintf(xpath, sizeof(xpath), "%s/@features", name);
  if(mtev_conf_get_boolean(s, xpath, &on) && on) {
    mtev_hash_merge_as_dict(h, mtev_capabilities_get_features());
  }
  return h;
}

static void mtev_consul_interp(char *id_str, size_t id_str_len, const char *id) {
  for(const char *cp=id; *cp; ) {
    if(!strncmp(cp, "{app}", 5)) {
      strlcat(id_str, mtev_get_app_name(), id_str_len);
      cp += 5;
    }
    else if(!strncmp(cp, "{node}", 6)) {
      struct utsname utsn;
      if(uname(&utsn) < 0) {
        strlcat(id_str, "unknown", id_str_len);
      } else {
        strlcat(id_str, utsn.nodename, id_str_len);
      }
      cp += 6;
    }
    else {
      char chrstr[2] = { *cp, '\0' };
      strlcat(id_str, chrstr, id_str_len);
      cp++;
    }
  }
}

service_register *mtev_consul_service_registry_f(const char *tmpl) {
  char id_str[128];
  id_str[0] = '\0';
  mtev_consul_interp(id_str, sizeof(id_str), tmpl);
  void *vsr = NULL;
  if(mtev_hash_retrieve(&service_registry, id_str, strlen(id_str), &vsr)) {
    if(vsr) {
      service_register_ref((service_register *)vsr);
    }
    return (service_register *)vsr;
  }
  return NULL;
}

void mtev_consul_service_register_register_f(service_register *r) {
  r->desired_state = CS_REGISTERED;
}

void mtev_consul_service_register_deregister_f(service_register *r) {
  r->desired_state = CS_DEREGISTERED;
}

mtev_consul_service *
mtev_consul_service_alloc_f(const char *name, const char *id,
                            const char *address, unsigned short port,
                            mtev_hash_table *tags, bool tags_owned,
                            mtev_hash_table *meta, bool meta_owned) {
  char id_str[256];
  id_str[0] = '\0';
  mtev_consul_interp(id_str, sizeof(id_str), id);

  mtev_consul_service *cs = calloc(1, sizeof(*cs));
  
  cs->name = strdup(name);
  cs->id = strdup(id_str);
  cs->address = strdup(address);
  cs->port = port;
  cs->weights.passing = 10;
  cs->weights.warning = 1;
  cs->tags = tags;
  cs->tags_owned = tags_owned;
  cs->meta = meta;
  cs->meta_owned = meta_owned;
  return cs;
}
void mtev_consul_service_check_none_f(mtev_consul_service *cs) {
  for(int i=0; i<MAX_CHECKS; i++) {
    free(cs->check[i].name);
    switch(cs->check[i].type) {
      case CHECK_PUSH:
        free(cs->check[i].push.ttl);
        break;
      case CHECK_TCP:
        free(cs->check[i].tcp.tcp);
        free(cs->check[i].tcp.interval);
        free(cs->check[i].tcp.timeout);
        break;
      case CHECK_HTTP:
        free(cs->check[i].http.url);
        free(cs->check[i].http.method);
        free(cs->check[i].http.interval);
        free(cs->check[i].http.timeout);
        break;
      case CHECK_HTTPS:
        free(cs->check[i].https.url);
        free(cs->check[i].https.method);
        free(cs->check[i].https.tlsservername);
        free(cs->check[i].https.interval);
        free(cs->check[i].https.timeout);
        break;
      default:
        break;
    }
    free(cs->check[i].deregistercriticalserviceafter);
  }
  memset(&cs->check, 0, sizeof(cs->check));
}
void mtev_consul_service_free_f(mtev_consul_service *cs) {
  free(cs->name);
  free(cs->id);
  free(cs->address);
  mtev_consul_service_check_none_f(cs);
  if(cs->tags_owned && cs->tags) {
    mtev_hash_destroy(cs->tags, free, free);
    free(cs->tags);
  }
  if(cs->meta_owned && cs->meta) {
    mtev_hash_destroy(cs->meta, free, free);
    free(cs->meta);
  }
  free(cs);
}
char *mtev_consul_service_id_f(mtev_consul_service *cs) {
  return strdup(cs->id);
}
void mtev_consul_service_set_address_f(mtev_consul_service *cs, const char *address) {
  free(cs->address);
  cs->address = strdup(address);
}
void mtev_consul_service_set_port_f(mtev_consul_service *cs, unsigned short port) {
  cs->port = port;
}
static int get_next_check(mtev_consul_service *cs) {
  for(int i=0; i<MAX_CHECKS; i++) {
    if(cs->check[i].type == CHECK_NONE) return i;
  }
  return -1;
}
int mtev_consul_service_check_push_f(mtev_consul_service *cs, const char *name, unsigned ttl, unsigned dac) {
  int i = get_next_check(cs);
  if(i < 0) return -1;
  cs->check[i].type = CHECK_PUSH;
  if(name) cs->check[i].name = strdup(name);
  mtevEvalAssert(-1 != asprintf(&cs->check[i].push.ttl, "%us", ttl));
  if(dac) mtevEvalAssert(-1 != asprintf(&cs->check[i].deregistercriticalserviceafter, "%us", dac));
  return i;
}
int mtev_consul_service_check_tcp_f(mtev_consul_service *cs, const char *name,
                                    const char *tcp,
                                    const unsigned interval, const unsigned *timeout, unsigned dac) {
  int i = get_next_check(cs);
  if(i < 0) return -1;
  cs->check[i].type = CHECK_TCP;
  if(name) cs->check[i].name = strdup(name);
  if(tcp) cs->check[i].tcp.tcp = strdup(tcp);
  else mtevEvalAssert(-1 != asprintf(&cs->check[i].tcp.tcp, "%s:%u", cs->address, cs->port));
  mtevEvalAssert(-1 != asprintf(&cs->check[i].tcp.interval, "%us", interval));
  if(timeout) mtevEvalAssert(-1 != asprintf(&cs->check[i].tcp.timeout, "%us", *timeout));
  if(dac) mtevEvalAssert(-1 != asprintf(&cs->check[i].deregistercriticalserviceafter, "%us", dac));
  return i;
}
int mtev_consul_service_check_http_f(mtev_consul_service *cs, const char *name,
                                     const char *url, const char *method,
                                     const unsigned interval, const unsigned *timeout, unsigned dac) {
  int i = get_next_check(cs);
  if(i < 0) return -1;
  cs->check[i].type = CHECK_HTTP;
  if(name) cs->check[i].name = strdup(name);
  if(url) cs->check[i].http.url = strdup(url);
  if(method) cs->check[i].http.method = strdup(method);
  mtevEvalAssert(-1 != asprintf(&cs->check[i].http.interval, "%us", interval));
  if(timeout) mtevEvalAssert(-1 != asprintf(&cs->check[i].http.timeout, "%us", *timeout));
  if(dac) mtevEvalAssert(-1 != asprintf(&cs->check[i].deregistercriticalserviceafter, "%us", dac));
  return i;
}
int mtev_consul_service_check_https_f(mtev_consul_service *cs, const char *name,
                                      const char *url, const char *method,
                                      const char *tlsservername, bool tlsskipverify,
                                      const unsigned interval, const unsigned *timeout, unsigned dac) {
  int i = get_next_check(cs);
  if(i < 0) return i;
  cs->check[i].type = CHECK_HTTPS;
  if(name) cs->check[i].name = strdup(name);
  if(url) cs->check[i].https.url = strdup(url);
  if(method) cs->check[i].https.method = strdup(method);
  if(tlsservername) cs->check[i].https.tlsservername = strdup(tlsservername);
  cs->check[i].https.tlsskipverify = tlsskipverify;
  mtevEvalAssert(-1 != asprintf(&cs->check[i].https.interval, "%us", interval));
  if(timeout) mtevEvalAssert(-1 != asprintf(&cs->check[i].https.timeout, "%us", *timeout));
  if(dac) mtevEvalAssert(-1 != asprintf(&cs->check[i].deregistercriticalserviceafter, "%us", dac));
  return i;
}
bool mtev_consul_register_f(mtev_consul_service *cs) {
  if(cs->id == NULL || cs->name == NULL) return false;

  void *vsr = NULL;
  service_register *sr;
  if(mtev_hash_retrieve(&service_registry, cs->id, strlen(cs->id), &vsr)) {
    sr = vsr;
  } else {
    sr = calloc(1, sizeof(*sr));
    ck_spinlock_init(&sr->lock);
    sr->service_id = strdup(cs->id);
    for(int i=0; i<MAX_CHECKS; i++) {
      sr->service_code[i] = default_service_code;
    }
  }

  char URL_tmpl[1024];
  char URL[1536];
  URL[0] = '\0';
  mtev_json_object *so = MJ_OBJ();
  MJ_KV(so, "ID", MJ_STR(cs->id));
  MJ_KV(so, "Name", MJ_STR(cs->name));
  MJ_KV(so, "Address", MJ_STR(cs->address));
  MJ_KV(so, "Port", MJ_INT(cs->port));
  MJ_KV(so, "EnableTagOverride", MJ_BOOL(cs->enabletagoverride));
  if(cs->check[0].type != CHECK_NONE) {
    mtev_json_object *checks = MJ_ARR();
    for(int i=0; i<MAX_CHECKS; i++) {
      if(cs->check[i].type != CHECK_NONE) {
        mtev_json_object *co = MJ_OBJ();
        if(cs->check[i].deregistercriticalserviceafter) {
          MJ_KV(co, "DeregisterCriticalServiceAfter", MJ_STR(cs->check[i].deregistercriticalserviceafter));
        }
        // prep our URL
        if(cs->check[i].type == CHECK_HTTP || cs->check[i].type == CHECK_HTTPS) {
          const char *url = (cs->check[i].type == CHECK_HTTP) ? cs->check[i].http.url : cs->check[i].https.url;
          if(!url || strlen(url) == 0) snprintf(URL_tmpl, sizeof(URL_tmpl), "/module/consul/health/%s?n=%d", cs->id, i+1);
          else strlcpy(URL_tmpl, url, sizeof(URL_tmpl));
          if(strncmp(URL_tmpl, "http:", 5) && strncmp(URL_tmpl, "https:", 6)) {
            /* they want us to fill in the schema://host:port part */
            snprintf(URL, sizeof(URL), "%s://%s:%u%s",
                     (cs->check[i].type == CHECK_HTTPS) ? "https" : "http", cs->address, cs->port, URL_tmpl);
          } else {
            strlcpy(URL, URL_tmpl, sizeof(URL));
          }
        }
        char checkid[300];
        snprintf(checkid, sizeof(checkid), "service:%s:%d", cs->id, i+1);
        MJ_KV(co, "CheckID", MJ_STR(checkid));
        if(cs->check[i].name) MJ_KV(co, "Name", MJ_STR(cs->check[i].name));
        switch(cs->check[i].type) {
          case CHECK_NONE: abort(); break;
          case CHECK_PUSH:
            if(cs->check[i].push.ttl) {
              uint64_t period;
              mtev_confstr_parse_duration(cs->check[i].push.ttl, &period, mtev_get_durations_s());
              period /= 3;
              sr->period[i] = MAX(period, 1);
              MJ_KV(co, "TTL", MJ_STR(cs->check[i].push.ttl));
            }
            break;
          case CHECK_TCP:
            MJ_KV(co, "TCP", MJ_STR(cs->check[i].tcp.tcp));
            MJ_KV(co, "Interval", MJ_STR(cs->check[i].tcp.interval));
            if(cs->check[i].tcp.timeout) MJ_KV(co, "Timeout", MJ_STR(cs->check[i].tcp.timeout));
            break;
          case CHECK_HTTP:
            MJ_KV(co, "HTTP", MJ_STR(URL));
            MJ_KV(co, "Interval", MJ_STR(cs->check[i].http.interval));
            if(cs->check[i].http.method) MJ_KV(co, "Method", MJ_STR(cs->check[i].http.method));
            if(cs->check[i].http.timeout) MJ_KV(co, "Timeout", MJ_STR(cs->check[i].http.timeout));
            break;
          case CHECK_HTTPS:
            MJ_KV(co, "HTTP", MJ_STR(URL));
            MJ_KV(co, "Interval", MJ_STR(cs->check[i].https.interval));
            if(cs->check[i].https.tlsservername) MJ_KV(co, "TLSServerName", MJ_STR(cs->check[i].https.tlsservername));
            if(cs->check[i].https.tlsskipverify) MJ_KV(co, "TLSSkipVerify", MJ_BOOL(true));
            if(cs->check[i].https.method) MJ_KV(co, "Method", MJ_STR(cs->check[i].https.method));
            if(cs->check[i].https.timeout) MJ_KV(co, "Timeout", MJ_STR(cs->check[i].https.timeout));
            break;
        }
        MJ_ADD(checks, co);
      }
    }
    MJ_KV(so, "Checks", checks);
  }
  mtev_json_object *wo = MJ_OBJ();
    MJ_KV(wo, "Passing", MJ_INT(cs->weights.passing));
    MJ_KV(wo, "Warning", MJ_INT(cs->weights.warning));
  MJ_KV(so, "Weights", wo);
  mtev_json_object *tagarr = MJ_ARR();
    mtev_hash_iter tag_iter = MTEV_HASH_ITER_ZERO;
    while(cs->tags && mtev_hash_adv(cs->tags, &tag_iter)) {
      char tagstr[256];
      if(tag_iter.value.str == NULL || 0 == strlen(tag_iter.value.str))
        snprintf(tagstr, sizeof(tagstr), "%s", tag_iter.key.str);
      else
        snprintf(tagstr, sizeof(tagstr), "%s:%s", tag_iter.key.str, tag_iter.value.str);
      MJ_ADD(tagarr, MJ_STR(tagstr));
    }
  MJ_KV(so, "Tags", tagarr);
  mtev_json_object *mo = MJ_OBJ();
    mtev_hash_iter meta_iter = MTEV_HASH_ITER_ZERO;
    while(cs->meta && mtev_hash_adv(cs->meta, &meta_iter)) {
      MJ_KV(mo, meta_iter.key.str, MJ_STR(meta_iter.value.str));
    }
  MJ_KV(so, "Meta", mo);

  ck_spinlock_lock(&sr->lock);
  if(sr->consul_object) MJ_DROP(sr->consul_object);
  sr->consul_object = so;
  sr->desired_state = CS_REGISTERED;
  sr->state = CS_UNINIT;
  ck_spinlock_unlock(&sr->lock);
  if(vsr == NULL) {
    mtev_hash_replace(&service_registry, strdup(cs->id), strlen(cs->id), sr,
                      free, service_register_deref);
    mtevL(mtev_notice, "consul: registering [%s] service %s on port %s:%u\n",
          cs->id, cs->name, cs->address, cs->port);
  } else {
    mtevL(mtev_notice, "consul: re-registering [%s] service %s on port %s:%u\n",
          cs->id, cs->name, cs->address, cs->port);
  }
  mtev_consul_sync_services();
  return true;
}

static void
mtev_consul_configure(void) {
  int cnt;
  mtev_conf_section_t *cservices = mtev_conf_get_sections_read(MTEV_CONF_ROOT, "//consul//service", &cnt);
  mtevL(mtev_debug, "Found %d consul service sections\n", cnt);
  for(int i=0; i<cnt; i++) {
    int scnt;
    mtev_conf_section_t *services = mtev_conf_get_sections_read(cservices[i], "*[@port]", &scnt);
    mtevL(mtev_debug, "Found %d consul service configs in section %d\n", scnt, i+1);
    for(int si=0; si<scnt; si++) {
      mtev_conf_section_t *service = &services[si];

      const char *service_name = (const char *)mtev_conf_section_to_xmlnodeptr(*service)->name;

      const char *id = "{app}-{node}";
      char id_override[256];
      if(mtev_conf_get_stringbuf(*service, "@id", id_override, sizeof(id_override))) id = id_override;
      char id_str[256];
      id_str[0] = '\0';
      mtev_consul_interp(id_str, sizeof(id_str), id);

      int port = 0;
      if(!mtev_conf_get_int32(*service, "@port", &port) || port < 1 || port > 65535) {
        mtevL(error_ls, "Invalid port for consul service '%s' registration: %d\n",
              service_name, port);
      }
      char address[256];
      address[0] = '\0';
      if(!mtev_conf_get_stringbuf(*service, "@address", address, sizeof(address))) {
        struct in_addr remote, local;
        remote.s_addr = 0x08080808;
        if(0 != mtev_getip_ipv4(remote, &local) ||
           NULL == inet_ntop(AF_INET, &local, address, sizeof(address))) {
          strlcat(address, "127.0.0.1", sizeof(address));
        }
      }

      /* check */
      mtev_conf_section_t check = mtev_conf_get_section_read(*service, "check");
#define CHECK_DECL(name, len, def) \
  char name[len] = def; \
  bool has_ ## name = false; \
  (void)has_ ## name
#define CHECK_GET(name) do { \
  char tmpbuf[sizeof(name)]; \
  if(mtev_conf_get_stringbuf(check, "@" #name, tmpbuf, sizeof(tmpbuf))) { \
    has_ ## name = true; \
    if(strlen(tmpbuf) > 0) { \
      strlcpy(name, tmpbuf, sizeof(name)); \
    } \
  } \
} while(0)
      uint64_t period = 0;
      CHECK_DECL(DeregisterCriticalServiceAfter, 32, "30m");
      CHECK_DECL(Interval, 32, "5s");
      CHECK_DECL(HTTP, 410, "");
      snprintf(HTTP, sizeof(HTTP), "/module/consul/health/%s?n=1", id_str);
      CHECK_DECL(HTTPS, 410, "");
      snprintf(HTTPS, sizeof(HTTPS), "/module/consul/health/%s?n=1", id_str);
      CHECK_DECL(Method, 10, "GET");
      CHECK_DECL(TCP, 128, "");
      CHECK_DECL(PUSH, 10, "5s");
      CHECK_DECL(Timeout, 10, "5s");

      if(!mtev_conf_section_is_empty(check)) {
        CHECK_GET(DeregisterCriticalServiceAfter);
        CHECK_GET(Interval);
        CHECK_GET(HTTPS);
        CHECK_GET(HTTP);
        CHECK_GET(Method);
        CHECK_GET(TCP);
        CHECK_GET(PUSH);
        CHECK_GET(Timeout);
        if(has_PUSH) {
          (void)mtev_confstr_parse_duration(PUSH, &period, mtev_get_durations_s());
        }
        snprintf(PUSH, sizeof(PUSH), "%zus", period * 3);
      }
      mtev_conf_release_section_read(check);

      char HTTP_tmpl[128];
      if(has_HTTPS) strlcpy(HTTP_tmpl, HTTPS, sizeof(HTTP_tmpl));
      else strlcpy(HTTP_tmpl, HTTP, sizeof(HTTP_tmpl));
      if(strncmp(HTTP_tmpl, "http:", 5) && strncmp(HTTP_tmpl, "https:", 6)) {
        /* they want us to fill in the schema://host:port part */
        snprintf(HTTP, sizeof(HTTP), "%s://%s:%d%s", has_HTTPS ? "https" : "http", address, port, HTTP_tmpl);
      } else {
        strlcat(HTTP, HTTP_tmpl, sizeof(HTTP));
      }

      /* weights */
      int weights_passing = 10;
      int weights_warning = 1;
      (void)mtev_conf_get_int32(*service, "weights/@passing", &weights_passing);
      (void)mtev_conf_get_int32(*service, "weights/@warning", &weights_warning);

      /* tags */
      mtev_hash_table *tags = populate_dict_from_conf(*service, "tags");

      /* meta */
      mtev_hash_table *meta = populate_dict_from_conf(*service, "meta");

      mtev_json_object *so = MJ_OBJ();
      MJ_KV(so, "ID", MJ_STR(id_str));
      MJ_KV(so, "Name", MJ_STR(service_name));
      MJ_KV(so, "Address", MJ_STR(address));
      MJ_KV(so, "Port", MJ_INT(port));
      MJ_KV(so, "EnableTagOverride", MJ_BOOL(0));
      mtev_json_object *co = MJ_OBJ();
        MJ_KV(co, "DeregisterCriticalServiceAfter", MJ_STR(DeregisterCriticalServiceAfter));
        if(has_PUSH) {
          MJ_KV(co, "TTL", MJ_STR(PUSH));
        }
        else if(has_TCP) {
          MJ_KV(co, "TCP", MJ_STR(TCP));
          MJ_KV(co, "Interval", MJ_STR(Interval));
          if(has_Timeout) MJ_KV(co, "Timeout", MJ_STR(Timeout));
        }
        else {
          MJ_KV(co, "HTTP", MJ_STR(HTTP));
          MJ_KV(co, "Interval", MJ_STR(Interval));
          if(has_Method) MJ_KV(co, "Method", MJ_STR(Method));
          if(has_Timeout) MJ_KV(co, "Timeout", MJ_STR(Timeout));
        }
        char checkid[300];
        snprintf(checkid, sizeof(checkid), "service:%s:1", id_str);
        MJ_KV(co, "CheckID", MJ_STR(checkid));
      MJ_KV(so, "Check", co);
      mtev_json_object *wo = MJ_OBJ();
        MJ_KV(wo, "Passing", MJ_INT(weights_passing));
        MJ_KV(wo, "Warning", MJ_INT(weights_warning));
      MJ_KV(so, "Weights", wo);
      mtev_json_object *tagarr = MJ_ARR();
        mtev_hash_iter tag_iter = MTEV_HASH_ITER_ZERO;
        while(mtev_hash_adv(tags, &tag_iter)) {
          char tagstr[256];
          snprintf(tagstr, sizeof(tagstr), "%s:%s", tag_iter.key.str, tag_iter.value.str);
          MJ_ADD(tagarr, MJ_STR(tagstr));
        }
      MJ_KV(so, "Tags", tagarr);
      mtev_json_object *mo = MJ_OBJ();
        mtev_hash_iter meta_iter = MTEV_HASH_ITER_ZERO;
        while(mtev_hash_adv(meta, &meta_iter)) {
          MJ_KV(mo, meta_iter.key.str, MJ_STR(meta_iter.value.str));
        }
      MJ_KV(so, "Meta", mo);
      mtev_hash_destroy(tags, free, free);
      free(tags);
      mtev_hash_destroy(meta, free, free);
      free(meta);

      service_register *sr = calloc(1, sizeof(*sr));
      ck_spinlock_init(&sr->lock);
      sr->consul_object = so;
      sr->period[0] = period;
      sr->service_id = strdup(id_str);
      for(int i=0; i<MAX_CHECKS; i++) {
        sr->service_code[i] = default_service_code;
      }
      sr->desired_state = CS_REGISTERED;
      sr->state = CS_UNINIT;
      mtev_hash_replace(&service_registry, strdup(id_str), strlen(id_str), sr,
                        free, service_register_deref);
      mtevL(mtev_notice, "consul: registering [%s] service %s on port %s:%d\n",
            id_str, service_name, address, port);
      mtev_consul_sync_services();
    }
    mtev_conf_release_sections_read(services, scnt);
  }
  mtev_conf_release_sections_read(cservices, cnt);
}

static void
mtev_consul_sync_services(void) {
  if(mtev_hash_size(&service_registry) > 0) {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    while(mtev_hash_adv(&service_registry, &iter)) {
      service_register *sr = (service_register *)iter.value.ptr;
      ck_spinlock_lock(&sr->lock);
      if(sr->state != sr->desired_state) {
        eventer_add_asynch(consul_jobq, eventer_alloc_asynch(mtev_consul_complete_service_registration_ef, sr));
      }
      ck_spinlock_unlock(&sr->lock);
    }
  }
}
static void consul_sync(void) {
  while(1) {
    mtev_consul_sync_services();
    eventer_aco_sleep(&(struct timeval){ 1UL, 0UL });
  }
}
static mtev_hook_return_t
mtev_consul_post_init(void *vcl) {
  (void)vcl;
  consul_jobq = eventer_jobq_retrieve("consul");
  if(!consul_jobq) {
    consul_jobq = eventer_jobq_create("consul");
    eventer_jobq_set_min_max(consul_jobq, 1, 1);
    eventer_jobq_set_floor(consul_jobq, 0);
    eventer_jobq_set_concurrency(consul_jobq, 1);
  }
  mtev_consul_configure();
  mtev_consul_sync_services();

  eventer_aco_start(consul_sync, NULL);
  return MTEV_HOOK_CONTINUE;
}

static int
mtev_consul_health_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  service_code_e code = default_service_code;
  if(npats > 0) {
    void *vsr = NULL;
    code = CRITICAL_CODE;
    if(mtev_hash_retrieve(&service_registry, pats[0], strlen(pats[0]), &vsr)) {
      mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
      service_register *sr = (service_register *)vsr;
      const char *n = mtev_http_request_querystring(req, "n");
      if(n) {
        int idx = atoi(n) - 1;
        if(idx >= 0 && idx < MAX_CHECKS) {
          code = sr->service_code[idx];
        }
      }
    }
  }
  mtev_http_response_standard(restc->http_ctx, code, "HEALTH", "text/plain");
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

static mtev_hook_return_t
mtev_consul_conf_fixup(void *closure, mtev_conf_section_t section, const char *xpath,
                       const char *nodepath, int set, char **value) {
  (void)closure;
  (void)section;
  (void)xpath;
  (void)nodepath;
  char *tofree = NULL;
  if(set && *value && !strncmp(*value, "consul:", 7)) {
    char *fallback = *value + 7;
    tofree = *value;
    char *key = strrchr(fallback, ':');
    if(key) *key++ = '\0';
    else {
      key = fallback;
      fallback = NULL;
    }
    uint32_t index;

    *value = mtev_consul_fetch_config_kv(key, &index);
    if(*value == NULL && fallback != NULL) *value = strdup(fallback);

    xmlFree(tofree);
    mtevL(debug_ls, "lookup [%s] %s -> %s @%u\n", nodepath, key, *value, index);

    return *value ? MTEV_HOOK_DONE : MTEV_HOOK_ABORT;
  }
  return MTEV_HOOK_CONTINUE;
}

static int
mtev_consul_init(mtev_dso_generic_t *self) {
  (void)self;
  error_ls = mtev_log_stream_find("error/consul");
  debug_ls = mtev_log_stream_find("debug/consul");
  debug_curl_ls = mtev_log_stream_find("debug/consul/curl");
  mtev_hash_init(&service_registry);

  mtev_rest_mountpoint_t *rule = mtev_http_rest_new_rule(
    "GET", "/module/consul/", "^health(?:/(.+))?$", mtev_consul_health_handler
  );
  mtev_rest_mountpoint_set_auth(rule, mtev_http_rest_client_cert_auth);
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  eventer_started_hook_register("consul", mtev_consul_post_init, NULL);
  mtev_conf_value_fixup_hook_register("consul", mtev_consul_conf_fixup, NULL);
  return 0;
}

static int
mtev_consul_onload(mtev_image_t *self) {
  (void)self;
  consul_bearer_token = getenv("CONSUL_BEARER_TOKEN");
  /* null is fine */
  return 0;
}

#include "consul.xmlh"

mtev_dso_generic_t consul = {
  {
    MTEV_GENERIC_MAGIC,
    MTEV_GENERIC_ABI_VERSION,
    "consul",
    "consul integration",
    consul_xml_description,
    mtev_consul_onload,
    0
  },
  mtev_consul_config,
  mtev_consul_init
};
