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
#include "mtev_conf.h"
#include "mtev_version.h"
#include "mtev_confstr.h"
#include "mtev_dso.h"
#include "mtev_dyn_buffer.h"
#include "mtev_hash.h"
#include "mtev_rest.h"
#include "mtev_http.h"
#include "mtev_getip.h"
#include "mtev_capabilities_listener.h"
#include "mtev_zipkin_curl.h"

#include <sys/utsname.h>
#include <libxml/tree.h>
#include <curl/curl.h>

/* This module registers mtev apps with consul and provides KV config lookups. */

/*
        <consul>
          <service>
            <myservice id="{app}-{node}" port="12123">
              <check deregister_after="10m" interval="5s" HTTP="/url" (PUSH="5s" or TCP=":12123" />
              <weights passing="10" warning="1"/>
              <tags features="true">
                <foo/>
                <bar>baz</bar>
              </tags>
              <meta version="true">
                <key>value</key>
              </meta>
            </myservice>
          </service>
        </consul>
 */

static CURLM *global_curl_handle;
static eventer_t global_curl_timeout;
static mtev_hash_table service_registry;
static char *consul_bearer_token = NULL;
static char *consul_kv_prefix = NULL;
static char *consul_service_endpoint = "http://localhost:8500";
static int global_service_code = 204;
static mtev_log_stream_t debug_ls, debug_curl_ls, error_ls;
static void process_global_curlm(void);

static const char *health_string(void) {
  switch(global_service_code) {
    case 204: return "pass";
    case 429: return "warn";
    default: return "fail";
  }
}

static int
mtev_consul_curl_debug(CURL *handle, curl_infotype type, char *data, size_t size, void *vl) {
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
            (type == CURLINFO_DATA_IN || CURLINFO_SSL_DATA_IN) ? "IN" : "OUT", size);
      break;
    default:
      break;
  }
  return 0;
}

typedef struct {
  mtev_json_object *consul_object;
  int period;
  char *service_id;
  bool registered;
} service_register;

static void service_register_free(void *vsr) {
  service_register *sr = vsr;
  free(sr->service_id);
  if(sr->consul_object) MJ_DROP(sr->consul_object);
  free(sr);
}

void mtev_consul_set_passing(void) {
  global_service_code = 204;
}
void mtev_consul_set_warning(void) {
  global_service_code = 429;
}
void mtev_consul_set_critical(void) {
  global_service_code = 502;
}

static char *mtev_consul_fetch_config_kv(const char *key) {
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
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mtev_dyn_curl_write_callback);

  char *value = NULL;
  CURLcode code = mtev_zipkin_curl_easy_perform(curl);
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

static int mtev_consul_push_health(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  service_register *sr = (service_register *)closure;
  mtev_dyn_buffer_t *dyn = calloc(1, sizeof(*dyn));
  mtev_dyn_buffer_init(dyn);

  char header[256];
  CURL *handle = curl_easy_init();
  char url[1024];
  static struct curl_slist *slist = NULL;
  if(slist == NULL && consul_bearer_token) {
    snprintf(header, sizeof(header), "Authorization: Bearer %s", consul_bearer_token);
    slist = curl_slist_append(slist, header);
  }
  char *escaped_key = curl_easy_escape(handle, sr->service_id, 0); 
  snprintf(url, sizeof(url), "%s/v1/agent/check/%s/service:%s",
          consul_service_endpoint, health_string(), escaped_key);
  curl_easy_setopt(handle, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PUT");
  curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, sr->period * 1000);
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, 100);
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, mtev_dyn_curl_write_callback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, dyn);
  curl_easy_setopt(handle, CURLOPT_PRIVATE, dyn);
  curl_easy_setopt(handle, CURLOPT_URL, url);
  curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, mtev_consul_curl_debug);
  curl_easy_setopt(handle, CURLOPT_DEBUGDATA, debug_curl_ls);
  if(N_L_S_ON(debug_curl_ls)) {
    curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
  }
  curl_free(escaped_key);

  mtevL(debug_ls, "health -> %s\n", url);
  curl_multi_add_handle(global_curl_handle, handle);

  int running_handles;
  curl_multi_socket_action(global_curl_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);

  process_global_curlm();

  struct timeval next = *now;
  next.tv_sec += sr->period;
  eventer_update_whence(e, next);
  return EVENTER_TIMER;
}
static void *mtev_consul_complete_service_registration(void *unused) {
  (void)unused;
  bool failures = false;
  long sleep_time = 0;
  do {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    failures = false;
    if(sleep_time) usleep(sleep_time);
    while(mtev_hash_adv(&service_registry, &iter)) {
      service_register *sr = (service_register *)iter.value.ptr;
      if(sr->registered == false) {
        char url[1024];
        snprintf(url, sizeof(url), "%s/v1/agent/service/register", consul_service_endpoint);
        if(curl_put_json(url, sr->consul_object) == 0) {
          sr->registered = true;
          if(sr->period) {
            eventer_add_in_s_us(mtev_consul_push_health, sr, 0, 0);
          }
        } else {
          failures = true;
        }
      }
    }
    sleep_time += sleep_time + 10;
    if(sleep_time > 4000000) sleep_time = 4000000;
  } while(failures);
  mtevL(mtev_notice, "consul: service registration complete\n");
  return NULL;
}

static int
mtev_consul_config(mtev_dso_generic_t *self, mtev_hash_table *options) {
  (void)self;
  (void)options;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(options, &iter)) {
    if(!strcmp(iter.key.str, "boot_state")) {
      if(!strcmp(iter.value.str, "passing")) mtev_consul_set_passing();
      else if(!strcmp(iter.value.str, "warning")) mtev_consul_set_warning();
      else if(!strcmp(iter.value.str, "critical")) mtev_consul_set_critical();
      else {
        mtevL(mtev_error, "consul boot_state invalid: %s\n", iter.value.str);
        return -1;
      }
    }
    else if(!strcmp(iter.key.str, "kv_prefix")) {
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

static void
mtev_consul_configure(void) {
  int cnt;
  mtev_conf_section_t *cservices = mtev_conf_get_sections(MTEV_CONF_ROOT, "//consul//service", &cnt);
  mtevL(mtev_debug, "Found %d consul service sections\n", cnt);
  for(int i=0; i<cnt; i++) {
    int scnt;
    mtev_conf_section_t *services = mtev_conf_get_sections(cservices[i], "*[@port]", &scnt);
    mtevL(mtev_debug, "Found %d consul service configs in section %d\n", scnt, i+1);
    for(int si=0; si<scnt; si++) {
      mtev_conf_section_t *service = &services[si];

      const char *service_name = (const char *)mtev_conf_section_to_xmlnodeptr(*service)->name;

      const char *id = "{app}-{node}";
      char id_override[256];
      if(mtev_conf_get_stringbuf(*service, "@id", id_override, sizeof(id_override))) id = id_override;
      char id_str[256];
      id_str[0] = '\0';
      for(const char *cp=id; *cp; ) {
        if(!strncmp(cp, "{app}", 5)) {
          strlcat(id_str, mtev_get_app_name(), sizeof(id_str));
          cp += 5;
        }
        else if(!strncmp(cp, "{node}", 6)) {
          struct utsname utsn;
          if(uname(&utsn) < 0) {
            strlcat(id_str, "unknown", sizeof(id_str));
          } else {
            strlcat(id_str, utsn.nodename, sizeof(id_str));
          }
          cp += 6;
        }
        else {
          char chrstr[2] = { *cp, '\0' };
          strlcat(id_str, chrstr, sizeof(id_str));
          cp++;
        }
      }

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
      mtev_conf_section_t check = mtev_conf_get_section(*service, "check");
#define CHECK_DECL(name, len, def) \
  char name[len] = def; \
  bool has_ ## name = false; \
  (void)has_ ## name
#define CHECK_GET(name) do { \
  if(mtev_conf_get_stringbuf(check, "@" #name, name, sizeof(name))) has_ ## name = true; \
} while(0)
      uint64_t period = 0;
      CHECK_DECL(DeregisterCriticalServiceAfter, 32, "30m");
      CHECK_DECL(Interval, 32, "5s");
      CHECK_DECL(HTTP, 128, "/module/consul/health");
      CHECK_DECL(HTTPS, 128, "/module/consul/health");
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
      mtev_conf_release_section(check);

      char HTTP_tmpl[128];
      if(has_HTTPS) strlcpy(HTTP_tmpl, HTTPS, sizeof(HTTP_tmpl));
      else strlcpy(HTTP_tmpl, HTTP, sizeof(HTTP_tmpl));
      if(strncmp(HTTP_tmpl, "http:", 5) && strncmp(HTTP_tmpl, "https:", 6)) {
        /* they want use to fill in the schema://host:port part */
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
          MJ_KV(mo, tag_iter.key.str, MJ_STR(tag_iter.value.str));
        }
      MJ_KV(so, "Meta", mo);
      mtev_hash_destroy(tags, free, free);
      free(tags);
      mtev_hash_destroy(meta, free, free);
      free(meta);

      service_register *sr = calloc(1, sizeof(*sr));
      sr->consul_object = so;
      sr->period = period;
      sr->service_id = strdup(id_str);
      sr->registered = false;
      mtev_hash_replace(&service_registry, strdup(service_name), strlen(service_name), sr,
                        free, service_register_free);
      mtevL(mtev_notice, "consul: registering [%s] service %s on port %s:%d\n",
            id_str, service_name, address, port);
    }
    mtev_conf_release_sections(services, scnt);
  }
  mtev_conf_release_sections(cservices, cnt);
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
  mtev_dyn_buffer_t *dyn;
  while((message = curl_multi_info_read(global_curl_handle, &pending))) {
    switch(message->msg) {
    case CURLMSG_DONE:
      easy_handle = message->easy_handle;

      curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &done_url);
      if(message->data.result != CURLE_OK) {
        mtevL(error_ls, "%s -> %s\n", done_url, curl_easy_strerror(message->data.result));
      }
      long httpcode;
      curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, (char **)&dyn);
      curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &httpcode);
      if(httpcode == 200) {
        mtevL(debug_ls, "%s DONE\n", done_url);
      } else {
        mtevL(error_ls, "%s -> %d %.*s\n", done_url, (int)httpcode,
              (int)mtev_dyn_buffer_used(dyn), (const char *)mtev_dyn_buffer_data(dyn));
      }
 
      curl_multi_remove_handle(global_curl_handle, easy_handle);
      curl_easy_cleanup(easy_handle);
      if(dyn) {
        mtev_dyn_buffer_destroy(dyn);
        free(dyn);
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

  curl_multi_socket_action(global_curl_handle, c->s, flags, &running_handles);

  process_global_curlm();

  return c->e == NULL ? 0 : eventer_get_mask(e);
}
static int
eventer_curl_on_timeout(eventer_t e, int mask, void *c, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)c;
  (void)now;
  mtevL(debug_curl_ls, "curl_multi timeout\n");
  int running_handles;
  curl_multi_socket_action(global_curl_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
  global_curl_timeout = NULL;
  process_global_curlm();
  return 0;
}
static int
eventer_curl_start_timeout(CURLM *multi, long timeout_ms, void *userp) {
  (void)multi;
  (void)userp;
  mtevL(debug_curl_ls, "curl_multi start timeout %d\n", (int)timeout_ms);
  if(timeout_ms < 0) {
    if(global_curl_timeout) {
      eventer_remove(global_curl_timeout);
      global_curl_timeout = NULL;
    }
    else {
      if(timeout_ms == 0) timeout_ms = 1;
      global_curl_timeout = eventer_in_s_us(eventer_curl_on_timeout, NULL,
                                            timeout_ms / 1000, 1000 * (timeout_ms % 1000));
      eventer_add(global_curl_timeout);
    }
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
        curl_multi_assign(global_curl_handle, s, c);
      }
      if(action != CURL_POLL_IN) mask |= EVENTER_WRITE;
      if(action != CURL_POLL_OUT) mask |= EVENTER_READ;
      mtevL(debug_curl_ls, "curl wants %x\n", mask);
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
        curl_multi_assign(global_curl_handle, s, c);
      }
      if(c) {
        if(c->e) {
          eventer_t tofree = eventer_remove_fde(c->e);
          mtevL(debug_curl_ls, "curl removed %p as %p\n", c->e, tofree);
          c->e = NULL;
        }
        free(c);
        curl_multi_assign(global_curl_handle, s, NULL);
      } else {
        mtevL(debug_curl_ls, "curl removal with no socket ptr\n");
        close(s);
      }
      break;
    default:
      mtevAssert(0);
  }
  return 0;
}
static mtev_hook_return_t
mtev_consul_post_init(void *vcl) {
  (void)vcl;
  mtev_consul_configure();

  if(mtev_hash_size(&service_registry) > 0) {
    pthread_t tid;
    pthread_create(&tid, NULL, mtev_consul_complete_service_registration, NULL);
  }
  return MTEV_HOOK_CONTINUE;
}

static int
mtev_consul_health_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_response_standard(restc->http_ctx, global_service_code, "HEALTH", "text/plain");
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
    char *key = strchr(fallback, ':');
    if(key) *key++ = '\0';
    else {
      key = fallback;
      fallback = NULL;
    }

    *value = mtev_consul_fetch_config_kv(key);
    if(*value == NULL && fallback != NULL) *value = strdup(fallback);

    xmlFree(tofree);
    mtevL(debug_ls, "lookup [%s] %s -> %s\n", nodepath, key, *value);

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

  global_curl_handle = curl_multi_init();
  curl_multi_setopt(global_curl_handle, CURLMOPT_SOCKETFUNCTION, eventer_curl_handle_socket);
  curl_multi_setopt(global_curl_handle, CURLMOPT_TIMERFUNCTION, eventer_curl_start_timeout);

  mtev_rest_mountpoint_t *rule = mtev_http_rest_new_rule(
    "GET", "/module/consul/", "^health$", mtev_consul_health_handler
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
