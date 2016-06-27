/*
 * Copyright (c) 2013-2015, Circonus, Inc. All rights reserved.
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
#include "mtev_listener.h"
#include "mtev_http.h"
#include "mtev_rest.h"
#include "mtev_conf.h"
#include "eventer/eventer.h"
#include "mtev_json.h"
#include <errno.h>
#include <arpa/inet.h>

static void
json_spit_event(eventer_t e, void *closure) {
  struct json_object *doc = closure;
  struct json_object *eo, *ao = NULL;
  const char *cbname;
  char ip[INET6_ADDRSTRLEN];
  union {
    struct sockaddr a;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
  } addr;
  socklen_t addrlen;
  eo = json_object_new_object();
  
  cbname = eventer_name_for_callback_e(e->callback, e);
  if(!cbname) cbname = "unknown";
  json_object_object_add(eo, "callback", json_object_new_string(cbname));
  if(e->mask & (EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION)) {
    json_object_object_add(eo, "fd", json_object_new_int(e->fd));
    ip[0] = '\0';
    addrlen = sizeof(addr);
    if(getsockname(e->fd, &addr.a, &addrlen) == 0) {
      switch(addr.a.sa_family) {
        case AF_INET:
          if(inet_ntop(AF_INET, &addr.ip4.sin_addr, ip, sizeof(ip))) {
            ao = json_object_new_object();
            json_object_object_add(ao, "address", json_object_new_string(ip));
            json_object_object_add(ao, "port", json_object_new_int(ntohs(addr.ip4.sin_port)));
          }
          break;
        case AF_INET6:
          if(inet_ntop(AF_INET, &addr.ip6.sin6_addr, ip, sizeof(ip))) {
            ao = json_object_new_object();
            json_object_object_add(ao, "address", json_object_new_string(ip));
            json_object_object_add(ao, "port", json_object_new_int(ntohs(addr.ip6.sin6_port)));
          }
          break;
        default: break;
      }
      if(ao) json_object_object_add(eo, "local", ao);
    }
    ao = NULL;
    ip[0] = '\0';
    addrlen = sizeof(addr);
    if(getpeername(e->fd, &addr.a, &addrlen) == 0) {
      switch(addr.a.sa_family) {
        case AF_INET:
          if(inet_ntop(AF_INET, &addr.ip4.sin_addr, ip, sizeof(ip))) {
            ao = json_object_new_object();
            json_object_object_add(ao, "address", json_object_new_string(ip));
            json_object_object_add(ao, "port", json_object_new_int(ntohs(addr.ip4.sin_port)));
          }
          break;
        case AF_INET6:
          if(inet_ntop(AF_INET, &addr.ip6.sin6_addr, ip, sizeof(ip))) {
            ao = json_object_new_object();
            json_object_object_add(ao, "address", json_object_new_string(ip));
            json_object_object_add(ao, "port", json_object_new_int(ntohs(addr.ip6.sin6_port)));
          }
          break;
        default:
          break;
      }
      if(ao) json_object_object_add(eo, "remote", ao);
    }
    json_object_object_add(eo, "impl", json_object_new_string(e->opset->name));
    json_object_object_add(eo, "mask", json_object_new_int(e->mask));
  }
  else if(e->mask & EVENTER_TIMER) {
    struct json_object *wo;
    u_int64_t ms = e->whence.tv_sec;
    ms *= 1000ULL;
    ms += e->whence.tv_usec/1000;
    wo = json_object_new_int(ms);
    json_object_set_int_overflow(wo, json_overflow_uint64);
    json_object_set_uint64(wo, ms);
    json_object_object_add(eo, "whence", wo);
  }

  json_object_array_add(doc, eo);
}
static void
json_spit_jobq(eventer_jobq_t *jobq, void *closure) {
  struct json_object *doc = closure;
  struct json_object *jo = json_object_new_object();
  json_object_object_add(jo, "concurrency", json_object_new_int(jobq->concurrency));
  json_object_object_add(jo, "desired_concurrency", json_object_new_int(jobq->desired_concurrency));
  struct json_object *li = json_object_new_int(0);
  json_object_set_int_overflow(li, json_overflow_int64);
  json_object_set_int64(li, (long long int)jobq->total_jobs);
  json_object_object_add(jo, "total_jobs", li);
  json_object_object_add(jo, "backlog", json_object_new_int(jobq->backlog));
  json_object_object_add(jo, "inflight", json_object_new_int(jobq->inflight));
  li = json_object_new_int(0);
  json_object_set_int_overflow(li, json_overflow_int64);
  json_object_set_int64(li, (long long int)jobq->timeouts);
  json_object_object_add(jo, "timeouts", li);
  json_object_object_add(jo, "avg_wait_ms", json_object_new_double((double)jobq->avg_wait_ns/1000000.0));
  json_object_object_add(jo, "avg_run_ms", json_object_new_double((double)jobq->avg_run_ns/1000000.0));
  json_object_object_add(doc, jobq->queue_name, jo);
}

static int
mtev_rest_eventer_timers(mtev_http_rest_closure_t *restc, int n, char **p) {
  const char *jsonstr;
  struct json_object *doc;
  doc = json_object_new_array();
  eventer_foreach_timedevent(json_spit_event, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_memory(mtev_http_rest_closure_t *restc, int n, char **p) {
  const char *jsonstr;
  struct json_object *doc, *eobj;
  doc = json_object_new_object();
  eobj = json_object_new_object();
  json_object_object_add(doc, "eventer_t", eobj);
  json_object_object_add(eobj, "current",
    json_object_new_int((int)eventer_allocations_current()));
  json_object_object_add(eobj, "total",
    json_object_new_int((int)eventer_allocations_total()));

  mtev_http_response_ok(restc->http_ctx, "application/json");
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_sockets(mtev_http_rest_closure_t *restc, int n, char **p) {
  const char *jsonstr;
  struct json_object *doc;
  doc = json_object_new_array();
  eventer_foreach_fdevent(json_spit_event, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_jobq(mtev_http_rest_closure_t *restc, int n, char **p) {
  const char *jsonstr;
  struct json_object *doc;
  doc = json_object_new_object();
  eventer_jobq_process_each(json_spit_jobq, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

static int
json_spit_log(u_int64_t idx, const struct timeval *whence,
              const char *log, size_t len, void *closure) {
  struct json_object *doc = (struct json_object *)closure;
  struct json_object *o, *wo;
  u_int64_t ms;

  o = json_object_new_object();

  wo = json_object_new_int(idx);
  json_object_set_int_overflow(wo, json_overflow_uint64);
  json_object_set_uint64(wo, idx);
  json_object_object_add(o, "idx", wo);

  ms = whence->tv_sec;
  ms *= 1000ULL;
  ms += whence->tv_usec/1000;
  wo = json_object_new_int(ms);
  json_object_set_int_overflow(wo, json_overflow_uint64);
  json_object_set_uint64(wo, ms);
  json_object_object_add(o, "whence", wo);

  json_object_object_add(o, "line", json_object_new_string_len(log, len));

  json_object_array_add(doc, o);
  return 0;
}

int
mtev_rest_eventer_logs(mtev_http_rest_closure_t *restc, int n, char **p) {
  char *endptr = NULL;
  const char *since_s, *last_s;
  const char *jsonstr;
  char errbuf[128];
  unsigned long long since;
  int last = 0;
  struct json_object *doc;
  mtev_log_stream_t ls;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
  since_s = mtev_http_request_querystring(req, "since");
  if(since_s) since = strtoull(since_s, &endptr, 10);
  last_s = mtev_http_request_querystring(req, "last");
  if(last_s) last = atoi(last_s);

  mtevAssert(n==1);
  ls = mtev_log_stream_find(p[0]);
  if(!ls || strcmp(mtev_log_stream_get_type(ls),"memory"))
    goto not_found;

  doc = json_object_new_array();
  if(endptr != since_s)
    mtev_log_memory_lines_since(ls, since, json_spit_log, doc);
  else
    mtev_log_memory_lines(ls, last, json_spit_log, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
 not_found:
  doc = json_object_new_object();
  snprintf(errbuf, sizeof(errbuf), "log '%s' not found", p[0]);
  json_object_object_add(doc, "error", json_object_new_string(errbuf));
  jsonstr = json_object_to_json_string(doc);
  mtev_http_response_not_found(restc->http_ctx, "application/json");
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  json_object_put(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

void
mtev_events_rest_init() {
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/eventer/", "^memory\\.json$",
    mtev_rest_eventer_memory, mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/eventer/", "^sockets\\.json$",
    mtev_rest_eventer_sockets, mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/eventer/", "^timers\\.json$",
    mtev_rest_eventer_timers, mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/eventer/", "^jobq\\.json$",
    mtev_rest_eventer_jobq, mtev_http_rest_client_cert_auth
  ) == 0);
  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/eventer/", "^logs/(.+)\\.json$",
    mtev_rest_eventer_logs, mtev_http_rest_client_cert_auth
  ) == 0);
}
