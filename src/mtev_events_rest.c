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
#include "eventer/eventer_impl_private.h"
#include "mtev_json.h"
#include <errno.h>
#include <arpa/inet.h>

static void
json_spit_event(eventer_t e, void *closure) {
  mtev_json_object *doc = closure;
  mtev_json_object *eo, *ao = NULL;
  const char *cbname;
  eventer_pool_t *epool = NULL;
  char ip[INET6_ADDRSTRLEN];
  union {
    struct sockaddr a;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
  } addr;
  socklen_t addrlen;
  eo = MJ_OBJ();
 
  epool = eventer_get_pool_for_event(e); 
  cbname = eventer_name_for_callback_e(e->callback, e);
  if(!cbname) cbname = "unknown";
  MJ_KV(eo, "callback", MJ_STR(cbname));
  if(e->mask & (EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION)) {
    MJ_KV(eo, "fd", MJ_INT(e->fd));
    ip[0] = '\0';
    addrlen = sizeof(addr);
    if(getsockname(e->fd, &addr.a, &addrlen) == 0) {
      switch(addr.a.sa_family) {
        case AF_INET:
          if(inet_ntop(AF_INET, &addr.ip4.sin_addr, ip, sizeof(ip))) {
            ao = MJ_OBJ();
            MJ_KV(ao, "address", MJ_STR(ip));
            MJ_KV(ao, "port", MJ_INT(ntohs(addr.ip4.sin_port)));
          }
          break;
        case AF_INET6:
          if(inet_ntop(AF_INET, &addr.ip6.sin6_addr, ip, sizeof(ip))) {
            ao = MJ_OBJ();
            MJ_KV(ao, "address", MJ_STR(ip));
            MJ_KV(ao, "port", MJ_INT(ntohs(addr.ip6.sin6_port)));
          }
          break;
        default: break;
      }
      if(ao) MJ_KV(eo, "local", ao);
    }
    ao = NULL;
    ip[0] = '\0';
    addrlen = sizeof(addr);
    if(getpeername(e->fd, &addr.a, &addrlen) == 0) {
      switch(addr.a.sa_family) {
        case AF_INET:
          if(inet_ntop(AF_INET, &addr.ip4.sin_addr, ip, sizeof(ip))) {
            ao = MJ_OBJ();
            MJ_KV(ao, "address", MJ_STR(ip));
            MJ_KV(ao, "port", MJ_INT(ntohs(addr.ip4.sin_port)));
          }
          break;
        case AF_INET6:
          if(inet_ntop(AF_INET, &addr.ip6.sin6_addr, ip, sizeof(ip))) {
            ao = MJ_OBJ();
            MJ_KV(ao, "address", MJ_STR(ip));
            MJ_KV(ao, "port", MJ_INT(ntohs(addr.ip6.sin6_port)));
          }
          break;
        default:
          break;
      }
      if(ao) MJ_KV(eo, "remote", ao);
    }
    MJ_KV(eo, "impl", MJ_STR(e->opset->name));
    MJ_KV(eo, "mask", MJ_INT(e->mask));
  }
  else if(e->mask & EVENTER_TIMER) {
    uint64_t ms = e->whence.tv_sec;
    ms *= 1000ULL;
    ms += e->whence.tv_usec/1000;
    MJ_KV(eo, "whence", MJ_UINT64(ms));
  }
  if(epool) {
    MJ_KV(eo, "eventer_pool", MJ_STR(eventer_pool_name(epool)));
  }

  MJ_ADD(doc, eo);
}
static void
json_spit_jobq(eventer_jobq_t *jobq, void *closure) {
  mtev_json_object *doc = closure, *jo;

  MJ_KV(doc, jobq->queue_name, jo = MJ_OBJ());
  MJ_KV(jo, "concurrency", MJ_INT(jobq->concurrency));
  MJ_KV(jo, "desired_concurrency", MJ_INT(jobq->desired_concurrency));
  MJ_KV(jo, "total_jobs", MJ_INT64(jobq->total_jobs));
  MJ_KV(jo, "backlog", MJ_INT(jobq->backlog));
  MJ_KV(jo, "inflight", MJ_INT(jobq->inflight));
  MJ_KV(jo, "timeouts", MJ_INT64(jobq->timeouts));
  MJ_KV(jo, "avg_wait_ms", MJ_DOUBLE((double)jobq->avg_wait_ns/1000000.0));
  MJ_KV(jo, "avg_run_ms", MJ_DOUBLE((double)jobq->avg_run_ns/1000000.0));
}

static int
mtev_rest_eventer_timers(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_json_object *doc = MJ_ARR();
  eventer_foreach_timedevent(json_spit_event, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_memory(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_json_object *doc = MJ_OBJ(), *eobj;

  MJ_KV(doc, "eventer_t", eobj = MJ_OBJ());
  MJ_KV(eobj, "current", MJ_INT64(eventer_allocations_current()));
  MJ_KV(eobj, "total", MJ_INT64(eventer_allocations_total()));

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_sockets(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_json_object *doc = MJ_ARR();

  eventer_foreach_fdevent(json_spit_event, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}
static int
mtev_rest_eventer_jobq(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_json_object *doc = MJ_OBJ();

  eventer_jobq_process_each(json_spit_jobq, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

static int
json_spit_log(uint64_t idx, const struct timeval *whence,
              const char *log, size_t len, void *closure) {
  mtev_json_object *doc = closure, *o;
  uint64_t ms;

  ms = whence->tv_sec;
  ms *= 1000ULL;
  ms += whence->tv_usec/1000;

  MJ_ADD(doc, o = MJ_OBJ());
  MJ_KV(o, "idx", MJ_UINT64(idx));
  MJ_KV(o, "whence", MJ_UINT64(ms));
  MJ_KV(o, "line", MJ_STRN(log, len));
  return 0;
}

int
mtev_rest_eventer_logs(mtev_http_rest_closure_t *restc, int n, char **p) {
  char *endptr = NULL;
  const char *since_s, *last_s;
  char errbuf[128];
  unsigned long long since = 0;
  int last = 0;
  mtev_json_object *doc;
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

  doc = MJ_ARR();
  if(endptr != since_s)
    mtev_log_memory_lines_since(ls, since, json_spit_log, doc);
  else
    mtev_log_memory_lines(ls, last, json_spit_log, doc);

  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(restc->http_ctx);
  return 0;
 not_found:
  doc = MJ_OBJ();
  snprintf(errbuf, sizeof(errbuf), "log '%s' not found", p[0]);
  MJ_KV(doc, "error", MJ_STR(errbuf));
  mtev_http_response_not_found(restc->http_ctx, "application/json");
  mtev_http_response_append_json(restc->http_ctx, doc);
  MJ_DROP(doc);
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
