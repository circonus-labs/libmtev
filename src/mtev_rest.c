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
#include "mtev_listener.h"
#include "mtev_http.h"
#include "mtev_rest.h"
#include "mtev_conf.h"
#include "mtev_json.h"

#include <pcre.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <dlfcn.h>

struct rest_xml_payload {
  char *buffer;
  xmlDocPtr indoc;
  size_t len;
  size_t allocd;
  int complete;
};

struct rest_raw_payload {
  char *buffer;
  size_t len;
  size_t allocd;
  int complete;
};

struct rest_url_dispatcher {
  char *nice_name;
  char *method;
  char *expression_s;
  char *websocket_protocol;
  pcre *expression;
  pcre_extra *extra;
  rest_request_handler handler;
  rest_websocket_message_handler websocket_handler;
  rest_authorize_func_t auth;
  void *closure;
  eventer_pool_t *pool;
  int pool_rr; /* used for round-robin */
  /* Chain to the next one */
  struct rest_url_dispatcher *next;
  stats_handle_t *latency;
  mtev_boolean aco_enabled;
};

static stats_ns_t *rest_stats;

void
mtev_rest_mountpoint_set_handler(mtev_rest_mountpoint_t *mountpoint,
                           rest_request_handler h) {
  mountpoint->handler = h;
}
void
mtev_rest_mountpoint_set_auth(mtev_rest_mountpoint_t *mountpoint,
                        rest_authorize_func_t h) {
  mountpoint->auth = h;
}
void
mtev_rest_mountpoint_set_closure(mtev_rest_mountpoint_t *mountpoint,
                           void *h) {
  mountpoint->closure = h;
}
void
mtev_rest_mountpoint_set_websocket(mtev_rest_mountpoint_t *mountpoint,
                             const char *prot,
                             rest_websocket_message_handler h) {
  free(mountpoint->websocket_protocol);
  mountpoint->websocket_protocol = (prot == NULL) ? NULL : strdup(prot);
  mountpoint->websocket_handler = h;
}
void
mtev_rest_mountpoint_set_eventer_pool(mtev_rest_mountpoint_t *mountpoint,
                                eventer_pool_t *pool) {
  mountpoint->pool = pool;
}

void
mtev_rest_mountpoint_set_aco(mtev_rest_mountpoint_t *mountpoint,
                             mtev_boolean enabled) {
  mountpoint->aco_enabled = enabled;
}



struct rule_container {
  char *base;
  struct rest_url_dispatcher *rules;
  struct rest_url_dispatcher *rules_endptr;
};
mtev_hash_table dispatch_points;

struct mtev_rest_acl_rule {
  mtev_boolean allow;
  pcre *url;
  pcre *cn;
  mtev_hash_table *listener_res;
  struct mtev_rest_acl_rule *next;
};
struct mtev_rest_acl {
  mtev_boolean allow;
  pcre *url;
  pcre *cn;
  mtev_hash_table *listener_res;
  struct mtev_rest_acl_rule *rules;
  struct mtev_rest_acl *next;
};

static mtev_hash_table mime_type_defaults;

static struct mtev_rest_acl *global_rest_acls = NULL;

static mtev_boolean
  match_listener_res(mtev_hash_table *res, mtev_hash_table *config);

static int
mtev_http_rest_permission_denied(mtev_http_rest_closure_t *restc,
                                 int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_standard(ctx, 403, "DENIED", "text/xml");
  mtev_http_response_end(ctx);
  return 0;
}
int
mtev_console_show_rest(mtev_console_closure_t ncct, int argc, char **argv,
                       mtev_console_state_t *dstate, void *unused) {
  (void)argc;
  (void)argv;
  (void)dstate;
  (void)unused;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(&dispatch_points, &iter)) {
    struct rule_container *cont = iter.value.ptr;
    struct rest_url_dispatcher *rule;
    for(rule = cont->rules; rule; rule = rule->next) {
      Dl_info info;
      nc_printf(ncct, "%s [%s] %s\n", rule->method, iter.key.str, rule->expression_s);
      if(rule->handler && dladdr(rule->handler, &info) && info.dli_sname) {
        nc_printf(ncct, "\tHANDLER: %s+%lx\n", info.dli_sname,
                  (unsigned long)((uintptr_t)rule->handler - (uintptr_t)info.dli_saddr));
      }
      else {
        nc_printf(ncct, "\tHANDLER: %p\n", rule->handler);
      }
      if(rule->auth && dladdr(rule->auth, &info) && info.dli_sname) {
        nc_printf(ncct, "\tAUTH: %s+%lx\n", info.dli_sname,
                  (unsigned long)((uintptr_t)rule->handler - (uintptr_t)info.dli_saddr));
      }
      else {
        nc_printf(ncct, "\tAUTH: %p\n", rule->auth);
      }
    }
  }
  return 0;
}
static int
mtev_http_rest_endpoints(mtev_http_rest_closure_t *restc,
                         int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  mtev_json_object *doc = MJ_OBJ();
  while(mtev_hash_adv(&dispatch_points, &iter)) {
    struct rule_container *cont = iter.value.ptr;
    struct rest_url_dispatcher *rule;
    mtev_json_object *arr, *jrule;
    MJ_KV(doc, iter.key.str, arr = MJ_ARR());
    for(rule = cont->rules; rule; rule = rule->next) {
      MJ_ADD(arr, jrule = MJ_OBJ());
      MJ_KV(jrule, "method", MJ_STR(rule->method));
      MJ_KV(jrule, "expression", MJ_STR(rule->expression_s));
    }
  }

  mtev_http_response_standard(ctx, 200, "OK", "application/json");
  mtev_http_response_append_json(ctx, doc);
  MJ_DROP(doc);
  mtev_http_response_end(ctx);
  return 0;
}

static struct rest_url_dispatcher *
mtev_http_find_matching_route_rule(mtev_http_rest_closure_t *restc)
{
  struct rule_container *cont = NULL;
  struct rest_url_dispatcher *rule;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
  mtev_hash_table *headers;
  const char *uri_str;
  const char *protocol = NULL;
  const char *eoq, *eob;
  uri_str = mtev_http_request_uri_str(req);
  eoq = uri_str + strlen(uri_str);
  eob = eoq - 1;

  /* find the right base */
  while(1) {
    void *vcont;
    while(eob >= uri_str && *eob != '/') eob--;
    if(eob < uri_str) break; /* off the front */
    if(mtev_hash_retrieve(&dispatch_points, uri_str,
                          eob - uri_str + 1, &vcont)) {
      cont = vcont;
      eob++; /* move past the determined base */
      break;
    }
    eob--;
  }

  /* no base, give up */
  if(!cont) return NULL;

  headers = mtev_http_request_headers_table(req);

  (void)mtev_hash_retr_str(headers, "sec-websocket-protocol", strlen("sec-websocket-protocol"), &protocol);

  for(rule = cont->rules; rule; rule = rule->next) {
    int ovector[30];
    int cnt;
    if (mtev_http_is_websocket(restc->http_ctx) == mtev_true) {
      if (strcmp(rule->method, "WS")) continue;
      if (rule->websocket_protocol == NULL || protocol == NULL || strcmp(rule->websocket_protocol, protocol)) continue;
    } else {
      if (strcmp(rule->method, mtev_http_request_method_str(req))) continue;
    }
    if((cnt = pcre_exec(rule->expression, rule->extra, eob, eoq - eob, 0, 0,
                        ovector, sizeof(ovector)/sizeof(*ovector))) > 0) {

      restc->nparams = cnt - 1;
      if(restc->nparams) {
        restc->params = calloc(restc->nparams, sizeof(*restc->params));
        for(cnt = 0; cnt < restc->nparams; cnt++) {
          int start = ovector[(cnt+1)*2];
          int end = ovector[(cnt+1)*2+1];
          restc->params[cnt] = malloc(end - start + 1);
          memcpy(restc->params[cnt], eob + start, end - start);
          restc->params[cnt][end - start] = '\0';
        }
      }
      return rule;
    }
  }
  return NULL;
}

static rest_websocket_message_handler
mtev_http_get_websocket_handler(mtev_http_rest_closure_t *restc) 
{
  struct rest_url_dispatcher *rule = mtev_http_find_matching_route_rule(restc);
  if (rule != NULL) {
      /* We match, set 'er up */
    mtev_zipkin_span_rename(mtev_http_zipkip_span(restc->http_ctx),
                            rule->nice_name ? rule->nice_name : rule->expression_s,
                            false);
    mtev_http_session_track_latency(restc->http_ctx, rule->latency);
    restc->websocket_handler_memo = rule->websocket_handler;
    restc->closure = rule->closure;
    if(rule->auth && !rule->auth(restc, restc->nparams, restc->params)) {
      restc->closure = NULL;
      /* TODO: fix authentication problems under websockets */
      return NULL;
    }
    return restc->websocket_handler_memo;
  }
  return NULL;
}

static rest_request_handler
mtev_http_get_handler(mtev_http_rest_closure_t *restc, mtev_boolean *migrate) {
  struct rest_url_dispatcher *rule = mtev_http_find_matching_route_rule(restc);
  if (rule != NULL) {
      /* We match, set 'er up */
    mtev_zipkin_span_rename(mtev_http_zipkip_span(restc->http_ctx),
                            rule->nice_name ? rule->nice_name : rule->expression_s,
                            false);
    mtev_http_session_track_latency(restc->http_ctx, rule->latency);
    restc->fastpath = rule->handler;
    restc->closure = rule->closure;
    restc->aco_enabled = rule->aco_enabled;
    if(rule->pool) {
      eventer_t e = mtev_http_connection_event(mtev_http_session_connection(restc->http_ctx));
      if(e) {
        eventer_set_owner(e, eventer_choose_owner_pool(rule->pool, rule->pool_rr++));
        *migrate = !pthread_equal(eventer_get_owner(e), pthread_self());
      }
    }
    if(rule->auth && !rule->auth(restc, restc->nparams, restc->params)) {
      restc->closure = NULL;
      return mtev_http_rest_permission_denied;
    }
    return restc->fastpath;
  }
  return NULL;
}
mtev_boolean
mtev_http_rest_client_cert_auth(mtev_http_rest_closure_t *restc,
                               int npats, char **pats) {
  (void)npats;
  (void)pats;
  struct mtev_rest_acl *acl;
  struct mtev_rest_acl_rule *rule;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
  const char *uri_str;
  const char *remote_cn = "";
  int ovector[30];
  mtev_hash_table *config = mtev_acceptor_closure_config(restc->ac);

  if(restc->remote_cn) remote_cn = restc->remote_cn;
  uri_str = mtev_http_request_uri_str(req);
  for(acl = global_rest_acls; acl; acl = acl->next) {
    if(acl->cn && pcre_exec(acl->cn, NULL, remote_cn, strlen(remote_cn), 0, 0,
                            ovector, sizeof(ovector)/sizeof(*ovector)) <= 0)
      continue;
    if(acl->url && pcre_exec(acl->url, NULL, uri_str, strlen(uri_str), 0, 0,
                             ovector, sizeof(ovector)/sizeof(*ovector)) <= 0)
      continue;
    if(!match_listener_res(acl->listener_res, config))
      continue;
    for(rule = acl->rules; rule; rule = rule->next) {
      if(rule->cn && pcre_exec(rule->cn, NULL, remote_cn, strlen(remote_cn), 0, 0,
                               ovector, sizeof(ovector)/sizeof(*ovector)) <= 0)
        continue;
      if(rule->url && pcre_exec(rule->url, NULL, uri_str, strlen(uri_str), 0, 0,
                                ovector, sizeof(ovector)/sizeof(*ovector)) <= 0)
        continue;
      if(!match_listener_res(rule->listener_res, config))
        continue;
      return rule->allow;
    }
    return acl->allow;
  }
  return mtev_false;
}

struct rest_url_dispatcher *
mtev_http_rest_new_rule(const char *method, const char *base,
                        const char *expr, rest_request_handler f) {
  return mtev_http_rest_new_rule_auth_closure(method, base, expr, f, NULL, NULL, NULL, NULL);
}

int
mtev_http_rest_register(const char *method, const char *base,
                        const char *expr, rest_request_handler f) {
  return mtev_http_rest_register_auth_closure(method, base, expr, f, NULL, NULL, NULL, NULL);
}
void
mtev_http_rest_disclose_endpoints(const char *base, const char *expr) {
  mtev_http_rest_register("GET", base, expr, mtev_http_rest_endpoints);
}
int
mtev_http_rest_register_closure(const char *method, const char *base,
                        const char *expr, rest_request_handler f, void *c) {
  return mtev_http_rest_register_auth_closure(method, base, expr, f, NULL, NULL, NULL, c);
}
int
mtev_http_rest_register_auth(const char *method, const char *base,
                             const char *expr, rest_request_handler f,
                             rest_authorize_func_t auth) {
  return mtev_http_rest_register_auth_closure(method, base, expr, f, NULL, NULL, auth, NULL);
}


int
mtev_http_rest_websocket_register(const char *base,
                                  const char *expr, 
                                  const char *protocol,
                                  rest_websocket_message_handler wf) 
{
  return mtev_http_rest_websocket_register_closure(base, expr, protocol, wf, NULL);
}

int
mtev_http_rest_websocket_register_closure(const char *base,
                                          const char *expr, 
                                          const char *protocol,
                                          rest_websocket_message_handler wf,
                                          void *c) 
{
  return mtev_http_rest_register_auth_closure("WS", base, expr, NULL, wf, protocol, NULL, c);
}
 
int
mtev_http_rest_websocket_register_auth(const char *base,
                                       const char *expr,
                                       const char *protocol,
                                       rest_websocket_message_handler wf,
                                       rest_authorize_func_t auth) 
{
  return mtev_http_rest_websocket_register_auth_closure(base, expr, protocol, wf, auth, NULL);
}

int
mtev_http_rest_websocket_register_auth_closure(const char *base,
                                               const char *expr,
                                               const char *protocol,
                                               rest_websocket_message_handler wf,
                                               rest_authorize_func_t auth,
                                               void *c) 
{
  int rval = mtev_http_rest_register_auth_closure("WS", base, expr, NULL, wf, protocol, NULL, c);
  if ( rval != 0 ) {
    return rval;
  }
  return mtev_http_rest_register_auth("GET", base, expr, NULL, auth);
}

int
mtev_http_rest_register_auth_closure(const char *method, const char *base,
                                     const char *expr, rest_request_handler f,
                                     rest_websocket_message_handler wf, 
                                     const char *websocket_protocol, 
                                     rest_authorize_func_t auth, void *closure) 
{
  struct rest_url_dispatcher *rule;
  rule = mtev_http_rest_new_rule_auth_closure(method, base, expr, f, wf, websocket_protocol, auth, closure);
  if(rule) return 0;
  return -1;
}

mtev_rest_mountpoint_t *
mtev_http_rest_new_rule_auth_closure(const char *method, const char *base,
                                     const char *expr, rest_request_handler f,
                                     rest_websocket_message_handler wf, 
                                     const char *websocket_protocol, 
                                     rest_authorize_func_t auth, void *closure) 
{
  void *vcont;
  struct rule_container *cont;
  struct rest_url_dispatcher *rule;
  const char *error;
  int erroffset;
  pcre *pcre_expr;
  int blen = strlen(base);
  /* base must end in a /, 'cause I said so */
  if(blen == 0 || base[blen-1] != '/') {
    mtevL(mtev_error, "rest rule base must end in /!\n");
    return NULL;
  }
  pcre_expr = pcre_compile(expr, 0, &error, &erroffset, NULL);
  if(!pcre_expr) {
    mtevL(mtev_error, "Error in rest expr(%s) '%s'@%d: %s\n",
          base, expr, erroffset, error);
    return NULL;
  }
  rule = calloc(1, sizeof(*rule));
  rule->method = strdup(method);
  rule->nice_name = malloc(strlen(base) + strlen(expr) + 3);
  sprintf(rule->nice_name, "%s(%s)", base, expr);
  rule->expression_s = strdup(expr);
  rule->expression = pcre_expr;
  rule->extra = pcre_study(rule->expression, 0, &error);
  rule->handler = f;
  rule->websocket_handler = wf;
  rule->websocket_protocol = websocket_protocol != NULL ? strdup(websocket_protocol) : NULL;
  rule->closure = closure;
  rule->auth = auth;
  rule->latency = stats_register(rest_stats, rule->nice_name, STATS_TYPE_HISTOGRAM);

  /* Make sure we have a container */
  if(!mtev_hash_retrieve(&dispatch_points, base, strlen(base), &vcont)) {
    cont = calloc(1, sizeof(*cont));
    cont->base = strdup(base);
    mtev_hash_store(&dispatch_points, cont->base, strlen(cont->base), cont);
  }
  else cont = vcont;

  /* Append the rule */
  if(cont->rules_endptr) {
    cont->rules_endptr->next = rule;
    cont->rules_endptr = cont->rules_endptr->next;
  }
  else
    cont->rules = cont->rules_endptr = rule;
  return rule;
}

static mtev_http_rest_closure_t *
mtev_http_rest_closure_alloc(void) {
  mtev_http_rest_closure_t *restc;
  restc = calloc(1, sizeof(*restc));
  return restc;
}
void
mtev_http_rest_clean_request(mtev_http_rest_closure_t *restc) {
  int i;
  if (restc) {
    if(restc->params && restc->nparams) {
      for(i=0;i<restc->nparams;i++) free(restc->params[i]);
      free(restc->params);
    }
    if(restc->call_closure_free) restc->call_closure_free(restc->call_closure);
    restc->call_closure_free = NULL;
    restc->call_closure = NULL;
    restc->nparams = 0;
    restc->params = NULL;
    restc->fastpath = NULL;
  }
}
void
mtev_http_rest_closure_free(void *v) {
  mtev_http_rest_closure_t *restc = v;
  if (restc) {
    if (restc->remote_cn) {
      free(restc->remote_cn);
    }
    mtev_http_rest_clean_request(restc);
    free(restc);
  }
}

int
mtev_rest_websocket_dispatcher(mtev_http_session_ctx *ctx, uint8_t opcode, const unsigned char *msg, size_t msg_len) 
{
  mtev_http_rest_closure_t *restc = mtev_http_session_dispatcher_closure(ctx);
  rest_websocket_message_handler handler = restc->websocket_handler_memo;
  if (handler == NULL) handler = mtev_http_get_websocket_handler(restc);
  if (handler != NULL) {
    return handler(restc, opcode, msg, msg_len);
  }
  mtev_http_response_status_set(ctx, 404, "NOT FOUND");
  mtev_http_response_option_set(ctx, MTEV_HTTP_CHUNKED);
  mtev_http_rest_clean_request(restc);
  mtev_http_response_end(ctx);
  return -1;
}

struct mtev_rest_aco_ctx_t {
  mtev_http_session_ctx *http_ctx;
  rest_request_handler handler;
};
static int
next_tick_resume(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  mtev_http_connection_resume_after_float((mtev_http_connection *)closure);
  return 0;
}
static void
mtev_rest_aco_handler(void) {
  struct mtev_rest_aco_ctx_t *aco_ctx = eventer_aco_arg();

  /* First set this event into aco mode. */
  mtev_http_connection *conne = mtev_http_session_connection(aco_ctx->http_ctx);
  eventer_t newe = mtev_http_connection_event(conne);
  eventer_set_eventer_aco(newe);

  /* Call our handler. */
  mtev_http_rest_closure_t *restc = mtev_http_session_dispatcher_closure(aco_ctx->http_ctx);
  
  void *old_closure = restc, *new_closure;
  mtev_http_response *res = mtev_http_session_response(aco_ctx->http_ctx);
  aco_ctx->handler(restc, restc->nparams, restc->params);
  new_closure = mtev_http_session_dispatcher_closure(aco_ctx->http_ctx);
  if(old_closure == new_closure &&
     mtev_http_response_closed(res)) mtev_http_rest_clean_request(restc);

  /* Put this event back out of aco mode. */
  eventer_set_eventer_aco_co(newe, NULL);

  /* trigger the event */
  eventer_add_timer_next_opportunity(next_tick_resume, conne, pthread_self());
  free(aco_ctx);
  aco_exit();
}
int
mtev_rest_request_dispatcher(mtev_http_session_ctx *ctx) {
  mtev_boolean migrate = mtev_false;
  mtev_http_rest_closure_t *restc = mtev_http_session_dispatcher_closure(ctx);
  rest_request_handler handler = restc->fastpath;
  if(!handler) handler = mtev_http_get_handler(restc, &migrate);
  if(migrate) return EVENTER_READ|EVENTER_WRITE;
  if(!handler) {
    mtev_http_response_status_set(ctx, 404, "NOT FOUND");
    mtev_http_response_option_set(ctx, MTEV_HTTP_CHUNKED);
    mtev_http_rest_clean_request(restc);
    mtev_http_response_end(ctx);
    return 0;
  }
  if(restc->aco_enabled) {
    mtev_http_connection *conne = mtev_http_session_connection(ctx);
    eventer_t olde = mtev_http_connection_event_float(conne);
    eventer_remove_fde(olde);
    struct mtev_rest_aco_ctx_t *aco_ctx = calloc(1, sizeof(*aco_ctx));
    aco_ctx->http_ctx = ctx;
    aco_ctx->handler = handler;
    eventer_aco_start(mtev_rest_aco_handler, aco_ctx);
    return 0;
  }
  void *old_closure = restc, *new_closure;
  mtev_http_response *res = mtev_http_session_response(ctx);
  int rv;
  rv = handler(restc, restc->nparams, restc->params);
  /* If the request is closed, we need to cleanup.  However
   * if the dispatch closure has changed, the callee has done
   * something (presumably freeing the restc in the process)
   * and it would be unsafe for us to free it as well.
   */
  new_closure = mtev_http_session_dispatcher_closure(ctx);
  if(old_closure == new_closure &&
     mtev_http_response_closed(res)) mtev_http_rest_clean_request(restc);
  return rv;
}

int
mtev_http_rest_handler(eventer_t e, int mask, void *closure,
                       struct timeval *now) {
  int rv, done = 0;
  mtev_acceptor_closure_t *ac = closure;
  mtev_http_rest_closure_t *restc = mtev_acceptor_closure_ctx(ac);

  if(mask & EVENTER_EXCEPTION || (restc && restc->wants_shutdown)) {
socket_error:
    /* Exceptions cause us to simply snip the connection */
    (void)mtev_http_session_drive(e, mask, restc->http_ctx, now, &done);
    mtev_acceptor_closure_free(ac);
    return 0;
  }

  if(!restc) {
    const char *primer = "";
    const char *remote_cn = mtev_acceptor_closure_remote_cn(ac);
    restc = mtev_http_rest_closure_alloc();
    mtev_acceptor_closure_set_ctx(ac, restc, mtev_http_rest_closure_free);
    restc->ac = ac;
    restc->remote_cn = strdup(remote_cn ? remote_cn : "");
    restc->http_ctx =
        mtev_http_session_ctx_websocket_new(mtev_rest_request_dispatcher,
                                            mtev_rest_websocket_dispatcher, 
                                            restc, 
                                            e, ac);
    
    switch(mtev_acceptor_closure_cmd(ac)) {
      case MTEV_CONTROL_DELETE:
        primer = "DELE";
        break;
      case MTEV_CONTROL_GET:
        primer = "GET ";
        break;
      case MTEV_CONTROL_HEAD:
        primer = "HEAD";
        break;
      case MTEV_CONTROL_POST:
        primer = "POST";
        break;
      case MTEV_CONTROL_PUT:
        primer = "PUT ";
        break;
      case MTEV_CONTROL_MERGE:
        primer = "MERG";
        break;
      default:
        goto socket_error;
    }
    mtev_http_session_prime_input(restc->http_ctx, primer, 4);
  }
  rv = mtev_http_session_drive(e, mask, restc->http_ctx, now, &done);
  if(done) {
    mtev_acceptor_closure_free(ac);
  }
  return rv;
}

int
mtev_http_rest_raw_handler(eventer_t e, int mask, void *closure,
                           struct timeval *now) {
  int rv, done = 0;
  mtev_acceptor_closure_t *ac = closure;
  mtev_http_rest_closure_t *restc = mtev_acceptor_closure_ctx(ac);

  if(mask & EVENTER_EXCEPTION || (restc && restc->wants_shutdown)) {
    /* Exceptions cause us to simply snip the connection */
    (void)mtev_http_session_drive(e, mask, restc->http_ctx, now, &done);
    mtev_acceptor_closure_free(ac);
    return 0;
  }
  if(!restc) {
    restc = mtev_http_rest_closure_alloc();
    mtev_acceptor_closure_set_ctx(ac, restc, mtev_http_rest_closure_free);
    restc->ac = ac;
    restc->http_ctx =
      mtev_http_session_ctx_websocket_new(mtev_rest_request_dispatcher, 
                                          mtev_rest_websocket_dispatcher,
                                          restc, e, ac);
  }
  rv = mtev_http_session_drive(e, mask, restc->http_ctx, now, &done);
  if(done) {
    mtev_acceptor_closure_free(ac);
  }
  return rv;
}

static void
rest_xml_payload_free(void *f) {
  struct rest_xml_payload *xmlin = f;
  if (xmlin) {
    if(xmlin->buffer) free(xmlin->buffer);
    if(xmlin->indoc) xmlFreeDoc(xmlin->indoc);
    free(xmlin);
  }
}

xmlDocPtr
rest_get_xml_upload(mtev_http_rest_closure_t *restc,
                    int *mask, int *complete) {
  struct rest_xml_payload *rxc;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  if(restc->call_closure == NULL) {
    restc->call_closure = calloc(1, sizeof(*rxc));
    restc->call_closure_free = rest_xml_payload_free;
  }
  rxc = restc->call_closure;
  while(!rxc->complete) {
    int len;
    if(rxc->len == rxc->allocd) {
      char *b;
      rxc->allocd += 32768;
      b = rxc->buffer ? realloc(rxc->buffer, rxc->allocd) :
                        malloc(rxc->allocd);
      if(!b) {
        *complete = 1;
        return NULL;
      }
      rxc->buffer = b;
    }
    len = mtev_http_session_req_consume(restc->http_ctx,
                                        rxc->buffer + rxc->len,
                                        rxc->allocd - rxc->len,
                                        rxc->allocd - rxc->len,
                                        mask);
    if(len > 0) rxc->len += len;
    if(len < 0 && errno == EAGAIN) return NULL;
    else if(len < 0) {
      *complete = 1;
      return NULL;
    }
    if(rxc->len == mtev_http_request_content_length(req)) {
      rxc->indoc = xmlParseMemory(rxc->buffer, rxc->len);
      rxc->complete = 1;
    }
  }

  *complete = 1;
  return rxc->indoc;
}

static void
rest_raw_payload_free(void *f) {
  if (f) {
    free(f);
  }
}

static void req_payload_free(void *d, int64_t s, void *c) {
  (void)s;
  (void)c;
  if(d) free(d);
}

mtev_boolean
mtev_rest_complete_upload(mtev_http_rest_closure_t *restc, int *mask) {
  int complete = 0;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
  if(mtev_http_request_get_upload(req, NULL) == NULL &&
     mtev_http_request_has_payload(req)) {
    const void *payload = NULL;
    int payload_len = 0;
    payload = rest_get_raw_upload(restc, mask, &complete, &payload_len);
    if(!complete) return mtev_false;
    mtev_http_request_set_upload(req, (char *)payload, (int64_t)payload_len,
                                 req_payload_free, NULL);
    restc->call_closure_free(restc->call_closure);
    restc->call_closure = NULL;
  }
  return mtev_true;
}

void *
rest_get_raw_upload(mtev_http_rest_closure_t *restc,
                    int *mask, int *complete, int *size) {
  struct rest_raw_payload *rxc;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  *size = 0;
  if(restc->call_closure == NULL) {
    restc->call_closure = calloc(1, sizeof(*rxc));
    restc->call_closure_free = rest_raw_payload_free;
  }
  rxc = restc->call_closure;
  while(!rxc->complete) {
    int len;
    if(rxc->len == rxc->allocd) {
      char *b;
      rxc->allocd += 32768;
      b = rxc->buffer ? realloc(rxc->buffer, rxc->allocd) :
                        malloc(rxc->allocd);
      if(!b) {
        *complete = 1;
        return NULL;
      }
      rxc->buffer = b;
    }
    len = mtev_http_session_req_consume(restc->http_ctx,
                                        rxc->buffer + rxc->len,
                                        rxc->allocd - rxc->len,
                                        rxc->allocd - rxc->len,
                                        mask);
    if(len > 0) rxc->len += len;
    if(len < 0 && errno == EAGAIN) return NULL;
    else if(len < 0) {
      *complete = 1;
      return NULL;
    }
    if(rxc->len == mtev_http_request_content_length(req)) {
      *size = rxc->len;
      rxc->complete = 1;
    }
  }

  *complete = 1;
  return rxc->buffer;
}

int
mtev_rest_simple_file_handler(mtev_http_rest_closure_t *restc,
                              int npats, char **pats) {
  int drlen = 0;
  const char *document_root = NULL;
  const char *index_file = NULL;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  char file[PATH_MAX], rfile[PATH_MAX];
  struct stat st;
  int fd;
  void *contents = MAP_FAILED;
  const char *dot = NULL, *slash;
  const char *content_type = "application/octet-stream";
  mtev_hash_table *config = mtev_acceptor_closure_config(restc->ac);

  if(npats != 1 ||
     !mtev_hash_retr_str(config,
                         "document_root", strlen("document_root"),
                         &document_root)) {
    goto not_found;
  }
  if(!mtev_hash_retr_str(config,
                         "index_file", strlen("index_file"),
                         &index_file)) {
    index_file = "index.html";
  }
  drlen = strlen(document_root);
  snprintf(file, sizeof(file), "%s/%s", document_root, pats[0]);
  if(file[strlen(file) - 1] == '/') {
    snprintf(file + strlen(file), sizeof(file) - strlen(file),
             "%s", index_file);
  }
  /* resolve */
  if(realpath(file, rfile) == NULL) goto not_found;
  /* restrict */
  if(strncmp(rfile, document_root, drlen)) goto denied;
  if(rfile[drlen] != '/' && rfile[drlen + 1] != '/') goto denied;
  /* stat */
  /* coverity[fs_check_call] */
  if(stat(rfile, &st) != 0) {
    switch (errno) {
      case EACCES: goto denied;
      default: goto not_found;
    }
  }
  /* open */
  if(st.st_size > 0) {
    /* coverity[toctou] */
    fd = open(rfile, O_RDONLY);
    if(fd < 0) goto not_found;
    contents = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if(contents == MAP_FAILED) goto not_found;
  }
  /* set content type */
  slash = strchr(rfile, '/');
  while(slash) {
    const char *nslash = strchr(slash+1, '/');
    if(!nslash) break;
    slash = nslash;
  }
  if(slash) dot = strchr(slash+1, '.');
  while(dot) {
    const char *ndot = strchr(dot+1, '.');
    if(!ndot) break;
    dot = ndot;
  }
  /* If there is no extention, just use the filename */
  if(!dot) dot = slash+1;
  if(dot) {
    char ext[PATH_MAX];
    strlcpy(ext, "mime_type_", sizeof(ext));
    strlcpy(ext+strlen(ext), dot+1, sizeof(ext)-strlen(ext));
    if(!mtev_hash_retr_str(config,
                           ext, strlen(ext),
                           &content_type)) {
      if(!mtev_hash_retr_str(&mime_type_defaults, dot+1, strlen(dot+1),
                             &content_type)) {
        content_type = "application/octet-stream";
      }
    }
  }
  
  mtev_http_response_ok(ctx, content_type);
  if(st.st_size > 0) {
    mtev_http_response_append(ctx, contents, st.st_size);
    munmap(contents, st.st_size);
  }
  mtev_http_response_end(ctx);
  return 0;

 denied:
  mtev_http_response_denied(ctx, "text/html");
  mtev_http_response_end(ctx);
  return 0;
 not_found:
  mtev_http_response_not_found(ctx, "text/html");
  mtev_http_response_end(ctx);
  return 0;
}

static int
accrue_and_compile(const char *key, const char *value, void *vht) {
  mtev_hash_table *ht = vht;
  const char *error;
  int erroffset;
  pcre *re;
  if(strncmp(key, "listener_", strlen("listener_"))) return 0;
  key = key + strlen("listener_");
  re = pcre_compile(value, 0, &error, &erroffset, NULL);
  if(!re) {
    mtevL(mtev_error, "Error compiling ACL rule [%s]->'%s': %s\n",
          key, value, error);
    return 1;
  }
  if(mtev_hash_store(ht, strdup(key), strlen(key), re)) return 1;
  return 0;
}
static void
compile_listener_res(mtev_conf_section_t node, mtev_hash_table **htptr) {
  int cnt;
  mtev_hash_table *ht;
  ht = calloc(1, sizeof(*ht));
  mtev_hash_init(ht);
  cnt = mtev_conf_property_iter(node, accrue_and_compile, ht);
  if(cnt == 0) {
    mtev_hash_destroy(ht, free, pcre_free);
    free(ht);
    return;
  }
  *htptr = ht;
}

/* Matching listeners...
 * If there are no specifications, it is unrestricted.
 * If there are any specification, they all must match.
 */
static mtev_boolean
match_listener_res(mtev_hash_table *res, mtev_hash_table *config) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  if(res == NULL) return mtev_true;
  while(mtev_hash_adv(res, &iter)) {
    pcre *re = (pcre *)iter.value.ptr;
    const char *str;
    if(mtev_hash_retr_str(config, iter.key.str, iter.klen, &str)) {
      int ovector[30];
      if(pcre_exec(re, NULL, str, strlen(str), 0, 0,
                   ovector, sizeof(ovector)/sizeof(*ovector)) <= 0) {
        return mtev_false;
      }
    }
    else {
      return mtev_false;
    }
  }
  return mtev_true;
}
void mtev_http_rest_load_rules(void) {
  int ai, cnt = 0;
  mtev_conf_section_t *acls;
  char path[256];
  struct mtev_rest_acl *newhead = NULL, *oldacls, *remove_acl;
  struct mtev_rest_acl_rule *remove_rule;

  snprintf(path, sizeof(path), "//rest//acl");
  acls = mtev_conf_get_sections(MTEV_CONF_ROOT, path, &cnt);
  mtevL(mtev_debug, "Found %d acl stanzas\n", cnt);
  for(ai = cnt-1; ai>=0; ai--) {
    char tbuff[32];
    struct mtev_rest_acl *newacl;
    int ri, rcnt = 0;
    mtev_boolean default_allow = mtev_false;
    mtev_conf_section_t *rules;

    newacl = calloc(1, sizeof(*newacl));
    newacl->next = newhead;
    newhead = newacl;
    if(mtev_conf_get_stringbuf(acls[ai], "@type", tbuff, sizeof(tbuff)) &&
       !strcmp(tbuff, "allow"))
      newacl->allow = mtev_true;

#define compile_re(node, cont, name) do { \
  char buff[256]; \
  if(mtev_conf_get_stringbuf(node, "@" #name, buff, sizeof(buff))) { \
    const char *error; \
    int erroffset; \
    cont->name = pcre_compile(buff, 0, &error, &erroffset, NULL); \
  } \
} while(0)

    newacl->allow = default_allow;
    compile_re(acls[ai], newacl, cn);
    compile_re(acls[ai], newacl, url);
    compile_listener_res(acls[ai], &newacl->listener_res);
    rules = mtev_conf_get_sections(acls[ai], "rule", &rcnt);
    for(ri = rcnt - 1; ri >= 0; ri--) {
      struct mtev_rest_acl_rule *newacl_rule;
      newacl_rule = calloc(1, sizeof(*newacl_rule));
      newacl_rule->next = newacl->rules;
      newacl->rules = newacl_rule;
      if(mtev_conf_get_stringbuf(rules[ri], "@type", tbuff, sizeof(tbuff)) &&
         !strcmp(tbuff, "allow"))
        newacl_rule->allow = mtev_true;
      compile_re(rules[ri], newacl_rule, cn);
      compile_re(rules[ri], newacl_rule, url);
      compile_listener_res(rules[ri], &newacl_rule->listener_res);
    }
    mtev_conf_release_sections(rules, rcnt);
  }
  mtev_conf_release_sections(acls, cnt);

  oldacls = global_rest_acls;
  global_rest_acls = newhead;

  while(oldacls) {
    remove_acl = oldacls->next;
    while(oldacls->rules) {
      remove_rule = oldacls->rules->next;
      if(oldacls->rules->cn) pcre_free(oldacls->rules->cn);
      if(oldacls->rules->url) pcre_free(oldacls->rules->url);
      if(oldacls->rules->listener_res) {
        mtev_hash_destroy(oldacls->rules->listener_res, free, pcre_free);
        free(oldacls->rules->listener_res);
      }
      free(oldacls->rules);
      oldacls->rules = remove_rule;
    }
    if(oldacls->cn) pcre_free(oldacls->cn);
    if(oldacls->url) pcre_free(oldacls->url);
    if(oldacls->listener_res) {
      mtev_hash_destroy(oldacls->listener_res, free, pcre_free);
      free(oldacls->listener_res);
    }
    free(oldacls);
    oldacls = remove_acl;
  }
}
void mtev_http_rest_init(void) {
  mtev_http_init();
  rest_stats = mtev_stats_ns(mtev_stats_ns(NULL, "mtev"), "rest");
  eventer_name_callback("mtev_wire_rest_api/1.0", mtev_http_rest_handler);
  eventer_name_callback("http_rest_api", mtev_http_rest_raw_handler);

  /* some default mime types */
#define ADD_MIME_TYPE(ext, type) \
mtev_hash_store(&mime_type_defaults, strdup(ext), strlen(ext), strdup(type))
  ADD_MIME_TYPE("html", "text/html");
  ADD_MIME_TYPE("htm", "text/html");
  ADD_MIME_TYPE("js", "text/javascript");
  ADD_MIME_TYPE("css", "text/css");
  ADD_MIME_TYPE("ico", "image/x-icon");
  ADD_MIME_TYPE("gif", "image/gif");
  ADD_MIME_TYPE("png", "image/png");
  ADD_MIME_TYPE("jpg", "image/jpg");
  ADD_MIME_TYPE("jpeg", "image/jpg");
  ADD_MIME_TYPE("svg", "image/svg+xml");
  ADD_MIME_TYPE("json", "application/json");
  ADD_MIME_TYPE("eot", "application/vnd.ms-fontobject");
  ADD_MIME_TYPE("ttf", "application/octet-stream");
  ADD_MIME_TYPE("woff", "application/font-woff");
  ADD_MIME_TYPE("woff2", "application/font-woff2");

  mtev_http_rest_load_rules();

  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_DELETE,
                                 mtev_http_rest_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_MERGE,
                                 mtev_http_rest_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_GET,
                                 mtev_http_rest_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_HEAD,
                                 mtev_http_rest_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_POST,
                                 mtev_http_rest_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CONTROL_PUT,
                                 mtev_http_rest_handler);
}
void mtev_http_rest_init_globals(void) {
  mtev_hash_init_locks(&dispatch_points, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  mtev_hash_init(&mime_type_defaults);
}

