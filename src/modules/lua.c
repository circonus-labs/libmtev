/*
 * Copyright (c) 2007-2010, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2010-2015, Circonus, Inc. All rights reserved.
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
#include "mtev_json.h"

#include <unistd.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#include "mtev_conf.h"
#include "mtev_dso.h"
#include "mtev_log.h"

#include "lua_mtev.h"

static mtev_log_stream_t nldeb = NULL;
static mtev_hash_table mtev_lua_states;
static pthread_mutex_t mtev_lua_states_lock = PTHREAD_MUTEX_INITIALIZER;
static mtev_hash_table mtev_coros;
static pthread_mutex_t coro_lock = PTHREAD_MUTEX_INITIALIZER;

void
mtev_lua_cancel_coro(mtev_lua_resume_info_t *ci) {
  lua_getglobal(ci->lmc->lua_state, "mtev_coros");
  luaL_unref(ci->lmc->lua_state, -1, ci->coro_state_ref);
  lua_pop(ci->lmc->lua_state, 1);
  lua_gc(ci->lmc->lua_state, LUA_GCCOLLECT, 0);
  mtevL(nldeb, "coro_store <- %p\n", ci->coro_state);
  pthread_mutex_lock(&coro_lock);
  mtevAssert(mtev_hash_delete(&mtev_coros,
                          (const char *)&ci->coro_state, sizeof(ci->coro_state),
                          NULL, NULL));
  pthread_mutex_unlock(&coro_lock);
}

void
mtev_lua_set_resume_info(lua_State *L, mtev_lua_resume_info_t *ri) {
  lua_getglobal(L, "mtev_internal_lmc");
  ri->lmc = lua_touserdata(L, lua_gettop(L));
  mtevL(nldeb, "coro_store -> %p\n", ri->coro_state);
  pthread_mutex_lock(&coro_lock);
  mtev_hash_store(&mtev_coros,
                  (const char *)&ri->coro_state, sizeof(ri->coro_state),
                  ri); 
  pthread_mutex_unlock(&coro_lock);
}

struct lua_context_describer {
  int context_magic;
  void (*describe)(mtev_console_closure_t, mtev_lua_resume_info_t *);
  void (*describe_json)(struct json_object *, mtev_lua_resume_info_t *);
  struct lua_context_describer *next;
};

static struct lua_context_describer *context_describers = NULL;
void
mtev_lua_context_describe(int magic,
                          void (*f)(mtev_console_closure_t,
                                    mtev_lua_resume_info_t *)) {
  struct lua_context_describer *desc = calloc(1,sizeof(*desc));
  desc->context_magic = magic;
  desc->describe = f;
  desc->next = context_describers;
  context_describers = desc;
}
void
mtev_lua_context_describe_json(int magic,
                          void (*j)(struct json_object *,
                                    mtev_lua_resume_info_t *)) {
  struct lua_context_describer *desc = calloc(1,sizeof(*desc));
  desc->context_magic = magic;
  desc->describe_json = j;
  desc->next = context_describers;
  context_describers = desc;
}

static void
describe_lua_context_json(struct json_object *jcoro,
                          mtev_lua_resume_info_t *ri) {
  struct lua_context_describer *desc;
  switch(ri->context_magic) {
    case LUA_GENERAL_INFO_MAGIC:
      json_object_object_add(jcoro, "context", json_object_new_string("lua_general"));
      break;
    case LUA_REST_INFO_MAGIC:
      json_object_object_add(jcoro, "context", json_object_new_string("lua_web"));
      break;
    default:
	 break;
  }
  for(desc = context_describers; desc; desc = desc->next) {
    if(desc->context_magic == ri->context_magic) {
      if(desc->describe_json) {
        desc->describe_json(jcoro,ri);
        return;
      }
    }
  }
}
static void
describe_lua_context_ncct(mtev_console_closure_t ncct,
                          mtev_lua_resume_info_t *ri) {
  struct lua_context_describer *desc;
  for(desc = context_describers; desc; desc = desc->next) {
    if(desc->context_magic == ri->context_magic) {
      if(desc->describe) {
        desc->describe(ncct,ri);
        return;
      }
    }
  }
  if(ri->context_magic == 0) {
    nc_printf(ncct, "lua_native(state:%p, parent:%p)\n",
              ri->coro_state, ri->lmc->lua_state);
    return;
  }
  nc_printf(ncct, "Unknown lua context(state:%p, parent:%p)\n",
            ri->coro_state, ri->lmc->lua_state);
}

struct lua_reporter {
  pthread_mutex_t lock;
  enum { LUA_REPORT_NCCT, LUA_REPORT_JSON } approach;
  int timeout_ms;
  mtev_http_rest_closure_t *restc;
  struct timeval start;
  mtev_console_closure_t ncct;
  struct json_object *root;
  mtev_atomic32_t outstanding;
};

static struct lua_reporter *
mtev_lua_reporter_alloc() {
    struct lua_reporter *reporter;
    reporter = calloc(1, sizeof(*reporter));
    gettimeofday(&reporter->start, NULL);
    pthread_mutex_init(&reporter->lock, NULL);
    reporter->outstanding = 1;
    return reporter;
}
static void mtev_lua_reporter_ref(struct lua_reporter *reporter) {
    mtev_atomic_inc32(&reporter->outstanding);
}
static void mtev_lua_reporter_deref(struct lua_reporter *reporter) {
  if(mtev_atomic_dec32(&reporter->outstanding) == 0) {
    if(reporter->ncct) reporter->ncct = NULL;
    if(reporter->root) json_object_put(reporter->root);
    reporter->root = NULL;
    pthread_mutex_destroy(&reporter->lock);
  }
}
static int
mtev_console_lua_thread_reporter_json(eventer_t e, int mask, void *closure,
                                      struct timeval *now) {
  struct lua_reporter *reporter = closure;
  mtev_hash_iter zero = MTEV_HASH_ITER_ZERO, iter;
  const char *key;
  int klen;
  void *vri;
  pthread_t me;
  me = pthread_self();
  mtevAssert(reporter->approach == LUA_REPORT_JSON);
  struct json_object *states = NULL;

  pthread_mutex_lock(&reporter->lock);
  states = json_object_object_get(reporter->root, "states");
  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_next(&mtev_lua_states, &iter, &key, &klen, &vri)) {
    struct json_object *state_info = NULL;
    char state_str[32];
    char thr_str[32];
    lua_State **Lptr = (lua_State **)key;
    pthread_t tgt = (pthread_t)(vpsized_int)vri;
    if(!pthread_equal(me, tgt)) continue;

    int thr_id = eventer_is_loop(me);
    snprintf(thr_str, sizeof(thr_str), "0x%llx", (unsigned long long)me);
    if (thr_id >= 0) snprintf(thr_str, sizeof(thr_str), "%d", thr_id);
    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)*Lptr);
    state_info = json_object_new_object();
    json_object_object_add(state_info, "thread", json_object_new_string(thr_str));
    json_object_object_add(state_info, "bytes",
        json_object_new_int(lua_gc(*Lptr, LUA_GCCOUNT, 0)*1024));
    json_object_object_add(state_info, "coroutines", json_object_new_object());
    json_object_object_add(states, state_str, state_info);
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);

  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&coro_lock);
  while(mtev_hash_next(&mtev_coros, &iter, &key, &klen, &vri)) {
    mtev_lua_resume_info_t *ri;
    int level = 1;
    lua_Debug ar;
    lua_State *L;
    mtevAssert(klen == sizeof(L));
    L = *((lua_State **)key);
    ri = vri;
    if(!pthread_equal(me, ri->lmc->owner)) continue;

    char state_str[32];
    json_object *state_info, *jcoros, *jcoro;
    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)ri->lmc->lua_state);
    state_info = json_object_object_get(states, state_str);
    if(!state_info) continue;
    jcoros = json_object_object_get(state_info, "coroutines");

    /* make state_str now point to this state */
    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)L);
    jcoro = json_object_new_object();
    if(ri) describe_lua_context_json(jcoro, ri);
    while (lua_getstack(L, level++, &ar));
    level--;
    struct json_object *jstack = json_object_new_array();
    while (level > 0 && lua_getstack(L, --level, &ar)) {
      struct json_object *jsentry;
      const char *name;
      lua_getinfo(L, "n", &ar);
      name = ar.name;
      lua_getinfo(L, "Snlf", &ar);
      if(!ar.source) ar.source = "???";
      if(ar.name == NULL) ar.name = name;
      if(ar.name == NULL) ar.name = "???";
      jsentry = json_object_new_object();
	 json_object_object_add(jsentry, "file", json_object_new_string(ar.source));
      if (ar.currentline > 0) json_object_object_add(jsentry, "line", json_object_new_int(ar.currentline));
      if (*ar.namewhat) json_object_object_add(jsentry, "namewhat", json_object_new_string(ar.namewhat));
      json_object_object_add(jsentry, "name", json_object_new_string(ar.name));
      json_object_array_add(jstack, jsentry);
    }
    json_object_object_add(jcoro, "stack", jstack);
    json_object_object_add(jcoros, state_str, jcoro);
  }
  pthread_mutex_unlock(&coro_lock);
  pthread_mutex_unlock(&reporter->lock);
  mtev_lua_reporter_deref(reporter);
  return 0;
}
static int
mtev_console_lua_thread_reporter_ncct(eventer_t e, int mask, void *closure,
                                      struct timeval *now) {
  struct lua_reporter *reporter = closure;
  mtev_console_closure_t ncct = reporter->ncct;
  mtev_hash_iter zero = MTEV_HASH_ITER_ZERO, iter;
  const char *key;
  int klen;
  void *vri;
  pthread_t me;
  me = pthread_self();
  mtevAssert(reporter->approach == LUA_REPORT_NCCT);

  pthread_mutex_lock(&reporter->lock);
  nc_printf(ncct, "== Thread %x ==\n", me);

  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_next(&mtev_lua_states, &iter, &key, &klen, &vri)) {
    lua_State **Lptr = (lua_State **)key;
    pthread_t tgt = (pthread_t)(vpsized_int)vri;
    if(!pthread_equal(me, tgt)) continue;
    nc_printf(ncct, "master (state:%p)\n", *Lptr);
    nc_printf(ncct, "\tmemory: %d kb\n", lua_gc(*Lptr, LUA_GCCOUNT, 0));
    nc_printf(ncct, "\n");
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);

  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&coro_lock);
  while(mtev_hash_next(&mtev_coros, &iter, &key, &klen, &vri)) {
    mtev_lua_resume_info_t *ri;
    int level = 1;
    lua_Debug ar;
    lua_State *L;
    mtevAssert(klen == sizeof(L));
    L = *((lua_State **)key);
    ri = vri;
    if(!pthread_equal(me, ri->lmc->owner)) continue;
    if(ri) describe_lua_context_ncct(ncct, ri);
    nc_printf(ncct, "\tstack:\n");
    while (lua_getstack(L, level++, &ar));
    level--;
    while (level > 0 && lua_getstack(L, --level, &ar)) {
      const char *name, *cp;
      lua_getinfo(L, "n", &ar);
      name = ar.name;
      lua_getinfo(L, "Snlf", &ar);
      cp = ar.source;
      if(cp) {
        cp = cp + strlen(cp) - 1;
        while(cp >= ar.source && *cp != '/' && *cp != '\n') cp--;
        cp++;
      }
      else cp = "???";
      if(ar.name == NULL) ar.name = name;
      if(ar.name == NULL) ar.name = "???";
      if (ar.currentline > 0) {
        if(*ar.namewhat) {
          nc_printf(ncct, "\t\t%s:%s(%s):%d\n", cp, ar.namewhat, ar.name, ar.currentline);
        } else {
          nc_printf(ncct, "\t\t%s:%d\n", cp, ar.currentline);
        }
      } else {
        nc_printf(ncct, "\t\t%s:%s(%s)\n", cp, ar.namewhat, ar.name);
      }
    }
    nc_printf(ncct, "\n");
  }
  pthread_mutex_unlock(&coro_lock);
  pthread_mutex_unlock(&reporter->lock);
  mtev_lua_reporter_deref(reporter);
  return 0;
}

static void
distribute_reporter_across_threads(struct lua_reporter *reporter,
                                   eventer_func_t reporter_f) {
  int i = 1;
  pthread_t me, tgt, first;
  struct timeval old = { 1ULL, 0ULL };

  mtev_lua_reporter_ref(reporter);
  reporter_f(NULL, 0, reporter, NULL);

  me = pthread_self();
  first = eventer_choose_owner(i++);
  do {
    tgt = eventer_choose_owner(i++);
    if(!pthread_equal(tgt, me)) {
      eventer_t e;
      e = eventer_alloc();
      memcpy(&e->whence, &old, sizeof(old));
      e->thr_owner = tgt;
      e->mask = EVENTER_TIMER;
      e->callback = reporter_f;
      e->closure = reporter;
      mtev_lua_reporter_ref(reporter);
      eventer_add(e);
    }
  } while(!pthread_equal(first, tgt));
}

static int
mtev_lua_rest_show_waiter(eventer_t e, int mask, void *closure,
                          struct timeval *now) {
  struct lua_reporter *reporter = closure;
  mtev_http_rest_closure_t *restc = reporter->restc;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  int age = sub_timeval_ms(*now, reporter->start);

  /* If we're not ready and we've not timed out */
  if(reporter->outstanding > 1 && age < reporter->timeout_ms) {
    eventer_add_in_s_us(mtev_lua_rest_show_waiter, reporter, 0, 100000);
    return 0;
  }
  eventer_t conne = mtev_http_connection_event(mtev_http_session_connection(ctx));
  if(conne) {
    conne->mask =  EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION;
    eventer_trigger(conne, EVENTER_WRITE);
  }
  return 0;
}
static int
mtev_rest_show_lua_complete(mtev_http_rest_closure_t *restc, int n, char **p) {
  struct lua_reporter *reporter = restc->call_closure;

  mtev_http_response_ok(restc->http_ctx, "application/json");
  pthread_mutex_lock(&reporter->lock);
  const char *jsonstr = json_object_to_json_string(reporter->root);
  mtev_http_response_append(restc->http_ctx, jsonstr, strlen(jsonstr));
  pthread_mutex_unlock(&reporter->lock);
  mtev_http_response_append(restc->http_ctx, "\n", 1);
  mtev_http_response_end(restc->http_ctx);

  mtev_lua_reporter_deref(reporter);
  return 0;
}
static int
mtev_rest_show_lua(mtev_http_rest_closure_t *restc, int n, char **p) {
  struct lua_reporter *crutch;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  crutch = mtev_lua_reporter_alloc();
  crutch->restc = restc;
  crutch->approach = LUA_REPORT_JSON;
  crutch->root = json_object_new_object();
  json_object_object_add(crutch->root, "metadata", json_object_new_object());
  json_object_object_add(crutch->root, "states", json_object_new_object());
  distribute_reporter_across_threads(crutch, mtev_console_lua_thread_reporter_json);
  restc->call_closure = crutch;
  restc->fastpath = mtev_rest_show_lua_complete;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  eventer_t conne = mtev_http_connection_event_float(mtev_http_session_connection(ctx));
  if(conne) {
    eventer_remove_fd(conne->fd);
  }

  /* Register our waiter */
  const char *timeout = mtev_http_request_querystring(req, "timeout");
  if(timeout) crutch->timeout_ms = atoi(timeout);
  if(crutch->timeout_ms <= 0) crutch->timeout_ms = 5000;
  eventer_add_in_s_us(mtev_lua_rest_show_waiter, crutch, 0, 0);
  return 0;
}

static int
mtev_console_show_lua(mtev_console_closure_t ncct,
                      int argc, char **argv,
                      mtev_console_state_t *dstate,
                      void *closure) {
  struct lua_reporter *crutch;

  crutch = mtev_lua_reporter_alloc();
  crutch->approach = LUA_REPORT_NCCT;
  crutch->ncct = ncct;
  distribute_reporter_across_threads(crutch, mtev_console_lua_thread_reporter_ncct);
  /* Wait for completion */
  while(crutch->outstanding > 1) {
    usleep(500);
  }
  mtev_lua_reporter_deref(crutch);
  return 0;
}

void
register_console_lua_commands() {
  static int loaded = 0;
  mtev_console_state_t *tl;
  cmd_info_t *showcmd;

  if(loaded) return;
  loaded = 1;
  tl = mtev_console_state_initial();
  showcmd = mtev_console_state_get_cmd(tl, "show");
  mtevAssert(showcmd && showcmd->dstate);
  mtev_console_state_add_cmd(showcmd->dstate,
    NCSCMD("lua", mtev_console_show_lua, NULL, NULL, NULL));

  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/module/lua/", "^state\\.json$",
    mtev_rest_show_lua, mtev_http_rest_client_cert_auth
  ) == 0); 
}

int
mtev_lua_traceback(lua_State *L) {
  if (!lua_isstring(L, -1)) {
    if (lua_isnoneornil(L, -1) || !luaL_callmeta(L, -1, "__tostring"))
      return 1;
    lua_remove(L, -1);
  }
  luaL_traceback(L, L, lua_tostring(L, -1), 1);
  return 1;
}

void 
mtev_lua_new_coro(mtev_lua_resume_info_t *ri) {
  lua_module_closure_t *lmc = ri->lmc;
  lua_State *L = lmc->lua_state;
  lua_getglobal(L, "mtev_coros");
  ri->coro_state = lua_newthread(L);
  ri->coro_state_ref = luaL_ref(L, -2);
  lua_pop(L, 1); /* pops mtev_coros */
  mtevL(nldeb, "coro_store -> %p\n", ri->coro_state);
  pthread_mutex_lock(&coro_lock);
  mtev_hash_store(&mtev_coros,
                  (const char *)&ri->coro_state, sizeof(ri->coro_state),
                  ri);
  pthread_mutex_unlock(&coro_lock);
  return;
}
mtev_lua_resume_info_t *
mtev_lua_get_resume_info(lua_State *L) {
  mtev_lua_resume_info_t *ri;
  void *v = NULL;
  pthread_mutex_lock(&coro_lock);
  if(mtev_hash_retrieve(&mtev_coros, (const char *)&L, sizeof(L), &v)) {
    pthread_mutex_unlock(&coro_lock);
    ri = v;
    mtevAssert(pthread_equal(pthread_self(), ri->bound_thread));
    return ri;
  }
  ri = calloc(1, sizeof(*ri));
  ri->bound_thread = pthread_self();
  ri->coro_state = L;
  lua_getglobal(L, "mtev_internal_lmc");;
  ri->lmc = lua_touserdata(L, lua_gettop(L));
  lua_pop(L, 1);
  mtevL(nldeb, "coro_store -> %p\n", ri->coro_state);
  lua_getglobal(L, "mtev_coros");
  lua_pushthread(L);
  ri->coro_state_ref = luaL_ref(L, -2);
  lua_pop(L, 1); /* pops mtev_coros */
  mtev_hash_store(&mtev_coros,
                  (const char *)&ri->coro_state, sizeof(ri->coro_state),
                  ri);
  pthread_mutex_unlock(&coro_lock);
  return ri;
}

static void
mtev_event_dispose(void *ev) {
  int mask;
  eventer_t *value = ev;
  eventer_t removed, e = *value;
  mtevL(nldeb, "lua check cleanup: dropping (%p)->fd (%d)\n", e, e->fd);
  removed = eventer_remove(e);
  mtevL(nldeb, "    remove from eventer system %s\n",
        removed ? "succeeded" : "failed");
  if(e->mask & (EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION)) {
    mtevL(nldeb, "    closing down fd %d\n", e->fd);
    e->opset->close(e->fd, &mask, e);
  }
  if(e->closure) {
    struct nl_generic_cl *cl;
    cl = e->closure;
    if(cl->free) cl->free(cl);
  }
  eventer_free(e);
  free(ev);
}
void
mtev_lua_register_event(mtev_lua_resume_info_t *ci, eventer_t e) {
  eventer_t *eptr;
  eptr = calloc(1, sizeof(*eptr));
  memcpy(eptr, &e, sizeof(*eptr));
  if(!ci->events) {
    ci->events = calloc(1, sizeof(*ci->events));
    mtev_hash_init(ci->events);
  }
  mtevAssert(mtev_hash_store(ci->events, (const char *)eptr, sizeof(*eptr), eptr));
}
void
mtev_lua_deregister_event(mtev_lua_resume_info_t *ci, eventer_t e,
                                int tofree) {
  mtevAssert(ci->events);
  mtevAssert(mtev_hash_delete(ci->events, (const char *)&e, sizeof(e),
                          NULL, tofree ? mtev_event_dispose : free));
}
void
mtev_lua_resume_clean_events(mtev_lua_resume_info_t *ci) {
  if(ci->events == NULL) return;
  mtev_hash_destroy(ci->events, NULL, mtev_event_dispose);
  free(ci->events);
  ci->events = NULL;
}

void
mtev_lua_pushmodule(lua_State *L, const char *m) {
  int stack_pos = 0;
  char *copy, *part, *brkt;
  copy = alloca(strlen(m)+1);
  mtevAssert(copy);
  memcpy(copy,m,strlen(m)+1);

  for(part = strtok_r(copy, ".", &brkt);
      part;
      part = strtok_r(NULL, ".", &brkt)) {
    if(stack_pos) {
      if(lua_isnil(L, stack_pos)) {
        return;
      }
      lua_getfield(L, stack_pos, part);
    }
    else lua_getglobal(L, part);
    if(stack_pos == -1) lua_remove(L, -2);
    else stack_pos = -1;
  }
}
mtev_hash_table *
mtev_lua_table_to_hash(lua_State *L, int idx) {
  mtev_hash_table *t;
  if(lua_gettop(L) < idx || !lua_istable(L,idx))
    luaL_error(L, "table_to_hash: not a table");

  t = calloc(1, sizeof(*t));
  mtev_hash_init(t);
  lua_pushnil(L);  /* first key */
  while (lua_next(L, idx) != 0) {
    const char *key, *value;
    size_t klen;
    key = lua_tolstring(L, -2, &klen);
    value = lua_tostring(L, -1);
    mtev_hash_store(t, key, klen, (void *)value);
    lua_pop(L, 1);
  }
  return t;
}
void
mtev_lua_hash_to_table(lua_State *L,
                       mtev_hash_table *t) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  const char *key, *value;
  int klen, kcnt;
  kcnt = t ? mtev_hash_size(t) : 0;
  lua_createtable(L, 0, kcnt);
  if(t) {
    while(mtev_hash_next_str(t, &iter, &key, &klen, &value)) {
      lua_pushlstring(L, value, strlen(value));
      lua_setfield(L, -2, key);
    }
  }
  return;
}

const char *
mtev_lua_type_name(int t) {
  switch(t) {
    case LUA_TNIL: return "nil";
    case LUA_TNUMBER: return "number";
    case LUA_TBOOLEAN: return "boolean";
    case LUA_TSTRING: return "string";
    case LUA_TTABLE: return "table";
    case LUA_TFUNCTION: return "function";
    case LUA_TUSERDATA: return "userdata";
    case LUA_TTHREAD: return "thread";
    case LUA_TLIGHTUSERDATA: return "lightuserdata";
    default: return "unknown";
  }
}

int
mtev_lua_yield(mtev_lua_resume_info_t *ci, int nargs) {
  mtevL(nldeb, "lua: %p yielding\n", ci->coro_state);
  return lua_yield(ci->coro_state, nargs);
}

static int mtev_lua_panic(lua_State *L) {
  if(L) {
    int level = 0;
    lua_Debug ar;
    const char *err = lua_tostring(L,2);
    
    while (lua_getstack(L, level++, &ar));
    mtevL(mtev_error, "lua panic[top:%d]: %s\n", lua_gettop(L), err);
    while (level > 0 && lua_getstack(L, --level, &ar)) {
      lua_getinfo(L, "Sl", &ar);
      lua_getinfo(L, "n", &ar);
      if (ar.currentline > 0) {
        const char *cp = ar.source;
        if(cp) {
          cp = cp + strlen(cp) - 1;
          while(cp >= ar.source && *cp != '/') cp--;
          cp++;
        }
        else cp = "???";
        if(ar.name == NULL) ar.name = "???";
        mtevL(mtev_error, "\t%s:%s(%s):%d\n", cp, ar.namewhat, ar.name, ar.currentline);
      }
    }
  }
  mtevAssert(L == NULL);
  return 0;
}

/* static void *l_alloc (void *ud, void *ptr, size_t osize, size_t nsize) { */
/*   (void)ud; (void)osize;  /\* not used *\/ */
/*   if (nsize == 0) { */
/*     free(ptr); */
/*     return NULL; */
/*   } */
/*   else */
/*     return realloc(ptr, nsize); */
/* } */

mtev_lua_resume_info_t *
mtev_lua_new_resume_info(lua_module_closure_t *lmc, int magic) {
  mtev_lua_resume_info_t *ri;
  ri = calloc(1, sizeof(*ri));
  mtevAssert(pthread_equal(lmc->owner, pthread_self()));
  ri->bound_thread = lmc->owner;
  ri->context_magic = magic;
  ri->lmc = lmc;
  lua_getglobal(lmc->lua_state, "mtev_coros");
  ri->coro_state = lua_newthread(lmc->lua_state);
  ri->coro_state_ref = luaL_ref(lmc->lua_state, -2);
  mtev_lua_set_resume_info(lmc->lua_state, ri);
  lua_pop(lmc->lua_state, 1); /* pops mtev_coros */
  mtevL(nldeb, "lua_general(%p) -> starting new job (%p)\n",
        lmc->lua_state, ri->coro_state);
  return ri;
}

int
mtev_lua_coroutine_spawn(lua_State *Lp,
                         mtev_lua_resume_info_t *(new_ri_f)(lua_module_closure_t *lmc)) {
  int nargs;
  lua_State *L;
  mtev_lua_resume_info_t *ri_parent = NULL, *ri = NULL;

  nargs = lua_gettop(Lp);
  if(nargs < 1 || !lua_isfunction(Lp,1))
    luaL_error(Lp, "mtev.coroutine_spawn(func, ...): bad arguments");
  ri_parent = mtev_lua_get_resume_info(Lp);
  mtevAssert(ri_parent);

  ri = new_ri_f(ri_parent->lmc);
  L = ri->coro_state;
  lua_xmove(Lp, L, nargs);
#if !defined(LUA_JITLIBNAME) && LUA_VERSION_NUM < 502
  lua_setlevel(Lp, L);
#endif
  ri->lmc->resume(ri, nargs-1);
  return 0;
}

static char *
package_manip_path(char *in, const char *find, const char *replace) {
  char *ocp, *npath = in;
  if(NULL != (ocp = strstr(in, find))) {
    int nlen = strlen(in) + strlen(replace);
    npath = malloc(nlen);
    memcpy(npath, in, ocp-in);
    npath[ocp-in] = '\0';
    strlcat(npath, replace, nlen);
    strlcat(npath, ocp + strlen(find), nlen);
    free(in);
  } else {
    npath = in;
  }
  return npath;
}

lua_State *
mtev_lua_open(const char *module_name, void *lmc,
              const char *script_dir, const char *cpath) {
  int rv;
  const char *existing_ppath, *existing_cpath;
  char *npath;
  lua_State *L = luaL_newstate(), **Lptr;
  lua_atpanic(L, &mtev_lua_panic);

  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */

  lua_newtable(L);
  lua_setglobal(L, "mtev_coros");

  if(lmc) {
    lua_pushlightuserdata(L, lmc);
    lua_setglobal(L, "mtev_internal_lmc");
  }

  lua_getglobal(L, "package");

  lua_getfield(L, -1, "path");
  existing_ppath = lua_tostring(L, -1);
  lua_pop(L,1);
  lua_getfield(L, -1, "cpath");
  existing_cpath = lua_tostring(L, -1);
  lua_pop(L,1);

  if(!script_dir) script_dir = "{mtev.lua_path};{package.path}";
  npath = strdup(script_dir);
  npath = package_manip_path(npath, "{package.path}", existing_ppath);
  npath = package_manip_path(npath, "{mtev.lua_path}",
                             MTEV_MODULES_DIR "/lua/?.lua");
  lua_pushfstring(L, "%s", npath);
  free(npath);
  lua_setfield(L, -2, "path");

  if(!cpath) cpath = "{mtev.lua_cpath};{package.cpath}";
  npath = strdup(cpath);
  npath = package_manip_path(npath, "{package.cpath}", existing_cpath);
  npath = package_manip_path(npath, "{mtev.lua_cpath}",
                             MTEV_LIB_DIR "/mtev_lua/?.so");
  lua_pushfstring(L, "%s", npath);
  free(npath);
  lua_setfield(L, -2, "cpath");
  lua_pop(L, 1);

  require(L, rv, mtev);
  require(L, rv, mtev.timeval);
  require(L, rv, mtev.extras);

  lua_gc(L, LUA_GCRESTART, 0);

  Lptr = malloc(sizeof(*Lptr));
  *Lptr = L;
  pthread_mutex_lock(&mtev_lua_states_lock);
  mtev_hash_store(&mtev_lua_states,
                  (const char *)Lptr, sizeof(*Lptr),
                  (void *)(vpsized_int)pthread_self());
  pthread_mutex_unlock(&mtev_lua_states_lock);

  return L;
}

void
mtev_lua_init_globals() {
  mtev_hash_init(&mtev_lua_states);
  mtev_hash_init(&mtev_coros);
}
