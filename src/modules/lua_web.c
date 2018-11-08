/*
 * Copyright (c) 2013-2015, Circonus, Inc.  All rights reserved.
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

#include <dlfcn.h>

#include "mtev_dso.h"
#include "mtev_http.h"
#include "mtev_rest.h"

#include "lua_mtev.h"

#define DEFAULT_MAX_POST_SIZE 1024*1024

typedef struct lua_web_conf {
  const char *script_dir;
  const char *cpath;
  struct {
    char *name;
    char *eventer_pool;
    char *method;
    char *mount;
    char *expr;
    char *module;
  } *mounts;
  const char **Cpreloads;
  int max_post_size;
  mtev_dso_generic_t *self;
  pthread_key_t key;
  lua_module_gc_params_t *gc_params;
} lua_web_conf_t;

static lua_module_closure_t *mtev_lua_web_setup_lmc(mtev_dso_generic_t *self);

static lua_web_conf_t *the_one_conf = NULL;
static lua_web_conf_t *get_config(mtev_dso_generic_t *self) {
  if(the_one_conf) return the_one_conf;
  the_one_conf = mtev_image_get_userdata(&self->hdr);
  if(the_one_conf) return the_one_conf;
  the_one_conf = calloc(1, sizeof(*the_one_conf));
  the_one_conf->self = self;
  pthread_key_create(&the_one_conf->key, NULL);
  mtev_image_set_userdata(&self->hdr, the_one_conf);
  return the_one_conf;
}

static void
rest_lua_ctx_free(void *cl) {
  mtev_lua_resume_info_t *ri = cl;
  if(ri) {
    mtev_lua_cancel_coro(ri);
    mtev_lua_resume_clean_events(ri);
    if(ri->context_data) {
      mtev_lua_resume_rest_info_t *ctx = ri->context_data;
      if (ctx) {
        if(ctx->err) free(ctx->err);
        free(ctx);
      }
    }
    free(ri);
  }
}

static int
lua_web_restc_fastpath(mtev_http_rest_closure_t *restc,
                       int npats, char **pats) {
  (void)npats;
  (void)pats;
  mtev_lua_resume_info_t *ri = restc->call_closure;
  mtev_http_response *res = mtev_http_session_response(restc->http_ctx);
  mtev_lua_resume_rest_info_t *ctx = ri->context_data;

  if(mtev_http_response_complete(res) != mtev_true) {
    mtev_http_response_standard(restc->http_ctx,
                                (ctx && ctx->httpcode) ? ctx->httpcode : 500,
                                "ERROR", "text/html");
    if(ctx->err) mtev_http_response_append(restc->http_ctx, ctx->err, strlen(ctx->err));
    mtev_http_response_end(restc->http_ctx);
  }

  mtev_http_rest_clean_request(restc);
  return 0;
}

static int
lua_web_resume(mtev_lua_resume_info_t *ri, int nargs) {
  const char *err = NULL;
  int status, base, rv = 0;
  mtev_lua_resume_rest_info_t *ctx = ri->context_data;
  mtev_http_rest_closure_t *restc = NULL;
  eventer_t conne = NULL;
  if(ctx) {
    restc = ctx->restc;
    conne = mtev_http_connection_event(mtev_http_session_connection(restc->http_ctx));
  }

  mtevAssert(pthread_equal(pthread_self(), ri->bound_thread));

#if LUA_VERSION_NUM >= 502
  status = lua_resume(ri->coro_state, ri->lmc->lua_state, nargs);
#else
  status = lua_resume(ri->coro_state, nargs);
#endif

  switch(status) {
    case 0:
      mtev_lua_gc(ri->lmc);
      break;
    case LUA_YIELD:
      mtev_lua_gc(ri->lmc);
      return 0;
    default: /* The complicated case */
      if(ctx) ctx->httpcode = 500;
      base = lua_gettop(ri->coro_state);
      if(base>0) {
        mtev_lua_traceback(ri->coro_state);
        base = lua_gettop(ri->coro_state);
        if(lua_isstring(ri->coro_state, base)) {
          err = lua_tostring(ri->coro_state, base);
          mtevL(mtev_error, "lua error: %s\n", err);
          if(ctx && !ctx->err) ctx->err = strdup(err);
        }
      }
      rv = -1;
  }

  if(restc) lua_web_restc_fastpath(restc, 0, NULL);
  if(conne) eventer_trigger(conne, EVENTER_READ|EVENTER_WRITE);
  return rv;
}

static int
lua_web_handler(mtev_http_rest_closure_t *restc,
                int npats, char **pats) {
  (void)npats;
  (void)pats;
  int status, rv, mask = 0;
  mtev_lua_resume_info_t *ri;
  mtev_lua_resume_rest_info_t *ctx = NULL;
  lua_State *L;
  eventer_t conne = NULL;

  lua_web_conf_t *conf = the_one_conf;
  if(!conf) {
    goto boom;
  }

  lua_module_closure_t *lmc = mtev_lua_web_setup_lmc(conf->self);
  if(!lmc) {
    goto boom;
  }

  mtev_http_response *res = mtev_http_session_response(restc->http_ctx);

  if(!mtev_rest_complete_upload(restc, &mask)) return mask;

  if(restc->call_closure == NULL) {
    ri = calloc(1, sizeof(*ri));
    ri->bound_thread = pthread_self();
    ri->context_magic = LUA_REST_INFO_MAGIC;
    ctx = ri->context_data = calloc(1, sizeof(mtev_lua_resume_rest_info_t));
    ctx->restc = restc;
    ri->lmc = lmc;
    ri->coro_state = lua_newthread(lmc->lua_state);
    ri->coro_state_ref = luaL_ref(lmc->lua_state, LUA_REGISTRYINDEX);

    mtev_lua_set_resume_info(lmc->lua_state, ri);

    restc->call_closure = ri;
    restc->call_closure_free = rest_lua_ctx_free;
  }
  ri = restc->call_closure;
  ctx = ri->context_data;
  ctx->httpcode = 404;

  L = ri->coro_state;

  lua_getglobal(L, "require");
  lua_pushstring(L, restc->closure);
  rv = lua_pcall(L, 1, 1, 0);
  if(rv) {
    int i;
    mtevL(mtev_error, "lua: require %s failed\n", (char *)restc->closure);
    mtev_lua_traceback(L);
    i = lua_gettop(L);
    if(i>0) {
      if(lua_isstring(L, i)) {
        const char *err;
        size_t len;
        err = lua_tolstring(L, i, &len);
        mtevL(mtev_error, "lua: %s\n", err);
      }
    }
    lua_pop(L,i);
    goto boom;
  }
  lua_pop(L, lua_gettop(L));

  mtev_lua_pushmodule(L, restc->closure);
  if(lua_isnil(L, -1)) {
    lua_pop(L, 1);
    ctx->err = strdup("no such module");
    goto boom;
  }
  lua_getfield(L, -1, "handler");
  lua_remove(L, -2);
  if(!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    ctx->err = strdup("no 'handler' function in module");
    goto boom;
  }
  mtev_lua_setup_restc(L, restc);
  mtev_lua_hash_to_table(L, mtev_acceptor_closure_config(restc->ac));

  conne = mtev_http_connection_event_float(mtev_http_session_connection(restc->http_ctx));
  if(conne) eventer_remove_fde(conne);
  restc->fastpath = lua_web_restc_fastpath;

  status = lmc->resume(ri, 2);
  if(status == 0) return 0;

  if(mtev_http_response_complete(res) != mtev_true) {
 boom:
    if(conne) eventer_add(conne);
    mtev_http_response_standard(restc->http_ctx,
                                (ctx && ctx->httpcode) ? ctx->httpcode : 500,
                                "ERROR", "text/plain");
    if(ctx && ctx->err) mtev_http_response_append(restc->http_ctx, ctx->err, strlen(ctx->err));
    mtev_http_response_end(restc->http_ctx);
  }
  return 0;
}

static void
describe_lua_rest_context(mtev_console_closure_t ncct,
                          mtev_lua_resume_info_t *ri) {
  nc_printf(ncct, "lua_rest(state:%p, parent:%p)\n",
            ri->coro_state, ri->lmc->lua_state);
}

static void
describe_lua_rest_context_json(mtev_json_object *jcoro,
                               mtev_lua_resume_info_t *ri) {
  char buff[32];
  snprintf(buff, sizeof(buff), "%p", ri->coro_state);
  MJ_KV(jcoro, "state", MJ_STR(buff));
  snprintf(buff, sizeof(buff), "%p", ri->lmc->lua_state);
  MJ_KV(jcoro, "parent", MJ_STR(buff));
}

static int
mtev_lua_web_driver_onload(mtev_image_t *self) {
  (void)self;
  mtev_lua_context_describe(LUA_REST_INFO_MAGIC, describe_lua_rest_context);
  mtev_lua_context_describe_json(LUA_REST_INFO_MAGIC,
                                 describe_lua_rest_context_json);
  return 0;
}

static mtev_lua_resume_info_t *
lua_web_new_resume_info(lua_module_closure_t *lmc) {
  mtev_lua_resume_info_t *ri = mtev_lua_new_resume_info(lmc, LUA_REST_INFO_MAGIC);
  ri->new_ri_f = lua_web_new_resume_info;
  return ri;
}

static int
lua_web_coroutine_spawn(lua_State *Lp) {
  return mtev_lua_coroutine_spawn(Lp, lua_web_new_resume_info);
}

static int
mtev_lua_web_driver_config(mtev_dso_generic_t *self, mtev_hash_table *o) {
  lua_web_conf_t *conf = get_config(self);
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  int i;
  const char *bstr;
  conf->script_dir = NULL;
  conf->cpath = NULL;
  (void)mtev_hash_retr_str(o, "directory", strlen("directory"), &conf->script_dir);
  if(conf->script_dir) conf->script_dir = strdup(conf->script_dir);
  (void)mtev_hash_retr_str(o, "cpath", strlen("cpath"), &conf->cpath);
  if(conf->cpath) conf->cpath = strdup(conf->cpath);

  conf->mounts = calloc(1+mtev_hash_size(o), sizeof(*conf->mounts));
  i = 0;
  while(mtev_hash_adv(o, &iter)) {
    if(!strncmp(iter.key.str, "mount_", strlen("mount_"))) {
      /* <module>:<method>:<mount>[:<expr>] */
      char *copy = strdup(iter.value.str);
      char *module, *method, *mount = NULL, *expr = NULL;
      module = copy;
      method = strchr(module, ':');
      if(method) {
        *method++ = '\0';
        mount = strchr(method, ':');
        if(mount) {
          *mount++ = '\0';
          expr = strchr(mount, ':');
          if(expr) *expr++ = '\0';
        }
      }
      if(!method || !mount) {
        mtevL(mtev_error, "Invalid lua_web mount syntax in '%s'\n", iter.key.str);
        free(copy);
        return -1;
      }
      conf->mounts[i].name = strdup(iter.key.str + strlen("mount_"));
      conf->mounts[i].module = strdup(module);
      conf->mounts[i].method = strdup(method);
      conf->mounts[i].mount = strdup(mount);
      conf->mounts[i].expr = expr ? strdup(expr) : strdup("(.*)$");
      i++;
      free(copy);
    }
  }
  memset(&iter, 0, sizeof(iter));
  while(mtev_hash_adv(o, &iter)) {
    if(!strncmp(iter.key.str, "loop_assign_", strlen("loop_assign_"))) {
      for(i=0;conf->mounts[i].name;i++) {
        if(!strcmp(iter.key.str + strlen("loop_assign_"), conf->mounts[i].name)) {
          conf->mounts[i].eventer_pool = strdup(iter.value.str);
        }
      }
    }
  }

  if(mtev_hash_retr_str(o, "Cpreloads", strlen("Cpreloads"), &bstr)) {
    int count = 1, i;
    char *brk = NULL, *cp, *copy;
    cp = copy = strdup(bstr);
    while(*cp) if(*cp++ == ',') count++; /* count terms (start with 1) */
    conf->Cpreloads = calloc(count+1, sizeof(char *)); /* null term */
    for(i = 0, cp = strtok_r(copy, ",", &brk);
      cp; cp = strtok_r(NULL, ",", &brk), i++) {
      conf->Cpreloads[i] = strdup(cp);
    }
    free(copy);
  }

  conf->gc_params = mtev_lua_config_gc_params(o);
  conf->max_post_size = DEFAULT_MAX_POST_SIZE;
  return 0;
}

static mtev_hook_return_t late_stage_rest_register(void *cl) {
  mtev_dso_generic_t *self = cl;
  lua_web_conf_t *conf = get_config(self);
  int i = 0;
  for(i=0; conf->mounts[i].module != NULL; i++) {
    mtevL(mtev_debug, "Registering [%s][%s][%s] -> %s\n",
          conf->mounts[i].method, conf->mounts[i].mount,
          conf->mounts[i].expr, conf->mounts[i].module);
    mtev_rest_mountpoint_t *rule;
    mtevAssert(NULL != (rule = mtev_http_rest_new_rule(
        conf->mounts[i].method, conf->mounts[i].mount,
        conf->mounts[i].expr, lua_web_handler
    )));
    mtev_rest_mountpoint_set_closure(rule, conf->mounts[i].module);
    if(conf->mounts[i].eventer_pool) {
      eventer_pool_t *pool = eventer_pool(conf->mounts[i].eventer_pool);
      if(pool) {
        mtev_rest_mountpoint_set_eventer_pool(rule, pool);
      }
    }
  }
  return MTEV_HOOK_CONTINUE;
}

static const luaL_Reg web_lua_funcs[] =
{
  {"coroutine_spawn", lua_web_coroutine_spawn },
  {NULL, NULL}
};

static lua_module_closure_t *
mtev_lua_web_setup_lmc(mtev_dso_generic_t *self) {
  lua_web_conf_t *conf = get_config(self);
  lua_module_closure_t *lmc = pthread_getspecific(conf->key);

  if(!lmc) {
    lmc = mtev_lua_lmc_alloc(self, lua_web_resume);
    mtev_lua_set_gc_params(lmc, conf->gc_params);
    pthread_setspecific(conf->key, lmc);
  }
  if(lmc->lua_state == NULL) {
    const char **module;
    lmc->lua_state = mtev_lua_open(self->hdr.name, lmc,
                                   conf->script_dir, conf->cpath);
    if(lmc->lua_state == NULL) return NULL;
    luaL_openlib(lmc->lua_state, "mtev", web_lua_funcs, 0);

    for(module = conf->Cpreloads; module && *module; module++) {
      int len;
      char *symbol = NULL;
      len = strlen(*module) + strlen("luaopen_");
      symbol = malloc(len+1);
      if(!symbol) mtevL(mtev_error, "Failed to preload %s: malloc error\n", *module);
      else {
        void (*f)(lua_State *);
        snprintf(symbol, len+1, "luaopen_%s", *module);
#ifdef RTLD_DEFAULT
        f = dlsym(RTLD_DEFAULT, symbol);
#else
        f = dlsym((void *)0, symbol);
#endif
        if(!f) mtevL(mtev_error, "Failed to preload %s: %s not found\n", *module, symbol);
        else f(lmc->lua_state);
      }
      free(symbol);
    }
  }
  return lmc;
}

static int
mtev_lua_web_driver_init(mtev_dso_generic_t *self) {
  if(mtev_lua_web_setup_lmc(self) == NULL) return -1;

  dso_post_init_hook_register("web_lua", late_stage_rest_register, self);
  return 0;
}

#include "lua_web.xmlh"

mtev_dso_generic_t lua_web = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "lua_web",
    .description = "web services in lua",
    .xml_description = lua_web_xml_description,
    .onload = mtev_lua_web_driver_onload
  },
  mtev_lua_web_driver_config,
  mtev_lua_web_driver_init
};
