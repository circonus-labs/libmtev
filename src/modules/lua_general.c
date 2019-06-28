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

#include "mtev_dso.h"
#include "mtev_http.h"
#include "mtev_rest.h"
#include "mtev_stats.h"
#include "mtev_perftimer.h"
#include "mtev_reverse_socket.h"

#define LUA_COMPAT_MODULE
#include "lua_mtev.h"
#include <dlfcn.h>
#include <ctype.h>

#define nldeb mtev_lua_debug_ls
#define nlerr mtev_lua_error_ls

#define MTEV_LUA_REPL_USERDATA "mtev::state::lua_repl"

static int general_loaded = 0;
static int mtev_lua_general_init(mtev_dso_generic_t *);
static mtev_hash_table hookinfo;
static pthread_mutex_t hookinfo_lock = PTHREAD_MUTEX_INITIALIZER;
static mtev_hash_table lua_ctypes;
static stats_handle_t *vm_time;

#define VM_TIME_BEGIN \
  mtev_perftimer_t timer; \
  mtev_perftimer_start(&timer);

#define VM_TIME_END \
  stats_set_hist_intscale(vm_time, mtev_perftimer_elapsed(&timer), -9, 1);


typedef struct mtev_lua_repl_userdata_t {
  mtev_dso_generic_t *self;
  char prompt[40];
} mtev_lua_repl_userdata_t;

typedef struct lua_general_conf {
  pthread_key_t key;
  const char *script_dir;
  const char *cpath;
  const char *module;
  const char *function;
  const char **Cpreloads;
  const char **preloads;
  lua_module_gc_params_t *gc_params;
  mtev_boolean concurrent;
  mtev_boolean booted;
  mtev_boolean tragedy_terminates;
} lua_general_conf_t;

static lua_general_conf_t *get_config(mtev_dso_generic_t *self) {
  lua_general_conf_t *conf = mtev_image_get_userdata(&self->hdr);
  if(conf) return conf;
  conf = calloc(1, sizeof(*conf));
  pthread_key_create(&conf->key, (void (*)(void *))mtev_lua_lmc_free);
  mtev_image_set_userdata(&self->hdr, conf);
  return conf;
}

static void
lua_general_ctx_free(void *cl) {
  mtev_lua_resume_info_t *ri = cl;
  if(ri) {
    mtevL(nldeb, "lua_general(%p) -> stopping job (%p)\n",
          ri->lmc->lua_state, ri->coro_state);
    mtev_lua_cancel_coro(ri);
    mtev_lua_resume_clean_events(ri);
    free(ri);
  }
}

static void
tragic_failure(mtev_dso_generic_t *self) {
  lua_general_conf_t *conf = get_config(self);
  if(conf->tragedy_terminates) {
    mtevL(mtev_error, "Unrecoverable run-time error. Terminating.\n");
    exit(-1);
  }
}

static int
lua_general_resume(mtev_lua_resume_info_t *ri, int nargs) {
  const char *err = NULL;
  int status, base, rv = 0;

  mtevAssert(pthread_equal(pthread_self(), ri->bound_thread));

  VM_TIME_BEGIN
#if LUA_VERSION_NUM >= 502
  status = lua_resume(ri->coro_state, ri->lmc->lua_state, nargs);
#else
  status = lua_resume(ri->coro_state, nargs);
#endif
  VM_TIME_END

  switch(status) {
    case 0: break;
    case LUA_YIELD:
      mtev_lua_gc(ri->lmc);
      return 0;
    default: /* The complicated case */
      mtevL(nlerr, "lua coro resume failed: %d\n", status);
      base = lua_gettop(ri->coro_state);
      if(base>0) {
        mtev_lua_traceback(ri->coro_state);
        base = lua_gettop(ri->coro_state);
        if(lua_isstring(ri->coro_state, base)) {
          err = lua_tostring(ri->coro_state, base);
          mtevL(nlerr, "lua error: %s\n", err);
        }
      }
      tragic_failure(ri->lmc->self);
      rv = -1;
  }

  lua_general_ctx_free(ri);
  return rv;
}

static mtev_lua_resume_info_t *
lua_general_new_resume_info(lua_module_closure_t *lmc) {
  mtev_lua_resume_info_t *ri = mtev_lua_new_resume_info(lmc, LUA_GENERAL_INFO_MAGIC);
  ri->new_ri_f = lua_general_new_resume_info;
  return ri;
}

static int
lua_general_handler_ex(mtev_dso_generic_t *self,
                      const char *module, const char *function) {
  char errbuf[128];
  int status, rv;
  const char *err = NULL;
  mtev_lua_resume_info_t *ri = NULL;
  lua_State *L;
  lua_general_conf_t *conf = get_config(self);
  if (!conf) {
    goto boom;
  }

  lua_module_closure_t *lmc = pthread_getspecific(conf->key);

  if(!lmc) mtev_lua_general_init(self);
  lmc = pthread_getspecific(conf->key);

  if(!lmc || !module || !function) {
    goto boom;
  }
  ri = lua_general_new_resume_info(lmc);
  L = ri->coro_state;

  lua_getglobal(L, "require");
  lua_pushstring(L, module);
  VM_TIME_BEGIN
  rv = lua_pcall(L, 1, 1, 0);
  VM_TIME_END
  if(rv) {
    int i;
    mtevL(nlerr, "lua: require %s failed\n", module);
    mtev_lua_traceback(L);
    i = lua_gettop(L);
    if(i>0) {
      if(lua_isstring(L, i)) {
        const char *err;
        size_t len;
        err = lua_tolstring(L, i, &len);
        mtevL(nlerr, "lua: %s\n", err);
      }
    }
    lua_pop(L,i);
    goto boom;
  }
  lua_pop(L, lua_gettop(L));

  mtev_lua_pushmodule(L, module);
  if(lua_isnil(L, -1)) {
    lua_pop(L, 1);
    snprintf(errbuf, sizeof(errbuf), "no such module: '%s'", module);
    err = errbuf;
    goto boom;
  }
  lua_getfield(L, -1, function);
  lua_remove(L, -2);
  if(!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    snprintf(errbuf, sizeof(errbuf), "no function '%s' in module '%s'",
             function, module);
    err = errbuf;
    goto boom;
  }

  status = lmc->resume(ri, 0);
  if(status == 0) return 0;
  /* If we've failed, resume has freed ri, so we should just return. */
  mtevL(nlerr, "lua dispatch error: %d\n", status);
  tragic_failure(self);
  return 0;

 boom:
  if(err) mtevL(nlerr, "lua dispatch error: %s\n", err);
  if(ri) lua_general_ctx_free(ri);
  tragic_failure(self);
  return 0;
}

static int
lua_general_handler(mtev_dso_generic_t *self) {
  lua_general_conf_t *conf = get_config(self);
  return lua_general_handler_ex(self, conf->module, conf->function);
}

static int
lua_general_coroutine_spawn(lua_State *Lp) {
  return mtev_lua_coroutine_spawn(Lp, lua_general_new_resume_info);
}

int
dispatch_general(eventer_t e, int mask, void *cl, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  return lua_general_handler((mtev_dso_generic_t *)cl);
}

static int
mtev_lua_general_config(mtev_dso_generic_t *self, mtev_hash_table *o) {
  const char *bstr, *tt_val;
  lua_general_conf_t *conf = get_config(self);
  conf->script_dir = NULL;
  conf->cpath = NULL;
  conf->module = NULL;
  conf->function = NULL;
  (void)mtev_hash_retr_str(o, "directory", strlen("directory"), &conf->script_dir);
  if(conf->script_dir) conf->script_dir = strdup(conf->script_dir);
  (void)mtev_hash_retr_str(o, "cpath", strlen("cpath"), &conf->cpath);
  if(conf->cpath) conf->cpath = strdup(conf->cpath);
  (void)mtev_hash_retr_str(o, "lua_module", strlen("lua_module"), &conf->module);
  if(conf->module) conf->module = strdup(conf->module);
  (void)mtev_hash_retr_str(o, "lua_function", strlen("lua_function"), &conf->function);
  if(conf->function) conf->function = strdup(conf->function);
  if(mtev_hash_retr_str(o, "concurrent", strlen("concurrent"), &bstr)) {
    if(!strcasecmp(bstr, "on") || !strcasecmp(bstr, "true")) {
      conf->concurrent = mtev_true;
    }
  }
  conf->tragedy_terminates = mtev_false;
  if(mtev_hash_retr_str(o, "tragedy_terminates", strlen("tragedy_terminates"),
                        &tt_val)) {
    if(!strcasecmp(tt_val, "true") || !strcasecmp(tt_val, "yes"))
      conf->tragedy_terminates = mtev_true;
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

  if(mtev_hash_retr_str(o, "preloads", strlen("preloads"), &bstr)) {
    int count = 1, i;
    char *brk = NULL, *cp, *copy;
    cp = copy = strdup(bstr);
    while(*cp) if(*cp++ == ',') count++; /* count terms (start with 1) */
    conf->preloads = calloc(count+1, sizeof(char *)); /* null term */
    for(i = 0, cp = strtok_r(copy, ",", &brk);
        cp; cp = strtok_r(NULL, ",", &brk), i++) {
      conf->preloads[i] = strdup(cp);
    }
    free(copy);
  }

  conf->gc_params = mtev_lua_config_gc_params(o);
  return 0;
}

static int
lua_general_reverse_socket_initiate(lua_State *L) {
  const char *host;
  int port;
  mtev_hash_table *sslconfig = NULL, *config = NULL;
  if(lua_gettop(L) < 2 ||
     !lua_isstring(L,1) ||
     !lua_isnumber(L,2) ||
     (lua_gettop(L) >= 3 && !lua_istable(L,3)) ||
     (lua_gettop(L) >= 4 && !lua_istable(L,4)))
    luaL_error(L, "reverse_start(host,port,sslconfig,config)");

  host = lua_tostring(L,1);
  port = lua_tointeger(L,2);
  if(lua_gettop(L)>=3) sslconfig = mtev_lua_table_to_hash(L,3);
  if(lua_gettop(L)>=4) config = mtev_lua_table_to_hash(L,4);

  mtev_lua_help_initiate_mtev_connection(host, port, sslconfig, config);

  if(sslconfig) {
    mtev_hash_destroy(sslconfig, NULL, NULL);
    free(sslconfig);
  }
  if(config) {
    mtev_hash_destroy(config, NULL, NULL);
    free(config);
  }
  return 0;
}
static int
lua_general_reverse_socket_shutdown(lua_State *L) {
  int rv;
  if(lua_gettop(L) < 2 ||
     !lua_isstring(L,1) ||
     !lua_isnumber(L,2))
    luaL_error(L, "reverse_stop(host,port)");

  rv = mtev_reverse_socket_connection_shutdown(lua_tostring(L,1), lua_tointeger(L,2));
  lua_pushboolean(L,rv);
  return 1;
}

static int
lua_general_conf_mark_changed(lua_State *L) {
  (void)L;
  mtev_conf_mark_changed();
  return 0;
}

static int
lua_general_conf_save(lua_State *L) {
  /* Invert the response to indicate a truthy success in lua */
  lua_pushboolean(L, mtev_conf_write_file(NULL) ? 0 : 1);
  return 1;
}

void
mtev_lua_register_dynamic_ctype_impl(const char *type_name, mtev_lua_push_dynamic_ctype_t func) {
  if(!general_loaded) return;
  mtev_hash_replace(&lua_ctypes, strdup(type_name), strlen(type_name),
                    func, free, NULL);
}

#define HOOK_EXTENSION_INVOKE 0
#define HOOK_EXTENSION_EXISTS 1
#define HOOK_EXTENSION_PROTO 2
#define HOOK_EXTENSION_REGISTER 3
#define HOOK_EXTENSIONS_CNT 4
static const char *hook_exts[HOOK_EXTENSIONS_CNT] = {
  "_hook_invoke",
  "_hook_exists",
  "_hook_proto",
  "_hook_register"
};

typedef struct {
  char *name;
  const char *proto;
  mtev_dso_generic_t *self;
  mtev_hash_table hooks;
} lua_hook_info_t;

static void
ptrim(char *orig, mtev_boolean *is_ptr) {
  int trimming = 1;
  int parens = 0;
  char *in = orig, *out = orig;
  if(is_ptr) *is_ptr = mtev_false;
  if(*orig == '\0') return;
  /* remove front and compress interstitial space */
  while(*in) {
    if(isspace(*in)) {
      if(!trimming) {
        *out++ = ' ';
        trimming = 1;
      }
    } else {
      /* not pointers */
      if(*in == '*' && is_ptr) *is_ptr = mtev_true;
      trimming = 0;
      if(*in == '(') trimming = 1;
      /* note parens */
      if(*in == ')' && out > orig && out[-1] == ' ') {
        parens = 1;
        out--;
      }
      *out++ = *in;
    }
    in++;
  }
  *out = '\0';
  /* remove trailing whitespace */
  if(out > orig && out[-1] == ' ') {
    out--;
  }
  /* move in to the "end" or prior to the first ')' */
  if(parens) in = strchr(orig, ')') - 1;
  else in = out;
  out = in - 1;
  while(*out && out > orig) {
    if(*out == '(') return; /* indicates a broken hook prototype */
    if(isspace(*out) || *out == '*') {
      out++;
      break;
    }
    out--;
  }
  while(*in) {
    *out++ = *in++;
  }
  *out = '\0';
}
#define MAX_VARARGS 10
static int
lua_hook_varargs(lua_State *L, const char *proto, va_list ap) {
  unsigned int clen, i = 0, nargs = 0;
  char copy[1024], *cp;
  char *args[MAX_VARARGS];
  mtevL(nldeb, "hook proto -> %s\n", proto);

  /* is it wrapped in () and short enough */
  if(*proto != '(') return -1;
  clen = strlen(proto);
  if(proto[clen-1] != ')') return -1;
  if(clen > sizeof(copy)) return -1;
  memcpy(copy, proto+1, clen-2);
  clen -= 2;
  copy[clen] = '\0';

  mtevL(nldeb, "extracting hook prototype args\n");
  /* extract args */
  cp = copy;
  while(*cp && nargs<MAX_VARARGS)  {
    int paren_cnt = 0;
    args[nargs++] = cp;
    while(*cp) {
      if(*cp == ',' && paren_cnt == 0) break;
      if(*cp == '(') paren_cnt++;
      if(*cp == ')') paren_cnt--;
      cp++;
    }
    if(*cp == ',') {
      *cp++ = '\0';
    }
  }

  /* The first are is void *closure, so we need at least one more */
  if(nargs < 2) return 0;

#define IFVTYPE(str, type, var) \
    if(!strcmp(args[i],str)) { \
      type var = va_arg(ap, type);
#define IFVTYPE_END() }

  /* normalize && convert and push, starting after our closure */
  for(i=1; i<nargs; i++) {
    void *vfunc;
    mtev_boolean is_ptr;
    ptrim(args[i], &is_ptr);
    mtevL(nldeb, "args[%d] %s-> '%s'\n", i, is_ptr ? "(ptr) " : "", args[i]);
    IFVTYPE("char *", char *, str)
      lua_pushstring(L, str);
    IFVTYPE_END()
    else IFVTYPE("const char *", char *, str)
      lua_pushstring(L, str);
    IFVTYPE_END()
    else if(mtev_hash_retrieve(&lua_ctypes, args[i], strlen(args[i]), &vfunc)) {
      mtev_lua_push_dynamic_ctype_t func = vfunc;
      func(L, ap);
      //mtev_lua_setup_http_ctx(L, ctx);
    } else {
      mtevL(nlerr, "unknown hook parameter type: '%s' consider mtev_lua_register_dynamic_ctype(...)\n", args[i]);
      if(is_ptr) {
        void *ptr = va_arg(ap, void *);
        lua_pushlightuserdata(L,ptr);
      } else {
        lua_pushnil(L);
      }
    }
  }
  return nargs - 1;
}
/* This calls all registered lua functions for a hook
 * if there is an error, the call is as if it did nothing
 * and returned MTEV_HOOK_CONTINUE.
 */
static mtev_hook_return_t
lua_hook_vahandler(void *closure, ...) {
  mtev_hook_return_t hook_rv = MTEV_HOOK_CONTINUE;
  int rv;
  va_list ap_top;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  lua_hook_info_t *lhi = closure;
  lua_general_conf_t *conf = get_config(lhi->self);
  lua_module_closure_t *lmc;
  mtevL(nldeb, "lua hook %s\n", lhi->name);

  lua_State *L;
  lmc = pthread_getspecific(conf->key);
  if(!lmc) {
    mtev_lua_general_init(lhi->self);
    lmc = pthread_getspecific(conf->key);
  }
  if(!lmc) {
    mtevL(nlerr, "Failed to load lua_general on thread.\n");
    return MTEV_HOOK_CONTINUE;
  }
  L = lmc->lua_state;

  va_start(ap_top, closure);
  while(mtev_hash_adv(&lhi->hooks, &iter)) {
    const char *module = iter.key.str;
    const char *function = module + strlen(module) + 1;
    mtevL(nldeb, "lua hook %s -> %s\n", module, function);
    va_list ap;

    lua_getglobal(L, "require");
    lua_pushstring(L, module);
    {
    VM_TIME_BEGIN
    rv = lua_pcall(L, 1, 1, 0);
    VM_TIME_END
    }
    if(rv) {
      int i;
      mtevL(nlerr, "lua: require %s failed\n", module);
      mtev_lua_traceback(L);
      i = lua_gettop(L);
      if(i>0 && lua_isstring(L, i)) mtevL(nlerr, "lua: %s\n", lua_tostring(L, i));
      lua_pop(L,i);
      continue;
    }
    lua_pop(L, lua_gettop(L));

    mtev_lua_pushmodule(L, module);
    if(lua_isnil(L, -1)) {
      lua_pop(L, 1);
      mtevL(nlerr, "no such module: '%s'", module);
      continue;
    }
    lua_getfield(L, -1, function);
    lua_remove(L, -2);
    if(!lua_isfunction(L, -1)) {
      lua_pop(L, 1);
      mtevL(nlerr, "no function '%s' in module '%s'", function, module);
      continue;
    }

    va_copy(ap, ap_top);
    int nargs = lua_hook_varargs(L, lhi->proto, ap);
    va_end(ap);

    if(nargs < 0) {
      mtevL(nlerr, "failed to parse hook proto '%s'\n", lhi->proto);
      continue;
    }

    mtevL(nldeb, "calling lua hook %s in %s\n", function, module);
    {
    VM_TIME_BEGIN
    rv = lua_pcall(L, nargs, 1, 0);
    VM_TIME_END
    }
    if(rv) {
      int i;
      mtev_lua_traceback(L);
      i = lua_gettop(L);
      if(i>0 && lua_isstring(L, i)) mtevL(nlerr, "lua: %s\n", lua_tostring(L, i));
      lua_pop(L,i);
      continue;
    }
    if(lua_gettop(L) == 1) {
      hook_rv = lua_tointeger(L,1);
      lua_pop(L,1);
      if(hook_rv != MTEV_HOOK_CONTINUE) break;
    }
  }
  va_end(ap_top);
  return hook_rv;
}

static int
lua_general_hook(lua_State *L) {
  int i;
  char symbol[1024];
  void *f[HOOK_EXTENSIONS_CNT] = { NULL };

  if(lua_gettop(L) != 1 && lua_gettop(L) != 3) {
    luaL_error(L, "mtev.hook(name,[\"func_name\"])");
  }

  /* Verify the request is a hook point */
  const char *basename = lua_tostring(L,1);
  for(i=0; i<HOOK_EXTENSIONS_CNT; i++) {
    snprintf(symbol, sizeof(symbol), "%s%s", basename, hook_exts[i]);
#ifdef RTLD_DEFAULT
    f[i] = dlsym(RTLD_DEFAULT, symbol);
#else
    f[i] = dlsym((void *)0, symbol);
#endif
    if(!f[i]) {
      mtevL(mtev_error, "symbol not found: %s\n", symbol);
      break;
    }
  }
  if(lua_gettop(L) == 1) {
    lua_pushboolean(L, i == HOOK_EXTENSIONS_CNT);
    return 1;
  }
  const char *module = lua_tostring(L,2);
  const char *func_name = lua_tostring(L,3);
  if(i != HOOK_EXTENSIONS_CNT) luaL_error(L, "hook not valid");

  /* we need the lmc to get a point to self */
  lua_module_closure_t *lmc;
  lua_getglobal(L, "mtev_internal_lmc");;
  lmc = lua_touserdata(L, lua_gettop(L));

  int klen = strlen(module)+1;
  char *combined = malloc(klen + strlen(func_name) + 1);
  memcpy(combined, module, klen);
  memcpy(combined + klen, func_name, strlen(func_name) + 1);
  klen += strlen(func_name) + 1;
  /* f is now the register call */
  pthread_mutex_lock(&hookinfo_lock);
  void *vlhi;
  lua_hook_info_t *lhi;
  if(mtev_hash_retrieve(&hookinfo, basename, strlen(basename), &vlhi)) {
    lhi = vlhi;
  } else {
    lhi = calloc(1, sizeof(*lhi));
    lhi->name = strdup(basename);
    lhi->self = lmc->self;
    mtev_hash_init(&lhi->hooks);
    mtev_hash_store(&hookinfo, lhi->name, strlen(lhi->name), lhi);
    snprintf(symbol, sizeof(symbol), "lua/%s", basename);

    void (*fcall)(const char *, mtev_hook_return_t (*)(void *, ...), void *);
    const char *(*protocall)(void);

    fcall = f[HOOK_EXTENSION_REGISTER];
    fcall(symbol, lua_hook_vahandler, lhi);

    protocall = f[HOOK_EXTENSION_PROTO];
    lhi->proto = protocall();
  }
  mtev_hash_replace(&lhi->hooks, combined, klen, NULL, free, NULL);
  pthread_mutex_unlock(&hookinfo_lock);
  lua_pushboolean(L, 1);
  return 1;
}

static const luaL_Reg general_lua_funcs[] =
{
  {"coroutine_spawn", lua_general_coroutine_spawn },
  {"reverse_start", lua_general_reverse_socket_initiate },
  {"reverse_stop", lua_general_reverse_socket_shutdown },
  {"conf_save", lua_general_conf_save },
  {"conf_mark_changed", lua_general_conf_mark_changed },
  {"hook", lua_general_hook },
  {NULL,  NULL}
};

static int
mtev_lua_general_init(mtev_dso_generic_t *self) {
  const char * const *module;
  int (*f)(lua_State *);
  lua_general_conf_t *conf = get_config(self);
  lua_module_closure_t *lmc = pthread_getspecific(conf->key);

  if(lmc) return 0;

  stats_ns_t *lua_stats_ns = mtev_stats_ns(mtev_stats_ns(mtev_stats_ns(NULL, "mtev"), "modules"), "lua");
  vm_time = stats_register(lua_stats_ns, "vm_invocation_runtime", STATS_TYPE_HISTOGRAM_FAST);
  stats_handle_add_tag(vm_time, "operation", "vm-invoke");
  stats_handle_tagged_name(vm_time, "runtime");
  stats_handle_units(vm_time, STATS_UNITS_SECONDS);

  if(!lmc) {
    lmc = mtev_lua_lmc_alloc(self, lua_general_resume);
    mtev_lua_set_gc_params(lmc, conf->gc_params);
    pthread_setspecific(conf->key, lmc);
  }

  if(!conf->module || !conf->function) {
    mtevL(nlerr, "lua_general cannot be used without module and function config\n");
    return -1;
  }

  lmc->lua_state = mtev_lua_open(self->hdr.name, lmc,
                                 conf->script_dir, conf->cpath);
  mtevL(nldeb, "lua_general opening state -> %p\n", lmc->lua_state);
  if(lmc->lua_state == NULL) {
    mtevL(mtev_error, "lua_general could not add general functions\n");
    return -1;
  }
  luaL_openlib(lmc->lua_state, "mtev", general_lua_funcs, 0);
  /* Load some preloads */

  for(module = conf->Cpreloads; module && *module; module++) {
    int len;
    char *symbol = NULL;
    len = strlen(*module) + strlen("luaopen_");
    symbol = malloc(len+1);
    if(!symbol) mtevL(nlerr, "Failed to preload %s: malloc error\n", *module);
    else {
      snprintf(symbol, len+1, "luaopen_%s", *module);
#ifdef RTLD_DEFAULT
      f = dlsym(RTLD_DEFAULT, symbol);
#else
      f = dlsym((void *)0, symbol);
#endif
      if(!f) mtevL(nlerr, "Failed to preload %s: %s not found\n", *module, symbol);
      else f(lmc->lua_state);
    }
    free(symbol);
  }

  for(module = conf->preloads; module && *module; module++) {
    int rv;
    lua_getglobal(lmc->lua_state, "require");
    lua_pushstring(lmc->lua_state, *module);
    rv = lua_pcall(lmc->lua_state, 1, 0, 0);
    if(rv) {
      mtevL(mtev_error, "preloads: require %s failed: %s\n", *module, lua_tostring(lmc->lua_state, -1));
    }
  }
  lua_settop(lmc->lua_state, 0);

  if(conf->booted) return true;
  conf->booted = mtev_true;
  eventer_add_in_s_us(dispatch_general, self, 0, 0);

  if(conf->concurrent) {
    int i = 1;
    pthread_t tgt, thr;
    thr = eventer_choose_owner(i++);
    do {
      eventer_t e = eventer_in_s_us(dispatch_general, self, 0, 0);
      tgt = eventer_choose_owner(i++);
      eventer_set_owner(e, tgt);
      eventer_add(e);
    } while(!pthread_equal(thr,tgt));
  }
  return 0;
}

static void
describe_lua_general_context(mtev_console_closure_t ncct,
                             mtev_lua_resume_info_t *ri) {
  nc_printf(ncct, "lua_general(state:%p, parent:%p)\n",
            ri->coro_state, ri->lmc->lua_state);
}
static void
describe_lua_general_context_json(mtev_json_object *jcoro,
                                  mtev_lua_resume_info_t *ri) {
  char buff[32];
  snprintf(buff, sizeof(buff), "%p", ri->coro_state);
  MJ_KV(jcoro, "state", MJ_STR(buff));
  snprintf(buff, sizeof(buff), "%p", ri->lmc->lua_state);
  MJ_KV(jcoro, "parent", MJ_STR(buff));
}

static void
lua_repl_raw_off(mtev_console_state_t *state, mtev_console_closure_t ncct) {
  (void)state;
  mtev_console_userdata_set(ncct, MTEV_CONSOLE_RAW_MODE,
                            MTEV_CONSOLE_RAW_MODE_OFF, NULL);
}
static void
lua_repl_userdata_free(void *data) {
  mtev_lua_repl_userdata_t *info = data;
  if(info) {
    free(info);
  }
}

static int
mtev_lua_ncct_print(lua_State *L) {
  mtev_console_closure_t ncct;
  int i;
  ncct = lua_touserdata(L, lua_upvalueindex(1));
  for(i=1; i<=lua_gettop(L); i++) {
    if(i>1) nc_printf(ncct, "\t");
    nc_printf(ncct, "%s", lua_tostring(L,1));
  }
  nc_printf(ncct, "\n");
  return 0;
}
static int
lua_pushConsole(lua_State *L, mtev_console_closure_t ncct) {
  lua_pushlightuserdata(L, ncct);
  lua_pushcclosure(L, mtev_lua_ncct_print, 1);
  return 1;
}
static int
mtev_console_lua_repl_execute(mtev_console_closure_t ncct,
                              int argc, char **argv,
                              mtev_console_state_t *state, void *closure) {
  (void)state;
  (void)closure;
  lua_State *L;
  mtev_lua_repl_userdata_t *info;
  lua_general_conf_t *conf = NULL;
  lua_module_closure_t *lmc = NULL;
  char *buff;
  int i, rv;

  info = mtev_console_userdata_get(ncct, MTEV_LUA_REPL_USERDATA);
  if(info) {
    conf = get_config(info->self);
    lmc = pthread_getspecific(conf->key);
  }
  if(!lmc) {
    nc_printf(ncct, "Internal error, cannot find lua state.\n");
    return -1;
  }
#define EVALSIZE (1<<15)
  buff = malloc(EVALSIZE);
  buff[0] = '\0';
  for(i=0;i<argc;i++) {
    if(i) strlcat(buff, " ", EVALSIZE);
    strlcat(buff, argv[i], EVALSIZE);
  }

  L = lmc->lua_state;
  lua_pushConsole(L, ncct);
  lua_getglobal(L, "mtev");
  lua_getfield(L, -1, "extras");
  lua_remove(L, -2);  /* pop mtev */
  lua_getfield(L, -1, "repl_eval");
  lua_remove(L, -2);  /* pop extras */
  lua_pushstring(L, buff);
  lua_pushConsole(L, ncct);
  VM_TIME_BEGIN
  rv = lua_pcall(L, 2, LUA_MULTRET, -4);
  VM_TIME_END
  if(rv) {
    int i;
    i = lua_gettop(L);
    if(i>0) {
      if(lua_isstring(L, i)) {
        const char *err;
        size_t len;
        err = lua_tolstring(L, i, &len);
        nc_printf(ncct, "eval failed: %s\n", err);
      }
    }
    lua_pop(L, i);
    return -1;
  }
  lua_pop(L, lua_gettop(L));

  free(buff);
#undef EVALSIZE
  return 0;
}

static int
mtev_console_state_lua(mtev_console_closure_t ncct,
                       int argc, char **argv,
                       mtev_console_state_t *state, void *closure) {
  mtev_lua_repl_userdata_t *info;
  if(argc > 2) {
    nc_printf(ncct, "extra arguments not expected.\n");
    return -1;
  }
  if(argc) {
    eventer_set_owner(ncct->e, eventer_choose_owner(atoi(argv[0])));
  }
  info = calloc(1, sizeof(*info));
  info->self = (mtev_dso_generic_t *)closure;
  mtev_console_userdata_set(ncct, MTEV_CONSOLE_RAW_MODE,
                            MTEV_CONSOLE_RAW_MODE_ON, NULL);
  mtev_console_userdata_set(ncct, MTEV_LUA_REPL_USERDATA, info,
                            lua_repl_userdata_free);
  mtev_console_state_push_state(ncct, state);
  mtev_console_state_init(ncct);
  return 0;
}

static int
get_eventer_id(mtev_console_closure_t ncct) {
  (void)ncct;
  int idx = 0;
  pthread_t stop, tid;
  stop = eventer_choose_owner(idx);
  while(1) {
    tid = eventer_choose_owner(idx);
    if(pthread_equal(tid, pthread_self())) return idx;
    if(idx != 0 && pthread_equal(stop, tid)) break;
    idx++;
  }
  return -1;
}
static char *
lua_repl_prompt(EditLine *el) {
  mtev_console_closure_t ncct;
  mtev_lua_repl_userdata_t *info;
  static char *tl = "lua_general(%d/%p)# ";
  lua_general_conf_t *conf;
  lua_module_closure_t *lmc;

  el_get(el, EL_USERDATA, (void *)&ncct);
  if(!ncct) return tl;
  info = mtev_console_userdata_get(ncct, MTEV_LUA_REPL_USERDATA);
  if(!info) return tl;

  conf = get_config(info->self);
  lmc = pthread_getspecific(conf->key);

  if(!lmc || !pthread_equal(eventer_get_owner(ncct->e), pthread_self()))
    snprintf(info->prompt, sizeof(info->prompt), "lua_general(...)# ");
  else
    snprintf(info->prompt, sizeof(info->prompt), tl, get_eventer_id(ncct), lmc->lua_state);
  return info->prompt;
}

static void
mtev_lua_general_register_console_commands(mtev_image_t *self) {
  mtev_console_state_t *tl, *luas;

  tl = mtev_console_state_initial();
  luas = mtev_console_state_alloc_empty();

  luas->console_prompt_function = lua_repl_prompt;
  luas->statefree = lua_repl_raw_off;
  mtev_console_state_add_cmd(luas, &console_command_exit);

  mtev_console_state_add_cmd(luas,
    NCSCMD("",  mtev_console_lua_repl_execute, NULL, NULL, self));

  mtev_console_state_add_cmd(tl,
    NCSCMD("lua_general", mtev_console_state_lua, NULL, luas, self));
}
static int
mtev_lua_general_onload(mtev_image_t *self) {
  mtev_hash_init_locks(&lua_ctypes, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  mtev_hash_init(&hookinfo);
  nlerr = mtev_log_stream_find("error/lua");
  nldeb = mtev_log_stream_find("debug/lua");
  mtev_lua_context_describe(LUA_GENERAL_INFO_MAGIC,
                            describe_lua_general_context);
  mtev_lua_context_describe_json(LUA_GENERAL_INFO_MAGIC,
                                 describe_lua_general_context_json);
  mtev_lua_general_register_console_commands(self);
  general_loaded = 1;
  return 0;
}

#include "lua_general.xmlh"

mtev_dso_generic_t lua_general = {
  {
    MTEV_GENERIC_MAGIC,
    MTEV_GENERIC_ABI_VERSION,
    "lua_general",
    "general services in lua",
    lua_general_xml_description,
    mtev_lua_general_onload,
    0
  },
  mtev_lua_general_config,
  mtev_lua_general_init
};
