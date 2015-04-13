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
#include "mtev_reverse_socket.h"

#define LUA_COMPAT_MODULE
#include "lua_mtev.h"
#include <assert.h>

#define MTEV_LUA_REPL_USERDATA "mtev::state::lua_repl"

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;
static int mtev_lua_general_init(mtev_dso_generic_t *);

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
  mtev_boolean concurrent;
  mtev_boolean booted;
} lua_general_conf_t;

static lua_general_conf_t *get_config(mtev_dso_generic_t *self) {
  lua_general_conf_t *conf = mtev_image_get_userdata(&self->hdr);
  if(conf) return conf;
  conf = calloc(1, sizeof(*conf));
  pthread_key_create(&conf->key, NULL);
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

static int
lua_general_resume(mtev_lua_resume_info_t *ri, int nargs) {
  const char *err = NULL;
  int status, base, rv = 0;

  assert(pthread_equal(pthread_self(), ri->bound_thread));

#if LUA_VERSION_NUM >= 502
  status = lua_resume(ri->coro_state, ri->lmc->lua_state, nargs);
#else
  status = lua_resume(ri->coro_state, nargs);
#endif

  switch(status) {
    case 0: break;
    case LUA_YIELD:
      lua_gc(ri->coro_state, LUA_GCCOLLECT, 0);
      return 0;
    default: /* The complicated case */
      base = lua_gettop(ri->coro_state);
      if(base>=0) {
        if(lua_isstring(ri->coro_state, base-1)) {
          err = lua_tostring(ri->coro_state, base-1);
          mtevL(nlerr, "err -> %s\n", err);
        }
      }
      rv = -1;
  }

  lua_general_ctx_free(ri);
  return rv;
}

static mtev_lua_resume_info_t *
lua_general_new_resume_info(lua_module_closure_t *lmc) {
  mtev_lua_resume_info_t *ri;
  ri = calloc(1, sizeof(*ri));
  assert(pthread_equal(lmc->owner, pthread_self()));
  ri->bound_thread = lmc->owner;
  ri->context_magic = LUA_GENERAL_INFO_MAGIC;
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

static int
lua_general_handler(mtev_dso_generic_t *self) {
  int status, rv;
  lua_general_conf_t *conf = get_config(self);
  lua_module_closure_t *lmc = pthread_getspecific(conf->key);
  mtev_lua_resume_info_t *ri = NULL;
  const char *err = NULL;
  char errbuf[128];
  lua_State *L;

  if(!lmc) mtev_lua_general_init(self);
  lmc = pthread_getspecific(conf->key);
  if(!lmc || !conf || !conf->module || !conf->function) {
    goto boom;
  }
  ri = lua_general_new_resume_info(lmc);
  L = ri->coro_state;

  lua_getglobal(L, "require");
  lua_pushstring(L, conf->module);
  rv = lua_pcall(L, 1, 1, 0);
  if(rv) {
    int i;
    mtevL(nlerr, "lua: require %s failed\n", conf->module);
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

  mtev_lua_pushmodule(L, conf->module);
  if(lua_isnil(L, -1)) {
    lua_pop(L, 1);
    snprintf(errbuf, sizeof(errbuf), "no such module: '%s'", conf->module);
    err = errbuf;
    goto boom;
  }
  lua_getfield(L, -1, conf->function);
  lua_remove(L, -2);
  if(!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    snprintf(errbuf, sizeof(errbuf), "no function '%s' in module '%s'",
             conf->function, conf->module);
    err = errbuf;
    goto boom;
  }

  status = lmc->resume(ri, 0);
  if(status == 0) return 0;
  /* If we've failed, resume has freed ri, so we should just return. */
  mtevL(nlerr, "lua dispatch error: %d\n", status);
  return 0;

 boom:
  if(err) mtevL(nlerr, "lua dispatch error: %s\n", err);
  if(ri) lua_general_ctx_free(ri);
  return 0;
}

static int
lua_general_coroutine_spawn(lua_State *Lp) {
  int nargs;
  lua_State *L;
  mtev_lua_resume_info_t *ri_parent = NULL, *ri = NULL;

  nargs = lua_gettop(Lp);
  if(nargs < 1 || !lua_isfunction(Lp,1))
    luaL_error(Lp, "mtev.coroutine_spawn(func, ...): bad arguments");
  ri_parent = mtev_lua_get_resume_info(Lp);
  assert(ri_parent);

  ri = lua_general_new_resume_info(ri_parent->lmc);
  L = ri->coro_state;
  lua_xmove(Lp, L, nargs);
#if !defined(LUA_JITLIBNAME) && LUA_VERSION_NUM < 502
  lua_setlevel(Lp, L);
#endif
  ri->lmc->resume(ri, nargs-1);
  return 0;
}

int
dispatch_general(eventer_t e, int mask, void *cl, struct timeval *now) {
  return lua_general_handler((mtev_dso_generic_t *)cl);
}

static int
mtev_lua_general_config(mtev_dso_generic_t *self, mtev_hash_table *o) {
  const char *bstr;
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

static const luaL_Reg general_lua_funcs[] =
{
  {"coroutine_spawn", lua_general_coroutine_spawn },
  {"reverse_start", lua_general_reverse_socket_initiate },
  {"reverse_stop", lua_general_reverse_socket_shutdown },
  {"conf_save", lua_general_conf_save },
  {"conf_mark_changed", lua_general_conf_mark_changed },
  {NULL,  NULL}
};


static int
mtev_lua_general_init(mtev_dso_generic_t *self) {
  lua_general_conf_t *conf = get_config(self);
  lua_module_closure_t *lmc = pthread_getspecific(conf->key);

  if(lmc) return 0;

  if(!lmc) {
    lmc = calloc(1, sizeof(*lmc));
    pthread_setspecific(conf->key, lmc);
  }

  if(!conf->module || !conf->function) {
    mtevL(nlerr, "lua_general cannot be used without module and function config\n");
    return -1;
  }

  lmc->resume = lua_general_resume;
  lmc->owner = pthread_self();
  lmc->eventer_id = eventer_is_loop(lmc->owner);
  lmc->lua_state = mtev_lua_open(self->hdr.name, lmc,
                                 conf->script_dir, conf->cpath);
  mtevL(nldeb, "lua_general opening state -> %p\n", lmc->lua_state);
  if(lmc->lua_state == NULL) {
    mtevL(mtev_error, "lua_general could not add general functions\n");
    return -1;
  }
  luaL_openlib(lmc->lua_state, "mtev", general_lua_funcs, 0);
  lmc->pending = calloc(1, sizeof(*lmc->pending));

  if(conf->booted) return true;
  conf->booted = mtev_true;
  eventer_add_in_s_us(dispatch_general, self, 0, 0);

  if(conf->concurrent) {
    int i = 1;
    pthread_t tgt, thr;
    thr = eventer_choose_owner(i++);
    do {
      eventer_t e = eventer_alloc();
      tgt = eventer_choose_owner(i++);
      e->thr_owner = tgt;
      e->callback = dispatch_general;
      e->closure = self;
      e->mask = EVENTER_TIMER;
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
lua_repl_raw_off(mtev_console_state_t *state, mtev_console_closure_t ncct) {
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
  rv = lua_pcall(L, 2, LUA_MULTRET, -4);
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
    ncct->e->thr_owner = eventer_choose_owner(atoi(argv[0]));
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
  int path_len, max_len;
  lua_general_conf_t *conf;
  lua_module_closure_t *lmc;

  el_get(el, EL_USERDATA, (void *)&ncct);
  if(!ncct) return tl;
  info = mtev_console_userdata_get(ncct, MTEV_LUA_REPL_USERDATA);
  if(!info) return tl;

  conf = get_config(info->self);
  lmc = pthread_getspecific(conf->key);

  if(!pthread_equal(ncct->e->thr_owner, pthread_self()))
    snprintf(info->prompt, sizeof(info->prompt), "lua_general(...)# ");
  else
    snprintf(info->prompt, sizeof(info->prompt), tl, get_eventer_id(ncct), lmc->lua_state);
  return info->prompt;
}

static void
mtev_lua_general_register_console_commands(mtev_image_t *self) {
  mtev_console_state_t *tl, *luas;
  cmd_info_t *showcmd;

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
  nlerr = mtev_log_stream_find("error/lua");
  nldeb = mtev_log_stream_find("debug/lua");
  if(!nlerr) nlerr = mtev_stderr;
  if(!nldeb) nldeb = mtev_debug;
  mtev_lua_context_describe(LUA_GENERAL_INFO_MAGIC, describe_lua_general_context);
  mtev_lua_general_register_console_commands(self);
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
    mtev_lua_general_onload
  },
  mtev_lua_general_config,
  mtev_lua_general_init
};
