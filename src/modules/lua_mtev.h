/*
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
 *     * Neither the name Circonus, Inc. nor the names
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

#ifndef LUA_MTEV_H
#define LUA_MTEV_H

#include "mtev_defines.h"

#include <assert.h>
#include <openssl/x509.h>

#include "mtev_conf.h"
#include "mtev_dso.h"
#include "mtev_rest.h"
#include "mtev_log.h"
#include "mtev_json.h"
#include "mtev_hooks.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

typedef struct mtev_lua_resume_info mtev_lua_resume_info_t;

typedef int (*mtev_lua_resume_t)(mtev_lua_resume_info_t *info, int nargs);

typedef struct lua_module_gc_params lua_module_gc_params_t;

API_EXPORT(lua_module_gc_params_t *) mtev_lua_config_gc_params(mtev_hash_table *);

typedef struct lua_module_closure {
  lua_State *lua_state;
  mtev_hash_table *pending;
  mtev_lua_resume_t resume;
  pthread_t owner;
  int eventer_id;
  mtev_hash_table state_coros;
  mtev_dso_generic_t *self;
  lua_module_gc_params_t *gcparams;
  int ffi_index;
  timer_t _timer;
  timer_t *timer;
  struct timeval interrupt_time;
} lua_module_closure_t;

API_EXPORT(void) mtev_lua_set_gc_params(lua_module_closure_t *, lua_module_gc_params_t *);
API_EXPORT(void) mtev_lua_gc(lua_module_closure_t *);
API_EXPORT(void) mtev_lua_gc_full(lua_module_closure_t *);

API_EXPORT(void)
  mtev_luaL_traceback(void (*cb)(void *, const char *, size_t), void *closure,
                      lua_State *L1, const char *msg, int level);
/*! \fn lua_module_closure_t *mtev_lua_lmc_alloc(mtev_dso_generic_t *self, mtev_lua_resume_info_t *resume)
    \brief Allocated and initialize a `lua_module_closure_t` for a new runtime.
    \param self the module implementing a custom lua runtime environment
    \param resume the custom resume function for this environment
    \return a new allocated and initialized `lua_module_closure`

    > Note these are not thread safe because lua is not thread safe. If you are managing multiple
    > C threads, you should have a `lua_module_closure_t` for each thread and maintain them in a
    > thread-local fashion.  Also ensure that any use of the eventer does not migrate cross thread.
*/
API_EXPORT(lua_module_closure_t *)
  mtev_lua_lmc_alloc(mtev_dso_generic_t *self, mtev_lua_resume_t resume);

/*! \fn void mtev_lua_lmc_free(lua_module_closure_t *lmc)
    \brief Free a `lua_module_closure_t` structure that has been allocated.
    \param lmc The `lua_module_closure_t` to be freed.
*/
API_EXPORT(void)
  mtev_lua_lmc_free(lua_module_closure_t *lmc);

/*! \fn lua_State *mtev_lua_lmc_L(lua_module_closure_t *lmc)
    \brief Get the `lua_State *` for this module closure.
    \param lmc the `lua_module_closure_t` that was allocated for this runtime.
    \return a Lua state
*/
API_EXPORT(lua_State *)
  mtev_lua_lmc_L(lua_module_closure_t *lmc);

/*! \fn lua_State *mtev_lua_lmc_setL(lua_module_closure_t *lmc)
    \brief Set the `lua_State *` for this module closure, returning the previous value.
    \param lmc the `lua_module_closure_t` that was allocated for this runtime.
    \param lmc the `lua_State *` that should be placed in this closure.
    \return the previous lua Lua state associated with this closure
*/
API_EXPORT(lua_State *)
  mtev_lua_lmc_setL(lua_module_closure_t *lmc, lua_State *L);

/*! \fn int mtev_lua_lmc_resume(lua_module_closure_t *lmc, mtev_lua_resume_info_t *ri, int nargs)
    \brief Invoke lua_resume with the correct context based on the `lua_module_closure_t`
    \param lmc the `lua_module_closure_t` associated with the current lua runtime.
    \param ri resume meta information
    \param nargs the number of arguments on the lua stack to return
    \return the return value of the underlying `lua_resume` call.
*/
API_EXPORT(int)
  mtev_lua_lmc_resume(lua_module_closure_t *lmc, mtev_lua_resume_info_t *ri, int nargs);

struct mtev_lua_resume_info {
  pthread_t bound_thread;
  lua_module_closure_t *lmc;
  lua_State *coro_state;
  int coro_state_ref;
  mtev_hash_table *events; /* Any eventers we need to cleanup */
  int context_magic;
  void *context_data;
  struct mtev_lua_resume_info *(*new_ri_f)(lua_module_closure_t *);
};
#define LUA_GENERAL_INFO_MAGIC 0x918243fa

typedef struct mtev_lua_resume_rest_info {
  mtev_http_rest_closure_t *restc;
  char *err;
  int httpcode;
} mtev_lua_resume_rest_info_t;
#define LUA_REST_INFO_MAGIC 0x80443000

struct nl_generic_cl {
  void (*free)(void *);
};

struct nl_intcl {
  void (*free)(void *);
  mtev_lua_resume_info_t *ri;
};

typedef struct lua_timeout_callback_ref {
  void (*free)(void *);
  lua_State *L;
  int callback_reference;
  eventer_t timed_out_eventer;
} lua_timeout_callback_ref;

struct nl_slcl {
  void (*free)(void *);
  int send_size;
  struct timeval start, deadline;
  char *inbuff;
  int   inbuff_allocd;
  int   inbuff_len;
  size_t read_sofar;
  size_t read_goal;
  const char *read_terminator;
  size_t read_terminator_len;
  const char *outbuff;
  size_t write_sofar;
  size_t write_goal;
  eventer_t *eptr;
  eventer_t pending_event;
  eventer_t timeout_event;

  int sendto; /* whether this send is a sendto call */
  union {
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
  } address;
  struct spawn_info *spawn_info;

  lua_State *L;
};

void mtev_lua_context_describe(int magic,
                               void (*f)(mtev_console_closure_t,
                                         mtev_lua_resume_info_t *));
void mtev_lua_context_describe_json(int magic,
                               void (*j)(mtev_json_object *,
                                         mtev_lua_resume_info_t *));
const char *mtev_lua_type_name(int);
mtev_lua_resume_info_t *
  mtev_lua_new_resume_info(lua_module_closure_t *lmc, int magic);
int mtev_lua_coroutine_spawn(lua_State *Lp,
    mtev_lua_resume_info_t *(*new_ri_f)(lua_module_closure_t *));
lua_State *mtev_lua_open(const char *module_name, void *lmc,
                         const char *script_dir, const char *cpath);
void mtev_lua_init_globals(void);
void register_console_lua_commands(void);
int mtev_lua_resume(lua_State *L, int, mtev_lua_resume_info_t *);
int mtev_lua_pcall(lua_State *L, int, int, int);
int mtev_lua_traceback(lua_State *L);
void mtev_lua_new_coro(mtev_lua_resume_info_t *);
void mtev_lua_cancel_coro(mtev_lua_resume_info_t *ci);
void mtev_lua_resume_clean_events(mtev_lua_resume_info_t *ci);
void mtev_lua_pushmodule(lua_State *L, const char *m);
void mtev_lua_init_dns(void);
int mtev_lua_push_inet_ntop(lua_State *L, struct sockaddr *r);
mtev_hash_table *mtev_lua_table_to_hash(lua_State *L, int idx);
void mtev_lua_hash_to_table(lua_State *L, mtev_hash_table *t);
int mtev_lua_dns_gc(lua_State *L);
int mtev_lua_dns_index_func(lua_State *L);
int nl_dns_lookup(lua_State *L);
int luaopen_mtev(lua_State *L);
int luaopen_mtev_http(lua_State *L);
int mtev_lua_crypto_newx509(lua_State *L, X509 *x509);
int mtev_lua_crypto_new_ssl_session(lua_State *L, SSL_SESSION *sess);
int luaopen_mtev_crypto(lua_State *L);
int luaopen_mtev_stats(lua_State *);
int luaopen_pack(lua_State *L); /* from lua_lpack.c */
int luaopen_bit(lua_State *L); /* from lua_bit.c */
mtev_lua_resume_info_t *mtev_lua_get_resume_info(lua_State *L);
mtev_lua_resume_info_t *mtev_lua_find_resume_info(lua_State *L, mtev_boolean lua_error);
void mtev_lua_set_resume_info(lua_State *L, mtev_lua_resume_info_t *ri);
int mtev_lua_yield(mtev_lua_resume_info_t *ci, int nargs);
void mtev_lua_register_event(mtev_lua_resume_info_t *ci, eventer_t e);
void mtev_lua_deregister_event(mtev_lua_resume_info_t *ci, eventer_t e,
                                     int tofree);

MTEV_RUNTIME_RESOLVE(mtev_lua_yield_dyn, mtev_lua_yield, int,
                     (mtev_lua_resume_info_t *ci, int nargs),
                     (ci, nargs));
MTEV_RUNTIME_AVAIL(mtev_lua_yield_dyn, mtev_lua_yield)
MTEV_RUNTIME_RESOLVE(mtev_lua_get_resume_info_dyn, mtev_lua_get_resume_info,
                     mtev_lua_resume_info_t *,
                     (lua_State *L),
                     (L));
MTEV_RUNTIME_AVAIL(mtev_lua_get_resume_info_dyn, mtev_lua_get_resume_info)

void
mtev_lua_setup_http_ctx(lua_State *L,
                        mtev_http_session_ctx *http_ctx);
void
mtev_lua_setup_restc(lua_State *L,
                     mtev_http_rest_closure_t *restc);

int
mtev_lua_ffi_size(lua_State *L, const char *type_name, uint32_t *id, size_t *len);

int
mtev_lua_ffi_new_thing(lua_State *L, uint32_t id, void *mem);

typedef void (*mtev_lua_push_dynamic_ctype_t)(lua_State *, va_list);

MTEV_RUNTIME_RESOLVE(mtev_lua_register_dynamic_ctype, mtev_lua_register_dynamic_ctype_impl, void,
                     (const char *type_name, mtev_lua_push_dynamic_ctype_t func),
                     (type_name, func))
MTEV_RUNTIME_AVAIL(mtev_lua_register_dynamic_ctype, mtev_lua_register_dynamic_ctype_impl)

#define require(L, rv, a) do { \
  lua_getglobal(L, "require"); \
  lua_pushstring(L, #a); \
  rv = mtev_lua_pcall(L, 1, 1, 0); \
  if(rv != 0) { \
    mtevL(mtev_stderr, "Loading %s: %d (%s)\n", #a, rv, lua_tostring(L,-1)); \
    lua_close(L); \
    return NULL; \
  } \
  lua_pop(L, 1); \
} while(0)

#define SETUP_CALL(L, object, func, failure) do { \
  mtev_lua_pushmodule(L, object); \
  lua_getfield(L, -1, func); \
  lua_remove(L, -2); \
  if(!lua_isfunction(L, -1)) { \
    lua_pop(L, 1); \
    failure; \
  } \
} while(0)

#define RETURN_INT(L, object, func, expr) do { \
  int base = lua_gettop(L); \
  mtevAssert(base == 1); \
  if(lua_isnumber(L, -1)) { \
    int rv; \
    rv = lua_tointeger(L, -1); \
    lua_pop(L, 1); \
    expr \
    return rv; \
  } \
  lua_pop(L,1); \
} while(0)

#ifdef __cplusplus
}
#endif

#endif
