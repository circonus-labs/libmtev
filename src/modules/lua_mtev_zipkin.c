/*
 * Copyright (c) 2022, Circonus, Inc. All rights reserved.
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

#include <errno.h>
#include <sys/mman.h>
#include <ctype.h>
#include <lauxlib.h>

#include "mtev_dso.h"

#include "lua_mtev.h"
#include "mtev_zipkin.h"

#define OO_LUA_DECL(L, type, var, methodvar) \
  type **udata, *var; \
  const char *methodvar; \
  int n; \
  n = lua_gettop(L);    /* number of arguments */ \
  mtevAssert(n == 2); \
  if(!luaL_checkudata(L, 1, #type)) { \
    luaL_error(L, "metatable error, arg1 not " #type "!"); \
  } \
  udata = lua_touserdata(L, 1); \
  var = *udata; \
  if(!lua_isstring(L, 2)) { \
    luaL_error(L, "metatable error, arg2 not a string!"); \
  } \
  methodvar = lua_tostring(L, 2)

#define CCALL_DECL(L, type, var, nargs) \
  type *var; \
  var = lua_touserdata(L, lua_upvalueindex(1)); \
  if(nargs && lua_gettop(L) != (nargs)) \
    luaL_error(L, "wrong number of arguments")

#define CCALL_NARGS(L, nargs) \
  if(nargs && lua_gettop(L) != (nargs)) \
    luaL_error(L, "wrong number of arguments")

#define SPAN_DISPATCH(name) do { \
  if(!strcmp(k, #name)) { \
    lua_pushlightuserdata(L, span); \
    lua_pushcclosure(L, zipkin_span_##name, 1); \
    return 1; \
  } \
} while(0)

static int zipkin_span_annotate(lua_State *L) {
  CCALL_DECL(L, Zipkin_Span, span, 0);
  const char *msg = lua_tostring(L, 2);
  int64_t _ts = 0, *ts = NULL;
  if(lua_gettop(L) > 2 && !lua_isnil(L,3)) {
    struct timeval *o = luaL_checkudata(L, 3, "mtev.timeval");
    if(o) {
      _ts = o->tv_sec * 1000000 + o->tv_usec;
      ts = &_ts;
    }
  }
  mtev_zipkin_span_annotate(span, ts, msg, true);
  return 0;
}
static int zipkin_span_log(lua_State *L) {
  return zipkin_span_annotate(L);
}
static int zipkin_span_bannotate(lua_State *L) {
  CCALL_DECL(L, Zipkin_Span, span, 3);
  const char *key = lua_tostring(L,2);
  if(lua_isnumber(L,3)) {
    double vd = lua_tonumber(L,3);
    int64_t vi = lua_tointeger(L,3);
    if(vd == (double)vi)
      mtev_zipkin_span_bannotate_i64(span, key, true, vi);
    else
      mtev_zipkin_span_bannotate_double(span, key, true, vd);
  }
  else if(lua_isstring(L,3)) {
    mtev_zipkin_span_bannotate_str(span, key, true, lua_tostring(L,3), true);
  }
  else {
    luaL_error(L, "mtev.zipkin bannotate/tag %s no supported", lua_typename(L, 3));
  }
  return 0;
}
static int zipkin_span_tag(lua_State *L) {
  return zipkin_span_bannotate(L);
}
static int
zipkin_span_index_func(lua_State *L) {
  OO_LUA_DECL(L, Zipkin_Span, span, k);
  switch(*k) {
    case 'a':
      SPAN_DISPATCH(annotate);
      break;
    case 'b':
      SPAN_DISPATCH(bannotate);
      break;
    case 'l':
      SPAN_DISPATCH(log);
      break;
    case 't':
      SPAN_DISPATCH(tag);
      break;
    default:
      break;
  }
  luaL_error(L, "mtev_http_request no such element: %s", k);
  return 0;
}

void
mtev_lua_setup_span(lua_State *L, Zipkin_Span *span) {
  Zipkin_Span **addr;
  addr = (Zipkin_Span **)lua_newuserdata(L, sizeof(span));
  *addr = span;
  luaL_getmetatable(L, "Zipkin_Span");
  lua_setmetatable(L, -2);
}

int
mtev_lua_zipkin_active(lua_State *L) {
  Zipkin_Span *span = mtev_zipkin_active_span(NULL);
  if(span)
    mtev_lua_setup_span(L, mtev_zipkin_active_span(NULL));
  else
    lua_pushnil(L);
  return 1;
}

static const struct luaL_Reg zipkin_funcs[] = {
  { "active",  mtev_lua_zipkin_active },
  { NULL, NULL }
};

int
luaopen_mtev_zipkin(lua_State *L) {
  (void)L;
  lua_newtable(L);
  lua_setglobal(L, "zipkin");

  luaL_newmetatable(L, "Zipkin_Span");
  lua_pushcclosure(L, zipkin_span_index_func, 0);
  lua_setfield(L, -2, "__index");

  luaL_openlib(L, "mtev.zipkin", zipkin_funcs, 0);
  return 0;
}
