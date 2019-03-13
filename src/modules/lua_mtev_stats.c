/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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

#include "circmetrics.h"

#include "mtev_conf.h"

#include "lua_mtev.h"

#define PUSH_OBJ(L, tname, obj) do { \
  *(void **)(lua_newuserdata(L, sizeof(void *))) = (obj); \
  luaL_getmetatable(L, tname); \
  lua_setmetatable(L, -2); \
} while(0)

static int
mtev_lua_stats_handle_record(lua_State *L) {
  void **udata;
  stats_handle_t *handle;
  stats_type_t type;
  int nargs = lua_gettop(L);
  if(nargs < 2)
    luaL_error(L, "libcircmetrics.handle.record(self,value[,cnt])");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1)) luaL_error(L, "must be called as method");
  handle = *udata;
  type = stats_handle_type(handle);
  if(lua_isnil(L,2)) {
    /* This clears a value */
    stats_set(handle, type, NULL);
    return 0;
  }
  switch(type) {
    case STATS_TYPE_STRING:
      stats_set(handle, STATS_TYPE_STRING, (char *)lua_tostring(L,2));
      return 0;
    case STATS_TYPE_COUNTER:
      stats_add64(handle, (int64_t)lua_tonumber(L,2));
      return 0;
#define SIMPLE_NUMERIC(ctype,statstype) \
    case statstype: \
    { ctype val = lua_tonumber(L,2); stats_set(handle, type, &val); return 0; }
    SIMPLE_NUMERIC(int32_t, STATS_TYPE_INT32)
    SIMPLE_NUMERIC(uint32_t, STATS_TYPE_UINT32)
    SIMPLE_NUMERIC(int64_t, STATS_TYPE_INT64)
    SIMPLE_NUMERIC(uint64_t, STATS_TYPE_UINT64)
    SIMPLE_NUMERIC(double, STATS_TYPE_DOUBLE)
    case STATS_TYPE_HISTOGRAM:
    case STATS_TYPE_HISTOGRAM_FAST:
    {
      uint64_t cnt = 1;
      if(nargs > 3) luaL_error(L, "record(hist,val[,cnt])");
      if(nargs == 3) cnt = lua_tointeger(L,3);
      if(lua_istable(L,2)) {
        lua_rawgeti(L,2,2);
        int scale = lua_tointeger(L,-1);
        lua_pop(L,1);
        lua_rawgeti(L,2,1);
        int64_t val = lua_tointeger(L,-1);
        lua_pop(L,1);
        stats_set_hist_intscale(handle, val, scale, cnt);
        return 0;
      }
      double val = lua_tonumber(L,2);
      stats_set_hist(handle, val, cnt);
      return 0;
    }
  }
  luaL_error(L, "libcircmetrics.handle.record unsupported type");
  return 0;
}

static int
mtev_lua_stats_handle_add_tag(lua_State *L) {
  void **udata;
  const char *tagcat, *tagval;
  stats_handle_t *handle;
  if(lua_gettop(L) != 3)
    luaL_error(L, "libcircmetrics.handle.add_tag must be called with two arguments");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1)) luaL_error(L, "must be called as method");
  handle = *udata;
  tagcat = lua_tostring(L, 2);
  if(!tagcat) luaL_error(L, "first argument must be a string");
  tagval = lua_tostring(L, 3);
  if(!tagval) luaL_error(L, "second argument must be a string");
  handle = *udata;
  stats_handle_add_tag(handle, tagcat, tagval);
  return 0;
}

static int
mtev_lua_stats_handle_index(lua_State *L) {
  const char *k;
  void **udata;
  mtevAssert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "libcircmetrics.handle")) {
    luaL_error(L, "metatable error, arg1 not a libcircmetric.handle!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  if(!strcmp(k, "record")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_handle_record, 1);
    return 1;
  }
  else if(!strcmp(k, "add_tag")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_handle_add_tag, 1);
    return 1;
  }
  luaL_error(L, "unknown field %s in libcircmetrics.handle", k);
  return 0;
}
static int
mtev_lua_stats_ns_register(lua_State *L) {
  void **udata;
  stats_ns_t *parent;
  stats_handle_t *handle = NULL;
  const char *name;
  int type;
  int nargs = lua_gettop(L);
  if(nargs != 3 && nargs != 4)
    luaL_error(L, "libcircmetrics.ns.register(self,name,type[,fanout])");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1)) luaL_error(L, "must be called as method");
  name = lua_tostring(L, 2);
  if(!name) luaL_error(L, "second argument must be a string");
  type = lua_tointeger(L, 3);
  if(type < 0 || type > STATS_TYPE_HISTOGRAM_FAST)
    luaL_error(L, "third argument must be valid stats type");
  parent = *udata;
  if(nargs == 4) {
    handle = stats_register_fanout(parent, name, (stats_type_t)type,
                                   lua_tointeger(L, 4));
  }
  else {
    handle = stats_register(parent, name, (stats_type_t)type);
  }
  PUSH_OBJ(L, "libcircmetrics.handle", handle);
  return 1;
}

static int
mtev_lua_stats_ns_ns(lua_State *L) {
  void **udata;
  stats_ns_t *parent;
  const char *name;
  if(lua_gettop(L) != 2)
    luaL_error(L, "libcircmetrics.ns.ns must be called with two arguments");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1)) luaL_error(L, "must be called as method");
  name = lua_tostring(L, 2);
  if(!name) luaL_error(L, "second argument must be a string");
  parent = *udata;
  stats_ns_t *ns = stats_register_ns(NULL, parent, name);
  PUSH_OBJ(L, "libcircmetrics.ns", ns);
  return 1;
}

static int
mtev_lua_stats_ns_add_tag(lua_State *L) {
  void **udata;
  stats_ns_t *parent;
  const char *tagcat, *tagval;
  if(lua_gettop(L) != 3)
    luaL_error(L, "libcircmetrics.ns.add_tag must be called with two arguments");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1)) luaL_error(L, "must be called as method");
  tagcat = lua_tostring(L, 2);
  if(!tagcat) luaL_error(L, "first argument must be a string");
  tagval = lua_tostring(L, 3);
  if(!tagval) luaL_error(L, "second argument must be a string");
  parent = *udata;
  stats_ns_add_tag(parent, tagcat, tagval);
  return 0;
}

static int
mtev_lua_stats_ns_index(lua_State *L) {
  const char *k;
  void **udata;
  mtevAssert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "libcircmetrics.ns")) {
    luaL_error(L, "metatable error, arg1 not a libcircmetric.ns!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  if(!strcmp(k, "ns")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_ns_ns, 1);
    return 1;
  }
  else if(!strcmp(k, "add_tag")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_ns_add_tag, 1);
    return 1;
  }
  else if(!strcmp(k, "register")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_ns_register, 1);
    return 1;
  }
#define DEF_ENUM(name, value) else if(!strcmp(k, #name)) { \
    lua_pushinteger(L, value); \
    return 1; \
  }
  DEF_ENUM(STRING, STATS_TYPE_STRING)
  DEF_ENUM(INT32, STATS_TYPE_INT32)
  DEF_ENUM(UINT32, STATS_TYPE_UINT32)
  DEF_ENUM(INT64, STATS_TYPE_INT64)
  DEF_ENUM(UINT64, STATS_TYPE_UINT64)
  DEF_ENUM(COUNTER, STATS_TYPE_COUNTER)
  DEF_ENUM(DOUBLE, STATS_TYPE_DOUBLE)
  DEF_ENUM(HISTOGRAM, STATS_TYPE_HISTOGRAM)
  DEF_ENUM(HISTOGRAM_FAST, STATS_TYPE_HISTOGRAM_FAST)
  luaL_error(L, "unknown field %s in libcircmetrics.ns", k);
  return 0;
}

static int
mtev_lua_stats_recorder_ns(lua_State *L) {
  void **udata;
  stats_recorder_t *r;
  const char *name;
  if(lua_gettop(L) != 2)
    luaL_error(L, "libcircmetrics.recorder.ns must be called with two arguments");
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1))
    luaL_error(L, "must be called as method");
  name = lua_tostring(L, 2);
  if(!name) luaL_error(L, "second argument must be a string");
  r = *udata;
  stats_ns_t *ns = stats_register_ns(r, NULL, name);
  PUSH_OBJ(L, "libcircmetrics.ns", ns);
  return 1;
}

static int
mtev_lua_stats_recorder_index(lua_State *L) {
  const char *k;
  void **udata;
  mtevAssert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "libcircmetrics.recorder")) {
    luaL_error(L, "metatable error, arg1 not a libcircmetric.recorder!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  if(!strcmp(k, "ns")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_stats_recorder_ns, 1);
    return 1;
  }
  DEF_ENUM(STRING, STATS_TYPE_STRING)
  DEF_ENUM(INT32, STATS_TYPE_INT32)
  DEF_ENUM(UINT32, STATS_TYPE_UINT32)
  DEF_ENUM(INT64, STATS_TYPE_INT64)
  DEF_ENUM(UINT64, STATS_TYPE_UINT64)
  DEF_ENUM(COUNTER, STATS_TYPE_COUNTER)
  DEF_ENUM(DOUBLE, STATS_TYPE_DOUBLE)
  DEF_ENUM(HISTOGRAM, STATS_TYPE_HISTOGRAM)
  DEF_ENUM(HISTOGRAM_FAST, STATS_TYPE_HISTOGRAM_FAST)
  luaL_error(L, "unknown field %s in libcircmetrics.recorder", k);
  return 0;
}

int
luaopen_mtev_stats(lua_State *L) {
  luaL_newmetatable(L, "libcircmetrics.recorder");
  lua_pushcclosure(L, mtev_lua_stats_recorder_index, 0);
  lua_setfield(L, -2, "__index");

  luaL_newmetatable(L, "libcircmetrics.ns");
  lua_pushcclosure(L, mtev_lua_stats_ns_index, 0);
  lua_setfield(L, -2, "__index");

  luaL_newmetatable(L, "libcircmetrics.handle");
  lua_pushcclosure(L, mtev_lua_stats_handle_index, 0);
  lua_setfield(L, -2, "__index");

  /* Expose the global mtev stats recorder as `mtev.stats` */
  lua_getglobal(L, "mtev");
  lua_pushstring(L, "stats");
  PUSH_OBJ(L, "libcircmetrics.recorder", mtev_stats_recorder());
  lua_settable(L, -3);
  
  return 0;
}
