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
 *     * Neither the name Circonus, Inc. nor the names of its
 *       contributors may be used to endorse or promote products
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
#define LUA_COMPAT_MODULE
#include "lua_mtev.h"
#include "mtev_consul.h"

#define LUA_DISPATCH(n, f) \
     if(!strcmp(k, #n)) { \
       lua_pushlightuserdata(L, udata); \
       lua_pushcclosure(L, f, 1); \
       return 1; \
     }

static int nl_service(lua_State *L) {
  mtev_consul_service **service;
  const char *name = lua_tostring(L,1);
  const char *id = lua_tostring(L,2);
  const char *address = lua_tostring(L,3);
  unsigned short port = lua_tointeger(L,4);
  mtev_hash_table *meta = NULL, *tags = NULL;
  if(lua_gettop(L) > 4) {
    luaL_checktype(L, 5, LUA_TTABLE);
    mtev_hash_table *tags_const = mtev_lua_table_to_hash(L, 5);
    if(tags_const && mtev_hash_size(tags_const)) {
      tags = calloc(1, sizeof(*tags));
      mtev_hash_init(tags);
      mtev_hash_merge_as_dict(tags, tags_const);
      mtev_hash_delete_all(tags_const, NULL, NULL);
    }
    free(tags_const);
  }
  if(lua_gettop(L) > 5) {
    luaL_checktype(L, 6, LUA_TTABLE);
    mtev_hash_table *meta_const = mtev_lua_table_to_hash(L, 6);
    if(meta_const && mtev_hash_size(meta_const)) {
      meta = calloc(1, sizeof(*meta));
      mtev_hash_init(meta);
      mtev_hash_merge_as_dict(meta, meta_const);
      mtev_hash_delete_all(meta_const, NULL, NULL);
    }
    free(meta_const);
  }
  service = (mtev_consul_service **)lua_newuserdata(L, sizeof(*service));
  *service = mtev_consul_service_alloc(name, id, address, port, tags, true, meta, true);
  luaL_getmetatable(L, "consul.service");
  lua_setmetatable(L, -2);
  return 1;
}

static int mtev_lua_consul_service_gc(lua_State *L) {
  if(!luaL_checkudata(L, 1, "consul.service")) {
    luaL_error(L, "consul.service GC on wrong type!");
  }
  mtev_consul_service **service = (mtev_consul_service **)lua_touserdata(L, 1);
  mtev_consul_service_free(*service);
  return 0;
}

static int mtev_lua_consul_service_register_get(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  char *idcopy = mtev_consul_service_id(*service);
  if(idcopy) {
    service_register *registry = mtev_consul_service_registry(idcopy);
    free(idcopy);
    if(registry) {
      service_register **udata = (service_register **)lua_newuserdata(L, sizeof(*udata));
      *udata = registry;
      luaL_getmetatable(L, "consul.service_register");
      lua_setmetatable(L, -2);
      return 1;
    }
  }
  lua_pushnil(L);
  return 1;
}

static int mtev_lua_consul_service_register(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  if(mtev_consul_register(*service)) {
    return mtev_lua_consul_service_register_get(L);
  }
  lua_pushnil(L);
  return 1;
}

static int mtev_lua_consul_service_set_address(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_set_address(*service, lua_tostring(L,2));
  return 0;
}

static int mtev_lua_consul_service_set_port(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_set_port(*service, lua_tointeger(L,2));
  return 0;
}

static int mtev_lua_consul_service_set_deregistercriticalserviceafter(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_set_deregistercriticalserviceafter(*service, lua_tointeger(L,2));
  return 0;
}

static int mtev_lua_consul_service_check_none(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_check_none(*service);
  return 0;
}

static int mtev_lua_consul_service_check_push(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_check_push(*service, lua_tointeger(L,2));
  return 0;
}

static int mtev_lua_consul_service_check_tcp(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  const char *tcp = NULL;
  if(lua_gettop(L) > 1 && !lua_isnil(L,2)) {
    tcp = lua_tostring(L, 2);
  }
  unsigned interval = 5, timeout = 5;
  unsigned *timeout_ptr = NULL;
  if(lua_gettop(L) > 2) {
    interval = lua_tointeger(L, 3);
  }
  if(lua_gettop(L) > 3 && lua_isnumber(L, 4)) {
    timeout = lua_tointeger(L, 4);
    timeout_ptr = &timeout;
  }
  mtev_consul_service_check_tcp(*service, tcp, interval, timeout_ptr);
  return 0;
}

static int mtev_lua_consul_service_check_http(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  unsigned interval = 5, timeout = 5;
  unsigned *timeout_ptr = NULL;
  const char *method = "GET";
  if(lua_gettop(L) > 2 && !lua_isnil(L,3)) {
    method = lua_tostring(L,3);
  }
  if(lua_gettop(L) > 3) {
    interval = lua_tointeger(L, 4);
  }
  if(lua_gettop(L) > 4 && lua_isnumber(L, 5)) {
    timeout = lua_tointeger(L, 5);
    timeout_ptr = &timeout;
  }
  mtev_consul_service_check_http(*service, lua_tostring(L,2), method, interval, timeout_ptr);
  return 0;
}

static int mtev_lua_consul_service_check_https(lua_State *L) {
  mtev_consul_service **service = lua_touserdata(L, lua_upvalueindex(1));
  unsigned interval = 5, timeout = 5;
  unsigned *timeout_ptr = NULL;
  const char *method = "GET";
  const char *tlsservername = NULL;
  bool tlsskipverify = false;
  if(lua_gettop(L) > 2 && !lua_isnil(L,3)) {
    method = lua_tostring(L,3);
  }
  if(lua_gettop(L) > 3 && !lua_isnil(L,4)) {
    tlsservername = lua_tostring(L,4);
  }
  if(lua_gettop(L) > 4) {
    tlsskipverify = lua_toboolean(L,5);
  }
  if(lua_gettop(L) > 5) {
    interval = lua_tointeger(L, 6);
  }
  if(lua_gettop(L) > 6 && lua_isnumber(L, 7)) {
    timeout = lua_tointeger(L, 7);
    timeout_ptr = &timeout;
  }
  mtev_consul_service_check_https(*service, lua_tostring(L,2), method,
                                  tlsservername, tlsskipverify,
                                  interval, timeout_ptr);
  return 0;
}

static int mtev_lua_consul_service_index_func(lua_State *L) {
  int n = lua_gettop(L);
  mtevAssert(n == 2);
  mtev_consul_service **service = (mtev_consul_service **) luaL_testudata(L, 1, "consul.service");
  if(service == NULL) {
    luaL_error(L, "metatable error, arg1 not a consul.service!");
  }
  void *udata = service;
  if(!lua_isstring(L, 2)) {
    luaL_error(L, "metatable error, arg2 not a string!");
  }
  const char *k = lua_tostring(L, 2);
  switch(*k) {
    case 'c':
      LUA_DISPATCH(check_none, mtev_lua_consul_service_check_none);
      LUA_DISPATCH(check_push, mtev_lua_consul_service_check_push);
      LUA_DISPATCH(check_tcp, mtev_lua_consul_service_check_tcp);
      LUA_DISPATCH(check_http, mtev_lua_consul_service_check_http);
      LUA_DISPATCH(check_https, mtev_lua_consul_service_check_https);
      break;
    case 'i':
      if(!strcmp(k, "id")) {
        char *copy = mtev_consul_service_id(*service);
        lua_pushstring(L, copy);
        free(copy);
        return 1;
      }
      break;
    case 'r':
      LUA_DISPATCH(register, mtev_lua_consul_service_register);
      break;
    case 's':
      LUA_DISPATCH(set_address, mtev_lua_consul_service_set_address);
      LUA_DISPATCH(set_port, mtev_lua_consul_service_set_port);
      LUA_DISPATCH(set_deregistercriticalserviceafter, mtev_lua_consul_service_set_deregistercriticalserviceafter);
      break;
    default:
      break;
  }
  luaL_error(L, "Unknown method for consul.service: %s\n", k);
  return 0;
}

static int mtev_lua_consul_set_critical(lua_State *L) {
  service_register **reg = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_set_critical(*reg);
  return 0;
}
static int mtev_lua_consul_set_passing(lua_State *L) {
  service_register **reg = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_set_passing(*reg);
  return 0;
}
static int mtev_lua_consul_set_warning(lua_State *L) {
  service_register **reg = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_set_warning(*reg);
  return 0;
}
static int mtev_lua_consul_deregister(lua_State *L) {
  service_register **reg = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_register_deregister(*reg);
  return 0;
}
static int mtev_lua_consul_register(lua_State *L) {
  service_register **reg = lua_touserdata(L, lua_upvalueindex(1));
  mtev_consul_service_register_register(*reg);
  return 0;
}

static int mtev_lua_consul_service_register_index_func(lua_State *L) {
  int n = lua_gettop(L);
  mtevAssert(n == 2);
  service_register **reg = (service_register **) luaL_testudata(L, 1, "consul.service_register");
  if(reg == NULL) {
    luaL_error(L, "metatable error, arg1 not a consul.service_register!");
  }
  void *udata = reg;
  if(!lua_isstring(L, 2)) {
    luaL_error(L, "metatable error, arg2 not a string!");
  }
  const char *k = lua_tostring(L, 2);
  switch(*k) {
    case 'c':
      LUA_DISPATCH(critical, mtev_lua_consul_set_critical);
      break;
    case 'd':
      LUA_DISPATCH(deregister, mtev_lua_consul_deregister);
      break;
    case 'p':
      LUA_DISPATCH(passing, mtev_lua_consul_set_passing);
      break;
    case 'r':
      LUA_DISPATCH(register, mtev_lua_consul_register);
      break;
    case 'w':
      LUA_DISPATCH(warning, mtev_lua_consul_set_warning);
      break;
    default:
      break;
  }
  luaL_error(L, "Unknown method for consul.service_register: %s\n", k);
  return 0;
}

static int mtev_lua_consul_service_register_gc(lua_State *L) {
  if(!luaL_checkudata(L, 1, "consul.service_register")) {
    luaL_error(L, "consul.service_register GC on wrong type!");
  }
  service_register **r = (service_register **)lua_touserdata(L, 1);
  mtev_consul_service_register_deref(*r);
  return 0;
}

static const luaL_Reg mtevconsullib[] = {
  { "service", nl_service },
  { NULL, NULL }
};

int luaopen_mtev_consul(lua_State *L) {
  luaL_newmetatable(L, "consul.service");
  lua_pushcfunction(L, mtev_lua_consul_service_gc);
  lua_setfield(L, -2, "__gc");
  lua_pushcfunction(L, mtev_lua_consul_service_index_func);
  lua_setfield(L, -2, "__index");

  luaL_newmetatable(L, "consul.service_register");
  lua_pushcfunction(L, mtev_lua_consul_service_register_gc);
  lua_setfield(L, -2, "__gc");
  lua_pushcfunction(L, mtev_lua_consul_service_register_index_func);
  lua_setfield(L, -2, "__index");

  luaL_openlib(L, "mtev.consul", mtevconsullib, 0);
  return 0;
}
