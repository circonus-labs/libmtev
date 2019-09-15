/*
** Copyright (C) 2005-2017 Mike Pall. See Copyright Notice in luajit.h
** Copyright (C) 2019 Circonus, Inc. See LICENSE file.
*/

#define lj_debug_c
#define LUA_CORE

#include "mtev_defines.h"
#include <stdio.h>

#ifdef HAVE_LUAJIT_SOURCE
#include "lj_obj.h"
#include "lj_err.h"
#include "lj_debug.h"
#include "lj_buf.h"
#include "lj_tab.h"
#include "lj_state.h"
#include "lj_frame.h"
#include "lj_bc.h"
#include "lj_strfmt.h"
#if LJ_HASJIT
#include "lj_jit.h"
#endif

/* Number of frames for the leading and trailing part of a traceback. */
#define TRACEBACK_LEVELS1	12
#define TRACEBACK_LEVELS2	10

void mtev_luaL_traceback (void (*cb)(void *, const char *, size_t), void *closure,
                          lua_State *L1, const char *msg, int level) {
#define CBF(closure, arg...) do { \
  char buff[1024]; \
  snprintf(buff, sizeof(buff), arg); \
  cb(closure, buff, strlen(buff)); \
} while(0)
  int lim = TRACEBACK_LEVELS1;
  lua_Debug ar;
  if (msg) CBF(closure, "%s\n", msg);
  cb(closure, "stack traceback:", strlen("stack traceback:"));
  while (lua_getstack(L1, level++, &ar)) {
    GCfunc *fn;
    if (level > lim) {
      if (!lua_getstack(L1, level + TRACEBACK_LEVELS2, &ar)) {
	level--;
      } else {
	cb(closure, "\n\t...", strlen("\n\t..."));
	lua_getstack(L1, -10, &ar);
	level = ar.i_ci - TRACEBACK_LEVELS2;
      }
      lim = 2147483647;
      continue;
    }
    lua_getinfo(L1, "Snlf", &ar);
    if(L1->top == NULL) fn = NULL;
    else {
      fn = funcV(L1->top-1);
      L1->top--;
    }
    if (fn && isffunc(fn) && !*ar.namewhat)
      CBF(closure, "\n\t[builtin#%d]:", fn->c.ffid);
    else
      CBF(closure, "\n\t%s:", ar.short_src);
    if (ar.currentline > 0)
      CBF(closure, "%d:", ar.currentline);
    if (*ar.namewhat) {
      CBF(closure, " in function " LUA_QS, ar.name);
    } else {
      if (*ar.what == 'm') {
	cb(closure, " in main chunk", strlen(" in main chunk"));
      } else if (fn && *ar.what == 'C') {
	CBF(closure, " at %p", fn->c.f);
      } else {
	CBF(closure, " in function <%s:%d>",
            ar.short_src, ar.linedefined);
      }
    }
  }
  cb(closure, "\n", 1);
}

#else 
void mtev_luaL_traceback (void (*cb)(void *, const char *, size_t), void *closure,
                          lua_State *L1, const char *msg, int level) {
  cb(closure, "\tlua internals disabled\n", strlen("\tlua internals disabled\n"));
}

#endif
