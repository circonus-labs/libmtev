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
#include "mtev_stacktrace.h"
#include <ck_pr.h>

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>

#include "mtev_conf.h"
#include "mtev_dso.h"
#include "mtev_log.h"
#include "mtev_perftimer.h"
#include "mtev_stacktrace.h"
#include "mtev_stats.h"

#include "lua_mtev.h"

#define nldeb mtev_lua_debug_ls
#define nlerr mtev_lua_error_ls

MTEV_HOOK_IMPL(mtev_lua_dispatch_defunct, (lua_module_closure_t *lmc), void *, closure,
               (void *closure, lua_module_closure_t *lmc), (closure, lmc));

mtev_log_stream_t mtev_lua_debug_ls;
mtev_log_stream_t mtev_lua_error_ls;

static eventer_jobq_t *release_jobq;
static mtev_hash_table mtev_lua_states;
static pthread_mutex_t mtev_lua_states_lock = PTHREAD_MUTEX_INITIALIZER;
static mtev_hash_table mtev_coros;
static pthread_mutex_t coro_lock = PTHREAD_MUTEX_INITIALIZER;
static stats_ns_t *lua_stats_ns;
static stats_handle_t *gc_total, *gc_full, *gc_latency;
static stats_handle_t *states_started, *states_stopped, *states_current, *state_preemptions;
static uint64_t global_gen = 0;

struct lua_module_gc_params {
  int iters_since_full;
  int full_every;
  int steps;
  int steps_multiplier, set_steps_multiplier;
  int pause_size, set_pause_size;
};

static lua_module_gc_params_t default_gc_params = {
  .iters_since_full = 0,
  .full_every = 1000,
  .steps = 0,
  .steps_multiplier = 1, .set_steps_multiplier = 1,
  .pause_size = 200, .set_pause_size = 200
};

lua_module_gc_params_t *
mtev_lua_config_gc_params(mtev_hash_table *o) {
  lua_module_gc_params_t *p = calloc(1, sizeof(*p));
  memcpy(p, &default_gc_params, sizeof(*p));
  if(o) {
    const char *str;
    if(mtev_hash_retr_str(o, "gc_full", strlen("gc_full"), &str))
      p->full_every = atoi(str);
    if(mtev_hash_retr_str(o, "gc_step", strlen("gc_step"), &str))
      p->steps = atoi(str);
    if(mtev_hash_retr_str(o, "gc_pause", strlen("gc_pause"), &str))
      p->set_pause_size = atoi(str);
    if(mtev_hash_retr_str(o, "gc_stepmul", strlen("gc_stepmul"), &str))
      p->set_steps_multiplier = atoi(str);
  }
  return p;
}

void
mtev_lua_set_gc_params(lua_module_closure_t *lmc, lua_module_gc_params_t *p) {
  if(lmc->gcparams == NULL) {
    lua_module_gc_params_t *newp = calloc(1, sizeof(*newp));
    memcpy(newp, p, sizeof(*p));
    lmc->gcparams = newp;
  }
  else {
    memcpy(lmc->gcparams, p, sizeof(*p));
  }
}

static int
mtev_lua_gc_callback(eventer_t e, int mask, void *c, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  mtev_perftimer_t timer;
  lua_module_closure_t *lmc = c;
  lua_State *L = lmc->lua_state;
  lua_module_gc_params_t *p = lmc->gcparams;

  mtev_perftimer_start(&timer);
  stats_add64(gc_total, 1);
  if(!p) {
    lua_gc(L, LUA_GCCOLLECT, 0);
    stats_add64(gc_full, 1);
    stats_set_hist_intscale(gc_latency, mtev_perftimer_elapsed(&timer), -9, 1);
    return 0;
  }

  if(p->steps_multiplier != p->set_steps_multiplier) {
    lua_gc(L, LUA_GCSETSTEPMUL, p->set_steps_multiplier);
    p->steps_multiplier = p->set_steps_multiplier;
  }
  if(p->pause_size != p->set_pause_size) {
    lua_gc(L, LUA_GCSETPAUSE, p->set_pause_size);
    p->pause_size = p->set_pause_size;
  }

  p->iters_since_full++;
  if(p->full_every && (p->iters_since_full >= p->full_every)) {
    p->iters_since_full = 0;
    lua_gc(L, LUA_GCCOLLECT, 0);
    stats_add64(gc_full, 1);
    stats_set_hist_intscale(gc_latency, mtev_perftimer_elapsed(&timer), -9, 1);
    return 0;
  }
  lua_gc(L, LUA_GCSTEP, p->steps);
  stats_set_hist_intscale(gc_latency, mtev_perftimer_elapsed(&timer), -9, 1);
  return 0;
}
void
mtev_lua_gc(lua_module_closure_t *lmc) {
  eventer_add_in_s_us(mtev_lua_gc_callback, lmc, 0, 0);
}

void
mtev_lua_gc_full(lua_module_closure_t *lmc) {
  lua_module_gc_params_t *p = lmc->gcparams;
  if(p) {
    /* Fake the tracking so as to induce a full,
     * if p is not set, a full will occur anyway. */
    p->iters_since_full = p->full_every;
  }
  eventer_add_in_s_us(mtev_lua_gc_callback, lmc, 0, 0);
}


static void
mtev_lua_timer_setup(lua_module_closure_t *lmc) {
#if defined(linux) || defined(__linux) || defined(__linux__)
  struct sigevent sev;
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = SIGUSR1;
  sev._sigev_un._tid = syscall(SYS_gettid);
  sev.sigev_value.sival_ptr = &lmc->_timer;
  if (timer_create(CLOCK_MONOTONIC, &sev, &lmc->_timer) == -1) {
    mtevL(mtev_error, "timer_create failed: %s", strerror(errno));
    return;
  }

  lmc->timer = &lmc->_timer;
#else
  (void)lmc;
#endif
}

void mtev_lua_validate_lmc(lua_module_closure_t *lmc) {
  if(!lmc) return;
  if(ck_pr_load_64(&global_gen) != lmc->gen) {
    lmc->wants_restart = true;
  }
}

static int
mtev_lua_dispatch_defunct_cb(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  lua_module_closure_t *lmc = (lua_module_closure_t *)closure;

  mtev_lua_validate_lmc(lmc);
  if(lmc->wants_restart == false) return 0;
  if(lmc->defunct_cb_fired) return 0;
  lmc->defunct_cb_fired = true;

  lua_State *L = lmc->lua_state;
  lua_getglobal(L, "mtev");
  lua_getfield(L, -1, "__defunct_cb");
  if(lua_isfunction(L, -1)) {
    mtev_lua_pcall(L, 0, 0, 0);
  }
  mtev_lua_dispatch_defunct_hook_invoke(lmc);
  mtev_lua_deref(lmc);
  return 0;
}

void
mtev_lua_dispatch_defunct(void) {
  mtev_hash_iter iter = {};
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_adv(&mtev_lua_states, &iter)) {
    lua_module_closure_t *lmc = iter.value.ptr;
    mtev_lua_validate_lmc(lmc);
    pthread_t tgt = lmc->owner;
    if(lmc->wants_restart == false || eventer_is_loop(tgt) < 0) {
      continue;
    }

    mtev_lua_ref(lmc);
    eventer_t e = eventer_in_s_us(mtev_lua_dispatch_defunct_cb, lmc, 0, 0);
    eventer_set_owner(e, tgt);
    eventer_add(e);
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);
}

void mtev_lua_trigger_reload(void) {
  ck_pr_inc_64(&global_gen);
  mtev_lua_dispatch_defunct();
}

lua_module_closure_t *
mtev_lua_lmc_alloc(mtev_dso_generic_t *self, mtev_lua_resume_t resume) {
  lua_module_closure_t *lmc;
  lmc = calloc(1, sizeof(*lmc));
  lmc->pending = calloc(1, sizeof(*lmc->pending));
  mtev_hash_init(lmc->pending);
  mtev_hash_init(&lmc->state_coros);
  lmc->owner = pthread_self();
  lmc->eventer_id = eventer_is_loop(lmc->owner);
  lmc->self = self;
  lmc->resume = resume;
  lmc->ref_cnt = 1;
  lmc->gen = global_gen;
  mtev_lua_timer_setup(lmc);
  stats_add64(states_started, 1);
  stats_add64(states_current, 1);
  return lmc;
}

void mtev_lua_ref(lua_module_closure_t *lmc) {
  mtevAssert(lmc->ref_cnt);
  ++lmc->ref_cnt;
  mtevL(nldeb, "mtev_lua_deref(%p) -> %u\n", lmc, lmc->ref_cnt);
}

static int mtev_lua_release(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)now;
  if(mask == EVENTER_ASYNCH_WORK) mtev_lua_lmc_free((lua_module_closure_t *)closure);
  return 0;
}

void mtev_lua_deref(lua_module_closure_t *lmc) {
  mtevL(nldeb, "mtev_lua_deref(%p) -> %u\n", lmc, lmc->ref_cnt - 1);
  if(--lmc->ref_cnt == 0) {
    eventer_t e = eventer_alloc_asynch(mtev_lua_release, lmc);
    eventer_add_asynch(release_jobq, e);
  }
}

void
mtev_lua_lmc_free(lua_module_closure_t *lmc) {
  if(lmc) {
    if(lmc->lua_state) lua_close(lmc->lua_state);
    if(lmc->pending) {
      mtev_hash_destroy(lmc->pending, free, free);
      free(lmc->pending);
    }
    mtev_hash_destroy(&lmc->state_coros, NULL, NULL);
    pthread_mutex_lock(&mtev_lua_states_lock);
    mtev_hash_delete(&mtev_lua_states,
                     (const char*)&lmc->lua_state, sizeof(lmc->lua_state),
                     free, NULL);
    pthread_mutex_unlock(&mtev_lua_states_lock);
    if(lmc->timer) {
      if (timer_delete(lmc->_timer) == -1) {
        mtevL(mtev_error, "timer_delete failed: %s", strerror(errno));
      }
    }
    stats_add64(states_stopped, 1);
    stats_add64(states_current, -1);
  }
  free(lmc);
}

static __thread lua_State *tls_active_lua_state = NULL;
static __thread bool assist_fired;

static void
mtev_lua_timer_start(timer_t *lua_timer, struct timeval *diff) {
  if(lua_timer == NULL) return;

  mtevL(nldeb, "Starting lua timer: %p for %ld.%06ld\n", lua_timer, diff->tv_sec, diff->tv_usec);
  struct itimerspec ispec;
  memset(&ispec, 0, sizeof(ispec));
  ispec.it_value.tv_sec = diff->tv_sec;
  ispec.it_value.tv_nsec = diff->tv_usec * 1000;
  if(timer_settime(*lua_timer, 0, &ispec, NULL) != 0)
    mtevL(mtev_error, "timer_settime failed: %s\n", strerror(errno));
}

static void
mtev_lua_timer_stop(timer_t *lua_timer) {
  if(lua_timer == NULL) return;

  mtevL(nldeb, "Stopping lua timer: %p\n", lua_timer);
  struct itimerspec ispec;
  memset(&ispec, 0, sizeof(ispec));
  if(timer_settime(*lua_timer, 0, &ispec, NULL) != 0)
    mtevL(mtev_error, "timer_settime failed: %s\n", strerror(errno));
}
static int mtev_lua_preempt_resume(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  lua_State *L = (lua_State *)closure;
  mtev_lua_resume_info_t *ri = mtev_lua_find_resume_info(L, mtev_false);
  if(ri) {
    ri->lmc->resume(ri, 0);
  }
  return 0;
}

static void lerror (lua_State *L, lua_Debug *ar) {
  (void)ar;  /* unused arg. */
  mtev_lua_resume_info_t *ri = mtev_lua_find_resume_info(L, mtev_false);
  if(ri) {
    lua_sethook(ri->coro_state, NULL, 0, 0);  /* reset hook */
    luaL_error(L, "externally triggered error");
  }
}

struct lua_actuation {
  lua_State *L;
  mtev_boolean error;
};

static int
trigger_actuate_cb(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  struct lua_actuation *la = closure;
  lua_State *L = la->L;
  mtev_lua_resume_info_t *ri = mtev_lua_find_resume_info(L, mtev_false);
  if(ri) {
    if(la->error) {
      lua_sethook(ri->coro_state, lerror, LUA_MASKCOUNT, 1);
    } else {
      mtev_lua_cancel_coro(ri);
    }
  }
  free(la);
  return 0;
}

mtev_boolean
mtev_lua_actuate_foreign_state(lua_State *L, mtev_boolean error) {
  mtev_lua_resume_info_t *ri = mtev_lua_find_resume_info_any_thread(L);
  if(!ri || eventer_is_loop(ri->lmc->owner) < 0) {
    mtevL(mtev_error, "lua_State %p not eligible for remote errors\n", L);
    return mtev_false;
  }

  struct lua_actuation *la = calloc(1, sizeof(*la));
  la->L = L;
  la->error = error;
  eventer_t e = eventer_in_s_us(trigger_actuate_cb, la, 0, 0);
  eventer_set_owner(e, ri->lmc->owner);
  eventer_add(e);
  return mtev_true;
}

static void lstop (lua_State *L, lua_Debug *ar) {
  (void)ar;  /* unused arg. */
  mtev_lua_resume_info_t *ri = mtev_lua_find_resume_info(L, mtev_false);
  if(!ri || ri->lmc->interrupt_mode == INTERRUPT_ERRORS) {
    if(ri) ri->lmc->wants_restart = true;
    lua_sethook(L, NULL, 0, 0);  /* reset hook */
    luaL_error(L, "interrupted!");
  }

  L = ri->coro_state;
  if(!lua_isyieldable(L)) {
    return;
  }
  lua_sethook(L, NULL, 0, 0);  /* reset hook */
  stats_add64(state_preemptions, 1);
  eventer_add_in_s_us(mtev_lua_preempt_resume, L, 0, 0);
  mtev_lua_yield(ri, 0);
}

static void
mtev_lua_timer_fire(int sig, siginfo_t *info, void *c) {
  (void)sig;
  (void)info;
  (void)c;
  mtevL(nldeb, "timer fired: lua %p\n", tls_active_lua_state);

  if(tls_active_lua_state) {
    lua_sethook(tls_active_lua_state, lstop, LUA_MASKCOUNT, 1);
  }
}

int
mtev_lua_resume(lua_State *L, int a, mtev_lua_resume_info_t *ri) {
  int rv;
  struct timeval diff = { .tv_sec = 0, .tv_usec = 0 };
  lua_State *previous = tls_active_lua_state;
  tls_active_lua_state = L;
  if(eventer_heartbeat_deadline(NULL, &diff)) {
    sub_timeval(diff, (struct timeval){ .tv_sec = 2, .tv_usec = 0 }, &diff);
    if(diff.tv_sec < 0 || diff.tv_usec < 0) {
      mtevL(nlerr, "lua attempting to resume with no time left before watchdog\n");
      mtev_stacktrace(nlerr);
      diff.tv_sec = 0;
      diff.tv_usec = 1;
    }
  }
  if(ri && ri->lmc) {
    if(!(ri->lmc->interrupt_time.tv_sec == 0 && ri->lmc->interrupt_time.tv_usec == 0)) {
      /* if we have an interrupt time specified for this lmc, then we should potentially reduce to it */
      if((diff.tv_sec == 0 && diff.tv_usec == 0) ||
         compare_timeval(ri->lmc->interrupt_time, diff) < 0) {
        diff = ri->lmc->interrupt_time;
      }
    }
    if(diff.tv_sec >= 0 && diff.tv_usec >= 0) {
      mtev_lua_timer_start(ri->lmc->timer, &diff);
    }
  }
  rv = lua_resume(L, a);
  if(ri && ri->lmc) mtev_lua_timer_stop(ri->lmc->timer);
  tls_active_lua_state = previous;
  return rv;
}
int
mtev_lua_pcall(lua_State *L, int a, int b, int c) {
  int rv;
  lua_State *previous = tls_active_lua_state;
  tls_active_lua_state = L;
  rv = lua_pcall(L, a, b, c);
  tls_active_lua_state = previous;
  return rv;
}
static mtev_hook_return_t
mtev_lua_stacktrace_assist(void *closure, void (*cb)(void *, const char *, size_t), void *cb_closure,
                           uintptr_t pc, const char *fname, const char *sname, int frame, int nframes) {
  (void)closure;
  (void)pc;
  (void)sname;
  if(frame == 0) assist_fired = false;
  if(tls_active_lua_state == NULL) return MTEV_HOOK_CONTINUE;
  if(!assist_fired && NULL != fname && NULL != strstr(fname, "libluajit")) {
    if(tls_active_lua_state) {
      mtev_luaL_traceback(cb, cb_closure, tls_active_lua_state,
                          "-- mtev lua runtime stacktrace --", 0);
      assist_fired = true;
    }
  }
  if(frame == nframes-1 && !assist_fired && tls_active_lua_state) {
    mtev_luaL_traceback(cb, cb_closure, tls_active_lua_state,
                        "-- mtev lua runtime stacktrace --", 0);
    assist_fired = true;
  }
  return MTEV_HOOK_CONTINUE;
}
int
mtev_lua_lmc_resume(lua_module_closure_t *lmc,
                    mtev_lua_resume_info_t *ri, int nargs) {
  int rv;
  lua_State *previous = tls_active_lua_state;
  tls_active_lua_state = ri->coro_state;
  mtev_lua_ref(lmc);
  rv = lmc->resume(ri, nargs);
  mtev_lua_deref(lmc);
  tls_active_lua_state = previous;
  return rv;
}

lua_State *
mtev_lua_lmc_L(lua_module_closure_t *lmc) {
  return lmc->lua_state;
}

lua_State *
mtev_lua_lmc_setL(lua_module_closure_t *lmc, lua_State *L) {
  lua_State *prev = lmc->lua_state;
  lmc->lua_state = L;
  return prev;
}

void
mtev_lua_cancel_coro(mtev_lua_resume_info_t *ci) {
  mtevL(nldeb, "coro_store <- %p\n", ci->coro_state);
  luaL_unref(ci->lmc->lua_state, LUA_REGISTRYINDEX, ci->coro_state_ref);
  /* IF we want a restart, we're going to toss everyrhing,
   * so don't pay for GC inline here.
   */
  if(!ci->lmc->wants_restart) {
    mtev_lua_gc_full(ci->lmc);
  }
  mtevAssert(mtev_hash_delete(&ci->lmc->state_coros,
                          (const char *)&ci->coro_state, sizeof(ci->coro_state),
                          NULL, NULL));
  pthread_mutex_lock(&coro_lock);
  mtevAssert(mtev_hash_delete(&mtev_coros,
                          (const char *)&ci->coro_state, sizeof(ci->coro_state),
                          free, NULL));
  pthread_mutex_unlock(&coro_lock);
  mtevL(nldeb, "coro_store <- %p [deleted]\n", ci->coro_state);
  ci->coro_state = NULL;
  ci->coro_state_ref = 0;
}

void
mtev_lua_set_resume_info(lua_State *L, mtev_lua_resume_info_t *ri) {
  lua_getglobal(L, "mtev_internal_lmc");
  ri->lmc = lua_touserdata(L, lua_gettop(L));
  lua_pop(L,1);
  mtevL(nldeb, "coro_store -> %p\n", ri->coro_state);
  lua_State **Lp = malloc(sizeof(*Lp));
  *Lp = ri->coro_state;
  mtevAssert(mtev_hash_store(&ri->lmc->state_coros,
                             (const char *)Lp, sizeof(*Lp),
                             ri)); 
  pthread_mutex_lock(&coro_lock);
  mtevAssert(mtev_hash_store(&mtev_coros,
                             (const char *)Lp, sizeof(*Lp),
                             ri));
  pthread_mutex_unlock(&coro_lock);
}

struct lua_context_describer {
  int context_magic;
  void (*describe)(mtev_console_closure_t, mtev_lua_resume_info_t *);
  void (*describe_json)(mtev_json_object *, mtev_lua_resume_info_t *);
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
                          void (*j)(mtev_json_object *,
                                    mtev_lua_resume_info_t *)) {
  struct lua_context_describer *desc = calloc(1,sizeof(*desc));
  desc->context_magic = magic;
  desc->describe_json = j;
  desc->next = context_describers;
  context_describers = desc;
}

static void
describe_lua_context_json(mtev_json_object *jcoro,
                          mtev_lua_resume_info_t *ri) {
  struct lua_context_describer *desc;
  switch(ri->context_magic) {
    case LUA_GENERAL_INFO_MAGIC:
      MJ_KV(jcoro, "context", MJ_STR("lua_general"));
      break;
    case LUA_REST_INFO_MAGIC:
      MJ_KV(jcoro, "context", MJ_STR("lua_web"));
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
  eventer_pool_t *pool;
  enum { LUA_REPORT_NCCT, LUA_REPORT_JSON } approach;
  int timeout_ms;
  mtev_http_rest_closure_t *restc;
  struct timeval start;
  mtev_console_closure_t ncct;
  mtev_json_object *root;
  uint32_t outstanding;
  mtev_hash_table *args;
};

static struct lua_reporter *
mtev_lua_reporter_alloc(void) {
    struct lua_reporter *reporter;
    reporter = calloc(1, sizeof(*reporter));
    mtev_gettimeofday(&reporter->start, NULL);
    pthread_mutex_init(&reporter->lock, NULL);
    reporter->outstanding = 1;
    return reporter;
}
static void mtev_lua_reporter_ref(struct lua_reporter *reporter) {
    ck_pr_inc_32(&reporter->outstanding);
}
static void mtev_lua_reporter_deref(struct lua_reporter *reporter) {
  bool zero;
  ck_pr_dec_32_zero(&reporter->outstanding, &zero);
  if(zero) {
    if(reporter->ncct) reporter->ncct = NULL;
    if(reporter->root) MJ_DROP(reporter->root);
    reporter->root = NULL;
    pthread_mutex_destroy(&reporter->lock);
    free(reporter);
  }
}
static int
mtev_console_lua_thread_reporter_json(eventer_t e, int mask, void *closure,
                                      struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  struct lua_reporter *reporter = closure;
  mtev_hash_iter zero = MTEV_HASH_ITER_ZERO, iter;
  pthread_t me;
  me = pthread_self();
  mtevAssert(reporter->approach == LUA_REPORT_JSON);
  mtev_json_object *states = NULL;

  pthread_mutex_lock(&reporter->lock);
  states = mtev_json_object_object_get(reporter->root, "states");
  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_adv(&mtev_lua_states, &iter)) {
    mtev_json_object *state_info = NULL;
    char state_str[32];
    char thr_str[32];
    lua_State **Lptr = (lua_State **)iter.key.ptr;
    lua_module_closure_t *lmc = iter.value.ptr;
    pthread_t tgt = lmc->owner;
    if(!pthread_equal(me, tgt)) continue;

    int thr_id = eventer_is_loop(me);
    snprintf(thr_str, sizeof(thr_str), "0x%llx", (unsigned long long)(uintptr_t)me);
    if (thr_id >= 0) snprintf(thr_str, sizeof(thr_str), "%d", thr_id);
    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)*Lptr);
    MJ_KV(states, state_str, state_info = MJ_OBJ());
    MJ_KV(state_info, "thread", MJ_STR(thr_str));
    MJ_KV(state_info, "bytes", MJ_INT64(lua_gc(*Lptr, LUA_GCCOUNT, 0)*1024));
    MJ_KV(state_info, "coroutines", MJ_OBJ());
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);

  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&coro_lock);
  while(mtev_hash_adv(&mtev_coros, &iter)) {
    char state_str[32];
    mtev_json_object *state_info, *jcoros, *jcoro, *jstack;
    mtev_lua_resume_info_t *ri;
    int level = 1;
    lua_Debug ar;
    lua_State *L;

    mtevAssert(iter.klen == sizeof(L));
    L = *((lua_State **)iter.key.ptr);
    ri = iter.value.ptr;
    if(!pthread_equal(me, ri->lmc->owner)) continue;

    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)ri->lmc->lua_state);
    state_info = mtev_json_object_object_get(states, state_str);
    if(!state_info) continue;
    jcoros = mtev_json_object_object_get(state_info, "coroutines");

    /* make state_str now point to this state */
    snprintf(state_str, sizeof(state_str), "0x%llx", (unsigned long long)(uintptr_t)L);

    MJ_KV(jcoros, state_str, jcoro = MJ_OBJ());
    describe_lua_context_json(jcoro, ri);
    while (lua_getstack(L, level++, &ar));
    level--;
    MJ_KV(jcoro, "stack", jstack = MJ_ARR());
    while (level > 0 && lua_getstack(L, --level, &ar)) {
      struct json_object *jsentry;
      const char *name;
      lua_getinfo(L, "n", &ar);
      name = ar.name;
      lua_getinfo(L, "Snlf", &ar);
      if(!ar.source) ar.source = "???";
      if(ar.name == NULL) ar.name = name;
      if(ar.name == NULL) ar.name = "???";
      MJ_ADD(jstack, jsentry = MJ_OBJ());
      MJ_KV(jsentry, "file", MJ_STR(ar.source));
      if (ar.currentline > 0) MJ_KV(jsentry, "line", MJ_INT(ar.currentline));
      if (*ar.namewhat) MJ_KV(jsentry, "namewhat", MJ_STR(ar.namewhat));
      MJ_KV(jsentry, "name", MJ_STR(ar.name));
    }
  }
  pthread_mutex_unlock(&coro_lock);
  pthread_mutex_unlock(&reporter->lock);
  mtev_lua_reporter_deref(reporter);
  return 0;
}
static int
mtev_console_lua_thread_reporter_ncct(eventer_t e, int mask, void *closure,
                                      struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  struct lua_reporter *reporter = closure;
  mtev_console_closure_t ncct = reporter->ncct;
  mtev_hash_iter zero = MTEV_HASH_ITER_ZERO, iter;
  pthread_t me;
  me = pthread_self();
  mtevAssert(reporter->approach == LUA_REPORT_NCCT);

  pthread_mutex_lock(&reporter->lock);

  memcpy(&iter, &zero, sizeof(zero));
  bool header = false;
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_adv(&mtev_lua_states, &iter)) {
    lua_State **Lptr = (lua_State **)iter.key.ptr;
    lua_module_closure_t *lmc = iter.value.ptr;
    pthread_t tgt = lmc->owner;
    if(!pthread_equal(me, tgt)) continue;
    if(!header) {
      nc_printf(ncct, "== Thread %lx ==\n", (unsigned long)me);
      header = true;
    }
    nc_printf(ncct, "master (state:%p)\n", *Lptr);
    nc_printf(ncct, "\tgeneration: %" PRIu64"\n", lmc->gen);
    nc_printf(ncct, "\tmemory: %d kb\n", lua_gc(*Lptr, LUA_GCCOUNT, 0));
    if(lmc->gcparams) {
      lua_module_gc_params_t *p = lmc->gcparams;
      if(p->full_every) {
        nc_printf(ncct, "\tgc: %d/%d to full\n", p->iters_since_full, p->full_every);
      } else {
        nc_printf(ncct, "\tgc: full\n");
      }
    }
    
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);

  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&coro_lock);
  while(mtev_hash_adv(&mtev_coros, &iter)) {
    mtev_lua_resume_info_t *ri;
    int level = 1;
    lua_Debug ar;
    lua_State *L;
    mtevAssert(iter.klen == sizeof(L));
    L = *((lua_State **)iter.key.ptr);
    ri = iter.value.ptr;
    if(!pthread_equal(me, ri->lmc->owner)) continue;
    nc_printf(ncct, "\n");
    describe_lua_context_ncct(ncct, ri);
    mtevL(nldeb, "describing lua state %p\n", L);
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
dispatch_reporter(struct lua_reporter *reporter, eventer_func_t reporter_f, pthread_t tgt, mtev_boolean *include_me) {
  struct timeval old = { 1ULL, 0ULL };
  if(pthread_equal(tgt, pthread_self())) {
    *include_me = mtev_true;
  }
  else {
    eventer_t e;
    e = eventer_alloc_timer(reporter_f, reporter, &old);
    eventer_set_owner(e, tgt);
    mtev_lua_reporter_ref(reporter);
    eventer_add(e);
  }
}
static void
distribute_reporter_across_threads(struct lua_reporter *reporter,
                                   eventer_func_t reporter_f) {
  size_t i = 0;
  mtev_boolean include_me = mtev_false;

  mtev_lua_reporter_ref(reporter);

  if(reporter->pool) {
    for(i=0;i<eventer_pool_concurrency(reporter->pool);i++) {
      pthread_t tgt = eventer_choose_owner_pool(reporter->pool, i);
      dispatch_reporter(reporter, reporter_f, tgt, &include_me);
    }
  } else {
    /* go by tracked lmc */
    mtev_hash_iter iter = {};
    mtev_hash_table dups;
    mtev_hash_init(&dups);
    pthread_mutex_lock(&mtev_lua_states_lock);
    while(mtev_hash_adv(&mtev_lua_states, &iter)) {
      lua_module_closure_t *lmc = iter.value.ptr;
      pthread_t tgt = lmc->owner;
      if(eventer_is_loop(tgt) < 0) {
        continue;
      }
      if(mtev_hash_store(&dups, &lmc->owner, sizeof(lmc->owner), NULL)) {
        dispatch_reporter(reporter, reporter_f, tgt, &include_me);
      }
    }
    pthread_mutex_unlock(&mtev_lua_states_lock);
    mtev_hash_destroy(&dups, NULL, NULL);
  }

  if(include_me)
    reporter_f(NULL, 0, reporter, NULL);
  else
    mtev_lua_reporter_deref(reporter);
}

static int
mtev_lua_rest_show_waiter(eventer_t e, int mask, void *closure,
                          struct timeval *now) {
  (void)e;
  (void)mask;
  struct lua_reporter *reporter = closure;
  mtev_http_rest_closure_t *restc = reporter->restc;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  int age = sub_timeval_ms(*now, reporter->start);

  /* If we're not ready and we've not timed out */
  if(ck_pr_load_32(&reporter->outstanding) > 1 && age < reporter->timeout_ms) {
    eventer_add_in_s_us(mtev_lua_rest_show_waiter, reporter, 0, 100000);
    return 0;
  }
  eventer_t conne = mtev_http_connection_event(mtev_http_session_connection(ctx));
  if(conne) {
    eventer_trigger(conne, EVENTER_WRITE);
  }
  return 0;
}
static int
mtev_rest_show_lua_complete(mtev_http_rest_closure_t *restc, int n, char **p) {
  (void)n;
  (void)p;
  struct lua_reporter *reporter = restc->call_closure;

  mtev_http_response_ok(restc->http_ctx, "application/json");
  pthread_mutex_lock(&reporter->lock);
  mtev_http_response_append_json(restc->http_ctx, reporter->root);
  pthread_mutex_unlock(&reporter->lock);
  mtev_http_response_end(restc->http_ctx);

  mtev_lua_reporter_deref(reporter);
  return 0;
}
static int
mtev_rest_show_lua(mtev_http_rest_closure_t *restc, int n, char **p) {
  (void)n;
  (void)p;
  eventer_pool_t *pool;
  struct lua_reporter *crutch;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  crutch = mtev_lua_reporter_alloc();
  const char *loopname = mtev_http_request_querystring(req, "loop");
  if(loopname) {
    pool = eventer_pool(loopname);
    if(pool) crutch->pool = pool;
  }
  crutch->restc = restc;
  crutch->approach = LUA_REPORT_JSON;
  crutch->root = MJ_OBJ();
  MJ_KV(crutch->root, "metadata", MJ_OBJ());
  MJ_KV(crutch->root, "states", MJ_OBJ());
  distribute_reporter_across_threads(crutch, mtev_console_lua_thread_reporter_json);
  restc->call_closure = crutch;
  restc->fastpath = mtev_rest_show_lua_complete;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  eventer_t conne = mtev_http_connection_event_float(mtev_http_session_connection(ctx));
  if(conne) {
    eventer_remove_fde(conne);
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
  (void)dstate;
  (void)closure;
  struct lua_reporter *crutch;

  crutch = mtev_lua_reporter_alloc();
  if(argc == 1) {
    eventer_pool_t *pool = eventer_pool(argv[0]);
    if(!pool) {
      nc_printf(ncct, "No such loop, using default\n");
    }
    else crutch->pool = pool;
  }
  crutch->approach = LUA_REPORT_NCCT;
  crutch->ncct = ncct;
  distribute_reporter_across_threads(crutch, mtev_console_lua_thread_reporter_ncct);
  /* Wait for completion */
  while(ck_pr_load_32(&crutch->outstanding) > 1) {
    usleep(500);
  }
  mtev_lua_reporter_deref(crutch);
  return 0;
}

static int
mtev_console_lua_actuate(mtev_console_closure_t ncct,
                         int argc, char **argv,
                         mtev_console_state_t *dstate,
                         void *closure) {
  (void)dstate;
  bool terminate = (bool)(uintptr_t)closure;
  if(argc != 1) {
    nc_printf(ncct, "lua_State in hex required\n");
    return 0;
  }
  char *endptr;
  lua_State *co = NULL;
  if(!strncasecmp(argv[0], "0x", 2)) {
    uintptr_t ptr = strtoull(argv[0]+2, &endptr, 16);
    if(*endptr == '\0') co = (lua_State *)ptr;
  } else {
    uintptr_t ptr = strtoull(argv[0], &endptr, 10);
    if(*endptr == '\0') co = (lua_State *)ptr;
  }
  if(!co) {
    nc_printf(ncct, "could not parse lua_State\n");
    return 0;
  }
  if(!mtev_lua_actuate_foreign_state(co, terminate)) {
    nc_printf(ncct, "Could not find lua_State 0x%zx\n", (uintptr_t)co);
  }
  return 0;
}

static int
mtev_rest_bump_lua(mtev_http_rest_closure_t *restc, int n, char **p) {
  (void)n;
  (void)p;
  ck_pr_inc_64(&global_gen);
  mtev_http_response_ok(restc->http_ctx, "application/json");
  mtev_http_response_appendf(restc->http_ctx, "{\"gen\":%" PRIu64 "}\n", global_gen);
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

static int
mtev_lua_xcall_reporter(eventer_t e, int mask, void *closure,
                               struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  struct lua_reporter *reporter = closure;
  mtev_hash_iter zero = MTEV_HASH_ITER_ZERO, iter;
  pthread_t me = pthread_self();
  mtev_json_object *states = NULL;

  mtevAssert(reporter->approach == LUA_REPORT_JSON);

  pthread_mutex_lock(&reporter->lock);
  states = reporter->root;
  memcpy(&iter, &zero, sizeof(zero));
  pthread_mutex_lock(&mtev_lua_states_lock);
  while(mtev_hash_adv(&mtev_lua_states, &iter)) {
    lua_State *L = *((lua_State **) iter.key.ptr);
    lua_module_closure_t *lmc = iter.value.ptr;
    pthread_t tgt = lmc->owner;
    char state_str[32];
    mtev_json_object *out;
    if(!pthread_equal(me, tgt)) continue;
    snprintf(state_str, sizeof(state_str), "%p", (void*)L);
    lua_getglobal(L, "mtev_xcall");
    if(lua_isnil(L, -1)) {
      continue;
    }
    else {
      mtev_lua_hash_to_table(L, reporter->args);
      /*  Invoke xcall() */
      lua_call(L, 1, 1);
      if(lua_isnil(L, -1)) {
        /* skip lua states that return an explicit nil */
        continue;
      }
      /* Convert results to json via mtev.tojson(...):unwrap() */
      lua_getglobal(L, "mtev");
      lua_getfield(L, -1, "tojson");
      lua_remove(L, -2);
      lua_insert(L, -2);
      lua_call(L, 1, 1);
      lua_getfield(L, -1, "unwrap");
      lua_insert(L, -2);
      lua_call(L, 1, 1);
      mtev_json_object **udata = luaL_checkudata(L, -1, "mtev.json_object");
      out = (*udata);
    }
    MJ_KV(states, state_str, out);
  }
  pthread_mutex_unlock(&mtev_lua_states_lock);
  pthread_mutex_unlock(&reporter->lock);
  mtev_lua_reporter_deref(reporter);
  return 0;
}

/* GET /module/lua/xcall.json

   Calls _G.mtev_xcall(querystring_table) in each Lua State.
   Returns serialized output values as as JSON object of the form:

        { "$stateptr" : <val> }

*/
static int
mtev_lua_xcall(mtev_http_rest_closure_t *restc, int n, char **p) {
  (void)n;
  (void)p;
  struct lua_reporter *reporter;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);
  reporter = mtev_lua_reporter_alloc();
  reporter->restc = restc;
  reporter->approach = LUA_REPORT_JSON;
  reporter->root = MJ_OBJ();
  reporter->args = mtev_http_request_querystring_table(req);

  distribute_reporter_across_threads(reporter, mtev_lua_xcall_reporter);
  restc->call_closure = reporter;
  restc->fastpath = mtev_rest_show_lua_complete;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  eventer_t conne = mtev_http_connection_event_float(mtev_http_session_connection(ctx));
  if(conne) {
    eventer_remove_fde(conne);
  }

  /* Register our waiter */
  const char *timeout = mtev_http_request_querystring(req, "timeout");
  if(timeout) reporter->timeout_ms = atoi(timeout);
  if(reporter->timeout_ms <= 0) reporter->timeout_ms = 5000;
  eventer_add_in_s_us(mtev_lua_rest_show_waiter, reporter, 0, 0);
  return 0;
}

void
register_console_lua_commands(void) {
  static int loaded = 0;
  mtev_console_state_t *tl, *luast;
  cmd_info_t *showcmd, *mtevcmd;

  if(loaded) return;
  loaded = 1;
  tl = mtev_console_state_initial();
  showcmd = mtev_console_state_get_cmd(tl, "show");
  mtevAssert(showcmd && showcmd->dstate);
  mtev_console_state_add_cmd(showcmd->dstate,
    NCSCMD("lua", mtev_console_show_lua, NULL, NULL, NULL));

  mtevcmd = mtev_console_state_get_cmd(tl, "mtev");
  mtevAssert(mtevcmd && mtevcmd->dstate);
  luast = mtev_console_mksubdelegate(mtevcmd->dstate, "lua");

  mtev_console_state_add_cmd(luast,
      NCSCMD("cancel", mtev_console_lua_actuate, NULL, NULL, (void *)(uintptr_t)0));

  mtev_console_state_add_cmd(luast,
      NCSCMD("kill", mtev_console_lua_actuate, NULL, NULL, (void *)(uintptr_t)1));

  mtevAssert(mtev_http_rest_register_auth(
    "POST", "/module/lua/", "^bump\\.json$",
    mtev_rest_bump_lua, mtev_http_rest_client_cert_auth
  ) == 0);

  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/module/lua/", "^state\\.json$",
    mtev_rest_show_lua, mtev_http_rest_client_cert_auth
  ) == 0);

  mtevAssert(mtev_http_rest_register_auth(
    "GET", "/module/lua/", "^xcall\\.json$",
    mtev_lua_xcall, mtev_http_rest_client_cert_auth
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
  (void)ri;
  mtevL(mtev_error, "mtev_lua_new_coro is an invalid API.\n");
  mtev_stacktrace(mtev_error);
  return;
}

static mtev_lua_resume_info_t *
mtev_lua_get_resume_info_internal(lua_State *L, mtev_boolean create, mtev_boolean any_thread) {
  mtev_lua_resume_info_t *ri;
  void *v = NULL;
  pthread_mutex_lock(&coro_lock);
  if(mtev_hash_retrieve(&mtev_coros, (const char *)&L, sizeof(L), &v)) {
    pthread_mutex_unlock(&coro_lock);
    ri = v;
    if(!any_thread) mtevAssert(pthread_equal(pthread_self(), ri->bound_thread));
    return ri;
  }
  if(!create) {
    pthread_mutex_unlock(&coro_lock);
    return NULL;
  }
  ri = calloc(1, sizeof(*ri));
  ri->bound_thread = pthread_self();
  ri->coro_state = L;
  lua_getglobal(L, "mtev_internal_lmc");;
  ri->lmc = lua_touserdata(L, lua_gettop(L));
  lua_pop(L, 1);
  mtevL(nldeb, "coro_store -> %p\n", ri->coro_state);
  lua_pushthread(L);
  ri->coro_state_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  
  lua_State **Lp = malloc(sizeof(*Lp));
  *Lp = ri->coro_state;
  mtevAssert(mtev_hash_store(&ri->lmc->state_coros,
                  (const char *)Lp, sizeof(*Lp),
                  ri));
  mtevAssert(mtev_hash_store(&mtev_coros,
                  (const char *)Lp, sizeof(*Lp),
                  ri));
  pthread_mutex_unlock(&coro_lock);
  return ri;
}
mtev_lua_resume_info_t *
mtev_lua_get_resume_info(lua_State *L) {
  mtev_lua_resume_info_t *ri = mtev_lua_get_resume_info_internal(L, mtev_true, mtev_false);
  return ri;
}
mtev_lua_resume_info_t *
mtev_lua_find_resume_info(lua_State *L, mtev_boolean lua_error) {
  mtev_lua_resume_info_t *ri = mtev_lua_get_resume_info_internal(L, mtev_false, mtev_false);
  if(ri == NULL && lua_error) luaL_error(L, "coro terminated");
  return ri;
}
mtev_lua_resume_info_t *
mtev_lua_find_resume_info_any_thread(lua_State *L) {
  mtev_lua_resume_info_t *ri = mtev_lua_get_resume_info_internal(L, mtev_false, mtev_true);
  return ri;
}

static void
mtev_event_dispose(void *ev) {
  int mask;
  eventer_t *value = ev;
  eventer_t removed, e = *value;
  struct nl_generic_cl *cl;
  if(e == NULL) {
    free(ev);
    return;
  }
  mtevL(nldeb, "lua check cleanup: dropping (%p)->fd (%d)\n", e, eventer_get_fd(e));
  if(eventer_get_mask(e) != 0) {
    removed = eventer_remove(e);
    mtevL(nldeb, "    remove from eventer system %s\n",
          removed ? "succeeded" : "failed");
  }
  cl = eventer_get_closure(e);
  if(cl) {
    if(eventer_get_fd_opset(e) != NULL) {
      mtevL(nldeb, "    closing down fd %d\n", eventer_get_fd(e));
      eventer_close(e, &mask);
    }
    if(cl && cl->free) cl->free(cl);
    eventer_set_closure(e, NULL);
  }
  eventer_free(e);
  free(ev);
}
void
mtev_lua_register_event(mtev_lua_resume_info_t *ci, eventer_t e) {
  eventer_t *eptr;
  eptr = calloc(1, sizeof(*eptr));
  *eptr = e;
  if(!ci->events) {
    ci->events = calloc(1, sizeof(*ci->events));
    mtev_hash_init(ci->events);
  }
  mtevL(nldeb, "register_event( in: %p , e: %p )\n", ci->coro_state, e);
  mtevAssert(mtev_hash_store(ci->events, (const char *)eptr, sizeof(*eptr), eptr));
}
void
mtev_lua_deregister_event(mtev_lua_resume_info_t *ci, eventer_t e,
                                int tofree) {
  mtevAssert(ci->events);
  uintptr_t eptr = (uintptr_t)e;
  mtevL(nldeb, "deregister_event( in: %p , e: %p )\n", ci->coro_state, e);
  mtevAssert(mtev_hash_delete(ci->events, (const char *)&eptr, sizeof(uintptr_t),
                          NULL, tofree ? mtev_event_dispose : free));
}
void
mtev_lua_resume_clean_events(mtev_lua_resume_info_t *ci) {
  if(ci->events == NULL) return;
  mtevL(nldeb, "clean_events( in: %p )\n", ci->coro_state);
  mtev_hash_destroy(ci->events, NULL, mtev_event_dispose);
  free(ci->events);
  ci->events = NULL;
  mtevL(nldeb, "cleaned_events( in: %p )\n", ci->coro_state);
}

void
mtev_lua_pushmodule(lua_State *L, const char *m) {
  int stack_pos = 0;
  char *copy, *part, *brkt = NULL;
  copy = malloc(strlen(m)+1);
  mtevAssert(copy);
  memcpy(copy,m,strlen(m)+1);

  for(part = strtok_r(copy, ".", &brkt);
      part;
      part = strtok_r(NULL, ".", &brkt)) {
    if(stack_pos) {
      if(lua_isnil(L, stack_pos)) {
        free(copy);
        return;
      }
      lua_getfield(L, stack_pos, part);
    }
    else lua_getglobal(L, part);
    if(stack_pos == -1) lua_remove(L, -2);
    else stack_pos = -1;
  }
  free(copy);
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
  int kcnt;
  kcnt = t ? mtev_hash_size(t) : 0;
  lua_createtable(L, 0, kcnt);
  if(t) {
    while(mtev_hash_adv(t, &iter)) {
      if(iter.value.str != NULL) {
        lua_pushlstring(L, iter.value.str, strlen(iter.value.str));
        lua_setfield(L, -2, iter.key.str);
      }
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

mtev_lua_resume_info_t *
mtev_lua_new_resume_info(lua_module_closure_t *lmc, int magic) {
  mtev_lua_resume_info_t *ri;
  ri = calloc(1, sizeof(*ri));
  mtevAssert(pthread_equal(lmc->owner, pthread_self()));
  ri->bound_thread = lmc->owner;
  ri->context_magic = magic;
  ri->lmc = lmc;
  ri->coro_state = lua_newthread(lmc->lua_state);
  ri->coro_state_ref = luaL_ref(lmc->lua_state, LUA_REGISTRYINDEX);
  mtev_lua_set_resume_info(lmc->lua_state, ri);
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

  if(new_ri_f == NULL) new_ri_f = ri_parent->new_ri_f;

  ri = new_ri_f(ri_parent->lmc);
  ri->new_ri_f = new_ri_f;
  L = ri->coro_state;
  lua_xmove(Lp, L, nargs);
#if !defined(LUA_JITLIBNAME) && LUA_VERSION_NUM < 502
  lua_setlevel(Lp, L);
#endif
  mtev_lua_ref(ri->lmc);
  mtev_lua_lmc_resume(ri->lmc, ri, nargs-1);
  return 0;
}

static char *
package_manip_path(char *in, const char *find, const char *replace) {
  char *ocp, *npath = in;
  if(NULL != (ocp = strstr(in, find))) {
    int nlen = strlen(in) + strlen(replace) + 1; //NUL term
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

static int MTEV_JIT_OFF(void) {
  static int jit_off = -1;
  if(jit_off == -1) {
    char *env = getenv("MTEV_JIT_OFF");
    jit_off = env ? atoi(env) : 0;
  }
  return jit_off;
}

static int MTEV_JIT_OPT(void) {
  static int jit_opt = -2;
  if(jit_opt == -2) {
    char *env = getenv("MTEV_JIT_OPT");
    jit_opt = env ? atoi(env) : -1;
  }
  return jit_opt;
}

lua_State *
mtev_lua_open(const char *module_name, void *lmc,
              const char *script_dir, const char *cpath) {
  (void)module_name;
  int rv;
  const char *existing_ppath, *existing_cpath;
  char *npath;
  lua_State *L = luaL_newstate(), **Lptr;
  lua_atpanic(L, &mtev_lua_panic);

  lua_gc(L, LUA_GCSTOP, 0);  /* stop collector during initialization */
  luaL_openlibs(L);  /* open libraries */

  if(MTEV_JIT_OFF()) {
    lua_getglobal(L, "jit");
    lua_getfield(L, -1, "off");
    lua_call(L, 0, 0);
    lua_pop(L, 1);
  }

  if(MTEV_JIT_OPT() >= 0) {
    lua_getglobal(L, "jit");
    lua_getfield(L, -1, "opt");
    lua_getfield(L, -1, "start");
    lua_pushinteger(L, MTEV_JIT_OPT());
    lua_call(L, 1, 0);
    lua_pop(L, 2);
  }

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

  require(L, rv, ffi);
  require(L, rv, mtev);
  require(L, rv, mtev.lua_init);

  lua_gc(L, LUA_GCRESTART, 0);

  if(lmc) {
    Lptr = malloc(sizeof(*Lptr));
    *Lptr = L;
    pthread_mutex_lock(&mtev_lua_states_lock);
    mtev_hash_store(&mtev_lua_states,
                    (const char *)Lptr, sizeof(*Lptr), lmc);
    pthread_mutex_unlock(&mtev_lua_states_lock);
  }

  return L;
}

int
mtev_lua_push_inet_ntop(lua_State *L, struct sockaddr *r) {
  char remote_str[128];
  int len;
  switch(r->sa_family) {
    case AF_INET:
      len = sizeof(struct sockaddr_in);
      inet_ntop(AF_INET, &((struct sockaddr_in *)r)->sin_addr,
                remote_str, len);
      lua_pushstring(L, remote_str);
      lua_pushinteger(L, ntohs(((struct sockaddr_in *)r)->sin_port));
      break;
    case AF_INET6:
      len = sizeof(struct sockaddr_in6);
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)r)->sin6_addr,
                remote_str, len);
      lua_pushstring(L, remote_str);
      lua_pushinteger(L, ntohs(((struct sockaddr_in6 *)r)->sin6_port));
      break;
    default:
      lua_pushnil(L);
      lua_pushnil(L);
  }
  return 2;
}

void
mtev_lua_init_globals(void) {
  release_jobq = eventer_jobq_retrieve("lua_release");
  mtev_hash_init(&mtev_lua_states);
  mtev_hash_init(&mtev_coros);
  mtev_stacktrace_frame_hook_register("mtev_lua", mtev_lua_stacktrace_assist, NULL);
  eventer_name_callback("mtev_lua_gc_callback", mtev_lua_gc_callback);
  eventer_name_callback("mtev_lua_release", mtev_lua_release);
  eventer_name_callback("mtev_lua_preempt_resume", mtev_lua_preempt_resume);
  lua_stats_ns = mtev_stats_ns(mtev_stats_ns(mtev_stats_ns(NULL, "mtev"), "modules"), "lua");
  stats_ns_add_tag(lua_stats_ns, "mtev-module", "lua");
  gc_full = stats_register(lua_stats_ns, "gc_full", STATS_TYPE_COUNTER);
  stats_handle_units(gc_full, STATS_UNITS_TRANSACTIONS);
  gc_total = stats_register(lua_stats_ns, "gc_total", STATS_TYPE_COUNTER);
  stats_handle_units(gc_total, STATS_UNITS_TRANSACTIONS);
  gc_latency = stats_register(lua_stats_ns, "gc_latency", STATS_TYPE_HISTOGRAM_FAST);
  stats_handle_units(gc_latency, STATS_UNITS_SECONDS);
  state_preemptions = stats_register(lua_stats_ns, "lua_preemptions", STATS_TYPE_COUNTER);
  stats_handle_tagged_name(state_preemptions, "preemptions");
  states_started = stats_register(lua_stats_ns, "lua_states_allocated", STATS_TYPE_COUNTER);
  stats_handle_tagged_name(states_started, "lua_states");
  stats_handle_add_tag(states_started, "state", "allocated");
  states_stopped = stats_register(lua_stats_ns, "lua_states_released", STATS_TYPE_COUNTER);
  stats_handle_tagged_name(states_stopped, "lua_states");
  stats_handle_add_tag(states_stopped, "state", "released");
  states_current = stats_register(lua_stats_ns, "lua_states_live", STATS_TYPE_UINT64);
  stats_handle_tagged_name(states_current, "lua_states");
  stats_handle_add_tag(states_current, "state", "live");

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = mtev_lua_timer_fire;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) == -1)
    mtevL(mtev_error, "sigaction failed: %s\n", strerror(errno));

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
    mtevL(mtev_error, "sigprocmask failed: %s\n", strerror(errno));

}
