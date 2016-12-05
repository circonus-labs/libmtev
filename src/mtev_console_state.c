/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
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
#include "mtev_version.h"
#include "eventer/eventer.h"
#include "eventer/eventer_impl_private.h"
#include "eventer/eventer_jobq.h"
#include "mtev_log.h"
#include "mtev_hash.h"
#include "mtev_time.h"
#include "mtev_listener.h"
#include "mtev_rest.h"
#include "mtev_console.h"
#include "mtev_tokenizer.h"
#include "mtev_capabilities_listener.h"

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcre.h>
#include <errno.h>
#include <sys/utsname.h>
#include <inttypes.h>

int cmd_info_comparek(const void *akv, const void *bv) {
  char *ak = (char *)akv;
  cmd_info_t *b = (cmd_info_t *)bv;
  return strcasecmp(ak, b->name);
}
int cmd_info_compare(const void *av, const void *bv) {
  cmd_info_t *a = (cmd_info_t *)av;
  cmd_info_t *b = (cmd_info_t *)bv;
  return strcasecmp(a->name, b->name);
}
static void
mtev_console_spit_event(eventer_t e, void *c) {
  struct timeval now, diff;
  mtev_console_closure_t ncct = c;
  char fdstr[12];
  char wfn[42];
  char funcptr[20];
  const char *cname;

  cname = eventer_name_for_callback_e(e->callback, e);
  snprintf(fdstr, sizeof(fdstr), " fd: %d", e->fd);
  mtev_gettimeofday(&now, NULL);
  sub_timeval(e->whence, now, &diff);
  snprintf(wfn, sizeof(wfn), " fires: %lld.%06ds", (long long)diff.tv_sec, (int)diff.tv_usec);
  snprintf(funcptr, sizeof(funcptr), "%p", e->callback);
  nc_printf(ncct, "  [%p]%s%s t@%s:%x [%c%c%c%c] -> %s(%p)\n",
            e,
            e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION) ? fdstr : "",
            e->mask & (EVENTER_TIMER) ?  wfn : "",
            eventer_pool_name(eventer_get_pool_for_event(e)), e->thr_owner,
            e->mask & EVENTER_READ ? 'r' : '-',
            e->mask & EVENTER_WRITE ? 'w' : '-',
            e->mask & EVENTER_EXCEPTION ? 'e' : '-',
            e->mask & EVENTER_TIMER ? 't' : '-',
            cname ? cname : funcptr, e->closure);
}
static void
mtev_console_spit_jobq(eventer_jobq_t *jobq, void *c) {
  mtev_console_closure_t ncct = c;
  int qlen = 0;
  nc_printf(ncct, "=== %s ===\n", jobq->queue_name);
  nc_printf(ncct, " concurrency: %d/%d\n", jobq->concurrency, jobq->desired_concurrency);
  sem_getvalue(&jobq->semaphore, &qlen);
  nc_printf(ncct, " total jobs: %lld\n", (long long int)jobq->total_jobs);
  nc_printf(ncct, " backlog: %d\n", jobq->backlog);
  nc_printf(ncct, " inflight: %d\n", jobq->inflight);
  nc_printf(ncct, " timeouts: %lld\n", (long long int)jobq->timeouts);
  nc_printf(ncct, " avg_wait_ms: %f\n", (double)jobq->avg_wait_ns/1000000.0);
  nc_printf(ncct, " avg_run_ms: %f\n", (double)jobq->avg_run_ns/1000000.0);
}
static int
mtev_console_eventer_timers(mtev_console_closure_t ncct, int argc, char **argv,
                            mtev_console_state_t *dstate, void *unused) {
  if(argc != 0) return -1;
  eventer_foreach_timedevent(mtev_console_spit_event, ncct);
  return 0;
}
static int
mtev_console_eventer_sockets(mtev_console_closure_t ncct, int argc, char **argv,
                             mtev_console_state_t *dstate, void *unused) {
  if(argc != 0) return -1;
  eventer_foreach_fdevent(mtev_console_spit_event, ncct);
  return 0;
}
static int
mtev_console_eventer_jobq(mtev_console_closure_t ncct, int argc, char **argv,
                             mtev_console_state_t *dstate, void *unused) {
  eventer_jobq_t *jobq;
  if(argc != 1) {
    eventer_jobq_process_each(mtev_console_spit_jobq, (void *)ncct);
    return 0;
  }
  jobq = eventer_jobq_retrieve(argv[0]);
  if(!jobq) {
    nc_printf(ncct, "no jobq found for '%s'\n", argv[0] ? argv[0] : "");
    return 0;
  }
  mtev_console_spit_jobq(jobq, ncct);
  return 0;
}

static int
mtev_console_eventer_memory(mtev_console_closure_t ncct, int argc, char **argv,
                            mtev_console_state_t *dstate, void *unused) {
  int64_t eventer_allocd, eventer_total;
  eventer_allocd = eventer_allocations_current();
  eventer_total = eventer_allocations_total();
  nc_printf(ncct, "current eventer_t allocations: %llu\n", eventer_allocd);
  nc_printf(ncct, "total eventer_t allocations: %llu\n", eventer_total);
  return 0;
}

static int
mtev_console_jobq(mtev_console_closure_t ncct, int argc, char **argv,
                  mtev_console_state_t *dstate, void *unused) {
  if(argc != 3) {
    nc_printf(ncct, "<jobq> concurrency <n>\n");
    return -1;
  }
  eventer_jobq_t *jobq;
  jobq = eventer_jobq_retrieve(argv[0]);
  if(jobq == NULL) {
    nc_printf(ncct, "No such jobq.\n");
    return -1;
  }
  if(strcmp(argv[1], "concurrency")) {
    nc_printf(ncct, "Unknown jobq command: %s\n", argv[1]);
  }
  uint32_t new_concurrency = strtoul(argv[2], NULL, 10);
  eventer_jobq_set_concurrency(jobq, new_concurrency);
  nc_printf(ncct, "Setting '%s' jobq concurrency to %u\n", jobq->queue_name, new_concurrency);
  return 0;
}

static int
mtev_console_coreclocks(mtev_console_closure_t ncct, int argc, char **argv,
                        mtev_console_state_t *dstate, void *unused) {
  int i = 0;
  mtev_time_coreclock_t info;
  mtev_boolean brief = mtev_true;
  if(argc == 1 && !strcmp(argv[0], "full")) brief = mtev_false;

  nc_printf(ncct, "   CPU  |  ticks/ns |             skew |       fast calls |      desyncs |\n");
  nc_printf(ncct, "--------+-----------+------------------+------------------+--------------+\n");
  while(mtev_time_coreclock_info(i++, &info)) {
    if(info.skew_ns == 0 && info.ticks_per_nano == 0 &&
       info.fast_calls == 0 && info.desyncs == 0 && brief) continue;
    nc_printf(ncct, "%7d | %.7f | %14" PRId64 "ns | %16" PRIu64 " | %12" PRIu64 " |\n",
              (i-1), info.ticks_per_nano, info.skew_ns, info.fast_calls, info.desyncs);
  }
  return 0;
}

static int
mtev_console_time_status(mtev_console_closure_t ncct, int argc, char **argv,
                         mtev_console_state_t *dstate, void *onoff) {
  const char *reason;
  mtev_boolean status;
  status = mtev_time_fast_mode(&reason);
  nc_printf(ncct, "rdtsc is current %s\n", status ? "active" : "inactive");
  if(reason) nc_printf(ncct, "%s\n", reason);
  return 0;
}

static int
mtev_console_coreclocks_toggle(mtev_console_closure_t ncct, int argc, char **argv,
                               mtev_console_state_t *dstate, void *onoff) {
  mtev_time_toggle_tsc(onoff != NULL);
  return 0;
}

static int
mtev_console_hang_action(eventer_t e, int m, void *cl, struct timeval *now) {
  pause();
  return 0;
}
int
mtev_console_hang(mtev_console_closure_t ncct, int argc, char **argv,
                   mtev_console_state_t *dstate, void *unused) {
  if(argc == 1) {
    int id = atoi(argv[0]);
    nc_printf(ncct, "hang: %d\n", id);
    eventer_t e = eventer_in_s_us(mtev_console_hang_action, NULL, 0, 0);
    e->thr_owner = eventer_choose_owner(id);
    eventer_add(e);
  } else {
    pause();
  }
  return 0;
}

cmd_info_t console_command_help = {
  "help", mtev_console_help, mtev_console_opt_delegate, NULL, NULL
};
cmd_info_t console_command_exit = {
  "exit", mtev_console_state_pop, NULL, NULL, NULL
};
cmd_info_t console_command_crash = {
  "crash", mtev_console_crash, NULL, NULL, NULL
};
cmd_info_t console_command_hang = {
  "hang", mtev_console_hang, NULL, NULL, NULL
};
cmd_info_t console_command_shutdown = {
  "shutdown", mtev_console_shutdown, NULL, NULL, NULL
};
cmd_info_t console_command_restart = {
  "restart", mtev_console_restart, NULL, NULL, NULL
};
cmd_info_t console_command_eventer_timers = {
  "timers", mtev_console_eventer_timers, NULL, NULL, NULL
};
cmd_info_t console_command_eventer_sockets = {
  "sockets", mtev_console_eventer_sockets, NULL, NULL, NULL
};
cmd_info_t console_command_eventer_jobq = {
  "jobq", mtev_console_eventer_jobq, NULL, NULL, NULL
};
cmd_info_t console_command_eventer_memory = {
  "memory", mtev_console_eventer_memory, NULL, NULL, NULL
};
cmd_info_t console_command_coreclocks = {
  "coreclocks", mtev_console_coreclocks, NULL, NULL, NULL
};
cmd_info_t console_command_jobq = {
  "jobq", mtev_console_jobq, NULL, NULL, (void *)1
};
cmd_info_t console_command_rdtsc_status = {
  "status", mtev_console_time_status, NULL, NULL, (void *)1
};
cmd_info_t console_command_rdtsc_enable = {
  "enable", mtev_console_coreclocks_toggle, NULL, NULL, (void *)1
};
cmd_info_t console_command_rdtsc_disable = {
  "disable", mtev_console_coreclocks_toggle, NULL, NULL, NULL
};

static int
mtev_console_version(mtev_console_closure_t ncct, int argc, char **argv,
                     mtev_console_state_t *dstate, void *unused) {
  char buff[256];
  struct utsname utsn;
  nc_printf(ncct,   "build sysname:\t%s\nbuild nodename:\t%s\n"
                    "build release:\t%s\nbuild version:\t%s\n"
                    "build machine:\t%s\n",
            UNAME_S, UNAME_N, UNAME_R, UNAME_V, UNAME_M);
  if(uname(&utsn) < 0)
    nc_printf(ncct, "run:\terror; %s\n", strerror(errno));
  else
    nc_printf(ncct, "run sysname:\t%s\nrun nodename:\t%s\n"
                    "run release:\t%s\nrun version:\t%s\n"
                    "run machine:\t%s\n",
              utsn.sysname, utsn.nodename, utsn.release, utsn.version, utsn.machine);
  nc_printf(ncct, "bitwidth:\t%dbit\n", (int)sizeof(void *)*8);
  mtev_build_version(buff, sizeof(buff));
  nc_printf(ncct, "version:\t%s\n", buff);
  mtev_capabilities_features_ncprint(ncct);
  return 0;
}
cmd_info_t console_command_version = {
  "version", mtev_console_version, NULL, NULL, NULL
};

static int
mtev_console_log_a_line(u_int64_t idx, const struct timeval *whence,
                        const char *line, size_t len, void *cl) {
  mtev_console_closure_t ncct = cl;
  (void)whence;
  nc_printf(ncct, "[%llu] %.*s", (unsigned long long)idx, (int)len, line);
  return 0;
}
static int
mtev_console_log_lines(mtev_console_closure_t ncct, int argc, char **argv,
                       mtev_console_state_t *dstate, void *unused) {
  mtev_log_stream_t ls;
  int log_lines = 23;
  if(argc < 1 || argc > 2) return -1;
  if(argc == 2) log_lines = atoi(argv[1]);
  ls = mtev_log_stream_find(argv[0]);
  if(!ls || strcmp(mtev_log_stream_get_type(ls),"memory")) {
    nc_printf(ncct, "No memory log '%s'\n", argv[0]);
    return 0;
  }
  mtev_log_memory_lines(ls, log_lines, mtev_console_log_a_line, ncct);
  return 0;
}
static char *
mtev_console_memory_log_opts(mtev_console_closure_t ncct,
                             mtev_console_state_stack_t *stack,
                             mtev_console_state_t *dstate,
                             int argc, char **argv, int idx) {
  mtev_log_stream_t *loggers;
  int cnt, i, offset = 0;

  if(argc == 1) {
    cnt = mtev_log_list(NULL, 0);
    if(cnt < 0 ) {
      cnt = 0 - cnt;
      loggers = alloca(sizeof(*loggers) * cnt);
      cnt = mtev_log_list(loggers, cnt);
      if(cnt > 0) {
        for(i=0;i<cnt;i++) {
          const char *name = mtev_log_stream_get_name(loggers[i]);
          const char *type = mtev_log_stream_get_type(loggers[i]);

          if(type && !strcmp(type, "memory")) {
            if(name && !strncmp(name, argv[0], strlen(argv[0]))) {
              if(offset == idx) return strdup(name);
              offset++;
            }
          }
        }
      }
    }
  }
  return NULL;
}

cmd_info_t console_command_log_lines = {
  "log", mtev_console_log_lines, mtev_console_memory_log_opts, NULL, NULL
};

cmd_info_t console_command_show_rest = {
  "rest", mtev_mtev_console_show, NULL, NULL, NULL
};

void
mtev_console_add_help(const char *topic, console_cmd_func_t topic_func,
                      console_opt_func_t ac) {
  mtev_console_state_t *s = console_command_help.dstate;
  if(!s) {
    console_command_help.dstate = s = calloc(1, sizeof(*s));
    mtev_skiplist_init(&s->cmds);
    mtev_skiplist_set_compare(&s->cmds, cmd_info_compare, cmd_info_comparek);
  }
  mtev_console_state_add_cmd(s, NCSCMD(topic, topic_func, ac, NULL, NULL));
}

static char *default_prompt = NULL;

void
mtev_console_set_default_prompt(const char *prompt) {
  char *tofree = default_prompt;
  default_prompt = strdup(prompt);
  if(tofree) free(tofree);
}
static char *
mtev_console_state_prompt(EditLine *el) {
  static char *tl = "mtev# ";
  if(default_prompt) return default_prompt;
  return tl;
}

static char *
apply_replace(const char *src, const char *name, const char *value) {
  char *result, *cp;
  const char *nextpat, *searchstart;
  char pat[256];
  int maxlen, patlen, vlen, slen;
  snprintf(pat, sizeof(pat), "{%s}", name);
  patlen = strlen(pat);
  vlen = strlen(value);
  slen = strlen(src);
  /* Worst case is just a stream of replacements. */
  maxlen = (slen / patlen) * MAX(vlen,patlen) + (slen % patlen) + 1;
  cp = result = malloc(maxlen);
  searchstart = src;
  while((nextpat = strstr(searchstart, pat)) != NULL) {
    memcpy(cp, searchstart, nextpat - searchstart); /* pull the prefix */
    cp += nextpat - searchstart;                    /* advance destination */
    memcpy(cp, value, vlen);                        /* copy replacement */
    cp += vlen;                                     /* advance destination */
    searchstart = nextpat + patlen;                 /* set new searchstart */
  }
  /* Pick up the trailer (plus '\0') */
  memcpy(cp, searchstart, strlen(searchstart)+1);
  return result;
}
static pcre *IP_match = NULL;
static pcre *numeric_match = NULL;
static int
expand_range(const char *range, char ***set, int max_count, const char **err) {
  int count, erroff, ovector[30], rv;
  char buff[32]; /* submatches */
  const char *pcre_err;
  *err = NULL;
  if(!IP_match) {
    IP_match = pcre_compile("^(full:)?(\\d+\\.\\d+\\.\\d+\\.\\d+)/(\\d+)$",
                            0, &pcre_err, &erroff, NULL);
    if(!IP_match) {
      *err = "IP match pattern failed to compile!";
      mtevL(mtev_error, "pcre_compiled failed offset %d: %s\n", erroff, pcre_err);
      return -1;
    }
  }
  if(!numeric_match) {
    numeric_match = pcre_compile("^(\\d+)(?:,(\\d+))?\\.\\.(\\d+)$",
                                 0, &pcre_err, &erroff, NULL);
    if(!numeric_match) {
      *err = "numeric match pattern failed to compile!";
      mtevL(mtev_error, "pcre_compiled failed offset %d: %s\n", erroff, pcre_err);
      return -1;
    }
  }
  rv = pcre_exec(IP_match, NULL, range, strlen(range), 0, 0, ovector, 30);
  if(rv >= 0) {
    int mask, full = 0, i;
    u_int32_t host_addr;
    struct in_addr addr;
    /* 0 is the full monty, 1 is "" or "full:", 2 is the IP, 3 is the mask */
    pcre_copy_substring(range, ovector, rv, 1, buff, sizeof(buff));
    full = buff[0] ? 1 : 0;
    pcre_copy_substring(range, ovector, rv, 3, buff, sizeof(buff));
    mask = atoi(buff);
    if(mask == 32) full = 1; /* host implies.. the host */
    if(mask < 0 || mask > 32) {
      *err = "invalid netmask";
      return 0;
    }
    count = 1 << (32-mask);
    pcre_copy_substring(range, ovector, rv, 2, buff, sizeof(buff));
    if(inet_pton(AF_INET, buff, &addr) != 1) {
      *err = "could not parse IP address";
      return 0;
    }
    host_addr = ntohl(addr.s_addr);
    host_addr &= ~((u_int32_t)count - 1);

    if(!full) count -= 2; /* No network or broadcast */
    if(count > max_count || !count) return -count;
    if(!full) host_addr++; /* Skip the network address */

    *set = malloc(count * sizeof(**set));
    for(i=0; i<count; i++)  {
      addr.s_addr = htonl(host_addr + i);
      inet_ntop(AF_INET, &addr, buff, sizeof(buff));
      (*set)[i] = strdup(buff);
    }
    return count;
  }
  rv = pcre_exec(numeric_match, NULL, range, strlen(range), 0, 0, ovector, 30);
  if(rv >= 0) {
    int s, n, e, i;
    pcre_copy_substring(range, ovector, rv, 1, buff, sizeof(buff));
    s = atoi(buff);
    pcre_copy_substring(range, ovector, rv, 3, buff, sizeof(buff));
    e = atoi(buff);
    pcre_copy_substring(range, ovector, rv, 2, buff, sizeof(buff));
    if(buff[0]) n = atoi(buff);
    else n = (s<e) ? s+1 : s-1;

    /* Ensure that s < n < e */
    if((s<e && s>n) || (s>e && s<n)) {
      *err = "mixed up sequence";
      return 0;
    }
    i = n - s; /* Our increment */
    if(i == 0) return 0;
    count = (e - s) / i + 1;
    *set = malloc(count * sizeof(**set));
    count = 0;
    for(; (i>0 && s<=e) || (i<0 && s>=e); s += i) {
      snprintf(buff, sizeof(buff), "%d", s);
      (*set)[count] = strdup(buff);
      count++;
    }
    return count;
  }
  *err = "cannot understand range";
  return 0;
}
int
mtev_console_generic_apply(mtev_console_closure_t ncct,
                           int argc, char **argv,
                           mtev_console_state_t *dstate,
                           void *closure) {
  int i, j, count;
  char *name, *range;
  char **nargv, **expanded = NULL;
  const char *err;
  int problems = 0;
  if(argc < 3) {
    nc_printf(ncct, "apply <name> <range> cmd ...\n");
    return -1;
  }
  name = argv[0];
  range = argv[1];
  argc -= 2;
  argv += 2;

  count = expand_range(range, &expanded, 256, &err);
  if(!count) {
    nc_printf(ncct, "apply error: '%s' range produced nothing [%s]\n",
              range, err ? err : "unknown error");
    mtevAssert(expanded == NULL);
    return -1;
  }
  if(count < 0) {
    nc_printf(ncct, "apply error: '%s' range would produce %d items.\n",
              range, count);
    return -1;
  }
  nargv = malloc(argc * sizeof(*nargv));
  for(i=0; i<count; i++) {
    for(j=0; j<argc; j++) nargv[j] = apply_replace(argv[j], name, expanded[i]);
    if(mtev_console_state_do(ncct, argc, nargv)) problems = -1;
    for(j=0; j<argc; j++) free(nargv[j]);
    free(expanded[i]);
  }
  free(nargv);
  free(expanded);
  return problems;
}

int
mtev_console_render_help(mtev_console_closure_t ncct,
                         mtev_console_state_t *dstate) {
  mtev_skiplist_node *iter = NULL;
  if(!dstate) {
    nc_printf(ncct, "No help available.\n");
    return -1;
  }
  for(iter = mtev_skiplist_getlist(&dstate->cmds); iter;
      mtev_skiplist_next(&dstate->cmds,&iter)) {
    cmd_info_t *cmd = iter->data;
    if(strcmp(cmd->name, "help")) nc_printf(ncct, "  ==> '%s'\n", cmd->name);
  }
  return 0;
}

int
mtev_console_state_delegate(mtev_console_closure_t ncct,
                            int argc, char **argv,
                            mtev_console_state_t *dstate,
                            void *closure) {
  mtev_console_state_stack_t tmps = { 0 };

  if(argc == 0) {
    mtev_console_render_help(ncct, dstate);
    nc_printf(ncct, "incomplete command.\n");
    return -1;
  }
  if(!dstate) {
    nc_printf(ncct, "internal error: no delegate state\n");
    return -1;
  }
  tmps.state = dstate;
  return _mtev_console_state_do(ncct, &tmps, argc, argv);
}

int
_mtev_console_state_do(mtev_console_closure_t ncct,
                       mtev_console_state_stack_t *stack,
                       int argc, char **argv) {
  mtev_skiplist_node *next, *amb = NULL;
  cmd_info_t *cmd;

  if(!argc) {
    mtev_console_render_help(ncct, stack->state);
    nc_printf(ncct, "arguments expected\n");
    return -1;
  }
  cmd = mtev_skiplist_find_neighbors(&stack->state->cmds, argv[0],
                                     NULL, NULL, &next);
  if(!cmd) {
    int ambiguous = 0;
    if(next) {
      cmd_info_t *pcmd = NULL;
      cmd = next->data;
      amb = next;
      mtev_skiplist_next(&stack->state->cmds, &amb);
      if(amb) pcmd = amb->data;
      /* So cmd is the next in line... pcmd is the one after that.
       * If they both strncasecmp to 0, we're ambiguous,
       *    neither, then we're not found.
       *    only cmd, then we've found a partial, unambiguous.
       */
      if(strncasecmp(cmd->name, argv[0], strlen(argv[0])) == 0) {
        if(pcmd && strncasecmp(pcmd->name, argv[0], strlen(argv[0])) == 0) {
          cmd = NULL;
          ambiguous = 1;
        }
        else if(strcasecmp(cmd->name, "exit") == 0) {
          cmd = NULL;
        }
      }
      else
        cmd = NULL;
    }
    if(!cmd) {
      if(ambiguous || !strcmp(argv[0], "?")) {
        char *partial = ambiguous ? argv[0] : "";
        if(ambiguous) nc_printf(ncct, "Ambiguous command: '%s'\n", argv[0]);
        amb = ambiguous ? next : mtev_skiplist_getlist(&stack->state->cmds);
        for(; amb; mtev_skiplist_next(&stack->state->cmds, &amb)) {
          cmd = amb->data;
          if(!strlen(partial) || strncasecmp(cmd->name, partial, strlen(partial)) == 0)
            nc_printf(ncct, "\t%s\n", cmd->name);
          else
            break;
        }
      }
      else {
        cmd = mtev_skiplist_find(&stack->state->cmds, "", NULL);
        if(cmd) {
          if(ncct->state_stack->name) free(ncct->state_stack->name);
          ncct->state_stack->name = strdup(cmd->name);
          return cmd->func(ncct, argc, argv, cmd->dstate, cmd->closure);
        }
        nc_printf(ncct, "No such command: '%s'\n", argv[0]);
      }
      return -1;
    }
  }
  if(ncct->state_stack->name) free(ncct->state_stack->name);
  ncct->state_stack->name = strdup(cmd->name);
  return cmd->func(ncct, argc-1, argv+1, cmd->dstate, cmd->closure);
}
int
mtev_console_state_do(mtev_console_closure_t ncct, int argc, char **argv) {
  return _mtev_console_state_do(ncct, ncct->state_stack, argc, argv);
}

mtev_console_state_t *
mtev_console_state_alloc_empty(void) {
  mtev_console_state_t *s;
  s = calloc(1, sizeof(*s));
  mtev_skiplist_init(&s->cmds);
  mtev_skiplist_set_compare(&s->cmds, cmd_info_compare, cmd_info_comparek);
  return s;
}

mtev_console_state_t *
mtev_console_state_alloc(void) {
  mtev_console_state_t *s;
  s = mtev_console_state_alloc_empty();
  mtev_console_state_add_cmd(s,
      NCSCMD("apply", mtev_console_generic_apply, NULL, NULL, NULL));
  mtev_console_state_add_cmd(s, &console_command_help);
  return s;
}

int
mtev_console_state_add_cmd(mtev_console_state_t *state,
                           cmd_info_t *cmd) {
  return (mtev_skiplist_insert(&state->cmds, cmd) != NULL);
}

cmd_info_t *
mtev_console_state_get_cmd(mtev_console_state_t *state,
                           const char *name) {
  cmd_info_t *cmd;
  cmd = mtev_skiplist_find(&state->cmds, name, NULL);
  return cmd;
}

mtev_console_state_t *
mtev_console_state_build(console_prompt_func_t promptf, cmd_info_t **clist,
                         state_free_func_t sfreef) {
  mtev_console_state_t *state;
  state = mtev_console_state_alloc();
  state->console_prompt_function = promptf;
  while(*clist) {
    mtev_skiplist_insert(&state->cmds, *clist);
    clist++;
  }
  state->statefree = sfreef;
  return state;
}

cmd_info_t *NCSCMD(const char *name, console_cmd_func_t func,
                   console_opt_func_t ac,
                   mtev_console_state_t *dstate, void *closure) {
  cmd_info_t *cmd;
  cmd = calloc(1, sizeof(*cmd));
  cmd->name = strdup(name);
  cmd->func = func;
  cmd->autocomplete = ac;
  cmd->dstate = dstate;
  cmd->closure = closure;
  return cmd;
}

mtev_console_state_t *
mtev_console_mksubdelegate(mtev_console_state_t *parent, const char *cmd) {
  mtev_console_state_t *child;
  cmd_info_t *existing;
  existing = mtev_console_state_get_cmd(parent, cmd);
  if(existing) return existing->dstate;
  child = mtev_console_state_alloc();
  mtev_console_state_add_cmd(parent,
                              NCSCMD(cmd, mtev_console_state_delegate,
                                     mtev_console_opt_delegate, child, NULL));
  return child;
}

mtev_console_state_t *
mtev_console_state_initial() {
  static mtev_console_state_t *_top_level_state = NULL;
  if(!_top_level_state) {
    static mtev_console_state_t *no_state, *show_state, *evdeb, *mtevdeb,
                                *mtevst, *rdtsc;
    _top_level_state = mtev_console_state_alloc();
    mtev_console_state_add_cmd(_top_level_state, &console_command_exit);
    show_state = mtev_console_mksubdelegate(_top_level_state, "show");
    no_state = mtev_console_mksubdelegate(_top_level_state, "no");

    mtev_console_state_add_cmd(_top_level_state, &console_command_crash);
    mtev_console_state_add_cmd(_top_level_state, &console_command_hang);
    mtev_console_state_add_cmd(_top_level_state, &console_command_shutdown);
    mtev_console_state_add_cmd(_top_level_state, &console_command_restart);
    mtev_console_state_add_cmd(show_state, &console_command_version);
    mtev_console_state_add_cmd(show_state, &console_command_log_lines);
    mtev_console_state_add_cmd(show_state, &console_command_show_rest);
    (void)no_state;

    evdeb = mtev_console_mksubdelegate(
              mtev_console_mksubdelegate(show_state,
                                         "eventer"),
                                       "debug");
    mtev_console_state_add_cmd(evdeb, &console_command_eventer_timers);
    mtev_console_state_add_cmd(evdeb, &console_command_eventer_sockets);
    mtev_console_state_add_cmd(evdeb, &console_command_eventer_jobq);
    mtev_console_state_add_cmd(evdeb, &console_command_eventer_memory);

    mtevdeb = mtev_console_mksubdelegate(
              mtev_console_mksubdelegate(show_state,
                                         "mtev"),
                                       "debug");
    mtev_console_state_add_cmd(mtevdeb, &console_command_coreclocks);

    mtevst = mtev_console_mksubdelegate(_top_level_state, "mtev");
    mtev_console_state_add_cmd(mtevst, &console_command_jobq);
    rdtsc = mtev_console_mksubdelegate(mtevst, "rdtsc");
    mtev_console_state_add_cmd(rdtsc, &console_command_rdtsc_status);
    mtev_console_state_add_cmd(rdtsc, &console_command_rdtsc_enable);
    mtev_console_state_add_cmd(rdtsc, &console_command_rdtsc_disable);
  }
  return _top_level_state;
}

void
mtev_console_state_push_state(mtev_console_closure_t ncct,
                              mtev_console_state_t *state) {
  mtev_console_state_stack_t *stack;
  stack = calloc(1, sizeof(*stack));
  stack->last = ncct->state_stack;
  stack->state = state;
  ncct->state_stack = stack;
}

static int
mtev_console_crash_action(eventer_t e, int m, void *cl, struct timeval *now) {
  *((volatile int *)0) = 0;
  return 0;
}
int
mtev_console_crash(mtev_console_closure_t ncct, int argc, char **argv,
                   mtev_console_state_t *dstate, void *unused) {
  if(argc == 1) {
    int id = atoi(argv[0]);
    nc_printf(ncct, "crash: %d\n", id);
    eventer_t e = eventer_in_s_us(mtev_console_crash_action, NULL, 0, 0);
    e->thr_owner = eventer_choose_owner(id);
    eventer_add(e);
  } else {
    *((volatile int *)0) = 0;
  }
  return 0;
}
int
mtev_console_shutdown(mtev_console_closure_t ncct, int argc, char **argv,
                      mtev_console_state_t *dstate, void *unused) {
  exit(2);
}
int
mtev_console_restart(mtev_console_closure_t ncct, int argc, char **argv,
                     mtev_console_state_t *dstate, void *unused) {
  exit(1);
}
int
mtev_console_help(mtev_console_closure_t ncct, int argc, char **argv,
                  mtev_console_state_t *dstate, void *unused) {
  mtev_console_state_stack_t *current;
  current = ncct->state_stack;

  if(!argc) {
    mtev_console_state_stack_t *i;
    if(!current) {
      nc_printf(ncct, "no state!\n");
      return -1;
    }
    for(i=current;i;i=i->last) {
      if(i != current)
        nc_printf(ncct, " -> '%s'\n", i->name ? i->name : "(null)");
    }
    if(dstate) {
      nc_printf(ncct, "= Topics =\n");
      mtev_console_render_help(ncct, dstate);
    }
    if(current->state) {
      nc_printf(ncct, "\n= Commands =\n");
      mtev_console_render_help(ncct, current->state);
    }
    return 0;
  }
  else if(argc > 0) {
    nc_printf(ncct, "Help for '%s':\n", argv[0]);
    if(mtev_console_state_delegate(ncct, argc, argv, dstate, NULL) == 0)
      return 0;
  }
  nc_printf(ncct, "command not understood.\n");
  return -1;
}
int
mtev_console_state_pop(mtev_console_closure_t ncct, int argc, char **argv,
                       mtev_console_state_t *dstate, void *unused) {
  mtev_console_state_stack_t *current;

  if(argc) {
    nc_printf(ncct, "no arguments allowed to this command.\n");
    return -1;
  }
  if(!ncct->state_stack || !ncct->state_stack->last) {
    ncct->wants_shutdown = 1;
    return 0;
  }

  current = ncct->state_stack;
  ncct->state_stack = current->last;
  current->last = NULL;
  if(current->state->statefree) current->state->statefree(current->state, ncct);
  if(current->name) free(current->name);
  free(current);
  mtev_console_state_init(ncct);
  return 0;
}

int
mtev_console_state_init(mtev_console_closure_t ncct) {
  if(ncct->el) {
    console_prompt_func_t f;
    f = ncct->state_stack->state->console_prompt_function;
    el_set(ncct->el, EL_PROMPT, f ? f : mtev_console_state_prompt);
  }
  return 0;
}
