/*
 * Copyright (c) 2011, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015-2016, Circonus, Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <zlib.h>
#include <lz4frame.h>


#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "mtev_log.h"
#include "mtev_main.h"
#include "mtev_conf.h"
#include "mtev_memory.h"
#include "mtev_thread.h"
#include "mtev_zipkin.h"
#include "mtev_time.h"
#include "mtev_watchdog.h"
#include "mtev_lockfile.h"
#include "mtev_listener.h"
#include "mtev_capabilities_listener.h"
#include "mtev_rest.h"
#include "mtev_reverse_socket.h"
#include "mtev_dso.h"
#include "eventer/eventer.h"

#define MAX_CLI_LOGS 128
static char *enable_logs[MAX_CLI_LOGS];
static int enable_logs_cnt = 0;
static char *disable_logs[MAX_CLI_LOGS];
static int disable_logs_cnt = 0;

/* Little helper to find one of the 4 baked-in logs:
 * stderr, error, notice, debug
 */
static mtev_log_stream_t mtev_baked_log(const char *name) {
  if(!strcmp(name, "stderr")) return mtev_stderr;
  if(!strcmp(name, "error")) return mtev_error;
  if(!strcmp(name, "notice")) return mtev_notice;
  if(!strcmp(name, "debug")) return mtev_debug;
  return NULL;
}

void
mtev_main_enable_log(const char *name) {
  mtev_log_stream_t baked;
  if(enable_logs_cnt >= MAX_CLI_LOGS) return;
  if((baked = mtev_baked_log(name)) != NULL && !N_L_S_ON(baked))
    mtev_log_stream_set_flags(baked, mtev_log_stream_get_flags(baked) | MTEV_LOG_STREAM_ENABLED);
  enable_logs[enable_logs_cnt++] = strdup(name);
}
void
mtev_main_disable_log(const char *name) {
  mtev_log_stream_t baked;
  if(disable_logs_cnt >= MAX_CLI_LOGS) return;
  if((baked = mtev_baked_log(name)) != NULL && !N_L_S_ON(baked))
    mtev_log_stream_set_flags(baked, mtev_log_stream_get_flags(baked) & ~MTEV_LOG_STREAM_ENABLED);
  disable_logs[disable_logs_cnt++] = strdup(name);
}
static int
configure_eventer(const char *appname) {
  int rv = 0;
  mtev_boolean rlim_found = mtev_false;
  mtev_hash_table *table;
  char appscratch[1024];

  snprintf(appscratch, sizeof(appscratch), "/%s/eventer/config", appname);
  table = mtev_conf_get_hash(NULL, appscratch);
  if(table) {
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    while(mtev_hash_adv(table, &iter)) {
      int subrv;
      /* We want to set a sane default if the user doesn't provide an
       * rlim_nofiles value... however, we have to try to set the user
       * value before we set the default, because otherwise, if snowth
       * is being run as a non-privileged user and we set a default
       * lower than the user specified one, we can't raise it. Ergo -
       * try to set from the config first, then set a default if one
       * isn't specified */
      if ((strlen(iter.key.str) == strlen("rlim_nofiles")) &&
          (strncmp(iter.key.str, "rlim_nofiles", strlen(iter.key.str)) == 0) ) {
        rlim_found = mtev_true;
      }
      if((subrv = eventer_propset(iter.key.str, iter.value.str)) != 0)
        rv = subrv;
    }
    mtev_hash_destroy(table, free, free);
    free(table);
  }

  /* If no rlim_nofiles configuration was found, set a default
   * of (2048*2048) */
  if (!rlim_found) {
    eventer_propset("rlim_nofiles", "4194304");
  }
  return rv;
}

void cli_log_switches(void) {
  int i;
  mtev_log_stream_t ls;
  for(i=0; i<enable_logs_cnt; i++) {
    ls = mtev_log_stream_find(enable_logs[i]);
    if(!ls) ls = mtev_baked_log(enable_logs[i]);
    if(!ls) mtevL(mtev_error, "No such log: '%s'\n", enable_logs[i]);
    if(ls && !N_L_S_ON(ls)) {
      if(ls != mtev_notice) mtevL(mtev_notice, "Enabling %s\n", enable_logs[i]);
      mtev_log_stream_set_flags(ls, mtev_log_stream_get_flags(ls) | MTEV_LOG_STREAM_ENABLED);
    }
  }
  for(i=0; i<disable_logs_cnt; i++) {
    ls = mtev_log_stream_find(disable_logs[i]);
    if(!ls) ls = mtev_baked_log(disable_logs[i]);
    if(!ls) mtevL(mtev_error, "No such log: '%s'\n", enable_logs[i]);
    if(ls && N_L_S_ON(ls)) {
      if(ls != mtev_notice) mtevL(mtev_notice, "Disabling %s\n", disable_logs[i]);
      mtev_log_stream_set_flags(ls, mtev_log_stream_get_flags(ls) & ~MTEV_LOG_STREAM_ENABLED);
    }
  }
}

static mtev_spinlock_t mtev_init_globals_lock = 0;
static int mtev_init_globals_once = 0;

void
mtev_init_globals(void) {
  /* instead of just a cas, we lock.. this makes sure
   * no one leaves this function before the job is done.
   */
  mtev_spinlock_lock(&mtev_init_globals_lock);
  if(mtev_init_globals_once == 0) {
    mtev_memory_init();
    eventer_init_globals();
    eventer_jobq_init_globals();
    mtev_capabilities_init_globals();
    mtev_conf_init_globals();
    mtev_dso_init_globals();
    mtev_http_rest_init_globals();
    mtev_listener_init_globals();
    mtev_reverse_socket_init_globals();

    mtev_capabilities_add_feature("http_accept_encoding_gzip", ZLIB_VERSION);
    char lz4f_version[15] = {0};
    snprintf(lz4f_version, sizeof(lz4f_version), "%d", LZ4F_VERSION);
    mtev_capabilities_add_feature("http_accept_encoding_lz4f", lz4f_version);

    mtev_init_globals_once = 1;
  }
  mtev_spinlock_unlock(&mtev_init_globals_lock);
}

__attribute__((constructor))
static void
mtev_init_globals_ctor(void) {
  mtev_init_globals();
  eventer_boot_ctor();
}

int
mtev_main_terminate(const char *appname,
                    const char *config_filename, int debug) {
  int lockfd;
  pid_t owner;
  char lockfile[PATH_MAX];
  char appscratch[PATH_MAX];

  mtev_init_globals();
  mtev_log_init(debug);
  mtev_log_stream_set_flags(mtev_debug, mtev_log_stream_get_flags(mtev_debug) & ~MTEV_LOG_STREAM_DEBUG);
  mtev_conf_use_namespace(appname);
  mtev_conf_init(appname);
  if(mtev_conf_load(config_filename) == -1) {
    fprintf(stderr, "Cannot load config: '%s'\n", config_filename);
    return -1;
  }
  lockfd = -1;
  lockfile[0] = '\0';
  snprintf(appscratch, sizeof(appscratch), "/%s/@lockfile", appname);
  if(!mtev_conf_get_stringbuf(NULL, appscratch,
                             lockfile, sizeof(lockfile))) {
    mtevL(mtev_debug, "No lockfile specified for application.\n");
    return -1;
  }

  if((lockfd = mtev_lockfile_acquire_owner(lockfile, &owner)) < 0) {
    if(owner == -1) {
      mtevL(mtev_debug, "Error: %s\n", strerror(errno));
      return -1;
    }
    pid_t groupid = getpgid(owner);
    if(groupid < 0) {
      mtevL(mtev_debug, "Error: %s\n", strerror(errno));
      return -1;
    }
    mtevL(mtev_debug, "Terminating process group %d.\n", groupid);
    if(kill(-groupid, SIGCONT) < 0 ||
       kill(-groupid, SIGTERM) < 0) {
      mtevL(mtev_debug, "Failed to kill progress group: %s.\n", strerror(errno));
      return -1;
    }
    while(kill(-groupid, 0) == 0) usleep(100000);
    mtevL(mtev_debug, "%s pgid:%d terminated.\n", appname, groupid);
    return 0;
  }
  close(lockfd);
  mtevL(mtev_debug, "%s not running.\n", appname);
  return 0;
}

int
mtev_main_status(const char *appname,
                 const char *config_filename, int debug,
                 pid_t *pid, pid_t *pgid) {
  int lockfd;
  pid_t owner;
  char lockfile[PATH_MAX];
  char appscratch[PATH_MAX];

  if(pid) *pid = -1;
  if(pgid) *pgid = -1;

  mtev_init_globals();
  mtev_log_init(debug);
  mtev_log_stream_set_flags(mtev_debug, mtev_log_stream_get_flags(mtev_debug) & ~MTEV_LOG_STREAM_DEBUG);
  mtev_conf_use_namespace(appname);
  mtev_conf_init(appname);
  if(mtev_conf_load(config_filename) == -1) {
    fprintf(stderr, "Cannot load config: '%s'\n", config_filename);
    return -1;
  }
  lockfd = -1;
  lockfile[0] = '\0';
  snprintf(appscratch, sizeof(appscratch), "/%s/@lockfile", appname);
  if(!mtev_conf_get_stringbuf(NULL, appscratch,
                             lockfile, sizeof(lockfile))) {
    mtevL(mtev_debug, "No lockfile specified for application.\n");
    return -1;
  }

  if((lockfd = mtev_lockfile_acquire_owner(lockfile, &owner)) < 0) {
    if(owner == -1) {
      mtevL(mtev_debug, "Error: %s\n", strerror(errno));
      return -1;
    }
    if(pid) *pid = owner;
    pid_t groupid = getpgid(owner);
    if(groupid < 0) {
      mtevL(mtev_debug, "Error: %s\n", strerror(errno));
      return -1;
    }
    if(pgid) *pgid = groupid;
    return 0;
  }
  close(lockfd);
  mtevL(mtev_debug, "%s not running.\n", appname);
  return -1;
}


int
mtev_main(const char *appname,
          const char *config_filename, int debug, int foreground,
          mtev_lock_op_t lock, const char *_glider,
          const char *drop_to_user, const char *drop_to_group,
          int (*passed_child_main)(void)) {
  mtev_conf_section_t watchdog_conf;
  int fd, lockfd, watchdog_timeout = 0, rv;
  int wait_for_lock;
  char conf_str[1024];
  char lockfile[PATH_MAX];
  char *trace_dir = NULL;
  char appscratch[1024];
  char *glider = (char *)_glider;
  char *watchdog_timeout_str;
  int retry_val;
  int span_val;
  int ret;
  int cnt;
  mtev_conf_section_t root;
 
  wait_for_lock = (lock == MTEV_LOCK_OP_WAIT) ? 1 : 0;

  mtev_init_globals();
  mtev_zipkin_default_service_name(appname, mtev_true);

  char *require_invariant_tsc = getenv("MTEV_RDTSC_REQUIRE_INVARIANT");
  if (require_invariant_tsc && strcmp(require_invariant_tsc, "0") == 0) {
    mtev_time_toggle_require_invariant_tsc(mtev_false);
  }

#ifdef __sun
#ifdef RUNNING_ON_VALGRIND
  if(RUNNING_ON_VALGRIND != 0) {
    mtev_time_toggle_require_invariant_tsc(mtev_false);
  }
#endif
#endif

  char *disable_rdtsc = getenv("MTEV_RDTSC_DISABLE");
  if (disable_rdtsc && strcmp(disable_rdtsc, "1") == 0) {
    mtev_time_toggle_tsc(mtev_false);
  }

  char *disable_binding = getenv("MTEV_THREAD_BINDING_DISABLE");
  if (disable_binding && strcmp(disable_binding, "1") == 0) {
    mtev_thread_disable_binding();
  }

  /* First initialize logging, so we can log errors */
  mtev_log_init(debug);

  /* Next load the configs */
  mtev_conf_use_namespace(appname);
  mtev_conf_init(appname);
  if(mtev_conf_load(config_filename) == -1) {
    fprintf(stderr, "Cannot load config: '%s'\n", config_filename);
    exit(-1);
  }

  char* root_section_path = alloca(strlen(appname)+2);
  sprintf(root_section_path, "/%s", appname);
  root = mtev_conf_get_sections(NULL, root_section_path, &cnt);
  free(root);
  if(cnt==0) {
    fprintf(stderr, "The config must have <%s> as its root node\n", appname);
    exit(-1);
  }

  /* Reinitialize the logging system now that we have a config */
  mtev_conf_log_init(appname, drop_to_user, drop_to_group);
  if(debug) {
    mtev_log_stream_set_flags(mtev_debug, mtev_log_stream_get_flags(mtev_debug) | MTEV_LOG_STREAM_ENABLED);
  }
  cli_log_switches();

  snprintf(appscratch, sizeof(appscratch), "/%s/watchdog|/%s/include/watchdog", appname, appname);
  watchdog_conf = mtev_conf_get_section(NULL, appscratch);

  if(!glider) (void) mtev_conf_get_string(watchdog_conf, "@glider", &glider);
  if(mtev_watchdog_glider(glider)) {
    mtevL(mtev_stderr, "Invalid glider, exiting.\n");
    exit(-1);
  }
  (void)mtev_conf_get_string(watchdog_conf, "@tracedir", &trace_dir);
  if(trace_dir) {
    if(mtev_watchdog_glider_trace_dir(trace_dir)) {
      mtevL(mtev_stderr, "Invalid glider tracedir, exiting.\n");
      exit(-1);
    }
  }

  ret = mtev_conf_get_int(watchdog_conf, "@retries", &retry_val);
  if((ret == 0) || (retry_val == 0)){
    retry_val = 5;
  }
  ret = mtev_conf_get_int(watchdog_conf, "@span", &span_val);
  if((ret == 0) || (span_val == 0)){
    span_val = 60;
  }

  mtev_watchdog_ratelimit(retry_val, span_val);

  /* Lastly, run through all other system inits */
  snprintf(appscratch, sizeof(appscratch), "/%s/eventer/@implementation", appname);
  if(!mtev_conf_get_stringbuf(NULL, appscratch, conf_str, sizeof(conf_str))) {
    mtevL(mtev_stderr, "Cannot find '%s' in configuration\n", appscratch);
    exit(-1);
  }
  if(eventer_choose(conf_str) == -1) {
    mtevL(mtev_stderr, "Cannot choose eventer %s\n", conf_str);
    exit(-1);
  }
  if(configure_eventer(appname) != 0) {
    mtevL(mtev_stderr, "Cannot configure eventer\n");
    exit(-1);
  }

  mtev_watchdog_prefork_init();

  if(foreground != 1 && chdir("/") != 0) {
    mtevL(mtev_stderr, "Failed chdir(\"/\"): %s\n", strerror(errno));
    exit(-1);
  }

  /* Acquire the lock so that we can throw an error if it doesn't work.
   * If we've started -D, we'll have the lock.
   * If not we will daemon and must reacquire the lock.
   */
  lockfd = -1;
  lockfile[0] = '\0';
  snprintf(appscratch, sizeof(appscratch), "/%s/@lockfile", appname);
  if(lock != MTEV_LOCK_OP_NONE &&
     mtev_conf_get_stringbuf(NULL, appscratch,
                             lockfile, sizeof(lockfile))) {
    do {
      pid_t owner;
      if((lockfd = mtev_lockfile_acquire_owner(lockfile, &owner)) < 0) {
        if(!wait_for_lock) {
          mtevL(mtev_stderr, "Failed to acquire lock: %s\n", lockfile);
          if(owner != -1) {
            pid_t groupid = getpgid(owner);
            mtevL(mtev_stderr, "%s running pid: %d, pgid: %d\n",
                  appname, owner, groupid);
          }
          exit(-1);
        }
        if(wait_for_lock == 1) {
          mtevL(mtev_stderr, "%d failed to acquire lock(%s), waiting...\n",
                (int)getpid(), lockfile);
          wait_for_lock++;
        }
        usleep(1000);
      }
      else {
        if(wait_for_lock > 1) mtevL(mtev_stderr, "Lock acquired proceeding.\n");
        wait_for_lock = 0;
      }
    } while(wait_for_lock);
  }

  if(foreground == 1) {
    mtev_time_start_tsc();
    mtevL(mtev_notice, "%s booting [unmanaged]\n", appname);
    mtev_setup_crash_signals(mtev_self_diagnose);
    int rv = passed_child_main();
    mtev_lockfile_release(lockfd);
    return rv;
  }

  watchdog_timeout_str = getenv("WATCHDOG_TIMEOUT");
  if(watchdog_timeout_str) {
    watchdog_timeout = atoi(watchdog_timeout_str);
    mtevL(mtev_notice, "Setting watchdog timeout to %d\n",
          watchdog_timeout);
  }

  /* This isn't inherited across forks... */
  if(lockfd >= 0) mtev_lockfile_release(lockfd);
  lockfd = -1;

  if(foreground == 0) {
    fd = open("/dev/null", O_RDONLY);
    if(fd < 0 || dup2(fd, STDIN_FILENO) < 0) {
      fprintf(stderr, "Failed to setup stdin: %s\n", strerror(errno));
      exit(-1);
    }
    close(fd);
    fd = open("/dev/null", O_WRONLY);
    if(fd < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
      fprintf(stderr, "Failed to setup std{out,err}: %s\n", strerror(errno));
      exit(-1);
    }
    close(fd);

    if(fork()) exit(0); /* detach from invoking process */
    setsid(); /* create a new session so we don't die */
    if(fork()) exit(0); /* don't lead our sessions (controlling terminal) */
    /* set our process group to us to make things simpler,
     * if this fails, it's no big deal. */
    setpgid(getpid(), getpid());
  }

  /* Reacquire the lock */
  if(*lockfile) {
    if (lock) {
      if((lockfd = mtev_lockfile_acquire(lockfile)) < 0) {
        mtevL(mtev_stderr, "Failed to acquire lock: %s\n", lockfile);
        exit(-1);
      }
    }
  }

  signal(SIGHUP, SIG_IGN);
  mtevL(mtev_notice, "%s booting\n", appname);
  rv = mtev_watchdog_start_child(appname, passed_child_main, watchdog_timeout);
  mtev_lockfile_release(lockfd);
  return rv;
}
