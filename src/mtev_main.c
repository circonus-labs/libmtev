/*
 * Copyright (c) 2011, OmniTI Computer Consulting, Inc.
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

#include <assert.h>
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

#include "mtev_log.h"
#include "mtev_main.h"
#include "mtev_conf.h"
#include "mtev_watchdog.h"
#include "mtev_lockfile.h"
#include "eventer/eventer.h"

#define MAX_CLI_LOGS 128
static char *enable_logs[MAX_CLI_LOGS];
static int enable_logs_cnt = 0;
static char *disable_logs[MAX_CLI_LOGS];
static int disable_logs_cnt = 0;

void
mtev_main_enable_log(const char *name) {
  if(enable_logs_cnt >= MAX_CLI_LOGS) return;
  enable_logs[enable_logs_cnt++] = strdup(name);
}
void
mtev_main_disable_log(const char *name) {
  if(disable_logs_cnt >= MAX_CLI_LOGS) return;
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
    const char *key, *value;
    int klen;
    while(mtev_hash_next_str(table, &iter, &key, &klen, &value)) {
      int subrv;
      /* We want to set a sane default if the user doesn't provide an
       * rlim_nofiles value... however, we have to try to set the user
       * value before we set the default, because otherwise, if snowth
       * is being run as a non-privileged user and we set a default
       * lower than the user specified one, we can't raise it. Ergo -
       * try to set from the config first, then set a default if one
       * isn't specified */
      if ((strlen(key) == strlen("rlim_nofiles")) &&
          (strncmp(key, "rlim_nofiles", strlen(key)) == 0) ) {
        rlim_found = mtev_true;
      }
      if((subrv = eventer_propset(key, value)) != 0)
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

void cli_log_switches() {
  int i;
  mtev_log_stream_t ls;
  for(i=0; i<enable_logs_cnt; i++) {
    ls = mtev_log_stream_find(enable_logs[i]);
    if(!ls) mtevL(mtev_error, "No such log: '%s'\n", enable_logs[i]);
    if(ls && !N_L_S_ON(ls)) {
      mtevL(mtev_notice, "Enabling %s\n", enable_logs[i]);
      mtev_log_stream_set_flags(ls, mtev_log_stream_get_flags(ls) | MTEV_LOG_STREAM_ENABLED);
    }
  }
  for(i=0; i<disable_logs_cnt; i++) {
    ls = mtev_log_stream_find(disable_logs[i]);
    if(!ls) mtevL(mtev_error, "No such log: '%s'\n", enable_logs[i]);
    if(ls && N_L_S_ON(ls)) {
      mtevL(mtev_notice, "Disabling %s\n", disable_logs[i]);
      mtev_log_stream_set_flags(ls, mtev_log_stream_get_flags(ls) & ~MTEV_LOG_STREAM_ENABLED);
    }
  }
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
 
  wait_for_lock = (lock == MTEV_LOCK_OP_WAIT) ? 1 : 0;
   
  /* First initialize logging, so we can log errors */
  mtev_log_init(debug);
  mtev_log_stream_add_stream(mtev_debug, mtev_stderr);
  mtev_log_stream_add_stream(mtev_error, mtev_stderr);
  mtev_log_stream_add_stream(mtev_notice, mtev_error);

  /* Next load the configs */
  mtev_conf_use_namespace(appname);
  mtev_conf_init(appname);
  if(mtev_conf_load(config_filename) == -1) {
    fprintf(stderr, "Cannot load config: '%s'\n", config_filename);
    exit(-1);
  }

  cli_log_switches();

  /* Reinitialize the logging system now that we have a config */
  mtev_conf_log_init(appname, drop_to_user, drop_to_group);
  if(debug) {
    mtev_log_stream_set_flags(mtev_debug, mtev_log_stream_get_flags(mtev_debug) | MTEV_LOG_STREAM_ENABLED);
  }

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
      if((lockfd = mtev_lockfile_acquire(lockfile)) < 0) {
        if(!wait_for_lock) {
          mtevL(mtev_stderr, "Failed to acquire lock: %s\n", lockfile);
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
    int rv = passed_child_main();
    mtev_lockfile_release(lockfd);
    return rv;
  }

  watchdog_timeout_str = getenv("WATCHDOG_TIMEOUT");
  if(watchdog_timeout_str) {
    watchdog_timeout = atoi(watchdog_timeout_str);
    mtevL(mtev_error, "Setting watchdog timeout to %d\n",
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

    if(fork()) exit(0);
    setsid();
    if(fork()) exit(0);
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
  rv = mtev_watchdog_start_child(appname, passed_child_main, watchdog_timeout);
  mtev_lockfile_release(lockfd);
  return rv;
}
