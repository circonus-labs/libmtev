/*
 * Copyright (c) 2007-2009, OmniTI Computer Consulting, Inc.
 * All rights reserved.
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <execinfo.h>
#if defined(__sun__)
#include <ucontext.h>
#include <sys/lwp.h>
#endif
#if defined(__MACH__) && defined(__APPLE__)
#include <libproc.h>
#endif

#include <signal.h>
#include <time.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_time.h"
#include "mtev_watchdog.h"
#include "mtev_stacktrace.h"

struct mtev_watchdog_t {
  int ticker;
  enum {
    CRASHY_NOTATALL = 0,
    CRASHY_CRASH = 0x00dead00,
    CRASHY_RESTART = 0x99dead99
  } action;
  enum {
    HEART_ACTIVE_OFF = 0,
    HEART_ACTIVE_ON = 1,
    HEART_ACTIVE_SKIP = 2
  } active;
  struct {
    struct timeval last_changed;
    int last_ticker;
  } parent_view;
  double timeout_override;
};

#define CHILD_WATCHDOG_TIMEOUT 5.0 /*seconds*/
#define MAX_CRASH_FDS 1024
#define MAX_HEARTS 1024

const static char *appname = "unknown";
const static char *glider_path = NULL;
const static char *trace_dir = "/var/tmp";
static int retries = 5;
static int span = 60;
static int allow_async_dumps = 1;
static mtev_atomic32_t on_crash_fds_to_close[MAX_CRASH_FDS];

typedef enum {
  GLIDE_CRASH,
  GLIDE_WATCHDOG
} glide_reason_t;

int mtev_watchdog_glider(const char *path) {
  glider_path = path;
  if(glider_path) {
    int rv;
    struct stat sb;
    while((rv = stat(path, &sb)) == -1 && errno == EINTR);
    if(rv == -1 || !S_ISREG(sb.st_mode) || (sb.st_mode & 0111) == 0) {
      mtevL(mtev_error, "glider '%s' doesn't exist or isn't executable.\n",
            glider_path);
      return -1;
    }
    mtevL(mtev_notice, "Setting watchdog glider to '%s'\n", glider_path);
  }
  return 0;
}
int mtev_watchdog_glider_trace_dir(const char *path) {
  trace_dir = path;
  if(trace_dir) {
    int rv;
    struct stat sb;
    while((rv = stat(path, &sb)) == -1 && errno == EINTR);
    if(rv == -1 || !S_ISDIR(sb.st_mode) || (sb.st_mode & 0111) == 0) {
      mtevL(mtev_error, "glider trace_dir '%s': no such directory.\n",
            trace_dir);
      return -1;
    }
  }
  return 0;
}
void mtev_watchdog_ratelimit(int retry_val, int span_val) {
    retries = retry_val;
    span = span_val;
}

/* Watchdog stuff */
static pid_t watcher = -1;
static mtev_watchdog_t *mmap_lifelines = NULL;
static double last_tick_time(mtev_watchdog_t *lifeline, struct timeval *now) {
  struct timeval diff;

  if(lifeline == NULL) lifeline = mmap_lifelines;

  if(lifeline->parent_view.last_ticker != lifeline->ticker) {
    lifeline->parent_view.last_ticker = lifeline->ticker;
    memcpy(&lifeline->parent_view.last_changed, now, sizeof(*now));
  }
  if(lifeline->parent_view.last_changed.tv_sec == 0) return 0;

  sub_timeval(*now, lifeline->parent_view.last_changed, &diff);
  return (double)diff.tv_sec + (double)diff.tv_usec / 1000000.0;
}
static void it_ticks_crash(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  if(lifeline) lifeline->action = CRASHY_CRASH;
}
static void it_ticks_crash_release(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  if(lifeline) lifeline->action = CRASHY_RESTART;
}
static int it_ticks_crashed(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  return (lifeline->action == CRASHY_CRASH);
}
static int it_ticks_crash_restart(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  return (lifeline->action == CRASHY_RESTART);
}
static void it_ticks_zero(mtev_watchdog_t *lifeline) {
  if(mmap_lifelines) {
    if(lifeline == NULL) {
      int i;
      for(i=0; i<MAX_HEARTS; i++) {
        it_ticks_zero(mmap_lifelines + i);
      }
      mmap_lifelines->active = HEART_ACTIVE_ON;
    } else {
      memset(lifeline, 0, sizeof(*lifeline));
    }
  }
}
static void it_ticks(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  if(lifeline) lifeline->ticker++;
}
int mtev_watchdog_child_heartbeat() {
  it_ticks(NULL);
  return 0;
}
int mtev_watchdog_prefork_init() {
  int i;
  const char *async;
  if(NULL != (async = getenv("ASYNCH_CORE_DUMP")))
    allow_async_dumps = atoi(async);
  watcher = getpid();
  for(i=0;i<MAX_CRASH_FDS;i++)
    on_crash_fds_to_close[i] = -1;
  mmap_lifelines =
    (mtev_watchdog_t *)mmap(NULL, MAX_HEARTS*sizeof(mtev_watchdog_t),
                            PROT_READ|PROT_WRITE,
                            MAP_SHARED|MAP_ANON, -1, 0);
  if(mmap_lifelines == MAP_FAILED) {
    mtevL(mtev_error, "Failed to mmap anon for watchdog\n");
    return -1;
  }
  it_ticks_zero(NULL);
  return 0;
}

int mtev_monitored_child_pid = -1;

void run_glider(int pid, glide_reason_t glide_reason) {
  const char *glide_reason_str = "unkown";
  char cmd[1024];
  int unused __attribute__((unused));
  if(glider_path) {
    char *oldpath, oldpath_buf[PATH_MAX];
    oldpath = getcwd(oldpath_buf, sizeof(oldpath_buf));
    if(oldpath) unused = chdir(trace_dir);
    switch(glide_reason) {
      case GLIDE_CRASH: glide_reason_str = "crash"; break;
      case GLIDE_WATCHDOG: glide_reason_str = "watchdog"; break;
      default: glide_reason_str = "unknown";
    }
    snprintf(cmd, sizeof(cmd), "%s %d %s > %s/%s.%d.trc",
             glider_path, pid, glide_reason_str, trace_dir, appname, pid);
    unused = system(cmd);
    if(oldpath) unused = chdir(oldpath);
  }
}

static void close_fds() {
  int i;
  for(i=0;i<MAX_CRASH_FDS;i++)
    if(on_crash_fds_to_close[i] != -1) {
      mtevL(mtev_error, "emancipate closing fd %d\n", on_crash_fds_to_close[i]);
      close(on_crash_fds_to_close[i]);
    }
}
static void stop_other_threads() {
#ifdef UNSAFE_STOP
#if defined(__sun__)
  lwpid_t self;
  char path[PATH_MAX];
  DIR *root;
  struct dirent *de, *entry;
  int size = 0;

  self = _lwp_self();
  snprintf(path, sizeof(path), "/proc/%d/lwp", getpid());
#ifdef _PC_NAME_MAX
  size = pathconf(path, _PC_NAME_MAX);
#endif
  size = MAX(size, PATH_MAX + 128);
  de = alloca(size);
  root = opendir(path);
  if(!root) return;
  while(portable_readdir_r(root, de, &entry) == 0 && entry != NULL) {
    if(entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
      lwpid_t tgt;
      tgt = atoi(entry->d_name);
      if(tgt != self) {
        mtevL(mtev_error, "emancipate stoping thread %p\n", tgt);
        _lwp_suspend(tgt);
      }
    }
  }
  closedir(root);
#endif
#endif
}

void mtev_watchdog_on_crash_close_remove_fd(int fd) {
  int i;
  for(i=0; i<MAX_CRASH_FDS; i++) {
    if(on_crash_fds_to_close[i] == fd) {
      on_crash_fds_to_close[i] = -1;
    }
  }
}
void mtev_watchdog_on_crash_close_add_fd(int fd) {
  int i;
  for(i=0; i<MAX_CRASH_FDS; i++)
    if(mtev_atomic_cas32(&on_crash_fds_to_close[i], fd, -1) == -1) return;

  /* If we get here, it means that we failed to find a slot,
   * so we can't safely dump core asynchronously anymore.
   */
  allow_async_dumps = 0;
}

void mtev_self_diagnose(int sig, siginfo_t *si, void *uc) {
#if defined(__sun__)
  walkcontext(uc, mtev_simple_stack_print, mtev_error);
#else
  mtev_stacktrace(mtev_error);
#endif
  raise(sig);
}

void emancipate(int sig, siginfo_t *si, void *uc) {
  mtev_log_enter_sighandler();
  mtevL(mtev_error, "emancipate: process %d, monitored %d, signal %d\n", getpid(), mtev_monitored_child_pid, sig);
  if(getpid() == watcher) {
    run_glider(mtev_monitored_child_pid, GLIDE_CRASH);
    kill(mtev_monitored_child_pid, sig);
  }
  else if (getpid() == mtev_monitored_child_pid){
    it_ticks_crash(NULL); /* slow notification path */
    kill(mtev_monitored_child_pid, SIGSTOP); /* stop and wait for a glide */

    /* attempt a simple stack trace */
#if defined(__sun__)
    walkcontext(uc, mtev_simple_stack_print, mtev_error);
#else
    mtev_stacktrace(mtev_error);
#endif

    if(allow_async_dumps) { 
      stop_other_threads(); /* suspend all peer threads... to safely */
      close_fds();          /* close all our FDs */
      it_ticks_crash_release(NULL); /* notify parent that it can fork a new one */
      /* the subsequent dump may take a while on big processes and slow disks */
      mtevL(mtev_error, "crash resources released\n");
    }
    int unused __attribute__((unused));
    unused = chdir(trace_dir); /* switch to this directory to drop our core */
    kill(mtev_monitored_child_pid, sig);
  }
  mtev_log_leave_sighandler();
}

void subprocess_killed(int sig) {
  mtevL(mtev_error, "got a signal from spawned process.... exiting\n");
  exit(-1);
}


/* monitoring...
 *
 *  /-----------------/                /---------------------------------/
 *  /  Child running  / --> (hang) --> / Parent tick age > timeout       /
 *  /-----------------/   (no crash)   /     SIGSTOP -> glide -> SIGKILL /
 *         |                           /---------------------------------/
 *       (segv)
 *         |
 *  /--------------------------------------------------/
 *  /   `emancipate`                                   /
 *  /  Child annotates shared memory CRASHED indicator / -(notices crash)
 *  /  Child STOPs itself.                             /         |
 *  /     [ possible fd shutdown and mark as RESTART ] /         |
 *  /--------------------------------------------------/         |
 *         |                                                     |
 *         |                           /---------------------------------/
 *         |                           /  Parent runs run glider.        /
 *         |<----(wakeup)--------------/  Parent SIGCONT Child.          /
 *         |                           /  if RESTART, clear indicator    /
 *  /-----------------------/          /---------------------------------/
 *  / Child reraises signal / 
 *  /-----------------------/
 *
 */

void clear_signals() {
  sigset_t all;
  struct sigaction act;
  struct itimerval izero;

  memset(&izero, 0, sizeof(izero));
  mtevAssert(setitimer(ITIMER_REAL, &izero, NULL) == 0);
  sigfillset(&all);
  sigprocmask(SIG_UNBLOCK, &all, NULL);
  memset(&act, 0, sizeof(act));
  sigaction(SIGCHLD, &act, NULL);
  sigaction(SIGALRM, &act, NULL);
}

static void noop_sighndlr(int unused) { (void)unused; }

void setup_signals(sigset_t *mysigs) {
  struct itimerval attention;
  struct sigaction act;
  
  sigprocmask(SIG_BLOCK, mysigs, NULL);

  act.sa_handler = noop_sighndlr;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGCHLD, &act, NULL);

  act.sa_handler = noop_sighndlr;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGALRM, &act, NULL);

  attention.it_value.tv_sec = 0;
  attention.it_value.tv_usec = 77000;
  attention.it_interval.tv_sec = 0;
  attention.it_interval.tv_usec = 77000;
  mtevAssert(setitimer(ITIMER_REAL, &attention, NULL) == 0);
}

static int mtev_heartcheck(double child_watchdog_timeout, double *ltt, int *heartno) {
  int i;
  struct timeval now;
  mtev_gettimeofday(&now, NULL);
  for(i=0; i<MAX_HEARTS; i++) {
    mtev_watchdog_t *lifeline = &mmap_lifelines[i];
    double age;

    *heartno = i;
    age = last_tick_time(lifeline, &now);
    double local_timeout = (lifeline->timeout_override != 0.0) ? lifeline->timeout_override : child_watchdog_timeout;
    if (lifeline->active == HEART_ACTIVE_OFF) break;
    if (lifeline->active == HEART_ACTIVE_SKIP) continue;
    if (lifeline->action == CRASHY_NOTATALL && age > local_timeout) {
      *ltt = age;
      return 1;
    }
  }
  return 0;
}

static void *alt_stack_ptr = NULL; /* dupe leak detector */
int
mtev_setup_crash_signals(void (*action)(int, siginfo_t *, void *)) {
  /* trace handlers */
  int i;
  char *envcp;
  struct sigaction sa;
  stack_t altstack;
  size_t altstack_size = 0, default_altstack_size = 262144;
  static const int signals[] = {
    SIGSEGV,
    SIGABRT,
    SIGBUS,
    SIGILL,
#ifdef SIGIOT
    SIGIOT,
#endif
    SIGFPE
  };

  if(NULL != (envcp = getenv("MTEV_ALTSTACK_SIZE"))) {
    altstack_size = default_altstack_size = atoi(envcp);
  }
  if(default_altstack_size > 0 && alt_stack_ptr == NULL) {
    altstack_size = MAX(MINSIGSTKSZ, default_altstack_size);
    if((altstack.ss_sp = malloc(altstack_size)) == NULL)
      altstack_size = 0;
    else {
      altstack.ss_size = altstack_size;
      altstack.ss_flags = 0;
      if(sigaltstack(&altstack,0) < 0) {
        free(altstack.ss_sp);
        altstack_size = 0;
      }
      else {
        alt_stack_ptr = altstack.ss_sp;
      }
    }
  }
  if(altstack_size == 0)
    mtevL(mtev_notice, "sigaltstack not used.\n");

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = action;
  sa.sa_flags = SA_RESETHAND|SA_SIGINFO;
  if(altstack_size) sa.sa_flags |= SA_ONSTACK;
  sigemptyset(&sa.sa_mask);

  for (i = 0; i < sizeof(signals) / sizeof(*signals); i++)
    sigaddset(&sa.sa_mask, signals[i]);

  for (i = 0; i < sizeof(signals) / sizeof(*signals); i++)
    sigaction(signals[i], &sa, NULL);

  return 0;
}

int mtev_watchdog_start_child(const char *app, int (*func)(),
                              int child_watchdog_timeout_int) {
  double child_watchdog_timeout = (double)child_watchdog_timeout_int;
  int child_pid, crashing_pid = -1;
  time_t time_data[retries];
  int offset = 0;

  memset(time_data, 0, sizeof(time_data));

  appname = strdup(app);
  if(child_watchdog_timeout == 0.0)
    child_watchdog_timeout = CHILD_WATCHDOG_TIMEOUT;
  while(1) {
    int heartno = 0;
    double ltt = 0;
    /* This sets up things so we start alive */
    it_ticks_zero(NULL);
    clear_signals();
    child_pid = fork();
    if(child_pid == -1) {
      mtevL(mtev_error, "fork failed: %s\n", strerror(errno));
      exit(-1);
    }
    if(child_pid == 0) {
      mtev_time_start_tsc();
      mtev_monitored_child_pid = getpid();
      if(glider_path)
        mtevL(mtev_error, "catching faults with glider\n");
      else if(allow_async_dumps)
        mtevL(mtev_error, "no glider, allowing a single emancipated minor\n");

      mtev_setup_crash_signals(emancipate);
      /* run the program */
      exit(func());
    }
    else {
      sigset_t mysigs;
      int child_sig = -1, sig = -1, exit_val = -1;
      sigemptyset(&mysigs);
      sigaddset(&mysigs, SIGCHLD);
      sigaddset(&mysigs, SIGALRM);
      setup_signals(&mysigs);
      mtev_monitored_child_pid = child_pid;
      while(1) {
        int status, rv;
        if(sigwait(&mysigs, &sig) == -1) {
          mtevL(mtev_error, "[monitor] sigwait error: %s\n", strerror(errno));
          continue;
        }
        switch(sig) {
          case SIGCHLD:
            if(child_pid != crashing_pid && crashing_pid != -1) {
              mtevL(mtev_error, "[monitoring] suspending services while reaping emancipated child %d\n", crashing_pid);
              while((rv = waitpid(crashing_pid, &status, 0) == -1) && errno == EINTR);
              if(rv == crashing_pid) {
                mtevL(mtev_error, "[monitor] emancipated child %d [%d/%d] reaped.\n",
                      crashing_pid, WEXITSTATUS(status), WTERMSIG(status));
              }
              else if(rv != 0 && errno != ECHILD) {
                mtevL(mtev_error, "[monitor] unexpected return from emancipated waitpid: %d (%s)\n", rv, strerror(errno));
              }
              mtevL(mtev_error, "[monitor] resuming serivces for child %d\n", child_pid);
              crashing_pid =-1;
            }

            rv = waitpid(child_pid, &status, WNOHANG|WUNTRACED);
            if(rv == 0) {
              /* Nothing */
            }
            else if (rv == child_pid) {
              /* If we're stopped, we might have crashed */
              if(WIFSTOPPED(status)) {
                mtevL(mtev_error, "[monitor] %s %d has stopped.\n", app, rv);
                if(it_ticks_crashed(NULL) && crashing_pid == -1) {
                  crashing_pid = mtev_monitored_child_pid;
                  mtevL(mtev_error, "[monitor] %s %d has crashed.\n", app, crashing_pid);
                  run_glider(crashing_pid, GLIDE_CRASH);
                  kill(crashing_pid, SIGCONT);
                }
              } else {
                /* We died!... we need to relaunch, unless the status was a requested exit (2) */
                int quit;
                if(child_pid == crashing_pid) {
                  mmap_lifelines->action = CRASHY_NOTATALL;
                  crashing_pid = -1;
                }
                mtev_monitored_child_pid = -1;
                child_sig = WTERMSIG(status);
                exit_val = WEXITSTATUS(status);
                quit = update_retries(&offset, time_data);
                if (quit) {
                  mtevL(mtev_error, "[monitor] exceeded retry limit of %d retries in %d seconds... exiting...\n", retries, span);
                  exit(0);
                }
                else if(child_sig == SIGINT || child_sig == SIGQUIT ||
                   (child_sig == 0 && (exit_val == 2 || exit_val < 0))) {
                  mtevL(mtev_error, "[monitor] %s shutdown acknowledged.\n", app);
                  exit(0);
                }
                mtevL(mtev_error, "[monitor] reaped pid: %d.\n", rv);
                goto out_loop2;
              }
            }
            else if(errno != ECHILD) {
              mtevL(mtev_error, "[monitor] unexpected return from waitpid: %d (%s)\n", rv, strerror(errno));
              exit(-1);
            } else if(rv > 0) {
              mtevL(mtev_error, "[monitor] reaped pid: %d\n", rv);
            }
            /* fall through */
          case SIGALRM:
            /* here we just wake up to check stuff */
            if(it_ticks_crash_restart(NULL)) {
              mtevL(mtev_error, "[monitor] %s %d is emancipated for dumping.\n", app, crashing_pid);
              mmap_lifelines->action = CRASHY_NOTATALL;
              mtev_monitored_child_pid = -1;
              goto out_loop2;
            }
            else if(mtev_monitored_child_pid == child_pid &&
                    mtev_heartcheck(child_watchdog_timeout, &ltt, &heartno)) {
              mtevL(mtev_error,
                    "[monitor] Watchdog timeout on heart#%d (%f s)... terminating child\n",
                    heartno, ltt);
              if(glider_path) {
                kill(child_pid, SIGSTOP);
                run_glider(child_pid, GLIDE_WATCHDOG);
                kill(child_pid, SIGCONT);
              }
              kill(child_pid, SIGKILL);
              mtev_monitored_child_pid = -1;
            }
            mtev_log_reopen_type("file");
            break;
          default:
            break;
        }
      }
     out_loop2:
      if(child_sig >= 0) {
        mtevL(mtev_error, "[monitor] %s child died [%d/%d], restarting.\n",
              app, exit_val, sig);
      }
    }
  }
}

int update_retries(int* offset, time_t times[]) {
  int i;
  time_t currtime = time(NULL);
  time_t cutoff = currtime - span;

  times[*offset % retries] = currtime;
  *offset = *offset + 1;

  for (i=0; i < retries; i++) {
    if (times[i] < cutoff) {
      return 0;
    }
  }

  return 1;
}

mtev_watchdog_t *mtev_watchdog_create() {
  int i;
  for(i=0; i<MAX_HEARTS; i++) {
    mtev_watchdog_t *lifeline = &mmap_lifelines[i];
    if(lifeline->active == HEART_ACTIVE_OFF) {
      lifeline->active = HEART_ACTIVE_ON;
      mtevL(mtev_debug, "activating heart: %d\n", i);
      return lifeline;
    }
  }
  return NULL;
}

void mtev_watchdog_enable(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  lifeline->active = HEART_ACTIVE_ON;
}
void mtev_watchdog_override_timeout(mtev_watchdog_t *lifeline, double timeout) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  lifeline->timeout_override = timeout;
}
void mtev_watchdog_disable(mtev_watchdog_t *lifeline) {
  if(lifeline == NULL) lifeline = mmap_lifelines;
  lifeline->active = HEART_ACTIVE_SKIP;
}

int mtev_watchdog_heartbeat(mtev_watchdog_t *hb) {
  it_ticks(hb);
  return 0;
}
static int watchdog_tick(eventer_t e, int mask, void *lifeline, struct timeval *now) {
  it_ticks(lifeline);
  return 0;
}
eventer_t mtev_watchdog_recurrent_heartbeat(mtev_watchdog_t *hb) {
  eventer_t e;
  mtevAssert(__eventer);
  e = eventer_alloc_recurrent(watchdog_tick, hb);
  return e;
}
int mtev_watchdog_child_eventer_heartbeat() {
  eventer_t e;
  e = mtev_watchdog_recurrent_heartbeat(NULL);
  eventer_add_recurrent(e);
  return 0;
}

