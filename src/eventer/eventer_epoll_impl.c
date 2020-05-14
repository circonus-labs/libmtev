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

struct _eventer_impl eventer_epoll_impl;
#define LOCAL_EVENTER eventer_epoll_impl
#define LOCAL_EVENTER_foreach_fdevent eventer_epoll_impl_foreach_fdevent
#define maxfds LOCAL_EVENTER._maxfds
#define master_fds LOCAL_EVENTER._master_fds

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "mtev_skiplist.h"
#include "mtev_memory.h"
#include "mtev_log.h"
#include "libmtev_dtrace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif

#include "eventer/eventer_impl_private.h"

static int *masks;
struct epoll_spec {
  int epoll_fd;
  int event_fd;
};

static void *eventer_epoll_spec_alloc(void) {
  struct epoll_spec *spec;
  spec = calloc(1, sizeof(*spec));
  spec->epoll_fd = epoll_create(1024);
  if(spec->epoll_fd < 0) {
    mtevFatal(mtev_error, "error in eveter_epoll_spec_alloc... spec->epoll_fd < 0 (%d)\n",
            spec->epoll_fd);
  }
  spec->event_fd = -1;
#if defined(EFD_NONBLOCK) && defined(EFD_CLOEXEC)
  spec->event_fd = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC);
#elif defined(HAVE_SYS_EVENTFD_H)
  spec->event_fd = eventfd(0, 0);
  if(spec->event_fd >= 0) {
    int flags;
    if(((flags = fcntl(spec->event_fd, F_GETFL, 0)) == -1) ||
       (fcntl(spec->event_fd, F_SETFL, flags|O_NONBLOCK) == -1)) {
      close(spec->event_fd);
      spec->event_fd = -1;
    }
  }
  if(spec->event_fd >= 0) {
    int flags;
    if(((flags = fcntl(spec->event_fd, F_GETFD, 0)) == -1) ||
       (fcntl(spec->event_fd, F_SETFD, flags|FD_CLOEXEC) == -1)) {
      close(spec->event_fd);
      spec->event_fd = -1;
    }
  }
#endif
  return spec;
}

#ifdef HAVE_SYS_EVENTFD_H
static int eventer_epoll_awaken(eventer_t e, int mask,
                                void *closure, struct timeval *now) {
  (void)mask;
  (void)now;
  (void)closure;
  uint64_t dummy;
  int unused __attribute__((unused));
  unused = read(e->fd, &dummy, sizeof(dummy));
  return EVENTER_READ;
}
#endif
static int eventer_epoll_impl_init(void) {
  int rv;

#ifdef HAVE_SYS_EVENTFD_H
  eventer_name_callback("eventer_epoll_awaken", eventer_epoll_awaken);
#endif

  maxfds = eventer_impl_setrlimit();
  master_fds = calloc(maxfds, sizeof(*master_fds));
  masks = calloc(maxfds, sizeof(*masks));

  /* super init */
  if((rv = eventer_impl_init()) != 0) return rv;

  signal(SIGPIPE, SIG_IGN);
  return 0;
}
static int eventer_epoll_impl_propset(const char *key, const char *value) {
  if(eventer_impl_propset(key, value)) {
    /* Do our epoll local properties here */
    return -1;
  }
  return 0;
}
static void eventer_epoll_impl_add(eventer_t e) {
  int rv;
  struct epoll_spec *spec;
  struct epoll_event _ev;
  ev_lock_state_t lockstate;
  mtevAssert(e->mask);

  if(e->mask & EVENTER_ASYNCH) {
    eventer_add_asynch(NULL, e);
    return;
  }

  /* Recurrent delegation */
  if(e->mask & EVENTER_RECURRENT) {
    eventer_add_recurrent(e);
    return;
  }

  /* Timed events are simple */
  if(e->mask & EVENTER_TIMER) {
    eventer_add_timed(e);
    return;
  }

  spec = eventer_get_spec_for_event(e);
  /* file descriptor event */
  mtevAssert(e->whence.tv_sec == 0 && e->whence.tv_usec == 0);
  memset(&_ev, 0, sizeof(_ev));
  _ev.data.fd = e->fd;
  if(e->mask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
  if(e->mask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
  if(e->mask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);

  lockstate = acquire_master_fd(e->fd);
  master_fds[e->fd].e = e;

  mtevL(eventer_deb, "epoll_ctl(%d, add, %d)\n", spec->epoll_fd, e->fd);
  rv = epoll_ctl(spec->epoll_fd, EPOLL_CTL_ADD, e->fd, &_ev);
  if(rv != 0) {
    if(errno == EPERM) {
      mtevL(eventer_deb, "epoll_ctl add /dev/null, ignored\n");
    }
    else {
      mtevFatal(mtev_error, "epoll_ctl(%d,add,%d,%x) -> %d (%d: %s)\n",
                spec->epoll_fd, e->fd, e->mask, rv, errno, strerror(errno));
    }
  }

  release_master_fd(e->fd, lockstate);
}
static eventer_t eventer_epoll_impl_remove(eventer_t e) {
  struct epoll_spec *spec;
  eventer_t removed = NULL;
  if(e->mask & EVENTER_ASYNCH) {
    mtevFatal(mtev_error, "error in eventer_epoll_impl_remove: got unexpected EVENTER_ASYNCH mask\n");
  }
  if(e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    ev_lock_state_t lockstate;
    struct epoll_event _ev;
    spec = eventer_get_spec_for_event(e);
    memset(&_ev, 0, sizeof(_ev));
    _ev.data.fd = e->fd;
    lockstate = acquire_master_fd(e->fd);
    if(e == master_fds[e->fd].e) {
      removed = e;
      master_fds[e->fd].e = NULL;
      mtevL(eventer_deb, "epoll_ctl(%d, del, %d)\n", spec->epoll_fd, e->fd);
      if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, e->fd, &_ev) != 0) {
        mtevL(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
              spec->epoll_fd, e->fd, strerror(errno));
        if(errno != ENOENT) {
          mtevFatal(mtev_error, "errno != ENOENT: %d (%s)\n", errno, strerror(errno));
        }
      }
    }
    release_master_fd(e->fd, lockstate);
  }
  else if(e->mask & EVENTER_TIMER) {
    removed = eventer_remove_timed(e);
  }
  else if(e->mask & EVENTER_RECURRENT) {
    removed = eventer_remove_recurrent(e);
  }
  else {
    mtevFatal(mtev_error, "error in eventer_epoll_impl_remove: got unknown mask (0x%04x)\n",
            e->mask);
  }
  return removed;
}
static void eventer_epoll_impl_update(eventer_t e, int mask) {
  struct epoll_event _ev;
  int ctl_op = EPOLL_CTL_MOD;
  if(e->mask & EVENTER_TIMER) {
    eventer_update_timed_internal(e,mask,&e->whence);
    return;
  }
  memset(&_ev, 0, sizeof(_ev));
  _ev.data.fd = e->fd;
  if(e->mask == 0) ctl_op = EPOLL_CTL_ADD;
  e->mask = mask;
  if(e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    struct epoll_spec *spec;
    spec = eventer_get_spec_for_event(e);
    if(e->mask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
    if(e->mask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
    if(e->mask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);
    mtevL(eventer_deb, "epoll_ctl(%d, %s, %d) -> %x\n", spec->epoll_fd,
	  ctl_op == EPOLL_CTL_ADD ? "add" : "mod",
	  e->fd, e->mask);
    int epoll_rv = epoll_ctl(spec->epoll_fd, ctl_op, e->fd, &_ev);
    if(epoll_rv != 0 &&
       ((ctl_op == EPOLL_CTL_ADD && errno == EEXIST) ||
	(ctl_op == EPOLL_CTL_MOD && errno == ENOENT))) {
      /* try the other way */
      ctl_op = (ctl_op == EPOLL_CTL_ADD) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
      epoll_rv = epoll_ctl(spec->epoll_fd, ctl_op, e->fd, &_ev);
      if (epoll_rv != 0) {
        mtevFatal(mtev_error, "epoll_ctl(%d, %s, %d) -> %s\n",
                  spec->epoll_fd, ctl_op == EPOLL_CTL_ADD ? "add" : "mod",
                  e->fd, strerror(errno));
      }
    }
  }
}
static eventer_t eventer_epoll_impl_remove_fd(int fd) {
  eventer_t eiq = NULL;
  ev_lock_state_t lockstate;
  if(master_fds[fd].e) {
    struct epoll_spec *spec;
    struct epoll_event _ev;
    memset(&_ev, 0, sizeof(_ev));
    _ev.data.fd = fd;
    lockstate = acquire_master_fd(fd);
    eiq = master_fds[fd].e;
    spec = eventer_get_spec_for_event(eiq);
    master_fds[fd].e = NULL;
    mtevL(eventer_deb, "epoll_ctl(%d, del, %d)\n", spec->epoll_fd, fd);
    if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, fd, &_ev) != 0) {
      mtevL(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
            spec->epoll_fd, fd, strerror(errno));
      if(errno != ENOENT) {
        mtevFatal(mtev_error, "errno != ENOENT: %d (%s)\n", errno, strerror(errno));
      }
    }
    release_master_fd(fd, lockstate);
  }
  return eiq;
}
static eventer_t eventer_epoll_impl_find_fd(int fd) {
  if(fd < 0 || fd >= maxfds) return NULL;
  return master_fds[fd].e;
}

static void eventer_epoll_impl_trigger(eventer_t e, int mask) {
  struct epoll_spec *spec;
  struct timeval __now;
  int fd, newmask;
  const char *cbname;
  ev_lock_state_t lockstate;
  int cross_thread = mask & EVENTER_CROSS_THREAD_TRIGGER;
  uint64_t duration;

  eventer_ref(e);
  mask = mask & ~(EVENTER_RESERVED);
  fd = e->fd;
  if(cross_thread) {
    if(master_fds[fd].e != NULL) {
      mtevL(eventer_deb, "Attempting to trigger already-registered event fd: %d cross thread.\n", fd);
    }
    /* mtevAssert(master_fds[fd].e == NULL); */
  }
  if(!pthread_equal(pthread_self(), e->thr_owner)) {
    /* If we're triggering across threads, it can't be registered yet */
    if(master_fds[fd].e != NULL) {
      mtevL(eventer_deb, "Attempting to trigger already-registered event fd: %d cross thread.\n", fd);
    }
    /* mtevAssert(master_fds[fd].e == NULL); */

    eventer_cross_thread_trigger(e,mask);
    eventer_deref(e);
    return;
  }
  if(master_fds[fd].e == NULL) {
    lockstate = acquire_master_fd(fd);
    if (lockstate == EV_ALREADY_OWNED) {
      /* The incoming triggered event is already owned by this thread.
       * This means our floated event completed before the current
       * event handler even exited.  So it retriggered recursively
       * from inside the event handler.
       *
       * Treat this special case the same as a cross thread trigger
       * and just queue this event to be picked up on the next loop
       */
      eventer_cross_thread_trigger(e, mask);
      eventer_deref(e);
      return;
    }
    /* We've acquired the lock, recheck our predicate */
    if(master_fds[fd].e == NULL) { 
    /*
     * If we are readding the event to the master list here, also do the needful
     * with the epoll_ctl.
     *
     * This can happen in cases where some event was floated and the float
     * completed so fast that we finished the job in the same thread 
     * that it started in.  Since we `eventer_remove_fd` before we float
     * the re-add here should replace the fd in the epoll_ctl.
     */
      master_fds[fd].e = e;
      e->mask = 0;
      struct epoll_event _ev;
      memset(&_ev, 0, sizeof(_ev));
      _ev.data.fd = fd;
      spec = eventer_get_spec_for_event(e);
      if(mask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
      if(mask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
      if(mask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);
  
      mtevL(eventer_deb, "epoll_ctl(%d, add, %d)\n", spec->epoll_fd, fd);
      if (epoll_ctl(spec->epoll_fd, EPOLL_CTL_ADD, fd, &_ev) != 0) {
        mtevL(mtev_error, "epoll_ctl(%d, add, %d, %d)\n", spec->epoll_fd, fd, errno);
      }
    }
    release_master_fd(fd, lockstate);
  }
  if(e != master_fds[fd].e) {
    mtevL(mtev_error, "Incoming event: %p, does not match master list: %p\n", e, master_fds[fd].e);
    eventer_deref(e);
    return;
  }
  lockstate = acquire_master_fd(fd);
  if(lockstate == EV_ALREADY_OWNED) {
    mtevL(eventer_deb, "Incoming event: %p already owned by this thread\n", e);
    eventer_deref(e);
    return;
  }
  mtevAssert(lockstate == EV_OWNED);

  mtev_gettimeofday(&__now, NULL);
  cbname = eventer_name_for_callback_e(e->callback, e);
  spec = eventer_get_spec_for_event(e);
  mtevLT(eventer_deb, &__now, "epoll(%d): fire on %d/%x to %s(%p)\n",
         spec->epoll_fd, fd, mask, cbname?cbname:"???", e->callback);
  stats_handle_t *lat = eventer_latency_handle_for_callback(e->callback);
  LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)e, (void *)e->callback, (char *)cbname, fd, e->mask, mask);
  newmask = eventer_run_callback(e->callback, e, mask, e->closure, &__now, &duration);
  LIBMTEV_EVENTER_CALLBACK_RETURN((void *)e, (void *)e->callback, (char *)cbname, newmask);
  stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
  if(lat) stats_set_hist_intscale(lat, duration, -9, 1);

  if(newmask) {
    struct epoll_event _ev;
    memset(&_ev, 0, sizeof(_ev));
    _ev.data.fd = fd;
    if(newmask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
    if(newmask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
    if(newmask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);
    if(master_fds[fd].e == NULL) {
      mtevL(mtev_debug, "eventer %s(%p) epoll asked to modify descheduled fd: %d\n",
            cbname?cbname:"???", e->callback, fd);
    } else {
      if(!pthread_equal(pthread_self(), e->thr_owner)) {
        pthread_t tgt = e->thr_owner;
        e->thr_owner = pthread_self();
        spec = eventer_get_spec_for_event(e);
        mtevL(eventer_deb, "epoll_ctl(%d, del, %d)\n", spec->epoll_fd, fd);
        if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, fd, &_ev) != 0 && errno != ENOENT) {
          mtevFatal(mtev_error,
                    "epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, fd, &_ev) failed; "
                    "spec->epoll_fd: %d; fd: %d; errno: %d (%s)\n",
                    spec->epoll_fd, fd, errno, strerror(errno));
        }
        e->thr_owner = tgt;
        spec = eventer_get_spec_for_event(e);
        mtevL(eventer_deb, "epoll_ctl(%d, add, %d)\n", spec->epoll_fd, fd);
        if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_ADD, fd, &_ev) != 0) {
          mtevL(mtev_error, "epoll_ctl(%d, add, %d, %d)\n", spec->epoll_fd, fd, errno);
        }
        mtevL(eventer_deb, "epoll(%d) moved event[%p] from t@%d to t@%d\n", spec->epoll_fd, e, (int)pthread_self(), (int)tgt);
      }
      else {
        int epoll_rv;
        int epoll_cmd = e->mask == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        spec = eventer_get_spec_for_event(e);
        mtevL(eventer_deb, "epoll_ctl(%d, %s, %d) => %x\n", spec->epoll_fd, epoll_cmd == EPOLL_CTL_ADD ? "add" : "mod", fd, e->mask);
        epoll_rv = epoll_ctl(spec->epoll_fd, epoll_cmd, fd, &_ev);
        if(epoll_rv != 0 &&
           ((epoll_cmd == EPOLL_CTL_ADD && errno == EEXIST) ||
            (epoll_cmd == EPOLL_CTL_MOD && errno == ENOENT))) {
            /* try the other way */
          epoll_cmd = (epoll_cmd == EPOLL_CTL_ADD) ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
          mtevL(eventer_deb, "retry epoll_ctl(%d, %s, %d)\n", spec->epoll_fd, epoll_cmd == EPOLL_CTL_ADD ? "add" : "mod", fd);
	  epoll_rv = epoll_ctl(spec->epoll_fd, epoll_cmd, fd, &_ev);
        }
        if(epoll_rv != 0) {
          const char *cb_name = eventer_name_for_callback_e(e->callback, e);
          mtevFatal(mtev_error,
                    "epoll_ctl(spec->epoll_fd, %s, fd, &_ev) failed; "
                    "spec->epoll_fd: %d; fd: %d; errno: %d (%s); callback: %s\n",
                    epoll_cmd == EPOLL_CTL_ADD ? "EPOLL_CTL_ADD" : "EPOLL_CTL_MOD",
                    spec->epoll_fd, fd, errno, strerror(errno), cb_name ? cb_name : "???");
        }
      }
    }
    /* Set our mask */
    e->mask = newmask;
  }
  else {
    /* see kqueue implementation for details on the next line */
    if(master_fds[fd].e == e) {

      /* if newmask == 0 the user has floated the connection.  If we get here
       * and they have not called `eventer_remove_fd` it is a misuse of mtev.
       *
       * Check if they are compliant with floats here and remove_fd if they
       * forgot to and warn in the log
       */
      spec = eventer_get_spec_for_event(e);
      struct epoll_event _ev;
      memset(&_ev, 0, sizeof(_ev));
      _ev.data.fd = fd;
      if (epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, e->fd, &_ev) == 0) {
        mtevFatal(mtev_error, "You forgot to 'eventer_remove_fd()' in %s before returning a mask of zero.\n",
                  eventer_name_for_callback_e(e->callback, e));
      }
      master_fds[fd].e = NULL;
    }
    eventer_deref(e);
  }
  eventer_deref(e);
  release_master_fd(fd, lockstate);
}
static int eventer_epoll_impl_loop(int id, eventer_impl_data_t *t) {
  (void)id;
  struct epoll_event *epev;
  struct epoll_spec *spec;
  int max_fds_at_once = 1024;

  spec = eventer_get_spec_for_event(NULL);
  epev = malloc(sizeof(*epev) * max_fds_at_once);

#ifdef HAVE_SYS_EVENTFD_H
  if(spec->event_fd >= 0) {
    eventer_t e = eventer_alloc();
    e->callback = eventer_epoll_awaken;
    e->opset = eventer_POSIX_fd_opset;
    e->fd = spec->event_fd;
    e->mask = EVENTER_READ;
    eventer_add(e);
  }
#endif

  struct timeval max_sleeptime = eventer_max_sleeptime;
  eventer_adjust_max_sleeptime(&max_sleeptime);

  while(1) {
    struct timeval __sleeptime;
    int fd_cnt = 0;

    __sleeptime = max_sleeptime;

    eventer_dispatch_timed(t, &__sleeptime);

    /* Handle cross_thread dispatches */
    eventer_cross_thread_process(t);

    /* Handle recurrent events */
    eventer_dispatch_recurrent(t);

    /* Now we move on to our fd-based events */
    do {
      fd_cnt = epoll_wait(spec->epoll_fd, epev, max_fds_at_once,
                          __sleeptime.tv_sec * 1000 + __sleeptime.tv_usec / 1000);
    } while(fd_cnt < 0 && errno == EINTR);
    eventer_heartbeat();
    mtevL(eventer_deb, "debug: epoll_wait(%d, [], %d, %lu) => %d\n",
          spec->epoll_fd, max_fds_at_once, __sleeptime.tv_sec * 1000 + __sleeptime.tv_usec / 1000, fd_cnt);
    if(fd_cnt < 0) {
      mtevL(eventer_err, "epoll_wait: %s\n", strerror(errno));
    }
    else {
      int idx;
      /* loop once to clear */
      for(idx = 0; idx < fd_cnt; idx++) {
        struct epoll_event *ev;
        eventer_t e;
        int fd, mask = 0;

        ev = &epev[idx];

        if(ev->events & (EPOLLIN|EPOLLPRI)) mask |= EVENTER_READ;
        if(ev->events & (EPOLLOUT)) mask |= EVENTER_WRITE;
        if(ev->events & (EPOLLERR|EPOLLHUP)) mask |= EVENTER_EXCEPTION;

        fd = ev->data.fd;

        e = master_fds[fd].e;

        /* It's possible that someone removed the event and freed it
         * before we got here.
         */
        if(!e) continue;

        if(!pthread_equal(e->thr_owner, pthread_self())) {
          mtevFatal(mtev_error, "e(%p) fired in thread %s instead of %s\n", e, eventer_thread_name(pthread_self()), eventer_thread_name(e->thr_owner));
        }
        eventer_epoll_impl_trigger(e, mask);
      }
    }
  }
  /* NOTREACHED */
  return 0;
}

static void eventer_epoll_impl_wakeup(eventer_t e) {
#ifdef HAVE_SYS_EVENTFD_H
  struct epoll_spec *spec;
  spec = eventer_get_spec_for_event(e);
  if(spec->event_fd >= 0) {
    uint64_t nudge = 1;
    int unused __attribute__((unused));
    unused = write(spec->event_fd, &nudge, sizeof(nudge));
  }
#endif
}
struct _eventer_impl eventer_epoll_impl = {
  "epoll",
  eventer_epoll_impl_init,
  eventer_epoll_impl_propset,
  eventer_epoll_impl_add,
  eventer_epoll_impl_remove,
  eventer_epoll_impl_update,
  eventer_epoll_impl_remove_fd,
  eventer_epoll_impl_find_fd,
  eventer_epoll_impl_trigger,
  eventer_epoll_impl_loop,
  eventer_epoll_impl_foreach_fdevent,
  eventer_epoll_impl_wakeup,
  eventer_epoll_spec_alloc,
  { 0, 200000 },
  0,
  NULL
};
