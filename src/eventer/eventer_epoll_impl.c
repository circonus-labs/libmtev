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
#include "eventer/eventer.h"
#include "mtev_atomic.h"
#include "mtev_skiplist.h"
#include "mtev_memory.h"
#include "mtev_log.h"
#include "libmtev_dtrace_probes.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif

struct _eventer_impl eventer_epoll_impl;
#define LOCAL_EVENTER eventer_epoll_impl
#define LOCAL_EVENTER_foreach_fdevent eventer_epoll_impl_foreach_fdevent
#define maxfds LOCAL_EVENTER.maxfds
#define master_fds LOCAL_EVENTER.master_fds

#include "eventer/eventer_impl_private.h"

static int *masks;
struct epoll_spec {
  int epoll_fd;
  int event_fd;
};

static void *eventer_epoll_spec_alloc() {
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

static int eventer_epoll_impl_init() {
  int rv;

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
  assert(e->mask);

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
  assert(e->whence.tv_sec == 0 && e->whence.tv_usec == 0);
  memset(&_ev, 0, sizeof(_ev));
  _ev.data.fd = e->fd;
  if(e->mask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
  if(e->mask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
  if(e->mask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);

  lockstate = acquire_master_fd(e->fd);
  master_fds[e->fd].e = e;

  rv = epoll_ctl(spec->epoll_fd, EPOLL_CTL_ADD, e->fd, &_ev);
  if(rv != 0) {
    mtevFatal(mtev_error, "epoll_ctl(%d,add,%d,%x) -> %d (%d: %s)\n",
          spec->epoll_fd, e->fd, e->mask, rv, errno, strerror(errno));
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
      if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, e->fd, &_ev) != 0) {
        if(errno != ENOENT) {
          mtevFatal(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
                spec->epoll_fd, e->fd, strerror(errno));
        }
        else {
          mtevL(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
                spec->epoll_fd, e->fd, strerror(errno));
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
  if(e->mask & EVENTER_TIMER) {
    eventer_update_timed(e,mask);
    return;
  }
  memset(&_ev, 0, sizeof(_ev));
  _ev.data.fd = e->fd;
  e->mask = mask;
  if(e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    struct epoll_spec *spec;
    spec = eventer_get_spec_for_event(e);
    if(e->mask & EVENTER_READ) _ev.events |= (EPOLLIN|EPOLLPRI);
    if(e->mask & EVENTER_WRITE) _ev.events |= (EPOLLOUT);
    if(e->mask & EVENTER_EXCEPTION) _ev.events |= (EPOLLERR|EPOLLHUP);
    if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_MOD, e->fd, &_ev) != 0) {
      mtevFatal(mtev_error, "epoll_ctl(%d, EPOLL_CTL_MOD, %d) -> %s\n",
            spec->epoll_fd, e->fd, strerror(errno));
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
    if(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, fd, &_ev) != 0) {
      if(errno != ENOENT) {
        mtevFatal(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
              spec->epoll_fd, fd, strerror(errno));
      }
      else {
        mtevL(mtev_error, "epoll_ctl(%d, EPOLL_CTL_DEL, %d) -> %s\n",
              spec->epoll_fd, fd, strerror(errno));
      }
    }
    release_master_fd(fd, lockstate);
  }
  return eiq;
}
static eventer_t eventer_epoll_impl_find_fd(int fd) {
  return master_fds[fd].e;
}

static void eventer_epoll_impl_trigger(eventer_t e, int mask) {
  struct epoll_spec *spec;
  struct timeval __now;
  int fd, newmask;
  const char *cbname;
  ev_lock_state_t lockstate;
  int cross_thread = mask & EVENTER_CROSS_THREAD_TRIGGER;

  mask = mask & ~(EVENTER_RESERVED);
  fd = e->fd;
  if(cross_thread) {
    if(master_fds[fd].e != NULL) {
      mtevL(eventer_deb, "Attempting to trigger already-registered event fd: %d cross thread.\n", fd);
    }
    /* assert(master_fds[fd].e == NULL); */
  }
  if(!pthread_equal(pthread_self(), e->thr_owner)) {
    /* If we're triggering across threads, it can't be registered yet */
    if(master_fds[fd].e != NULL) {
      mtevL(eventer_deb, "Attempting to trigger already-registered event fd: %d cross thread.\n", fd);
    }
    /* assert(master_fds[fd].e == NULL); */
    
    eventer_cross_thread_trigger(e,mask);
    return;
  }
  if(master_fds[fd].e == NULL) {
    master_fds[fd].e = e;
    e->mask = 0;
  }
  if(e != master_fds[fd].e) return;
  lockstate = acquire_master_fd(fd);
  if(lockstate == EV_ALREADY_OWNED) return;
  assert(lockstate == EV_OWNED);

  gettimeofday(&__now, NULL);
  cbname = eventer_name_for_callback_e(e->callback, e);
  mtevLT(eventer_deb, &__now, "epoll: fire on %d/%x to %s(%p)\n",
         fd, mask, cbname?cbname:"???", e->callback);
  mtev_memory_begin();
  LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)e, (void *)e->callback, (char *)cbname, fd, e->mask, mask);
  newmask = e->callback(e, mask, e->closure, &__now);
  LIBMTEV_EVENTER_CALLBACK_RETURN((void *)e, (void *)e->callback, (char *)cbname, newmask);
  mtev_memory_end();

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
        assert(epoll_ctl(spec->epoll_fd, EPOLL_CTL_DEL, fd, &_ev) == 0);
        e->thr_owner = tgt;
        spec = eventer_get_spec_for_event(e);
        assert(epoll_ctl(spec->epoll_fd, EPOLL_CTL_ADD, fd, &_ev) == 0);
        mtevL(eventer_deb, "moved event[%p] from t@%d to t@%d\n", e, (int)pthread_self(), (int)tgt);
      }
      else {
        spec = eventer_get_spec_for_event(e);
        assert(epoll_ctl(spec->epoll_fd, EPOLL_CTL_MOD, fd, &_ev) == 0);
      }
    }
    /* Set our mask */
    e->mask = newmask;
  }
  else {
    /* see kqueue implementation for details on the next line */
    if(master_fds[fd].e == e) master_fds[fd].e = NULL;
    eventer_free(e);
  }
  release_master_fd(fd, lockstate);
}
#ifdef HAVE_SYS_EVENTFD_H
static int eventer_epoll_eventfd_read(eventer_t e, int mask,
                                      void *closure, struct timeval *now) {
  (void)mask;
  (void)now;
  (void)closure;
  uint64_t dummy;
  (void)read(e->fd, &dummy, sizeof(dummy));
  return EVENTER_READ;
}
#endif
static int eventer_epoll_impl_loop() {
  struct epoll_event *epev;
  struct epoll_spec *spec;

  spec = eventer_get_spec_for_event(NULL);
  epev = malloc(sizeof(*epev) * maxfds);

#ifdef HAVE_SYS_EVENTFD_H
  if(spec->event_fd >= 0) {
    eventer_t e = eventer_alloc();
    e->callback = eventer_epoll_eventfd_read;
    e->fd = spec->event_fd;
    e->mask = EVENTER_READ;
    eventer_add(e);
  }
#endif

  while(1) {
    struct timeval __now, __sleeptime;
    int fd_cnt = 0;

    __sleeptime = eventer_max_sleeptime;

    gettimeofday(&__now, NULL);
    eventer_dispatch_timed(&__now, &__sleeptime);

    /* Handle cross_thread dispatches */
    eventer_cross_thread_process();

    /* Handle recurrent events */
    eventer_dispatch_recurrent(&__now);

    /* Now we move on to our fd-based events */
    do {
      fd_cnt = epoll_wait(spec->epoll_fd, epev, maxfds,
                          __sleeptime.tv_sec * 1000 + __sleeptime.tv_usec / 1000);
    } while(fd_cnt < 0 && errno == EINTR);
    mtevLT(eventer_deb, &__now, "debug: epoll_wait(%d, [], %d) => %d\n",
           spec->epoll_fd, maxfds, fd_cnt);
    if(fd_cnt < 0) {
      mtevLT(eventer_err, &__now, "epoll_wait: %s\n", strerror(errno));
    }
    else {
      int idx;
      /* loop once to clear */
      for(idx = 0; idx < fd_cnt; idx++) {
        struct epoll_event *ev;
        eventer_t e;
        int fd, mask = 0;

        ev = &epev[idx];

        if(ev->events & (EPOLLIN | EPOLLPRI)) mask |= EVENTER_READ;
        if(ev->events & (EPOLLOUT)) mask |= EVENTER_WRITE;
        if(ev->events & (EPOLLERR|EPOLLHUP)) mask |= EVENTER_EXCEPTION;

        fd = ev->data.fd;

        e = master_fds[fd].e;
        /* It's possible that someone removed the event and freed it
         * before we got here.
         */
        if(!e) continue;

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
    (void)write(spec->event_fd, &nudge, sizeof(nudge));
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
