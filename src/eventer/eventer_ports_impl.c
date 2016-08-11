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
#include "mtev_time.h"
#include "libmtev_dtrace_probes.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <port.h>
#include <pthread.h>

#define MAX_PORT_EVENTS 1024

struct _eventer_impl eventer_ports_impl;
#define LOCAL_EVENTER eventer_ports_impl
#define LOCAL_EVENTER_foreach_fdevent eventer_ports_impl_foreach_fdevent
#define LOCAL_EVENTER_foreach_timedevent eventer_ports_impl_foreach_timedevent
#define maxfds LOCAL_EVENTER.maxfds
#define master_fds LOCAL_EVENTER.master_fds

#include "eventer/eventer_impl_private.h"

static const struct timeval __dyna_increment = { 0, 1000 }; /* 1 ms */
struct ports_spec {
  int port_fd;
  mtev_spinlock_t wakeup_notify;
};

static void *eventer_ports_spec_alloc() {
  struct ports_spec *spec;
  spec = calloc(1, sizeof(*spec));
  spec->port_fd = port_create();
  if(spec->port_fd < 0) {
    mtevFatal(mtev_error, "error in eveter_ports_spec_alloc... spec->port_fd < 0 (%d)\n",
            spec->port_fd);
  }
  return spec;
}


static int eventer_ports_impl_init() {
  int rv;

  maxfds = eventer_impl_setrlimit();
  master_fds = calloc(maxfds, sizeof(*master_fds));

  /* super init */
  if((rv = eventer_impl_init()) != 0) return rv;

  signal(SIGPIPE, SIG_IGN);
  return 0;
}
static int eventer_ports_impl_propset(const char *key, const char *value) {
  if(eventer_impl_propset(key, value)) {
    return -1;
  }
  return 0;
}

static void alter_fd_associate(eventer_t e, int mask, struct ports_spec *spec) {
  int events = 0, s_errno = 0, ret;
  if(mask & EVENTER_READ) events |= POLLIN;
  if(mask & EVENTER_WRITE) events |= POLLOUT;
  if(mask & EVENTER_EXCEPTION) events |= POLLERR;
  errno = 0;
  ret = port_associate(spec->port_fd, PORT_SOURCE_FD, e->fd, events, (void *)(vpsized_int)e->fd);
  s_errno = errno;
  if (ret == -1) {
    mtevFatal(mtev_error,
          "eventer port_associate failed(%d-%d): %d/%s\n", e->fd, spec->port_fd, s_errno, strerror(s_errno));
  }
}

static void alter_fd_dissociate(eventer_t e, int mask, struct ports_spec *spec) {
  int s_errno = 0, ret;
  errno = 0;
  ret = port_dissociate(spec->port_fd, PORT_SOURCE_FD, e->fd);
  s_errno = errno;
  if (ret == -1) {
    if(s_errno == ENOENT) return; /* Fine */
    if(s_errno == EBADFD) return; /* Fine */
    mtevFatal(mtev_error,
          "eventer port_dissociate failed(%d-%d): %d/%s\n", e->fd, spec->port_fd, s_errno, strerror(s_errno));
  }
}

static void alter_fd(eventer_t e, int mask) {
  struct ports_spec *spec;
  spec = eventer_get_spec_for_event(e);
  if(mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    alter_fd_associate(e, mask, spec);
  }
  else {
    alter_fd_dissociate(e, mask, spec);
  }
}
static void eventer_ports_impl_add(eventer_t e) {
  mtevAssert(e->mask);
  ev_lock_state_t lockstate;
  const char *cbname;
  cbname = eventer_name_for_callback_e(e->callback, e);

  if(e->mask & EVENTER_ASYNCH) {
    mtevL(eventer_deb, "debug: eventer_add asynch (%s)\n", cbname ? cbname : "???");
    eventer_add_asynch(NULL, e);
    return;
  }

  /* Recurrent delegation */
  if(e->mask & EVENTER_RECURRENT) {
    mtevL(eventer_deb, "debug: eventer_add recurrent (%s)\n", cbname ? cbname : "???");
    eventer_add_recurrent(e);
    return;
  }

  /* Timed events are simple */
  if(e->mask & EVENTER_TIMER) {
    eventer_add_timed(e);
    return;
  }

  /* file descriptor event */
  mtevL(eventer_deb, "debug: eventer_add fd (%s,%d,0x%04x)\n", cbname ? cbname : "???", e->fd, e->mask);
  lockstate = acquire_master_fd(e->fd);
  mtevAssert(e->whence.tv_sec == 0 && e->whence.tv_usec == 0);
  master_fds[e->fd].e = e;
  alter_fd(e, e->mask);
  release_master_fd(e->fd, lockstate);
}
static eventer_t eventer_ports_impl_remove(eventer_t e) {
  eventer_t removed = NULL;
  if(e->mask & EVENTER_ASYNCH) {
    mtevFatal(mtev_error, "error in eventer_ports_impl_remove: got unexpected EVENTER_ASYNCH mask\n");
  }
  if(e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    ev_lock_state_t lockstate;
    lockstate = acquire_master_fd(e->fd);
    if(e == master_fds[e->fd].e) {
      removed = e;
      master_fds[e->fd].e = NULL;
      alter_fd(e, 0);
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
    mtevFatal(mtev_error, "error in eventer_ports_impl_remove: got unknown mask (0x%04x)\n",
            e->mask);
  }
  return removed;
}
static void eventer_ports_impl_update(eventer_t e, int mask) {
  if(e->mask & EVENTER_TIMER) {
    eventer_update_timed(e,mask);
    return;
  }
  alter_fd(e, mask);
  e->mask = mask;
}
static eventer_t eventer_ports_impl_remove_fd(int fd) {
  eventer_t eiq = NULL;
  ev_lock_state_t lockstate;
  if(master_fds[fd].e) {
    lockstate = acquire_master_fd(fd);
    /* Looks redundant, but we need to make sure we didn't lose
     * the event between checking and acquiring the lock */
    if(master_fds[fd].e) {
      eiq = master_fds[fd].e;
      master_fds[fd].e = NULL;
      alter_fd(eiq, 0);
    }
    release_master_fd(fd, lockstate);
  }
  return eiq;
}
static eventer_t eventer_ports_impl_find_fd(int fd) {
  return master_fds[fd].e;
}
static void
eventer_ports_impl_trigger(eventer_t e, int mask) {
  ev_lock_state_t lockstate;
  const char *cbname;
  struct timeval __now;
  int fd, newmask;
  int cross_thread = mask & EVENTER_CROSS_THREAD_TRIGGER;

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
    return;
  }
  if(master_fds[fd].e == NULL) {
    master_fds[fd].e = e;
    e->mask = 0;
  }
  if(e != master_fds[fd].e) return;
  lockstate = acquire_master_fd(fd);
  if(lockstate == EV_ALREADY_OWNED) return;
  mtevAssert(lockstate == EV_OWNED);

  gettimeofday(&__now, NULL);
  cbname = eventer_name_for_callback_e(e->callback, e);
  mtevLT(eventer_deb, &__now, "ports: fire on %d/%x to %s(%p)\n",
         fd, mask, cbname?cbname:"???", e->callback);
  mtev_memory_begin();
  LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)e, (void *)e->callback, (char *)cbname, fd, e->mask, mask);
  newmask = e->callback(e, mask, e->closure, &__now);
  LIBMTEV_EVENTER_CALLBACK_RETURN((void *)e, (void *)e->callback, (char *)cbname, newmask);
  mtev_memory_end();

  if(newmask) {
    if(!pthread_equal(pthread_self(), e->thr_owner)) {
      pthread_t tgt = e->thr_owner;
      e->thr_owner = pthread_self();
      alter_fd(e, 0);
      e->thr_owner = tgt;
      alter_fd(e, newmask);
      mtevL(eventer_deb, "moved event[%p] from t@%d to t@%d\n", e, pthread_self(), tgt);
    }
    else {
      alter_fd(e, newmask);
      /* Set our mask */
      e->mask = newmask;
      mtevLT(eventer_deb, &__now, "ports: complete on %d/(%x->%x) to %s(%p)\n",
             fd, mask, newmask, cbname?cbname:"???", e->callback);
    }
  }
  else {
    mtevLT(eventer_deb, &__now, "ports: complete on %d/none to %s(%p)\n",
           fd, cbname?cbname:"???", e->callback);
    /*
     * Long story long:
     *  When integrating with a few external event systems, we find
     *  it difficult to make their use of remove+add as an update
     *  as it can be recurrent in a single handler call and you cannot
     *  remove completely from the event system if you are going to
     *  just update (otherwise the eventer_t in your call stack could
     *  be stale).  What we do is perform a superficial remove, marking
     *  the mask as 0, but not eventer_remove_fd.  Then on an add, if
     *  we already have an event, we just update the mask (as we
     *  have not yet returned to the eventer's loop.
     *  This leaves us in a tricky situation when a remove is called
     *  and the add doesn't roll in, we return 0 (mask == 0) and hit
     *  this spot.  We have intended to remove the event, but it still
     *  resides at master_fds[fd].e -- even after we free it.
     *  So, in the evnet that we return 0 and the event that
     *  master_fds[fd].e == the event we're about to free... we NULL
     *  it out.
     */
    if(master_fds[fd].e == e) master_fds[fd].e = NULL;
    eventer_free(e);
  }
  release_master_fd(fd, lockstate);
}
static int eventer_ports_impl_loop() {
  struct timeval __dyna_sleep = { 0, 0 };
  struct ports_spec *spec;
  spec = eventer_get_spec_for_event(NULL);

  while(1) {
    struct timeval __now, __sleeptime;
    struct timespec __ports_sleeptime;
    unsigned int fd_cnt = 0;
    int ret;
    port_event_t pevents[MAX_PORT_EVENTS];

    mtev_time_maintain();

    if(compare_timeval(eventer_max_sleeptime, __dyna_sleep) < 0)
      __dyna_sleep = eventer_max_sleeptime;
 
    __sleeptime = __dyna_sleep;

    eventer_dispatch_timed(&__now, &__sleeptime);

    if(compare_timeval(__sleeptime, __dyna_sleep) > 0)
      __sleeptime = __dyna_sleep;

    /* Handle cross_thread dispatches */
    eventer_cross_thread_process();

    /* Handle recurrent events */
    eventer_dispatch_recurrent(&__now);

    /* Now we move on to our fd-based events */
    __ports_sleeptime.tv_sec = __sleeptime.tv_sec;
    __ports_sleeptime.tv_nsec = __sleeptime.tv_usec * 1000;
    fd_cnt = 1;

    pevents[0].portev_source = 65535; /* This is impossible */

    ret = port_getn(spec->port_fd, pevents, MAX_PORT_EVENTS, &fd_cnt,
                    &__ports_sleeptime);
    spec->wakeup_notify = 0; /* force unlock */
    /* The timeout case is a tad complex with ports.  -1/ETIME is clearly
     * a timeout.  However, it i spossible that we got that and fd_cnt isn't
     * 0, which means we both timed out and got events... WTF?
     */
    if(fd_cnt == 0 ||
       (ret == -1 && errno == ETIME && pevents[0].portev_source == 65535))
      add_timeval(__dyna_sleep, __dyna_increment, &__dyna_sleep);

    if(ret == -1 && (errno != ETIME && errno != EINTR))
      mtevLT(eventer_err, &__now, "port_getn: %s\n", strerror(errno));

    if(ret < 0)
      mtevLT(eventer_deb, &__now, "port_getn: %s\n", strerror(errno));

    mtevLT(eventer_deb, &__now, "debug: port_getn(%d, [], %d) => %d\n",
           spec->port_fd, fd_cnt, ret);

    if(pevents[0].portev_source == 65535) {
      /* the impossible still remains, which means our fd_cnt _must_ be 0 */
      fd_cnt = 0;
    }

    if(fd_cnt > 0) {
      int idx;
      /* Loop a last time to process */
      __dyna_sleep.tv_sec = __dyna_sleep.tv_usec = 0; /* reset */
      for(idx = 0; idx < fd_cnt; idx++) {
        port_event_t *pe;
        eventer_t e;
        int fd, mask;

        pe = &pevents[idx];
        if(pe->portev_source != PORT_SOURCE_FD) continue;
        fd = (int)pe->portev_object;
        mtevAssert((vpsized_int)pe->portev_user == fd);
        e = master_fds[fd].e;

        /* It's possible that someone removed the event and freed it
         * before we got here.... bail out if we're null.
         */
        if (!e) continue;

        mask = 0;
        if(pe->portev_events & (POLLIN | POLLHUP))
          mask |= EVENTER_READ;
        if(pe->portev_events & (POLLOUT))
          mask |= EVENTER_WRITE;
        if(pe->portev_events & (POLLERR | POLLHUP | POLLNVAL))
          mask |= EVENTER_EXCEPTION;

        eventer_ports_impl_trigger(e, mask);
      }
    }
  }
  /* NOTREACHED */
  return 0;
}

static void
eventer_ports_impl_wakeup(eventer_t e) {
  struct ports_spec *spec = eventer_get_spec_for_event(e);
  if(mtev_spinlock_trylock(&spec->wakeup_notify))
    port_send(spec->port_fd, 0, NULL);
}

struct _eventer_impl eventer_ports_impl = {
  "ports",
  eventer_ports_impl_init,
  eventer_ports_impl_propset,
  eventer_ports_impl_add,
  eventer_ports_impl_remove,
  eventer_ports_impl_update,
  eventer_ports_impl_remove_fd,
  eventer_ports_impl_find_fd,
  eventer_ports_impl_trigger,
  eventer_ports_impl_loop,
  eventer_ports_impl_foreach_fdevent,
  eventer_ports_impl_wakeup,
  eventer_ports_spec_alloc,
  { 0, 200000 },
  0,
  NULL
};
