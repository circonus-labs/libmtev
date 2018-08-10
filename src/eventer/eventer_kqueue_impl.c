/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
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
#include "mtev_skiplist.h"
#include "mtev_memory.h"
#include "mtev_log.h"
#include "libmtev_dtrace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <pthread.h>
#include <ck_spinlock.h>

struct _eventer_impl eventer_kqueue_impl;
#define LOCAL_EVENTER eventer_kqueue_impl
#define LOCAL_EVENTER_foreach_fdevent eventer_kqueue_impl_foreach_fdevent
#define LOCAL_EVENTER_foreach_timedevent eventer_kqueue_impl_foreach_timedevent
#define maxfds LOCAL_EVENTER.maxfds
#define master_fds LOCAL_EVENTER.master_fds

#include "eventer/eventer_impl_private.h"

static const struct timeval __dyna_increment = { 0, 10000 }; /* 10 ms */
typedef struct kqueue_spec {
  int kqueue_fd;
  ck_spinlock_t wakeup_notify;
  pthread_mutex_t lock;
  struct {
    struct kevent *__ke_vec;
    unsigned int __ke_vec_a;
    unsigned int __ke_vec_used;
  } q;
} *kqs_t;

static int *masks;
#define KQUEUE_DECL kqs_t kqs
#define KQUEUE_SETUP(e) kqs = (kqs_t) eventer_get_spec_for_event(e)
#define ke_vec kqs->q.__ke_vec
#define ke_vec_a kqs->q.__ke_vec_a
#define ke_vec_used kqs->q.__ke_vec_used

static void kqs_init(kqs_t kqs) {
  enum { initial_alloc = 64 };
  ke_vec_a = initial_alloc;
  ke_vec = (struct kevent *) malloc(ke_vec_a * sizeof (struct kevent));
}
static void
ke_change (register int const ident,
           register int const filter,
           register int const flags,
           register eventer_t e) {
  register struct kevent *kep;
  KQUEUE_DECL;
  KQUEUE_SETUP(e);

  pthread_mutex_lock(&kqs->lock);
  if (!ke_vec_a) {
    kqs_init(kqs);
  }
  else if (ke_vec_used == ke_vec_a) {
    ke_vec_a <<= 1;
    ke_vec = (struct kevent *) realloc(ke_vec,
                                       ke_vec_a * sizeof (struct kevent));
  }
  kep = &ke_vec[ke_vec_used++];

  EV_SET(kep, ident, filter, flags, 0, 0, (void *)(intptr_t)e->fd);
  mtevL(eventer_deb, "debug: [t@%zx] ke_change(fd:%d, filt:%x, flags:%x)\n",
        (intptr_t)e->thr_owner, ident, filter, flags);
  pthread_mutex_unlock(&kqs->lock);
}

static void eventer_kqueue_impl_wakeup_spec(struct kqueue_spec *spec) {
  struct kevent kev;
	EV_SET(&kev, 0, EVFILT_USER, 0, NOTE_FFCOPY|NOTE_TRIGGER|0x1, 0, NULL);
	kevent(spec->kqueue_fd, &kev, 1, NULL, 0, NULL);
}

static int eventer_kqueue_impl_register_wakeup(struct kqueue_spec *spec) {
  struct kevent kev;
  EV_SET(&kev, 0, EVFILT_USER, EV_ADD|EV_ONESHOT, NOTE_FFNOP, 0, NULL);
  mtevL(eventer_deb, "wakeup... reregister\n");
  return kevent(spec->kqueue_fd, &kev, 1, NULL, 0, NULL);
}

static void *eventer_kqueue_spec_alloc(void) {
  struct kqueue_spec *spec;
  spec = calloc(1, sizeof(*spec));
  spec->kqueue_fd = kqueue();
  if(spec->kqueue_fd == -1) {
    mtevFatal(mtev_error, "error in eveter_kqueue_spec_alloc... spec->epoll_fd < 0 (%d)\n",
              spec->kqueue_fd);
  }
  kqs_init(spec);
  pthread_mutex_init(&spec->lock, NULL);
  return spec;
}

static int eventer_kqueue_impl_init(void) {
  int rv;

  maxfds = eventer_impl_setrlimit();
  master_fds = calloc(maxfds, sizeof(*master_fds));
  masks = calloc(maxfds, sizeof(*masks));
  master_fds = calloc(maxfds, sizeof(*master_fds));
  masks = calloc(maxfds, sizeof(*masks));

  /* super init */
  if((rv = eventer_impl_init()) != 0) return rv;

  signal(SIGPIPE, SIG_IGN);
  return 0;
}
static int eventer_kqueue_impl_propset(const char *key, const char *value) {
  if(eventer_impl_propset(key, value)) {
    /* Do our kqueue local properties here */
    return -1;
  }
  return 0;
}
static void eventer_kqueue_impl_add(eventer_t e) {
  mtevAssert(e->mask);
  mtevAssert(eventer_is_loop(e->thr_owner) >= 0);
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
  mtevAssert(e->whence.tv_sec == 0 && e->whence.tv_usec == 0);
  lockstate = acquire_master_fd(e->fd);
  master_fds[e->fd].e = e;
  if(e->mask & (EVENTER_READ | EVENTER_EXCEPTION))
    ke_change(e->fd, EVFILT_READ, EV_ADD | EV_ENABLE, e);
  if(e->mask & (EVENTER_WRITE))
    ke_change(e->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, e);
  release_master_fd(e->fd, lockstate);
}
static eventer_t eventer_kqueue_impl_remove(eventer_t e) {
  eventer_t removed = NULL;
  if(e->mask & EVENTER_ASYNCH) {
    mtevFatal(mtev_error, "error in eventer_kqueue_impl_remove: got unexpected EVENTER_ASYNCH mask\n");
  }
  if(e->mask & (EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION)) {
    ev_lock_state_t lockstate;
    lockstate = acquire_master_fd(e->fd);
    mtevL(eventer_deb, "kqueue: remove(%d)\n", e->fd);
    if(e == master_fds[e->fd].e) {
      removed = e;
      master_fds[e->fd].e = NULL;
      if(e->mask & (EVENTER_READ | EVENTER_EXCEPTION))
        ke_change(e->fd, EVFILT_READ, EV_DELETE | EV_DISABLE, e);
      if(e->mask & (EVENTER_WRITE))
        ke_change(e->fd, EVFILT_WRITE, EV_DELETE | EV_DISABLE, e);
    } else
      mtevL(eventer_deb, "kqueue: remove(%d) failed.\n", e->fd);
    release_master_fd(e->fd, lockstate);
  }
  else if(e->mask & EVENTER_TIMER) {
    removed = eventer_remove_timed(e);
  }
  else if(e->mask & EVENTER_RECURRENT) {
    removed = eventer_remove_recurrent(e);
  }
  else {
    mtevFatal(mtev_error, "error in eventer_kqueue_impl_remove: got unknown mask (0x%04x)\n",
            e->mask);
  }
  return removed;
}
static void eventer_kqueue_impl_update(eventer_t e, int mask) {
  if(e->mask & EVENTER_TIMER) {
    eventer_update_timed_internal(e, mask, &e->whence);
    return;
  }
  mtevL(eventer_deb, "kqueue: update(%d, %x->%x)\n", e->fd, e->mask, mask);
  /* Disable old, if they aren't active in the new */
  if((e->mask & (EVENTER_READ | EVENTER_EXCEPTION)) &&
     !(mask & (EVENTER_READ | EVENTER_EXCEPTION)))
    ke_change(e->fd, EVFILT_READ, EV_DELETE | EV_DISABLE, e);
  if((e->mask & (EVENTER_WRITE)) &&
     !(mask & (EVENTER_WRITE)))
    ke_change(e->fd, EVFILT_WRITE, EV_DELETE | EV_DISABLE, e);

  /* Enable new, if the weren't in the old */
  if((mask & (EVENTER_READ | EVENTER_EXCEPTION)) &&
     !(e->mask & (EVENTER_READ | EVENTER_EXCEPTION)))
    ke_change(e->fd, EVFILT_READ, EV_ADD | EV_ENABLE, e);
  if((mask & (EVENTER_WRITE)) &&
     !(e->mask & (EVENTER_WRITE)))
    ke_change(e->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, e);

  /* Switch */
  e->mask = mask;
}
static eventer_t eventer_kqueue_impl_remove_fd(int fd) {
  eventer_t eiq = NULL;
  ev_lock_state_t lockstate;
  if(master_fds[fd].e) {
    mtevL(eventer_deb, "kqueue: remove_fd(%d)\n", fd);
    lockstate = acquire_master_fd(fd);
    eiq = master_fds[fd].e;
    master_fds[fd].e = NULL;
    if(eiq->mask & (EVENTER_READ | EVENTER_EXCEPTION))
      ke_change(fd, EVFILT_READ, EV_DELETE | EV_DISABLE, eiq);
    if(eiq->mask & (EVENTER_WRITE))
      ke_change(fd, EVFILT_WRITE, EV_DELETE | EV_DISABLE, eiq);
    release_master_fd(fd, lockstate);
  }
  return eiq;
}
static eventer_t eventer_kqueue_impl_find_fd(int fd) {
  if(fd < 0 || fd >= maxfds) return NULL;
  return master_fds[fd].e;
}
static void
alter_kqueue_mask(eventer_t e, int oldmask, int newmask) {
  /* toggle the read bits if needed */
  if(newmask & (EVENTER_READ | EVENTER_EXCEPTION)) {
    if(!(oldmask & (EVENTER_READ | EVENTER_EXCEPTION)))
      ke_change(e->fd, EVFILT_READ, EV_ADD | EV_ENABLE, e);
  }
  else if(oldmask & (EVENTER_READ | EVENTER_EXCEPTION))
    ke_change(e->fd, EVFILT_READ, EV_DELETE | EV_DISABLE, e);

  /* toggle the write bits if needed */
  if(newmask & EVENTER_WRITE) {
    if(!(oldmask & EVENTER_WRITE))
      ke_change(e->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, e);
  }
  else if(oldmask & EVENTER_WRITE)
    ke_change(e->fd, EVFILT_WRITE, EV_DELETE | EV_DISABLE, e);
}

static void eventer_kqueue_impl_wakeup(eventer_t e) {
  KQUEUE_DECL;
  KQUEUE_SETUP(e);
  if(ck_spinlock_trylock(&kqs->wakeup_notify))
    eventer_kqueue_impl_wakeup_spec(kqs);
}

static void eventer_kqueue_impl_trigger(eventer_t e, int mask) {
  ev_lock_state_t lockstate;
  struct timeval __now;
  int oldmask, newmask;
  const char *cbname;
  int fd;
  uint64_t start, duration;
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
    lockstate = acquire_master_fd(fd);
    if (lockstate == EV_ALREADY_OWNED) {
      /* The incoming triggered event is already owned by this thread.
	 This means our floated event completed before the current
	 event handler even exited.  So it retriggered recursively
	 from inside the event handler.

	 Treat this special case the same as a cross thread trigger
	 and just queue this event to be picked up on the next loop
      */
      eventer_cross_thread_trigger(e, mask);
      return;
    }
    release_master_fd(fd, lockstate);
    master_fds[fd].e = e;
    e->mask = 0;
  }
  if(e != master_fds[fd].e) return;
  lockstate = acquire_master_fd(fd);
  if(lockstate == EV_ALREADY_OWNED) {
    mtevL(eventer_deb, "Incoming event: %p already owned by this thread\n", e);
    return;
  }
  mtevAssert(lockstate == EV_OWNED);

  eventer_mark_callback_time();
  eventer_gettimeofcallback(&__now, NULL);
  /* We're going to lie to ourselves.  You'd think this should be:
   * oldmask = e->mask;  However, we just fired with masks[fd], so
   * kqueue is clearly looking for all of the events in masks[fd].
   * So, we combine them "just to be safe."
   */
  oldmask = e->mask | masks[fd];
  cbname = eventer_name_for_callback_e(e->callback, e);
  mtevL(eventer_deb, "kqueue: fire on %d/%x to %s(%p)\n",
         fd, masks[fd], cbname?cbname:"???", e->callback);
  mtev_memory_begin();
  LIBMTEV_EVENTER_CALLBACK_ENTRY((void *)e, (void *)e->callback, (char *)cbname, fd, e->mask, mask);
  start = mtev_gethrtime();
  newmask = eventer_run_callback(e, mask, e->closure, &__now);
  duration = mtev_gethrtime() - start;
  LIBMTEV_EVENTER_CALLBACK_RETURN((void *)e, (void *)e->callback, (char *)cbname, newmask);
  mtev_memory_end();
  stats_set_hist_intscale(eventer_callback_latency, duration, -9, 1);
  stats_set_hist_intscale(eventer_latency_handle_for_callback(e->callback), duration, -9, 1);

  if(newmask) {
    if(!pthread_equal(pthread_self(), e->thr_owner)) {
      pthread_t tgt = e->thr_owner;
      e->thr_owner = pthread_self();
      alter_kqueue_mask(e, oldmask, 0);
      e->thr_owner = tgt;
      mtevL(eventer_deb, "moved event[%p] from t@%zx to t@%zx\n", e, (intptr_t)pthread_self(), (intptr_t)tgt);
      if(newmask) eventer_cross_thread_trigger(e, newmask & ~(EVENTER_EXCEPTION));
    }
    else {
      if(master_fds[fd].e != e) {
        e = master_fds[fd].e;
        mtevL(eventer_deb, "%strigger complete [event switched] %d : %x->%x\n", cross_thread ? "[X]" : "", e->fd, master_fds[fd].e->mask, newmask);
      } else {
        mtevL(eventer_deb, "%strigger complete %d : %x->%x\n", cross_thread ? "[X]" : "", e->fd, oldmask, newmask);
      }
      alter_kqueue_mask(e, (e->mask == 0 || cross_thread) ? 0 : oldmask, newmask);
      /* Set our mask */
      e->mask = newmask;
    }
  }
  else {
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
static int eventer_kqueue_impl_loop(int id) {
  struct timeval __dyna_sleep = { 0, 0 };
  KQUEUE_DECL;
  KQUEUE_SETUP(NULL);

  if(eventer_kqueue_impl_register_wakeup(kqs) == -1) {
    mtevFatal(mtev_error, "error in eventer_kqueue_impl_loop: could not eventer_kqueue_impl_register_wakeup\n");
  }

  while(1) {
    struct timeval __sleeptime;
    struct timespec __kqueue_sleeptime;
    int fd_cnt = 0;

    if(compare_timeval(eventer_max_sleeptime, __dyna_sleep) < 0)
      __dyna_sleep = eventer_max_sleeptime;

    __sleeptime = __dyna_sleep;

    eventer_dispatch_timed(&__sleeptime);

    if(compare_timeval(__sleeptime, __dyna_sleep) > 0)
      __sleeptime = __dyna_sleep;

    /* Handle cross_thread dispatches */
    eventer_cross_thread_process();

    /* Handle recurrent events */
    eventer_dispatch_recurrent();

    /* Now we move on to our fd-based events */
    __kqueue_sleeptime.tv_sec = __sleeptime.tv_sec;
    __kqueue_sleeptime.tv_nsec = __sleeptime.tv_usec * 1000;
    fd_cnt = kevent(kqs->kqueue_fd, ke_vec, ke_vec_used,
                    ke_vec, ke_vec_a,
                    &__kqueue_sleeptime);
    ck_spinlock_init(&kqs->wakeup_notify);
    if(fd_cnt > 0 || ke_vec_used)
      mtevL(eventer_deb, "[t@%zx] kevent(%d, [...], %d) => %d\n", (intptr_t)pthread_self(), kqs->kqueue_fd, ke_vec_used, fd_cnt);
    ke_vec_used = 0;
    if(fd_cnt < 0) {
      mtevL(eventer_err, "kevent(s/%d): %s\n", kqs->kqueue_fd, strerror(errno));
    }
    else if(fd_cnt == 0 ||
            (fd_cnt == 1 && ke_vec[0].filter == EVFILT_USER)) {
      /* timeout */
      if(fd_cnt) eventer_kqueue_impl_register_wakeup(kqs);
      add_timeval(__dyna_sleep, __dyna_increment, &__dyna_sleep);
    }
    else {
      int idx;
      __dyna_sleep.tv_sec = __dyna_sleep.tv_usec = 0; /* reset */
      /* loop once to clear */
      for(idx = 0; idx < fd_cnt; idx++) {
        struct kevent *ke;
        ke = &ke_vec[idx];
        if(ke->flags & EV_ERROR) continue;
        if(ke->filter == EVFILT_USER) {
          eventer_kqueue_impl_register_wakeup(kqs);
          continue;
        }
        masks[ke->ident] = 0;
      }
      /* Loop again to aggregate */
      for(idx = 0; idx < fd_cnt; idx++) {
        struct kevent *ke;
        ke = &ke_vec[idx];
        if(ke->flags & EV_ERROR) continue;
        if(ke->filter == EVFILT_USER) continue;
        if(ke->filter == EVFILT_READ) masks[ke->ident] |= EVENTER_READ;
        if(ke->filter == EVFILT_WRITE) masks[ke->ident] |= EVENTER_WRITE;
      }
      /* Loop a last time to process */
      for(idx = 0; idx < fd_cnt; idx++) {
        struct kevent *ke;
        eventer_t e;
        int fd;

        ke = &ke_vec[idx];
        if(ke->filter == EVFILT_USER) continue;
        if(ke->flags & EV_ERROR) {
          if(ke->data != EBADF && ke->data != ENOENT)
            mtevL(eventer_err, "error [%d]: %s\n",
                   (int)ke->ident, strerror(ke->data));
          continue;
        }
        mtevAssert((intptr_t)ke->udata == (intptr_t)ke->ident);
        fd = ke->ident;
        e = master_fds[fd].e;
        /* If we've seen this fd, don't callback twice */
        if(!masks[fd]) continue;
        /* It's possible that someone removed the event and freed it
         * before we got here.
         */
        if(e) eventer_kqueue_impl_trigger(e, masks[fd]);
        masks[fd] = 0; /* indicates we've processed this fd */
      }
    }
  }
  /* NOTREACHED */
  return 0;
}

struct _eventer_impl eventer_kqueue_impl = {
  "kqueue",
  eventer_kqueue_impl_init,
  eventer_kqueue_impl_propset,
  eventer_kqueue_impl_add,
  eventer_kqueue_impl_remove,
  eventer_kqueue_impl_update,
  eventer_kqueue_impl_remove_fd,
  eventer_kqueue_impl_find_fd,
  eventer_kqueue_impl_trigger,
  eventer_kqueue_impl_loop,
  eventer_kqueue_impl_foreach_fdevent,
  eventer_kqueue_impl_wakeup,
  eventer_kqueue_spec_alloc,
  { 0, 200000 },
  0,
  NULL
};
