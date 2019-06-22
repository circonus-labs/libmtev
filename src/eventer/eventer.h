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

#ifndef _EVENTER_EVENTER_H
#define _EVENTER_EVENTER_H

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_time.h"
#include <ck_pr.h>
#include <ck_spinlock.h>
#include <sys/time.h>
#include <sys/socket.h>

#define EVENTER_READ             0x01
#define EVENTER_WRITE            0x02
#define EVENTER_EXCEPTION        0x04
#define EVENTER_TIMER            0x08
#define EVENTER_ASYNCH_WORK_D    0x10
#define EVENTER_ASYNCH_CLEANUP_D 0x20
#define EVENTER_ASYNCH_D         (EVENTER_ASYNCH_WORK_D | EVENTER_ASYNCH_CLEANUP_D)
#define EVENTER_ASYNCH_COMPLETE_D EVENTER_ASYNCH_D
#define EVENTER_RECURRENT        0x80
#define EVENTER_EVIL_BRUTAL     0x100
#define EVENTER_CANCEL_DEFERRED 0x200
#define EVENTER_CANCEL_ASYNCH   0x400
#define EVENTER_CANCEL          (EVENTER_CANCEL_DEFERRED|EVENTER_CANCEL_ASYNCH)

#define EVENTER_RESERVED                  0xfff00000
#define EVENTER_CROSS_THREAD_TRIGGER      0x80000000

#define EVENTER_DEFAULT_ASYNCH_ABORT EVENTER_EVIL_BRUTAL

#define EVENTER_CHOOSE_THREAD_FOR_EVENT_FD(e) eventer_choose_owner(eventer_get_fd(e)+1)

typedef enum eventer_asynch_op {
  EVENTER_ASYNCH_WORK = EVENTER_ASYNCH_WORK_D,
  EVENTER_ASYNCH_CLEANUP = EVENTER_ASYNCH_CLEANUP_D,
  EVENTER_ASYNCH_COMPLETE = EVENTER_ASYNCH_COMPLETE_D
} eventer_asynch_op_t;

#define EVENTER_ASYNCH EVENTER_ASYNCH_COMPLETE

/*! \fn const char *eventer_get_thread_name(void)
    \brief Retrieve a human-friendly name for an eventer thread.
    \return A thread name.
*/
const char *eventer_get_thread_name(void);

/* All of these functions act like their POSIX couterparts with two
 * additional arguments.  The first is the mask they require to be active
 * to make progress in the event of an EAGAIN.  The second is a closure
 * which is the event itself.
 */
typedef struct _fd_opset *eventer_fd_opset_t;

typedef int (*eventer_fd_accept_t)
            (int, struct sockaddr *, socklen_t *, int *mask, void *closure);
typedef int (*eventer_fd_read_t)
            (int, void *, size_t, int *mask, void *closure);
typedef int (*eventer_fd_write_t)
            (int, const void *, size_t, int *mask, void *closure);
typedef int (*eventer_fd_close_t)
            (int, int *mask, void *closure);
typedef void (*eventer_fd_set_opset_t)
             (void *closure, eventer_fd_opset_t opset);
typedef void *(*eventer_fd_get_opset_ctx_t)
              (void *closure);
typedef void (*eventer_fd_set_opset_ctx_t)
             (void *closure, void *newctx);

struct _event;
typedef int (*eventer_func_t)
            (struct _event *e, int mask, void *closure, struct timeval *tv);
typedef struct _event *eventer_t;
typedef struct _event_aco *eventer_aco_t;
typedef struct _event_aco_gate *eventer_aco_gate_t;

typedef void (*eventer_asynch_simple_func_t)(void *closure);
typedef void (*eventer_asynch_func_t)(eventer_asynch_op_t, void *closure);

typedef struct eventer_context_opset_t {
  eventer_t (*eventer_t_init)(eventer_t);
  void (*eventer_t_deinit)(eventer_t);
  void (*eventer_t_copy)(eventer_t, const eventer_t);
  void (*eventer_t_callback_prep)(eventer_t, int, void *, struct timeval *);
  void (*eventer_t_callback_cleanup)(eventer_t, int);
} eventer_context_opset_t;

/*! \fn int eventer_register_context(const char *name, eventer_context_opset_t *opset)
    \brief Register an eventer carry context.
    \param name a string naming the context class.
    \param opset an opset for context maintenance
    \return A `ctx_idx`, -1 on failure.
*/
int eventer_register_context(const char *name,
                             eventer_context_opset_t *opset);

/*! \fn int eventer_get_context(eventer_t e, int ctx_idx)
    \brief Get a context for an event.
    \param e an event object
    \param ctx_idx is an idx returned from `eventer_register_context`
    \return The attached context.
*/
void *eventer_get_context(eventer_t e, int ctx_idx);

/*! \fn void *eventer_set_context(eventer_t e, int ctx_idx, void *data)
    \brief Set a context for an event.
    \param e an event object
    \param ctx_idx is an idx returned from `eventer_register_context`
    \param data is new context data.
    \return The previously attached context.
*/
void *eventer_set_context(eventer_t e, int ctx_idx, void *);

typedef struct eventer_pool_t eventer_pool_t;

/*! \fn eventer_fd_accept_t eventer_fd_opset_get_accept(eventer_fd_opset_t opset)
    \brief Retrieve the accept function from an fd opset.
    \param opset an opset (see `eventer_get_fd_opset`)
    \return An eventer_fd_accept_t function
*/
eventer_fd_accept_t eventer_fd_opset_get_accept(eventer_fd_opset_t opset);
/*! \fn eventer_fd_read_t eventer_fd_opset_get_read(eventer_fd_opset_t opset)
    \brief Retrieve the read function from an fd opset.
    \param opset an opset (see `eventer_get_fd_opset`)
    \return An eventer_fd_read_t function
*/
eventer_fd_read_t eventer_fd_opset_get_read(eventer_fd_opset_t opset);
/*! \fn eventer_fd_write_t eventer_fd_opset_get_write(eventer_fd_opset_t opset)
    \brief Retrieve the write function from an fd opset.
    \param opset an opset (see `eventer_get_fd_opset`)
    \return An eventer_fd_write_t function
*/
eventer_fd_write_t eventer_fd_opset_get_write(eventer_fd_opset_t opset);
/*! \fn eventer_fd_close_t eventer_fd_opset_get_close(eventer_fd_opset_t opset)
    \brief Retrieve the close function from an fd opset.
    \param opset an opset (see `eventer_get_fd_opset`)
    \return An eventer_fd_close_t function
*/
eventer_fd_close_t eventer_fd_opset_get_close(eventer_fd_opset_t opset);
/*! \fn eventer_fd_opset_t eventer_get_fd_opset(eventer_t e)
    \brief Retrieve the fd opset from an event.
    \param e an event object
    \return The currently active opset for a fd-based eventer_t.
*/
eventer_fd_opset_t eventer_get_fd_opset(eventer_t e);

/*! \fn int eventer_get_fd(eventer_t e)
    \brief Retrieve the file descriptor for an fd-based event.
    \param e an event object
    \return a file descriptor.
*/
int eventer_get_fd(eventer_t e);
/*! \fn int eventer_get_mask(eventer_t e)
    \brief Retrieve the mask for an event.
    \param e an event object
    \return a mask of bitwise-or'd valued.

        * `EVENTER_READ` -- trigger/set when a file descriptor is readable.
        * `EVENTER_WRITE` -- trigger/set when a file descriptor is writeable.
        * `EVENTER_EXCEPTION` -- trigger/set problems with a file descriptor.
        * `EVENTER_TIMER` -- trigger/set at a specific time.
        * `EVENTER_RECURRENT` -- trigger/set on each pass through the event-loop.
        * `EVENTER_ASYNCH_COMPLETE` -- trigger from a non-event-loop thread, set upon completion.
        * `EVENTER_ASYNCH_WORK` -- set during asynchronous work.
        * `EVENTER_ASYNCH_CLEANUP` -- set during asynchronous cleanup.
*/
int eventer_get_mask(eventer_t e);
/*! \fn void eventer_set_mask(eventer_t e, int mask)
    \brief Change an event's interests or intentions.
    \param e an event object
    \param mask a new mask

    Do not change change a mask from one event "type" to another. fd events
    must remain fd events. Timer must remain timer. Recurrent must remain recurrent.
    Do not alter asynch events at all.  This simply changes the mask of the event
    without changing any eventer state and should be used with extremem care.
    Consider using the callback's return value or `eventer_update` to change
    the mask of an active event in the system.
*/
void eventer_set_mask(eventer_t e, int mask);
/*! \fn struct timeval eventer_get_whence(eventer_t e)
    \brief Retrieve the time at which a timer event will fire.
    \param e an event object
    \return A absolute time.
*/
struct timeval eventer_get_whence(eventer_t e);
/*! \fn pthread_t eventer_get_owner(eventer_t e)
    \brief Retrieve the thread that owns an event.
    \param e an event object
    \return a `pthread_t` thread.
*/
pthread_t eventer_get_owner(eventer_t e);
/*! \fn void eventer_set_owner(eventer_t e, pthread_t t)
    \brief Set the thread that owns an event.
    \param e an event object
    \param t a `pthread_t` thread; must be a valid event-loop.
*/
void eventer_set_owner(eventer_t e, pthread_t t);
/*! \fn eventer_func_t eventer_get_callback(eventer_t e)
    \brief Retrieve the callback function for an event.
    \param e an event object
    \return An `eventer_func_t` callback function.
*/
eventer_func_t eventer_get_callback(eventer_t e);
/*! \fn void eventer_set_callback(eventer_t e, eventer_func_t func)
    \brief Set an event's callback function.
    \param e an event object
*/
void eventer_set_callback(eventer_t e, eventer_func_t);
/*! \fn void *eventer_get_closure(eventer_t e)
    \brief Retrieve an event's closure.
    \param e an event object
    \return The previous closure set.
*/
void *eventer_get_closure(eventer_t e);
/*! \fn void eventer_set_closure(eventer_t e, void *closure)
    \brief Set an event's closure.
    \param e an event object
    \param closure a pointer to user-data to be supplied during callback.
*/
void eventer_set_closure(eventer_t e, void *);

/*! \fn void *eventer_aco_get_closure(eventer_aco_t e)
    \brief Retrieve an event's closure.
    \param e an event object
    \return The previous closure set.
*/
void *eventer_aco_get_closure(eventer_aco_t e);
/*! \fn void eventer_aco_set_closure(eventer_aco_t e, void *closure)
    \brief Set an event's closure.
    \param e an event object
    \param closure a pointer to user-data to be supplied during callback.
*/
void eventer_aco_set_closure(eventer_aco_t e, void *);

/* I hate this name, it should be eventer_remove_fd... */
/*! \fn eventer_t eventer_remove_fde(eventer_t e)
    \brief Removes an fd event from the eventloop based on filedescriptor alone.
    \param e an event object
    \return The event removed, NULL if no event was present.
*/
#define eventer_remove_fde(e) eventer_remove_fd(eventer_get_fd(e))

/*! \fn int eventer_callback(eventer_t e, int mask, void *closure, struct timeval *now)
    \brief Directly invoke an event's callback.
    \param e an event object
    \param mask the mask that callback should be acting upon (see `eventer_get_mask`)
    \param closure the closure on which the callback should act
    \param now the time the callback should see as "now".
    \return The return value of the callback function as invoked.

    This does not call the callback in the contexts of the eventloop.  This means
    that should the callback return a mask, the event-loop will not interpret it
    and change state appropriately.  The caller must respond appropriately to any
    return values.
*/
#define eventer_callback(e,v1,v2,v3) \
  eventer_get_callback(e)((e),(v1),(v2),(v3))

/*! \fn int eventer_accept(eventer_t e, struct sockaddr *addr, socklen_t *len, int *mask)
    \brief Execute an opset-appropriate `accept` call.
    \param e an event object
    \param addr a `struct sockaddr` to be populated.
    \param len a `socklen_t` pointer to the size of the `addr` argument; updated.
    \param mask a point the a mask. If the call does not complete, `*mask` it set.
    \return an opset-appropriate return value. (fd for POSIX, -1 for SSL).

    If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
    necessary activity to make progress.
*/
API_EXPORT(int)
  eventer_accept(eventer_t e, struct sockaddr *addr, socklen_t *len, int *mask);

/*! \fn int eventer_read(eventer_t e, void *buff, size_t len, int *mask)
    \brief Execute an opset-appropriate `read` call.
    \param e an event object
    \param buff a buffer in which to place read data.
    \param len the size of `buff` in bytes.
    \param mask a point the a mask. If the call does not complete, `*mask` it set.
    \return the number of bytes read or -1 with errno set.

    If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
    necessary activity to make progress.
*/
API_EXPORT(int) eventer_read(eventer_t e, void *buff, size_t len, int *mask);

/*! \fn int eventer_write(eventer_t e, const void *buff, size_t len, int *mask)
    \brief Execute an opset-appropriate `write` call.
    \param e an event object
    \param buff a buffer containing data to write.
    \param len the size of `buff` in bytes.
    \param mask a point the a mask. If the call does not complete, `*mask` it set.
    \return the number of bytes written or -1 with errno set.

    If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
    necessary activity to make progress.
*/
API_EXPORT(int) eventer_write(eventer_t e, const void *buff, size_t len, int *mask);

/*! \fn int eventer_close(eventer_t e, int *mask)
    \brief Execute an opset-appropriate `close` call.
    \param e an event object
    \param mask a point the a mask. If the call does not complete, `*mask` it set.
    \return 0 on sucess or -1 with errno set.

    If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
    necessary activity to make progress.
*/
API_EXPORT(int) eventer_close(eventer_t e, int *mask);

#include "eventer/eventer_POSIX_fd_opset.h"
#include "eventer/eventer_SSL_fd_opset.h"
#include "eventer/eventer_aco_opset.h"

/*! \fn void eventer_aco_set_accept_timeout(eventer_aco_t e, struct timeval *duration)
    \brief Change the default timeout for ACO events.
    \param e the ACO event to update.
    \param duration a timeout duration, NULL will undo the default.
*/
API_EXPORT(void) eventer_aco_set_accept_timeout(eventer_aco_t e, struct timeval *duration);

/*! \fn void eventer_aco_set_read_timeout(eventer_aco_t e, struct timeval *duration)
    \brief Change the default timeout for ACO events.
    \param e the ACO event to update.
    \param duration a timeout duration, NULL will undo the default.
*/
API_EXPORT(void) eventer_aco_set_read_timeout(eventer_aco_t e, struct timeval *duration);

/*! \fn void eventer_aco_set_write_timeout(eventer_aco_t e, struct timeval *duration)
    \brief Change the default timeout for ACO events.
    \param e the ACO event to update.
    \param duration a timeout duration, NULL will undo the default.
*/
API_EXPORT(void) eventer_aco_set_write_timeout(eventer_aco_t e, struct timeval *duration);

/*! \fn void eventer_aco_sleep(struct timeval *duration)
    \brief Execute a sleep within an aco context.
    \param duration the time to suspend.
*/
API_EXPORT(void) eventer_aco_sleep(struct timeval *duration);

/*! \fn int eventer_aco_accept(eventer_t e, struct sockaddr *addr, socklen_t *len, struct timeval *timeout)
    \brief Execute an opset-appropriate `accept` call.
    \param e an event object
    \param addr a `struct sockaddr` to be populated.
    \param len a `socklen_t` pointer to the size of the `addr` argument; updated.
    \param timeout if not NULL, the time after which we fail -1, ETIME
    \return an opset-appropriate return value. (fd for POSIX, -1 for SSL).
*/
API_EXPORT(int)
  eventer_aco_accept(eventer_aco_t e, struct sockaddr *addr, socklen_t *len, struct timeval *timeout);

/*! \fn int eventer_aco_read(eventer_aco_t e, void *buff, size_t len, struct timeval *timeout)
    \brief Execute an opset-appropriate `read` call.
    \param e an event object
    \param buff a buffer in which to place read data.
    \param len the size of `buff` in bytes.
    \param timeout if not NULL, the time after which we fail -1, ETIME
    \return the number of bytes read or -1 with errno set.
*/
API_EXPORT(int) eventer_aco_read(eventer_aco_t e, void *buff, size_t len, struct timeval *timeout);

/*! \fn int eventer_aco_write(eventer_aco_t e, const void *buff, size_t len, struct timeval *timeout)
    \brief Execute an opset-appropriate `write` call.
    \param e an event object
    \param buff a buffer containing data to write.
    \param len the size of `buff` in bytes.
    \param timeout if not NULL, the time after which we fail -1, ETIME
    \return the number of bytes written or -1 with errno set.
*/
API_EXPORT(int) eventer_aco_write(eventer_aco_t e, const void *buff, size_t len, struct timeval *timeout);

/*! \fn int eventer_aco_close(eventer_aco_t e)
    \brief Execute an opset-appropriate `close` call.
    \param e an event object
    \return 0 on sucess or -1 with errno set.
*/
API_EXPORT(int) eventer_aco_close(eventer_aco_t e);

/* allocating, freeing and reference counts:
   When eventer_alloc() is called, the object returned has a refcnt == 1.
   Once the event it handed into the eventer (via the eventer_add type
   functions), the eventer is then responsible for deref'ing the event.
   If another thread needs access to this event and is worried about
   the eventer firing and subsequently freeing the event, the event
   should be eventer_ref()'d before it is passed to that new thread and
   subsequently eventer_deref()'d by the new thread when it is no longer
   needed.

   use 1:
     THREAD 1

     e = eventer_alloc()
     ...
     eventer_add(e)

   use 2:
     THREAD 1                |  THREAD 2
     e = eventer_alloc()     |
     ...                     |
     eventer_ref(e)          |
     // hand e to thread 2   |  // receive e
     ...                     |  ...
     eventer_add(e)          |  ...
                             |  eventer_deref(e)
 */

/*! \fn eventer_t eventer_alloc()
    \brief Allocate an event to be injected into the eventer system.
    \return A newly allocated event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.
*/
API_EXPORT(eventer_t) eventer_alloc(void);

/*! \fn eventer_t eventer_alloc_copy(eventer_t src)
    \brief Allocate an event copied from another to be injected into the eventer system.
    \param src a source eventer_t to copy.
    \return A newly allocated event that is a copy of src.

    The allocated event has a refernce count of 1.
*/
API_EXPORT(eventer_t) eventer_alloc_copy(eventer_t src);

/*! \fn eventer_t eventer_alloc_timer(eventer_func_t func, void *closure, struct timeval *whence)
    \brief Allocate an event to be injected into the eventer system.
    \param func The callback function.
    \param closure The closure for the callback function.
    \param whence The time at which the event should fire.
    \return A newly allocated timer event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.
*/
API_EXPORT(eventer_t) eventer_alloc_timer(eventer_func_t, void *, struct timeval *);

/*! \fn eventer_t eventer_alloc_recurrent(eventer_func_t func, void *closure)
    \brief Allocate an event to be injected into the eventer system.
    \param func The callback function.
    \param closure The closure for the callback function.
    \return A newly allocated recurrent event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.
*/
API_EXPORT(eventer_t) eventer_alloc_recurrent(eventer_func_t, void *);

/*! \fn eventer_t eventer_alloc_fd(eventer_func_t func, void *closure, int fd, int mask)
    \brief Allocate an event to be injected into the eventer system.
    \param func The callback function.
    \param closure The closure for the callback function.
    \param fd The file descriptor.
    \param mask The mask of activity of interest.
    \return A newly allocated fd event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.
*/
API_EXPORT(eventer_t) eventer_alloc_fd(eventer_func_t, void *, int, int);

/*! \fn eventer_t eventer_alloc_asynch(eventer_func_t func, void *closure)
    \brief Allocate an event to be injected into the eventer system.
    \param func The callback function.
    \param closure The closure for the callback function.
    \return A newly allocated asynch event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.
*/
API_EXPORT(eventer_t) eventer_alloc_asynch(eventer_func_t, void *);

/*! \fn eventer_t eventer_alloc_asynch_timeout(eventer_func_t func, void *closure, struct timeval *deadline)
    \brief Allocate an event to be injected into the eventer system.
    \param func The callback function.
    \param closure The closure for the callback function.
    \param deadline an absolute time by which the task must be completed.
    \return A newly allocated asynch event.

    The allocated event has a refernce count of 1 and is attached to the
    calling thread.  Depending on the timeout method, there are not hard
    guarantees on enforcing the deadline; this is more of a guideline for
    the schedule and the job could be aborted (where the `EVENTER_ASYNCH_WORK`
    phase is not finished or even started, but the `EVENTER_ASYNCH_CLEANUP`
    will be called).
*/
API_EXPORT(eventer_t) eventer_alloc_asynch_timeout(eventer_func_t, void *, struct timeval *);

/*! \fn void eventer_free(eventer_t e)
    \brief Dereferences the event specified.
    \param e the event to dereference.
*/
API_EXPORT(void)      eventer_free(eventer_t);

/*! \fn void eventer_ref(eventer_t e)
    \brief Add a reference to an event.
    \param e the event to reference.

    Adding a reference to an event will prevent it from being deallocated
    prematurely.  This is classic reference counting.  It is are that one
    needs to maintain an actual event past the point where the eventer
    system would normally free it.  Typically, one will allocate a new
    event and copy the contents of the old event into it allowing the
    original to be freed.
*/
API_EXPORT(void)      eventer_ref(eventer_t);

/*! \fn void eventer_deref(eventer_t e)
    \brief See eventer_free.
    \param e the event to dereference.
*/
API_EXPORT(void)      eventer_deref(eventer_t);

/*! \fn int64_t eventer_allocations_current()
    \return the number of currently allocated eventer objects.
*/
API_EXPORT(int64_t)   eventer_allocations_current(void);

/*! \fn int64_t eventer_allocations_total()
    \return the number of allocated eventer objects over the life of the process.
*/
API_EXPORT(int64_t)   eventer_allocations_total(void);

/*! \fn int eventer_name_callback(const char *name, eventer_func_t callback)
    \brief Register a human/developer readable name for a eventer callback function.
    \param name the human readable name.  You should select clear/unique names for clarity in debugging.
    \param callback the function pointer of the eventer callback.
    \return 0 on success.
*/
API_EXPORT(int)       eventer_name_callback(const char *name, eventer_func_t f);

/*! \fn int eventer_name_callback_ext(const char *name, eventer_func_t callback, void (*fn)(char *buff,int bufflen,eventer_t e,void *closure), void *closure)
    \brief Register a functional describer for a callback and it's event object.
    \param name the human readable name.  You should select clear/unique names for clarity in debugging.
    \param callback the function pointer of the eventer callback.
    \param fn function to call when describing the event. It should write a null terminated string into buff (no more than bufflen).  If this is defined, it will override the "name" paramter when eventer_name_for_callback is called.
    \return 0 on success.

    This function allows more in-depth descriptions of events.  When an event
    is displayed (over the console or REST endpoints), this function is called
    with the event in question and the closure specified at registration time.
*/
API_EXPORT(int)       eventer_name_callback_ext(const char *name,
                                                eventer_func_t f,
                                                void (*fn)(char *,int,eventer_t,void *),
                                                void *);

/*! \fn const char *eventer_name_for_callback(evneter_func_t f)
    \brief Retrieve a human readable name for the provided callback.
    \param f a callback function.
    \return name or extended descripton of callback

    If an extended description function is available, it will be preferred with  
    the name returned as a default.
    The returned value may be a pointer to reusable thread-local storage.
    The value should be used before a subsequent call to this function.
    Aside from that caveat, it is thread-safe.
*/
API_EXPORT(const char *)
                      eventer_name_for_callback(eventer_func_t f);

/*! \fn const char *eventer_name_for_callback(evneter_func_t f, eventer_t e)
    \brief Retrieve a human readable name for the provided callback with event context.
    \param f a callback function.
    \param e and event object
    \return name of callback

    The returned value may be a pointer to reusable thread-local storage.
    The value should be used before a subsequent call to this function.
    Aside from that caveat, it is thread-safe.
*/
API_EXPORT(const char *)
                      eventer_name_for_callback_e(eventer_func_t, eventer_t);

/*! \fn evneter_func_t eventer_callback_for_name(const char *name)
    \brief Find an event callback function that has been registered by name.
    \param name the name of the callback.
    \return the function pointer or NULL if no such callback has been registered.
*/
API_EXPORT(eventer_func_t)
                      eventer_callback_for_name(const char *name);

/*! \fn eventer_gettimeofcallback(struct timeval *now, void *tzp)
    \brief Get the time of the last invoked callback in this thread.
    \param now a `struct timeval` to populate with the request time.
    \param tzp is ignored and for API compatibility with gettimeofday.
    \return 0 on success, non-zero on failure.

    This function returns the time of the last callback execution.  It
    is fast and cheap (cheaper than gettimeofday), so if a function
    wishes to know what time it is and the "time of invocation" is good
    enough, this is considerably cheaper than a call to `mtev_gettimeofday`
    or other system facilities.
 */
API_EXPORT(int)
  eventer_gettimeofcallback(struct timeval *now, void *tzp);

/*! \fn uint64_t eventer_callback_ms()
    \brief Get the milliseconds since epoch of the current callback invocation.
    \return milliseconds since epoch of callback invocation, or current time.
 */
API_EXPORT(uint64_t) eventer_callback_ms(void);

/*! \fn uint64_t eventer_callback_us()
    \brief Get the microseconds since epoch of the current callback invocation.
    \return microseconds since epoch of callback invocation, or current time.
 */
API_EXPORT(uint64_t) eventer_callback_us(void);

/* These values are set on initialization and are safe to use
 * on any platform.  They will be set to zero on platforms that
 * do not support them.  As such, you can always bit-or them.
 */
API_EXPORT(int) NE_SOCK_CLOEXEC;
API_EXPORT(int) NE_O_CLOEXEC;

typedef struct _eventer_impl {
  const char         *name;
  int               (*init)(void);
  int               (*propset)(const char *key, const char *value);
  void              (*add)(eventer_t e);
  eventer_t         (*remove)(eventer_t e);
  void              (*update)(eventer_t e, int newmask);
  eventer_t         (*remove_fd)(int fd);
  eventer_t         (*find_fd)(int fd);
  void              (*trigger)(eventer_t e, int mask);
  int               (*loop)(int id);
  void              (*foreach_fdevent)(void (*f)(eventer_t, void *), void *);
  void              (*wakeup)(eventer_t);
  void             *(*alloc_spec)(void);
  struct timeval    max_sleeptime;
  int               maxfds;
  struct {
    eventer_t e;
    pthread_t executor;
    ck_spinlock_t lock;
  }                 *master_fds;
} *eventer_impl_t;

extern eventer_impl_t __eventer;
extern mtev_log_stream_t eventer_err;
extern mtev_log_stream_t eventer_deb;

API_EXPORT(int) eventer_choose(const char *name);

/*! \fn void eventer_loop()
    \brief Start the event loop.
    \return N/A (does not return)

    This function should be called as that last thing in your `child_main` function.
    See [`mtev_main`](c.md#mtevmain`).
*/
API_EXPORT(void) eventer_loop(void);

/*! \fn void eventer_loop_return()
    \brief Start the event loop and return control to the caller.

    This function should be called as that last thing in your `child_main` function.
    Be sure not to return or exit after calling this as it could terminate your program.
    See [`mtev_main`](c.md#mtevmain`).
*/
API_EXPORT(void) eventer_loop_return(void);

/*! \fn int eventer_is_loop(pthread_t tid)
    \brief Determine if a thread is participating in the eventer loop.
    \param tid a thread
    \return 0 if the specified thread lives outside the eventer loop; 1 otherwise.
*/
API_EXPORT(int) eventer_is_loop(pthread_t tid);

/*! \fn mtev_boolean eventer_in_loop(void)
    \brief Determine if the current thread is an event loop thread.
    \return mtev_true if currently in an event loop thread, mtev_false otherwise.
*/
API_EXPORT(mtev_boolean) eventer_in_loop(void);

/*! \fn int eventer_loop_concurrency()
    \brief Determine the concurrency of the default eventer loop.
    \return number of threads used for the default eventer loop.
*/
API_EXPORT(int) eventer_loop_concurrency(void);

/*! \fn void eventer_init_globals()
    \brief Initialize global structures required for eventer operation.

    This function is called by [`mtev_main`](c.md#mtevmain).  Developers should not
    need to call this function directly.
*/
API_EXPORT(void) eventer_init_globals(void);

#define eventer_propset       __eventer->propset
#define eventer_init          __eventer->init

/*! \fn void eventer_add(eventer_t e)
    \brief Add an event object to the eventer system.
    \param e an event object to add.
*/
#define eventer_add           __eventer->add

/*! \fn eventer_t eventer_remove(eventer_t e)
    \brief Remove an event object from the eventer system.
    \param e an event object to add.
    \return the event object removed if found; NULL if not found.
*/
#define eventer_remove        __eventer->remove

/*! \fn void eventer_update(evneter_t e, int mask)
    \brief Change the activity mask for file descriptor events.
    \param e an event object
    \param mask a new mask that is some bitwise or of `EVENTER_READ`, `EVENTER_WRITE`, and `EVENTER_EXCEPTION`
*/
#define eventer_update        __eventer->update

/*! \fn void void eventer_update_whence(eventer_t e, struct timeval whence)
    \brief Change the time at which a registered timer event should fire.
    \param e an event object
    \param whence an absolute time.
*/
void eventer_update_whence(eventer_t e, struct timeval w);

/*! \fn eventer_t eventer_remove_fd(int e)
    \brief Remove an event object from the eventer system by file descriptor.
    \param fd a file descriptor
    \return the event object removed if found; NULL if not found.
*/
#define eventer_remove_fd     __eventer->remove_fd

/*! \fn eventer_t eventer_find_fd(int e)
    \brief Find an event object in the eventer system by file descriptor.
    \param fd a file descriptor
    \return the event object if it exists; NULL if not found.
*/
#define eventer_find_fd       __eventer->find_fd

/*! \fn void eventer_trigger(eventer_t e, int mask)
    \brief Trigger an unregistered eventer and incorporate the outcome into the eventer.
    \param e an event object that is not registered with the eventer.
    \param mask the mask to be used when invoking the event's callback.

    This is often used to "start back up" an event that has been removed from the
    eventer for any reason.
*/
#define eventer_trigger       __eventer->trigger

#define eventer_max_sleeptime __eventer->max_sleeptime

/*! \fn void eventer_foreach_fdevent(void (*fn)(eventer_t, void *), void *closure)
    \brief Run a user-provided function over all registered file descriptor events.
    \param fn a function to be called with each event and `closure` as its arguments.
    \param closure the second argument to be passed to `fn`.
*/
#define eventer_foreach_fdevent  __eventer->foreach_fdevent

/*! \fn void eventer_wakeup(eventer_t e)
    \brief Signal up an event loop manually.
    \param e an event

    The event `e` is used to determine which thread of the eventer loop to wake up.
    If `e` is `NULL` the first thread in the default eventer loop is signalled. The
    eventer loop can wake up on timed events, asynchronous job completions and 
    file descriptor activity.  If, for an external reason, one needs to wake up
    a looping thread, this call is used.
*/
#define eventer_wakeup        __eventer->wakeup

extern eventer_impl_t registered_eventers[];

#define eventer_hrtime_t mtev_hrtime_t
#define eventer_gethrtime mtev_gethrtime

#include "eventer/eventer_jobq.h"

API_EXPORT(int) eventer_boot_ctor(void);
API_EXPORT(eventer_jobq_t *) eventer_default_backq(eventer_t);

/*! \fn int eventer_impl_propset(const char *key, const char *value)
    \brief Set properties for the event loop.
    \param key the property
    \param value the property's value.
    \return 0 on success, -1 otherwise.

    Sets propoerties within the eventer. That can only be called prior
    to [`eventer_init`](c.md#eventerinit). See [Eventer configuuration)(../config/eventer.md)
    for valid properties.
*/
API_EXPORT(int) eventer_impl_propset(const char *key, const char *value);

/*! \fn int eventer_impl_setrlimit()
    \brief Attempt to set the rlimit on allowable open files.
    \return the limit of the number of open files.

    The target is the `rlim_nofiles` eventer config option. If that configuration
    option is unspecified, 1048576 is used.
*/
API_EXPORT(int) eventer_impl_setrlimit(void);

/*! \fn void eventer_add_asynch(eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue.
    \param q a job queue
    \param e an event object

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.
*/
API_EXPORT(void) eventer_add_asynch(eventer_jobq_t *q, eventer_t e);

/*! \fn void eventer_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.
*/
API_EXPORT(void) eventer_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn void eventer_add_asynch_dep(eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue dependent on the current job.
    \param q a job queue
    \param e an event object

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(void) eventer_add_asynch_dep(eventer_jobq_t *q, eventer_t e);

/*! \fn void eventer_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(void) eventer_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn mtev_boolean eventer_try_add_asynch(eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue.
    \param q a job queue
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.
*/
API_EXPORT(mtev_boolean) eventer_try_add_asynch(eventer_jobq_t *q, eventer_t e);

/*! \fn mtev_boolean eventer_try_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.
*/
API_EXPORT(mtev_boolean) eventer_try_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn mtev_boolean eventer_try_add_asynch_dep(eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue dependent on the current job.
    \param q a job queue
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(mtev_boolean) eventer_try_add_asynch_dep(eventer_jobq_t *q, eventer_t e);

/*! \fn mtev_boolean eventer_try_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(mtev_boolean) eventer_try_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn eventer_aco_gate_t eventer_aco_gate(void)
    \brief Create a new asynchronous gate.
*/
API_EXPORT(eventer_aco_gate_t) eventer_aco_gate(void);

/*! \fn void eventer_aco_gate_wait(eventer_aco_gate_t gate)
    \brief Wait for any asynchronous work on this gate to finish.
    \param gate an asynchronous gate
*/
API_EXPORT(void) eventer_aco_gate_wait(eventer_aco_gate_t gate);

/*! \fn mtev_boolean eventer_aco_try_run_asynch_queue_subqueue(eventer_aco_gate_t gate, eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and signal the gate on completion.
    \param gate the gate to signal
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(mtev_boolean) eventer_aco_try_run_asynch_queue_subqueue_gated(eventer_aco_gate_t, eventer_jobq_t *q, eventer_t e, uint64_t id);
#define eventer_aco_try_run_asynch_queue_gated(q,e) eventer_aco_try_run_asynch_queue_subqueue_gated(g,q,e,0)
#define eventer_aco_try_run_asynch_gated(e) eventer_aco_try_run_asynch_queue_subqueue_gated(g,NULL,e,0)

/*! \fn mtev_boolean eventer_aco_try_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(mtev_boolean) eventer_aco_try_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);
#define eventer_aco_try_run_asynch_queue(q,e) eventer_aco_try_run_asynch_queue_subqueue(q,e,0)
#define eventer_aco_try_run_asynch(e) eventer_aco_try_run_asynch_queue_subqueue(NULL,e,0)

/*! \fn mtev_boolean eventer_aco_run_asynch_queue_subqueue_gated(eventer_aco_gate_t gate, eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and signal gate on completion.
    \param gate a gate
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(void) eventer_aco_run_asynch_queue_subqueue_gated(eventer_aco_gate_t, eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn mtev_boolean eventer_aco_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.
    \param q a job queue
    \param e an event object
    \param id is a fairly competing subqueue identifier
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
API_EXPORT(void) eventer_aco_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id);

/*! \fn mtev_boolean eventer_aco_run_asynch_queue_gated(eventer_aco_gate_t gate, eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and signal gate on completion.
    \param gate a gate
    \param q a job queue
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
#define eventer_aco_run_asynch_queue_gated(g,q,e) eventer_aco_run_asynch_queue_subqueue_gated(g,q,e,0)

/*! \fn mtev_boolean eventer_aco_run_asynch_queue(eventer_jobq_t *q, eventer_t e)
    \brief Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.
    \param q a job queue
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the job queue `q`.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
#define eventer_aco_run_asynch_queue(q,e) eventer_aco_run_asynch_queue_subqueue(q,e,0)

/*! \fn mtev_boolean eventer_aco_run_asynch_gated(eventer_aco_gate_t gate, eventer_t e)
    \brief Add an asynchronous event dependent on the current job and signal gate on completion.
    \param gate a gate
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the default job queue.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
#define eventer_aco_run_asynch_gated(g,e) eventer_aco_run_asynch_queue_subqueue_gated(g,NULL,e,0)

/*! \fn mtev_boolean eventer_aco_run_asynch(eventer_t e)
    \brief Add an asynchronous event dependent on the current job and wait until completion.
    \param e an event object
    \return `mtev_false` if over max backlog, caller must clean event.

    This adds the `e` event to the default job queue.  `e` must have a mask
    of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
    during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
    of the currently executing job.
*/
#define eventer_aco_run_asynch(e) eventer_aco_run_asynch_queue_subqueue(NULL,e,0)

/*! \fn void eventer_aco_asynch_queue_subqueue_deadline_gated(eventer_aco_gate_t gate, eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id, struct timeval *whence)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
    \param whence the deadline
*/
API_EXPORT(void) eventer_aco_asynch_queue_subqueue_deadline_gated(eventer_aco_gate_t gate, eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id, struct timeval *whence);

/*! \fn void eventer_aco_asynch_queue_subqueue_deadline(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id, struct timeval *whence)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
    \param whence the deadline
*/
API_EXPORT(void) eventer_aco_asynch_queue_subqueue_deadline(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id, struct timeval *whence);

/*! \fn void eventer_aco_asynch_queue_subqueue_gated(eventer_aco_gate_t gate, eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
*/
#define eventer_aco_asynch_queue_subqueue_gated(g,f,c,q) eventer_aco_asynch_queue_subqueue_deadline_gated(g,f,c,q,0,NULL)

/*! \fn void eventer_aco_asynch_queue_subqueue(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
*/
#define eventer_aco_asynch_queue_subqueue(f,c,q) eventer_aco_asynch_queue_subqueue_deadline(f,c,q,0,NULL)

/*! \fn void eventer_aco_asynch_queue_gated(eventer_aco_gate_t gate, eventer_asynch_func_t func, void *closure, eventer_jobq_t *q)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
*/
#define eventer_aco_asynch_queue_gated(g,f,c,q) eventer_aco_asynch_queue_subqueue_deadline_gated(g,f,c,q,0,NULL)

/*! \fn void eventer_aco_asynch_queue(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
*/
#define eventer_aco_asynch_queue(f,c,q) eventer_aco_asynch_queue_subqueue_deadline(f,c,q,0,NULL)

/*! \fn void eventer_aco_asynch_gated(eventer_aco_gate_t gate, eventer_asynch_func_t func, void *closure)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
*/
#define eventer_aco_asynch_gated(g,f,c) eventer_aco_asynch_queue_subqueue_deadline_gated(g,f,c,NULL,0,NULL)

/*! \fn void eventer_aco_asynch(eventer_asynch_func_t func, void *closure)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
*/
#define eventer_aco_asynch(f,c) eventer_aco_asynch_queue_subqueue_deadline(f,c,NULL,0,NULL)

/*! \fn void eventer_aco_simple_asynch_queue_subqueue_gated(eventer_aco_gate_t gate, eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q, uint64_t id)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
*/
API_EXPORT(void) eventer_aco_simple_asynch_queue_subqueue_gated(eventer_aco_gate_t gate, eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q, uint64_t id);

/*! \fn void eventer_aco_simple_asynch_queue_subqueue(eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q, uint64_t id)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
    \param id the subqueue within the jobq.
*/
API_EXPORT(void) eventer_aco_simple_asynch_queue_subqueue(eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q, uint64_t id);

/*! \fn void eventer_aco_simple_asynch_queue_gated(eventer_aco_gate_t gate, eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
*/
#define eventer_aco_simple_asynch_queue_gated(g,f,c,q) eventer_aco_simple_asynch_queue_subqueue_gated(g,f,c,q,0)

/*! \fn void eventer_aco_simple_asynch_queue(eventer_asynch_simple_func_t func, void *closure, eventer_jobq_t *q)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
    \param q the jobq on which to schedule the work.
*/
#define eventer_aco_simple_asynch_queue(f,c,q) eventer_aco_simple_asynch_queue_subqueue(f,c,q,0)

/*! \fn void eventer_aco_simple_asynch_gated(eventer_aco_gate_t gate, eventer_asynch_simple_func_t func, void *closure)
    \brief Asynchronously execute a function.
    \param gate a gate to notify on completion.
    \param func the function to execute.
    \param closure the closure for the function.
*/
#define eventer_aco_simple_asynch_gated(g,f,c) eventer_aco_simple_asynch_queue_subqueue_gated(g,f,c,NULL,0)

/*! \fn void eventer_aco_simple_asynch(eventer_asynch_simple_func_t func, void *closure)
    \brief Asynchronously execute a function.
    \param func the function to execute.
    \param closure the closure for the function.
*/
#define eventer_aco_simple_asynch(f,c) eventer_aco_simple_asynch_queue_subqueue(f,c,NULL,0)

/*! \fn void eventer_aco_free(eventer_aco_t e)
    \brief Dereferences the event specified.
    \param e the event to dereference.
*/
API_EXPORT(void)      eventer_aco_free(eventer_aco_t);


/*! \fn void eventer_add_timed(eventer_t e)
    \brief Add a timed event to the eventer system.
    \param e an event object

    This adds the `e` event to the eventer. `e` must have a mask of
    `EVENTER_TIMED`.
*/
API_EXPORT(void) eventer_add_timed(eventer_t e);

/*! \fn eventer_t eventer_remove_timed(eventer_t e)
    \brief Remove a timed event from the eventer.
    \param e an event object (mask must be `EVENTER_TIMED`).
    \return the event removed, NULL if not found.
*/
API_EXPORT(eventer_t) eventer_remove_timed(eventer_t e);

/*! \fn eventer_t eventer_remove_timed(eventer_t e)
    \brief Remove a timed event from the eventer.
    \param e an event object (mask must be `EVENTER_TIMED`).
    \return the event removed, NULL if not found.
*/

/*! \fn void eventer_foreach_timedevent(void (*fn)(eventer_t, void *), void *closure)
    \brief Run a user-provided function over all registered timed events.
    \param fn a function to be called with each event and `closure` as its arguments.
    \param closure the second argument to be passed to `fn`.
*/
API_EXPORT(void)
  eventer_foreach_timedevent (void (*f)(eventer_t e, void *), void *closure);

/*! \fn void eventer_add_recurrent(eventer_t e)
    \brief Add an event to run during every loop cycle.
    \param e an event object

    `e` must have a mask of EVENER_RECURRENT.  This event will be invoked on
    a single thread (dictated by `e`) once for each pass through the eventer loop.
    This happens _often_, so do light work.
*/
API_EXPORT(void) eventer_add_recurrent(eventer_t e);

/*! \fn eventer_t eventer_remove_recurrent(eventer_t e)
    \brief Remove a recurrent event from the eventer.
    \param e an event object.
    \return The event removed (`== e`); NULL if not found.
*/
API_EXPORT(eventer_t) eventer_remove_recurrent(eventer_t e);

/*! \fn int eventer_get_epoch(struct timeval *epoch)
    \brief Find the start time of the eventer loop.
    \param epoch a point to a `struct timeval` to fill out.
    \return 0 on success; -1 on failure (eventer loop not started).
*/
API_EXPORT(int) eventer_get_epoch(struct timeval *epoch);

/*! \fn eventer_pool_t *eventer_pool(const char *name)
    \brief Find an eventer pool by name.
    \param name the name of an eventer pool.
    \return an `eventer_pool_t *` by the given name, or NULL.
*/
API_EXPORT(eventer_pool_t *) eventer_pool(const char *name);

/*! \fn eventer_pool_t *eventer_get_pool_for_event(eventer_t e)
    \brief Determin which eventer pool owns a given event.
    \param e an event object.
    \return the `eventer_pool_t` to which the event is scheduled.
*/
API_EXPORT(eventer_pool_t *) eventer_get_pool_for_event(eventer_t);

/*! \fn const char *eventer_pool_name(eventer_pool_t *pool)
    \brief Retrieve the name of an eventer pool.
    \param pool an eventer pool.
    \return the name of the eventer pool.
*/
API_EXPORT(const char *) eventer_pool_name(eventer_pool_t *);

/*! \fn uint32_t eventer_pool_concurrency(eventer_pool_t *pool)
    \brief Retrieve the concurrency of an eventer pool.
    \param pool an eventer pool.
    \return the number of threads powering the specified pool.
*/
API_EXPORT(uint32_t) eventer_pool_concurrency(eventer_pool_t *);

/*! \fn void eventer_pool_watchdog_timeout(eventer_pool_t *pool, double timeout)
    \brief Set a custom watchdog timeout for threads in an eventer pool.
    \param pool an eventer pool
    \param timeout the deadman timer in seconds.
*/
API_EXPORT(void) eventer_pool_watchdog_timeout(eventer_pool_t *pool, double timeout);

/*! \fn double eventer_watchdog_timeout(void)
    \brief Return the current watchdog timeout on this thread.
    \return A timeout in seconds, 0.0 if none configured.
*/
API_EXPORT(double) eventer_watchdog_timeout(void);

/*! \fn mtev_boolean eventer_watchdog_timeout_timeval(struct timeval *dur)
    \brief Return the current watchdog timeout on this thread.
    \param dur the timeval structure to populate with the timeout.
    \return mtev_true if a timeout is set, mtev_false otherwise.
*/
API_EXPORT(mtev_boolean) eventer_watchdog_timeout_timeval(struct timeval *);

/*! \fn pthread_t eventer_choose_owner(int n)
    \brief Find a thread in the default eventer pool.
    \param n an integer.
    \return a pthread_t of an eventer loop thread in the default eventer pool.

    This return the first thread when 0 is passed as an argument.  All non-zero arguments
    are spread across the remaining threads (if existent) as `n` modulo one less than
    the concurrency of the default event pool.

    This is done because many systems aren't thread safe and can only schedule their
    work on a single thread (thread 1). By spreading all thread-safe workloads across
    the remaining threads we reduce potential overloading of the "main" thread.

    To assign an event to a thread, use the result of this function to assign:
    `e->thr_owner`.
*/
API_EXPORT(pthread_t) eventer_choose_owner(int);

/*! \fn pthread_t eventer_choose_owner_pool(eventer_pool_t *pool, int n)
    \brief Find a thread in a specific eventer pool.
    \param pool an eventer pool.
    \param n an integer.
    \return a pthread_t of an eventer loop thread in the specified evneter pool.

    This function chooses a thread within the specified pool by taking `n`
    modulo the concurrency of the pool.  If the default pool is speicified, special
    assignment behavior applies. See [`eventer_choose_owner`](c.md#eventerchooseowner).

    To assign an event to a thread, use the result of this function to assign:
    `e->thr_owner`.
*/
API_EXPORT(pthread_t) eventer_choose_owner_pool(eventer_pool_t *pool, int);

/* Helpers to schedule timed events */
/*! \fn eventer_t eventer_at(eventer_func_t func, void *closure, struct timeval whence)
    \brief Convenience function to create an event to run a callback at a specific time.
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param whence the time at which to run the callback.
    \return an event that has not been added to the eventer.

    > Note this does not actually schedule the event. See [`eventer_add_at`](c.md#eventeraddat).
*/
static inline eventer_t
eventer_at(eventer_func_t func, void *cl, struct timeval t) {
  eventer_t e = eventer_alloc_timer(func, cl, &t);
  return e;
}

/*! \fn eventer_t eventer_alloc_timer_next_opportunity(eventer_func_t func, void *closure, pthread_t owner)
    \brief Convenience function to create an event to run a callback on a specific thread.
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param owner the event-loop thread on which to run the callback.
    \return an event that has not been added to the eventer.

    > Note this does not actually schedule the event. See [`eventer_add_timer_next_opportunity`](c.md#eventeraddtimernextopportunity).
*/
static inline eventer_t
eventer_alloc_timer_next_opportunity(eventer_func_t func, void *cl, pthread_t owner) {
  struct timeval t = { 0, 0 };
  eventer_t e = eventer_alloc_timer(func, cl, &t);
  eventer_set_owner(e, owner);
  return e;
}

/*! \fn eventer_t eventer_add_at(eventer_func_t func, void *closure, struct timeval whence)
    \brief Convenience function to schedule a callback at a specific time.
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param whence the time at which to run the callback.
    \return N/A (C Macro).
*/
static inline eventer_t
eventer_add_at(eventer_func_t func, void *cl, struct timeval t) {
  eventer_t e = eventer_at(func,cl,t);
  eventer_add(e);
  return e;
}

/*! \fn eventer_t eventer_add_timer_next_opportunity(eventer_func_t func, void *closure, pthread_t owner)
    \brief Convenience function to schedule a callback to run in a specific event-loop thread.
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param owner the event-loop thread in which to run the callback.
    \return N/A (C Macro).
*/
static inline eventer_t
eventer_add_timer_next_opportunity(eventer_func_t func, void *cl, pthread_t owner) {
  eventer_t e = eventer_alloc_timer_next_opportunity(func,cl,owner);
  eventer_add(e);
  return e;
}

/*! \fn eventer_t eventer_in(eventer_func_t func, void *closure, struct timeval diff)
    \brief Convenience function to create an event to run a callback in the future
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param diff the amount of time to wait before running the callback.
    \return an event that has not been added to the eventer.

    > Note this does not actually schedule the event. See [`eventer_add_in`](c.md#eventeraddin).
*/
static inline eventer_t
eventer_in(eventer_func_t func, void *cl, struct timeval t) {
  struct timeval __now;
  mtev_gettimeofday(&__now, NULL);
  add_timeval(__now, t, &t);
  eventer_t e = eventer_alloc_timer(func, cl, &t);
  return e;
}

/*! \fn eventer_t eventer_add_in(eventer_func_t func, void *closure, struct timeval diff)
    \brief Convenience function to create an event to run a callback in the future
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param diff the amount of time to wait before running the callback.
    \return N/A (C Macro).
*/
static inline eventer_t
eventer_add_in(eventer_func_t func, void *cl, struct timeval t) {
  eventer_t e = eventer_in(func,cl,t);
  eventer_add(e);
  return e;
}

/*! \fn eventer_t eventer_in_s_us(eventer_func_t func, void *closure, unsigned long seconds, unsigned long microseconds)
    \brief Convenience function to create an event to run a callback in the future
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param seconds the number of seconds to wait before running the callback.
    \param microseconds the number of microseconds (in addition to `seconds`) to wait before running the callback.
    \return an event that has not been added to the eventer.

    > Note this does not actually schedule the event. See [`eventer_add_in_s_us`](c.md#eventeraddinsus).
*/
static inline eventer_t
eventer_in_s_us(eventer_func_t func, void *cl, unsigned long s, unsigned long us) {
  struct timeval __now, diff = { (time_t)s, (suseconds_t)us };
  mtev_gettimeofday(&__now, NULL);
  add_timeval(__now, diff, &diff);
  eventer_t e = eventer_alloc_timer(func, cl, &diff);
  return e;
}

/*! \fn eventer_t eventer_add_in_s_us(eventer_func_t func, void *closure, unsigned long seconds, unsigned long microseconds)
    \brief Convenience function to create an event to run a callback in the future
    \param func the callback function to run.
    \param closure the closure to be passed to the callback.
    \param seconds the number of seconds to wait before running the callback.
    \param microseconds the number of microseconds (in addition to `seconds`) to wait before running the callback.
    \return N/A (C Macro).
*/
static inline eventer_t
eventer_add_in_s_us(eventer_func_t func, void *cl, unsigned long s, unsigned long us) {
  eventer_t e = eventer_in_s_us(func,cl,s,us);
  eventer_add(e);
  return e;
}

/* Helpers to set sockets non-blocking / blocking */
/*! \fn int eventer_set_fd_nonblocking(int fd)
    \brief Set a file descriptor into non-blocking mode.
    \param fd a file descriptor
    \return 0 on success, -1 on error (errno set).
*/
API_EXPORT(int) eventer_set_fd_nonblocking(int fd);

/*! \fn int eventer_set_fd_blocking(int fd)
    \brief Set a file descriptor into blocking mode.
    \param fd a file descriptor
    \return 0 on success, -1 on error (errno set).
*/
API_EXPORT(int) eventer_set_fd_blocking(int fd);

/*! \fn int eventer_thread_check(eventer_t e)
    \brief Determine if the calling thread "owns" an event.
    \param e an event object
    \return 0 if `e->thr_owner` is the `pthread_self()`, non-zero otherwise.
*/
API_EXPORT(int) eventer_thread_check(eventer_t);

/*! \fn void eventer_run_in_thread(eventer_t e, int mask)
    \brief Spawns a thread and runs the event until it returns 0.
    \param e an event object
    \param a starting mask for triggering the event.

    This function will remove the event from the eventer and set the socket into blocking mode.
*/
API_EXPORT(void) eventer_run_in_thread(eventer_t, int mask);

/*! \fn eventer_t eventer_get_this_event(void)
    \brief Get the eventer_t (if any) of which we are currently in the callback.
    \return An eventer_t or NULL.
*/
API_EXPORT(eventer_t) eventer_get_this_event(void);

/*! \fn void eventer_aco_start(void (*func)(void), void *closure)
    \brief Start a new aco coroutine to be eventer driven.
    \param func The function to start.
    \param closure The closure to set (available within `func` via `eventer_aco_arg()`)
*/
API_EXPORT(void) eventer_aco_start(void (*func)(void), void *closure);

/*! \fn void eventer_aco_start_stack(void (*func)(void), void *closure, size_t stksz)
    \brief Start a new aco coroutine to be eventer driven.
    \param func The function to start.
    \param closure The closure to set (available within `func` via `eventer_aco_arg()`)
    \param stksz A specified maximum stack size other than the default 32k.
*/
API_EXPORT(void) eventer_aco_start_stack(void (*func)(void), void *closure, size_t stksz);

/*! \fn void * eventer_aco_arg(void)
    \brief Gets the argument used to start an aco coroutine.
    \return The closure parameter that was passed to `eventer_aco_start`.
*/
API_EXPORT(void *) eventer_aco_arg(void);

/* Private */
API_EXPORT(int) eventer_impl_init(void);
API_EXPORT(void *) eventer_get_spec_for_event(eventer_t);
API_EXPORT(int) eventer_cpu_sockets_and_cores(int *sockets, int *cores);

#endif
