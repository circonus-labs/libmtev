# The Eventer

The eventer is designed to perform micro tasks without the overhead of a
context switch.  The underlying goal is to support millions of "seemingly"
concurrent heavy tasks by modifying the tasks to be reactive to state changes,
make small, non-blocking progress, and yielding control back to the event loop.

Not all work can be done in a non-blocking fashion (e.g. disk reads/writes,
and intense computational work).  For this, the eventer provides work queues
that allow for blocking operations.

Events (`eventer_t`) have a `callback` and a `closure` at their heart.  The
rest of the fields dictate when, why and possibly where the callback will be
invoked with the provided closure.

Event types are dictated by the `mask` set in the `eventer_t` object.
There are four basic event types available for use:

 * [File Descriptor Activity](#file-descriptor-activity)
 * [Recurrent Events](#recurrent-events)
 * [Timed Events](#timed-events)
 * [Asynchronous Events](#asynchronous-events)

### File Descriptor Activity

```c
#define EVENTER_READ             0x01
#define EVENTER_WRITE            0x02
#define EVENTER_EXCEPTION        0x04
```

File descriptor based events ("fd events") can react to any of three conditions (by bitwise OR):

 * `EVENTER_READ` : the availability of data to read
 * `EVENTER_WRITE` : the availability of buffer space so a write may succeed
 * `EVENTER_EXCEPTION` : an error condition has occured on the file descriptor

Note that under most circumstances, the file descriptor should be a socket.  In
typical POSIX systems, these fd events don't fire as expected on files.

The return value of callbacks for fd events represents the new
`mask` that should be used (for subsequent callback invocations).  If 0 is
returned, the event will be removed from the system and `eventer_free` will
be invoked.

#### Operations on the file descriptor

While the `fd` field of the `eventer_t` is a normal file descriptor and normal
POSIX operations can be performed on it (such as read(2), write(2), etc.). These
operations are all abstracted away behind the `eventer_read`, `eventer_write`, etc.
convenience functions.

The opset can be changed to support SSL operations and, in such operations, some
non-blocking operations can require some non-obvious events to make progress.
Namely, an SSL read may fail with `EAGAIN`, but require an `EVENTER_WRITE` event
to continue due to a renegotiation.

```c
static int
my_callback(eventer_t e, int mask, void *closure, struct timeval *now) {
  char buff[1024];
  size_t len;
  int mask = 0;

  len = eventer_read(e, buff, sizeof(buff), &mask);
  if (len < 0) {
    if (errno == EAGAIN) return mask|EVENTER_EXCEPTION;
    eventer_remove_fde(e);
    eventer_close(e, &mask);
    return 0;
  }

  /* use buff */

  return EVENTER_READ|EVENTER_EXCEPTION;
}
```

Order of operations (and other) notes:

  * Always set an fd as non-blocking after creation using `eventer_set_fd_nonblocking(int fd)`

  * Remember that `connect(2)` can block and often sets `errno = EINPROGRESS` and not `EAGAIN`

  * Always remove an fd event from the eventer before closing it.

  * To suspend an fd event (A) while an asynch event (B) is run:
    * In A's callback
      * `eventer_remove_fde(A)`
      * `eventer_ref(A)`
      * pass A as a part of B's closure
      * `eventer_add(B)`
      * `return 0`
    * in B's callback with `mask = EVNETER_ASYNCH_WORK`
      * `eventer_trigger(A, EVENTER_READ|EVENTER_WRITE)`

### Recurrent Events

```c
#define EVENTER_RECURRENT        0x80
```

Recurrent events are registered to run **every** time through an event loop.
Use these with care.  They should be extremely light-weight.

The return value from recurrent events should be `EVENTER_RECURRENT`.

##### recurrent_example.c (snippet)

```c
  eventer_t e = eventer_alloc_recurrent(super_often, NULL;
  eventer_add(e);
```

### Timed Events

```c
#define EVENTER_TIMER            0x08
```

By setting the `mask` to `EVENTER_TIMER` and the `whence` to a desired time,
an event will perform its callback at some point in the future.

The return value of callbacks for timer events should always be 0.

##### timers.c (snippet)

```c
  eventer_t e;
  struct timeval whence;
  mtev_gettimeofday(&whence, NULL);
  whence.tv_sec += 5;
  e = eventer_alloc_timer(something_to_do_in_five_seconds, NULL, &whence);
  eventer_add(e);

  /* equivalent via helpers */
  struct timeval when;
  mtev_gettimeofday(&when, NULL);
  when.tv_sec += 5;
  eventer_add_at(something_to_do_in_five_seconds, NULL, when);

  /* or */
  struct timeval diff = { .tv_sec = 5 };
  eventer_add_in(something_to_do_in_five_seconds, NULL, diff);

  /* or */
  eventer_add_in_s_us(something_to_do_in_five_seconds, NULL, 5, 0);
```

### Asynchronous Events

```c
#define EVENTER_ASYNCH_WORK      0x10
#define EVENTER_ASYNCH_CLEANUP   0x20
#define EVENTER_ASYNCH           (EVENTER_ASYNCH_WORK | EVENTER_ASYNCH_CLEANUP)
```

##### asynch\_example.c

```c
static int
asynch_test(eventer_t e, int mask, void *c, struct timeval *now) {
  mtevL(mtev_error, "thread %p -> %04x\n", pthread_self(), mask);
  return 0;
}

void child_main() {

  ...

  mtevL(mtev_error, "thread %p -> add\n", pthread_self());
  eventer_t e = eventer_alloc_asynch(asynch_test, NULL);
  eventer_add(e);

  eventer_loop();
}
```

##### asynch\_example.c (output)

```
[2016-12-04 12:01:50.216744] [error] thread 0x7fffcf7093c0 -> add
[2016-12-04 12:01:50.216776] [error] thread 0x70000086d000 -> 0010
[2016-12-04 12:01:50.216815] [error] thread 0x70000086d000 -> 0020
[2016-12-04 12:01:50.216863] [error] thread 0x7fffcf7093c0 -> 0030
```

It is important to note the life-cycle of an asynchronous event:

 1. The event is added from some thread A (usually an event loop thread)
 1. A jobq thread B will invoke the `callback` with `mask = EVENTER_ASYNCH_WORK` if `whence` is set and in the future.
 1. Thread B will invoke the `callback` with `mask = EVENTER_ASYNCH_CLEANUP`
 1. The event will return to thread A and `callback` will be invoked with `mask = EVENTER_ASYNCH`

### Choosing Threads

By default new events are created on the "current" event loop thread.  This
has the effect of causing all new connections from a listener to gang on a
single event loop thread.  If an event is added from a non-event-loop thread,
it will be assigned to thread 1.

The `thr_owner` field of the `eventer_t` structure describes which event
loop thread owns the event.  This can be changed using the `eventer_choose_owner_pool`
and `eventer_choose_owner` functions.

To take an event and move it to a random thread within its current eventer pool:

##### move\_event1.c (snippet)

```c
static int
my_acceptor(eventer_t e, int mask, void *c, struct timeval *now) {
  eventer_pool_t *my_pool = eventer_get_pool_for_event(e);
  int newfd, newmask;

  newfd = eventer_accept(e, &addr, &addrlen, &newmask);
  if(newfd < 0) return newmask | EVENTER_EXCEPTION;
  if(eventer_set_fd_nonblocking(newfd)) {
    close(newfd);
    return EVENTER_READ|EVENTER_EXCEPTION;
  }
  int mask = EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION;
  newe = eventer_alloc_fd(my_handler, NULL, newfd, mask);
  eventer_set_owner(newe, eventer_choose_owner_pool(my_pool, rand()));
  eventer_add(newe);

  return EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
}
```

In the above example, a new connection is received and the new event
that is created is assigned to a random thread within the same pool
as the parent (listening) event.

##### move\_event2.c (snippet)

```c
  ...
  if (want_move) {
    eventer_pool_t *my_pool = eventer_get_pool_for_event(e);
    eventer_set_owner(e, eventer_choose_owner_pool(my_pool, rand()));
    return EVENTER_READ|EVENTER_WRITE|EVENTER_EXCEPTION;
  }
```

To switch an event from one thread to another, simply reassign the
`thr_owner` and then return immediately with the desired mask.  The
eventer will reschedule the event on the requested thread.  Be careful
to not ping-pong back and forth without making proress!

### Complex Interactions

