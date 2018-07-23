# The Eventer (ACO)

Non-blocking programming can be a real mind bender.  While using the classic
event system is fast and extremely powerful, it can be difficult to cope
with context.  When there isn't data available and you need to be called
back later, you must track that context yourself through closures and
if you consider complex protocols requiring asynch operations your resulting
state machine can be a monster.

This is where ACO comes in.  ACO stands for Arkenstone Co-routines; see
[libaco](https://github.com/hnes/libaco).  This system provides a novel
cooperative co-routine approach that allows the "call me back later" to
happen in a seemingly blocking coding style.

### How it works.

In order to use ACO, you must start an ACO procedure.  This procedure
runs a function that should not return, but instead call `aco_exit()`.
Within this function, the execution is in the context of a "green thread."

Once in this function, the stack pointer is switched to an alternate
co-routine "shared stack" (one per operating system thread).  Each co-routine on a 
given operating system thread will have a small "save stack".  When the
thread performs an operation that would normally require using a callback
within the classic event system, it yields control back to the event loop.
When an event triggers that would allow this co-routine to continue, it is
resumed.  If the co-routine wasn't the last one on the "shared stack" then
it is swapped in ("shared stack" copied to the current owner's "save stack"
and the resuming thread's "save stack" copied into the "shared stack").

This stack swapping means that a coroutine's "save stack" can be right-sized
and occupy very little space.  The copying can be expensive for larger stacks
so it is also important that you keep your stack usage small.  Turning on
debug logging will report stack sizes of co-routines as they are resumed.
Additionally, your compiler can help you: `-Wstack-size=1024` for example.

Co-routines do not "manage" [asynchronous events](eventer#asynchronous-events),
but can place calls to them.

## Relationship with the classic event system.

You can create and schedule classic events from anywhere in the system
including a co-routine.  Special interactions with events will yield/resume
automatically are performed through the `eventer_aco` family of functions.
Not all classic events make sense to interact with.

 * Recurrent events have no meaning in co-routines.  Co-routines aren't recurrent.
 * Timed events make little sense in non-callback-oriented coding. `eventer_aco_sleep`
   should be everything you need.
 * Asynchronous events are blocking already, so co-routines make no sense.  However,
   waiting for the completion of an asynchronous event is quite useful. This is
   what the `eventer_aco_simple_asynch` and `eventer_aco_run_asynch` families of
   functions do.
 * File-descriptor-based events are the obvious deep integration.  Each of the
   `eventer_aco_` variants to read, write, accept, and close events have
   optional timeouts as parameters instead of a mask.

If a normal `eventer_read` (or write, etc.) function is called upon an
`eventer_aco_t` object (breaking the type safety), it will be treated as if it
is a call to its `eventer_aco_` counterpart with no timeout.

## Examples

### Starting a simple co-routine

```c
static void my_coroutine(void) {
  struct timeval *sleep_time = eventer_aco_arg();
  while(1) {
    mtev_aco_sleep(sleep_time);
    mtevL(mtev_error, "Waking up to do something\n");
  }
  aco_exit();
}

void calling_function(void) {
  struct timeval *sleep_time = malloc(sizeof(*sleep_time));
  sleep_time->tv_sec = 2;
  sleep_time->tv_usec = 0;
  eventer_aco_start(my_coroutine, sleep_time);
}
```

The `calling_function` can be call any time after `eventer_init()`.  While
the `my_coroutine` function looks blocking, it is actually cooperating with
all classic events and other aco events on the same eventer thread.

### Moving an event to aco

```c
static void my_aco_process(void);

static int
classic_callback(eventer_t e, int mask, void *c, struct timeval *now) {
  // First we must remove the event from the eventer system.
  eventer_remove_fde(e)

  // When we return 0 from this function, the event will be freed,
  // so we need a copy.
  eventer_t copy = eventer_alloc_copy(e);

  // This event needs to be converted to an aco event, but we don't
  // have a coroutine yet.
  eventer_aco_start(my_aco_process, copy);

  return 0;
}

static void
my_aco_process(void) {
  eventer_t classic_e = eventer_aco_arg();

  // We're now in an aco context so we can convert this to an aco event.
  eventer_aco_t e = eventer_set_eventer_aco(classic_e);

  // Use eventer_aco_* functions to interact with e.

  aco_exit();
}
```

### Making an aco listener

The listener subsystem is outfitted to dispatch to aco threads. In this
case, all of the event duplication and conversion is done for you. Simply
register a named function as an aco function with the listener subsystem.

```c
static void listen_to_me(void) {
  eventer_aco_t e = eventer_aco_arg();
  struct timeval tensec = { .tv_sec = 10 };
  while(1) {
    int rv;
    char buff[128];
    rv = eventer_aco_read(e, buff, sizeof(buff), &tensec);
    if(rv == -1) {
      if(errno == ETIME) {
        eventer_aco_write(e, "bye!\n", 5, NULL);
      }
      break;
    }
    if(rv >=4 && !strncasecmp(buff, "quit", 4)) {
      eventer_aco_write(e, "quitter!\n", 9, NULL);
      break;
    }
    if(eventer_aco_write(e, "thanks!\n", 9, NULL) < 0)
      break;
  }

  eventer_aco_close(e);
  eventer_aco_free(e);
  // our caller aco_exit()s, but it won't hurt anything if we do it first
  // aco_exit();
}

static int child_main(void) {
  ...
  eventer_init();
  mtev_listener_register_aco_function("listen_to_me", listen_to_me);
  mtev_listener_init(APPNAME);
  eventer_loop();
  return 0;
}
```

### Using aco with REST

To use aco with REST handlers, simply use `mtev_rest_mountpoint_set_aco`.
The handler has the same signature, but it will be serviced within an aco
co-routine.  This is particularly useful for calling asynch events.  As
the `eventer_aco_simple_asynch` family of functions will run code
asynchronously in a job queue and appear to block until it is complete.


```c
static void asynch_hello(void *closure) {
  mtev_http_rest_closure_t *restc = closure;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  sleep(1);
  mtev_http_response_append_str(ctx, "Hello world.\n");
}

static int
hello_handler(mtev_http_rest_closure_t *restc,
              int npats, char **pats) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_ok(ctx, "text/plain");
  eventer_aco_simple_asynch(asynch_hello, restc);
  mtev_http_response_end(ctx);
  return 0;
}

static int child_main(void) {
  ...
  eventer_init();
  mtev_http_rest_init();
  mtev_listener_init("myapp");
  ...

  mtev_rest_mountpoint_t *rule = mtev_http_rest_new_rule(
    "GET", "/", "^hello$", hello_handler
  );
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  eventer_loop();

}
```
