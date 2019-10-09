# Eventer

The libmtev eventer can be configured through a top-level `<eventer>`
configuration block.

```xml
<application>
  <eventer [ implementation="..." ]>
    <key>value</key>
    ...
  </eventer>
</application>
```

The `implementation` attribute is optional and must be supported on  the
platform; it is recommended that one omit this from configurataions.  Valid
values are `epoll`, `kqueue`, and `ports`.

The keys and values supported are:

 * ##### debugging

   If this key is present and the value is anything other than "0", eventer
   debugging facilities will be enabled.  This can be slow and should not be
   used in production.

 * ##### show_loop_callbacks_threshold

   Specify a millsecond threshold for logging of "slow" callbacks in eventer
   loops.  The default is 0 (all are logged), -1 disables logging.  Logging
   is sent to a log stream called `debug/eventer/callbacks/loop/<loopname>`.

 * ##### show_jobq_callbacks_threshold

   Like `show_loop_callbacks_threshold`, but for callbacks run in
   asynchronous job queues. Logging is sent to a log stream called
   `debug/eventer/callbacks/jobq/<queuename>`.

 * ##### rlim_nofiles

   Specified the number of file descriptors desired. libmtev will attempt to up
   the operating system limits to allow the application to open this many
   files.  The specified value must be at least 256.  If not specified, a
   default value of 1048576 will be used.

 * ##### default_queue_threads

   This specified the number of threads that should be used to manage the default
   asynchronous job queue.  If not specified, a value of 10 is used.

 * ##### concurrency

   The number of event loop threads to start.  This effects the concurrency
   of the default event loop and sets the default of any non-default event
   loops.  If not specified or specified as 0, the library will attempt to
   make a reasonable guess as to a good concurrency level based on the number
   of CPU cores in the system.

 * ##### loop_&lt;name&gt;

   This establishes a new named event loop and sets its concurrency and watchdog
   timeout to the provided values. The format is:
   `concurrency[,timeout_in_seconds]`
 
   If a concurrency value of 0 is provided, then the named event loop will use the
   default concurrency specified by the `concurrency` key.  Floating point notation
   can be used to specify subsecond or partial second timeouts.  If unspecified or
   specified as 0, the timeout will default to the global setting (which defaults
   to 5.0 unless overriden by the application).

 * ##### jobq_&lt;name&gt;

   This establishes a new named jobq and sets parameters around concurrency
   and memory safety.  The format of the value is:
   `concurrency[,min[,max[,safety[,backlog[,lifo]]]]]`.  Concurrency, min, max, and backlog are all
   unsigned integers. Concurrency must be greater than zero.  If minimum is omitted or
   zero, no minimum is set.  If max is omitted, it is set to min.  If max is
   zero, there is no maximum.  Safety can be one of `none` , `cs` , or
   `gc` (default).  For more information om memory settings see [eventer_jobq.h](https://github.com/circonus-labs/libmtev/tree/master/src/eventer/eventer_jobq.h) and [mtev_memory.h](https://github.com/circonus-labs/libmtev/tree/master/src/utils/mtev_memory.h). Backlog sets
   the advisory queue length backlog limit for the queue. The `lifo` setting instructs the
   jobq to process event last-in-first-out.  The values for this field is either `lifo` or 
   `fifo`.

   > Note that this merely creates the jobq. One must find and use it
   > programmatically within the software.  It is designed to have a code-free
   > way of allowing operators to adjust parameters around jobqs used within
   > an application.

 * ##### default_jobq_ordering

   Specified if jobqs should, by default, use LIFO or FIFO processing order.  The default
   is FIFO.  The value of this field should either be omitted for the default or one of
   `lifo` and `fifo`.

 * ##### default_ca_chain

   Specified the path to a file containing a PEM encoded set of certificate authorities
   to trust by default.

 * ##### ssl_ctx_cache_expiry

   Sets the default number of seconds after which cached SSL contexts will be released.
   The default is 5 seconds.

 * ##### ssl_dhparam1024_file & ssl_dhparam2048_file

   Sets the filename to cache generated DH params for SSL connections.  If the keys are
   omitted, no cahce will be used and new parameters will (likely needlessly) be
   regenerated during startup.  If specified and empty, DH params will not be generated
   and this be unavailable to the SSL subsystem; this will prevent forward secrecy.
