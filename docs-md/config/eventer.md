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
   of the default event loop and sets the default of any non-default event loops.
   If not specified, the library will attempt to make a reasonable guess as to
   a good concurrency level based on the number of CPU cores in the system.

 * ##### loop_&lt;name&gt;

   This establishes a new named event loop and sets it concurrency to the provided
   value.  If a value of 0 is provided, then the named event loop will use the
   default concurrency specified by the `concurrency` key.

 * ##### jobq_&lt;name&gt;

   This establishes a new named jobq and sets parameters around concurrency
   and memory safety.  The format of the value is:
   `concurrency[,min[,max[,safety]]]`.  Concurrency, min, and max are all
   integers. Concurrency must be greater than zero.  If minimum is omitted or
   zero, no minimum is set.  If max is omitted, it is set to min.  If max is
   zero, there is no maximum.  Safety can be one of `none` (default), `cs`, or
   `gc`.  For more information om memory settings see `mtev_memory.h`.

   > Note that this merely creates the jobq. One must find and use it
   > programmatically within the software.  It is designed to have a code-free
   > way of allowing operators to adjust parameters around jobqs used within
   > an application.

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
