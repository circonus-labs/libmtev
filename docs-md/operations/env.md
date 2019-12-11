## Environment Variables

Other than the interactions environment variables can have on configuration,
there are several standard environment variables that effect the operation of
any libmtev application.

 * ##### EVENTER_DEBUGGING

   If set to 1 it will enable the `debug/eventer` log stream.

 * ##### MTEV_DWARF

   If set to 0, dwarf sections will not be analyzed to make human readable
   stacktraces.

 * ##### MTEV_JIT_OFF

   If set to 1 it will disable the JIT within the lua module.

 * ##### MTEV_JIT_OPT

   If numeric and positive, it be passed numerically to `jit.opt.start` in
   the lua module.

 * ##### MTEV_RDTSC_REQUIRE_INVARIANT

   If set to 0, this will disable the requirement for an invariant rdtsc
   for libmtev's "faster time" support.

 * ##### MTEV_RDTSC_DISABLE

   If set to 1, this will disable libmtev's "faster time" support.

 * ##### MTEV_THREAD_BINDING_DISABLE

   If set to 1, threads created via `mtev_thread` will not be bound to CPUs.

 * ##### MTEV_DIAGNOSE_CRASH

   If set to 0, libmtev's internal crash handling code will not
   be run.  If set to 1, will run libmtev's internal crash handling code.
   If set to a file path for a script or external tool, this will be invoked
   on a crash with the thread id and process pid as parameters (pid only on
   non-linux).  Use a wrapper script with execution rights and sudoers as
   needed to give sudo permissions or additional calling parameters when
   invoking the external tool.

 * ##### MTEV_LOG_DEBUG

   If numeric and non-zero, this turns on debug logging for the logging system.
   This should only be used by developers to debug the logging system itself.
   These logs all go to stderr.

 * ##### MTEV_ASYNCH_CORE_DUMP

   If zero, this disables "asynch core dumps."  It forces the monitor process
   to wait for the child process to leave the process table before attempting
   to restart it upon crash.

 * ##### MTEV_ALTSTACK_SIZE

   A size (in bytes) for the altstack for handling crashes.

 * ##### MTEV_WATCHDOG_TIMEOUT

   A timeout observed by the parent monitor.  If the child process
   does not heartbeat from each thread within this number of seconds,
   the monitor will terminate and restart the child.  Non-integral
   numbers are allowed.
