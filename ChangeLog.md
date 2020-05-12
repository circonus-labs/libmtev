# libmtev changes

# 1

## 1.10

 * NPN upgrades could reference a stale context resulting in crashes.

### 1.10.8

 * Add backtrace/ptrace pretty-printers for `mtev_hash_table` and
   `mtev_http*_request` values
 * Fix NPE when freeing a broken SSL context.
 * The `/cluster` PUT endpoint will now synchronously write the configuration
   to storage if the "x-mtev-conf-synch" header is present and set to "1".
 * Add support for aarch64

### 1.10.7

 * Revert a behavior change in jobqs introduced in 1.10.3
 * Further optimize `mtev_log` filtering.

### 1.10.6

 * Logic optimizations and string slices.
 * Logging optimizations: avoid allocations in some cases, and filter prior to
   Flatbuffer serialization.
 * Fix non-string matching in log filtering.
 * Fix short allocation in filter parsing.
 * Expose log volume statistics as metrics in mtev/stats for configured outlets
 * Fix thread naming in fq module.
 * Add `fanout` and `fanout_pool` config options in `fq` module.
 * Assist subroutine name lookups with libunwind (for crash dumps)
 * Change `MTEV_DWARF` to default to 0, enable by setting to non zero value.
 * Add support for environment variable replacement in config values:
   `ENV:fallback:{ENVKEY}`

### 1.10.5 (skipped)

### 1.10.4

 * Fix use-after-free race in `http_observer` module.
 * Allow null strings in `mtev_log` KV metadata.

### 1.10.3

 * Fix metadata reporting in consul module.
 * Add metadata in http logging.
 * Implement filtering logic for log outlets.
 * Update mtevEL to support new types.
 * Require -std=c11 (use of `_Generic`)

### 1.10.2

 * Fix thread-safey issue using XPath within `mtev_conf`.
 * Fix `mtev.uname` on Solaris/Illummos
 * Fix missed http/1 request count increment.
 * Include -lssl in `mtev_lua/mtev.so`

### 1.10.1

 * Don't truncate SSL errors in logs.
 * Add `mtev.get_ipv4` and `mtev.uname` lua functions.
 * Add `mtev.reverse_details` lua function to monitor reverse connections.

### 1.10.0

 * Fix libmtev on FreeBSD. There were some compile issues and the kqueue
   eventer unsafely reused the change vector.
 * Deprecate `mtev_conf_{get,release}_section{,s}` and add
   `_read` and `_write` variants to allow concurrency configuration access.
 * Fix crash when HTTP/2 fails to setup upon connection.
 * Add cross-thread lua support for serialized waitfor/notify.
 * Add jlog log configs: `segment_size` and `precommit`

## 1.9

### 1.9.12

 * Expose counter stats for http[12] requests and responses.
 * Support managed applications (service restarting of arbitrary sidecars)
 * Make dropping privileges a noop instead of an error when the the process
   is already running as the requested user/group.

### 1.9.11

 * Pass the siginfo context into the stacktrace for self-diagnosis.
 * Fix short HTTP/1 payload reads.

### 1.9.10

 * Move eventer SSL debug logging to `debug/eventer/ssl`
 * Fix use-after-free in http logging when HTTP/2 sessions are interrupted.
 * Make the lua subsystem interrupt as it approaches a watchdog timeout.

### 1.9.9

 * If MTEV_DIAGNOSE_CRASH is set to an external tool path, then the
   tool will be invoked on a crash with the faulting thread id and
   process pid (pid only on non-linux).
 * Display source line column numbers in stacktrace (when available) for
   callstack addresses
 * Fix compressed uploads in `rest_get_raw_upload`.
 * `mtev_json_object` ref counting is now atomic.

### 1.9.8

 * Convey the client CN into the rest closure for `http_rest_api` listeners.
 * Support http/2 ALPN upgrades on `http_rest_api` and
   `mtev_wire_rest_api/1.0` listeners.
 * Fix crash in http/2 socket error on `mtev_wire_rest_api/1.0` listeners.
 * Allow reporting failures to curl library when using the mtev_compress
   curl helper.

### 1.9.7

 * Protect against invalid watchdog retry and span settings.
 * Make `mtev_http_rest_register` use the default ACL auth such
   that configured ACL will apply.  This prevents a classic coding
   mistake that produces unsecurable endpoints.

### 1.9.6

 * Improve safety of hooked stack traces.
 * Make http append and flush return false for disconnected clients.
 * Make foreground stacktraces reliably print.
 * Fix cross-thread trigger on closed events.

### 1.9.5

 * Fix issue with logging threads not starting for "file"
   log types when daemonized.

### 1.9.4

 * Fix issue with stderr log failing during daemonization.
 * Update jquery to 3.4.1.

### 1.9.3

 * lua: Fix mtev.timezone():extract(...,"offset") function
 * Adopt aklomp/base64 implementation for better performance.
 * Allow crash stacktraces to be redirected optionally onto
   different log outlet
 * Add file_synch log type
 * Add MTEV_DWARF=0 environment option to suppress dwarf section
   analysis.
 * Allow FD-based log outlets (e.g. stderr) to be asynch and make
   them asynch by default.
 * Add `no_delay` listener option support. Default is `on`.
 * Improve eventer performance (code optimization).
 * Support building and installing a static library: `libmtev.a`

### 1.9.2

 * Fix race in implicit eventer callback naming.
 * Fix zipkin spans to have appropriate callback names.

### 1.9.1

 * Fix http/1 and http/2 issues moving requests into and out
   of ACO mode. (symptom hangs and crashes when mixing
   ACO and non-ACO request service on a single http session).
 * Fix leaks in initial logging setup.
 * Make mtev_heartbeat_timeout return the default heartbeat when
   NULL is passed.

### 1.9.0

 * Add @name and @skipto options for rest ACL rules.
 * Allow CIDR expression as @ip in rest ACL rules.
 * Add zipkin context to flatbuffer logs.
 * Make zipkin work with http2 and ACO.
 * If the app name is unset do not add app:unknown to stats.
 * Fix sign issues in jobq statistics.
 * Add `total_jobs` to jobq statistics.
 * Add a browser cookie-based login mechanism (http_hmac_cookie)
 * Support LIFO ordering on jobqs.
 * Allow EAGAIN in websocket client handshake.
 * Allow service/protocol to be omitted in websocket client creation.
 * Fix malloc in signal handler when logging flatbuffers.
 * Fix watchdog traces on e:default/0, its hearbeat thread was unassigned.

## 1.8

### 1.8.5

 * Fix double free issue in amqp broadcast delivery.
 * Fix lua panic on SunOS when registering a hook that has ffi pointer
   arguments.  These hooks do not work on SunOS due to luajit's issues
   with SunOS' "very high" stack location.

### 1.8.4

 * Add an mtev_console_dispatch hook for controlling terminal interactions.
 * Fix alignment issue in logging related to freeing built flatbuffers.
   This requires a patches flatcc 0.4.3 or 0.5.0 or later.  configure.in
   was updated to enforce this requirement. The bug manifested as a crash
   on large log messages (10s of kilobytes or more).

### 1.8.3

 * Support logging of slow callbacks.  See eventer config docs for more
   details.
 * Allow structured logging via flatbuffers and support variant format
   logging outputs: flatbuffer, and json.
 * Deprececate and disable log dedupping.
 * Fix mpmc ck_fifo in mtev_log to be 16-byte aligned.

### 1.8.2

 * File-based (and stderr) logs now split newlines into separate
   annotated log statements making logs easier to read.
 * Address several crash issues with ACO+eventer interaction:
   * "current" event is now ACO-local in addition to thread-local.
   * http floating is bypassed for http connections in ACO mode.
   * total removal of alloca() from the code base.
 * The stock web UI javascript was fixed to prevent a flurry of queued API
   requests when the application comes back up after an interruption and the
   UI remained active in the browser.

### 1.8.1

 * Change some eventer.h #define mappings into static inline functions.
 * mtev_memmem is a #define to memmem on platforms with working memmem.
 * Elide a function call in the logging path when zipkin spans aren't active.
 * Update the web support to assist displaying clusters.
 * Explicitly name more callbacks in the eventer.
 * The eventer now returns the number of processing units as the number of
   cores as this is what callers were expecting. (people should not run w/
   hyper-threading anyway).
 * Expose a useful coverity model for libmtev.

### 1.8.0

 * Rudimentary support for a lua stack tracer on crashes where luajit
   is in the C stacks (requires the luajit source headers).
 * Make aco_resume not offend the ASAN stack underflow detection.
 * Performance improvements in the eventer (reduced overhead of tracking
   callback latencies).
 * Make lua mtev_hooks auto ffi.cast the arguments for ease of use.
 * Allow compilation without libdwarf.
 * Allow direct builds against OpenSSL 1.1.

## 1.7

### 1.7.3

 * Add mtev_memory_in_cs() to determine if the caller is inside a
   mtev_memory_{begin,end} block.
 * Allow eventer_aco_start from a non-eventer thread (or before eventer_init)
   for convenience. It will schedule delay and run on e:default/0.

### 1.7.2

 * mtev_memory_safe_free now performs just-in-time epoch allocation.

### 1.7.1

 * Set app:<appname> tag on all top-level stats namespaces.
 * Add mtev_thread_setnamef and mtev_thread_getname.
 * Support logging thread names that are set via mtev_thread_ APIs.
 * Fix eventer_is_aco(NULL) to report if the current context is ACO.
 * Make the watchdog more doggedly reap children.
 * Change default behaviour of jobqs to be GC not CS for SMR.
 * Do not make all eventer callbacks an SMR critical section.
 * Use ck_epoch_sections and make ACO use dedicated sections to ensure progress.

### 1.7.0

 * Add generic consul module with dynamic attachments.
 * Cleanup some ABI exposure in the lua modules.
 * Fix issue in auto flushing of http responses when data
   has not yet been sent out. (performance fix)
 * Allow mtev_memory SMR to work along side ACO.
 * Remove implicit mtev_memory_{begin,end} from eventer callbacks.

## 1.6

### 1.6.26

 * Fix payload_complete in the http1 system for Content-Length requests.

### 1.6.25

* http1.c: Fix a bug in chunk encoded uploads.
  This commit fixes a bug, where chunk-sizes were not correctly read, if they happen
  to lie on a buffer boundary. This was affecting uploads which submit a HTTP chunk
  of around 32704 bytes.

* http1.c: Avoid re-allocating buffers, if sufficient space is left.

### 1.6.24

 * Fix race condition in asynchronous eventer_close.

### 1.6.23

 * Fix http/1 upload data with content-length that is either oversized
   or before a pipelined request.
 * Change the http/1 driver to drain inbound data before completing the
   request. This specifically solves issues running behind Google GLB.
 * Make `eventer_close()` asynch and call `shutdown()` before `close()`.

### 1.6.22

 * Add mtev.inet_pton() function to luamtev
 * Add mtev.getaddrinfo() function to luamtev

### 1.6.21

 * Fix issues with aco/http interplay on Illumos (and likely issues
   elsewhere that were undetected).
 * Make `eventer_update_whence` act correctly on "this" event.
 * Make queue maintenance and conf timer functions reuse their events
   for fewer eventer_t alloc/frees.

### 1.6.20

 * Fix several bugs in the eventer, rest and http interaction:
 * Always remove epoll registration when migrating to a new thread.
 * Do not support handoff in the http driver in ACO mode.
 * The ACO driver in mtev_rest should emulate event_trigger as it
   dereferences the event.

### 1.6.19

 * Note errors on asynch http connections so that we can avoid
   subsequeny unnecessary errors (and erroneous access logs).
 * Fix eventer reference tracking for cross-thread triggers.

### 1.6.18

 * Make HTTP/1 flush/flush_asynch automatic.
 * Add HTTP auto-flushing that defaults to a bchain size (~32k).
 * Add `mtev_http_response_auto_flush` to control HTTP auto-flushing.
 * Support idle_timeout on listener accepted sockets.
 * Provide thread-safe access to http append methods.
 * Reference count events during trigger to avoid freeing while in use.
 * Add thread safety fixes to mtev_intern.

### 1.6.17

 * Add preloads configuration option to lua_web/lua_general modules
 * Add mtev_set_app_name and mtev_get_app_name for conf file root discovery.
 * Add foreground `SIGINT`, `SIGQUIT`, and `SIGTERM` signals to call
   plain-old exit().
 * Add `mtev_{set,get}_app_name` functions to help in places where we need the
   config root.
 * Add `mtev_http_request_payload_complete1 to help consumers correctly
   determine if they should stop calling `mtev_http_request_consume_read`.
 * `MTEV_MAYBE` macros will no longer initialize the whole initial buffer,
   only the first element (performance).

### 1.6.16

 * Add /module/lua/xcall.json REST endpoint (for state inspection).
 * Add lua mtev.semaphore().
 * Fix web UI where suppressed tabs would prevernt `mtev-loaded` signal.

### 1.6.15

 * Fix compiler warnings for gcc 7.
 * Fix inverted predicate in configuration property iteration.
 * Add upload bytes to http access log format.

### 1.6.14

 * Add timeout parameter to socket:connect() in lua
 * Fix deadlock caused by eventer_t:close() in lua

### 1.6.13

 * Fix crash (double free) in sending AMQP messages in duplicate.
 * Avoid dwarf scanning in luamtev by default.
 * Add hooks and a module for watching HTTP request servicing.

### 1.6.12

 * Fix crash bug when listener has npn set to "none" explicitly and
   a client tried to upgrade via ALPN.
 * SECURITY: bug fix in http authentication handling where thread fan out
   could short-circuit ACLs with allow.

### 1.6.11

 * Fix bug in http1 driver related to reading chunked encoded payloads.

### 1.6.10

 * mtev_intern pools with extent_size 0 should just malloc/free.
 * Allow hooking of rest handler assignments: `mtev_rest_get_handler`
 * Introduce `mtev_log_has_material_output`.
 * Change N_L_S_ON to respect if the log will ultimately output.

### 1.6.9

 * Change the default jobq memory safeter from `cs` to `gc`.
 * Add symbol extraction APIs to mtev_stacktrace.

### 1.6.8

 * Add statistics for lua VM time and lua GC time.
 * Expose the watchdog timeout as timeval: mtev_watchdog_get_timeout_timeval
 * Expose eventer thread watchdog timeouts: eventer_watchdog_timeout_timeval
 * Adjust max eventer sleeptime to not exceed 1/20 watchdog timeout.
 * Heartbeat the eventer immediately upon event wakeup.
 * Fix UI issue displaying histogram stats (bin compaction).

### 1.6.7

 * Make mtevbusted tests usage of HTTP headers case
   insensitive.

### 1.6.6

 * Revert eventer_t allocation to the default allocator.
 * Add max backlog stat for jobq and display.
 * Add filter for stats in UI.
 * Be more careful when setting jobq concurrency from the console
 * Explicitly name log dedup, amqp, and fq threads
 * Add more NULL safety in amqp connection management
 * Add -skip flag to mtevbusted
 * Fix bug where mtevbusted API helper was forcing Accept: application/json
 * Default the jobq web UI view to hide completely unused jobqs.

### 1.6.5

 * Support tagged metrics via ?format=tagged
 * Ensure xxhash.h is include with XXH_PRIVATE_API
 * Docs fixups
 * mtev_memory: prevent multiple gc_return queue deinit

### 1.6.4

 * Documentation fixes in zipkin module docs.
 * Fix mtev_hooks to be usable with more compiler warning flags.
 * Fix starvation issue in fq module hook polling.

### 1.6.3

 * Fix mtev_intern freelist manipulation bug resulting in leaks and crashes.

### 1.6.2

 * When spawning a child asynch job within an existing asynch job,
   persist the subqueue assignment rather than always making it the first
   subqueue every time. This will help in job scheduling fairness.
 * Expose `EVENTER_ASYNCH_COMPLETE` as a preferred and more descriptive
   literal for the old `EVENTER_ASYNCH` literal.  `EVENTER_ASYNCH` is
   informally deprecated.
 * Add aco support for non-simple asynch work
   (with all three asynch call phases).
 * Add aco support for enqueueing asynch work with deadlines.
 * Add support for eliding asynch work on jobs when a deadline is set
   and no cancellation type is provided. (don't start work when it is
   already past the deadline)
 * Fix fair scheduling of subqueues when there is a single job in flight.
 * Add test for jobs subqueues and deadlines.
 * Add stats exposure for mtev_intern pools, including via the mtev
   console.
 * Change mtev_hash implementation to XXH64 to improve speed.

### 1.6.1

 * Fix bug in mtev.notify/mtev.waitfor where trying to notify from an
   unyieldable context multiple times in a row could cause crashes or hangs.

### 1.6.0

 * Add HTTP/2 support (via libnghttp2).
   * A TLS-enabled listener may disable HTTP/2 upgrade support by setting an
     `npn` value of `none` in the
     [sslconfig](http://circonus-labs.github.io/libmtev/config/listeners.html#sslconfig).
 * Console listeners may now specify an optional `history_file` attribute to
   preserve command history across console sessions.
 * Reduce memory usage in highly concurrent configurations on Linux by limiting
   the number of file descriptors in a given invocation of `epoll_wait`.
 * Fix memory leak in SMR queue during thread shutdown.
 * Make base64 decoding also accept URL alphabet
   ([rfc4648](https://tools.ietf.org/html/rfc4648)).
 * Fix crash in hash to lua table conversion where value is NULL.
 * Provide mtev_intern compaction as a side effect of `mtev_intern_release`
   (this prevents pathological mmap leaks if programmers fail to compact).
 * Fix several http bugs around payload reading.
 * Fix mtev.notify/mtev.waitfor when the notify originates in an unyieldable
   context and a waitfor is pending. (C -> lua -> C -> lua -> mtev.notify)

## 1.5

### 1.5.28

 * Fix failed merge (install target broken).

### 1.5.27

 * Fix mtev_intern memory volatility/ordering issues.

### 1.5.26

 * Fix ACO registry mismanagement causing crashes.
 * Fix leak of `ck_epoch_record` on thread termination.

### 1.5.25

 * Fix hangs in HTTP content upload when clients paused in the middle
   of a block (bug introduced in 1.5.24)

### 1.5.24

 * Fix DNS fast failures in lua could cause null pointer dereference.
 * Fix support for aco-style REST handlers. This bug manifested as failed
   upload support.
 * Fix naming of aco events.  They now report the underlying event.
 * Rearchitect the watchdog timeouts to allow children to cooperate and signal
   into the correct thread so we get a SIGTRAP-induced stack trace from the
   offending thread. (only systems with pthread_sigqueue, like Linux).
 * Articulate in logs and in glider invocation which thread watchdogged.

### 1.5.23

 * Do not block thread exit for SMR, instead disown the return queue and
   allow gc thread to cleanup (this also fixes leaks at thread exit) #465

### 1.5.22

 * Eventer thread naming no longer requires SMR.
 * Fix REST-driven jemalloc heap profiler.

### 1.5.21

 * Fix SMR regression in jobs thread winddown.
 * Code now compiles with -Wextra with clang/gcc.

### 1.5.20

 * Make SSL "connection closed" accept failures a debug message.
 * Remove port from SSL connection failures so they log dedup.
 * Make ncct (telnet console) output thread safe (crash fix).
 * Fix leak of thread name in SMR context.
 * Add `eventer_jobq_memory_safety_name()` function.
 * Add reporting on SMR activity.
 * Avoid unnecessary epoch synchronization (SMR), when there is no work to do.

### 1.5.19

 * Fix livelock in mtev_intern when racing for a removed object
 * Make the SMR cleanup in thread termination asynch (fix CPU burn)

### 1.5.18

 * Move SMR maintenance into the eventer (out of a callback)

### 1.5.17

 * Fix off-by-on error in lua\_web lua stack management (crash fix).
 * Lua: Add `printf()`, `errorf()` functions.
 * Improve `Api.lua` error reporting, accept 2xx return codes.

### 1.5.16

 * Apply lua GC on next tick and not inline.
 * Make "cs" the default jobq memory safety level.

### 1.5.15

 * Make `mtev_memory_{begin,end}` recursively safe.
 * Use asynch barrier SMR in jobqs.
 * Avoid clipping last letter off long log lines.

### 1.5.14

 * Fix improper calculation of required space in base64 encode/decode that
   could allow two bytes of overrun in decoding into a "too small" buffer.
 * Documentation fixes.
 * Implement mtevStartupTerminate and mtevTerminate

### 1.5.13

 * Have luamtev use a default pool concurrency of 1, add -n option.
 * `mtev_intern_release` will release to the originating pool.
 * mi{STR,STRL,PTR,PTRL,NEW,NEWL,COPY,FREE} macros added for ease-of-use
 * Change the default build to use `DT_RUNPATH` over `DT_RPATH` where applicable.
 * Disable log dedup in luamtev by default.
 * Add `SO_REUSEPORT` to lua setsockopt if available.

### 1.5.12

 * Be extra precautious when shutting down the last thread in a pool to make sure
   there is no backlog.
 * Fix header to expose `eventer_jobq_set_floor` correctly.
 * Expose more controls for jobq mutation via console.

### 1.5.11

 * Fix tagged release version extraction.
 * Fix infinite loop when logging oversized log entries introduced in 1.5.8

### 1.5.10

 * Fix unsafe fork (fork while resize\_lock held) in logging subsystem.

### 1.5.9

 * Revert changes to child.lua in mtevbusted - they were causing
   issues resulting in test failures.

### 1.5.8

 * Fix libslz's trailing byte problem and integrate it.
 * `mtev_intern` implementation for share strings and byte buffers.
 * Implement log dedupping `dedup_seconds` configuration option.
 * Watchdog config option to disable saving of glider stdout, useful in cases
   where the glider produces its own output files.
 * Add lua classes mtev.Proc / mtev.Api
 * Add lua functions `mtev.time`, `mtev.exec`, `mtev.sh`
 * Document mtev.xml\* functionality.

### 1.5.7

 * Revert "Adopt libslz's faster gzip/deflate encoding". The
   behavior was not consistent with the previous implementation.

### 1.5.6

 * Introduce `mtev_watchdog_disable_asynch_core_dump()`

### 1.5.5

 * Fix early loop starts cause mtevbusted to detect boot too early.
 * Add the libluajit default path/cpath to luamtev by default

### 1.5.4

 * Revert "Do not start eventer threads before `eventer_loop`". It caused more
   problems than it solved.
 * Don't gate startup of event loops.
 * Fix a leak of per-thread Lua closure structs.

### 1.5.3

 * Fix asynchronous memory reclamation.
 * Do not start eventer threads before `eventer_loop`.
 * Protect against attempting to close invalid file descriptors.
 * Do proper cleanup of eventer objects, even if not registered. This bug was
   introduced in 1.5.0 with the lua GC race fix.
 * Fix internal accounting stats for eventer allocations.

### 1.5.2

 * Fix `gc_full=1` to fire on every invocation as documented.

### 1.5.1

 * Fix a bug where we were not always closing the socket/connection
   in `lua_web_resume` - could cause connections to hang.
 * Fix a lock contention issue that occurred at startup.
 * Fix a memory leak in the lua path.
 * Fix some clean targets in the Makefile that were inadequate.
 * Move some logging from error log to debug log.

### 1.5.0

 * Make `mtev_hash_merge_as_dict` safe for NULL values.
 * Fix reported memory leak in DWARF reading.
 * Fix race conditions in freeing `mtev_websocket_client_t`.
 * Fix race in lua state (mtev lua coroutine) GC.
 * Remove local callback latency tracking.
 * Add per-pool callback latency tracking.
 * Skip epoch reclamation in threads that have never freed anything.
 * Always do asynchronous barrier epoch collection from the eventloop.
 * Batch asynchronous epoch reclamation to reduce epoch synching.
 * Fix lua/ssl\_upgrade eventer actuation.
 * Add granular lua garbage collection configuration.
   default: step 1000 time before a full collect.
 * Monitor process now passes TERM, QUIT, and INT signals to child.

## 1.4

### 1.4.6

 * Fix `mtev.shared_seq()` producing duplicate keys during startup.
 * Add `mtev_cluster_node_get_idx` to get a node's deterministic offset in a
   cluster topology.

### 1.4.5

 * Back off aggressive SSL context stance in 1.4.2, Just use v23 by default.
 * Change default event loop's main thread (thread 0) to run separate from the
   main application thread.
 * Add `eventer_loop_return()` which return control to the main thread.
 * Add `mtev_boolean eventer_in_loop()` as a near-zero cost boolean call
   (compared to `int eventer_is_loop()` which returns the internal ID or -1)
 * Postpone non-primary thread event loops start until `eventer_loop` is called.

### 1.4.4

 * Fix bug in `mtev_conf_env_off` lock releasing.
 * Expose `mtev_backtrace` as a portable backtrace.

### 1.4.3

 * Fix bug in tls sni name extraction. (double-free)

### 1.4.2

 * Change SSL behaviour to default to TLSv1.2, TLSv1.1 and then SSLv23 based
   on availability as the default.
 * Support retrieving the client-provided SNI name in the eventer:
   `eventer_ssl_get_sni_name` and `mtev.ssl_ctx:sni_name()`
 * Fix overflow/underflow in `eventer_find_fd` with wild fds (like -1).
 * Fix bug in matching environmental config exclusions with a failed getenv()

### 1.4.1

 * Implement optional DWARF filtering to skip certain files.
 * No need for recursion in DWARF processing to get source line info.
 * Implement DWARF map loading on illumos.
 * Fix possible uninitialized variable usage in net-heartbeat address handling.
 * Expose additional reverse-connection-related probes even when DTrace is not
   in use.

### 1.4.0

 * New `eventer_aco_*` functions that provide [Arkenstone Co-Routines](https://github.com/hnes/libaco)
   (ACO) which allow for writing asynchronous code in a seemingly blocking
   manner. See the [Eventer (ACO)](http://circonus-labs.github.io/libmtev/development/eventer-aco.html)
   documentation for details.
 * New Lua function `mtev.shared_seq()` for retrieving a global sequence
   number.
 * If libunwind and/or libdwarf are available, stack traces will be more
   informative.

## 1.3

### 1.3.5
 * Add lua `mtev.eventer:{sock,peer}_name()`.
 * Add `mtev_lfu_iterate`.
 * Fix null pointer dereference in lua event cleanup.
 * More documentation.

### 1.3.4
 * Add luamtev `mtev.timeval:seconds()` method.
 * Add luamtev examples.
 * Crash fix for Zipkin thread annotations.

### 1.3.3
 * Deprecate built-in atomics in favor of ConcurrencyKit.
 * Support naming threads, add names for some common threads.

### 1.3.2
 * Implement required subset of `mtev_uuid_*` functions and remove libuuid
   dependency.
 * Applications must explicitly include and link libuuid if they want to use
   it.

### 1.3.1
 * Fix null termination in `mtev_uuid_unparse_lower`

### 1.3.0
 * Add optimized `mtev_uuid_unparse_lower` function
 * Add buffer-based `mtev_rand` functions
 * Make `strnstrn` and `mtev_memmem` "like Linux" on other platforms
   with respect to the `needle_len == 0` case
 * Eventer `max_backlog` now settable via configuration
 * Add memory safety accessor
 * Add floor for jobqs
 * `ASYNCH_CORE_DUMP=0` should waitpid before launching next child
 * Various Coverity fixes

## 1.2

### 1.2.9
 * Add `mtev_main_eventer_config` (see docs)
 * Expose min/max concurrency in jobq display
 * Deprecate `strnstrn` and expose `mtev_memmem`
 * Deprecate `mtev__strndup` for `mtev_strndup`
 * Fix "none" as an explicity memory safety declaration in eventer jobq configs
 * Support optional `queuename` in `mtev_amqp` module
 * Compile `mtev_str` functions with aggressive optimizations

### 1.2.8
 * Allow control of JIT and optimizations for LuaJIT
 * Add heap profiling with jemalloc
 * Add support for mtev.timezone
 * Change clock timings to be hypervisor friendly

### 1.2.7

 * Add lua functions `mtev.log_enabled()`, `mtev.cluster()`
 * Remove experimental lua functions `mtev.cluster_details()` and
   `mtev.cluster_get_self()`
 * Remove unused function `mtev_conf_correct_namespace()`
 * Add more documentation for `mtev_cluster_*`

### 1.2.6

 * Add Lua code to get the exit code and other flags from return
   value of `waitpid()`
 * Fix some tests that were not working properly
 * Fix some inconsistent behavior with `posix_spawnp` call in lua
   handler between Linux and Solaris


### 1.2.5

 * Fixes bug affecting event reporting via rest

### 1.2.4

 * Fix race in mtev\_lua initialization (#380).
 * Scalability improvements in the UI.
 * Docs: updated build requirements with optional modules.

### 1.2.3

 * Address responsiveness of UI when there are a large number of log lines.
   (#379)
 * Fix for misuse of non-file-descriptor events as file-descriptor events. Apps
   will now crash if they misuse events this way, rather than being allowed to,
   for example, call `eventer_close` on a non-file-descriptor event, which
   would have undefined behavior. (#375)
 * Support for building with GNU libc v2.24+ and GCC 7 (#370)
 * Various mtev\_cluster-related fixes.
 * Fix anchors in Lua code docs.

### 1.2.2

 * Fix bugs causing performance issues with reverse socket
   connections.

### 1.2.1

 * Improve debug messages for reverse sockets.

### 1.2.0

 * No changes, semver bump due to 1.1.3's new eventer calls.

## 1.1

### 1.1.3

 * Add `eventer_jobq` documentation.
 * Add `eventer_jobq_set_max_backlog`.
 * Add "try" variants for the `eventer_add_asynch` calls.

### 1.1.2

 * Fix potential use-after-free in reverse connections. (#317)

### 1.1.1

 * Allow 64bit integers for size-based log rotation parameters.
 * Make `mtev.thread_self` work in lua\_web as it does in lua\_general.
 * Const-ify `mtev_huge_hash` APIs.

### 1.1.0

 * Add new structure, `mtev_huge_hash`, which uses LMDB to provide a
   disk-backed hash table of arbitrary size. If a dependency on LMDB is
   undesirable, one may configure with `--disable-lmdb`.
 * Change SONAME to include just the major version, making future minor-version
   bumps easier.

## 1.0

### 1.0.2

 * Fix use-after-free in Zipkin span publication.
 * Sensibly set a default IP address for Zipkin spans.
 * Protect against crash when tracing is enabled after boot.

### 1.0.1

 * Rework logging within websockets support code.
 * Various documentation fixes and updates.
 * Fixes crash in `lua_web` `mtev.coroutine_spawn`
 * Fixes memory leak in lua `mtev.waitfor`/`mtev.notify`.
 * Fixes memory leak when destroying an eventer jobq.

### 1.0.0

 * 3231 commits from 37 people over 10 years...
