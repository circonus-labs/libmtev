# libmtev changes

# 1

## 1.6

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
