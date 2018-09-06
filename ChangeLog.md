# libmtev changes

# 1

## 1.5

### 1.5.x

 * Fix early loop starts cause mtevbusted to detect boot too early.

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
