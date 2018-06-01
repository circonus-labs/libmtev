# libmtev changes

# 1

## 1.3

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
