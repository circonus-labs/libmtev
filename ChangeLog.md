# libmtev changes

# 1

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
