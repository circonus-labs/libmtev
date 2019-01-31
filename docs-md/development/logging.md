# Logging

Logging within libmtev depends heavily upon [logging configuration](../config/logging.md).

### DTrace

The logging system is instruemented with DTrace, so despite any configuration
settings, an operator can leverage DTrace to sniff logs (regardless of their
outlets or disabled state) using the `libmtev*:::log` probe. See [DTrace
operations](../operations/dtrace.md).

### log\_stream

The C logging API requires directing each log statements to an `mtev_log_stream_t`.  There
are four builtin log stream: `mtev_stderr`, `mtev_error`, `mtev_notice`, and `mtev_debug`.
Their behavior can be modified via configuration or programmatically via the API.

Before using the log system it must be initialized via `mtev_log_init(int debug)`, but `mtev_main`
handles this for you.

#### Startup sequence

Within your `child_main` that is called by `mtev_main`, you should reopen all logs and then
enable rotation (config driven).

```c
  if(mtev_conf_load(config_file) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    exit(2);
  }
  mtev_log_reopen_all();
  mtev_log_go_asynch();
  if(eventer_init() == -1) mtevFatal(mtev_stderr, "Cannot initialize eventer\n");
  mtev_conf_log_init_rotate(APPNAME, mtev_false);
```

Because the watchdog subsystem can restart our process on crash, it is important to always (re)load the
config and reopen all log files immediate inside of `child_main`.  `mtev_log_go_asynch()` is optional and
will make logging operations (aside from type `memory`) asychronous to the calling thread.  This is
important for high-performance systems where writting logs can interfere with latency and throughput objectives.

`mtev_conf_log_init_rotate` tells the configuration system to register maintenance for any logs configured to
have rotation.  It uses the eventer subsystem to performan maintenance and requires the eventer to be initialized
beforehand.

#### Getting a mtev_log_stream_t

```c
static mtev_log_stream_t my_awesome_log;
void some_init_function() {
  my_awesome_log = mtev_log_stream_find("awesome");
}
```

Getting a log stream by name will implicitly create a typeless log_stream with no outlets if no such name
log already exists in the system.

#### Writing to a log

```c
  struct timeval now;
  mtev_gettimeofday(&now, NULL);
  mtevLT(mtev_error, &now, "Avoids the internal mtev_gettimeofday call\n");

  mtevL(my_awesome_log, "My %d %s-style format string.\n", 1, "sprintf");
```

The mtevLT and mtevL "functions" are actually vararg macros.  This is done so that if a log is disabled,
none the arguments are actually evaluated.  If one of the parameters to these macros is an expensive
function call, the call will be elided if the log is disabled.

> Note: writing to a log does not automatically append a line feed.  You almost always want to include
> line feeds in your log lines explicitly.

#### Logging a programming error

```c
  if(disaster_strikes) {
    mtevFatal(mtev_error, "Disaster has struck, I give up.\n");
  }
```

A special macro `mtevFatal(<stream>, <fmt>, ...)` is provided that will take three actions.

  1. `mtev_log_go_synch()` will be called to ensure logging goes synchronous and the subsequent log message will be written.
  2. `mtevL(...)` log the arguments.
  3. `abort()`

### Other logging APIs

##### mtev_log_go_asynch

```c
void mtev_log_go_asynch();
```

All logging operations that can be performed asynchronously will be done asynchronously.

##### mtev_log_go_synch

```c
void mtev_log_go_synch();
```

All logging operations will be performed synchronously with respect to the called upon return of this function.

##### mtev_log_reopen_all

```c
void mtev_log_reopen_all();
```

Reopen all log files.  Log types that do not implement reopen are unaffected.

##### mtev_log_reopen_type

```c
void mtev_log_reopen_type(const char *type);
```

Repoen all log files of the specified type.

##### mtev_log_stream_get_flags

```c
#define MTEV_LOG_STREAM_ENABLED
#define MTEV_LOG_STREAM_DEBUG
#define MTEV_LOG_STREAM_TIMESTAMPS
#define MTEV_LOG_STREAM_FACILITY
int mtev_log_stream_get_flags(mtev_log_stream_t);
```

Retrieve a bitmask of the enabled flags on a stream.

##### mtev_log_stream_set_flags

```c
int mtev_log_stream_set_flags(mtev_log_stream_t, int newmask);
```

Set a bitmask of the enabled flags on a stream, returning the previous mask.

##### mtev_log_stream_get_type

```c
const char *mtev_log_stream_get_type(mtev_log_stream_t);
```

Returns the type of the log stream.

##### mtev_log_stream_get_name

```c
const char *mtev_log_stream_get_name(mtev_log_stream_t);
```

Returns the name of the log stream.

##### mtev_log_stream_get_path

```c
const char *mtev_log_stream_get_path(mtev_log_stream_t);
```

Returns the path of the log stream.

##### mtev_log_stream_set_property

```c
void mtev_log_stream_set_property(mtev_log_stream_t ls,
                                  const char *prop, const char *v);
```

Set an arbitrary property on a log stream.

##### mtev_log_stream_get_property

```c
const char *mtev_log_stream_get_property(mtev_log_stream_t ls,
                                         const char *prop);
```

Retrieve an arbitrary property from a log stream.

### Adding custom logging types

Libmtev ships with three logging types: `memory`, `file`, and `jlog`.  The system is extensible and additional
types can be added.  Those types do not have the benefit of existence checking as the logging is initialized before
dynamic modules are loaded and new logging types are typically added via dynamic modules.  This chicken-and-egg issue
requires us to load log_streams with unknown types and resolve them post-facto.

```c
  typedef struct {
    mtev_boolean supports_async;
    int (*openop)(mtev_log_stream_t);
    int (*reopenop)(mtev_log_stream_t);
    int (*writeop)(mtev_log_stream_t, const struct timeval *whence, const void *, size_t);
    int (*writevop)(mtev_log_stream_t, const struct timeval *whence, const struct iovec *iov, int iovcnt);
    int (*closeop)(mtev_log_stream_t);
    size_t (*sizeop)(mtev_log_stream_t);
    int (*renameop)(mtev_log_stream_t, const char *);
    int (*cullop)(mtev_log_stream_t, int age, ssize_t bytes);
  } logops_t;

  void mtev_register_logops(const char *name, logops_t *ops);
```

By implementing the `logops_t` structure and registering it with a name, you can then delcare `<log>` stanzas with `type` of that name.

The following operations are optional to implement:

 * reopenop
 * writevop
 * sizeop
 * renameop
 * cullop

#### Attaching contexts

Most log implementations require some context to be attached to the `mtev_log_stream_t`.  Two functions are provided to attach and retrieve an arbitrary context to a log_stream. These functions should only be used by those implementing new logging types as the context will be some arbitrary domain-specific struct that is opaque to those outside the implementation.

```c
  void *mtev_log_stream_get_ctx(mtev_log_stream_t);
  void mtev_log_stream_set_ctx(mtev_log_stream_t, void *);
```
