# Logging

The logging system within libmtev represents a directed acyclic graph of
input-output chains. Each node in the graph has a unique name and is called
a "log_stream." Log_streams without a `type` attribute have output to downstream nodes
("outlets").  Nodes with a `type` attribute havd additional output
characteristics (like outputing to a file).

Upon startup, the system will establish several built-in log_streams, only one of
which has a type.  The "stderr" log_stream has a type of `file` and an output
filedescriptor of 2.  Other log_stream are setup and and configured to have
the "stderr" log_stream as their outlet.  These log_streams are called: "error", "notice",
"debug."  The correspond to the global logging symbols in the C API:
`mtev_stderr`, `mtev_error`, `mtev_notice`, and `mtev_debug`, respectively.
For more information on logging via the API, see the development section
of this documentation relaated to logging.  The "debug" log_stream is
disabled by default.

All logging configuration exists within the toplevel XML node `<logs>`.
Individual log_streams are declared using `<log>` stanzas and outlets are
declared using `<outlet>` stanzas.  A log_stream uses all `<outlet>` stanzas
that are its direct child or direct child of any ancestor node.

##### application.conf

```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<application>
  <logs>
    <log name="internal" type="memory" path="10000,1000000" require_env="MEMLOG"/>
    <log name="logfile" type="file" path="/var/log/app.log"
         rotate_bytes="10000000" retain_bytes="50000000" timestamps="on"/>
    <log name="http/access" type="jlog" path="/var/log/app-http.feed(*)"/>
    <console_output>
      <outlet name="stderr"/>
      <outlet name="internal"/>
      <outlet name="logfile"/>
      <log name="error"/>
    </console_output>
    <components>
      <error>
        <outlet name="error"/>
        <log name="error/example"/>
        <log name="error/sample"/>
      </error>
      <debug>
        <outlet name="debug"/>
        <log name="debug/example" disabled="true"/>
      </debug>
    </components>
  </logs>
</application>
```

Let's walk through this sample file to understand what's going on. First there
are seven `<log>` stanzas establishing log_streams named "internal", "logfile",
"http/access", "error", "error/example", "error/sample", and "debug/example".

Starting at the end, the "debug/example" log_stream is declared in a disabled state
via the `disabled="true"` attribute.  If walk it and its anscestors we find one
`<outlet name="debug"/>` child.  This log_stream has no type, so any messages sent
into this log are only output to its outlet "debug."  You'll notice that no
log_stream named "debug" is declared.  We rely on the built-in "debug" log which
is setup to output to "stderr".  Also, because we did not declare a "debug"
log_stream with `disabled="false"`, the default state remains disabled.

The "error/example" and "error/sample" log_stream are similarly configured to output to the "error"
log_stream as its outlet.  But, we've declared the "error" log_stream in this configuration so that
we can manipulate its outlets.  The `<components>`, `<error>`, and `<debug>`
nodes have no special meaning by name; they are simply used as descriptive
heirarchical containers to allow us to share outlet configuration and to
logically isolate our intentions.

The "error" log_stream already exists as a built-in log_stream.  The declaration here
is used to set outlets to the three log_streams named: "stderr", "internal", and "logfile".
As before, we use an arbitrarily named node to contiain the declaration logically; this
time called `<console_output>`.

The "internal" log_stream is of type `memory` which uses an in-memory ring buffer
to store recent log lines.  We have a limit ot 10000 log lines and 1000000 bytes. It
is also only active if the environment variable INMEM is set.

The "logfile" log_stream is of type `file` and will auto-rotate files as they hit
10 million bytes and delete old log files as the cummulative space consumed
exceeds 50 million bytes.  Timestamps are turned on for this log_stream.

The "http/access" log_stream is of type `jlog` which is create a [Jlog](https://github.com/omniti-labs/jlog)
journaled log for external consumption.

## Generic Attributes

 * ##### require_env

   This optionally requires conditions around an environment variable.  See
   [`require_env`](README.md#requireenv).

 * ##### debug

   If "on"/"true", additional debugging information (like thread ID) is injected into logged lines.

 * ##### facility

   If "on"/"true", the name of the log is injected into logged lines.

 * ##### timestamps

   If "on"/"true", timestamps are injected into logged lines.

 * ##### disabled

   If "on"/"true", the stream is disabled and attempts to log to the facility will result in a single branch instruction.

## Log Types

### memory

The memory log_stream type establishes an internal ring buffer in memory.  There are APIs
(including REST endpoints) to retrieve the contents of this ring buffer.  Additionally,
if the process crashes one can examine the contents of the ring buffer with a debugger.

 * ##### path

   The `path` attribute takes two numbers comma separated.  The first number is the maximum
   number of log lines to be retained.  The second number is the maximum number of bytes
   to be retained.  The implementation will not exceed either limit.

### file

The file log_stream type is used to drive writing to ordinary files using the POSIX
API.  It provides both time-based and size-based retention management capabilities.

 * ##### path

   The path is the filename to which log data should be written.

 * ##### rotate_seconds

   Specifies how many seconds of log data should be written into a file before it is
   moved aside and a new file is started. (used with `retain_seconds` and not with
   `rotate_bytes` or `retain_bytes`).

 * ##### retain_seconds

   Specified the number of seconds of data to be retained.  If all log data in a
   rotated file are older than this value, the file will be removed. (used with
   `rotate_seconds` and not with `rotate_bytes` or `retain_bytes`).

 * ##### rotate_bytes

   Specifies how many bytes of log data should be written into a file before it is
   moved aside and a new file is started. (used with `retain_bytes` and not with
   `rotate_seconds` or `retain_seconds`).

 * ##### retain_bytes

   Specified the number of bytes of data to be retained.  If all log data in a
   in all rotated files exceed this value, the oldest file will be removed. (used with
   `rotate_bytes` and not with `rotate_seconds` or `retain_seconds`).

### jlog

The jlog log_stream type implements an log output to the [Jlog](https://github.com/omniti-labs/jlog)
multi-file journalled logging format.  Jlog is a segmented write-ahead log that is fast and efficient
and supports multiple subscribers with independently maintained process checkpoints.

 * ##### path

   The path is the Jlog directory to be used. It may optionally be ended with
   a parenthesized subscriber name.  If a name (other than "*") is provided,
   a subscriber of that name will be added to the Jlog on creation.
