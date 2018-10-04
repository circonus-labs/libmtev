# Watchdog

The watchdog subsystem in libmtev provides a facility for hang protection, crash recovery, and crash reporting.

When "things go wrong" the parent (monitor) process will trace the monitored child using `{gilder} $pid $reason > {trace_dir}/$appname.$pid.trc`, ensure it is dead, confirm that it should restart it and then launch a new child.

##### example1.conf

```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<example1 lockfile="/var/tmp/example.lock">
  <watchdog glider="/opt/local/bin/bt"
            tracedir="/var/traces/example"/>
</example1>
```

The following watchdog attributes are supported:

 * ##### tracedir

   A directory to deposit trace files.  Trace files contain the output of the `glider` command.  File names are of the format `{appname}.{pid}.trc`.

 * ##### glider

   The full path to an executable to invoke when a monitor process crashes or is killed due to inactivity.  It is invoked with two arguments: process id and reason (one of "crash", "watchdog", or "unknown").

 * ##### save_trace_output

   Choose whether to store any output that the glider may produce on stdout. Its value is "true" or "false", and the default is "true" if not specified. If true, the glider output is saved as described in the `tracedir` attribute above. Some gliders may produce their own output files, in which case the stdout stream is unnecessary and one may choose to ignore it by setting this attribute to "false".

 * ##### retries

   The maximum number of restart attempts to be made over `span` seconds. Default: 5 retries over 60 seconds.

 * ##### span

   The number of seconds over which restarts are rate limited. Default: 5 retries over 60 seconds.
