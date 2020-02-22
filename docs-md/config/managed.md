# Managed Applications

The watchdog subsystem has the ability to manage sub-process that need to remain running.  These are often called sidecar applications.

Applications listend in the `managed` section of the config will be started when running in managed mode and restarted upon failure.  If the application exits normally with an exit code of 0, it is restarted immediately.  In all other cases, an expoentential backoff is used in the restart sequence so as not to overwhelme the system.

Applications are found using the XPath `/example1/managed//application|/example1/include/managed//application` to pull all nested application declarations from underneath top-level `managed` sections (even when included).

##### example1.conf

```xml
<?xml version="1.0" encoding="utf8" standalone="yes"?>
<example1 lockfile="/var/tmp/example.lock">
  <managed>
    <application exec="/opt/foo/sidecar1"
                 user="nobody" group="nogroup" dir="/var/run/sidecar1"
                 stderr="app/sidecar/stdout" stdout="app/sidecar/stderr" environment="true">
      <arg>-l</arg>
      <arg>localhost</arg>
      <env>TESTVAR=TESTVAL</env>
    </application>
  </managed>
</example1>
```

The following application attributes are supported:

 * ##### exec

   An executable to run, either a fully qualified path or name that is searched for in the PATH environment.

 * ##### arg0

   Specifies the first argument to `execve` is the program itself.  If this option is not specified, the value of `exec` is used as arg0.

 * ##### user

   Specifies a user to `setuid` to. If this is not specified, it will default to the user specified to the application (usually via a `-u` argument) which is passed into `mtev_main()`.

 * ##### group

   Specifies a group to `setgid` to. If this is not specified, it will default to the group specified to the application (usually via a `-g` argument) which is passed into `mtev_main()`.

 * ##### dir

   If specified, the managed application will `chdir` to this directory prior to `exec`.

 * ##### environment

   Specified whether the parents environment should be copied into the manage application.  The default is true.

 * ##### stdout

   A name of a log facility to channel stdout (FD 1) to. The default is `error`.

 * ##### stderr

   A name of a log facility to channel stderr (FD 2) to. The default is `error`.

Arguments are passed to the application in order by specifying `<arg>` elements within the `<application>` configuration.

Environment variables can be added using `<env>` elements within the `<application>` configuration.  If no `=` sign is found in the value of the specified `<env>` text, then value is used as a key and that environment variable value is extracted from the parents environment and pushed into the applications environment.  This is useful in combination with `environment="false"` to pass through on specific environment variables.
