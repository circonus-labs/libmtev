### B

#### mtev.base64_decode

```lua
mtev.base64_decode()
```



#### mtev.base64_encode

```lua
mtev.base64_encode()
```



### C

#### mtev.cancel_coro

```lua
mtev.cancel_coro()
```



#### mtev.close

```lua
mtev.close(fd)
```

 

#### mtev.cluster

```lua
cluster =
mtev.cluster(name)
```

  * `name` name of cluster
  * **RETURN** a cluster object


#### mtev.conf_get_boolean

```lua
mtev.conf_get_boolean()
```



#### mtev.conf_get_float

```lua
mtev.conf_get_float()
```



#### mtev.conf_get_integer

```lua
mtev.conf_get_integer()
```



#### mtev.conf_get_string

```lua
mtev.conf_get_string()
```



#### mtev.conf_get_string_list

```lua
mtev.conf_get_string_list()
```



#### mtev.conf_replace_boolean

```lua
mtev.conf_replace_boolean()
```



#### mtev.conf_replace_value

```lua
mtev.conf_replace_value()
```



### D

#### mtev.dns

>Create an `mtev.dns` object for DNS lookups.

```lua
mtev.dns =
mtev.dns(nameserver = nil)
```


  * `nameserver` an optional argument specifying the nameserver to use.
  * **RETURN** an `mtev.dns` object.

This function creates an `mtev.dns` object that can be used to perform
lookups and IP address validation.


#### mtev.dns:is_valid_ip

>Determine address family of an IP address.

```lua
bool, family =
mtev.dns:is_valid_ip(ipstr)
```


  * `ipstr` a string of an potential IP address.
  * **RETURN** if the address is valid and, if it is, the family.

The first return is true if the suplied string is a valid IPv4 or IPv6
address, otherwise false.  If the address is valid, the second argument
will be the address family as an integer, otherwise nil.


#### mtev.dns:lookup

>Perform a DNS lookup.

```lua
record =
mtev.dns:lookup(query, rtype = "A", ctype = "IN")
```


  * `query` a string representing the DNS query.
  * `rtype` the DNS resource type (default "A").
  * `ctype` the DNS class type (default "IN").
  * **RETURN** a lua table, nil if the lookup fails.

DNS lookup works cooperatively with the eventer to schedule an
lookup and yield the current coroutine to the event loop.  If
successful the table returned will contain field(s) for the
requested resource. Possible fields are:

* `a` and `ttl`
* `aaaa` and `ttl`
* `mx` and `preference`
* `cname` and `ttl`
* `ptr` and `ttl`
* `ns` and `ttl`
* `mb` and `ttl`
* `md` and `ttl`
* `mf` and `ttl`
* `mg` and `ttl`
* `mr` and `ttl`


### E

#### mtev.enable_log

>Enable or disable a log facility by name.

```lua
mtev.enable_log(facility, flags = true)
```


  * `facility` the name of the mtev_log_stream (e.g. "debug")
  * `flags` true enables, false disables


#### mtev.eventer_loop_concurrency

```lua
mtev.eventer_loop_concurrency()
```



#### mtev.extended_free

```lua
mtev.extended_free()
```



### G

#### mtev.getcwd

```lua
path =
mtev.getcwd()
```

  * **RETURN** path string or nil


#### mtev.gettimeofday

```lua
sec, usec =
mtev.gettimeofday()
```

  * **RETURN** the seconds and microseconds since epoch (1970 UTC)


#### mtev.gunzip

```lua
mtev.gunzip()
```



#### mtev.gunzip_deflate

```lua
mtev.gunzip_deflate()
```



### H

#### mtev.hmac_sha1_encode

```lua
mtev.hmac_sha1_encode()
```



#### mtev.hmac_sha256_encode

```lua
mtev.hmac_sha256_encode()
```



### J

#### mtev.json:document

>return a lua prepresentation of an `mtev.json` object

```lua
obj =
mtev.json:document()
```


  * **RETURN** a lua object (usually a table)

Returns a fair representation of the underlying JSON document
as native lua objects.


#### mtev.json:tostring

>return a JSON-formatted string of an `mtev.json` object

```lua
obj =
mtev.json:tostring()
```


  * **RETURN** a lua string

Returns a JSON document (as a string) representing the underlying
`mtev.json` object.


### L

#### mtev.log

>write message into the libmtev logging system

```lua
len =
mtev.log(facility, format, ...)
```


  * `facility` the name of the mtev_log_stream (e.g. "error")
  * `format` a format string see printf(3c)
  * `...` arguments to be used within the specified format
  * **RETURN** the number of bytes written


#### mtev.log_enabled

>Determine the enabled status of a log.

```lua
boolean =
mtev.log_enabled(facility)
```


  * `facility` the name of the mtev_log_stream (e.g. "debug")
  * **RETURN** a boolean indicating the enabled status of the log facility


### M

#### mtev.md5

```lua
mtev.md5()
```



#### mtev.md5_hex

```lua
mtev.md5_hex()
```



#### mtev.mkdir

```lua
ok, errno, errstr =
mtev.mkdir(path)
```

  * `path` string
  * **RETURN** boolean success flag, error number, string representation of error


#### mtev.mkdir_for_file

```lua
ok, errno, errstr =
mtev.mkdir_for_file(path)
```

    * `path` string
    * **RETURN** boolean success flag, error number, string representation of error


### O

#### mtev.open

```lua
fh =
mtev.open(file, flags)
```

    * `file` to open (string)
    * `integer` flag
    * **RETURN** file handle

  The following flag constants are pre-defined:
  `O_RDONLY`,
  `O_WRONLY`,
  `O_RDWR`,
  `O_APPEND`,
  `O_SYNC`,
  `O_NOFOLLOW`,
  `O_CREAT`,
  `O_TRUNC`,
  `O_EXCL`
  see `man 2 open` for their semantics.


### P

#### mtev.parsejson

>Convert a JSON strint to an `mtev.json`.

```lua
jsonobj, err, offset =
mtev.parsejson(string)
```


  * `string` is a JSON formatted string.
  * **RETURN** an mtev.json object plus errors on failure.

This converts a JSON string to a lua object.  As lua
does not support table keys with nil values, this
implementation sets them to nil and thus elides the keys.
If parsing fails nil is returned followed by the error and
the byte offset into the string where the error occurred.


#### mtev.parsexml

```lua
mtev.parsexml()
```



#### mtev.pcre

```lua
matcher =
mtev.pcre(pcre_expression)
```

  * `pcre_expression` a perl compatible regular expression
  * **RETURN** a matcher function `rv, m, ... = matcher(subject, options)`

A compiled pcre matcher function takes a string subject as the first
argument and optional options as second argument.

The matcher will return first whether there was a match (true/false).
If true, the next return value will be to entire scope of the match
followed by any capture subexpressions.  If the same subject variable
is supplied, subsequent calls will act on the remainder of the subject
past previous matches (allowing for global search emulation).  If the
subject changes, the match starting location is reset to the beginning.
The caller can force a reset by calling `matcher(nil)`.

`options` is an option table with the optional fields `limit`
(`PCRE_CONFIG_MATCH_LIMIT`) and `limit_recurse` (`PCRE_CONFIG_MATCH_LIMIT_RECURSION`).
See the pcreapi man page for more details.


#### mtev.print

```lua
len =
mtev.print(format, ...)
```

  * `format` a format string see printf(3c)
  * `...` arguments to be used within the specified format
  * **RETURN** the number of bytes written

This function is effectively the `mtev.log` function with the first argument
set to "error".  It is also aliased into the global `print` symbol such that
one cannot accidentally call the print builtin.


#### mtev.process:kill

>Kill a spawned process.

```lua
success, errno =
mtev.process:kill(signal)
```


  * `signal` the integer signal to deliver, if omitted `SIGTERM` is used.
  * **RETURN** true on success or false and an errno on failure.


#### mtev.process:pid

>Return the process id of a spawned process.

```lua
pid =
mtev.process:pid()
```


  * **RETURN** The process id.


#### mtev.process:wait

>Attempt to wait for a spawned process to terminate.

```lua
status, errno =
mtev.process:wait(timeout)
```


  * `timeout` an option time in second to wait for exit (0 in unspecified).
  * **RETURN** The process status and an errno if applicable.

Wait for a process (using `waitpid` with the `WNOHANG` option) to terminate
and return its exit status.  If the process has not exited and the timeout
has elapsed, the call will return with a nil value for status.  The lua
subsystem exists within a complex system that might handle process in different
ways, so it does not rely on `SIGCHLD` signal delivery and instead polls the
system using `waitpid` every 20ms.


### R

#### mtev.realpath

>Return the real path of a relative path.

```lua
path =
mtev.realpath(inpath)
```


  * `inpath` a relative path as a string
  * **RETURN** The non-relative path inpath refers to (or nil on error).


#### mtev.rmdir

```lua
ok, errno, errstr =
mtev.rmdir(path)
```

  * `path` string
  * **RETURN** boolean success flag, error number, string representation of error
 

### S

#### mtev.sha1

```lua
mtev.sha1()
```



#### mtev.sha1_hex

```lua
mtev.sha1_hex()
```



#### mtev.sha256

```lua
digest =
mtev.sha256(s)
```

  * `s` a string
  * **RETURN** the SHA256 digest of the input string


#### mtev.sha256_hash

```lua
digest_hex =
mtev.sha256_hash(s)
```

  * `s` a string
  * **RETURN** the SHA256 digest of the input string, encoded in hexadecimal format

**DEPRECATED**

Use sha256_hex instead.


#### mtev.sha256_hex

```lua
digest_hex =
mtev.sha256_hex(s)
```

  * `s` a string
  * **RETURN** the SHA256 digest of the input string, encoded in hexadecimal format


#### mtev.shared_get

```lua
mtev.shared_get()
```



#### mtev.shared_set

```lua
mtev.shared_set()
```



#### mtev.sleep

```lua
slept =
mtev.sleep(duration_s)
```

  * `duration_s` the number of sections to sleep
  * **RETURN** the number of sections slept.


#### mtev.socket

```lua
mtev.socket()
```



#### mtev.socket_internal

```lua
mtev.socket_internal()
```



#### mtev.spawn

>Spawn a subprocess.

```lua
mtev.process =
mtev.spawn(path, argv, env)
```


  * `path` the path to the executable to spawn
  * `argv` an array of arguments (first argument is the process name)
  * `env` an optional array of "K=V" strings.
  * **RETURN** an object with the mtev.process metatable set.

This function spawns a new subprocess running the binary specified as
the first argument.


### T

#### mtev.thread_self

```lua
thread, tid =
mtev.thread_self()
```



#### mtev.timezone

```lua
mtev.timezone =
mtev.timezone(zonename)
```

 *   * `zonename` is the name of the timezone (e.g. "UTC" or "US/Eastern")
 *   * **RETURN** an mtev.timezone object.
 

#### mtev.timezone:extract

```lua
a,... =
mtev.timezone:extract(time, field1, ...)
```

  * `time` is the offset in seconds from UNIX epoch.
  * `field1` is a field to extract in the time local to the timezone object.
  * **RETURN** The value of each each requested field.

Valid fields are "second", "minute", "hour", "monthday", "month", "weekday",
"yearday", "year", "dst", "offset", and "zonename."


#### mtev.tojson

>Convert a lua object into a json doucument.

```lua
jsonobj =
mtev.tojson(obj, maxdepth = -1)
```


  * `obj` a lua object (usually a table).
  * `maxdepth` if specified limits the recursion.
  * **RETURN** an mtev.json object.

This converts a lua object, ignoring types that do not have JSON
counterparts (like userdata, lightuserdata, functions, threads, etc.).
The return is an `mtev.json` object not a string. You must invoke
the `tostring` method to convert it to a simple string.


### U

#### mtev.utf8tohtml

```lua
mtev.utf8tohtml()
```



#### mtev.uuid

```lua
mtev.uuid()
```



### W

#### mtev.watchdog_child_heartbeat

>Heartbeat from a child process.

```lua
rv =
mtev.watchdog_child_heartbeat()
```


  * **RETURN** The return value of `mtev_watchdog_child_heartbeat()`


#### mtev.watchdog_timeout

>Return the watchdog timeout on the current thread.

```lua
timeout =
mtev.watchdog_timeout()
```


  * **RETURN** A timeout in seconds, or nil if no watchdog configured.


#### mtev.WCOREDUMP

```lua
mtev.WCOREDUMP(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** true if the process produced a core dump

Only valid if `mtev.WIFSIGNALED(status)` is also true.


#### mtev.WEXITSTATUS

```lua
mtev.WEXITSTATUS(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** the exit status of the process

Only valid if `mtev.WIFEXITED(status)` is true.


#### mtev.WIFCONTINUED

```lua
mtev.WIFCONTINUED(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** true if the process has continued after a job control stop, but not terminated


#### mtev.WIFEXITED

```lua
mtev.WIFEXITED(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** true if the process terminated normally


#### mtev.WIFSIGNALED

```lua
mtev.WIFSIGNALED(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** true if the process terminated due to receipt of a signal


#### mtev.WIFSTOPPED

```lua
mtev.WIFSTOPPED(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** true if the process was stopped, but not terminated


#### mtev.write

```lua
mtev.write(fd, str)
```



#### mtev.WSTOPSIG

```lua
mtev.WSTOPSIG(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** the number of the signal that caused the process to stop

Only valid if `mtev.WIFSTOPPED(status)` is true.


#### mtev.WTERMSIG

```lua
mtev.WTERMSIG(status)
```

  * `status` a process status returned by `mtev.process:wait(timeout)`
  * **RETURN** the number of the signal that caused the termination of the process

Only valid if `mtev.WIFSIGNALED(status)` is true.


