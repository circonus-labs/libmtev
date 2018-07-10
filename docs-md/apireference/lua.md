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



#### mtev.chmod

>Change the mode of a file.

```lua
rv =
mtev.chmod(file, mode)
```


  * `file` the path to a target file.
  * `a` new file mode.
  * **RETURN** rv is the return as documented by the `chmod` libc call.


#### mtev.close

>Close a file descripto.

```lua
mtev.close(fd)
```


  * `fd` the integer file descriptor to close.
 

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


#### mtev.eventer:accept

>Accept a new connection.

```lua
mtev.eventer =
mtev.eventer:accept()
```


  * **RETURN** a new eventer object representing the new connection.


#### mtev.eventer:bind

>Bind a socket to an address.

```lua
rv, err =
mtev.eventer:bind(address, port)
```


  * `address` the IP address to which to bind.
  * `port` the port to which to bind.
  * **RETURN** rv is 0 on success, on error rv is non-zero and err contains an error message.


#### mtev.eventer:close

>Closes the socket.

```lua
rv =
mtev.eventer:close()
```




#### mtev.eventer:connect

>Request a connection on a socket.

```lua
rv, err =
mtev.eventer:connect(target[, port])
```


  * `target` the target address for a connection.  Either an IP address (in which case a port is required), or a `reverse:` connection for reverse tunnelled connections.
  * **RETURN** rv is 0 on success, non-zero on failure with err holding the error message.


#### mtev.eventer:listen

>Listen on a socket.

```lua
rv, errno, err =
mtev.eventer:listen(backlog)
```


  * `backlog` the listen backlog.
  * **RETURN** rv is 0 on success, on failure rv is non-zero and errno and err contain error information.


#### mtev.eventer:own

>Declare ownership of an event within a spawned co-routine.

```lua
mtev.eventer:own()
```




#### mtev.eventer:peer_name

>Get details of the remote side of a socket.

```lua
address, port =
mtev.eventer:peer_name()
```


  * **RETURN** local address, local port


#### mtev.eventer:read

>Read data from a socket.

```lua
payload =
mtev.eventer:read(stop)
```


  * `stop` is either an integer describing a number of bytes to read or a string describing an inclusive read terminator.
  * **RETURN** the payload read, or nothing on error.


#### mtev.eventer:recv

>Receive bytes from a socket.

```lua
rv, payload, address, port =
mtev.eventer:recv(nbytes)
```


  * `nbytes` the number of bytes to receive.
  * **RETURN** rv is the return of the `recvfrom` libc call, < 0 if error, otherwise it represents the number of bytes received. payload is a lua string representing the data received. address and port are those of the sender of the packet.


#### mtev.eventer:send

>Send data over a socket.

```lua
nbytes, err =
mtev.eventer:send(payload)
```


  * `payload` the payload to send as a lua string.
  * **RETURN** bytes is -1 on error, otherwise the number of bytes sent. err contains error messages.


#### mtev.eventer:sendto

>Send data over a disconnected socket.

```lua
nbytes, err =
mtev.eventer:sendto(payload, address, port)
```


  * `payload` the payload to send as a lua string.
  * `address` is the destination address for the payload.
  * `port` is the destination port for the payload.
  * **RETURN** bytes is -1 on error, otherwise the number of bytes sent. err contains error messages.


#### mtev.eventer:setsockopt

>Set a socket option.

```lua
rv, err =
mtev.eventer:setsockopt(feature, value)
```


  * `feature` is on the the OS `SO_` parameters as a string.
  * `value` is the value to which `feature` should be set.
  * **RETURN** rv is 0 on success, -1 on failure. err contains error messages.


#### mtev.eventer:sock_name

>Get details of the local side of a socket.

```lua
address, port =
mtev.eventer:sock_name()
```


  * **RETURN** local address, local port


#### mtev.eventer:ssl_ctx

>Gets the SSL context associated with an SSL-upgraded event.

```lua
mtev.eventer.ssl_ctx =
mtev.eventer:ssl_ctx()
```


  * **RETURN** an mtev.eventer.ssl_ctx object.


#### mtev.eventer:ssl_upgrade_socket

>Upgrade a normal TCP socket to SSL.

```lua
rv, err =
mtev.eventer:ssl_upgrade_socket(cert, key[, ca[, ciphers[, snihost[, layer]]]])
```


  * `cert` a path to a PEM-encoded certificate file.
  * `key` a path to a PEM-encoded key file.
  * `ca` a path to a PEM-encoded CA chain.
  * `ciphers` an OpenSSL cipher preference list.
  * `snihost` the host name to which we're connecting (SNI).
  * `layer` a desired SSL layer.
  * **RETURN** rv is 0 on success, -1 on failure. err contains error messages.


#### mtev.eventer:write

>Writes data to a socket.

```lua
nbytes =
mtev.eventer:write(data)
```


  * `data` a lua string that contains the data to write.
  * **RETURN** the number of bytes written.


#### mtev.eventer_loop_concurrency

```lua
mtev.eventer_loop_concurrency()
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


### N

#### mtev.notify

>Send notification message on given key, to be received by mtev.waitfor(key)

```lua
mtev.notify(key, ...)
```


  * `key` key specifying notification channel
  * `...` additional args to be included in the message


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
  * **RETURN** the time slept as mtev.timeval object


#### mtev.socket

>Open a socket for eventer-friendly interaction.

```lua
mtev.eventer =
mtev.socket(address[, type])
```


  * `address` a string 'inet', 'inet6' or an address to connect to
  * `type` an optional string 'tcp' or 'udp' (default is 'tcp')
  * **RETURN** an eventer object.

No connect() call is performed here, the address provided is only used
to ascertain the address family for the socket.


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

#### mtev.waitfor

>Suspend until for notification on key is received or the timeout is reached.

```lua
... =
mtev.waitfor(key, [timeout])
```


  * **RETURN** arguments passed to mtev.notify() including the key.


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


