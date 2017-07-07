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


### G

#### mtev.gettimeofday

```lua
sec, usec = 
mtev.gettimeofday()
```

  * **RETURN** the seconds and microseconds since epoch (1970 UTC)


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


### S

#### mtev.sleep

```lua
slept = 
mtev.sleep(duration_s)
```

  * `duration_s` the number of sections to sleep
  * **RETURN** the number of sections slept.


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


