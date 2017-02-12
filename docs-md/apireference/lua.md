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

>Convert a JSON strint to an `mtev.json`

```lua
jsonobj = 
mtev.parsejson(string)
```


  * `string` is a JSON formatted string.
  * **RETURN** an mtev.json object.

This converts a JSON string to a lua object.  As lua
does not support table keys with nil values, this
implementation sets them to nil and thus elides the keys.


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


### S

#### mtev.sleep

```lua
slept = 
mtev.sleep(duration_s)
```

  * `duration_s` the number of sections to sleep
  * **RETURN** the number of sections slept.


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


