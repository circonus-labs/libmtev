### G

#### mtev.gettimeofday

```lua
sec, usec = 
mtev.gettimeofday()
```

  * **RETURN** the seconds and microseconds since epoch (1970 UTC)


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


