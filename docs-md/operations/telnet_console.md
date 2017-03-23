# Telnet Console Observability

A full telnet console is available for online operations of libmtev applications.
To enable the telnet console, add something like the following to your configuration.
Note that "bad things" can be done via the telnet console, so restricting access makes
good sense.

##### listener.conf
```
   <consoles type="mtev_console">
      <listener address="127.0.0.1" port="32322">
        <config>
          <line_protocol>telnet</line_protocol>
        </config>
      </listener>
    </consoles>
```

The telnet console support tab completion, so navigating and exploring the possibilities
can be an interactive experience.

## Logs

```console
app# show log internal
[1] Hello world.

app# show log internal 100
[1] Hello world.

app# show log debug/eventer details
{ "name": "debug\/eventer",
  "enabled": false,
  "debugging": false,
  "timestamps": false,
  "facility": false,
  "outlets": [ { "name": "debug",
                 "outlets": [ { "name": "stderr" } ] } ] }

app# log notice Hello from the console
logged.
```

### Commands

##### `show log <logname>`

> Show the last 23 lines of `<logname>` if it is a "memory" type log.

##### `show log <logname> [# lines]`

> Show the last requested number lines of `<logname>` if it is a "memory" type log.

##### `show log <logname> details`

> Show the details of the the `<logname>` log stream, including outlets.

##### `log to <logname> <something to log>`

> Cause a `<something to log>` to be immediately logged to the specified log.

##### `log [dis]connect <logname> [tgtlogname]`

> Connect or disconnect `<tgtlogname>` as an outlets for `<logname>`. If `<tgtlogname>` is omitted, the attached console is used.

##### `[no] log <enable|facility|debug|timestamps> <logname>`

> Sets (or unsets) flags on the specified log.
