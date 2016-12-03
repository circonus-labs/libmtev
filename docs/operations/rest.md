# REST-accessible Observability Endpoints

Various components in the libmtev namespace can register REST endpoints
via the `http_rest.h` APIs and expose a wealth of configuration
and run-time mechanics to the caller.

##### application.conf
```
  <root>
  <listeners>
    <listener type="http_rest_api" address="*" port="8888" ssl="off">
      <config>
        <document_root>/path/to/docroot</document_root>
      </config>
    </listener>
  </listeners>
  <rest>
    <acl>
      <!-- you should consider tighter ACLs -->
      <rule type="allow" />
    </acl>
  </rest>
  </root>
  ]]></programlisting>
  </example>
```

In addition to a confgiuration snippet similar to the above, the HTTP REST subsystem
must be programmatically initialized via a call to `mtev_http_rest_init()`.

The REST listener is implemented on a non-compliant HTTP listener by
subverting the four-byte control words "DELE", "MERG", "GET ", "HEAD",
"POST", "PUT " and dropping them into a compliant HTTP state machine.  While
the session intiiation is not strictly compliant with the HTTP specification
it happily serves all known browsers and plays nicely with HTTP proxies as
well.

If the listener "type" is `http_rest_api`, then only
the REST handler is served on that listening socket.  If the more general
type of `control_dispatch` is used, then a full control channel
is served and the REST services are superimposed on that.  Listeners
of type `control_dispatch` are even less HTTP compliant, but
still serve all web browers and proxies correctly.

### The capabilities endpoint

It is highly recommended that you expose the libmtev capabilities
endpoints.  This service exposes information about the libmtev version
and build as well as any dispatch handlers that have been registered
via `mtev_control_dispatch_delegate(...)`.</para>

#### GET /capa

Bot the CAPA HTTP verb and a GET of /capa will return the application capabilities in XML.

```
# curl -XCAPA http://127.0.0.1:8888/
# curl http://127.0.0.1:8888/capa

<?xml version="1.0" encoding="utf8"?>
<mtev_capabilities>
  <version>master.5553ef6a1c838ac5a639a634027db7b2c39be23d.1459876317</version>
  <unameBuild bitwidth="64">
    <sysname>Darwin</sysname>
    <nodename>cudgel</nodename>
    <release>15.3.0</release>
    <version>Darwin Kernel Version 15.3.0; root:xnu-3248.30.4~1/RELEASE_X86_64</version>
    <machine>x86_64</machine>
  </unameBuild>
  <unameRun bitwidth="64">
    <sysname>Darwin</sysname>
    <nodename>cudgel</nodename>
    <release>15.4.0</release>
    <version>Darwin Kernel Version 15.4.0; root:xnu-3248.40.184~3/RELEASE_X86_64</version>
    <machine>x86_64</machine>
  </unameRun>
  <features/>
  <current_time>1460120546.029</current_time>
  <services>
    <service name="control_dispatch" connected="true">
      <command name="mtev_wire_rest_api" version="1.0" code="0x504f5354"/>
      <command name="mtev_wire_rest_api" version="1.0" code="0x4d455247"/>
      <command name="mtev_wire_rest_api" version="1.0" code="0x48454144"/>
      <command name="mtev_wire_rest_api" version="1.0" code="0x47455420"/>
      <command name="capabilities_transit" version="1.0" code="0x43415041"/>
      <command name="mtev_wire_rest_api" version="1.0" code="0x50555420"/>
      <command name="mtev_wire_rest_api" version="1.0" code="0x44454c45"/>
    </service>
  </services>
  <modules/>
</mtev_capabilities>
```

#### GET /capa.json

Capanilities are also available in JSON format.

```
# curl http://127.0.0.1:8888/capa.json

{
  "version": "master.5553ef6a1c838ac5a639a634027db7b2c39be23d.1459876317",
  "unameBuild": {
    "bitwidth": 64,
    "sysname": "Darwin",
    "nodename": "cudgel",
    "release": "15.3.0",
    "version": "Darwin Kernel Version 15.3.0; root:xnu-3248.30.4~1/RELEASE_X86_64",
    "machine": "x86_64"
  },
  "unameRun": {
    "bitwidth": 64,
    "sysname": "Darwin",
    "nodename": "cudgel",
    "release": "15.4.0",
    "version": "Darwin Kernel Version 15.4.0; root:xnu-3248.40.184~3/RELEASE_X86_64",
    "machine": "x86_64"
  },
  "features": {},
  "current_time": "1460121207543",
  "services": {
    "0x10e19480": {
      "control_dispatch": "control_dispatch",
      "commands": {
        "0x504f5354": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        },
        "0x4d455247": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        },
        "0x48454144": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        },
        "0x47455420": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        },
        "0x43415041": {
          "name": "capabilities_transit",
          "version": "1.0"
        },
        "0x50555420": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        },
        "0x44454c45": {
          "name": "mtev_wire_rest_api",
          "version": "1.0"
        }
      }
    }
  },
  "modules": {}
}
```

### The Eventer System

Assuming the application has registered the eventer system reporting over rest via the `mtev_events_rest_init()` call,
robust information about the current state of all events in the system is available in JSON.

#### GET /eventer/sockets.json

```
# curl http://localhost:8888/eventer/sockets.json

[
  {
    "callback": "listener(mtev_console)",
    "fd": 9,
    "local": {
      "address": "0.0.0.0",
      "port": 32322
    },
    "impl": "POSIX",
    "mask": 5,
    "eventer_pool": "default"
  },
  {
    "callback": "listener(control_dispatch)",
    "fd": 11,
    "local": {
      "address": "0.0.0.0",
      "port": 8888
    },
    "impl": "POSIX",
    "mask": 5,
    "eventer_pool": "default"
  },
  {
    "callback": "mtev_wire_rest_api/1.0",
    "fd": 12,
    "local": {
      "address": "127.0.0.1",
      "port": 8888
    },
    "remote": {
      "address": "127.0.0.1",
      "port": 60088
    },
    "impl": "POSIX",
    "mask": 5,
    "eventer_pool": "default"
  }
]
```

#### GET /eventer/timers.json

```
# curl http://localhost:8888/eventer/timers.json

[
  {
    "callback": "mtev_conf_watch_config_and_journal",
    "whence": 1480805474873,
    "eventer_pool": "default"
  }
]
```

#### GET /eventer/jobq.json

```
# curl http://localhost:8888/eventer/jobq.json

{
  "default_queue": {
    "concurrency": 10,
    "desired_concurrency": 10,
    "total_jobs": 1,
    "backlog": 0,
    "inflight": 0,
    "timeouts": 0,
    "avg_wait_ms": 0.034546,
    "avg_run_ms": 1142.833808
  },
  "default_back_queue/0": {
    "concurrency": 0,
    "desired_concurrency": 0,
    "total_jobs": 1,
    "backlog": 0,
    "inflight": 0,
    "timeouts": 0,
    "avg_wait_ms": 0,
    "avg_run_ms": 0
  },
  "default_back_queue/1": {
    "concurrency": 0,
    "desired_concurrency": 0,
    "total_jobs": 0,
    "backlog": 0,
    "inflight": 0,
    "timeouts": 0,
    "avg_wait_ms": 0,
    "avg_run_ms": 0
  }
}
```

#### GET /eventer/logs/&lt;name&gt;.json

Returns logs from the stream named `<name>` of type "memory".

Querystring parameters include:

 * last=N

    requests only the N most recent log lines. Log lines are returned with index numbers.

 * since=I

    requests only log lines after index I.

```
# curl http://localhost:8888/eventer/logs/internal.json?last=2

[
  {
    "idx": 4,
    "whence": 1480805410721,
    "line": "Generating 1024 bit DH parameters.\n"
  },
  {
    "idx": 5,
    "whence": 1480805416435,
    "line": "Finished generating 1024 bit DH parameters.\n"
  }
]
```
