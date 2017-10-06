# DTrace-accessible Observability

See the [DTrace Guide](http://dtrace.org/guide/preface.html) for general
information on how to use DTrace.

libmtev includes a number of [Statically Defined
Trace](http://dtrace.org/guide/chp-usdt.html#chp-usdt) points (SDTs) for key
events in the system.

Probes will be visible using the provider `libmtev<pid>` where `<pid>` is the
process ID of a libmtev application. To trace all PIDs of all libmtev
applications currently running, one would use the [provider
definition](http://dtrace.org/guide/chp-prog.html#chp-prog-2)
`libmtev*:::`.

List all available libmtev probes:
```
dtrace -l -n 'libmtev*:::'
```

## DTrace probe definitions

### Logging
```
provider libmtev {
  probe log (char *facility, char *file, int line, char *msg);
};
```

### Eventer
```
provider libmtev {
  probe eventer-accept-entry (int, void *, int, int, void *);
  probe eventer-accept-return (int, void *, int, int, void *, int);
  probe eventer-read-entry (int, char *, size_t, int, void *);
  probe eventer-read-return (int, char *, size_t, int, void *, int);
  probe eventer-write-entry (int, char *, size_t, int, void *);
  probe eventer-write-return (int, char *, size_t, int, void *, int);
  probe eventer-close-entry (int, int, void *);
  probe eventer-close-return (int, int, void *, int);
  probe eventer-callback-entry (void *, void *, char *, int, int, int);
  probe eventer-callback-return (void *, void *, char *, int);
};
```

### Reverse Connections
```
provider libmtev {
  probe reverse-reschedule (int, char *, char *, int);
  probe reverse-shutdown-permanent (int, char *, char *);
  probe reverse-connect (int, char *, char *);
  probe reverse-connect-success (int, char *, char *);
  probe reverse-connect-close (int, char *, char *, int, int);
  probe reverse-connect-failed (int, char *, char *, int);
  probe reverse-connect-ssl (int, char *, char *);
  probe reverse-connect-ssl-success (int, char *, char *);
  probe reverse-connect-ssl-failed (int, char *, char *, char *, int);
};
```

### HTTP Server
```
provider libmtev {
  probe http-accept (int, struct mtev_http_session_ctx *);
  probe http-request-start (int, struct mtev_http_session_ctx *);
  probe http-request-finish (int, struct mtev_http_session_ctx *);
  probe http-response-start (int, struct mtev_http_session_ctx *);
  probe http-response-finish (int, struct mtev_http_session_ctx *);
  probe http-log (int, struct mtev_http_session_ctx *, char *);
  probe http-close (int, struct mtev_http_session_ctx *);
};
```
