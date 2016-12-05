# DTrace-accessible Observability

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
