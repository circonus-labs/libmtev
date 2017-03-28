
provider libmtev {
  probe log (char *, char *, int, char *);

  probe eventer__accept__entry (int, void *, int, int, void *);
  probe eventer__accept__return (int, void *, int, int, void *, int);
  probe eventer__read__entry (int, char *, size_t, int, void *);
  probe eventer__read__return (int, char *, size_t, int, void *, int);
  probe eventer__write__entry (int, char *, size_t, int, void *);
  probe eventer__write__return (int, char *, size_t, int, void *, int);
  probe eventer__close__entry (int, int, void *);
  probe eventer__close__return (int, int, void *, int);
  probe eventer__callback__entry (void *, void *, char *, int, int, int);
  probe eventer__callback__return (void *, void *, char *, int);

  probe reverse__reschedule (int, char *, char *, int);
  probe reverse__shutdown__permanent (int, char *, char *);
  probe reverse__connect (int, char *, char *);
  probe reverse__connect__success (int, char *, char *);
  probe reverse__connect__close (int, char *, char *, int, int);
  probe reverse__connect__failed (int, char *, char *, int);
  probe reverse__connect__ssl (int, char *, char *);
  probe reverse__connect__ssl__success (int, char *, char *);
  probe reverse__connect__ssl__failed (int, char *, char *, char *, int);

  probe http__accept(int, struct mtev_http_session_ctx *);
  probe http__request__start(int, struct mtev_http_session_ctx *);
  probe http__request__finish(int, struct mtev_http_session_ctx *);
  probe http__response__start(int, struct mtev_http_session_ctx *);
  probe http__response__finish(int, struct mtev_http_session_ctx *);
  probe http__log(int, struct mtev_http_session_ctx *, char *);
  probe http__close(int, struct mtev_http_session_ctx *);
};

#pragma D attributes Evolving/Evolving/ISA provider libmtev provider
#pragma D attributes Private/Private/Unknown provider libmtev module
#pragma D attributes Private/Private/Unknown provider libmtev function
#pragma D attributes Private/Private/ISA provider libmtev name
#pragma D attributes Evolving/Evolving/ISA provider libmtev args
