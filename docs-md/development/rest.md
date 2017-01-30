# REST

The default network listening framework allows for simply registration
of REST-based services via HTTP service.

##### app.conf (snippet)

```
<app>
  <listener type="http_rest_api" address="127.0.0.1" port="80">
    <config>
      <acl>internal</acl>
      <document_root>/path/to/docroot</document_root>
    </config>
  </listener>
  <rest>
    <acl type="deny" listener_acl="^internal$">
      <rule type="allow" url="."/>
    </acl>
    <acl type="deny"></acl>
  </rest>
</app>
```

More information about listener configuration can be found in the
[listener configuration](../config/listeners.md) section.

The above config establishes a REST-capable listener listening on
`localhost` port 80.  The "ACL" config option is set to `internal`
which can be used as a filter for ACL rules in the `rest/acl` config
section.  The `document_root` is set, which will enable serving of
static files on URLs that do not otherwise match routing rules. The
ACL rule for `internal` set that all urls are allowed followed by a
a blanket deny rule.  Other listeners that might not specify an `acl`
option would not see the first ACL allowing any URL, but still see the
blanket deny rule.

## Registering a REST handler.

##### myhandler.c (snippet)

```c
#include <mtev_rest.h>

static int
my_rest_handler(mtev_http_rest_closure_t *restc,
                int npats, char **pats) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_append(ctx, "myhandler: ", strlen("myhandler: "));
  mtev_http_response_append(ctx, pats[0], strlen(pats[0]));
  mtev_http_response_append(ctx, "\n", 1);
  mtev_http_response_end(ctx);
  return 0;
}

void child_main() {
 ...

  mtev_http_rest_register_auth(
    "GET", "/", "^myhandler/(.+)$", my_rest_handler,
           mtev_http_rest_client_cert_auth
  );
  mtev_http_rest_register_auth(
    "GET", "/", "^(.*)$", mtev_rest_simple_file_handler,
           mtev_http_rest_client_cert_auth
  );
  eventer_loop();
  return 0;
}
```

## Handling asynchronous work.

In order to complete some complex action in response to an inbound REST
request, it might be necessary to schedule some asynchronous work and
complete the response later.  This is possible, but requires a bit of
juggling.  The basic idea is:

 * from you handler:
  * copy and remove the connection's event from the eventer
  * set the rest's fastpath to a completion routine
  * schedule asynchronous work
  * return 0;
 * from the async job's completion:
  * trigger the connection's event

##### sleepy.c (snippet)

```c
#include <mtev_rest.h>

static int handler_work(eventer_t e, int mask, void *closure,
                        struct timeval *now) {
  mtev_http_rest_closure_t *restc = closure;
  if(mask == EVENTER_ASYNCH_WORK) {
    sleep(5);
  }
  if(mask == EVENTER_ASYNCH) {
    eventer_t conne;
    mtev_http_session_ctx *ctx = restc->http_ctx;

    /* trigger a continuation of the HTTP connection */
    conne = mtev_http_session_connection(ctx);
    if(conne) {
      eventer_trigger(conne, EVENTER_READ|EVENTER_WRITE);
    }
  }
  return 0;
}

static int handler_complete(mtev_http_rest_closure_t *restc,
                            int npats, char **pats) {
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_response_ok(ctx, "text/plain");
  mtev_http_response_append(ctx, "Hello world\n", strlen("Hello world\n"));
  mtev_http_response_end(ctx);
  return 0;
}

static int handler(mtev_http_rest_closure_t *restc,
                   int npats, char **pats) {
  eventer_t conne, worke;
  mtev_http_session_ctx *ctx = restc->http_ctx;

  /* remove the eventer */
  conne = mtev_http_connection_event_float(mtev_http_session_connection(ctx));
  if(conne) eventer_remove_fd(conne->fd);

  /* set a completion routine */
  restc->fastpath = handler_complete;

  /* schedule our work */
  worke = eventer_alloc();
  worke->closure = restc;
  worke->mask = EVENTER_ASYNCH;
  worke->callback = handler_work;
  eventer_add(worke);
  return 0;
}
```

## Handling POST/PUT data

Reading data from the HTTP request is done by calling the
`mtev_http_session_req_consume` function.  This can be tedious,
so unless you are doing something special it can be much easier
to simply first invoke the `mtev_rest_complete_upload` convenience
wrapper.

It must be called as the first action inside your REST callback handler.
Any manipulation of the restc (closures in particular) will have undefined
outcome.

```c
static int handler(mtev_http_rest_closure_t *restc,
                   int npats, char **pats) {
  int mask;
  void *payload;
  int64_t payload_len;
  mtev_http_request *req = mtev_http_session_request(restc->http_ctx);

  if(!mtev_rest_complete_upload(restc, &mask)) return mask;
  payload = mtev_http_request_get_upload(req, &payload_len);

  ...
}
```
