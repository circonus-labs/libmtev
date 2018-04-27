#include "mtev_heap_profiler.h"
#include "mtev_rest.h"

#include <dlfcn.h>
#include <link.h>

static int (*mallctl)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static mtev_boolean jemalloc_loaded = mtev_false;

int
mtev_rest_heap_profiler_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) 
{
  mtev_http_session_ctx *ctx = restc->http_ctx;
  const char *error_str = NULL;

  if(!jemalloc_loaded) {
    error_str = "libjemalloc is not loaded, cannot heap profile\n";
    goto error;
  }

  mtev_hash_table *h = mtev_http_request_querystring_table(mtev_http_session_request(ctx));
  if (!h) {
    error_str = "Cannot read query string params\n";
    goto error;
  }

  char *prefix = NULL;
  mtev_boolean active = mtev_false;
  mtev_boolean dump = mtev_false;
  void *value;
  if (mtev_hash_retrieve(h, "prefix", strlen("prefix"), &value)) {
    prefix = strdup((char *) value);
  }
  if (mtev_hash_retrieve(h, "active", strlen("active"), &value)) {
    active = strcmp((char *)value, "true") == 0;
  }
  if (mtev_hash_retrieve(h, "trigger_dump", strlen("trigger_dump"), &value)) {
    dump = strcmp((char *)value, "true") == 0;
  }

  mtev_http_response_ok(ctx, "text/plain");
  if (prefix != NULL) {
    mallctl("opt.prof_prefix", NULL, NULL, &prefix, sizeof(char *));
    mtev_http_response_append_str(ctx, "Set dump prefix to: %s\n", prefix);
  }
  if (active) {
    bool bactive = true;
    mallctl("prof.active", NULL, NULL, &bactive, sizeof(bool));
    mtev_http_response_append_str(ctx, "Profiling is activated\n");
  } else {
    bool bactive = false;
    mallctl("prof.active", NULL, NULL, &bactive, sizeof(bool));
    mtev_http_response_append_str(ctx, "Profiling is deactivated\n");
  }

  if (dump) {
    mallctl("prof.dump", NULL, NULL, NULL, 0);
    mtev_http_response_append_str(ctx, "Dumped heap profile\n");
  }

  mtev_http_response_end(ctx);
  return 0;

 error:
  mtev_http_response_server_error(ctx, "text/plain");
  mtev_http_response_append_str(ctx, error_str);
  mtev_http_response_end(ctx);
  return 0;

}


void mtev_heap_profiler_init(void)
{
  /* it's loaded so we can enable mallctl */
#ifdef RTLD_DEFAULT
  mallctl = dlsym(RTLD_DEFAULT, "mallctl");
#else
  mallctl = dlsym((void *)0, "mallctl");
#endif

  if (mallctl) {
    bool active = false;
    mallctl("opt.prof_active", NULL, NULL, &active, sizeof(bool));
  }
}

void mtev_heap_profiler_rest_init(void)
{
  mtev_heap_profiler_init();
  mtevAssert(mtev_http_rest_register_auth(
                 "GET", "/mtev/", "^heap_profile$", mtev_rest_heap_profiler_handler,
                 mtev_http_rest_client_cert_auth) == 0);
}
