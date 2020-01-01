#include "mtev_heap_profiler.h"

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static int (*mallctl)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static mtev_boolean jemalloc_loaded = mtev_false;

const char *
mtev_heap_profile(mtev_http_session_ctx *ctx, mtev_boolean active_present,
                  mtev_boolean active, mtev_boolean dump, char **result_str, char *path)
{
  int r = 0;
  static char buf[PATH_MAX] = { '\0' };
  *result_str = NULL;
  if (!path) { path = "/tmp"; }
  if (active_present)
  {
    bool bactive = active ? true : false;
    r = mallctl("prof.active", NULL, NULL, &bactive, sizeof(bool));
    if(r) {
      return strerror(r);
    }
    *result_str = active ? "Profiling is activated\n" : "Profiling is deactivated\n";
    if (ctx) {
      mtev_http_response_ok(ctx, "text/plain");
      mtev_http_response_append_str(ctx, *result_str);
      mtev_http_response_end(ctx);
    }
  } else if (dump) {
    snprintf(buf, PATH_MAX, "%s/heap_profile.%d", path, getpid());
    mtevL(mtev_debug, "Dumping heap profile to file: %s\n", buf);
    r = mallctl("prof.dump", NULL, NULL, &buf, sizeof(const char *));
    if(r) {
      return strerror(r);
    }
    if (ctx)
    {
      int fd = open(buf, O_RDONLY);
      unlink(buf);
      if (fd >= 0) {
        struct stat s;
        if (fstat(fd, &s) == 0) {
          mtev_http_response_ok(ctx, "application/x-jemalloc-heap-profile");
          mtev_http_response_append_mmap(ctx, fd, s.st_size, MAP_SHARED, 0);
          mtev_http_response_end(ctx);
          close(fd);
        } else {
          close(fd);
          return "Cannot fstat temp file\n";
        }
      } else {
        return strerror(errno);
      }
    }
    strlcat(buf, " was written successfully\n", sizeof(buf));
    *result_str = buf;
  } else {
    if (ctx) {
      mtev_http_response_ok(ctx, "text/plain");
    }
    bool bactive = false;
    size_t bactive_size = sizeof(bactive);
    r = mallctl("opt.prof", &bactive, &bactive_size, NULL, 0);
    snprintf(buf, sizeof(buf), "opt.prof: %s\n", r ? "error" : bactive ? "true" : "false");
    if(r == 0 && !bactive) {
      strlcat(buf, "# needs MALLOC_CONF=\"prof:true\"\n", sizeof(buf));
    }
    bactive_size = sizeof(bactive);
    r = mallctl("prof.active", &bactive, &bactive_size, NULL, 0);
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "prof.active: %s\n",
             r ? "error" : bactive ? "true" : "false");
    bactive_size = sizeof(bactive);
    r = mallctl("prof.thread_active_init", &bactive, &bactive_size, NULL, 0);
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "prof.thread_active_init: %s\n",
             r ? "error" : bactive ? "true" : "false");
    *result_str = buf;
    if (ctx) {
      mtev_http_response_appendf(ctx, buf);
      mtev_http_response_end(ctx);
    }
  }
  return NULL;
}

int
mtev_rest_heap_profiler_handler(mtev_http_rest_closure_t *restc, int npats, char **pats) 
{
  (void)npats;
  (void)pats;
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

  mtev_boolean active = mtev_false;
  mtev_boolean active_present = mtev_false;
  mtev_boolean dump = mtev_false;
  void *value;
  if (mtev_hash_retrieve(h, "active", strlen("active"), &value)) {
    active = strcmp((char *)value, "true") == 0;
    active_present = mtev_true;
  }
  if (mtev_hash_retrieve(h, "trigger_dump", strlen("trigger_dump"), &value)) {
    dump = strcmp((char *)value, "true") == 0;
  }

  char *result_str = NULL;
  error_str = mtev_heap_profile(ctx, active_present, active, dump, &result_str, NULL);
  if (!error_str) {
    return 0;
  }

 error:
  mtev_http_response_server_error(ctx, "text/plain");
  mtev_http_response_append_str(ctx, error_str);
  mtev_http_response_end(ctx);
  return 0;
}


void mtev_heap_profiler_init(void)
{
  mallctl = 
#ifdef RTLD_DEFAULT
  dlsym(RTLD_DEFAULT, "mallctl");
#else
  dlsym(NULL, "mallctl");
#endif
  if (mallctl) jemalloc_loaded = mtev_true;
  else jemalloc_loaded = mtev_false;
}

void mtev_heap_profiler_rest_init(void)
{
  mtev_heap_profiler_init();
  mtevAssert(mtev_http_rest_register_auth(
                 "GET", "/mtev/", "^heap_profile$", mtev_rest_heap_profiler_handler,
                 mtev_http_rest_client_cert_auth) == 0);
}
