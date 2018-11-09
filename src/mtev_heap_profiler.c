#include "mtev_heap_profiler.h"
#include "mtev_rest.h"

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

  if (active_present) {
    if (active) {
      bool bactive = true;
      int r = mallctl("prof.active", NULL, NULL, &bactive, sizeof(bool));
      if(r != 0) {
        error_str = strerror(r);
        goto error;
      }
      mtev_http_response_ok(ctx, "text/plain");
      mtev_http_response_append_str(ctx, "Profiling is activated\n");
    } else {
      bool bactive = false;
      int r = mallctl("prof.active", NULL, NULL, &bactive, sizeof(bool));
      if(r != 0) {
        error_str = strerror(r);
        goto error;
      }
      mtev_http_response_ok(ctx, "text/plain");
      mtev_http_response_append_str(ctx, "Profiling is deactivated\n");
    }
  } else if(dump) {
    char *name = malloc(PATH_MAX);
    snprintf(name, PATH_MAX, "/tmp/heap_profile.%d", getpid());
    mtevL(mtev_notice, "Dumping heap profile to file: %s\n", name);
    int r = mallctl("prof.dump", NULL, NULL, &name, sizeof(const char *));
    if(r != 0) {
      error_str = strerror(r);
      free(name);
      goto error;
    }
    mtevL(mtev_notice, "Dumping result: %d\n", r);
    int fd = open(name, O_RDONLY);
    unlink(name);
    free(name);
    if (fd >= 0) {
      struct stat s;
      if (fstat(fd, &s) == 0) {
        mtev_http_response_ok(ctx, "application/x-jemalloc-heap-profile");
        mtev_http_response_append_mmap(ctx, fd, s.st_size, MAP_SHARED, 0);
        close(fd);
      } else {
        close(fd);
        error_str = "Cannot fstat temp file\n";
        goto error;
      }
    } else {
      error_str = strerror(errno);
      goto error;
    }
  } else {
    int r;
    mtev_http_response_ok(ctx, "text/plain");
    bool bactive = false;
    size_t bactive_size = sizeof(bactive);
    r = mallctl("opt.prof", &bactive, &bactive_size, NULL, 0);
    mtev_http_response_appendf(ctx, "opt.prof: %s\n", r ? "error" : bactive ? "true" : "false");
    if(r == 0 && !bactive) {
      mtev_http_response_appendf(ctx, "# needs MALLOC_CONF=\"prof:true\"\n");
    }
    r = mallctl("prof.active", &bactive, &bactive_size, NULL, 0);
    mtev_http_response_appendf(ctx, "prof.active: %s\n", r ? "error" : bactive ? "true" : "false");
    r = mallctl("prof.thread_active_init", &bactive, &bactive_size, NULL, 0);
    mtev_http_response_appendf(ctx, "prof.thread_active_init: %s\n", r ? "error" : bactive ? "true" : "false");
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
