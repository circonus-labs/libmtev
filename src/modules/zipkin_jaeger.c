/*
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mtev_defines.h"
#include "mtev_zipkin.h"
#include "mtev_b64.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"

#include "zipkin_jaeger.xmlh"

#include <curl/curl.h>

#define MAX_HALF_SLEEP_US 64000 /* 128ms / 2 */

static char *zc_host = "127.0.0.1";
static unsigned short zc_port = 14268;
static uint32_t zc_period = 500;
static uint32_t zc_max_batch = 500;
static uint32_t zc_backlog = 5000;
static uint32_t zc_retries = 0;
static uint32_t zc_timeout_ms = 5000;
static uint32_t zc_connect_timeout_ms = 1000;
static pthread_t zc_tid;
static mtev_log_stream_t debugls = NULL;
static mtev_log_stream_t errorls = NULL;

struct span_list {
  Zipkin_Span *span;
  struct span_list *next;
};

static pthread_mutex_t todo_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static int todo_queue_size;
static struct span_list *todo_queue_head, *todo_queue_tail;

static void todo_enqueue(Zipkin_Span *span) {
  struct span_list *newnode = NULL;
  if(todo_queue_size > zc_backlog) return;
 
  newnode = calloc(1, sizeof(*newnode)); 
  pthread_mutex_lock(&todo_queue_lock);
  if(todo_queue_size < zc_backlog) {
    mtev_zipkin_span_ref(span);
    newnode->span = span;
    if(!todo_queue_head) todo_queue_head = todo_queue_tail = newnode;
    else {
      todo_queue_tail->next = newnode;
      todo_queue_tail = newnode;
    }
    todo_queue_size++;
    newnode = NULL;
  }
  pthread_mutex_unlock(&todo_queue_lock);
  free(newnode);
}
static Zipkin_Span *todo_dequeue(void) {
  Zipkin_Span *span = NULL;
  if(todo_queue_head == NULL) return NULL;
  pthread_mutex_lock(&todo_queue_lock);
  if(todo_queue_head != NULL) {
    struct span_list *tofree = todo_queue_head;
    span = todo_queue_head->span;
    todo_queue_head = todo_queue_head->next;
    free(tofree);
    if(todo_queue_head == NULL) todo_queue_tail = NULL;
  }
  pthread_mutex_unlock(&todo_queue_lock);
  return span;
}

static mtev_hook_return_t
zipkin_jaeger_queue(void *closure, Zipkin_Span *span) {
  todo_enqueue(span);
  return MTEV_HOOK_CONTINUE;
}

static size_t
debug_writefile(void *b, size_t s, size_t n, FILE *v) {
  mtevL(debugls, "%.*s\n", (int)(s*n), (char *)b);
  return s*n;
}
static int
jaeger_publish_thrift(unsigned char *buff, size_t buflen, uint32_t retries) {
  CURLcode code;
  long httpcode;
  static CURL *curl;
  char error[CURL_ERROR_SIZE];

  if(!curl) {
    char url[1024];
    struct curl_slist *headers=NULL;
    snprintf(url, sizeof(url), "http://%s:%d/api/traces?format=zipkin.thrift", zc_host, zc_port);
    headers = curl_slist_append(headers, "Content-Type: application/x-thrift");
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, debug_writefile);
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 131072);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, zc_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, zc_connect_timeout_ms);
  }
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void *)buff);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, buflen);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);

  do {
    error[0] = '\0';
    httpcode = 0;
    code = curl_easy_perform(curl);
    if(CURLE_OK == code)
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
  } while(retries > 0 && (httpcode < 200 || httpcode > 299));
  if(httpcode < 200 || httpcode > 299) {
    mtevL(errorls, "zipkin submit to jaeger failed: %s\n", error);
    return -1;
  }
  return 0;
}

static void *
zipking_jaeger_submitter(void *unused) {
  unsigned char *buff;
  size_t buflen;
  (void)unused;
  Zipkin_Span **spans = calloc(zc_max_batch, sizeof(*spans));
  mtev_hrtime_t last_submit = mtev_gethrtime(), now, trigger_time;
  int sleep_time = 1000;

  buflen = 128*1024;
  buff = malloc(buflen);
  trigger_time = last_submit + zc_period * 1000000ULL;
  while(1) {
    size_t len;
    int i, cnt = 0;
    while(1) {
      while(cnt < zc_max_batch && NULL != (spans[cnt] = todo_dequeue())) cnt++;
      if(cnt >= zc_max_batch || (now = mtev_gethrtime()) >= trigger_time) break;
      usleep(sleep_time);
      if(sleep_time <= MAX_HALF_SLEEP_US) sleep_time += sleep_time;
    }
    if(cnt == 0) {
      last_submit = mtev_gethrtime();
      trigger_time = last_submit + zc_period * 1000000ULL;
      continue;
    }
    sleep_time = 1000;

    len = mtev_zipkin_encode_list(buff, buflen, spans, cnt);
    if(len > buflen) {
      free(buff);
      buflen = len;
      buff = malloc(buflen);
      len = mtev_zipkin_encode_list(buff, buflen, spans, cnt);
    }
    if(len > buflen) {
      mtevL(errorls, "zipkin jaeger publisher buffer %zu > %zu\n", len, buflen);
    } else {
      last_submit = mtev_gethrtime();
      trigger_time = last_submit + zc_period * 1000000ULL;
      if(jaeger_publish_thrift(buff, len, zc_retries) == 0) {
        mtevL(debugls, "zipkin published %d spans to jaeger\n", cnt);
      }
    }
    for(i=0; i<cnt; i++) {
      mtev_zipkin_span_drop(spans[i]);
    }
  }
  /* UNREACHABLE */
  return NULL;
}

#define RCONFSTR(a) do { \
  const char *vstr; \
  if(mtev_hash_retr_str(options, #a, strlen(#a), &vstr)) { \
    zc_##a = strdup(vstr); \
  } \
} while(0)
#define RCONFINT(a) do { \
  const char *vstr; \
  if(mtev_hash_retr_str(options, #a, strlen(#a), &vstr)) { \
    zc_##a = atoi(vstr); \
  } \
} while(0)

static int
zipkin_jaeger_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  RCONFSTR(host);
  RCONFINT(port);
  RCONFINT(period);
  RCONFINT(backlog);
  RCONFINT(max_batch);
  RCONFINT(retries);
  return 0;
}

static int
zipkin_jaeger_driver_init(mtev_dso_generic_t *img) {
  pthread_attr_t tattr;
  pthread_attr_init(&tattr);
  pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
  pthread_create(&zc_tid, &tattr, zipking_jaeger_submitter, NULL);

  debugls = mtev_log_stream_find("debug/zipkin_jaeger");
  errorls = mtev_log_stream_find("error/zipkin_jaeger");
  zipkin_publish_span_hook_register("jaeger", zipkin_jaeger_queue, NULL);
  return 0;
}

mtev_dso_generic_t zipkin_jaeger = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "zipkin_jaeger",
    .description = "A Jaeger publisher for zipkin traces",
    .xml_description = zipkin_jaeger_xml_description,
  },
  zipkin_jaeger_driver_config,
  zipkin_jaeger_driver_init
};
