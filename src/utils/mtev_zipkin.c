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
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_time.h"
#include "mtev_zipkin.h"
#include "mtev_getip.h"
#include "mtev_rand.h"
#include "eventer/eventer.h"
#include "mtev_zipkin_encode.h"

#include <ctype.h>
#include <string.h>

const char *ZIPKIN_SPAN_KIND = "span.kind";
const char *ZIPKIN_INTERNAL = "internal";
const char *ZIPKIN_MTEV_EVENTER_MASK = "eventer.mask";
const char *ZIPKIN_MTEV_EVENTER_RMASK = "eventer.return";
const char *ZIPKIN_MTEV_EVENTER_THREAD = "eventer.thread";
const char *ZIPKIN_INTERNAL_START = "internal_start";
const char *ZIPKIN_INTERNAL_DONE = "internal_done";
const char *ZIPKIN_CLIENT_SEND = "cs";
const char *ZIPKIN_CLIENT_SEND_DONE = "cs_done";
const char *ZIPKIN_CLIENT_RECV = "cr";
const char *ZIPKIN_CLIENT_RECV_DONE = "cr_done";
const char *ZIPKIN_SERVER_SEND = "ss";
const char *ZIPKIN_SERVER_SEND_DONE = "ss_done";
const char *ZIPKIN_SERVER_RECV = "sr";
const char *ZIPKIN_SERVER_RECV_DONE = "sr_done";

inline bool mtev_zipkin_span_logs_attached(Zipkin_Span *span) {
  if(span) return span->mtevlogging;
  return false;
}

void mtev_zipkin_span_rename(Zipkin_Span *span, const char *name, bool copy) {
  if(span == NULL) return;
  if(span->name.needs_free) free(span->name.value);
  span->name.needs_free = copy;
  span->name.value = copy ? strdup(name) : (char *)name;
}

/* This isn't API exposed, but it is not static for testing purposes.
 * zipkin will "turn on" automatically if there is a publishing hook.
 */
static double ze_new_trace_probability = 0.0;
static double ze_parented_trace_probability = 1.0;
static double ze_debug_trace_probability = 1.0;

MTEV_HOOK_IMPL(zipkin_publish,
  (int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
  void *, closure,
  (void *closure, int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
  (closure,traceid,spanid,buffer,len))

MTEV_HOOK_IMPL(zipkin_publish_span,
  (Zipkin_Span *span),
  void *, closure,
  (void *closure, Zipkin_Span *span),
  (closure,span))


/* Exposed Implementation */

int64_t
mtev_zipkin_timeval_to_timestamp(struct timeval *tv) {
  int64_t timestamp;
  timestamp = tv->tv_sec * 1000000L;
  timestamp += tv->tv_usec;
  return timestamp;
}

size_t
mtev_zipkin_encode(byte *buffer, size_t len, Zipkin_Span *span) {
  size_t sofar = 0;
  ADV_SAFE(ze_Zipkin_Span(buffer, len, span));
  return sofar;
}

size_t
mtev_zipkin_encode_list(byte *buffer, size_t len, Zipkin_Span **spans, int cnt) {
  size_t sofar = 0;
  ADV_SAFE(ze_Zipkin_Span_List(buffer, len, spans, cnt));
  return sofar;
}

static Zipkin_Endpoint ze_global_default_endpoint = {
  .service_name = { .value = "mtev", .needs_free = false }
};
void
mtev_zipkin_default_service_name(const char *service_name, bool service_name_copy) {
  char *tofree = NULL;
  if(ze_global_default_endpoint.service_name.needs_free)
    tofree = ze_global_default_endpoint.service_name.value;
  ze_global_default_endpoint.service_name.needs_free = service_name_copy;
  ze_global_default_endpoint.service_name.value =
    service_name_copy ? strdup(service_name) : (char *)service_name;
  free(tofree);
}

void
mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy,
                             struct in_addr host, unsigned short port) {
  ze_update_Zipkin_Endpoint(&ze_global_default_endpoint,
                            service_name, service_name_copy, host, port);
}

bool
mtev_zipkin_span_get_ids(Zipkin_Span *span, int64_t *tid, int64_t *pid, int64_t *sid) {
  if(tid) *tid = span->trace_id;
  if(pid && span->parent_id) *pid = *(span->parent_id);
  if(sid) *sid = span->id;
  return span->parent_id != NULL;
}
Zipkin_Span *
mtev_zipkin_span_new(int64_t *trace_id,
                     int64_t *parent_span_id, int64_t *span_id,
                     const char *name, bool name_copy,
                     bool *debug, bool force) {
  int64_t my_trace_id = 0, my_span_id = 0;
  Zipkin_Span *span;

  if(!force && debug && *debug) {
    if(ze_debug_trace_probability != 1.0 &&
       /* coverity[DC.WEAK_CRYPTO] */ drand48() > ze_debug_trace_probability) return NULL;
    force = true;
  }

  if(!trace_id) {
    if(!force && ze_new_trace_probability != 1.0 &&
       /* coverity[DC.WEAK_CRYPTO] */ drand48() > ze_new_trace_probability) return NULL;

    my_trace_id = ze_get_traceid();
    trace_id = &my_trace_id;
    /* Without a trace_id passed, it makes no sense to respect the span ids */
    parent_span_id = span_id = NULL;
    force = true;
  }

  if(parent_span_id && !span_id) {
    /* A newspan is being requested, let's get one */
    my_span_id = ze_get_traceid();
    span_id = &my_span_id;
  }

  if(!span_id) {
    /* Makes no sense to have a parent specified without a span id */
    parent_span_id = NULL;
    span_id = trace_id;
  }

  if(parent_span_id) {
    if(!force && ze_parented_trace_probability != 1.0 &&
       /* coverity[DC.WEAK_CRYPTO] */ drand48() > ze_parented_trace_probability) return NULL;
  }

  span = calloc(1, sizeof(*span));
  span->refcnt = 1;
  struct timeval nowtv;
  mtev_gettimeofday(&nowtv,NULL);
  span->timestamp = mtev_zipkin_timeval_to_timestamp(&nowtv);
  span->name.value = name_copy ? strdup(name) : (char *)name;
  span->name.needs_free = name_copy;
  span->trace_id = *trace_id;
  if(parent_span_id) {
    span->_parent_id = *parent_span_id;
    span->parent_id = &span->_parent_id;
  }
  span->id = *span_id;
  if(debug) {
    span->_debug = *debug;
    span->debug = &span->_debug;
  }
  memcpy(&span->_default_host, &ze_global_default_endpoint,
         sizeof(Zipkin_Endpoint));
  span->_default_host.service_name.needs_free = false;
  return span;
}

void
mtev_zipkin_span_ref(Zipkin_Span *span) {
  ck_pr_inc_32(&span->refcnt);
}

void
mtev_zipkin_span_drop(Zipkin_Span *span) {
  if(!span) return;
  bool zero;
  ck_pr_dec_32_zero(&span->refcnt, &zero);
  if(!zero) return;
  if(span->name.needs_free && span->name.value) free(span->name.value);
  while(span->annotations) {
    Zipkin_List_Zipkin_Annotation *node = span->annotations;
    Zipkin_Annotation *a = &node->data;
    if(a->value.needs_free && a->value.value) free(a->value.value);
    if(a->_host.service_name.needs_free && a->_host.service_name.value) {
      free(a->_host.service_name.value);
    }
    span->annotations = node->next;
    free(node);
  }
  while(span->binary_annotations) {
    Zipkin_List_Zipkin_BinaryAnnotation *node = span->binary_annotations;
    Zipkin_BinaryAnnotation *a = &node->data;
    if(a->key.needs_free && a->key.value) free(a->key.value);
    if(a->value.needs_free && a->value.value) free(a->value.value);
    if(a->_host.service_name.needs_free && a->_host.service_name.value) {
      free(a->_host.service_name.value);
    }
    span->binary_annotations = node->next;
    free(node);
  }
  if(span->_default_host.service_name.needs_free &&
     span->_default_host.service_name.value) {
    free(span->_default_host.service_name.value);
  }
  free(span);
}

void
mtev_zipkin_span_publish(Zipkin_Span *span) {
  if(!span) return;

  if(zipkin_publish_span_hook_exists()) {
    zipkin_publish_span_hook_invoke(span);
  }
  if(zipkin_publish_hook_exists()) {
    unsigned char *buffer, hopeful[4192], *allocd = NULL;
    size_t len;
    int64_t traceid, spanid;

    len = mtev_zipkin_encode(hopeful,sizeof(hopeful),span);
    if(len <= sizeof(hopeful)) buffer = hopeful;
    else {
      size_t expected_len = len;
      allocd = malloc(expected_len);
      if(!allocd) {
        mtevL(mtev_error, "mtev_zipkin_span_publish malloc(%zu) failed\n",
              expected_len);
        return;
      }
      len = mtev_zipkin_encode(allocd,expected_len,span);
      if(len > expected_len) {
        mtevL(mtev_error, "mtev_zipkin_span_publish short buffer %zu > %zu\n",
              len, expected_len);
        free(allocd);
        return;
      }
      buffer = allocd;
    }
    traceid = span->trace_id;
    spanid = span->id;
    mtev_zipkin_span_drop(span);

    zipkin_publish_hook_invoke(traceid, spanid, buffer, len);
    if(allocd) free(allocd);
    return;
  }
  mtev_zipkin_span_drop(span);
}

void
mtev_zipkin_span_default_endpoint(Zipkin_Span *span, const char *service_name,
                                  bool service_name_copy,
                                  struct in_addr host, unsigned short port) {
  if(!span) return;
  ze_update_Zipkin_Endpoint(&span->_default_host,
                            service_name, service_name_copy,
                            host, port);
}

Zipkin_Annotation *
mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp_in,
                          const char *value, bool value_copy) {
  Zipkin_List_Zipkin_Annotation *node;
  Zipkin_Annotation *a;
  int64_t timestamp;

  if(!span) return NULL;

  node = calloc(1, sizeof(*node));
  a = &node->data;

  if(timestamp_in) {
    timestamp = *timestamp_in;
  } else {
    struct timeval nowtv;
    mtev_gettimeofday(&nowtv,NULL);
    timestamp = mtev_zipkin_timeval_to_timestamp(&nowtv);
  }
  a->timestamp = timestamp;

  /* coerce the span's timestamp to the earliest we see */
  if(span->timestamp == 0 || a->timestamp < span->timestamp)
    span->timestamp = a->timestamp;
  /* set the duration of the span to the largest spread */
  if(span->timestamp != 0 && a->timestamp > span->timestamp) {
    int64_t ndur = a->timestamp - span->timestamp;
    if(ndur > span->duration) span->duration = ndur;
  }

  a->value.needs_free = value_copy;
  a->value.value = value_copy ? strdup(value) : (char *)value;
  a->host = &span->_default_host;

  node->next = span->annotations;
  span->annotations = node;
  return a;
}

void
mtev_zipkin_annotation_set_endpoint(Zipkin_Annotation *annotation,
                                    const char *service_name,
                                    bool service_name_copy,
                                    struct in_addr host, unsigned short port) {
  if(!annotation) return;
  ze_update_Zipkin_Endpoint(&annotation->_host,
                            service_name, service_name_copy, host, port);
  annotation->host = &annotation->_host;
}

Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate(Zipkin_Span *span, Zipkin_AnnotationType atype,
                           const char *key, bool key_copy,
                           const void *value, int32_t value_len, bool value_copy) {
  Zipkin_List_Zipkin_BinaryAnnotation *node;
  Zipkin_BinaryAnnotation *a;

  if(!span) return NULL;

  node = calloc(1, sizeof(*node));
  a = &node->data;

  a->annotation_type = atype;
  a->key.needs_free = key_copy;
  a->key.value = key_copy ? strdup(key) : (char *)key;

  a->value.len = value_len;
  if(value_copy && value_len <= (int32_t)sizeof(a->value.data)) {
    /* common encoding no-alloc path for up to N bytes */
    memcpy(a->value.data, value, value_len);
    a->value.value = a->value.data;
    a->value.needs_free = false;
  }
  else {
    /* Normal path where in we conditionally make a copy */
    a->value.needs_free = value_copy;
    if(value_copy) {
      a->value.value = malloc(value_len);
      memcpy(a->value.value, value, value_len);
    }
    else {
      a->value.value = (void *)value;
    }
  }

  node->next = span->binary_annotations;
  span->binary_annotations = node;
  return a;
}

Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_str(Zipkin_Span *span,
                               const char *key, bool key_copy,
                               const char *val, bool val_copy) {
  return mtev_zipkin_span_bannotate(span, ZIPKIN_STRING, key, key_copy, val, strlen(val), val_copy);
}

Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_i32(Zipkin_Span *span,
                               const char *key, bool key_copy, int32_t v) {
  int32_t vnet = htonl(v);
  return mtev_zipkin_span_bannotate(span, ZIPKIN_I32, key, key_copy, &vnet, 4, true);
}

Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_i64(Zipkin_Span *span,
                               const char *key, bool key_copy, int64_t v) {
  int64_t vnet = htonll(v);
  return mtev_zipkin_span_bannotate(span, ZIPKIN_I64, key, key_copy, &vnet, 8, true);
}

Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_double(Zipkin_Span *span,
                                  const char *key, bool key_copy, double v) {
  double foo = v;
  int64_t *fooi64 = (int64_t *)&foo;
  *fooi64 = htonll(*fooi64);
  return mtev_zipkin_span_bannotate(span, ZIPKIN_I64, key, key_copy, fooi64, 8, true);
}

void
mtev_zipkin_span_attach_logs(Zipkin_Span *span, bool on) {
  if(!span) return;
  span->mtevlogging = on;
}

void
mtev_zipkin_bannotation_set_endpoint(Zipkin_BinaryAnnotation *annotation,
                                     const char *service_name,
                                     bool service_name_copy,
                                     struct in_addr host, unsigned short port) {
  if(!annotation) return;
  ze_update_Zipkin_Endpoint(&annotation->_host,
                            service_name, service_name_copy, host, port);
  annotation->host = &annotation->_host;
}

void
mtev_zipkin_sampling(double new_traces, double parented_traces,
	     double debug_traces) {
  if(ze_new_trace_probability != new_traces)
    mtevL(mtev_debug, "Zipkin new trace sampling: %0.2f%%\n",
          100.0*new_traces);
  ze_new_trace_probability = new_traces;
  if(ze_parented_trace_probability != parented_traces)
    mtevL(mtev_debug, "Zipkin parented trace sampling: %0.2f%%\n",
          100.0*parented_traces);
  ze_parented_trace_probability = parented_traces;
  if(ze_debug_trace_probability != debug_traces)
    mtevL(mtev_debug, "Zipkin debug trace sampling: %0.2f%%\n",
          100.0*debug_traces);
  ze_debug_trace_probability = debug_traces;
}

void
mtev_zipkin_get_sampling(double *new_traces, double *parented_traces,
	                 double *debug_traces) {
  if(new_traces) *new_traces = ze_new_trace_probability;
  if(parented_traces) *parented_traces = ze_parented_trace_probability;
  if(debug_traces) *debug_traces = ze_debug_trace_probability;
}

int64_t *
mtev_zipkin_str_to_id(const char *orig_in, int64_t *buf) {
  uint64_t out;
  const char *in = orig_in;
  char *end;
  if(!in) return NULL;
  while(*in && isspace(*in)) in++;
  if(in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) in += 2;
  if(*in == '\0') return NULL;
  out = strtoull(in, &end, 16);
  if(*end != '\0' && !isspace(*end)) return NULL;
  *buf = *((int64_t *)&out);
  return buf;
}

/* This adds context to the eventer systems */

typedef struct {
  mtev_zipkin_event_trace_level_t trace_events;
  bool my_span;
  Zipkin_Span *parent_span;
  Zipkin_Span *span;
  Zipkin_Span *client;
} zipkin_eventer_ctx_t;

static int zipkin_aco_ctx_idx = -1;
static int zipkin_ctx_idx = -1;
static mtev_zipkin_event_trace_level_t zipkin_trace_events;
static const char *generic_eventer_callback_name = "eventer_callback";
static inline zipkin_eventer_ctx_t *get_my_ctx(eventer_t e) {
  if(zipkin_ctx_idx < 0) return NULL;
  if(e == NULL) e = eventer_get_this_event();
  return eventer_get_context(e, zipkin_ctx_idx);
}
static void zipkin_eventer_ctx_free(zipkin_eventer_ctx_t *ctx) {
  if(ctx == NULL) return;
  if(ctx->span) {
    if(ctx->my_span) {
      mtev_zipkin_span_annotate(ctx->span, NULL, ZIPKIN_INTERNAL_DONE, false);
      mtev_zipkin_span_bannotate_str(ctx->span, ZIPKIN_SPAN_KIND, false, ZIPKIN_INTERNAL, false);
      mtev_zipkin_span_publish(ctx->span);
    } else {
      mtev_zipkin_span_drop(ctx->span);
    }
  }
  mtev_zipkin_span_drop(ctx->parent_span);
  mtev_zipkin_span_drop(ctx->client);
  free(ctx);
}

Zipkin_Span *mtev_zipkin_active_span(eventer_t e) {
  zipkin_eventer_ctx_t *ctx = NULL;
  if(aco_get_co() && zipkin_aco_ctx_idx >= 0) {
    ctx = aco_tls(aco_get_co(), zipkin_aco_ctx_idx);
  }
  if(!ctx) ctx = get_my_ctx(e);
  if(ctx) return ctx->span ? ctx->span : ctx->parent_span;
  return NULL;
}

Zipkin_Span *mtev_zipkin_client_span(eventer_t e) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  return ctx ? ctx->client : NULL;
}
bool mtev_zipkin_client_sampled_hdr(eventer_t e, char *buf, size_t len) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client && ctx->client->debug && *ctx->client->debug) {
    int rv = snprintf(buf, len, HEADER_ZIPKIN_SAMPLED ": 1");
    if(rv > 0 && (size_t)rv < len) return true;
  }
  return false;
}
bool mtev_zipkin_client_trace_hdr(eventer_t e, char *buf, size_t len) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client) {
    int rv = snprintf(buf, len, HEADER_ZIPKIN_TRACEID ": 0x%" PRIx64,
                      ctx->client->trace_id);
    if(rv > 0 && (size_t)rv < len) return true;
  }
  return false;
}
bool mtev_zipkin_client_parent_hdr(eventer_t e, char *buf, size_t len) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client && ctx->client->parent_id) {
    int rv = snprintf(buf, len, HEADER_ZIPKIN_PARENTSPANID ": 0x%" PRIx64,
                      *ctx->client->parent_id);
    if(rv > 0 && (size_t)rv < len) return true;
  }
  return false;
}
bool mtev_zipkin_client_span_hdr(eventer_t e, char *buf, size_t len) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client) {
    int rv = snprintf(buf, len, HEADER_ZIPKIN_SPANID ": 0x%" PRIx64,
                      ctx->client->id);
    if(rv > 0 && (size_t)rv < len) return true;
  }
  return false;
}
void
mtev_zipkin_client_new(eventer_t e, const char *name, bool name_copy) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(!ctx) return;
  Zipkin_Span *parent = ctx->span ? ctx->span : ctx->parent_span; 
  if(!parent) return;
  if(ctx->client) {
    /* close it up */
    mtev_zipkin_span_drop(ctx->client);
    ctx->client = NULL;
  }
  ctx->client = mtev_zipkin_span_new(
    &parent->trace_id, &parent->id, NULL, name, name_copy, parent->debug, false
  );
  if(ctx->client)
    ctx->client->mtevlogging = parent->mtevlogging;
  return;
}
void mtev_zipkin_client_drop(eventer_t e) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client) {
    mtev_zipkin_span_drop(ctx->client);
    ctx->client = NULL;
  }
}
void mtev_zipkin_client_publish(eventer_t e) {
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx && ctx->client) {
    mtev_zipkin_span_publish(ctx->client);
    ctx->client = NULL;
  }
}
static zipkin_eventer_ctx_t *
mtev_zipkin_new_ctx(Zipkin_Span *span, const char *cbname, bool new_child, mtev_zipkin_event_trace_level_t *track) {
  zipkin_eventer_ctx_t *ctx = calloc(1, sizeof(*ctx));
  ctx->trace_events = track ? *track : zipkin_trace_events;
  if(new_child) {
    if(cbname == NULL) cbname = generic_eventer_callback_name;
    ctx->span = mtev_zipkin_span_new(
       &span->trace_id, &span->id, NULL, cbname, true, span->debug, false
    );
    if(ctx->span) ctx->span->mtevlogging = span->mtevlogging;
    ctx->my_span = true;
    mtev_zipkin_span_annotate(ctx->span, NULL, ZIPKIN_INTERNAL_START, false);
  } else {
    ctx->span = span;
    mtev_zipkin_span_ref(span);
  }
  return ctx;
}
void mtev_zipkin_attach_to_aco(Zipkin_Span *span, bool new_child, mtev_zipkin_event_trace_level_t *track) {
  if(zipkin_aco_ctx_idx < 0) return;
  mtevAssert(aco_get_co());
  zipkin_eventer_ctx_t *ctx = aco_tls(aco_get_co(), zipkin_aco_ctx_idx);
  if(ctx) zipkin_eventer_ctx_free(ctx);
  if(span) {
    ctx = mtev_zipkin_new_ctx(span, NULL, new_child, track);
  } else {
    ctx = NULL;
  }
  aco_tls(aco_get_co(), zipkin_aco_ctx_idx) = ctx;
}
void mtev_zipkin_attach_to_eventer(eventer_t e, Zipkin_Span *span, bool new_child, mtev_zipkin_event_trace_level_t *track) {
  if(!span) return;
  zipkin_eventer_ctx_t *ctx = get_my_ctx(e);
  if(ctx) zipkin_eventer_ctx_free(ctx);
  const char *cbname = NULL;
  if(new_child) eventer_name_for_callback_e(eventer_get_callback(e), e);
  ctx = mtev_zipkin_new_ctx(span, cbname, new_child, track);
  eventer_set_context(e, zipkin_ctx_idx, ctx);
}
void zipkin_eventer_callback_prep(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)closure;
  zipkin_eventer_ctx_t *ctx;
  if(zipkin_ctx_idx < 0) return;
  ctx = eventer_get_context(e, zipkin_ctx_idx);
  if(!ctx || !ctx->parent_span) return;
  int64_t ts = mtev_zipkin_timeval_to_timestamp(now);
  if(ctx->trace_events != ZIPKIN_TRACE_EVENT_CALLBACKS) return;

  const char *cbname = eventer_name_for_callback_e(eventer_get_callback(e), e);
  if(cbname == NULL) cbname = generic_eventer_callback_name;
  ctx->span = mtev_zipkin_span_new(
     &ctx->parent_span->trace_id, &ctx->parent_span->id, NULL,
     cbname, true, ctx->parent_span->debug, false
  );
  if(ctx->span) ctx->span->mtevlogging = ctx->parent_span->mtevlogging;
  ctx->my_span = true;
  mtev_zipkin_span_annotate(ctx->span, &ts, ZIPKIN_INTERNAL_START, false);
  mtev_zipkin_span_bannotate_str(ctx->span, ZIPKIN_MTEV_EVENTER_THREAD, false, eventer_get_thread_name(), true);
  mtev_zipkin_span_bannotate_i32(ctx->span, ZIPKIN_MTEV_EVENTER_MASK, false, mask);
}
void zipkin_eventer_callback_cleanup(eventer_t e, int mask) {
  zipkin_eventer_ctx_t *ctx;
  if(zipkin_ctx_idx < 0) return;
  ctx = eventer_get_context(e, zipkin_ctx_idx);
  if(!ctx || !ctx->parent_span) return;
  if(ctx->trace_events != ZIPKIN_TRACE_EVENT_CALLBACKS) return;
  if(!ctx->my_span) return;
  mtev_zipkin_span_bannotate_i32(ctx->span, ZIPKIN_MTEV_EVENTER_RMASK, false, mask);
  mtev_zipkin_span_annotate(ctx->span, NULL, ZIPKIN_INTERNAL_DONE, false);
  mtev_zipkin_span_bannotate_str(ctx->span, ZIPKIN_SPAN_KIND, false, ZIPKIN_INTERNAL, false);
  mtev_zipkin_span_publish(ctx->span);
  ctx->my_span = false;
  ctx->span = NULL;
}
static eventer_t zipkin_eventer_init(eventer_t e) {
  zipkin_eventer_ctx_t *pctx = NULL, *ctx;
  if(zipkin_aco_ctx_idx >= 0 && aco_get_co()) {
    pctx = aco_tls(aco_get_co(), zipkin_aco_ctx_idx);
  }
  if(!pctx) {
    eventer_t parent;
    if(zipkin_ctx_idx < 0) return e;
    if(NULL == (parent = eventer_get_this_event())) return e;
    if(NULL == (pctx = eventer_get_context(parent, zipkin_ctx_idx))) return e;
  }

  if(pctx->span) mtev_zipkin_span_ref(pctx->span);

  ctx = calloc(1, sizeof(*ctx));
  ctx->trace_events = pctx->trace_events;
  if(pctx->span && ctx->trace_events == ZIPKIN_TRACE_EVENT_LIFETIME) {
    ctx->span = mtev_zipkin_span_new(&pctx->span->trace_id,
                                     &pctx->span->id, NULL,
                                     generic_eventer_callback_name, false,
                                     pctx->span->debug, false);
    if(ctx->span) ctx->span->mtevlogging = pctx->span->mtevlogging;
    mtev_zipkin_span_annotate(ctx->span, NULL, ZIPKIN_INTERNAL_START, false);
    ctx->my_span = true;
    mtev_zipkin_span_drop(pctx->span);
  } else if(ctx->trace_events == ZIPKIN_TRACE_EVENT_CALLBACKS) {
    ctx->parent_span = pctx->span;
  } else {
    ctx->span = pctx->span;
  }
  eventer_set_context(e, zipkin_ctx_idx, ctx);
  return e;
}
static void zipkin_eventer_deinit(eventer_t e) {
  zipkin_eventer_ctx_t *ctx;
  if(zipkin_ctx_idx < 0) return;
  ctx = eventer_get_context(e, zipkin_ctx_idx);
  if(ctx && ctx->my_span) {
    const char *cbname = eventer_name_for_callback(eventer_get_callback(e));
    if(cbname && !strcmp(generic_eventer_callback_name, ctx->span->name.value)) {
      if(ctx->span->name.needs_free) free(ctx->span->name.value);
      ctx->span->name.value = strdup(cbname);
      ctx->span->name.needs_free = true;
    }
  }
  zipkin_eventer_ctx_free(ctx);
}
static void zipkin_eventer_copy(eventer_t tgt, const eventer_t src) {
  zipkin_eventer_ctx_t *tgt_ctx, *src_ctx;
  if(zipkin_ctx_idx < 0) return;
  src_ctx = eventer_get_context(src, zipkin_ctx_idx);
  if(!src_ctx) return;
  tgt_ctx = calloc(1, sizeof(*tgt_ctx));
  memcpy(tgt_ctx, src_ctx, sizeof(*tgt_ctx));
  src_ctx->my_span = false;
  if(tgt_ctx->span) mtev_zipkin_span_ref(tgt_ctx->span);
  if(tgt_ctx->parent_span) mtev_zipkin_span_ref(tgt_ctx->parent_span);
  if(tgt_ctx->client) mtev_zipkin_span_ref(tgt_ctx->client);
  eventer_set_context(tgt, zipkin_ctx_idx, tgt_ctx);
}
eventer_context_opset_t zipkin_eventer_context_ops = {
  .eventer_t_init = zipkin_eventer_init,
  .eventer_t_deinit = zipkin_eventer_deinit,
  .eventer_t_copy = zipkin_eventer_copy,
  .eventer_t_callback_prep = zipkin_eventer_callback_prep,
  .eventer_t_callback_cleanup = zipkin_eventer_callback_cleanup
};

void mtev_zipkin_event_trace_level(mtev_zipkin_event_trace_level_t lvl) {
  zipkin_trace_events = lvl;
  switch(zipkin_trace_events) {
    case ZIPKIN_TRACE_EVENT_LIFETIME:
      mtevL(mtev_notice, "zipkin tracing of eventer_t lifetimes.\n");
      break;
    case ZIPKIN_TRACE_EVENT_CALLBACKS:
      mtevL(mtev_notice, "zipkin tracing of eventer_t callbacks.\n");
      break;
    default: break;
  }
}
void mtev_zipkin_eventer_init(void) {
  if(zipkin_ctx_idx >= 0) return;
  zipkin_ctx_idx = eventer_register_context("zipkin", &zipkin_eventer_context_ops);
  mtevL(mtev_debug, "distributed tracing contexts %s\n",
        (zipkin_ctx_idx < 0) ? "failed to register" : "registered");

  zipkin_aco_ctx_idx = aco_tls_assign_idx();

  struct in_addr remote, local;
  memset(&remote, 8, sizeof(remote)); /* 8.8.8.8 */
  mtev_getip_ipv4(remote, &local);
  mtev_zipkin_default_endpoint(NULL, false, local, 0);
}
