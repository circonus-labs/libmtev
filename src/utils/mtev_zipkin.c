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

#include <mtev_defines.h>
#include <mtev_log.h>
#include <mtev_hooks.h>
#include <mtev_time.h>
#include <mtev_zipkin.h>

#include <ctype.h>
#include <string.h>

const char *ZIPKIN_CLIENT_SEND = "cs";
const char *ZIPKIN_CLIENT_RECV = "cr";
const char *ZIPKIN_SERVER_SEND = "ss";
const char *ZIPKIN_SERVER_RECV = "sr";

#undef byte
#define byte unsigned char
#define ZE_STOP 0
#define ZE_BOOL 2
#define ZE_BYTE 3
#define ZE_DOUBLE 4
#define ZE_I16 6
#define ZE_I32 8
#define ZE_I64 10
#define ZE_STRING 11
#define ZE_STRUCT 12
#define ZE_LIST 15

/* This isn't API exposed, but it is not static for testing purposes.
 * zipkin will "turn on" automaticall if there is a publishing hook.
 */
static bool ze_enable_override = false;
void mtev_zipkin_enable(void) { ze_enable_override = true; }

static double ze_new_trace_probability = 0.0;
static double ze_parented_trace_probability = 1.0;
static double ze_debug_trace_probability = 1.0;

MTEV_HOOK_IMPL(zipkin_publish,
  (int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
  void *, closure,
  (void *closure, int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
  (closure,traceid,spanid,buffer,len))

static size_t
ze_bool(byte *buffer, size_t len, bool v) {
  if(len > 0) buffer[0] = v ? 1 : 0;
  return 1;
}
static size_t
ze_byte(byte *buffer, size_t len, byte v) {
  if(len > 0) buffer[0] = v;
  return 1;
}
static size_t
ze_i16(byte *buffer, size_t len, int16_t v) {
  if(len > 1) {
    int16_t nv = htons(v);
    memcpy(buffer, &nv, 2);
  }
  return 2;
}
static size_t
ze_i32(byte *buffer, size_t len, int32_t v) {
  if(len > 3) {
    int32_t nv = htonl(v);
    memcpy(buffer, &nv, 4);
  }
  return 4;
}
static size_t
ze_i64(byte *buffer, size_t len, int64_t v) {
  if(len > 7) {
    int64_t nv = htonll(v);
    memcpy(buffer, &nv, 8);
  }
  return 8;
}
/* static size_t */
/* ze_double(byte *buffer, size_t len, double v) { */
/*   if(len > 7) { */
/*     int64_t *in = (int64_t *)&v; */
/*     int64_t nv = htonll(*in); */
/*     memcpy(buffer, &nv, 8); */
/*   } */
/*   return 8; */
/* } */
static size_t
ze_list_begin(byte *buffer, size_t len, byte fieldtype, int32_t cnt) {
  if(len > 4) {
    ze_byte(buffer,len,fieldtype);
    ze_i32(buffer+1,len-1,cnt);
  }
  return 5;
}
#define ze_list_end(a,b) 0
#define ze_struct_begin(a,b,c) 0
#define ze_struct_end(a,b) 0
static size_t
ze_field_begin(byte *buffer, size_t len, const char *name,
               byte fieldtype, int16_t fieldid) {
  size_t sofar;
  if(len < 3) return 3;
  sofar = ze_byte(buffer, len, fieldtype);
  return sofar + ze_i16(buffer+1, len-1, fieldid);
}
#define ze_field_end(a,b) 0
#define ze_field_stop(a,b) ze_byte(a,b,ZE_STOP);
static size_t
ze_Zipkin_String(byte *buffer, size_t len, Zipkin_String *v) {
  size_t sofar;
  int32_t str_len = strlen(v->value);
  sofar = ze_i32(buffer, len, str_len);
  if(sofar + str_len > len) return sofar + str_len;
  memcpy(buffer + sofar, v->value, str_len);
  return sofar + str_len;
}
static size_t
ze_Zipkin_Binary(byte *buffer, size_t len, Zipkin_Binary *v) {
  size_t sofar;
  int32_t vlen = v->len;
  if(v->len < 0) vlen = 0;
  if(4 + vlen > len) return 4 + vlen;
  sofar = ze_i32(buffer, len, vlen);
  memcpy(buffer + sofar, v->value, vlen);
  return sofar + vlen;
}

#define ADV_SAFE(f) do { \
  size_t tlen = f; \
  if((tlen+sofar) < sofar) sofar = 0; /*overflow*/ \
  sofar += tlen; \
  if(sofar > len) len = 0; \
  else { \
    buffer += tlen; \
    len -= tlen; \
  } \
} while(0)
static size_t
ze_Zipkin_Endpoint(byte *buffer, size_t len, Zipkin_Endpoint *v) {
  size_t sofar = 0;
  ADV_SAFE(ze_struct_begin(buffer,len,"Endpoint"));

    ADV_SAFE(ze_field_begin(buffer,len,"ipv4",ZE_I32,1));
    ADV_SAFE(ze_i32(buffer,len,v->ipv4));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"port",ZE_I16,2));
    ADV_SAFE(ze_i16(buffer,len,v->port));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"service_name",ZE_STRING,3));
    ADV_SAFE(ze_Zipkin_String(buffer,len,&v->service_name));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_stop(buffer,len));
  ADV_SAFE(ze_struct_end(buffer,len));
  return sofar;
}
static size_t
ze_Zipkin_Annotation(byte *buffer, size_t len, Zipkin_Annotation *v) {
  size_t sofar = 0;
  ADV_SAFE(ze_struct_begin(buffer,len,"Annotation"));

    ADV_SAFE(ze_field_begin(buffer,len,"timestamp",ZE_I64,1));
    ADV_SAFE(ze_i64(buffer,len,v->timestamp));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"value",ZE_STRING,2));
    ADV_SAFE(ze_Zipkin_String(buffer,len,&v->value));
    ADV_SAFE(ze_field_end(buffer,len));

    if(v->host) {
      ADV_SAFE(ze_field_begin(buffer,len,"host",ZE_STRUCT,3));
      ADV_SAFE(ze_Zipkin_Endpoint(buffer,len,v->host));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    ADV_SAFE(ze_field_stop(buffer,len));
  ADV_SAFE(ze_struct_end(buffer,len));
  return sofar;
}
static size_t
ze_Zipkin_BinaryAnnotation(byte *buffer, size_t len,
                           Zipkin_BinaryAnnotation *v) {
  size_t sofar = 0;
  ADV_SAFE(ze_struct_begin(buffer,len,"BinaryAnnotation"));

    ADV_SAFE(ze_field_begin(buffer,len,"key",ZE_STRING,1));
    ADV_SAFE(ze_Zipkin_String(buffer,len,&v->key));
    ADV_SAFE(ze_field_end(buffer,len));

    /* String field type. Binary data. WTF Thirft? */
    ADV_SAFE(ze_field_begin(buffer,len,"value",ZE_STRING,2));
    ADV_SAFE(ze_Zipkin_Binary(buffer,len,&v->value));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"annotation_type",ZE_I32,3));
    ADV_SAFE(ze_i32(buffer,len,v->annotation_type));
    ADV_SAFE(ze_field_end(buffer,len));

    if(v->host) {
      ADV_SAFE(ze_field_begin(buffer,len,"host",ZE_STRUCT,4));
      ADV_SAFE(ze_Zipkin_Endpoint(buffer,len,v->host));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    ADV_SAFE(ze_field_stop(buffer,len));
  ADV_SAFE(ze_struct_end(buffer,len));
  return sofar;
}
static size_t
ze_Zipkin_Span(byte *buffer, size_t len, Zipkin_Span *v) {
  size_t sofar = 0;
  ADV_SAFE(ze_struct_begin(buffer,len,"BinaryAnnotation"));

    ADV_SAFE(ze_field_begin(buffer,len,"trace_id",ZE_I64,1));
    ADV_SAFE(ze_i64(buffer,len,v->trace_id));
    ADV_SAFE(ze_field_end(buffer,len));

    /* There is no field 2 */ 
 
    ADV_SAFE(ze_field_begin(buffer,len,"name",ZE_STRING,3));
    ADV_SAFE(ze_Zipkin_String(buffer,len,&v->name));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"id",ZE_I64,1));
    ADV_SAFE(ze_i64(buffer,len,v->id));
    ADV_SAFE(ze_field_end(buffer,len));
   
    if(v->parent_id) { 
      ADV_SAFE(ze_field_begin(buffer,len,"parent_id",ZE_I64,5));
      ADV_SAFE(ze_i64(buffer,len,*v->parent_id));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    if(v->annotations) {
      int cnt = 0;
      Zipkin_List_Zipkin_Annotation *node;
      for(node = v->annotations; node; node = node->next) cnt++;
      ADV_SAFE(ze_field_begin(buffer,len,"annotations",ZE_LIST,6));
        ADV_SAFE(ze_list_begin(buffer,len,ZE_STRUCT,cnt));
        for(node = v->annotations; node; node = node->next) {
          ADV_SAFE(ze_Zipkin_Annotation(buffer,len,&node->data));
        }
        ADV_SAFE(ze_list_end(buffer,len));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    /* There is no field 7 */ 

    if(v->binary_annotations) {
      int cnt = 0;
      Zipkin_List_Zipkin_BinaryAnnotation *node;
      for(node = v->binary_annotations; node; node = node->next) cnt++;
      ADV_SAFE(ze_field_begin(buffer,len,"binary_annotations",ZE_LIST,8));
        ADV_SAFE(ze_list_begin(buffer,len,ZE_STRUCT,cnt));
        for(node = v->binary_annotations; node; node = node->next) {
          ADV_SAFE(ze_Zipkin_BinaryAnnotation(buffer,len,&node->data));
        }
        ADV_SAFE(ze_list_end(buffer,len));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    if(v->debug) {
      ADV_SAFE(ze_field_begin(buffer,len,"debug",ZE_BOOL,9));
      ADV_SAFE(ze_bool(buffer,len,*v->debug));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    ADV_SAFE(ze_field_stop(buffer,len));
  ADV_SAFE(ze_struct_end(buffer,len));
  return sofar;
}

static __thread struct {
  unsigned short work[3];
  bool initialized;
} random_tracer_help;
static int64_t
ze_get_traceid(void) {
  int64_t id;
  if(!random_tracer_help.initialized) {
    uint64_t scratch = 0, i;
    mtev_hrtime_t t;
    for(i=0;i<8;i++) {
      t = mtev_gethrtime();
      scratch = (scratch << 8) ^ t;
    }
    memcpy(random_tracer_help.work, ((unsigned char *)&scratch)+2, 6);
    mtevL(mtev_debug, "trace for thread [%lx] initialized [%02x%02x%02x]\n",
          (unsigned long)pthread_self(),
          random_tracer_help.work[0],
          random_tracer_help.work[1],
          random_tracer_help.work[2]);
  }
  /* We sacrifice half the keyspace here because we want to avoid
   * sensible people using uint64_t from incorrectly decoding an int64_t.
   * Java and other languages without unsigned types are the plague.
   */
  id = jrand48(random_tracer_help.work);
  id = (id << 31) ^ jrand48(random_tracer_help.work);
  return id;
}

static void
ze_update_Zipkin_Endpoint(Zipkin_Endpoint *e, const char *service_name,
                          bool service_name_copy,
                          struct in_addr host, unsigned short port) {
  if(service_name) {
    if(e->service_name.needs_free && e->service_name.value) {
      free(e->service_name.value);
    }
    e->service_name.value =
      service_name_copy ? strdup(service_name) : (char *)service_name;
    e->service_name.needs_free = service_name_copy;
  }
  if(host.s_addr) memcpy(&e->ipv4, &host, 4);
  if(port) memcpy(&e->port, &port, 2);
}

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

static Zipkin_Endpoint ze_global_default_endpoint = {
  .service_name = { .value = "mtev", .needs_free = false }
};
void
mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy,
                             struct in_addr host, unsigned short port) {
  ze_update_Zipkin_Endpoint(&ze_global_default_endpoint,
                            service_name, service_name_copy, host, port);
}

Zipkin_Span *
mtev_zipkin_span_new(int64_t *trace_id,
                     int64_t *parent_span_id, int64_t *span_id,
                     const char *name, bool name_copy,
                     bool *debug, bool force) {
  int64_t my_trace_id = 0, my_span_id = 0;
  Zipkin_Span *span;

  if(!ze_enable_override && !zipkin_publish_hook_exists()) return NULL;

  if(!force && debug && *debug) {
    if(ze_debug_trace_probability != 1.0 &&
       drand48() > ze_new_trace_probability) return NULL;
    force = true;
  }

  if(!trace_id) {
    if(!force && ze_new_trace_probability != 1.0 &&
       drand48() > ze_new_trace_probability) return NULL;

    my_trace_id = ze_get_traceid();
    trace_id = &my_trace_id;
    /* Without a trace_id passed, it makes no sense to respect the span ids */
    parent_span_id = span_id = NULL;
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

  if(!force && ze_parented_trace_probability != 1.0 &&
     drand48() > ze_parented_trace_probability) return NULL;


  span = calloc(1, sizeof(*span));
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
mtev_zipkin_span_drop(Zipkin_Span *span) {
  if(!span) return;
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
  }
  if(span->_default_host.service_name.needs_free &&
     span->_default_host.service_name.value) {
    free(span->_default_host.service_name.value);
  }
}

void
mtev_zipkin_span_publish(Zipkin_Span *span) {
  unsigned char *buffer, hopeful[4192], *allocd = NULL;
  size_t len;
  int64_t traceid, spanid;

  if(!span) return;

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
  /* PUBLISH HERE */

  if(allocd) free(allocd);
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
mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp,
                          const char *value, bool value_copy) {
  Zipkin_List_Zipkin_Annotation *node;
  Zipkin_Annotation *a;
  int64_t now;

  if(!span) return NULL;

  node = calloc(1, sizeof(*node));
  a = &node->data;

  if(!timestamp) {
    struct timeval nowtv;
    mtev_gettimeofday(&nowtv,NULL);
    now = mtev_zipkin_timeval_to_timestamp(&nowtv);
    timestamp = &now;
  }
  a->timestamp = *timestamp;

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
  if(value_copy && value_len <= 8) {
    /* common encoding no-alloc path for up to 8 bytes */
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
    mtevL(mtev_notice, "Zipkin new trace sampling: %0.2f%%\n",
          100.0*new_traces);
  ze_new_trace_probability = new_traces;
  if(ze_parented_trace_probability != parented_traces)
    mtevL(mtev_notice, "Zipkin parented trace sampling: %0.2f%%\n",
          100.0*parented_traces);
  ze_parented_trace_probability = parented_traces;
  if(ze_debug_trace_probability != debug_traces)
    mtevL(mtev_notice, "Zipkin debug trace sampling: %0.2f%%\n",
          100.0*debug_traces);
  ze_debug_trace_probability = debug_traces;
}

int64_t *
mtev_zipkin_str_to_id(const char *in, int64_t *buf) {
  int64_t out;
  char *end;
  if(!in) return NULL;
  while(*in && isspace(*in)) in++;
  if(in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) in += 2;
  if(*in == '\0') return NULL;
  out = strtoll(in, &end, 16);
  if(*end != '\0' && !isspace(*end)) return NULL;
  *buf = out;
  return buf;
}
