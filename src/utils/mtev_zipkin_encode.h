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

#ifndef MTEV_UTILS_ZIPKIN_ENCODE_H
#define MTEV_UTILS_ZIPKIN_ENCODE_H

#include "mtev_defines.h"

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

typedef struct {
  char *value;
  bool needs_free;
} Zipkin_String;

typedef struct {
  void *value;
  char data[16];
  int32_t len;
  bool needs_free;
} Zipkin_Binary;

typedef struct {
  int32_t ipv4;
  int16_t port;
  Zipkin_String service_name;
} Zipkin_Endpoint;

struct Zipkin_Annotation {
  int64_t timestamp;
  Zipkin_String value;
  Zipkin_Endpoint *host;
  Zipkin_Endpoint _host;
};

struct Zipkin_BinaryAnnotation {
  Zipkin_String key;
  Zipkin_Binary value;
  Zipkin_AnnotationType annotation_type;
  Zipkin_Endpoint *host;
  Zipkin_Endpoint _host;
};

#define Zipkin_List(A) \
typedef struct _zl_##A { \
  A data; \
  struct _zl_##A *next; \
} Zipkin_List_##A \

Zipkin_List(Zipkin_Annotation);
Zipkin_List(Zipkin_BinaryAnnotation);

struct Zipkin_Span {
  int64_t trace_id;
  Zipkin_String name;
  int64_t id;
  int64_t *parent_id;
  int64_t _parent_id;
  Zipkin_List_Zipkin_Annotation *annotations;
  Zipkin_List_Zipkin_BinaryAnnotation *binary_annotations;
  bool *debug;
  bool _debug;

  int64_t timestamp;
  int64_t duration;
  bool mtevlogging;
  /* Not part of the spec, used by us to provide defaults */
  Zipkin_Endpoint _default_host;
  uint32_t refcnt;
};

static inline size_t
ze_bool(byte *buffer, size_t len, bool v) {
  if(len > 0) buffer[0] = v ? 1 : 0;
  return 1;
}
static inline size_t
ze_byte(byte *buffer, size_t len, byte v) {
  if(len > 0) buffer[0] = v;
  return 1;
}
static inline size_t
ze_i16(byte *buffer, size_t len, int16_t v) {
  if(len > 1) {
    int16_t nv = htons(v);
    memcpy(buffer, &nv, 2);
  }
  return 2;
}
static inline size_t
ze_i32(byte *buffer, size_t len, int32_t v) {
  if(len > 3) {
    int32_t nv = htonl(v);
    memcpy(buffer, &nv, 4);
  }
  return 4;
}
static inline size_t
ze_i64(byte *buffer, size_t len, int64_t v) {
  if(len > 7) {
    int64_t nv = htonll(v);
    memcpy(buffer, &nv, 8);
  }
  return 8;
}
static inline size_t
ze_double(byte *buffer, size_t len, double v) {
   if(len > 7) {
     int64_t *in = (int64_t *)&v;
     int64_t nv = htonll(*in);
     memcpy(buffer, &nv, 8);
   }
   return 8;
 }
static inline size_t
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
static inline size_t
ze_field_begin(byte *buffer, size_t len, const char *name,
               byte fieldtype, int16_t fieldid) {
  (void)name;
  size_t sofar;
  if(len < 3) return 3;
  sofar = ze_byte(buffer, len, fieldtype);
  return sofar + ze_i16(buffer+1, len-1, fieldid);
}
#define ze_field_end(a,b) 0
#define ze_field_stop(a,b) ze_byte(a,b,ZE_STOP);
static inline size_t
ze_Zipkin_String(byte *buffer, size_t len, Zipkin_String *v) {
  size_t sofar;
  int32_t str_len = strlen(v->value);
  sofar = ze_i32(buffer, len, str_len);
  if(sofar + str_len > len) return sofar + str_len;
  memcpy(buffer + sofar, v->value, str_len);
  return sofar + str_len;
}
static inline size_t
ze_Zipkin_Binary(byte *buffer, size_t len, Zipkin_Binary *v) {
  size_t sofar;
  int32_t vlen = v->len;
  if(v->len < 0) vlen = 0;
  if(4 + (size_t)vlen > len) return 4 + vlen;
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
static inline size_t
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
static inline size_t
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
static inline size_t
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
static inline size_t
ze_Zipkin_Span(byte *buffer, size_t len, Zipkin_Span *v) {
  size_t sofar = 0;
  ADV_SAFE(ze_struct_begin(buffer,len,"Span"));

    ADV_SAFE(ze_field_begin(buffer,len,"trace_id",ZE_I64,1));
    ADV_SAFE(ze_i64(buffer,len,v->trace_id));
    ADV_SAFE(ze_field_end(buffer,len));

    /* There is no field 2 */ 
 
    ADV_SAFE(ze_field_begin(buffer,len,"name",ZE_STRING,3));
    ADV_SAFE(ze_Zipkin_String(buffer,len,&v->name));
    ADV_SAFE(ze_field_end(buffer,len));

    ADV_SAFE(ze_field_begin(buffer,len,"id",ZE_I64,4));
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

    if(v->timestamp) {
      ADV_SAFE(ze_field_begin(buffer,len,"timestamp",ZE_I64,10));
      ADV_SAFE(ze_i64(buffer,len,v->timestamp));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    if(v->duration) {
      ADV_SAFE(ze_field_begin(buffer,len,"duration",ZE_I64,11));
      ADV_SAFE(ze_i64(buffer,len,v->duration));
      ADV_SAFE(ze_field_end(buffer,len));
    }

    ADV_SAFE(ze_field_stop(buffer,len));
  ADV_SAFE(ze_struct_end(buffer,len));
  return sofar;
}

static inline size_t
ze_Zipkin_Span_List(byte *buffer, size_t len, Zipkin_Span **v, int cnt) {
  size_t sofar = 0;
  int i;
  ADV_SAFE(ze_list_begin(buffer,len,ZE_STRUCT,cnt));
  for(i=0; i<cnt; i++) {
    ADV_SAFE(ze_Zipkin_Span(buffer,len,v[i]));
  }
  ADV_SAFE(ze_list_end(buffer,len));
  return sofar;
}

static inline int64_t
ze_get_traceid(void) {
  int64_t id = mtev_rand();
  /* We sacrifice half the keyspace here because we want to avoid
   * sensible people using uint64_t from incorrectly decoding an int64_t.
   * Java and other languages without unsigned types are the plague.
   */
  if (id < 0) return ~id;
  return id;
}

static inline void
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
  if(host.s_addr) {
    memcpy(&e->ipv4, &host, 4);
    e->ipv4 = ntohl(e->ipv4);
  }
  if(port) {
    memcpy(&e->port, &port, 2);
  }
}

#endif
