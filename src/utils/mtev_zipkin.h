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

#ifndef MTEV_ZIPKIN_H
#define MTEV_ZIPKIN_H

/*!  \file mtev_zipkin.h

     Interface to the mtev zipkin tracing system.
 */

#include <mtev_defines.h>

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <mtev_hooks.h>

extern const char *ZIPKIN_CLIENT_SEND;
extern const char *ZIPKIN_CLIENT_RECV;
extern const char *ZIPKIN_SERVER_SEND;
extern const char *ZIPKIN_SERVER_RECV;

#define HEADER_ZIPKIN_TRACEID "X-B3-TraceId"
#define HEADER_ZIPKIN_TRACEID_L "x-b3-traceid"
#define HEADER_ZIPKIN_SPANID "X-B3-SpanId"
#define HEADER_ZIPKIN_SPANID_L "x-b3-spanid"
#define HEADER_ZIPKIN_PARENTSPANID "X-B3-ParentSpanId"
#define HEADER_ZIPKIN_PARENTSPANID_L "x-b3-parentspanid"
#define HEADER_ZIPKIN_SAMPLED "X-B3-Sampled"
#define HEADER_ZIPKIN_SAMPLED_L "x-b3-sampled"
#define HEADER_ZIPKIN_SAMPLED "X-B3-Sampled"
#define HEADER_ZIPKIN_SAMPLED_L "x-b3-sampled"

#define HEADER_TRANSFER_ENCODING "transfer-encoding"

typedef enum {
  ZIPKIN_BOOL,
  ZIPKIN_BYTES,
  ZIPKIN_I16,
  ZIPKIN_I32,
  ZIPKIN_I64,
  ZIPKIN_DOUBLE,
  ZIPKIN_STRING
} Zipkin_AnnotationType;

typedef struct {
  char *value;
  bool needs_free;
} Zipkin_String;

typedef struct {
  void *value;
  char data[8];
  int32_t len;
  bool needs_free;
} Zipkin_Binary;

typedef struct {
  int32_t ipv4;
  int16_t port;
  Zipkin_String service_name;
} Zipkin_Endpoint;

typedef struct {
  int64_t timestamp;
  Zipkin_String value;
  Zipkin_Endpoint *host;
  Zipkin_Endpoint _host;
  int32_t *duration;
  int32_t _duration;
} Zipkin_Annotation;

typedef struct {
  Zipkin_String key;
  Zipkin_Binary value;
  Zipkin_AnnotationType annotation_type;
  Zipkin_Endpoint *host;
  Zipkin_Endpoint _host;
} Zipkin_BinaryAnnotation;

#define Zipkin_List(A) \
typedef struct _zl_##A { \
  A data; \
  struct _zl_##A *next; \
} Zipkin_List_##A \

Zipkin_List(Zipkin_Annotation);
Zipkin_List(Zipkin_BinaryAnnotation);

typedef struct {
  int64_t trace_id;
  Zipkin_String name;
  int64_t id;
  int64_t *parent_id;
  int64_t _parent_id;
  Zipkin_List_Zipkin_Annotation *annotations;
  Zipkin_List_Zipkin_BinaryAnnotation *binary_annotations;
  bool *debug;
  bool _debug;

  /* Not part of the spec, used by us to provide defaults */
  Zipkin_Endpoint _default_host;
} Zipkin_Span;

/*! \fn int64_t mtev_zipkin_timeval_to_timestamp(struct timeval *tv)
    \brief Convert a struct timeval to a timestamp.
    \param tv A point to a struct timeval representing the time in question.
    \return a timestamp suitable for use in annotations.

    mtev_zipkin_timeval_to_timestamp wil convert a struct timeval (e.g. from gettimeofday) to a the "microseconds since epoch" format expected by Zipkin.
 */
API_EXPORT(int64_t)
  mtev_zipkin_timeval_to_timestamp(struct timeval *tv);

/*! \fn Zipkin_Span * mtev_zipkin_span_new(int64_t *trace_id, int64_t *parent_span_id, int64_t *span_id, const char *name, bool name_copy, bool debug, bool force)
    \brief Allocate a new tracing span.
    \param trace_id A pointer to the trace_id, if NULL, one will be assigned.
    \param parent_span_id A point to the span's parent_id (NULL is originating).
    \param span_id A pointer to the span's id (NULL will imply that trace_id should be used).
    \param name A name for this span.
    \param name_copy Wether the name should be allocated (copied) within the span.
    \param debug Pointer to whether this is a debug span (bypasses any sampling), NULL allowed.
    \param force force the span to be created as if all probabilities were 1.
    \return A new span.

    mtev_zipkin_span_new allocates a new span in the system. The caller must eventually release the span via a call to either mtev_zipkin_span_drop or mtev_zipkin_span_publish.
 */
API_EXPORT(Zipkin_Span *)
  mtev_zipkin_span_new(int64_t *trace_id,
                       int64_t *parent_span_id, int64_t *span_id,
                       const char *name, bool name_copy,
	       bool *debug, bool force);

/*! \fn void mtev_zipkin_span_drop(Zipkin_Span *span)
    \brief Release resources allociated with span without publishing.
    \param span The span to release.

    mtev_zipkin_span_drop releases all resources associated with the span.
 */
API_EXPORT(void)
  mtev_zipkin_span_drop(Zipkin_Span *span);

/*! \fn void mtev_zipkin_span_publish(Zipkin_Span *span)
    \brief Pulish then release resources allociated with span without publishing.
    \param span The span to publish and release.

    mtev_zipkin_span_publish first publishes, then releases all resources associated with the span.
 */
API_EXPORT(void)
  mtev_zipkin_span_publish(Zipkin_Span *span);

/*! \fn void mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy, struct in_addr host, unsigned short port)
    \brief Sets the default endpoint used for new spans.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.
    \param host The IPv4 host address of theservice.
    \param port The IP port of the service.

    mtev_zipkin_default_endpoint sets a default endpoint for any new spans created without their own default.  Use this with care, it is application global.  You should likely only call this once at startup.
 */

API_EXPORT(void)
  mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy,
                               struct in_addr host, unsigned short port);


/*! \fn void mtev_zipkin_span_default_endpoint(Zipkin_Span *span, const char *service_name, bool service_name_copy, struct in_addr host, unsigned short port)
    \brief Sets the default endpoint used for new annotations within the span.
    \param span The span to update.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.
    \param host The IPv4 host address of theservice.
    \param port The IP port of the service.

    mtev_zipkin_span_default_endpoint sets a default endpoint for any annotations or binary_annotations added to the span.  All annotations added without an endpoint will use the last default set on the span.
 */
API_EXPORT(void)
  mtev_zipkin_span_default_endpoint(Zipkin_Span *span, const char *service_name,
                                    bool service_name_copy,
                                    struct in_addr host, unsigned short port);

/*! \fn Zipkin_Annotation * mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp, const char *value, bool value_copy, int32_t *duration)
    \brief Annotate a span.
    \param span The span to annotate.
    \param timestamp A pointer the number of microseconds since epoch. NULL means now.
    \param value The annotation value itself.
    \param value_copy Whether value should be allocated (copied) within the span.
    \param duration A pointer to the number of microseconds elapsed. NULL allowed (recommended).
    \return A new annotation.

    mtev_zipkin_span_annotate make an annotation on the provided span.  The returned resource is managed by the span and will be released with it.
 */

API_EXPORT(Zipkin_Annotation *)
  mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp,
                            const char *value, bool value_copy, int32_t *duration);

/*! \fn void mtev_zipkin_annotation_set_endpoint(Zipkin_Annotation *annotation, const char *service_name, bool service_name_copy, struct in_addr host, unsigned short port)
    \brief Sets the endpoint for an annotation.
    \param annotation The annotation to update.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.
    \param host The IPv4 host address of theservice.
    \param port The IP port of the service.

    mtev_zipkin_annotation_set_endpoint sets an endpoint for the provided annotation.
 */
API_EXPORT(void)
  mtev_zipkin_annotation_set_endpoint(Zipkin_Annotation *annotation,
                                      const char *service_name,
                                      bool service_name_copy,
                                      struct in_addr host, unsigned short port);


/*! \fn Zipkin_BinaryAnnotation * mtev_zipkin_span_bannotate(Zipkin_Span *span, Zipkin_AnnotationType annotation_type, const char *key, bool key_copy, const void *value, int32_t value_len, bool value_copy)
    \brief Annotate a span.
    \param span The span to annotate.
    \param annotation_type The type of the value being passed in.
    \param key The key for the annotation
    \param key_copy Whether key should be allocated (copied) within the span.
    \param value The pointer to a value for the annotation.
    \param value_len The length (in memory) of the binary value.
    \param value_copy Whether value should be allocated (copied) within the span.
    \return A new binary annotation.

    mtev_zipkin_span_bannotate make a binary annotation on the provided span.  The returned resource is managed by the span and will be released with it.
 */

API_EXPORT(Zipkin_BinaryAnnotation *)
  mtev_zipkin_span_bannotate(Zipkin_Span *span, Zipkin_AnnotationType atype,
                             const char *key, bool key_copy,
	             const void *value, int32_t value_len, bool value_copy);

/*! \fn void mtev_zipkin_bannotation_set_endpoint(Zipkin_BinaryAnnotation *annotation, const char *service_name, bool service_name_copy, struct in_addr host, unsigned short port)
    \brief Sets the endpoint for an annotation.
    \param annotation The annotation to update.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.
    \param host The IPv4 host address of theservice.
    \param port The IP port of the service.

    mtev_zipkin_bannotation_set_endpoint sets an endpoint for the provided annotation.
 */
API_EXPORT(void)
  mtev_zipkin_bannotation_set_endpoint(Zipkin_BinaryAnnotation *annotation,
                                       const char *service_name,
                                       bool service_name_copy,
                                       struct in_addr host, unsigned short port);

/*! \fn size_t mtev_zipkin_encode(unsigned char *buffer, size_t len, Zipkin_Span *span)
    \brief Encode a span into the specified buffer for Zipkin.
    \param buffer The target buffer.
    \param len The target buffer's size.
    \param span The span to encode.
    \return The length of a successful encoding.

    mtev_zipkin_encode will take a span and encode it for Zipkin using the Thift BinaryProtocol.  The return value is always the length of a successful encoding, even if the buffer supplied is too small.  The caller must check the the returned length is less than or equal to the provided length to determine whether the encoding was successful.  The caller may provide a NULL buffer if and only if the provided len is 0.
 */
API_EXPORT(size_t)
  mtev_zipkin_encode(unsigned char *buffer, size_t len, Zipkin_Span *span);

/*! \fn void mtev_zipkin_sampling(double new_traces, double parented_traces, double debug_traces)
    \brief Set sampling probabilities for different types of traces.
    \param new_traces probability of createing a new trace (trace_id == NULL)
    \param parented_traces probability of createing a parented trace (parent_span_id == NULL)
    \param debug_traces probability of createing a debug trace (debug != NULL && *debug)

    mtev_zipkin_sampling sets sampling probabilities for creating new traces. Default values are 1.0
 */
API_EXPORT(void)
  mtev_zipkin_sampling(double new_traces, double parented_traces,
                       double debug_traces);

/*! \fn int64_t * mtev_zipkin_str_to_id(const char *in, int64_t *buf)
    \brief Convert a string Id to an int64_t Id.
    \param in Id in string form
    \param buf working buffer (must not be NULL)
    \return pointer to translated id

    mtev_zipkin_str_to_id will take string form id (trace_id, parent_span_id, or span_id) and convert it to an int64_t.  If conversion fails, the function will return NULL.
 */
API_EXPORT(int64_t *)
  mtev_zipkin_str_to_id(const char *in, int64_t *buf);

MTEV_HOOK_PROTO(zipkin_publish,
                (int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
                void *, closure,
                (void *closure, int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len));


#endif
