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

/* Avoid the eventer/eventer.h header */
struct _event;

extern const char *ZIPKIN_CLIENT_SEND;
extern const char *ZIPKIN_CLIENT_SEND_DONE;
extern const char *ZIPKIN_CLIENT_RECV;
extern const char *ZIPKIN_CLIENT_RECV_DONE;
extern const char *ZIPKIN_SERVER_SEND;
extern const char *ZIPKIN_SERVER_SEND_DONE;
extern const char *ZIPKIN_SERVER_RECV;
extern const char *ZIPKIN_SERVER_RECV_DONE;

#define HEADER_ZIPKIN_MTEV_EVENT "X-mtev-Trace-Event"
#define HEADER_ZIPKIN_MTEV_EVENT_L "x-mtev-trace-event"
#define HEADER_ZIPKIN_MTEV_LOGS "X-mtev-Trace-Logs"
#define HEADER_ZIPKIN_MTEV_LOGS_L "x-mtev-trace-logs"
#define HEADER_ZIPKIN_TRACEID "X-B3-TraceId"
#define HEADER_ZIPKIN_TRACEID_L "x-b3-traceid"
#define HEADER_ZIPKIN_SPANID "X-B3-SpanId"
#define HEADER_ZIPKIN_SPANID_L "x-b3-spanid"
#define HEADER_ZIPKIN_PARENTSPANID "X-B3-ParentSpanId"
#define HEADER_ZIPKIN_PARENTSPANID_L "x-b3-parentspanid"
#define HEADER_ZIPKIN_SAMPLED "X-B3-Sampled"
#define HEADER_ZIPKIN_SAMPLED_L "x-b3-sampled"

#define HEADER_TRANSFER_ENCODING "transfer-encoding"

typedef enum {
  ZIPKIN_TRACE_EVENT_NONE = 0,
  ZIPKIN_TRACE_EVENT_LIFETIME = 1,
  ZIPKIN_TRACE_EVENT_CALLBACKS = 2
} mtev_zipkin_event_trace_level_t;

typedef enum {
  ZIPKIN_BOOL,
  ZIPKIN_BYTES,
  ZIPKIN_I16,
  ZIPKIN_I32,
  ZIPKIN_I64,
  ZIPKIN_DOUBLE,
  ZIPKIN_STRING
} Zipkin_AnnotationType;

typedef struct Zipkin_Span Zipkin_Span;
typedef struct Zipkin_Annotation Zipkin_Annotation;
typedef struct Zipkin_BinaryAnnotation Zipkin_BinaryAnnotation;

/*! \fn int64_t mtev_zipkin_timeval_to_timestamp(struct timeval *tv)
    \brief Convert a struct timeval to a timestamp.
    \param tv A point to a struct timeval representing the time in question.
    \return a timestamp suitable for use in annotations.

    mtev_zipkin_timeval_to_timestamp wil convert a struct timeval (e.g. from gettimeofday) to a the "microseconds since epoch" format expected by Zipkin.
 */
API_EXPORT(int64_t)
  mtev_zipkin_timeval_to_timestamp(struct timeval *);

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
  mtev_zipkin_span_new(int64_t *, int64_t *, int64_t *, const char *,
                       bool, bool *, bool );

/*! \fn bool mtev_zipkin_span_get_ids(Zipkin_Span *span, int64_t *traceid, int64_t *parent_id, int64_t *id)
    \brief Fetch the various IDs from a span.
    \param span The span on which to operate.
    \param traceid A pointer to a trace id to populate.
    \param parent_id A pointer to a parent span id to populate.
    \param span_id A pointer to a span id to populate.
    \return True if the span has a parent, false otherwise.
*/
API_EXPORT(bool)
  mtev_zipkin_span_get_ids(Zipkin_Span *, int64_t *, int64_t *, int64_t *);

/*! \fn void mtev_zipkin_span_rename(Zipkin_Span *span, const char *name, bool name_copy)
    \brief Rename a span after it has been created, but before publishing.
    \param span The span to rename.
    \param name The new name for the span.
    \param name_copy If the passed name will be freed or lost (copy required).
 */
API_EXPORT(void)
  mtev_zipkin_span_rename(Zipkin_Span *span, const char *name, bool copy);

/*! \fn void mtev_zipkin_span_ref(Zipkin_Span *span)
    \brief Increase the reference count to a span.
    \param span The span to reference.
 */
API_EXPORT(void)
  mtev_zipkin_span_ref(Zipkin_Span *);

/*! \fn void mtev_zipkin_span_drop(Zipkin_Span *span)
    \brief Release resources allociated with span without publishing.
    \param span The span to release.

    mtev_zipkin_span_drop releases all resources associated with the span.
 */
API_EXPORT(void)
  mtev_zipkin_span_drop(Zipkin_Span *);

/*! \fn void mtev_zipkin_span_publish(Zipkin_Span *span)
    \brief Pulish then release resources allociated with span without publishing.
    \param span The span to publish and release.

    mtev_zipkin_span_publish first publishes, then releases all resources associated with the span.
 */
API_EXPORT(void)
  mtev_zipkin_span_publish(Zipkin_Span *);

/*! \fn void mtev_zipkin_default_service_name(const char *service_name, bool service_name_copy)
    \brief Sets the default service name used for new spans.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.

    mtev_zipkin_default_service_name sets a default service name for endpoints for any new spans created without their own default.  Use this with care, it is application global.  You should likely only call this once at startup.
 */

API_EXPORT(void)
  mtev_zipkin_default_service_name(const char *, bool);

/*! \fn void mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy, struct in_addr host, unsigned short port)
    \brief Sets the default endpoint used for new spans.
    \param service_name The service name to use.
    \param service_name_copy Whether service_name should be allocated (copied) within the span.
    \param host The IPv4 host address of theservice.
    \param port The IP port of the service.

    mtev_zipkin_default_endpoint sets a default endpoint for any new spans created without their own default.  Use this with care, it is application global.  You should likely only call this once at startup.
 */

API_EXPORT(void)
  mtev_zipkin_default_endpoint(const char *, bool,
                               struct in_addr, unsigned short);


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
  mtev_zipkin_span_default_endpoint(Zipkin_Span *, const char *, bool,
                                    struct in_addr, unsigned short);

/*! \fn Zipkin_Annotation * mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp, const char *value, bool value_copy)
    \brief Annotate a span.
    \param span The span to annotate.
    \param timestamp A pointer the number of microseconds since epoch. NULL means now.
    \param value The annotation value itself.
    \param value_copy Whether value should be allocated (copied) within the span.
    \return A new annotation.

    mtev_zipkin_span_annotate make an annotation on the provided span.  The returned resource is managed by the span and will be released with it.
 */

API_EXPORT(Zipkin_Annotation *)
  mtev_zipkin_span_annotate(Zipkin_Span *, int64_t *,
                            const char *, bool);

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
  mtev_zipkin_annotation_set_endpoint(Zipkin_Annotation *, const char *, bool,
                                      struct in_addr, unsigned short);


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
  mtev_zipkin_span_bannotate(Zipkin_Span *, Zipkin_AnnotationType,
                             const char *, bool, const void *, int32_t, bool);

/*! \fn Zipkin_BinaryAnnotation * mtev_zipkin_span_bannotate_str(Zipkin_Span *span, const char *key, bool key_copy, const char *value, bool value_copy)
    \brief Annotate a span.
    \param span The span to annotate.
    \param annotation_type The type of the value being passed in.
    \param key The key for the annotation
    \param key_copy Whether key should be allocated (copied) within the span.
    \param value The value for the annotation.
    \param value_copy Whether value should be allocated (copied) within the span.
    \return A new binary annotation.
 */

API_EXPORT(Zipkin_BinaryAnnotation *)
  mtev_zipkin_span_bannotate_str(Zipkin_Span *, const char *, bool, const char *, bool);

/*! \fn Zipkin_BinaryAnnotation * mtev_zipkin_span_bannotate_i64(Zipkin_Span *span, const char *key, bool key_copy, int64_t value)
    \brief Annotate a span.
    \param span The span to annotate.
    \param annotation_type The type of the value being passed in.
    \param key The key for the annotation
    \param key_copy Whether key should be allocated (copied) within the span.
    \param value The value for the annotation.
    \return A new binary annotation.
 */

API_EXPORT(Zipkin_BinaryAnnotation *)
  mtev_zipkin_span_bannotate_i64(Zipkin_Span *, const char *, bool, int64_t);

/*! \fn Zipkin_BinaryAnnotation * mtev_zipkin_span_bannotate_i32(Zipkin_Span *span, const char *key, bool key_copy, int32_t value)
    \brief Annotate a span.
    \param span The span to annotate.
    \param annotation_type The type of the value being passed in.
    \param key The key for the annotation
    \param key_copy Whether key should be allocated (copied) within the span.
    \param value The value for the annotation.
    \return A new binary annotation.
 */

API_EXPORT(Zipkin_BinaryAnnotation *)
  mtev_zipkin_span_bannotate_i32(Zipkin_Span *, const char *, bool, int32_t);

/*! \fn Zipkin_BinaryAnnotation * mtev_zipkin_span_bannotate_double(Zipkin_Span *span, const char *key, bool key_copy, double value)
    \brief Annotate a span.
    \param span The span to annotate.
    \param annotation_type The type of the value being passed in.
    \param key The key for the annotation
    \param key_copy Whether key should be allocated (copied) within the span.
    \param value The value for the annotation.
    \return A new binary annotation.
 */

API_EXPORT(Zipkin_BinaryAnnotation *)
  mtev_zipkin_span_bannotate_double(Zipkin_Span *, const char *, bool, double);

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
  mtev_zipkin_bannotation_set_endpoint(Zipkin_BinaryAnnotation *,
                                       const char *, bool,
                                       struct in_addr, unsigned short);

/*! \fn size_t mtev_zipkin_encode(unsigned char *buffer, size_t len, Zipkin_Span *span)
    \brief Encode a span into the specified buffer for Zipkin.
    \param buffer The target buffer.
    \param len The target buffer's size.
    \param span The span to encode.
    \return The length of a successful encoding.

    mtev_zipkin_encode will take a span and encode it for Zipkin using the Thift BinaryProtocol.  The return value is always the length of a successful encoding, even if the buffer supplied is too small.  The caller must check the the returned length is less than or equal to the provided length to determine whether the encoding was successful.  The caller may provide a NULL buffer if and only if the provided len is 0.
 */
API_EXPORT(size_t)
  mtev_zipkin_encode(unsigned char *, size_t, Zipkin_Span *);

/*! \fn size_t mtev_zipkin_encode_list(unsigned char *buffer, size_t len, Zipkin_Span **spans, int cnt)
    \brief Encode a span into the specified buffer for Zipkin.
    \param buffer The target buffer.
    \param len The target buffer's size.
    \param spans The array of spans to encode.
    \param cnt The number of spans in `spans`.
    \return The length of a successful encoding.

    mtev_zipkin_encode_list will take a list of spans and encode it for Zipkin using the Thift BinaryProtocol.  The return value is always the length of a successful encoding, even if the buffer supplied is too small.  The caller must check the the returned length is less than or equal to the provided length to determine whether the encoding was successful.  The caller may provide a NULL buffer if and only if the provided len is 0.
 */
API_EXPORT(size_t)
  mtev_zipkin_encode_list(unsigned char *, size_t, Zipkin_Span **, int);

/*! \fn void mtev_zipkin_get_sampling(double *new_traces, double *parented_traces, double *debug_traces)
    \brief Get sampling probabilities for different types of traces.
    \param new_traces probability pointer to populate
    \param parented_traces probability pointer to populate
    \param debug_traces probability pointer to populate

    mtev_zipkin_get_sampling gets sampling probabilities for creating new traces.  See `mtev_zipkin_sampling` and the opentracing specification for more details on what each probability means.
 */
API_EXPORT(void)
  mtev_zipkin_get_sampling(double *new_traces, double *parented_traces,
                           double *debug_traces);

/*! \fn void mtev_zipkin_sampling(double new_traces, double parented_traces, double debug_traces)
    \brief Set sampling probabilities for different types of traces.
    \param new_traces probability of createing a new trace (trace_id == NULL)
    \param parented_traces probability of createing a parented trace (parent_span_id == NULL)
    \param debug_traces probability of createing a debug trace (debug != NULL && *debug)

    mtev_zipkin_sampling sets sampling probabilities for creating new traces. Default values are 1.0
 */
API_EXPORT(void)
  mtev_zipkin_sampling(double, double, double);

/*! \fn int64_t * mtev_zipkin_str_to_id(const char *in, int64_t *buf)
    \brief Convert a string Id to an int64_t Id.
    \param in Id in string form
    \param buf working buffer (must not be NULL)
    \return pointer to translated id

    mtev_zipkin_str_to_id will take string form id (trace_id, parent_span_id, or span_id) and convert it to an int64_t.  If conversion fails, the function will return NULL.
 */
API_EXPORT(int64_t *)
  mtev_zipkin_str_to_id(const char *, int64_t *);

/*! \fn void mtev_zipkin_eventer_init(void)
    \brief Initialize zipkin contexts for the eventer.
*/
API_EXPORT(void) mtev_zipkin_eventer_init(void);

/*! \fn Zipkin_Span * mtev_zipkin_active_span(eventer_t e)
    \brief Find the currently active span of work.
    \param e An event object (or NULL for the current event)
    \return A span or NULL if no span is currently active.
*/
API_EXPORT(Zipkin_Span *) mtev_zipkin_active_span(struct _event *e);

/*! \fn void mtev_zipkin_client_new(eventer_t e, const char *name, bool name_copy)
    \brief Create a new span for client user (remote calling)
    \param e An event object (or NULL for the current event)
    \param name A string to name the span
    \param name_copy Whether name should be allocated (copied) within the span.
*/
API_EXPORT(void) mtev_zipkin_client_new(struct _event *e, const char *, bool);

/*! \fn Zipkin_Span * mtev_zipkin_client_span(eventer_t e)
    \brief Retrieve the current client span should one exist.
    \param e An event object (or NULL for the current event)
    \return A span for client actions or NULL is no span exists.
*/
API_EXPORT(Zipkin_Span *) mtev_zipkin_client_span(struct _event *e);

/*! \fn bool mtev_zipkin_client_sampled_hdr(eventer_t e, char *buf, size_t len)
    \brief Format a sampled HTTP header for an HTTP request.
    \param e An event object (or NULL for the current event)
    \param buf An output buffer for "Header: Value"
    \param len The available space in `buf`
    \return True if successful, false if no trace is available of len is too short.
*/
API_EXPORT(bool) mtev_zipkin_client_sampled_hdr(struct _event *e, char *, size_t);

/*! \fn bool mtev_zipkin_client_trace_hdr(eventer_t e, char *buf, size_t len)
    \brief Format a trace HTTP header for an HTTP request.
    \param e An event object (or NULL for the current event)
    \param buf An output buffer for "Header: Value"
    \param len The available space in `buf`
    \return True if successful, false if no trace is available of len is too short.
*/
API_EXPORT(bool) mtev_zipkin_client_trace_hdr(struct _event *e, char *, size_t);

/*! \fn bool mtev_zipkin_client_parent_hdr(eventer_t e, char *buf, size_t len)
    \brief Format a parent span HTTP header for an HTTP request.
    \param e An event object (or NULL for the current event)
    \param buf An output buffer for "Header: Value"
    \param len The available space in `buf`
    \return True if successful, false if no trace is available of len is too short.
*/
API_EXPORT(bool) mtev_zipkin_client_parent_hdr(struct _event *e, char *, size_t);

/*! \fn bool mtev_zipkin_client_span_hdr(eventer_t e, char *buf, size_t len)
    \brief Format a span HTTP header for an HTTP request.
    \param e An event object (or NULL for the current event)
    \param buf An output buffer for "Header: Value"
    \param len The available space in `buf`
    \return True if successful, false if no trace is available of len is too short.
*/
API_EXPORT(bool) mtev_zipkin_client_span_hdr(struct _event *e, char *, size_t);

/*! \fn void mtev_zipkin_client_drop(eventer_t e)
    \brief Discard a client span if one exists.
    \param e An event object (or NULL for the current event)
*/
API_EXPORT(void) mtev_zipkin_client_drop(struct _event *e);

/*! \fn void mtev_zipkin_client_publish(eventer_t e)
    \brief Publish a client span if one exists.
    \param e An event object (or NULL for the current event)
*/
API_EXPORT(void) mtev_zipkin_client_publish(struct _event *e);

/*! \fn void mtev_zipkin_attach_to_eventer(eventer_t e, Zipkin_Span *span, bool new_child, mtev_zipkin_event_trace_level_t *track)
    \brief Attach an active span (or new child span) to an event.
    \param e An event object (or NULL for the current event)
    \param span An existing zipkin span.
    \param new_child Whether or not a child should be created under the provided span.
    \param track Specifies how event activity should be tracked.
*/
API_EXPORT(void)
  mtev_zipkin_attach_to_eventer(struct _event *e, Zipkin_Span *span,
                                bool new_child,
                                mtev_zipkin_event_trace_level_t *track);

/*! \fn void mtev_zipkin_span_attach_logs(Zipkin_Span *span, bool on)
    \brief Enable mtev_log appending if span is active.
    \param span A zipkin span (NULL allowed)
    \param on Wether to enable or disable log appending.
*/
API_EXPORT(void)
  mtev_zipkin_span_attach_logs(Zipkin_Span *span, bool on);

/*! \fn bool mtev_zipkin_span_logs_attached(Zipkin_Span *span)
    \brief Report whether a span should have logs attached.
    \param span A zipkin span to report on.
*/
API_EXPORT(bool)
  mtev_zipkin_span_logs_attached(Zipkin_Span *span);

/*! \fn void mtev_zipkin_event_trace_level(mtev_zipkin_event_trace_level_t level)
    \brief Globally set the default event trace level.
    \param level The new global default level for event tracing.
*/
API_EXPORT(void)
  mtev_zipkin_event_trace_level(mtev_zipkin_event_trace_level_t);

MTEV_HOOK_PROTO(zipkin_publish,
                (int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len),
                void *, closure,
                (void *closure, int64_t traceid, int64_t spanid, unsigned char *buffer, size_t len));

MTEV_HOOK_PROTO(zipkin_publish_span,
                (Zipkin_Span *span),
                void *, closure,
                (void *closure, Zipkin_Span *));

#endif
