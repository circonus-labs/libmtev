### B

#### mtev_b32_decode

>Decode a base32 encoded input buffer into the provided output buffer.

```c
int 
mtev_b32_decode(const char *src, size_t src_len, unsigned char *dest, size_t dest_len)
```


  * `src` The buffer containing the encoded content.
  * `src_len` The size (in bytes) of the encoded data.
  * `dest` The destination buffer to which the function will produce.
  * `dest_len` The size of the destination buffer.
  * **RETURN** The size of the decoded output.  Returns zero is dest_len is too small.

mtev_b32_decode decodes input until an the entire input is consumed or until an invalid base32 character is encountered.
 

#### mtev_b32_encode

>Encode raw data as base32 encoded output into the provided buffer.

```c
int 
mtev_b32_encode(const unsigned char *src, size_t src_len, char *dest, size_t dest_len)
```


  * `src` The buffer containing the raw data.
  * `src_len` The size (in bytes) of the raw data.
  * `dest` The destination buffer to which the function will produce.
  * `dest_len` The size of the destination buffer.
  * **RETURN** The size of the encoded output.  Returns zero is out_sz is too small.
 

#### mtev_b32_encode_len

>Calculate how large a buffer must be to contain the base-32 encoding for a given number of bytes.

```c
size_t 
mtev_b32_encode_len(size_t src_len)
```


  * `src_len` The size (in bytes) of the raw data buffer that might be encoded.
  * **RETURN** The size of the buffer that would be needed to store an encoded version of an input string.
 

#### mtev_b32_max_decode_len

>Calculate how large a buffer must be to contain a decoded base-32-encoded string of a given length.

```c
size_t 
mtev_b32_max_decode_len(size_t src_len)
```


  * `src_len` The size (in bytes) of the base-32-encoded string that might be decoded.
  * **RETURN** The size of the buffer that would be needed to decode the input string.
 

#### mtev_b64_decode

>Decode a base64 encoded input buffer into the provided output buffer.

```c
int 
mtev_b64_decode(const char *src, size_t src_len, unsigned char *dest, size_t dest_len)
```


  * `src` The buffer containing the encoded content.
  * `src_len` The size (in bytes) of the encoded data.
  * `dest` The destination buffer to which the function will produce.
  * `dest_len` The size of the destination buffer.
  * **RETURN** The size of the decoded output.  Returns zero is dest_len is too small.

mtev_b64_decode decodes input until an the entire input is consumed or until an invalid base64 character is encountered.
 

#### mtev_b64_encode

>Encode raw data as base64 encoded output into the provided buffer.

```c
int 
mtev_b64_encode(const unsigned char *src, size_t src_len, char *dest, size_t dest_len)
```


  * `src` The buffer containing the raw data.
  * `src_len` The size (in bytes) of the raw data.
  * `dest` The destination buffer to which the function will produce.
  * `dest_len` The size of the destination buffer.
  * **RETURN** The size of the encoded output.  Returns zero is out_sz is too small.

mtev_b64_encode encodes an input string into a base64 representation with no linefeeds.
 

#### mtev_b64_encode_len

>Calculate how large a buffer must be to contain the base-64 encoding for a given number of bytes.

```c
size_t 
mtev_b64_encode_len(size_t src_len)
```


  * `src_len` The size (in bytes) of the raw data buffer that might be encoded.
  * **RETURN** The size of the buffer that would be needed to store an encoded version of an input string.
 

#### mtev_b64_max_decode_len

>Calculate how large a buffer must be to contain a decoded base-64-encoded string of a given length.

```c
size_t 
mtev_b64_max_decode_len(size_t src_len)
```


  * `src_len` The size (in bytes) of the base-64-encoded string that might be decoded.
  * **RETURN** The size of the buffer that would be needed to decode the input string.
 

### C

#### mtev_cluster_by_name

>Find the cluster with the registered name.

```c
mtev_cluster_t *
mtev_cluster_by_name(const char *name)
```


  * `name` The name of the cluster.
  * **RETURN** Returns a pointer to the cluster or NULL is not found.

Takes a name and finds a globally registered cluster by that name.
 

#### mtev_cluster_enabled

>Report on the availability of the clusters feature.

```c
mtev_boolean 
mtev_cluster_enabled()
```


  * **RETURN** mtev_true if clusters can be configured, otherwise mtev_false.
 

#### mtev_cluster_find_node

>Find a node by uuid within a cluster.

```c
mtev_cluster_node_t *
mtev_cluster_find_node(mtev_cluster_t *cluster, uuid_t nodeid)
```


  * `cluster` The '<cluster>' containing the node.
  * `nodeid` The nodeid being searched for.
  * **RETURN** Returns a pointer to the mtev_cluster_node_t or NULL if not found.

Takes a cluster and a node UUID and returns a pointer to the 
corresponding mtev_cluster_node_t.
 

#### mtev_cluster_init

>Initialize the mtev cluster configuration.

```c
void 
mtev_cluster_init()
```



Initializes the mtev cluster configuration.
 

#### mtev_cluster_size

>Report the number of nodes in the cluster.

```c
int 
mtev_cluster_size(mtev_cluster_t *cluster)
```


  * `cluster` The cluster.
  * **RETURN** The number of nodes in the cluster.

Determines the number of nodes in the given cluster.
 

#### mtev_cluster_update

>Add or update an mtev cluster.

```c
int 
mtev_cluster_update(mtev_conf_section_t cluster)
```


  * `cluster` The '<cluster>' node configuration.
  * **RETURN** Returns -1 on error, 0 on insert, or 1 on update.

Takes a configuration section representing a cluster and registers
it in the global cluster configuration.
 

### G

#### mtev_getip_ipv4

>find the local IPv4 address that would be used to talk to remote

```c
int 
mtev_getip_ipv4(struct in_addr remote, struct in_addr *local)
```


  * `remote` the destination (no packets are sent)
  * `local` the pointer to the local address to be set
  * **RETURN** 0 on success, -1 on failure
 

### L

#### mtev_lockfile_acquire

>lock the file immediately if possible, return -1 otherwise.

```c
mtev_lockfile_t 
mtev_lockfile_acquire(const char *fp)
```


  * `fp` the path to the lock file
  * **RETURN** >= 0 on success, -1 on failure
 

#### mtev_lockfile_release

>release a held file lock

```c
int 
mtev_lockfile_release(mtev_lockfile_t fd)
```


  * `fd` the file lock to release
  * **RETURN** -1 on failure, 0 on success
 

### M

#### mkdir_for_file

>Create directories along a path.

```c
int 
mkdir_for_file(const char *file, mode_t m)
```


  * `file` a filename for which a directory is desired.
  * `m` the mode used for creating directories.
  * **RETURN** Returns 0 on success, -1 on error.

Creates all directories from / (as needed) to hold a named file.
 

### S

#### mtev_security_chroot

>chroot(2) to the specified directory.

```c
int 
mtev_security_chroot(const char *path)
```


  * `path` The path to chroot to.
  * **RETURN** Zero is returned on success.

mtev_security_chroot placing the calling application into a chroot
environment.
 

#### mtev_security_setcaps

>change the capabilities of the process

```c
int 
mtev_security_setcaps(mtev_security_captype_t type, const char *capstring)
```


  * `which` the effective, inherited or both
  * `capstring` alteration to the capabilities
  * **RETURN** Zero is returned on success.

mtev_security_setcaps will change the capability set of the current
process.
 

#### mtev_security_usergroup

>change the effective or real, effective and saved user and group

```c
int 
mtev_security_usergroup(const char *user, const char *group, mtev_boolean effective)
```


  * `user` The user name as either a login or a userid in string form.
  * `group` The group name as either a login or a groupid in string form.
  * `effective` If true then only effective user and group are changed.
  * **RETURN** Zero is returned on success.

mtev_security_usergroup will change the real, effective, and saved
user and group for the calling process.  This is thread-safe.
 

#### mtev_sem_destroy

>releases all resources related to a semaphore

```c
int 
mtev_sem_destroy(mtev_sem_t *s)
```


  * `s` the semaphore to destroy
  * **RETURN** 0 on success or -1 on failure
 

#### mtev_sem_getvalue

>retrieves the current value of a semaphore, placing it in *value

```c
int 
mtev_sem_getvalue(mtev_sem_t *s, int *value)
```


  * `s` the semaphore on which to operate
  * `value` a pointer an integer that will be populated with the current value of the semaphore
  * **RETURN** 0 on success or -1 on failure
 

#### mtev_sem_init

>initializes a counting semaphore for first time use.

```c
int 
mtev_sem_init(mtev_sem_t *s, int unused, int value)
```


  * `s` the semaphore to be initialized
  * `unused` is unused (keeps API combatibility with sem_init()
  * `value` sets the initial value of the semaphore
  * **RETURN** 0 on success or -1 on failure
 

#### mtev_sem_post

>increments the value of the semaphore releasing any waiters.

```c
int 
mtev_sem_post(mtev_sem_t *s)
```


  * `s` the semaphore on which to wait
  * **RETURN** 0 on success or -1 on failure
 

#### mtev_sem_trywait

>decrements the value of the semaphore if greater than 0 or fails

```c
int 
mtev_sem_trywait(mtev_sem_t *s)
```


  * `s` the semaphore on which to wait
  * **RETURN** 0 on success or -1 on failure
 

#### mtev_sem_wait

>decrements the value of the semaphore waiting if required.

```c
int 
mtev_sem_wait(mtev_sem_t *s)
```


  * `s` the semaphore on which to wait
  * **RETURN** 0 on success or -1 on failure
 

### U

#### update_retries

>Updates the list of retries and signals to quit if the limit is exceeded

```c
int 
update_retries(int retries, int span, retry_data** data)
```


  * `offset` The current location in the data array to place the new time in
  * `times` An array of times used to determine if there have been too many restarts
  * **RETURN** Returns 1 to signal a quit, 0 otherwise

.

update_retries will iterate through a list of times the task has restarted. If it determines that the system has been restarted too many times in too short a period, it will return 1 and the program will terminate. Otherwise, it will return 0 and the program will restart.
 

### W

#### mtev_watchdog_child_eventer_heartbeat

```c
int 
mtev_watchdog_child_eventer_heartbeat()
```

  * **RETURN** Returns zero on success

mtev_watchdog_child_eventer_heartbeat registers a periodic heartbeat through the eventer subsystem.  The eventer must be initialized before calling this function.
 

#### mtev_watchdog_child_heartbeat

```c
int 
mtev_watchdog_child_heartbeat()
```

  * **RETURN** Returns zero on success

mtev_watchdog_child_heartbeat is called within the child function to alert the parent that the child is still alive and functioning correctly.
 

#### mtev_watchdog_create

```c
mtev_watchdog_t *
mtev_watchdog_create()
```

  * **RETURN** a new heartbeat identifier (or null, if none could be allocated)

mtev_watchdog_create creates a new heartbeat that must be assessed for liveliness by the parent.
 

#### mtev_watchdog_disable

```c
void 
mtev_watchdog_disable(mtev_watchdog_t *hb)
```

  * `hb` the heart on which to act

mtev_watchdog_disable will make the parent ignore failed heartbeats.
 

#### mtev_watchdog_enable

```c
void 
mtev_watchdog_enable(mtev_watchdog_t *hb)
```

  * `hb` the heart on which to act

mtev_watchdog_enable will make the parent respect and act on failed heartbeats.
 

#### mtev_watchdog_heartbeat

```c
int 
mtev_watchdog_heartbeat(mtev_watchdog_t *hb)
```

  * `hb` is the heart on which to pulse.  If null, the default heart is used.
  * **RETURN** Returns zero on success

mtev_watchdog_heartbeat will pulse on the specified heart.
 

#### mtev_watchdog_override_timeout

```c
void 
mtev_watchdog_override_timeout(mtev_watchdog_t *lifeline, double timeout)
```

  * `hb` the heart on which to act
  * `timeout` the timeout in seconds for this heart (0 for default)

mtev_watchdog_override_timeout will allow the caller to override the timeout
for a specific heart in the system.
 

#### mtev_watchdog_prefork_init

>Prepare the program to split into a child/parent-monitor relationship.

```c
int 
mtev_watchdog_prefork_init()
```


  * **RETURN** Returns zero on success.

mtev_watchdog_prefork_init sets up the necessary plumbing to bridge across a
child to instrument watchdogs.
 

#### mtev_watchdog_recurrent_heartbeat

```c
eventer_t 
mtev_watchdog_recurrent_heartbeat(mtev_watchdog_t *hb)
```

  * `hb` is the heart on which to beat.
  * **RETURN** Returns and event that the caller must schedule.

mtev_watchdog_recurrent_heartbeat creates a recurrent eventer_t to beat a heart.
 

#### mtev_watchdog_start_child

>Starts a function as a separate child under close watch.

```c
int 
mtev_watchdog_start_child(const char *app, int (*func)(), int child_watchdog_timeout)
```


  * `app` The name of the application (for error output).
  * `func` The function that will be the child process.
  * `child_watchdog_timeout` The number of seconds of lifelessness before the parent reaps and restarts the child.
  * **RETURN** Returns on program termination.

mtev_watchdog_start_child will fork and run the specified function in the child process.  The parent will watch.  The child process must initialize the eventer system and then call mtev_watchdog_child_hearbeat to let the parent know it is alive.  If the eventer system is being used to drive the child process, mtev_watchdog_child_eventer_heartbeat may be called once after the eventer is initalized.  This will induce a regular heartbeat.
 

### Z

#### mtev_zipkin_annotation_set_endpoint

>Sets the endpoint for an annotation.

```c
void 
mtev_zipkin_annotation_set_endpoint(Zipkin_Annotation *annotation, const char *service_name, 
                                    bool service_name_copy, struct in_addr host, unsigned short port)
```


  * `annotation` The annotation to update.
  * `service_name` The service name to use.
  * `service_name_copy` Whether service_name should be allocated (copied) within the span.
  * `host` The IPv4 host address of theservice.
  * `port` The IP port of the service.

mtev_zipkin_annotation_set_endpoint sets an endpoint for the provided annotation.
 

#### mtev_zipkin_bannotation_set_endpoint

>Sets the endpoint for an annotation.

```c
void 
mtev_zipkin_bannotation_set_endpoint(Zipkin_BinaryAnnotation *annotation, const char *service_name, 
                                     bool service_name_copy, struct in_addr host, unsigned short port)
```


  * `annotation` The annotation to update.
  * `service_name` The service name to use.
  * `service_name_copy` Whether service_name should be allocated (copied) within the span.
  * `host` The IPv4 host address of theservice.
  * `port` The IP port of the service.

mtev_zipkin_bannotation_set_endpoint sets an endpoint for the provided annotation.
 

#### mtev_zipkin_default_endpoint

>Sets the default endpoint used for new spans.

```c
void 
mtev_zipkin_default_endpoint(const char *service_name, bool service_name_copy, struct in_addr host
                             unsigned short port)
```


  * `service_name` The service name to use.
  * `service_name_copy` Whether service_name should be allocated (copied) within the span.
  * `host` The IPv4 host address of theservice.
  * `port` The IP port of the service.

mtev_zipkin_default_endpoint sets a default endpoint for any new spans created without their own default.  Use this with care, it is application global.  You should likely only call this once at startup.
 

#### mtev_zipkin_encode

>Encode a span into the specified buffer for Zipkin.

```c
size_t 
mtev_zipkin_encode(unsigned char *buffer, size_t len, Zipkin_Span *span)
```


  * `buffer` The target buffer.
  * `len` The target buffer's size.
  * `span` The span to encode.
  * **RETURN** The length of a successful encoding.

mtev_zipkin_encode will take a span and encode it for Zipkin using the Thift BinaryProtocol.  The return value is always the length of a successful encoding, even if the buffer supplied is too small.  The caller must check the the returned length is less than or equal to the provided length to determine whether the encoding was successful.  The caller may provide a NULL buffer if and only if the provided len is 0.
 

#### mtev_zipkin_sampling

>Set sampling probabilities for different types of traces.

```c
void 
mtev_zipkin_sampling(double new_traces, double parented_traces, double debug_traces)
```


  * `new_traces` probability of createing a new trace (trace_id == NULL)
  * `parented_traces` probability of createing a parented trace (parent_span_id == NULL)
  * `debug_traces` probability of createing a debug trace (debug != NULL && *debug)

mtev_zipkin_sampling sets sampling probabilities for creating new traces. Default values are 1.0
 

#### mtev_zipkin_span_annotate

>Annotate a span.

```c
Zipkin_Annotation * 
mtev_zipkin_span_annotate(Zipkin_Span *span, int64_t *timestamp, const char *value, bool value_copy)
```


  * `span` The span to annotate.
  * `timestamp` A pointer the number of microseconds since epoch. NULL means now.
  * `value` The annotation value itself.
  * `value_copy` Whether value should be allocated (copied) within the span.
  * **RETURN** A new annotation.

mtev_zipkin_span_annotate make an annotation on the provided span.  The returned resource is managed by the span and will be released with it.
 

#### mtev_zipkin_span_bannotate

>Annotate a span.

```c
Zipkin_BinaryAnnotation * 
mtev_zipkin_span_bannotate(Zipkin_Span *span, Zipkin_AnnotationType annotation_type, const char *key, 
                           bool key_copy, const void *value, int32_t value_len, bool value_copy)
```


  * `span` The span to annotate.
  * `annotation_type` The type of the value being passed in.
  * `key` The key for the annotation
  * `key_copy` Whether key should be allocated (copied) within the span.
  * `value` The pointer to a value for the annotation.
  * `value_len` The length (in memory) of the binary value.
  * `value_copy` Whether value should be allocated (copied) within the span.
  * **RETURN** A new binary annotation.

mtev_zipkin_span_bannotate make a binary annotation on the provided span.  The returned resource is managed by the span and will be released with it.
 

#### mtev_zipkin_span_default_endpoint

>Sets the default endpoint used for new annotations within the span.

```c
void 
mtev_zipkin_span_default_endpoint(Zipkin_Span *span, const char *service_name, bool service_name_copy, 
                                  struct in_addr host, unsigned short port)
```


  * `span` The span to update.
  * `service_name` The service name to use.
  * `service_name_copy` Whether service_name should be allocated (copied) within the span.
  * `host` The IPv4 host address of theservice.
  * `port` The IP port of the service.

mtev_zipkin_span_default_endpoint sets a default endpoint for any annotations or binary_annotations added to the span.  All annotations added without an endpoint will use the last default set on the span.
 

#### mtev_zipkin_span_drop

>Release resources allociated with span without publishing.

```c
void 
mtev_zipkin_span_drop(Zipkin_Span *span)
```


  * `span` The span to release.

mtev_zipkin_span_drop releases all resources associated with the span.
 

#### mtev_zipkin_span_new

>Allocate a new tracing span.

```c
Zipkin_Span * 
mtev_zipkin_span_new(int64_t *trace_id, int64_t *parent_span_id, int64_t *span_id, 
                     const char *name, bool name_copy, bool debug, bool force)
```


  * `trace_id` A pointer to the trace_id, if NULL, one will be assigned.
  * `parent_span_id` A point to the span's parent_id (NULL is originating).
  * `span_id` A pointer to the span's id (NULL will imply that trace_id should be used).
  * `name` A name for this span.
  * `name_copy` Wether the name should be allocated (copied) within the span.
  * `debug` Pointer to whether this is a debug span (bypasses any sampling), NULL allowed.
  * `force` force the span to be created as if all probabilities were 1.
  * **RETURN** A new span.

mtev_zipkin_span_new allocates a new span in the system. The caller must eventually release the span via a call to either mtev_zipkin_span_drop or mtev_zipkin_span_publish.
 

#### mtev_zipkin_span_publish

>Pulish then release resources allociated with span without publishing.

```c
void 
mtev_zipkin_span_publish(Zipkin_Span *span)
```


  * `span` The span to publish and release.

mtev_zipkin_span_publish first publishes, then releases all resources associated with the span.
 

#### mtev_zipkin_str_to_id

>Convert a string Id to an int64_t Id.

```c
int64_t * 
mtev_zipkin_str_to_id(const char *in, int64_t *buf)
```


  * `in` Id in string form
  * `buf` working buffer (must not be NULL)
  * **RETURN** pointer to translated id

mtev_zipkin_str_to_id will take string form id (trace_id, parent_span_id, or span_id) and convert it to an int64_t.  If conversion fails, the function will return NULL.
 

#### mtev_zipkin_timeval_to_timestamp

>Convert a struct timeval to a timestamp.

```c
int64_t 
mtev_zipkin_timeval_to_timestamp(struct timeval *tv)
```


  * `tv` A point to a struct timeval representing the time in question.
  * **RETURN** a timestamp suitable for use in annotations.

mtev_zipkin_timeval_to_timestamp wil convert a struct timeval (e.g. from gettimeofday) to a the "microseconds since epoch" format expected by Zipkin.
 

