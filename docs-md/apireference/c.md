### A

#### mtev_amqp_send

>Publish an AMQP message to one of the configured amqp brokers.

```c
void
mtev_amqp_send(struct amqp_envelope_t_ *env, int mandatory, int immediate, int id)
```


  * `env` An envelope with a valid message. The env pointer must be word aligned.
  * `mandatory` Set to non-zero if the message should be sent with the mandatory flag.
  * `immediate` Set to non-zero if the message should be sent with the immediate flag.
  * `id` the ID of the connection: -1 to broadcast.
 

#### mtev_amqp_send_data

>Publish an AMQP message to one of the configured amqp brokers.

```c
void
mtev_amqp_send_data(char *exchange, char *route, int mandatory, int immediate, void *payload,
                    int len, int id)
```


  * `exchange` The AMQP exchange to publish to.
  * `route` The route to set on the message.
  * `mandatory` Set to non-zero if the message should be sent with the mandatory flag.
  * `immediate` Set to non-zero if the message should be sent with the immediate flag.
  * `payload` the contents of the message.
  * `len` the number of bytes present in payload.
  * `id` the ID of the connection: -1 to broadcast.
 

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
 

#### mtev_b64_encodev

>Encode raw data as base64 encoded output into the provided buffer.

```c
int
mtev_b64_encodev(const struct iovec *iov, size_t iov_len, char *dest, size_t dest_len)
```


  * `iov` The io-vectors containing the raw data.
  * `iovcnt` The number of io-vectors.
  * `dest` The destination buffer to which the function will produce.
  * `dest_len` The size of the destination buffer.
  * **RETURN** The size of the encoded output.  Returns zero is out_sz is too small.

mtev_b64_encodev encodes an input string into a base64 representation with no linefeeds.
 

#### mtev_b64_max_decode_len

>Calculate how large a buffer must be to contain a decoded base-64-encoded string of a given length.

```c
size_t
mtev_b64_max_decode_len(size_t src_len)
```


  * `src_len` The size (in bytes) of the base-64-encoded string that might be decoded.
  * **RETURN** The size of the buffer that would be needed to decode the input string.
 

### C

#### mtev_cluster_alive_filter

>A `mtev_cluster_node_filter_func_t` for alive nodes.

```c
mtev_cluster_node_filter_func_t
mtev_cluster_alive_filter```



This function is available to be passed as the `filter` argument to `mtev_cluster_filter_owners`.


#### mtev_cluster_am_i_oldest_node

>Determines if the local node is the oldest node within the cluster.

```c
mtev_boolean
mtev_cluster_am_i_oldest_node(const mtev_cluster_t *cluster)
```


  * `cluster` The cluster in question.
  * **RETURN** Returns mtev_false if there is a node in the cluster with a higher up-time than this one.
 

#### mtev_cluster_by_name

>Find the cluster with the registered name.

```c
mtev_cluster_t *
mtev_cluster_by_name(const char *name)
```


  * `name` The name of the cluster.
  * **RETURN** Returns a pointer to the cluster or NULL is not found.

Takes a name and finds a globally registered cluster by that name.
 

#### mtev_cluster_do_i_own

>Determines if the local node should possess a given key based on internal CHTs.

```c
mtev_boolean
mtev_cluster_do_i_own(mtev_cluster_t *cluster, void *key, size_t klen, int w)
```


  * `cluster` The cluster in question.
  * `key` A pointer to the key.
  * `klen` The length, in bytes, of the key.
  * `w` The number of nodes that are supposed to own this key.
  * **RETURN** Returns mtev_true or mtev_false based on ownership status.

This function determines if the local node is among the w nodes in this
cluster that should own the specified key.


#### mtev_cluster_enabled

>Report on the availability of the clusters feature.

```c
mtev_boolean
mtev_cluster_enabled()
```


  * **RETURN** mtev_true if clusters can be configured, otherwise mtev_false.
 

#### mtev_cluster_filter_owners

>Determines if the local node should possess a given key based on internal CHTs.

```c
mtev_boolean
mtev_cluster_filter_owners(mtev_cluster_t *cluster, void *key, size_t klen, mtev_cluster_node_t **set,
                           int *w, mtev_cluster_node_filter_func_t filter, void *closure)
```


  * `cluster` The cluster in question.
  * `key` A pointer to the key.
  * `klen` The length, in bytes, of the key.
  * `set` A caller allocated array of at least *w length.
  * `w` The number of nodes that are supposed to own this key, updated to set length that matches filter.
  * `filter` The function used to qualify nodes.
  * `closure` A user supplied value that is passed to the filter function.
  * **RETURN** Returns mtev_true or mtev_false if set[0] is this node.

This function populates a set of owners for a key, but first filters them according to a user-specified function.


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
 

#### mtev_cluster_get_config_seq

>Returns the current config sequence of the given cluster

```c
int64_t
mtev_cluster_get_config_seq(mtev_cluster_t *cluster)
```


  * `cluster` The cluster in question, may not be NULL.

This function returns the current config sequence of the given cluster
 

#### mtev_cluster_get_heartbeat_payload

>Gets the current value of a payload segment from a node.

```c
int
mtev_cluster_get_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key, void **payload)
```


  * `cluster` The cluster in question, may not be NULL.
  * `app_id` Used to identify the application that attached the payload.
  * `key` Used to identify the payload amongst other payloads from the application.
  * `payload` Pointer to a payload pointer.
  * **RETURN** The length of the payload, -1 if that payload segment does not exist.


#### mtev_cluster_get_my_boot_time

>Returns the boot time of the local node.

```c
struct timeval
mtev_cluster_get_my_boot_time()
```


  * **RETURN** The boot time of the local node.


#### mtev_cluster_get_name

>Returns the name of the cluster.

```c
const char *
mtev_cluster_get_name(mtev_cluster_t *cluster)
```


  * `cluster` a cluster
  * **RETURN** A pointer to the cluster's name.


#### mtev_cluster_get_node

>Find a node in a cluster by id.

```c
mtev_cluster_node_t *
mtev_cluster_get_node(mtev_cluster_t *cluster, uuid_t id)
```


  * `cluster` The cluster in question.
  * `id` The uuid of the node in question.
  * **RETURN** An `mtev_cluster_node_t *` if one is found with the provided id, otherwise NULL,


#### mtev_cluster_get_nodes

>Reports all nodes in the cluster (possible excluding the local node)

```c
int
mtev_cluster_get_nodes(mtev_cluster_t *cluster, mtev_cluster_node_t **nodes, int n
                       mtev_boolean includeme)
```


  * `cluster` The cluster in question.
  * `nodes` The destination array to which a node list will be written.
  * `n` The number of positions available in the passed nodes array.
  * `includeme` Whether the local node should included in the list.
  * **RETURN** Returns the number of nodes populated in the supplied nodes array.  If insufficient space is available, a negative value is returned whose absolute value indicates the required size of the input array.

Enumerates the nodes in a cluster into a provided nodes array.


#### mtev_cluster_get_oldest_node

>Returns the oldest node within the given cluster.

```c
mtev_cluster_get_oldest_node(const mtev_cluster_t *cluster)
```


  * `cluster` The cluster in question.
  * **RETURN** Returns the node in the given cluster with the highest up-time.
 

#### mtev_cluster_get_self

>Reports the UUID of the local node.

```c
void
mtev_cluster_get_self(uuid_t id)
```


  * `id` The UUID to be updated.
  * **RETURN** Returns -1 on error

Pouplates the passed uuid_t with the local node's UUID.


#### mtev_cluster_init

>Initialize the mtev cluster configuration.

```c
void
mtev_cluster_init()
```



Initializes the mtev cluster configuration.
 

#### mtev_cluster_node_get_addr

```c
int8_t
mtev_cluster_node_get_addr(mtev_cluster_node_t *node, struct sockaddr **addr, socklen_t *addrlen)
```

 

#### mtev_cluster_node_get_boot_time

```c
struct timeval
mtev_cluster_node_get_boot_time(mtev_cluster_node_t *node)
```

    * **RETURN** boot time as timeval struct
 

#### mtev_cluster_node_get_cn

```c
const char*
mtev_cluster_node_get_cn(mtev_cluster_node_t *node)
```

  * **RETURN** cn (canonical name) of the cluster node
 

#### mtev_cluster_node_get_config_seq

```c
int64_t
mtev_cluster_node_get_config_seq(mtev_cluster_node_t *node)
```



#### mtev_cluster_node_get_id

>Retrieve the ID of a cluster node.

```c
void
mtev_cluster_node_get_id(mtev_cluster_node_t *node, uuid_t out)
```


  * `node` The node in question.
  * `out` A `uuid_t` to fill in.


#### mtev_cluster_node_get_idx

>Get the unique integer idx of the node within it's cluster.

```c
int
mtev_cluster_node_get_idx(mtev_cluster_node_t *node)
```


  * `node` The node in question
  * **RETURN** A number between 0 and cluster_size - 1.
 

#### mtev_cluster_node_get_last_contact

```c
struct timeval
mtev_cluster_node_get_last_contact(mtev_cluster_node_t *node)
```

  * **RETURN** time of last contact to the given node


#### mtev_cluster_node_has_payload

>Determine a cluster node has a custom payload attached.

```c
mtev_boolean
mtev_cluster_node_has_payload(mtev_cluster_node_t *node)
```


  * `node` The node in question.
  * **RETURN** True if there is a payload, false otherwise.


#### mtev_cluster_node_is_dead

>Detrmines if the node in question is dead.

```c
mtev_boolean
mtev_cluster_node_is_dead(mtev_cluster_node_t *node)
```


  * `node` The node in question.
  * **RETURN** Returns true if the node is dead.


#### mtev_cluster_set_heartbeat_payload

>Triggers the attachment of an arbitrary payload to the cluster heartbeats (see mtev_cluster_handle_node_update)

```c
void
mtev_cluster_set_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key, void* payload
                                   uint8_t payload_length)
```


  * `cluster` The cluster in question, may not be NULL.
  * `app_id` Used to identify the application that attached the payload.
  * `key` Used to identify the payload amongst other payloads from the application.
  * `payload` A pointer to the payload that should be attached to every heartbeat message.
  * `payload_length` The number of bytes to be read from payload.
  * **RETURN** Returns mtev_true if the payload was not enabled yet

This function triggers the attachment of an arbitrary payload to the cluster heartbeats (see mtev_cluster_get_payload)


#### mtev_cluster_set_node_update_callback

>Sets a callback which is called everytime a node in the cluster changes it's up-time.

```c
int
mtev_cluster_set_node_update_callback(mtev_cluster_t *cluster, mtev_cluster_node_update_cb callback)
```


  * `cluster` The cluster in question.
  * `callback` Function pointer to the function that should be called.
  * **RETURN** Returns mtev_true if the cluster is not NULL, mtev_false otherwise


#### mtev_cluster_set_self

>Sets the UUID of the local node.

```c
void
mtev_cluster_set_self(uuid_t id)
```


  * `id` The UUID.

Sets the local node's cluster identity, potentially updating the on-disk configuration.


#### mtev_cluster_size

>Report the number of nodes in the cluster.

```c
int
mtev_cluster_size(mtev_cluster_t *cluster)
```


  * `cluster` The cluster.
  * **RETURN** The number of nodes in the cluster.

Determines the number of nodes in the given cluster.
 

#### mtev_cluster_unset_heartbeat_payload

>Detaches (clears) an arbitrary payload to the cluster heartbeats (see mtev_cluster_handle_node_update)

```c
void
mtev_cluster_unset_heartbeat_payload(mtev_cluster_t *cluster, uint8_t app_id, uint8_t key)
```


  * `cluster` The cluster in question, may not be NULL.
  * `app_id` Used to identify the application that attached the payload.
  * `key` Used to identify the payload amongst other payloads from the application.


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
 

#### mtev_confstr_parse_duration

```c
int
mtev_confstr_parse_duration(const char *input, uint64_t *output
                            const mtev_duration_definition_t *durations)
```

  * ``input`` String representing a duration.
  * ``output`` On successful parsing, filled in with the duration corresponding to `input`.
  * ``durations`` Describes allowable duration suffixes when parsing.
  * **RETURN** One of:
* * MTEV_CONFSTR_PARSE_SUCCESS
    (`input` was parsed successfully, `output` filled in)
* * MTEV_CONFSTR_PARSE_ERR_FORMAT (`input` was not well-formed.)

Parses a string representing a duration. The string should be
formatted as a set of (optionally) white-space separated duration
elements, where a duration element is a number with a resolution
suffix. For example, `"1s"` is a duration element representing one
second, while `"3min"` is a duration element representing three
minutes. The total duration is calculated by adding together all
the duration elements. For example, `"1min 30sec"`, with
resolution in seconds, would result in `output` of `90`; and
`"1min5ms"`, at millisecond resolution, would result in `output`
of `60005`.
 

#### mtev_confstr_parse_duration_ms

```c
int
mtev_confstr_parse_duration_ms(const char *input, uint64_t *output)
```


Convenience function for parsing a duration with resolution in milliseconds.
See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
and <A HREF="#mtevgetdurationsms">mtev_get_durations_ms</A>.
 

#### mtev_confstr_parse_duration_ns

```c
int
mtev_confstr_parse_duration_ns(const char *input, uint64_t *output)
```


Convenience function for parsing a duration with resolution in nanoseconds.
See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
and <A HREF="#mtevgetdurationsns">mtev_get_durations_ns</A>.
 

#### mtev_confstr_parse_duration_s

```c
int
mtev_confstr_parse_duration_s(const char *input, uint64_t *output)
```


Convenience function for parsing a duration with resolution in seconds.
See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
and <A HREF="#mtevgetdurationss">mtev_get_durations_s</A>.
 

#### mtev_confstr_parse_duration_us

```c
int
mtev_confstr_parse_duration_us(const char *input, uint64_t *output)
```


Convenience function for parsing a duration with resolution in microseconds.
See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
and <A HREF="#mtevgetdurationsus">mtev_get_durations_us</A>.
 

#### mtev_curl_write_callback

```c
size_t
mtev_curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
```


> Pass this to CURLOPT_WRITEFUNCTION and use an mtev_decompress_curl_helper_t as the CURLOPT_WRITEDATA




### D

#### mtev_dyn_buffer_add

>add data to the dyn_buffer.

```c
void
mtev_dyn_buffer_add(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len)
```


  * `buf` the buffer to add to.
  * `data` the data to add.
  * `len` the size of the data to add.
 

#### mtev_dyn_buffer_add_printf

>add data to the dyn_buffer using printf semantics.

```c
void
mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...)
```


  * `buf` the buffer to add to.
  * `format` the printf style format string
  * `args` printf arguments

This does NUL terminate the format string but does not advance the write_pointer past
the NUL.  Basically, the last mtev_dyn_buffer_add_printf will leave the resultant
data NUL terminated.

 

#### mtev_dyn_buffer_advance

>move the write_pointer forward len bytes

```c
void
mtev_dyn_buffer_advance(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to advance
 

#### mtev_dyn_buffer_data

>return the front of the dyn_buffer

```c
void
mtev_dyn_buffer_data(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to get the pointer from.
  * **RETURN** the pointer to the front (beginning) of the dyn_buffer
 

#### mtev_dyn_buffer_destroy

>destroy the dyn_buffer

```c
void
mtev_dyn_buffer_destroy(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to destroy

   This must be called at the end of dyn_buffer interactions in case the
   buffer has overflowed into dynamic allocation space.
 

#### mtev_dyn_buffer_ensure

>possibly grow the dyn_buffer so it can fit len bytes

```c
void
mtev_dyn_buffer_ensure(mtev_dyn_buffer_t *buf, size_t len)
```


  * `buf` the buffer to ensure
  * `len` the size of the data about to be added
 

#### mtev_dyn_buffer_init

>initialize a dyn_buffer

```c
void
mtev_dyn_buffer_init(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to init

   Provided for completeness or non-stack allocations.
 

#### mtev_dyn_buffer_reset

>move the write position to the beginning of the buffer

```c
void
mtev_dyn_buffer_reset(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to reset.
 

#### mtev_dyn_buffer_size

>return the total size of the buffer

```c
void
mtev_dyn_buffer_size(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to get the size from.
  * **RETURN** the total size of the buffer
 

#### mtev_dyn_buffer_used

>return the total used space of the buffer

```c
void
mtev_dyn_buffer_used(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to get the used space from.
  * **RETURN** the total used space of the buffer
 

#### mtev_dyn_buffer_write_pointer

>return the end of the dyn_buffer

```c
void
mtev_dyn_buffer_write_pointer(mtev_dyn_buffer_t *buf)
```


  * `buf` the buffer to get the pointer from.
  * **RETURN** the pointer to the end of the dyn_buffer
 

### E

#### eventer_accept

>Execute an opset-appropriate `accept` call.

```c
int
eventer_accept(eventer_t e, struct sockaddr *addr, socklen_t *len, int *mask)
```


  * `e` an event object
  * `addr` a `struct sockaddr` to be populated.
  * `len` a `socklen_t` pointer to the size of the `addr` argument; updated.
  * `mask` a point the a mask. If the call does not complete, `*mask` it set.
  * **RETURN** an opset-appropriate return value. (fd for POSIX, -1 for SSL).

If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
necessary activity to make progress.


#### eventer_aco_accept

>Execute an opset-appropriate `accept` call.

```c
int
eventer_aco_accept(eventer_t e, struct sockaddr *addr, socklen_t *len, struct timeval *timeout)
```


  * `e` an event object
  * `addr` a `struct sockaddr` to be populated.
  * `len` a `socklen_t` pointer to the size of the `addr` argument; updated.
  * `timeout` if not NULL, the time after which we fail -1, ETIME
  * **RETURN** an opset-appropriate return value. (fd for POSIX, -1 for SSL).


#### eventer_aco_arg

>Gets the argument used to start an aco coroutine.

```c
void *
eventer_aco_arg(void)
```


  * **RETURN** The closure parameter that was passed to `eventer_aco_start`.


#### eventer_aco_close

>Execute an opset-appropriate `close` call.

```c
int
eventer_aco_close(eventer_aco_t e)
```


  * `e` an event object
  * **RETURN** 0 on sucess or -1 with errno set.


#### eventer_aco_free

>Dereferences the event specified.

```c
void
eventer_aco_free(eventer_aco_t e)
```


  * `e` the event to dereference.


#### eventer_aco_get_closure

>Retrieve an event's closure.

```c
void *
eventer_aco_get_closure(eventer_aco_t e)
```


  * `e` an event object
  * **RETURN** The previous closure set.


#### eventer_aco_read

>Execute an opset-appropriate `read` call.

```c
int
eventer_aco_read(eventer_aco_t e, void *buff, size_t len, struct timeval *timeout)
```


  * `e` an event object
  * `buff` a buffer in which to place read data.
  * `len` the size of `buff` in bytes.
  * `timeout` if not NULL, the time after which we fail -1, ETIME
  * **RETURN** the number of bytes read or -1 with errno set.


#### eventer_aco_run_asynch

>Add an asynchronous event dependent on the current job and wait until completion.

```c
mtev_boolean
eventer_aco_run_asynch(eventer_t e)
```


  * `e` an event object
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the default job queue.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_aco_run_asynch_queue

>Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.

```c
mtev_boolean
eventer_aco_run_asynch_queue(eventer_jobq_t *q, eventer_t e)
```


  * `q` a job queue
  * `e` an event object
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_aco_run_asynch_queue_subqueue

>Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.

```c
mtev_boolean
eventer_aco_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_aco_set_accept_timeout

>Change the default timeout for ACO events.

```c
void
eventer_aco_set_accept_timeout(eventer_aco_t e, struct timeval *duration)
```


  * `e` the ACO event to update.
  * `duration` a timeout duration, NULL will undo the default.


#### eventer_aco_set_closure

>Set an event's closure.

```c
void
eventer_aco_set_closure(eventer_aco_t e, void *closure)
```


  * `e` an event object
  * `closure` a pointer to user-data to be supplied during callback.


#### eventer_aco_set_read_timeout

>Change the default timeout for ACO events.

```c
void
eventer_aco_set_read_timeout(eventer_aco_t e, struct timeval *duration)
```


  * `e` the ACO event to update.
  * `duration` a timeout duration, NULL will undo the default.


#### eventer_aco_set_write_timeout

>Change the default timeout for ACO events.

```c
void
eventer_aco_set_write_timeout(eventer_aco_t e, struct timeval *duration)
```


  * `e` the ACO event to update.
  * `duration` a timeout duration, NULL will undo the default.


#### eventer_aco_simple_asynch

>Asynchronously execute a function.

```c
void
eventer_aco_simple_asynch(eventer_asynch_func_t func, void *closure)
```


  * `func` the function to execute.
  * `closure` the closure for the function.


#### eventer_aco_simple_asynch_queue

>Asynchronously execute a function.

```c
void
eventer_aco_simple_asynch_queue(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q)
```


  * `func` the function to execute.
  * `closure` the closure for the function.
  * `q` the jobq on which to schedule the work.


#### eventer_aco_simple_asynch_queue_subqueue

>Asynchronously execute a function.

```c
void
eventer_aco_simple_asynch_queue_subqueue(eventer_asynch_func_t func, void *closure, eventer_jobq_t *q, uint64_t id)
```


  * `func` the function to execute.
  * `closure` the closure for the function.
  * `q` the jobq on which to schedule the work.
  * `id` the subqueue within the jobq.


#### eventer_aco_sleep

>Execute a sleep within an aco context.

```c
void
eventer_aco_sleep(struct timeval *duration)
```


  * `duration` the time to suspend.


#### eventer_aco_start

>Start a new aco coroutine to be eventer driven.

```c
void
eventer_aco_start(void (*func)(void), void *closure)
```


  * `func` The function to start.
  * `closure` The closure to set (available within `func` via `eventer_aco_arg()`)


#### eventer_aco_start_stack

>Start a new aco coroutine to be eventer driven.

```c
void
eventer_aco_start_stack(void (*func)(void), void *closure, size_t stksz)
```


  * `func` The function to start.
  * `closure` The closure to set (available within `func` via `eventer_aco_arg()`)
  * `stksz` A specified maximum stack size other than the default 32k.


#### eventer_aco_try_run_asynch_queue_subqueue

>Add an asynchronous event to a specific job queue dependent on the current job and wait until completion.

```c
mtev_boolean
eventer_aco_try_run_asynch_queue_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_aco_write

>Execute an opset-appropriate `write` call.

```c
int
eventer_aco_write(eventer_aco_t e, const void *buff, size_t len, struct timeval *timeout)
```


  * `e` an event object
  * `buff` a buffer containing data to write.
  * `len` the size of `buff` in bytes.
  * `timeout` if not NULL, the time after which we fail -1, ETIME
  * **RETURN** the number of bytes written or -1 with errno set.


#### eventer_add

>Add an event object to the eventer system.

```c
void
eventer_add(eventer_t e)
```


  * `e` an event object to add.


#### eventer_add_asynch

>Add an asynchronous event to a specific job queue.

```c
void
eventer_add_asynch(eventer_jobq_t *q, eventer_t e)
```


  * `q` a job queue
  * `e` an event object

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.


#### eventer_add_asynch_dep

>Add an asynchronous event to a specific job queue dependent on the current job.

```c
void
eventer_add_asynch_dep(eventer_jobq_t *q, eventer_t e)
```


  * `q` a job queue
  * `e` an event object

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_add_asynch_dep_subqueue

>Add an asynchronous event to a specific job queue dependent on the current job.

```c
void
eventer_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_add_asynch_subqueue

>Add an asynchronous event to a specific job queue.

```c
void
eventer_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.


#### eventer_add_at

>Convenience function to schedule a callback at a specific time.

```c
eventer_t
eventer_add_at(eventer_func_t func, void *closure, struct timeval whence)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `whence` the time at which to run the callback.
  * **RETURN** N/A (C Macro).


#### eventer_add_in

>Convenience function to create an event to run a callback in the future

```c
eventer_t
eventer_add_in(eventer_func_t func, void *closure, struct timeval diff)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `diff` the amount of time to wait before running the callback.
  * **RETURN** N/A (C Macro).


#### eventer_add_in_s_us

>Convenience function to create an event to run a callback in the future

```c
eventer_t
eventer_add_in_s_us(eventer_func_t func, void *closure, unsigned long seconds
                    unsigned long microseconds)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `seconds` the number of seconds to wait before running the callback.
  * `microseconds` the number of microseconds (in addition to `seconds`) to wait before running the callback.
  * **RETURN** N/A (C Macro).


#### eventer_add_recurrent

>Add an event to run during every loop cycle.

```c
void
eventer_add_recurrent(eventer_t e)
```


  * `e` an event object

`e` must have a mask of EVENER_RECURRENT.  This event will be invoked on
a single thread (dictated by `e`) once for each pass through the eventer loop.
This happens _often_, so do light work.


#### eventer_add_timed

>Add a timed event to the eventer system.

```c
void
eventer_add_timed(eventer_t e)
```


  * `e` an event object

This adds the `e` event to the eventer. `e` must have a mask of
`EVENTER_TIMED`.


#### eventer_add_timer_next_opportunity

>Convenience function to schedule a callback to run in a specific event-loop thread.

```c
eventer_t
eventer_add_timer_next_opportunity(eventer_func_t func, void *closure, pthread_t owner)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `owner` the event-loop thread in which to run the callback.
  * **RETURN** N/A (C Macro).


#### eventer_alloc

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc()
```


  * **RETURN** A newly allocated event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


#### eventer_alloc_asynch

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc_asynch(eventer_func_t func, void *closure)
```


  * `func` The callback function.
  * `closure` The closure for the callback function.
  * **RETURN** A newly allocated asynch event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


#### eventer_alloc_asynch_timeout

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc_asynch_timeout(eventer_func_t func, void *closure, struct timeval *deadline)
```


  * `func` The callback function.
  * `closure` The closure for the callback function.
  * `deadline` an absolute time by which the task must be completed.
  * **RETURN** A newly allocated asynch event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.  Depending on the timeout method, there are not hard
guarantees on enforcing the deadline; this is more of a guideline for
the schedule and the job could be aborted (where the `EVENTER_ASYNCH_WORK`
phase is not finished or even started, but the `EVENTER_ASYNCH_CLEANUP`
will be called).


#### eventer_alloc_copy

>Allocate an event copied from another to be injected into the eventer system.

```c
eventer_t
eventer_alloc_copy(eventer_t src)
```


  * `src` a source eventer_t to copy.
  * **RETURN** A newly allocated event that is a copy of src.

The allocated event has a refernce count of 1.


#### eventer_alloc_fd

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc_fd(eventer_func_t func, void *closure, int fd, int mask)
```


  * `func` The callback function.
  * `closure` The closure for the callback function.
  * `fd` The file descriptor.
  * `mask` The mask of activity of interest.
  * **RETURN** A newly allocated fd event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


#### eventer_alloc_recurrent

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc_recurrent(eventer_func_t func, void *closure)
```


  * `func` The callback function.
  * `closure` The closure for the callback function.
  * **RETURN** A newly allocated recurrent event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


#### eventer_alloc_timer

>Allocate an event to be injected into the eventer system.

```c
eventer_t
eventer_alloc_timer(eventer_func_t func, void *closure, struct timeval *whence)
```


  * `func` The callback function.
  * `closure` The closure for the callback function.
  * `whence` The time at which the event should fire.
  * **RETURN** A newly allocated timer event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


#### eventer_alloc_timer_next_opportunity

>Convenience function to create an event to run a callback on a specific thread.

```c
eventer_t
eventer_alloc_timer_next_opportunity(eventer_func_t func, void *closure, pthread_t owner)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `owner` the event-loop thread on which to run the callback.
  * **RETURN** an event that has not been added to the eventer.

> Note this does not actually schedule the event. See [`eventer_add_timer_next_opportunity`](c.md#eventeraddtimernextopportunity).


#### eventer_allocations_current

```c
int64_t
eventer_allocations_current()
```

  * **RETURN** the number of currently allocated eventer objects.


#### eventer_allocations_total

```c
int64_t
eventer_allocations_total()
```

  * **RETURN** the number of allocated eventer objects over the life of the process.


#### eventer_at

>Convenience function to create an event to run a callback at a specific time.

```c
eventer_t
eventer_at(eventer_func_t func, void *closure, struct timeval whence)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `whence` the time at which to run the callback.
  * **RETURN** an event that has not been added to the eventer.

> Note this does not actually schedule the event. See [`eventer_add_at`](c.md#eventeraddat).


#### eventer_callback

>Directly invoke an event's callback.

```c
int
eventer_callback(eventer_t e, int mask, void *closure, struct timeval *now)
```


  * `e` an event object
  * `mask` the mask that callback should be acting upon (see `eventer_get_mask`)
  * `closure` the closure on which the callback should act
  * `now` the time the callback should see as "now".
  * **RETURN** The return value of the callback function as invoked.

This does not call the callback in the contexts of the eventloop.  This means
that should the callback return a mask, the event-loop will not interpret it
and change state appropriately.  The caller must respond appropriately to any
return values.


#### eventer_callback_for_name

>Find an event callback function that has been registered by name.

```c
evneter_func_t
eventer_callback_for_name(const char *name)
```


  * `name` the name of the callback.
  * **RETURN** the function pointer or NULL if no such callback has been registered.


#### eventer_callback_ms

>Get the milliseconds since epoch of the current callback invocation.

```c
uint64_t
eventer_callback_ms()
```


  * **RETURN** milliseconds since epoch of callback invocation, or current time.
 

#### eventer_callback_us

>Get the microseconds since epoch of the current callback invocation.

```c
uint64_t
eventer_callback_us()
```


  * **RETURN** microseconds since epoch of callback invocation, or current time.
 

#### eventer_choose_owner

>Find a thread in the default eventer pool.

```c
pthread_t
eventer_choose_owner(int n)
```


  * `n` an integer.
  * **RETURN** a pthread_t of an eventer loop thread in the default eventer pool.

This return the first thread when 0 is passed as an argument.  All non-zero arguments
are spread across the remaining threads (if existent) as `n` modulo one less than
the concurrency of the default event pool.

This is done because many systems aren't thread safe and can only schedule their
work on a single thread (thread 1). By spreading all thread-safe workloads across
the remaining threads we reduce potential overloading of the "main" thread.

To assign an event to a thread, use the result of this function to assign:
`e->thr_owner`.


#### eventer_choose_owner_pool

>Find a thread in a specific eventer pool.

```c
pthread_t
eventer_choose_owner_pool(eventer_pool_t *pool, int n)
```


  * `pool` an eventer pool.
  * `n` an integer.
  * **RETURN** a pthread_t of an eventer loop thread in the specified evneter pool.

This function chooses a thread within the specified pool by taking `n`
modulo the concurrency of the pool.  If the default pool is speicified, special
assignment behavior applies. See [`eventer_choose_owner`](c.md#eventerchooseowner).

To assign an event to a thread, use the result of this function to assign:
`e->thr_owner`.


#### eventer_close

>Execute an opset-appropriate `close` call.

```c
int
eventer_close(eventer_t e, int *mask)
```


  * `e` an event object
  * `mask` a point the a mask. If the call does not complete, `*mask` it set.
  * **RETURN** 0 on sucess or -1 with errno set.

If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
necessary activity to make progress.


#### eventer_deref

>See eventer_free.

```c
void
eventer_deref(eventer_t e)
```


  * `e` the event to dereference.


#### eventer_fd_opset_get_accept

>Retrieve the accept function from an fd opset.

```c
eventer_fd_accept_t
eventer_fd_opset_get_accept(eventer_fd_opset_t opset)
```


  * `opset` an opset (see `eventer_get_fd_opset`)
  * **RETURN** An eventer_fd_accept_t function


#### eventer_fd_opset_get_close

>Retrieve the close function from an fd opset.

```c
eventer_fd_close_t
eventer_fd_opset_get_close(eventer_fd_opset_t opset)
```


  * `opset` an opset (see `eventer_get_fd_opset`)
  * **RETURN** An eventer_fd_close_t function


#### eventer_fd_opset_get_read

>Retrieve the read function from an fd opset.

```c
eventer_fd_read_t
eventer_fd_opset_get_read(eventer_fd_opset_t opset)
```


  * `opset` an opset (see `eventer_get_fd_opset`)
  * **RETURN** An eventer_fd_read_t function


#### eventer_fd_opset_get_write

>Retrieve the write function from an fd opset.

```c
eventer_fd_write_t
eventer_fd_opset_get_write(eventer_fd_opset_t opset)
```


  * `opset` an opset (see `eventer_get_fd_opset`)
  * **RETURN** An eventer_fd_write_t function


#### eventer_find_fd

>Find an event object in the eventer system by file descriptor.

```c
eventer_t
eventer_find_fd(int e)
```


  * `fd` a file descriptor
  * **RETURN** the event object if it exists; NULL if not found.


#### eventer_foreach_fdevent

>Run a user-provided function over all registered file descriptor events.

```c
void
eventer_foreach_fdevent(void (*fn)(eventer_t, void *), void *closure)
```


  * `fn` a function to be called with each event and `closure` as its arguments.
  * `closure` the second argument to be passed to `fn`.


#### eventer_foreach_timedevent

>Run a user-provided function over all registered timed events.

```c
void
eventer_foreach_timedevent(void (*fn)(eventer_t, void *), void *closure)
```


  * `fn` a function to be called with each event and `closure` as its arguments.
  * `closure` the second argument to be passed to `fn`.


#### eventer_free

>Dereferences the event specified.

```c
void
eventer_free(eventer_t e)
```


  * `e` the event to dereference.


#### eventer_get_callback

>Retrieve the callback function for an event.

```c
eventer_func_t
eventer_get_callback(eventer_t e)
```


  * `e` an event object
  * **RETURN** An `eventer_func_t` callback function.


#### eventer_get_closure

>Retrieve an event's closure.

```c
void *
eventer_get_closure(eventer_t e)
```


  * `e` an event object
  * **RETURN** The previous closure set.


#### eventer_get_context

>Get a context for an event.

```c
int
eventer_get_context(eventer_t e, int ctx_idx)
```


  * `e` an event object
  * `ctx_idx` is an idx returned from `eventer_register_context`
  * **RETURN** The attached context.


#### eventer_get_epoch

>Find the start time of the eventer loop.

```c
int
eventer_get_epoch(struct timeval *epoch)
```


  * `epoch` a point to a `struct timeval` to fill out.
  * **RETURN** 0 on success; -1 on failure (eventer loop not started).


#### eventer_get_fd

>Retrieve the file descriptor for an fd-based event.

```c
int
eventer_get_fd(eventer_t e)
```


  * `e` an event object
  * **RETURN** a file descriptor.


#### eventer_get_fd_opset

>Retrieve the fd opset from an event.

```c
eventer_fd_opset_t
eventer_get_fd_opset(eventer_t e)
```


  * `e` an event object
  * **RETURN** The currently active opset for a fd-based eventer_t.


#### eventer_get_mask

>Retrieve the mask for an event.

```c
int
eventer_get_mask(eventer_t e)
```


  * `e` an event object
  * **RETURN** a mask of bitwise-or'd valued.

    * `EVENTER_READ` -- trigger/set when a file descriptor is readable.
    * `EVENTER_WRITE` -- trigger/set when a file descriptor is writeable.
    * `EVENTER_EXCEPTION` -- trigger/set problems with a file descriptor.
    * `EVENTER_TIMER` -- trigger/set at a specific time.
    * `EVENTER_RECURRENT` -- trigger/set on each pass through the event-loop.
    * `EVENTER_ASYNCH` -- trigger from a non-event-loop thread, set upon completion.
    * `EVENTER_ASYNCH_WORK` -- set during asynchronous work.
    * `EVENTER_ASYNCH_CLEANUP` -- set during asynchronous cleanup.


#### eventer_get_owner

>Retrieve the thread that owns an event.

```c
pthread_t
eventer_get_owner(eventer_t e)
```


  * `e` an event object
  * **RETURN** a `pthread_t` thread.


#### eventer_get_pool_for_event

>Determin which eventer pool owns a given event.

```c
eventer_pool_t *
eventer_get_pool_for_event(eventer_t e)
```


  * `e` an event object.
  * **RETURN** the `eventer_pool_t` to which the event is scheduled.


#### eventer_get_this_event

>Get the eventer_t (if any) of which we are currently in the callback.

```c
eventer_t
eventer_get_this_event(void)
```


  * **RETURN** An eventer_t or NULL.


#### eventer_get_thread_name

>Retrieve a human-friendly name for an eventer thread.

```c
const char *
eventer_get_thread_name(void)
```


  * **RETURN** A thread name.


#### eventer_get_whence

>Retrieve the time at which a timer event will fire.

```c
struct timeval
eventer_get_whence(eventer_t e)
```


  * `e` an event object
  * **RETURN** A absolute time.


#### eventer_gettimeofcallback

>Get the time of the last invoked callback in this thread.

```c
eventer_gettimeofcallback(struct timeval *now, void *tzp)
```


  * `now` a `struct timeval` to populate with the request time.
  * `tzp` is ignored and for API compatibility with gettimeofday.
  * **RETURN** 0 on success, non-zero on failure.

This function returns the time of the last callback execution.  It
is fast and cheap (cheaper than gettimeofday), so if a function
wishes to know what time it is and the "time of invocation" is good
enough, this is considerably cheaper than a call to `mtev_gettimeofday`
or other system facilities.
 

#### eventer_impl_propset

>Set properties for the event loop.

```c
int
eventer_impl_propset(const char *key, const char *value)
```


  * `key` the property
  * `value` the property's value.
  * **RETURN** 0 on success, -1 otherwise.

Sets propoerties within the eventer. That can only be called prior
to [`eventer_init`](c.md#eventerinit). See [Eventer configuuration)(../config/eventer.md)
for valid properties.


#### eventer_impl_setrlimit

>Attempt to set the rlimit on allowable open files.

```c
int
eventer_impl_setrlimit()
```


  * **RETURN** the limit of the number of open files.

The target is the `rlim_nofiles` eventer config option. If that configuration
option is unspecified, 1048576 is used.


#### eventer_in

>Convenience function to create an event to run a callback in the future

```c
eventer_t
eventer_in(eventer_func_t func, void *closure, struct timeval diff)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `diff` the amount of time to wait before running the callback.
  * **RETURN** an event that has not been added to the eventer.

> Note this does not actually schedule the event. See [`eventer_add_in`](c.md#eventeraddin).


#### eventer_in_loop

>Determine if the current thread is an event loop thread.

```c
mtev_boolean
eventer_in_loop(void)
```


  * **RETURN** mtev_true if currently in an event loop thread, mtev_false otherwise.


#### eventer_in_s_us

>Convenience function to create an event to run a callback in the future

```c
eventer_t
eventer_in_s_us(eventer_func_t func, void *closure, unsigned long seconds
                unsigned long microseconds)
```


  * `func` the callback function to run.
  * `closure` the closure to be passed to the callback.
  * `seconds` the number of seconds to wait before running the callback.
  * `microseconds` the number of microseconds (in addition to `seconds`) to wait before running the callback.
  * **RETURN** an event that has not been added to the eventer.

> Note this does not actually schedule the event. See [`eventer_add_in_s_us`](c.md#eventeraddinsus).


#### eventer_init_globals

>Initialize global structures required for eventer operation.

```c
void
eventer_init_globals()
```



This function is called by [`mtev_main`](c.md#mtevmain).  Developers should not
need to call this function directly.


#### eventer_is_loop

>Determine if a thread is participating in the eventer loop.

```c
int
eventer_is_loop(pthread_t tid)
```


  * `tid` a thread
  * **RETURN** 0 if the specified thread lives outside the eventer loop; 1 otherwise.


#### eventer_jobq_create

>Create a new jobq.

```c
eventer_jobq_t *
eventer_jobq_create(const char *queue_name)
```


  * `queue_name` a name for the new jobq
  * **RETURN** a pointer to a new (or existing) jobq with that name. NULL on error.


#### eventer_jobq_create_backq

>Create a new jobq for use as a return queue.

```c
eventer_jobq_t *
eventer_jobq_create_backq(const char *queue_name)
```


  * `queue_name` a name for the new jobq
  * **RETURN** a pointer to a new (or existing) jobq with that name. NULL on error.


#### eventer_jobq_create_ms

>Create a new jobq with the specified memory safety.

```c
eventer_jobq_t *
eventer_jobq_create_ms(const char *queue_name, eventer_jobq_memory_safety_t safety)
```


  * `queue_name` a name for the new jobq
  * `safety` a specific mtev_memory safey level for epoch-based memory reclamation schemes.
  * **RETURN** a pointer to a new (or existing) jobq with that name. NULL on error.


#### eventer_jobq_destroy

>Destory a jobq.

```c
void
eventer_jobq_destroy(eventer_jobq_t *jobq)
```




#### eventer_jobq_inflight

>Reveal the currently executing job (visiable to a callee).

```c
eventer_job_t *
eventer_jobq_inflight(void)
```


  * **RETURN** the job that is currentlt running in the calling thread.


#### eventer_jobq_post

>Wake up a jobq to see if there are pending events.

```c
void
eventer_jobq_post(eventer_jobq_t *jobq)
```


  * `jobq` the jobq to post to.


#### eventer_jobq_retrieve

>Find a jobq by name.

```c
eventer_jobq_t *
eventer_jobq_retrieve(const char *name)
```


  * `name` the name of a jobq
  * **RETURN** a jobq or NULL if no such jobq exists.


#### eventer_jobq_set_concurrency

>Set a jobq's concurrency level.

```c
void
eventer_jobq_set_concurrency(eventer_jobq_t *jobq, uint32_t new_concurrency)
```


  * `jobq` the jobq to modify
  * `new_concurrency` the new number of desired threads


#### eventer_jobq_set_floor

>Set a jobq's minimum active thread count.

```c
void
eventer_jobq_set_floor(eventer_jobq_t *jobq, uint32_t new_floor)
```


  * `jobq` the jobq to modify
  * `new_floor` the new number of minimum threads


#### eventer_jobq_set_max_backlog

>Set and advisory limit on the backlog a jobq will handle.

```c
void
eventer_jobq_set_max_backlog(eventer_jobq_t *jobq, uint32_t max)
```


  * `jobq` the jobq to modify
  * `max` a maximum pending jobs count before eventer_try_add_asynch calls will fail.


#### eventer_jobq_set_min_max

>Set the upper and lower bounds on desired concurrency for a jobq.

```c
void
eventer_jobq_set_min_max(eventer_jobq_t *jobq, uint32_t min, uint32_t max)
```


  * `jobq` the jobq to modify
  * `min` a minimum number of threads to maintain
  * `max` a maximum number of threads to not exceed


#### eventer_jobq_set_shortname

>Set a "shorter" name for a jobq to be used in terse displays.

```c
void
eventer_jobq_set_shortname(eventer_jobq_t *jobq, const char *name)
```


  * `jobq` the jobq to modify
  * `name` a shorter name for a job (clipped to 13 characters)


#### eventer_loop

>Start the event loop.

```c
void
eventer_loop()
```


  * **RETURN** N/A (does not return)

This function should be called as that last thing in your `child_main` function.
See [`mtev_main`](c.md#mtevmain`).


#### eventer_loop_concurrency

>Determine the concurrency of the default eventer loop.

```c
int
eventer_loop_concurrency()
```


  * **RETURN** number of threads used for the default eventer loop.


#### eventer_loop_return

>Start the event loop and return control to the caller.

```c
void
eventer_loop_return()
```



This function should be called as that last thing in your `child_main` function.
Be sure not to return or exit after calling this as it could terminate your program.
See [`mtev_main`](c.md#mtevmain`).


#### eventer_name_callback

>Register a human/developer readable name for a eventer callback function.

```c
int
eventer_name_callback(const char *name, eventer_func_t callback)
```


  * `name` the human readable name.
  * `callback` the functin pointer of the eveter callback.
  * **RETURN** 0 on success.


#### eventer_name_callback_ext

>Register a functional describer for a callback and it's event object.

```c
int
eventer_name_callback_ext(const char *name, eventer_func_t callback, void (*fn)(char *buff, int bufflen,
                          eventer_t e, void *closure), void *closure)
```


  * `name` the human readable name.
  * `callback` the functin pointer of the eveter callback.
  * `fn` function to call when describing the event. It should write a null terminated string into buff (no more than bufflen).
  * **RETURN** 0 on success.

This function allows more in-depth descriptions of events.  When an event
is displayed (over the console or REST endpoints), this function is called
with the event in question and the closure specified at registration time.


#### eventer_name_for_callback

>Retrieve a human readable name for the provided callback with event context.

```c
const char *
eventer_name_for_callback(evneter_func_t f, eventer_t e)
```


  * `f` a callback function.
  * `e` and event object
  * **RETURN** name of callback

The returned value may be a pointer to reusable thread-local storage.
The value should be used before a subsequent call to this function.
Aside from that caveat, it is thread-safe.


#### eventer_pool

>Find an eventer pool by name.

```c
eventer_pool_t *
eventer_pool(const char *name)
```


  * `name` the name of an eventer pool.
  * **RETURN** an `eventer_pool_t *` by the given name, or NULL.


#### eventer_pool_concurrency

>Retrieve the concurrency of an eventer pool.

```c
uint32_t
eventer_pool_concurrency(eventer_pool_t *pool)
```


  * `pool` an eventer pool.
  * **RETURN** the number of threads powering the specified pool.


#### eventer_pool_name

>Retrieve the name of an eventer pool.

```c
const char *
eventer_pool_name(eventer_pool_t *pool)
```


  * `pool` an eventer pool.
  * **RETURN** the name of the eventer pool.


#### eventer_pool_watchdog_timeout

>Set a custom watchdog timeout for threads in an eventer pool.

```c
void
eventer_pool_watchdog_timeout(eventer_pool_t *pool, double timeout)
```


  * `pool` an eventer pool
  * `timeout` the deadman timer in seconds.


#### eventer_read

>Execute an opset-appropriate `read` call.

```c
int
eventer_read(eventer_t e, void *buff, size_t len, int *mask)
```


  * `e` an event object
  * `buff` a buffer in which to place read data.
  * `len` the size of `buff` in bytes.
  * `mask` a point the a mask. If the call does not complete, `*mask` it set.
  * **RETURN** the number of bytes read or -1 with errno set.

If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
necessary activity to make progress.


#### eventer_ref

>Add a reference to an event.

```c
void
eventer_ref(eventer_t e)
```


  * `e` the event to reference.

Adding a reference to an event will prevent it from being deallocated
prematurely.  This is classic reference counting.  It is are that one
needs to maintain an actual event past the point where the eventer
system would normally free it.  Typically, one will allocate a new
event and copy the contents of the old event into it allowing the
original to be freed.


#### eventer_register_context

>Register an eventer carry context.

```c
int
eventer_register_context(const char *name, eventer_context_opset_t *opset)
```


  * `name` a string naming the context class.
  * `opset` an opset for context maintenance
  * **RETURN** A `ctx_idx`, -1 on failure.


#### eventer_remove

>Remove an event object from the eventer system.

```c
eventer_t
eventer_remove(eventer_t e)
```


  * `e` an event object to add.
  * **RETURN** the event object removed if found; NULL if not found.


#### eventer_remove_fd

>Remove an event object from the eventer system by file descriptor.

```c
eventer_t
eventer_remove_fd(int e)
```


  * `fd` a file descriptor
  * **RETURN** the event object removed if found; NULL if not found.


#### eventer_remove_fde

>Removes an fd event from the eventloop based on filedescriptor alone.

```c
eventer_t
eventer_remove_fde(eventer_t e)
```


  * `e` an event object
  * **RETURN** The event removed, NULL if no event was present.


#### eventer_remove_recurrent

>Remove a recurrent event from the eventer.

```c
eventer_t
eventer_remove_recurrent(eventer_t e)
```


  * `e` an event object.
  * **RETURN** The event removed (`== e`); NULL if not found.


#### eventer_remove_timed

>Remove a timed event from the eventer.

```c
eventer_t
eventer_remove_timed(eventer_t e)
```


  * `e` an event object (mask must be `EVENTER_TIMED`).
  * **RETURN** the event removed, NULL if not found.


#### eventer_run_in_thread

>Spawns a thread and runs the event until it returns 0.

```c
void
eventer_run_in_thread(eventer_t e, int mask)
```


  * `e` an event object
  * `a` starting mask for triggering the event.

This function will remove the event from the eventer and set the socket into blocking mode.


#### eventer_set_callback

>Set an event's callback function.

```c
void
eventer_set_callback(eventer_t e, eventer_func_t func)
```


  * `e` an event object


#### eventer_set_closure

>Set an event's closure.

```c
void
eventer_set_closure(eventer_t e, void *closure)
```


  * `e` an event object
  * `closure` a pointer to user-data to be supplied during callback.


#### eventer_set_context

>Set a context for an event.

```c
void *
eventer_set_context(eventer_t e, int ctx_idx, void *data)
```


  * `e` an event object
  * `ctx_idx` is an idx returned from `eventer_register_context`
  * `data` is new context data.
  * **RETURN** The previously attached context.


#### eventer_set_eventer_aco

>Convert an eventer_t into an eventer_aco_t.

```c
eventer_aco_t
eventer_set_eventer_aco(eventer_t e)
```


  * `e` an event object
  * **RETURN** The converted event.

This calls `eventer_set_eventer_aco_co` with the current aco
as the `co` argument.


#### eventer_set_eventer_aco_co

>Convert an eventer_t into an eventer_aco_t.

```c
eventer_aco_t
eventer_set_eventer_aco_co(eventer_t e, aco_t *co)
```


  * `e` an event object
  * `co` a coroutine to which the event should bound. NULL to revert.
  * **RETURN** The converted event.

The input event is modified in-place.  If the NULL is passed as co,
then the event is reverted and NULL is returned.  You almost always
want to be calling this on a brand-new object or a `eventer_alloc_copy`
of a pre-existing object.


#### eventer_set_fd_blocking

>Set a file descriptor into blocking mode.

```c
int
eventer_set_fd_blocking(int fd)
```


  * `fd` a file descriptor
  * **RETURN** 0 on success, -1 on error (errno set).


#### eventer_set_fd_nonblocking

>Set a file descriptor into non-blocking mode.

```c
int
eventer_set_fd_nonblocking(int fd)
```


  * `fd` a file descriptor
  * **RETURN** 0 on success, -1 on error (errno set).


#### eventer_set_mask

>Change an event's interests or intentions.

```c
void
eventer_set_mask(eventer_t e, int mask)
```


  * `e` an event object
  * `mask` a new mask

Do not change change a mask from one event "type" to another. fd events
must remain fd events. Timer must remain timer. Recurrent must remain recurrent.
Do not alter asynch events at all.  This simply changes the mask of the event
without changing any eventer state and should be used with extremem care.
Consider using the callback's return value or `eventer_update` to change
the mask of an active event in the system.


#### eventer_set_owner

>Set the thread that owns an event.

```c
void
eventer_set_owner(eventer_t e, pthread_t t)
```


  * `e` an event object
  * `t` a `pthread_t` thread; must be a valid event-loop.


#### eventer_thread_check

>Determine if the calling thread "owns" an event.

```c
int
eventer_thread_check(eventer_t e)
```


  * `e` an event object
  * **RETURN** 0 if `e->thr_owner` is the `pthread_self()`, non-zero otherwise.


#### eventer_trigger

>Trigger an unregistered eventer and incorporate the outcome into the eventer.

```c
void
eventer_trigger(eventer_t e, int mask)
```


  * `e` an event object that is not registered with the eventer.
  * `mask` the mask to be used when invoking the event's callback.

This is often used to "start back up" an event that has been removed from the
eventer for any reason.


#### eventer_try_add_asynch

>Add an asynchronous event to a specific job queue.

```c
mtev_boolean
eventer_try_add_asynch(eventer_jobq_t *q, eventer_t e)
```


  * `q` a job queue
  * `e` an event object
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.


#### eventer_try_add_asynch_dep

>Add an asynchronous event to a specific job queue dependent on the current job.

```c
mtev_boolean
eventer_try_add_asynch_dep(eventer_jobq_t *q, eventer_t e)
```


  * `q` a job queue
  * `e` an event object
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_try_add_asynch_dep_subqueue

>Add an asynchronous event to a specific job queue dependent on the current job.

```c
mtev_boolean
eventer_try_add_asynch_dep_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.  This should be called from within a asynch callback
during a mask of `EVENTER_ASYNCH_WORK` and the new job will be a child
of the currently executing job.


#### eventer_try_add_asynch_subqueue

>Add an asynchronous event to a specific job queue.

```c
mtev_boolean
eventer_try_add_asynch_subqueue(eventer_jobq_t *q, eventer_t e, uint64_t id)
```


  * `q` a job queue
  * `e` an event object
  * `id` is a fairly competing subqueue identifier
  * **RETURN** `mtev_false` if over max backlog, caller must clean event.

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENTER_ASYNCH`.


#### eventer_update

>Change the activity mask for file descriptor events.

```c
void
eventer_update(evneter_t e, int mask)
```


  * `e` an event object
  * `mask` a new mask that is some bitwise or of `EVENTER_READ`, `EVENTER_WRITE`, and `EVENTER_EXCEPTION`


#### eventer_update_whence

>Change the time at which a registered timer event should fire.

```c
void void
eventer_update_whence(eventer_t e, struct timeval whence)
```


  * `e` an event object
  * `whence` an absolute time.


#### eventer_wakeup

>Signal up an event loop manually.

```c
void
eventer_wakeup(eventer_t e)
```


  * `e` an event

The event `e` is used to determine which thread of the eventer loop to wake up.
If `e` is `NULL` the first thread in the default eventer loop is signalled. The
eventer loop can wake up on timed events, asynchronous job completions and
file descriptor activity.  If, for an external reason, one needs to wake up
a looping thread, this call is used.


#### eventer_watchdog_timeout

>Return the current watchdog timeout on this thread.

```c
double
eventer_watchdog_timeout(void)
```


  * **RETURN** A timeout in seconds, 0.0 if none configured.


#### eventer_write

>Execute an opset-appropriate `write` call.

```c
int
eventer_write(eventer_t e, const void *buff, size_t len, int *mask)
```


  * `e` an event object
  * `buff` a buffer containing data to write.
  * `len` the size of `buff` in bytes.
  * `mask` a point the a mask. If the call does not complete, `*mask` it set.
  * **RETURN** the number of bytes written or -1 with errno set.

If the function returns -1 and `errno` is `EAGAIN`, the `*mask` reflects the
necessary activity to make progress.


### F

#### mtev_flow_regulator_ack

>Acknowledge processing mtev_flow_regulator_toggle_t instruction.

```c
mtev_flow_regulator_toggle_t
mtev_flow_regulator_ack(mtev_flow_regulator_t *fr, mtev_flow_regulator_toggle_t t)
```


  * `t` Instruction returned from previous call to `mtev_flow_regulator_raise_one`, `mtev_flow_regulator_lower`, or `mtev_flow_regulator_ack`.
  * **RETURN** New flow-toggle instruction.

The flow-regulator is designed to be usable in multi-producer
(where multiple concurrent entities may produce work) /
multi-consumer (where multiple concurrent entities may mark work
completed) scenarios, which means that many entities may be adding
and removing work from the flow-regulator at the same time. As
such, when one entity observes that the flow-regulator has become
disabled and takes some action to pause further work generation,
it's possible that enough work will have drained from the
flow-regulator that it needs to be re-enabled... Or, that after
re-enabling the flow-regulator, enough work was already being
scheduled that it needs to be disabled again. So
`mtev_flow_regulator_ack` returns a _new_ instruction, in case the
flow-regulator needs further adjustment. Clients are expected to
call this function in a loop, with the function's previous return
value, until the flow-regulator settles on
`MTEV_FLOW_REGULATOR_TOGGLE_KEEP` or
`MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`. (There is no harm in
continuing to call `mtev_flow_regulator_ack` after it reaches one
of these values: it will eventually settle on
`MTEV_FLOW_REGULATOR_TOGGLE_KEEP`.)

The toggle-instruction should be interpreted as follows:

* `MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`: Flow control is currently
  disabled. No client action necessary.
* `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`: Flow control _was_ enabled,
  and we've started transitioning to DISABLED. (The transition to
  DISABLED is not complete until the client calls
  `mtev_flow_regulator_ack`, again.) Client MAY try to prevent
  generating new work before calling `mtev_flow_regulator_ack`, again.
* `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`: No client action required.
* `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`: Flow control _was_ disabled,
  and has just started transitioning to ENABLED. (The transition to
  ENABLED is not complete until the client calls
  `mtev_flow_regulator_ack`, again.) Client MAY re-enable
  work-generation before calling `mtev_flow_regulator_ack`, again.


To facilitate multi-producer / multi-consumer use, the
flow-regulator enforces that only _one_ client will see a
flow-toggling result (_i.e._ `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`
or `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`) until that client calls
`mtev_flow_regulator_ack`, and that the same toggling result will
not occur twice in a row across all concurrent clients.
 

#### mtev_flow_regulator_create

>Create a flow-regulator object.

```c
mtev_flow_regulator_t *
mtev_flow_regulator_create(unsigned int low, unsigned int high)
```


  * `low` Threshold that indicates when work flow should be re-enabled.
  * `high` Threshold at which to stop work flow. Must be strictly greater than `low`.
  * **RETURN** Flow-regulator object.

The returned flow-regulator object is "enabled" on creation. When
`high` work items are added (by `mtev_flow_regulator_raise_one`)
without being removed (by `mtev_flow_regulator_lower`), the
flow-regulator will become disabled. When `high - low` work-items
are subsequently marked done (by `mtev_flow_regulator_lower`),
without new work being added (by `mtev_flow_regulator_raise_one`),
the flow-regulator will transition back to "enabled".
 

#### mtev_flow_regulator_destroy

>Destroy a flow-regulator object.

```c
void
mtev_flow_regulator_destroy(mtev_flow_regulator_t *fr)
```


 

#### mtev_flow_regulator_lower

>Release space for work-items in a flow-regulator.

```c
mtev_flow_regulator_toggle_t
mtev_flow_regulator_lower(mtev_flow_regulator_t *fr, unsigned int by)
```


  * `by` Number of work-items to mark completed.
  * **RETURN** Action to take on releasing work.

See `mtev_flow_regulator_ack` for description of how to handle the
return value. This function will return one of:

  * `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`
  * `MTEV_FLOW_REGULATOR_TOGGLE_ENABLE`
 

#### mtev_flow_regulator_raise_one

>Reserve space for a work-item in a flow-regulator.

```c
mtev_flow_regulator_toggle_t
mtev_flow_regulator_raise_one(mtev_flow_regulator_t *fr)
```


  * **RETURN** Success / fail status on inserting work.

See `mtev_flow_regulator_ack` for description of how to handle the
return value. This function will return one of:

* `MTEV_FLOW_REGULATOR_TOGGLE_DISABLED`
* `MTEV_FLOW_REGULATOR_TOGGLE_DISABLE`
* `MTEV_FLOW_REGULATOR_TOGGLE_KEEP`

Note that, unless the return value was
`MTEV_FLOW_REGULATOR_TOGGLE_KEEP`, space was _not_ reserved in the
flow-regulator for the work-item.
 

#### mtev_flow_regulator_stable_lower

```c
mtev_flow_regulator_toggle_t
mtev_flow_regulator_stable_lower(mtev_flow_regulator_t *fr, unsigned int by)
```

  * **RETURN** `mtev_true` if the caller is responsible for re-scheduling work-creation for the flow-regulator, `mtev_false` otherwise.

This function is a simple wrapper around
`mtev_flow_regulator_lower` and `mtev_flow_regulator_ack`, to
simplify handling in cases where the client needs take no explicit
action to enable or disable work-production before calling
`mtev_flow_regulator_ack`.
 

#### mtev_flow_regulator_stable_try_raise_one

```c
mtev_flow_regulator_toggle_t
mtev_flow_regulator_stable_try_raise_one(mtev_flow_regulator_t *fr)
```

  * **RETURN** mtev_true if work-item was successfully added to the flow regulator, mtev_false otherwise.

This function is a simple wrapper around
`mtev_flow_regulator_raise_one` and `mtev_flow_regulator_ack`, to
simplify handling in cases where the client needs take no explicit
action to enable or disable work-production before calling
`mtev_flow_regulator_ack`.
 

#### mtev_frrh_adjust_prob

>Change the replacement probability on a `mtev_frrh_t`.

```c
void
mtev_frrh_adjust_prob(mtev_frrh_t *cache, uint32_t prob)
```


  * `cache` the `mtev_frrh_t` on which to change the probability.
  * `prob` is the probability of replaement on collision (0 to UINT_MAX).


#### mtev_frrh_alloc

>Allocate a fast random replacement hash.

```c
mtev_frrh_t *
mtev_frrh_alloc(uint64_t size, size_t datasize, uint32_t prob, mtev_frrh_hash hashf,
                mtev_frrh_alloc_entry allocf, mtev_frrh_free_entry freef)
```


  * `size` is the total capacity of the hash.
  * `datasize` is the fixed-size of the data which will be stored.
  * `prob` is the probability of replaement on collision (0 to UINT_MAX).
  * `hashf` is the hashing function, NULL uses XXH64.
  * `allocf` is the allocation function to use, NULL uses malloc.
  * `freef` is the free function to use, NULL uses free.
  * **RETURN** a pointer to a `mtev_frrh_t` on success, NULL otherwise.
 

#### mtev_frrh_get

>Retrieves the data associated with the provided key from the cache.

```c
const void *
mtev_frrh_get(mtev_frrh_t *cache, const void *key, uint32_t keylen)
```


  * `cache` a `mtev_frrh_t`.
  * `key` a pointer to the key.
  * `keylen` the length of the key in bytes.
  * **RETURN** a pointer to a copy of the data store with the key.


#### mtev_frrh_set

>Possibly set a key-value pair in a `mtev_frrh_t`

```c
mtev_boolean
mtev_frrh_set(mtev_frrh_t *cache, const void *key, uint32_t keylen, const void *data)
```


  * `cache` a `mtev_frrh_t`.
  * `key` a pointer to the key.
  * `keylen` the length of the key in bytes.
  * `data` a pointer to the data (must be of the specified datasize for the `mtev_frrh_t`.
  * **RETURN** `mtev_true` if added, `mtev_false` if not.


#### mtev_frrh_stats

>Retrieve access and hit statatistics.

```c
void
mtev_frrh_stats(mtev_frrh_t *cache, uint64_t *accesses, uint64_t *hits)
```


  * `cache` the `mtev_frrh_t` in question.
  * `accesses` is an optional out pointer to store the number of accesses.
  * `hits` is an optional out pointer to store the number of hits.


### G

#### mtev_get_durations_ms

>Return suffixes for millisecond-resolution durations.

```c
const mtev_duration_definition_t *
mtev_get_durations_ms(void)
```



Return value is suitable to pass as the second argument to
mtev_confstr_parse_duration. Millisecond-scale duration suffixes are:

* `ms` (for milliseconds);
* `s` and `sec` (for seconds);
* `min` (for minutes);
* `hr` (for hours).
* `d` (for days).
* `w` (for weeks).
 

#### mtev_get_durations_ns

>Return suffixes for nanosecond-resolution durations.

```c
const mtev_duration_definition_t *
mtev_get_durations_ns(void)
```



Return value is suitable to pass as the second argument to
mtev_confstr_parse_duration. Nanosecond-scale duration suffixes are:

* `ns` (for nanoseconds);
* `us` (for microseconds);
* `ms` (for milliseconds);
* `s` and `sec` (for seconds);
* `min` (for minutes);
* `hr` (for hours).
 

#### mtev_get_durations_s

>Return suffixes for second-resolution durations.

```c
const mtev_duration_definition_t *
mtev_get_durations_s(void)
```



Return value is suitable to pass as the second argument to
mtev_confstr_parse_duration. Second-scale duration suffixes are:

* `s` and `sec` (for seconds);
* `min` (for minutes);
* `hr` (for hours).
* `d` (for days).
* `w` (for weeks).
 

#### mtev_get_durations_us

>Return suffixes for microsecond-resolution durations.

```c
const mtev_duration_definition_t *
mtev_get_durations_us(void)
```



Return value is suitable to pass as the second argument to
mtev_confstr_parse_duration. Microsecond-scale duration suffixes are:

* `us` (for microseconds);
* `ms` (for milliseconds);
* `s` and `sec` (for seconds);
* `min` (for minutes);
* `hr` (for hours).
* `d` (for days).
 

#### mtev_get_nanos

>Like mtev_gethrtime. It actually is the implementation of mtev_gethrtime()

```c
uint64_t
mtev_get_nanos(void)
```


  * **RETURN** number of nanos seconds from an arbitrary time in the past.
 

#### mtev_getip_ipv4

>find the local IPv4 address that would be used to talk to remote

```c
int
mtev_getip_ipv4(struct in_addr remote, struct in_addr *local)
```


  * `remote` the destination (no packets are sent)
  * `local` the pointer to the local address to be set
  * **RETURN** 0 on success, -1 on failure
 

#### mtev_gettimeofday

>Maybe fast-pathed version of gettimeofday

```c
int
mtev_gettimeofday(struct timeval *t, void **ttp)
```


  * **RETURN** same as system gettimeofday();

   If the fast path is taken, ttp is ignored.
 

### H

#### mtev_hash__hash

```c
uint32_t
mtev_hash__hash(const char *k, uint32_t length, uint32_t initval)
```


> the internal hash function that mtev_hash_table uses exposed for external usage


 

#### mtev_hash_adv

```c
int
mtev_hash_adv(mtev_hash_table *h, mtev_hash_iter *iter)
```


> iterate through key/values in the hash_table



  This is an iterator and requires the hash to not be written to during the
   iteration process.
   To use:
 mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

 while(mtev_hash_adv(h, &iter)) {
   .... use iter.key.{str,ptr}, iter.klen and iter.value.{str,ptr} ....
 }


#### mtev_hash_adv_spmc

```c
int
mtev_hash_adv_spmc(mtev_hash_table *h, mtev_hash_iter *iter)
```


> iterate through the key/values in the hash_table



   This is an iterator and requires that if the hash it written to
   during the iteration process, you must employ SMR on the hash itself
   to prevent destruction of memory for hash resizes by using the
   special init function mtev_hash_init_mtev_memory.

   To use:
   mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;

   while(mtev_hash_adv_spmc(h, &iter)) {
   .... use iter.key.{str,ptr}, iter.klen and iter.value.{str,ptr} ....
   }


#### mtev_hash_delete

```c
int
mtev_hash_delete(mtev_hash_table *h, const char *k, int klen, NoitHashFreeFunc keyfree
                 NoitHashFreeFunc datafree)
```


> remove the key/value stored at "k" and call keyfree and datafree if they are provided


 

#### mtev_hash_delete_all

```c
void
mtev_hash_delete_all(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
```


> remove all keys and values and call keyfree and datafree if they are provided


 

#### mtev_hash_destroy

```c
void
mtev_hash_destroy(mtev_hash_table *h, NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
```


> remove all keys and values and call keyfree and datafree if they are provided but also wipe out the underlying map



  This must be called on any hash_table that has been mtev_hash_inited or it will leak memory
 

#### mtev_hash_init

```c
void
mtev_hash_init(mtev_hash_table *h)
```


> initialize a hash_table



  will default to LOCK_MODE_NONE and MTEV_HASH_DEFAULT_SIZE (1<<7)
 

#### mtev_hash_init_locks

```c
void
mtev_hash_init_locks(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode)
```


> choose the lock mode when initing the hash.



  It's worth noting that the lock only affects the write side of the hash,
  the read side remains completely lock free.
 

#### mtev_hash_init_mtev_memory

```c
void
mtev_hash_init_mtev_memory(mtev_hash_table *h, int size, mtev_hash_lock_mode_t lock_mode)
```


> choose the lock mode when initing the hash.



  It's worth noting that the lock only affects the write side of the hash,
  the read side remains completely lock free.

  This variant will use mtev_memory ck allocator functions to allow this
  hash to participate in SMR via mtev_memory transactions.  You need to wrap
  memory transactions in mtev_memory_begin()/mtev_memory_end()
 

#### mtev_hash_init_size

```c
void
mtev_hash_init_size(mtev_hash_table *h, int size)
```


> initialize a hash_table with an initial size



  will default to LOCK_MODE_NONE
 

#### mtev_hash_merge_as_dict

```c
void
mtev_hash_merge_as_dict(mtev_hash_table *dst, mtev_hash_table *src)
```


> merge string values in "src" into "dst"



  This is a convenience function only.  It assumes that all keys and values
  in the destination hash are strings and allocated with malloc() and
  assumes that the source contains only keys and values that can be
  suitably duplicated by strdup().
 

#### mtev_hash_next

```c
int
mtev_hash_next(mtev_hash_table *h, mtev_hash_iter *iter, const char **k, int *klen
               void **data)
```


> iterate through the key/values in the hash_table




  These are older, more painful APIs... use mtev_hash_adv
   Note that neither of these sets the key, value, or klen in iter


#### mtev_hash_next_str

```c
int
mtev_hash_next_str(mtev_hash_table *h, mtev_hash_iter *iter, const char **k, int *klen
                   const char **dstr)
```


> iterate through the key/values in the hash_table as strings




  These are older, more painful APIs... use mtev_hash_adv 

#### mtev_hash_replace

```c
int
mtev_hash_replace(mtev_hash_table *h, const char *k, int klen, void *data,
                  NoitHashFreeFunc keyfree, NoitHashFreeFunc datafree)
```


> replace and delete (call keyfree and datafree functions) anything that was already in this hash location


 

#### mtev_hash_retr_str

```c
int
mtev_hash_retr_str(mtev_hash_table *h, const char *k, int klen, const char **dstr)
```


> fetch the value at "k" into "data" as a string


 

#### mtev_hash_retrieve

```c
int
mtev_hash_retrieve(mtev_hash_table *h, const char *k, int klen, void **data)
```


> fetch the value at "k" into "data"


 

#### mtev_hash_set

```c
int
mtev_hash_set(mtev_hash_table *h, const char *k, int klen, void *data, char **oldkey
              void **olddata)
```


> replace and return the old value and old key that was in this hash location



  will return MTEV_HASH_SUCCESS on successful set with no replacement
  will return MTEV_HASH_FAILURE on failure to set
  will return MTEV_HASH_SUCCESS_REPLACEMENT on successful set with replacement
 

#### mtev_hash_size

```c
int
mtev_hash_size(mtev_hash_table *h)
```


> return the number of entries in the hash_table


 

#### mtev_hash_store

```c
int
mtev_hash_store(mtev_hash_table *h, const char *k, int klen, void *data)
```


> put something in the hash_table



  This will fail if the key already exists in the hash_table

  NOTE! "k" and "data" MUST NOT be transient buffers, as the hash table
  implementation does not duplicate them.  You provide a pair of
  NoitHashFreeFunc functions to free up their storage when you call
  mtev_hash_delete(), mtev_hash_delete_all() or mtev_hash_destroy().
 

#### mtev_huge_hash_adv

```c
int
mtev_huge_hash_adv(mtev_huge_hash_iter_t *iter)
```


> iterate through key/values in the hash_table



   To use:
 mtev_huge_hash_iter_t *iter = mtev_huge_hash_create_iter(hh);

 while(mtev_huge_hash_adv(iter)) {
   size_t key_len, data_len;
   void *k = mtev_huge_hash_iter_key(iter, &key_len);
   void *d = mtev_huge_hash_iter_value(iter, &data_len);
 }


#### mtev_huge_hash_create

```c
mtev_huge_hash_t *
mtev_huge_hash_create(const char *path)
```


> create or open a huge_hash



  Failure to open or create will return NULL and errno will be set appropriately.
  See: mtev_huge_hash_strerror()
 

\fn mtev_huge_hash_iter_t *mtev_huge_hash_create_iter(mtev_huge_hash_t *hh);

> create an iterator for walking the huge_hash



  Note that the existence of an interator can prevent calls to mtev_huge_hash_store
  from completing if the underlying data has to resize.  Iterate with caution.


#### mtev_huge_hash_delete

```c
mtev_boolean
mtev_huge_hash_delete(mtev_huge_hash_t *hh, const void *k, size_t klen)
```


> remove the key/value stored at "k"


 

#### mtev_huge_hash_replace

```c
int
mtev_huge_hash_replace(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data
                       size_t dlen)
```


> replace anything that was already in this hash location


 

#### mtev_huge_hash_retrieve

```c
const void *
mtev_huge_hash_retrieve(mtev_huge_hash_t *hh, const void *k, size_t klen, size_t *data_len)
```


> return the value at "k" and fill data_len with sizeof the data



  The memory returned here is owned by the huge_hash.  Do not modify
 

#### mtev_huge_hash_size

```c
size_t
mtev_huge_hash_size(mtev_huge_hash_t *hh)
```


> return the number of entries in the huge_hash


 

#### mtev_huge_hash_store

```c
int
mtev_huge_hash_store(mtev_huge_hash_t *hh, const void *k, size_t klen, const void *data
                     size_t dlen)
```


> put something in the huge_hash



  This will fail if the key already exists in the hash_table
  Copies are made of `k` and `data`

  Returns mtev_true on success
 

### I

#### mtev_intern

>Like `mtev_intern_pool` invoked with `MTEV_INTERN_DEFAULT_POOL`.

```c
mtev_intern_t
mtev_intern(const void *buff, size_t len)
```


  * `buff` The data to be interned.
  * `len` The length of data to be considered (0, 2^23)
  * **RETURN** A new, or pre-existing intern from the default pool.
 

#### mtev_intern_copy

>Return a reference to an existing `mtev_intern_t`.

```c
mtev_intern_t
mtev_intern_copy(const mtev_intern_t iv)
```


  * `iv` An existing, valid `mtev_intern_t`
  * **RETURN** A reference to the interned data.

The copy must be released just as if you created it via `mtev_intern_pool`.
 

#### mtev_intern_get_cstr

>Retrieve the string from an `mtev_intern_t` type.

```c
const char *
mtev_intern_get_cstr(const mtev_intern_t iv, size_t *len)
```


  * `iv` The interned data.
  * `len` An out value for the length of the string. Unused if NULL.
  * **RETURN** The string contained in the interned value.

The return value is only valid until `mtev_intern_release*` is called.
 

#### mtev_intern_get_ptr

>Retrieve the data from an `mtev_intern_t` type.

```c
const void *
mtev_intern_get_ptr(const mtev_intern_t iv, size_t *len)
```


  * `iv` The interned data.
  * `len` An out value for the length of the string. Unused if NULL.
  * **RETURN** The memory contained in the interned value.

The return value is only valid until `mtev_intern_release*` is called.
 

#### mtev_intern_get_refcnt

>Retrieve the current refcnt for an intern item.

```c
uint32_t
mtev_intern_get_refcnt(mtev_intern_t iv)
```


  * `iv` The interned value.
  * **RETURN** The number of references currently outstanding.


#### mtev_intern_pool

>Request an interned data item with specific contents.

```c
mtev_intern_t
mtev_intern_pool(mtev_intern_pool_t *pool, const void *buff, size_t len)
```


  * `pool` The pool in which to intern the data.
  * `buff` The data to be interned.
  * `len` The length of data to be considered (0, 2^23)
  * **RETURN** A new, or pre-existing intern from the pool.

This function will attempt to find the specified data in the pool, but create it on absence.
The reference count of the interned object returned will be increased and it must be released
using `mtev_intern_release_pool`.
 

#### mtev_intern_pool_compact

>Attempt a compaction of an intern pool.

```c
int
mtev_intern_pool_compact(mtev_intern_pool_t *pool, mtev_boolean force)
```


  * `pool` The pool to compact.
  * `force` A boolean dictating if compaction should be forced.
  * **RETURN** The number of free fragment merges that occurred.

This function will walk all the free fragment lists within the
pool joining adjacent ones and promoting them into the the right
slabs.  If force is false, compaction will be avoided if there are less
than approximately 1.5x fragments as there were after the previous successful
compaction.
  

#### mtev_intern_pool_item_count

>Return the number of unique interned items in a pool.

```c
uint32_t
mtev_intern_pool_item_count(mtev_intern_pool_t *pool)
```


  * `pool` The pool to analyze.
  * **RETURN** The number of unique interned items.
 

#### mtev_intern_pool_new

>Create a new intern pool.

```c
mtev_intern_pool_t *
mtev_intern_pool_new(mtev_intern_pool_attr_t *attr)
```


  * `attr` the attributes describing the pool.
  * **RETURN** A new intern pool.
 

#### mtev_intern_pool_stats

>Return statistics for an intern pool.

```c
void
mtev_intern_pool_stats(mtev_intern_pool_t *pool, mtev_intern_pool_stats_t *stats)
```


  * `pool` The pool to inspect.
  * `stats` The statistics structure to fill out.
 

#### mtev_intern_pool_str

>Request an interned string item with specific contents.

```c
mtev_intern_t
mtev_intern_pool_str(mtev_intern_pool_t *pool, const char *buff, size_t len)
```


  * `pool` The pool in which to intern the string.
  * `buff` The string to be interned.
  * `len` The length of `buff`. `len` must be less than 2^23-1. If 0, strlen will be invoked.
  * **RETURN** A new, or pre-existing intern from the pool.

This function will attempt to find the specified string in the pool, but create it on absence.
The reference count of the interned string returned will be increased and it must be released
using `mtev_intern_release_pool`.
 

#### mtev_intern_release

>Release interned data back to the pool from which it was allocated.

```c
void
mtev_intern_release(mtev_intern_t iv)
```


  * `iv` The interned value to release.
 

#### mtev_intern_release_pool

>Release interned data back to a pool.

```c
void
mtev_intern_release_pool(mtev_intern_pool_t *pool, mtev_intern_t iv)
```


  * `pool` The pool to release `iv` to.
  * `iv` The interned value to release.

Interned values must be released to the pool they were retrieved from.  Attempting
to release to a different pool will cause a crash.


#### mtev_intern_str

>Like `mtev_intern_pool` invoked with `MTEV_INTERN_DEFAULT_POOL`.

```c
mtev_intern_t
mtev_intern_str(const char *buff, size_t len)
```


  * `buff` The string to be interned.
  * `len` The length of string. `len` must be less than 2^23-1. If 0, strlen will be invoked.
  * **RETURN** A new, or pre-existing intern from the default pool.
 

### L

#### mtev_lfu_create

```c
mtev_lfu_create(int32_t max_entries, void (*free_fn)(void *))
```


> Create an LFU of max_entries size



  Will call free_fn when an item is evicted. if free_fn is null, call free().
  If max_entries == -1 then this devolves to a normal hashtable.
 

#### mtev_lfu_destroy

```c
mtev_lfu_destroy(mtev_lfu_t *)
```


> Destroy the LFU


 

#### mtev_lfu_get

```c
mtev_lfu_entry_token
mtev_lfu_get(mtev_lfu_t *lfu, const char *key, size_t key_len, void **value)
```


> Get an item from the LFU by key



  This will fetch the item at "key" and put the value in "value". It will also
  return a token as the return value of the function.  This token is used
  as the checkout of the item from the LFU.  When you are finished using
  the value, you must call "mtev_lfu_release(mtev_lfu_t *lfu, mtev_lfu_entry_token token)"
  to let the LFU know that reclamation for that key/value is possible.
 

#### mtev_lfu_invalidate

```c
mtev_lfu_invalidate(mtev_lfu_t *)
```


> Remove all entries from the LFU


 

#### mtev_lfu_iterate

```c
void
mtev_lfu_iterate(mtev_lfu_t *lfu, void (*callback)(mtev_lfu_t *lfu, const char *key,
                 size_t key_len, void *value, void *closure), void *closure)
```


> Iterate through all entries in the LFU


    * `lfu` The LFU to iterate
    * `callback` This function is called for each item in the LFU
    * `closure` The pointer to pass as the last param to the callback

  This leaves the LFU locked during iteration which will starve
  out other operations.  Keep this in mind if you are storing
  a lot of stuff in the LFU and have multithreaded access to it.

  The "key" and "value" passed to the callback function is direct
  LFU memory and should not be freed.


#### mtev_lfu_put

```c
mtev_lfu_put(mtev_lfu_t *lfu, const char *key, size_t key_len, void *value)
```


> Put a new item into the LFU



  If some other thread has added a val at this key this will overwrite it and
  restart the frequency count at 1.

  This will cause an eviction of the least frequently used item if the cache is full.
 

#### mtev_lfu_release

```c
void
mtev_lfu_release(mtev_lfu_t *lfu, mtev_lfu_entry_token token)
```


> Surrender an item back to the LFU



  To be memory safe LFU tokens must be released back to the LFU when
  the user is finished using them.
 

#### mtev_lfu_remove

```c
mtev_lfu_remove(mtev_lfu_t *lfu, const char *key, size_t key_len)
```


> Remove key from the LFU



  This does not call the free_fn, instead it returns the value
 

#### mtev_lfu_size

```c
mtev_lfu_size(mtev_lfu_t *lfu)
```


> Return the total entry count in the LFU


 

#### mtev_lockfile_acquire

>lock the file immediately if possible, return -1 otherwise.

```c
mtev_lockfile_t
mtev_lockfile_acquire(const char *fp)
```


  * `fp` the path to the lock file
  * **RETURN** >= 0 on success, -1 on failure
 

#### mtev_lockfile_acquire_owner

>lock the file immediately if possible, return -1 otherwise.

```c
mtev_lockfile_t
mtev_lockfile_acquire_owner(const char *fp, pid_t *owner)
```


  * `fp` the path to the lock file
  * `owner` is a pointer to a pid.  If the lock is owned by another process, this will be set to that pid, otherwise it will be set to -1.
  * **RETURN** >= 0 on success, -1 on failure
 

#### mtev_lockfile_release

>release a held file lock

```c
int
mtev_lockfile_release(mtev_lockfile_t fd)
```


  * `fd` the file lock to release
  * **RETURN** -1 on failure, 0 on success
 

#### mtev_lua_lmc_alloc

>Allocated and initialize a `lua_module_closure_t` for a new runtime.

```c
lua_module_closure_t *
mtev_lua_lmc_alloc(mtev_dso_generic_t *self, mtev_lua_resume_info_t *resume)
```


  * `self` the module implementing a custom lua runtime environment
  * `resume` the custom resume function for this environment
  * **RETURN** a new allocated and initialized `lua_module_closure`

> Note these are not thread safe because lua is not thread safe. If you are managing multiple
> C threads, you should have a `lua_module_closure_t` for each thread and maintain them in a
> thread-local fashion.  Also ensure that any use of the eventer does not migrate cross thread.


#### mtev_lua_lmc_free

>Free a `lua_module_closure_t` structure that has been allocated.

```c
void
mtev_lua_lmc_free(lua_module_closure_t *lmc)
```


  * `lmc` The `lua_module_closure_t` to be freed.


#### mtev_lua_lmc_L

>Get the `lua_State *` for this module closure.

```c
lua_State *
mtev_lua_lmc_L(lua_module_closure_t *lmc)
```


  * `lmc` the `lua_module_closure_t` that was allocated for this runtime.
  * **RETURN** a Lua state


#### mtev_lua_lmc_resume

>Invoke lua_resume with the correct context based on the `lua_module_closure_t`

```c
int
mtev_lua_lmc_resume(lua_module_closure_t *lmc, mtev_lua_resume_info_t *ri, int nargs)
```


  * `lmc` the `lua_module_closure_t` associated with the current lua runtime.
  * `ri` resume meta information
  * `nargs` the number of arguments on the lua stack to return
  * **RETURN** the return value of the underlying `lua_resume` call.


#### mtev_lua_lmc_setL

>Set the `lua_State *` for this module closure, returning the previous value.

```c
lua_State *
mtev_lua_lmc_setL(lua_module_closure_t *lmc)
```


  * `lmc` the `lua_module_closure_t` that was allocated for this runtime.
  * `lmc` the `lua_State *` that should be placed in this closure.
  * **RETURN** the previous lua Lua state associated with this closure


### M

#### mtev_main

>Run a comprehensive mtev setup followed by a "main" routine.

```c
int
mtev_main(const char *appname, const char *config_filename, int debug, int foreground,
          mtev_log_op_t lock, const char *glider, const char *drop_to_user,
          const char *drop_to_group, int (*passed_child_main)(void))
```


  * `appname` The application name (should be the config root node name).
  * `config_filename` The path the the config file.
  * `debug` Enable debugging (logging).
  * `foreground` 0 to daemonize with watchdog, 1 to foreground, 2 to foreground with watchdog.
  * `lock` Specifies where to not lock, try lock or exit, or lock or wait.
  * `glider` A path to an executable to invoke against the process id on crash. May be NULL.
  * `drop_to_user` A target user for dropping privileges when under watchdog. May be NULL.
  * `drop_to_group` A target group for dropping privileges when under watchdog. May be NULL.
  * `passed_child_main` A programmers supplied main function.
  * **RETURN** -1 on failure, 0 on success if `foreground==1`, or the return value of `main` if run in the foreground.
 

#### mtev_main_eventer_config

>Set <eventer><config> options for an app that need not be specified explicitly in a config.

```c
void
mtev_main_eventer_config(const char *name, const char *value)
```


  * `name` The config key name
  * `value` The value of the config option


#### mtev_main_status

>Determine if that application is already running under this configuration.

```c
int
mtev_main_status(const char *appname, const char *config_filename, int debug, pid_t *pid
                 pid_t *pgid)
```


  * `appname` The application name (should be the config root node name).
  * `config_filename` The path the the config file.
  * `debug` Enable debugging (logging).
  * `pid` If not null, it is populated with the process id of the running instance.
  * `pgid` If not null, it is populated with the process group id of the running instance.
  * **RETURN** 0 on success, -1 on failure.
 

#### mtev_main_terminate

>Terminate an already running application under the same configuration.

```c
int
mtev_main_terminate(const char *appname, const char *config_filename, int debug)
```


  * `appname` The application name (should be the config root node name).
  * `config_filename` The path the the config file.
  * `debug` Enable debugging (logging).
  * **RETURN** 0 on success, -1 on failure.  If the application is not running at the time of invocation, termination is considered successful.
 

#### MTEV_MAYBE_DECL

>C Macro for declaring a "maybe" buffer.

```c
MTEV_MAYBE_DECL(type, name, cnt)
```


  * `type` A C type (e.g. char)
  * `name` The name of the C variable to declare.
  * `cnt` The number of type elements initially declared.

A "maybe" buffer is a buffer that is allocated on-stack, but
if more space is required can be reallocated off stack (malloc).
One should always call `MTEV_MAYBE_FREE` on any allocated
maybe buffer.
 

#### MTEV_MAYBE_DECL_VARS

>C Macro for declaring a "maybe" buffer.

```c
MTEV_MAYBE_DECL_VARS(type, name, cnt)
```


  * `type` A C type (e.g. char)
  * `name` The name of the C variable to declare.
  * `cnt` The number of type elements initially declared.
 

#### MTEV_MAYBE_FREE

>C Macro to free any heap space associated with a "maybe" buffer.

```c
MTEV_MAYBE_FREE(name)
```


  * `name` The name of the "maybe" buffer.
 

#### MTEV_MAYBE_INIT_VARS

>C Macro for initializing a "maybe" buffer

```c
MTEV_MAYBE_INIT_VARS(name)
```


  * `name` The name of "maybe" buffer.
 

#### MTEV_MAYBE_REALLOC

>C Macro to ensure a maybe buffer has at least cnt elements allocated.

```c
MTEV_MAYBE_REALLOC(name, cnt)
```


  * `name` The name of the "maybe" buffer.
  * `cnt` The total number of elements expected in the allocation.

This macro will never reduce the size and is a noop if a size smaller
than or equal to the current allocation size is specified.  It is safe
to simply run this macro prior to each write to the buffer.
 

#### MTEV_MAYBE_SIZE

>C Macro for number of bytes available in this buffer.

```c
MTEV_MAYBE_SIZE(name)
```


  * `name` The name of the "maybe" buffer.
 

#### mtev_merge_sort

>Merge sort data starting at head_ptr_ptr, iteratively

```c
void
mtev_merge_sort(void **head_ptr_ptr, mtev_sort_next_function next,
                mtev_sort_set_next_function set_next, mtev_sort_compare_function compare)
```


  * `next` the function to call to get the next pointer from a node
  * `set_next` the function to call to alter the item directly after current
  * `compare` the function to call to compare 2 nodes


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
 

### N

#### mtev_now_ms

```c
uint64_t
mtev_now_ms()
```


> the current system time in milliseconds


    * **RETURN** mtev_gettimeofday() in milliseconds since epoch
   

#### mtev_now_us

```c
uint64_t
mtev_now_us()
```


> the current system time in microseconds


    * **RETURN** mtev_gettimeofday() in microseconds since epoch
   

### R

#### mtev_rand

>Generate a pseudo-random number between [0,2^64)

```c
uint64_t
mtev_rand(void)
```


  * **RETURN** A pseudo-random number in the range [0,2^64)
 

#### mtev_rand_buf

>Fill a buffer with pseudo-random bytes.

```c
size_t
mtev_rand_buf(void *buf, size_t len)
```


  * `buf` A buffer to fill.
  * `len` The number of bytes to populate.
  * **RETURN** The number of bytes written to `buf` (always `len`).
 

#### mtev_rand_buf_secure

>Fill a buffer with securely random bytes.

```c
size_t
mtev_rand_buf_secure(void *buf, size_t len)
```


  * `buf` A buffer to fill.
  * `len` The number of bytes to populate.
  * **RETURN** The number of bytes written to `buf` (< len if insufficient entropy).
 

#### mtev_rand_buf_trysecure

>Fill a buffer with likely secure, but possibly pseudo-random bytes.

```c
size_t
mtev_rand_buf_trysecure(void *buf, size_t len)
```


  * `buf` A buffer to fill.
  * `len` The number of bytes to populate.
  * **RETURN** The number of bytes written to `buf` (always `len`).
 

#### mtev_rand_secure

>Generate a secure random number.

```c
int
mtev_rand_secure(uint64_t *out)
```


  * `out` A pointer to a `uint64_t` in which a securely generated random number will be stored.
  * **RETURN** 0 on success, -1 on failure (not enough entropy available).
 

#### mtev_rand_trysecure

>Generate a likely secure, but possibly pseudo-random number between [0,2^64)

```c
uint64_t
mtev_rand_trysecure(void)
```


  * **RETURN** A random pseudo-random number in the range [0,2^64)
 

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
 

#### mtev_sem_wait_noeintr

>Convenience function that delegates to sem_wait, swallowing EINTR errors.

```c
void
mtev_sem_wait_noeintr(mtev_sem_t *s)
```


  * `s` the semaphore on which to wait
  * **RETURN** 0 on success or -1 on failure

This function is built on sem_wait, and sem_wait can fail in other ways besides
EINTR, such as due to EINVAL. These other failures will be due to mis-use of the
semaphore API -- e.g., by trying to `sem_wait` on a structure that was never
initialized with `sem_init`. Mis-using thread-synchronization primitives will
often lead to subtle, serious, and hard-to-reproduce bugs, so this function will
mtevFatal on other errors, rather than forcing clients to deal with (likely)
un-handlable errors. If your client code can handle these other errors, use
sem_wait directly, do not use this function.
 

#### mtev_sort_compare_function

>Function definition to compare sortable entries

```c
int
mtev_sort_compare_function(void *left, void *right)
```


  * `left` one object to compare
  * `right` the other object to compare
  * **RETURN** less than zero, zero, or greater than zero if left is less than, equal, or greater than right.


#### mtev_sort_next_function

>Function definition to get the next item from current

```c
void *
mtev_sort_next_function(void *current)
```


  * `current` the current node
  * **RETURN** the item after current


#### mtev_sort_set_next_function

>Function definition to re-order objects

```c
int
mtev_sort_set_next_function(void *current, void *value)
```


  * `current` the current node
  * `value` the value that should be directly after current


#### mtev_sys_gethrtime

>Exposes the system gethrtime() or equivalent impl

```c
mtev_hrtime_t
mtev_sys_gethrtime(void)
```


  * **RETURN** mtev_hrtime_t the system high-res time
 

### T

#### mtev_time_fast_mode

>check to see if fast mode is enabled

```c
mtev_boolean
mtev_time_fast_mode(const char **reason)
```


  * **RETURN** true if fast mode is on, false otherwise, the reason param will contain a text description
 

#### mtev_time_maintain

>Usually this is managed for you, but this is safe to call at any time

```c
mtev_boolean
mtev_time_maintain(void)
```


  * **RETURN** mtev_true if it was successful in parameterizing the CPU for rdtsc, mtev_false otherwise

Safe to call at any time but if you start_tsc, you should never need to call this
as the maintenance system can do it for you. However, if you find you need to call it
you must be bound to a thread using the mtev_thread APIs and the function will return
whether it was successful in parameterizing the CPU for rdtsc use.
 

#### mtev_time_start_tsc

>use TSC clock if possible for this CPU num

```c
void
mtev_time_start_tsc()
```



   This will remain active in the thread until you call stop
 

#### mtev_time_stop_tsc

>Turn off TSC usage for the current cpu of this thread (from when start_tsc was called)

```c
void
mtev_time_stop_tsc(void)
```


 

#### mtev_time_toggle_require_invariant_tsc

>will switch on/off the requirement of an invariant tsc.  This must be run before any call to mtev_time_toggle_tsc() or mtev_time_tsc_start() and is a one time call.

```c
void
mtev_time_toggle_require_invariant_tsc(mtev_boolean enable)
```



   Defaults to enabled.
 

#### mtev_time_toggle_tsc

>will switch on/off rdtsc usage across all cores regardless of detected state of rdtsc or start/stop usage.

```c
void
mtev_time_toggle_tsc(mtev_boolean enable)
```



   Defaults to enabled.

   This is independent of start_tsc/stop_tsc.  You can disable all and then reenable and the thread
   will keep going using the state from the last start/stop_tsc
 

### U

#### mtev_uuid_clear

```c
void
mtev_uuid_clear(uuid_t uu)
```


> Set a uuid to the null uuid.



 Follows the same semantics of uuid_clear from libuuid


#### mtev_uuid_compare

```c
int
mtev_uuid_compare(const uuid_t uu1, const uuid_t uu2)
```


> Compare to uuids


   * **RETURN** 0 if equal, -1 if uu1 is less than uu2, 1 otherwise.

 Follows the same semantics of uuid_compare from libuuid


#### mtev_uuid_copy

```c
void
mtev_uuid_copy(uuid_t dst, const uuid_t src)
```


> Copy src to dst.



 Follows the same semantics of uuid_copy from libuuid


#### mtev_uuid_generate

```c
void
mtev_uuid_generate(uuid_t uu)
```


> Generate a V4 uuid.



 Follows the same semantics of uuid_generate from libuuid


#### mtev_uuid_is_null

```c
void
mtev_uuid_is_null(const uuid_t uu)
```


> Determine if the supplied uuid is the null uuid.


   * **RETURN** 0 if not null, 1 if null.

 Follows the same semantics of uuid_is_null from libuuid


#### mtev_uuid_parse

```c
int
mtev_uuid_parse(const char *in, uuid_t uu)
```


> Parse "in" in UUID format into "uu".


   * **RETURN** 0 on success, non-zero on parse error

 Follows the same semantics of uuid_parse from libuuid


#### mtev_uuid_unparse

```c
void
mtev_uuid_unparse(const uuid_t uu, char *out)
```


> Unparse "uu" into "out".



  Follows the same semantics of uuid_unparse_lower from libuuid.

  There is no bounds checking of "out", caller must ensure that "out"
  is at least UUID_STR_LEN in size.  This also does not NULL terminate
  "out".  That is also up to the caller.


#### mtev_uuid_unparse_lower

```c
void
mtev_uuid_unparse_lower(const uuid_t uu, char *out)
```


> Unparse "uu" into "out".



  Follows the same semantics of uuid_unparse_lower from libuuid.

  There is no bounds checking of "out", caller must ensure that "out"
  is at least UUID_STR_LEN in size.  This also does not NULL terminate
  "out".  That is also up to the caller.


#### mtev_uuid_unparse_upper

```c
void
mtev_uuid_unparse_upper(const uuid_t uu, char *out)
```


> Unparse "uu" into "out".



  Follows the same semantics of uuid_unparse_upper from libuuid.

  There is no bounds checking of "out", caller must ensure that "out"
  is at least UUID_STR_LEN in size.  This also does not NULL terminate
  "out".  That is also up to the caller.


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
 

#### mtev_watchdog_disable_asynch_core_dump

>Disable asynchronous core dumps.

```c
void
mtev_watchdog_disable_asynch_core_dump(void)
```



Disable starting a new child while a faulting prior child is still dumping.  This must be called
before `mtev_main` and will be overridden by the MTEV_ASYNCH_CORE_DUMP environment variable.
 

#### mtev_watchdog_enable

```c
void
mtev_watchdog_enable(mtev_watchdog_t *hb)
```

  * `hb` the heart on which to act

mtev_watchdog_enable will make the parent respect and act on failed heartbeats.
 

#### mtev_watchdog_get_timeout

>returns the timeout configured for this watchdog.

```c
double
mtev_watchdog_get_timeout(mtev_watchdog_t *hb)
```


  * `hb` the heart on which to act
  * **RETURN** A timeout in seconds, 0 if hb is NULL.
 

#### mtev_watchdog_glider

>Sets a glider command.

```c
int
mtev_watchdog_glider(const char *path)
```


  * `path` the full path to the executable.
  * **RETURN** 0 on success, non-zero on failure.

`path` is invoked with two parameters, the process id of the faulting child, and the reason for the fault (one of `crash`, `watchdog`, or `unknown`.
 

#### mtev_watchdog_glider_trace_dir

>Set the directory to store glider output.

```c
int
mtev_watchdog_glider_trace_dir(const char *path)
```


  * `path` a full path to a directory.
  * **RETURN** 0 on success, non-zero on failure.
 

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
mtev_watchdog_override_timeout(mtev_watchdog_t *hb, double timeout)
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
 

#### mtev_watchdog_ratelimit

>Set rate limiting for child restarting.

```c
void
mtev_watchdog_ratelimit(int retry_val, int span_val)
```


  * `retry_val` the number of times to retry in the given `span_val`
  * `span_val` the number of seconds over which to attempt retries.
 

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
 

#### mtev_websocket_client_free

>Free a client

```c
void
mtev_websocket_client_free(mtev_websocket_client_t *client)
```


  * `client` client to be freed

This function will cleanup the client(and hence trigger any set cleanup_callback) first.
This function does nothing if called with NULL.


#### mtev_websocket_client_get_closure

>Access the currently set closure, if any

```c
void *
mtev_websocket_client_get_closure(mtev_websocket_client_t *client)
```


  * `client` client to be accessed
  * **RETURN** most recently set closure, or NULL if never set


#### mtev_websocket_client_init_logs

>Enable debug logging to "debug/websocket_client"

```c
void
mtev_websocket_client_init_logs()
```



Error logging is always active to "error/websocket_client".


#### mtev_websocket_client_is_closed

>Check if a client has closed and can no longer send or receive

```c
mtev_boolean
mtev_websocket_client_is_closed(mtev_websocket_client_t *client)
```


  * `client` client to be checked
  * **RETURN** boolean indicating whether the client is closed

Only a return value of mtev_true can be trusted(once closed, a client
cannot re-open). Because the caller is unable to check this status inside
of a locked section, it is possible that the client closes and invalidates
the result of this function call before the caller can act on it.


#### mtev_websocket_client_is_ready

>Check if a client has completed its handshake and is ready to send messages

```c
mtev_boolean
mtev_websocket_client_is_ready(mtev_websocket_client_t *client)
```


  * `client` client to be checked
  * **RETURN** boolean indicating whether the client is ready

This function will continue to return true after the client has closed.


#### mtev_websocket_client_new

>Construct a new websocket client

```c
mtev_websocket_client_t *
mtev_websocket_client_new(const char *host, int port, const char *path, const char *service,
                          mtev_websocket_client_callbacks *callbacks, void *closure,
                          eventer_pool_t *pool, mtev_hash_table *sslconfig)
```


  * `host` required, host to connect to(ipv4 or ipv6 address)
  * `port` required, port to connect to on host
  * `path` required, path portion of URI
  * `service` required, protocol to connect with
  * `callbacks` required, struct containing a msg_callback and optionally ready_callback and cleanup_callback
  * `closure` optional, an opaque pointer that is passed through to the callbacks
  * `pool` optional, specify an eventer pool; thread will be chosen at random from the pool
  * `sslconfig` optional, enables SSL using the contained config
  * **RETURN** a newly constructed mtev_websocket_client_t on success, NULL on failure

ready_callback will be called immediately upon successful completion of the websocket handshake.
msg_callback is called with the complete contents of each non-control frame received.
cleanup_callback is called as the last step of cleaning up the client, after the connection has been torn down.
A client returned from this constructor must be freed with `mtev_websocket_client_free`.


#### mtev_websocket_client_new_noref

>Construct a new websocket client that will be freed automatically after cleanup

```c
mtev_boolean
mtev_websocket_client_new_noref(const char *host, int port, const char *path, const char *service,
                                mtev_websocket_client_callbacks *callbacks, void *closure,
                                eventer_pool_t *pool, mtev_hash_table *sslconfig)
```


  * `host` required, host to connect to(ipv4 or ipv6 address)
  * `port` required, port to connect to on host
  * `path` required, path portion of URI
  * `service` required, protocol to connect with
  * `callbacks` required, struct containing a msg_callback and optionally ready_callback and cleanup_callback
  * `closure` optional, an opaque pointer that is passed through to the callbacks
  * `pool` optional, specify an eventer pool; thread will be chosen at random from the pool
  * `sslconfig` optional, enables SSL using the contained config
  * **RETURN** boolean indicating success/failure

Clients allocated by this function are expected to be interacted with solely through the provided callbacks. There are two guarantees the caller must make:
1. The caller must not let a reference to the client escape from the provided callbacks.
2. The caller must not call `mtev_websocket_client_free()` with a reference to this client.


#### mtev_websocket_client_send

>Enqueue a message

```c
mtev_boolean
mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode, void *buf, size_t len)
```


  * `client` client to send message over
  * `opcode` opcode as defined in RFC 6455 and referenced in wslay.h
  * `buf` pointer to buffer containing data to send
  * `len` number of bytes of buf to send
  * **RETURN** boolean indicating success/failure

This function makes a copy of buf of length len.
This function may fail for the following reasons:
1. The client was not ready. See mtev_websocket_client_is_ready.
2. The client was already closed. See mtev_websocket_client_is_closed.
3. Out of memory.


#### mtev_websocket_client_set_cleanup_callback

>Set a new cleanup_callback on an existing client

```c
void
mtev_websocket_client_set_cleanup_callback(mtev_websocket_client_t *client
                                           mtev_websocket_client_cleanup_callback cleanup_callback)
```


  * `client` client to modify
  * `cleanup_callback` new cleanup_callback to set


#### mtev_websocket_client_set_closure

>Set a new closure

```c
void
mtev_websocket_client_set_closure(mtev_websocket_client_t *client, void *closure)
```


  * `client` client to be modified
  * `closure` closure to be set

If closure is NULL, this has the effect of removing a previously set closure.


#### mtev_websocket_client_set_msg_callback

>Set a new msg_callback on an existing client

```c
void
mtev_websocket_client_set_msg_callback(mtev_websocket_client_t *client
                                       mtev_websocket_client_msg_callback msg_callback)
```


  * `client` client to modify
  * `msg_callback` new msg_callback to set


#### mtev_websocket_client_set_ready_callback

>Set a new ready_callback on an existing client

```c
void
mtev_websocket_client_set_ready_callback(mtev_websocket_client_t *client
                                         mtev_websocket_client_ready_callback ready_callback)
```


  * `client` client to modify
  * `ready_callback` new ready_callback to set


### Z

#### mtev_zipkin_active_span

>Find the currently active span of work.

```c
Zipkin_Span *
mtev_zipkin_active_span(eventer_t e)
```


  * `e` An event object (or NULL for the current event)
  * **RETURN** A span or NULL if no span is currently active.


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
 

#### mtev_zipkin_attach_to_eventer

>Attach an active span (or new child span) to an event.

```c
void
mtev_zipkin_attach_to_eventer(eventer_t e, Zipkin_Span *span, bool new_child
                              mtev_zipkin_event_trace_level_t *track)
```


  * `e` An event object (or NULL for the current event)
  * `span` An existing zipkin span.
  * `new_child` Whether or not a child should be created under the provided span.
  * `track` Specifies how event activity should be tracked.


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
 

#### mtev_zipkin_client_drop

>Discard a client span if one exists.

```c
void
mtev_zipkin_client_drop(eventer_t e)
```


  * `e` An event object (or NULL for the current event)


#### mtev_zipkin_client_new

>Create a new span for client user (remote calling)

```c
void
mtev_zipkin_client_new(eventer_t e, const char *name, bool name_copy)
```


  * `e` An event object (or NULL for the current event)
  * `name` A string to name the span
  * `name_copy` Whether name should be allocated (copied) within the span.


#### mtev_zipkin_client_parent_hdr

>Format a parent span HTTP header for an HTTP request.

```c
bool
mtev_zipkin_client_parent_hdr(eventer_t e, char *buf, size_t len)
```


  * `e` An event object (or NULL for the current event)
  * `buf` An output buffer for "Header: Value"
  * `len` The available space in `buf`
  * **RETURN** True if successful, false if no trace is available of len is too short.


#### mtev_zipkin_client_publish

>Publish a client span if one exists.

```c
void
mtev_zipkin_client_publish(eventer_t e)
```


  * `e` An event object (or NULL for the current event)


#### mtev_zipkin_client_sampled_hdr

>Format a sampled HTTP header for an HTTP request.

```c
bool
mtev_zipkin_client_sampled_hdr(eventer_t e, char *buf, size_t len)
```


  * `e` An event object (or NULL for the current event)
  * `buf` An output buffer for "Header: Value"
  * `len` The available space in `buf`
  * **RETURN** True if successful, false if no trace is available of len is too short.


#### mtev_zipkin_client_span

>Retrieve the current client span should one exist.

```c
Zipkin_Span *
mtev_zipkin_client_span(eventer_t e)
```


  * `e` An event object (or NULL for the current event)
  * **RETURN** A span for client actions or NULL is no span exists.


#### mtev_zipkin_client_span_hdr

>Format a span HTTP header for an HTTP request.

```c
bool
mtev_zipkin_client_span_hdr(eventer_t e, char *buf, size_t len)
```


  * `e` An event object (or NULL for the current event)
  * `buf` An output buffer for "Header: Value"
  * `len` The available space in `buf`
  * **RETURN** True if successful, false if no trace is available of len is too short.


#### mtev_zipkin_client_trace_hdr

>Format a trace HTTP header for an HTTP request.

```c
bool
mtev_zipkin_client_trace_hdr(eventer_t e, char *buf, size_t len)
```


  * `e` An event object (or NULL for the current event)
  * `buf` An output buffer for "Header: Value"
  * `len` The available space in `buf`
  * **RETURN** True if successful, false if no trace is available of len is too short.


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
 

#### mtev_zipkin_default_service_name

>Sets the default service name used for new spans.

```c
void
mtev_zipkin_default_service_name(const char *service_name, bool service_name_copy)
```


  * `service_name` The service name to use.
  * `service_name_copy` Whether service_name should be allocated (copied) within the span.

mtev_zipkin_default_service_name sets a default service name for endpoints for any new spans created without their own default.  Use this with care, it is application global.  You should likely only call this once at startup.
 

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
 

#### mtev_zipkin_encode_list

>Encode a span into the specified buffer for Zipkin.

```c
size_t
mtev_zipkin_encode_list(unsigned char *buffer, size_t len, Zipkin_Span **spans, int cnt)
```


  * `buffer` The target buffer.
  * `len` The target buffer's size.
  * `spans` The array of spans to encode.
  * `cnt` The number of spans in `spans`.
  * **RETURN** The length of a successful encoding.

mtev_zipkin_encode_list will take a list of spans and encode it for Zipkin using the Thift BinaryProtocol.  The return value is always the length of a successful encoding, even if the buffer supplied is too small.  The caller must check the the returned length is less than or equal to the provided length to determine whether the encoding was successful.  The caller may provide a NULL buffer if and only if the provided len is 0.
 

#### mtev_zipkin_event_trace_level

>Globally set the default event trace level.

```c
void
mtev_zipkin_event_trace_level(mtev_zipkin_event_trace_level_t level)
```


  * `level` The new global default level for event tracing.


#### mtev_zipkin_eventer_init

>Initialize zipkin contexts for the eventer.

```c
void
mtev_zipkin_eventer_init(void)
```




#### mtev_zipkin_get_sampling

>Get sampling probabilities for different types of traces.

```c
void
mtev_zipkin_get_sampling(double *new_traces, double *parented_traces, double *debug_traces)
```


  * `new_traces` probability pointer to populate
  * `parented_traces` probability pointer to populate
  * `debug_traces` probability pointer to populate

mtev_zipkin_get_sampling gets sampling probabilities for creating new traces.  See `mtev_zipkin_sampling` and the opentracing specification for more details on what each probability means.
 

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
 

#### mtev_zipkin_span_attach_logs

>Enable mtev_log appending if span is active.

```c
void
mtev_zipkin_span_attach_logs(Zipkin_Span *span, bool on)
```


  * `span` A zipkin span (NULL allowed)
  * `on` Wether to enable or disable log appending.


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
 

#### mtev_zipkin_span_bannotate_double

>Annotate a span.

```c
Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_double(Zipkin_Span *span, const char *key, bool key_copy, double value)
```


  * `span` The span to annotate.
  * `annotation_type` The type of the value being passed in.
  * `key` The key for the annotation
  * `key_copy` Whether key should be allocated (copied) within the span.
  * `value` The value for the annotation.
  * **RETURN** A new binary annotation.
 

#### mtev_zipkin_span_bannotate_i32

>Annotate a span.

```c
Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_i32(Zipkin_Span *span, const char *key, bool key_copy, int32_t value)
```


  * `span` The span to annotate.
  * `annotation_type` The type of the value being passed in.
  * `key` The key for the annotation
  * `key_copy` Whether key should be allocated (copied) within the span.
  * `value` The value for the annotation.
  * **RETURN** A new binary annotation.
 

#### mtev_zipkin_span_bannotate_i64

>Annotate a span.

```c
Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_i64(Zipkin_Span *span, const char *key, bool key_copy, int64_t value)
```


  * `span` The span to annotate.
  * `annotation_type` The type of the value being passed in.
  * `key` The key for the annotation
  * `key_copy` Whether key should be allocated (copied) within the span.
  * `value` The value for the annotation.
  * **RETURN** A new binary annotation.
 

#### mtev_zipkin_span_bannotate_str

>Annotate a span.

```c
Zipkin_BinaryAnnotation *
mtev_zipkin_span_bannotate_str(Zipkin_Span *span, const char *key, bool key_copy, const char *value
                               bool value_copy)
```


  * `span` The span to annotate.
  * `annotation_type` The type of the value being passed in.
  * `key` The key for the annotation
  * `key_copy` Whether key should be allocated (copied) within the span.
  * `value` The value for the annotation.
  * `value_copy` Whether value should be allocated (copied) within the span.
  * **RETURN** A new binary annotation.
 

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
 

#### mtev_zipkin_span_get_ids

>Fetch the various IDs from a span.

```c
bool
mtev_zipkin_span_get_ids(Zipkin_Span *span, int64_t *traceid, int64_t *parent_id, int64_t *id)
```


  * `span` The span on which to operate.
  * `traceid` A pointer to a trace id to populate.
  * `parent_id` A pointer to a parent span id to populate.
  * `span_id` A pointer to a span id to populate.
  * **RETURN** True if the span has a parent, false otherwise.


#### mtev_zipkin_span_logs_attached

>Report whether a span should have logs attached.

```c
bool
mtev_zipkin_span_logs_attached(Zipkin_Span *span)
```


  * `span` A zipkin span to report on.


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
 

#### mtev_zipkin_span_ref

>Increase the reference count to a span.

```c
void
mtev_zipkin_span_ref(Zipkin_Span *span)
```


  * `span` The span to reference.
 

#### mtev_zipkin_span_rename

>Rename a span after it has been created, but before publishing.

```c
void
mtev_zipkin_span_rename(Zipkin_Span *span, const char *name, bool name_copy)
```


  * `span` The span to rename.
  * `name` The new name for the span.
  * `name_copy` If the passed name will be freed or lost (copy required).
 

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
 

