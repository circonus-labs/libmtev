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
 

### E

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
eventer_add_asynch(eventer_t e)
```


  * `q` a job queue
  * `e` an event object

This adds the `e` event to the job queue `q`.  `e` must have a mask
of `EVENETER_ASYNCH`.


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


#### eventer_alloc

>Allocate an event to be injected into the eventer system.

```c
eventer_t 
eventer_alloc()
```


  * **RETURN** A newly allocated event.

The allocated event has a refernce count of 1 and is attached to the
calling thread.


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


#### eventer_callback_for_name

>Find an event callback function that has been registered by name.

```c
evneter_func_t 
eventer_callback_for_name(const char *name)
```


  * `name` the name of the callback.
  * **RETURN** the function pointer or NULL if no such callback has been registered.


#### eventer_choose_owner

>Find a thread in the default eventer pool.

```c
pthread_t 
eventer_choose_owner(int n)
```


  * `n` an integer.
  * **RETURN** a pthread_t of an eventer loop thread in the default eventer pool.

This return the first thread when 0 is passed as an argument.  All non-zero arguments
are spread acorss the remaining threads (if existent) as `n` modulo one less than
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


#### eventer_deref

>See eventer_free.

```c
void 
eventer_deref(eventer_t e)
```


  * `e` the event to dereference.


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


#### eventer_get_epoch

>Find the start time of the eventer loop.

```c
int 
eventer_get_epoch(struct timeval *epoch)
```


  * `epoch` a point to a `struct timeval` to fill out.
  * **RETURN** 0 on success; -1 on failure (eventer loop not started).


#### eventer_get_pool_for_event

>Determin which eventer pool owns a given event.

```c
eventer_pool_t *
eventer_get_pool_for_event(eventer_t e)
```


  * `e` an event object.
  * **RETURN** the `eventer_pool_t` to which the event is scheduled.


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


#### eventer_loop

>Start the event loop.

```c
void 
eventer_loop()
```


  * **RETURN** N/A (does not return)

This function should be called as that last think in your `child_main` function.
See [`mtev_main`](c.md#mtevmain`).


#### eventer_loop_concurrency

>Determine the concurrency of the default eventer loop.

```c
int 
eventer_loop_concurrency()
```


  * **RETURN** number of threads used for the default eventer loop.


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


#### eventer_ref

>Add a reference to an event.

```c
void 
eventer_ref(evneter_t e)
```


  * `e` the event to reference.

Adding a reference to an event will prevent it from being deallocated
prematurely.  This is classic reference counting.  It is are that one
needs to maintain an actual event past the point where the eventer
system would normally free it.  Typically, one will allocate a new
event and copy the contents of the old event into it allowing the
original to be freed.


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


#### eventer_update

>Change the activity mask for file descriptor events.

```c
void 
eventer_update(evneter_t e, int mask)
```


  * `e` an event object
  * `mask` a new mask that is some bitwise or of `EVENTER_READ`, `EVENTER_WRITE`, and `EVENTER_EXCEPTION`


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
 

#### mtev_lua_lmc_L

>Get the `lua_State *` for this module closure.

```c
lua_State *
mtev_lua_lmc_L(lua_module_closure_t *lmc)
```


  * `lmc` the `lua_module_closure_t` that was allocated for this runtime.
  * **RETURN** a Lua state


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

#### mtev_merge_sort

>Merge sort data starting at head_ptr_ptr

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
 

