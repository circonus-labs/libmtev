/*
 * Copyright (c) 2005-2009, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2013-2017, Circonus, Inc. All rights reserved.
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
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
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

#ifndef _UTILS_MTEV_LOG_H
#define _UTILS_MTEV_LOG_H

#include <mtev_defines.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <mtev_dyn_buffer.h>
#include <mtev_hash.h>
#include <mtev_hooks.h>
#include <mtev_time.h>
#include <mtev_json.h>
#include <mtev_zipkin.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef mtev_log_impl
typedef struct _mtev_log_stream mtev_log_stream_t;
#define mtev_log_stream_t mtev_log_stream_t *
#else
typedef void * mtev_log_stream_public_t;
#define mtev_log_stream_t mtev_log_stream_public_t
#endif
typedef struct mtev_log_stream_pipe mtev_log_stream_pipe_t;

#define MTEV_LOG_DEFAULT_DEDUP_S 5
#define MTEV_LOG_SPECULATE_ROLLBACK ((mtev_log_stream_t)NULL)

typedef enum {
  MTEV_LOG_KV_TYPE_STRING = 0,
  MTEV_LOG_KV_TYPE_INT64 = 1,
  MTEV_LOG_KV_TYPE_UINT64 = 2,
  MTEV_LOG_KV_TYPE_DOUBLE = 3,
  MTEV_LOG_KV_TYPE_STRINGN = 4,
  MTEV_LOG_KV_TYPE_UUID = 5
} mtev_log_kv_type_t;

typedef struct {
  const char *key;
  mtev_log_kv_type_t value_type;
  union {
    const char *v_string;
    int64_t v_int64;
    uint64_t v_uint64;
    double v_double;
  } value;
  size_t len;
} mtev_log_kv_t;

typedef void *mtev_LogLine_fb_t;

/* Use as:
 * MLKV( MLKV_STR("foo", "string"), MLKV_INT64("bar", 1234), MLKV_END )
 */
#define MLKV(a...) { a }
#define MLKV_STR(k,v) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_STRING, .value = { .v_string = (v) } }
#define MLKV_STRN(k,v,l) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_STRINGN, .value = { .v_string = (v) }, .len = (l) }
#define MLKV_UUID(k,v) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_UUID, .value = { .v_string = (const char *)(v) }, .len = UUID_SIZE }
#define MLKV_INT64(k,v) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_INT64, .value = { .v_int64 = (v) } }
#define MLKV_UINT64(k,v) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_UINT64, .value = { .v_uint64 = (v) } }
#define MLKV_DOUBLE(k,v) (const mtev_log_kv_t){ (k), MTEV_LOG_KV_TYPE_DOUBLE, .value = { .v_double = (v) } }
#define MLKV_END (const mtev_log_kv_t){ NULL, MTEV_LOG_KV_TYPE_STRING, .value = { .v_string = NULL } }
#define MLKV_NUM(name,value) _Generic((value), \
  bool: MLKV_INT64(name,(int64_t)(value)), char: MLKV_INT64(name,(int64_t)(value)), \
  signed char: MLKV_UINT64(name,(uint64_t)(value)), unsigned char: MLKV_UINT64(name,(uint64_t)(value)), \
  short int: MLKV_INT64(name,(int64_t)(value)), unsigned short int: MLKV_UINT64(name,(uint64_t)(value)), \
  int: MLKV_INT64(name,(int64_t)(value)), unsigned int: MLKV_UINT64(name,(uint64_t)(value)), \
  long int: MLKV_INT64(name,(int64_t)(value)), unsigned long int: MLKV_UINT64(name,(uint64_t)(value)), \
  long long int: MLKV_INT64(name,(int64_t)(value)), unsigned long long int: MLKV_UINT64(name,(uint64_t)(value)), \
  float: MLKV_DOUBLE(name,(double)(value)), \
  double: MLKV_DOUBLE(name,(double)(value)), \
  long double: MLKV_DOUBLE(name,(double)(value)), \
  default: MLKV_STR(name, "type failure"))

typedef enum {
  MTEV_LOG_FORMAT_PLAIN = 0,
  MTEV_LOG_FORMAT_FLATBUFFER,
  MTEV_LOG_FORMAT_JSON
} mtev_log_format_t;

typedef struct {
  mtev_boolean supports_async;
  int (*openop)(mtev_log_stream_t);
  int (*reopenop)(mtev_log_stream_t);
  int (*writeop)(mtev_log_stream_t, const struct timeval *whence, const void *, size_t);
  int (*writevop)(mtev_log_stream_t, const struct timeval *whence, const struct iovec *iov, int iovcnt);
  int (*closeop)(mtev_log_stream_t);
  size_t (*sizeop)(mtev_log_stream_t);
  int (*renameop)(mtev_log_stream_t, const char *);
  int (*cullop)(mtev_log_stream_t, int age, ssize_t bytes);
} logops_t;

#define	MTEV_LOG_STREAM_ENABLED		0x01
#define	MTEV_LOG_STREAM_DEBUG		0x02
#define	MTEV_LOG_STREAM_TIMESTAMPS	0x04
#define MTEV_LOG_STREAM_FACILITY	0x08
#define MTEV_LOG_STREAM_RECALCULATE     0x10
#define MTEV_LOG_STREAM_SPLIT           0x20
#define MTEV_LOG_STREAM_FEATURES        (MTEV_LOG_STREAM_DEBUG|MTEV_LOG_STREAM_TIMESTAMPS|MTEV_LOG_STREAM_FACILITY)

extern mtev_log_stream_t mtev_stderr;
extern mtev_log_stream_t mtev_debug;
extern mtev_log_stream_t mtev_error;
extern mtev_log_stream_t mtev_notice;
extern mtev_log_stream_t mtev_error_stacktrace;

#define N_L_S_ON(ls) ((ls != NULL) && (*((unsigned *)ls) & MTEV_LOG_STREAM_ENABLED) && mtev_log_has_material_output(ls))

/*! \fn mtev_boolean mtev_log_has_material_output(mtev_log_stream_t ls)
    \brief Determine if writing to a specific stream would materially go anywhere.
    \param ls a log stream
    \return `mtev_true` if writing would materialize.
 */
API_EXPORT(mtev_boolean) mtev_log_has_material_output(mtev_log_stream_t ls);

/*! \fn void mtev_log_enter_sighandler(void)
    \brief Instruct the logging system that the current thread is in a signal handler.
 */
API_EXPORT(void) mtev_log_enter_sighandler(void);

/*! \fn void mtev_log_leave_sighandler(void)
    \brief Instruct the logging system that the current thread has left a signal handler.
 */
API_EXPORT(void) mtev_log_leave_sighandler(void);
API_EXPORT(int) mtev_log_global_enabled(void);

/*! \fn void mtev_log_init(int debug_on)
    \brief Initialize the logging system
    \param debug_on if non-zero the `mtev_debug` log stream will be enabled.
 */
API_EXPORT(void) mtev_log_init(int debug_on);

/*! \fn mtev_boolean mtev_log_final_resolve(void)
    \brief Instruct the logging system to rebuild its dependency graph with new information.

    This function is used to rebuild log streams that use `logops` that may have not been loaded
    yet.  It is called automatically after the `mtev_dso` system loads a module.
 */
API_EXPORT(mtev_boolean) mtev_log_final_resolve(void);

/*! \fn int mtev_log_go_asynch(void)
    \brief Instruct the logging system to use asynchronous logging for higher performance.
    \return 0 on success, -1 on failure.

    The `mtev_main` helpers system automatically calls this.
*/
API_EXPORT(int) mtev_log_go_asynch(void);

/*! \fn int mtev_log_go_synch(void)
    \brief Instruct the logging system to use synchronous logging.
    \return 0 on success, -1 on failure.

    This can be particularly useful when attempting debug a system.
*/
API_EXPORT(int) mtev_log_go_synch(void);

/*! \fn int mtev_log_reopen_all(void)
    \brief Instruct the logging system to reopen all logs if applicable.
    \return 0 on success, -1 on failure.
*/
API_EXPORT(int) mtev_log_reopen_all(void);

/*! \fn int mtev_log_reopen_type(const char *type)
    \brief Instruct the logging system to reopen all logs of a specific type.
    \param type a type matching a logops name.
    \return 0 on success, -1 on failure.
*/
API_EXPORT(int) mtev_log_reopen_type(const char *type);

/*! \fn void mtev_register_logops(const char *type, logops_t *ops)
    \brief Register a new set of named logging operations.
    \param type a type naming this type of logging
    \param ops a structure with callbacks to drive logging operations.

    This operation will not replace an existing `logops` of the same name.
*/
API_EXPORT(void) mtev_register_logops(const char *name, logops_t *ops);

/*! \fn void * mtev_log_stream_get_ctx(mtev_log_stream_t ls)
    \brief Fetch the custom context for a log stream.
    \param ls a log stream
    \return a pointer to the context (set via `mtev_log_stream_set_ctx`)

    This is used by `logops` implementors to manage context.
*/
API_EXPORT(void *) mtev_log_stream_get_ctx(mtev_log_stream_t);

/*! \fn void mtev_log_stream_get_ctx(mtev_log_stream_t ls, void *ctx)
    \brief Set the custom context for a log stream.
    \param ls a log stream
    \param ctx a user-supplied context.

    This is used by `logops` implementors to manage context.
*/
API_EXPORT(void) mtev_log_stream_set_ctx(mtev_log_stream_t, void *);


API_EXPORT(int) mtev_log_stream_get_dedup_s(mtev_log_stream_t) __attribute__((deprecated));
API_EXPORT(int) mtev_log_stream_set_dedup_s(mtev_log_stream_t, int) __attribute__((deprecated));

/*! \fn int mtev_log_stream_get_flags(mtev_log_stream_t ls)
    \brief Get the flags set on a particular log stream.
    \param ls a log stream
    \return The bitset of flags.
*/
API_EXPORT(int) mtev_log_stream_get_flags(mtev_log_stream_t);

/*! \fn int mtev_log_stream_set_flags(mtev_log_stream_t ls, int flags)
    \brief Get the flags set on a particular log stream.
    \param ls a log stream
    \param flags a new set of replacement flags.
    \return The bitset of flags that were replaced.
*/
API_EXPORT(int) mtev_log_stream_set_flags(mtev_log_stream_t, int);

/*! \fn mtev_boolean mtev_log_stream_set_format(mtev_log_stream_t ls, mtev_log_format format)
    \brief Set the format on a particular log stream.
    \param ls a log stream
    \param format a format identitier
    \return `mtev_true` if successful

    A log stream without `logops` cannot have a format set.
*/
API_EXPORT(mtev_boolean) mtev_log_stream_set_format(mtev_log_stream_t, mtev_log_format_t);

/*! \fn const char * mtev_log_stream_get_type(mtev_log_stream_t ls)
    \brief Get the type (name of logops) from a log stream
    \param ls a log stream
    \return The name of the `logops`, `NULL` if none
*/
API_EXPORT(const char *) mtev_log_stream_get_type(mtev_log_stream_t);

/*! \fn const char * mtev_log_stream_get_name(mtev_log_stream_t ls)
    \brief Get the name of a log stream
    \param ls a log stream
    \return The name
*/
API_EXPORT(const char *) mtev_log_stream_get_name(mtev_log_stream_t);

/*! \fn const char * mtev_log_stream_get_path(mtev_log_stream_t ls)
    \brief Get the path from a log stream
    \param ls a log stream
    \return The path, `NULL` if none
*/
API_EXPORT(const char *) mtev_log_stream_get_path(mtev_log_stream_t);

/*! \fn mtev_log_stream_t mtev_log_stream_new(const char *name, const char *type, const char *path, void *ctx, mtev_hash_table *options)
    \brief Create a new log stream of a specific type.
    \param name a name for the log stream
    \param type a type of `logops`
    \param path a path appropriate for the selected `logops`
    \param ctx a context for the log stream's selected `logops`
    \param options a table of options attached to the log stream
    \return a new log stream or `NULL` on error

    This will replace a log stream of the same name should one exist.
*/
API_EXPORT(mtev_log_stream_t)
  mtev_log_stream_new(const char *, const char *, const char *,
                      void *, mtev_hash_table *);

/*! \fn mtev_log_stream_t mtev_log_stream_new_on_fd(const char *name, int fd, mtev_hash_table *options)
    \brief Create a new log stream using appropriate `logops` attached to output to a file descriptor.
    \param name a name for the log stream
    \param fd the file descriptor for output
    \param options a table of options attached to the log stream
    \return a new log stream or `NULL` on error

    This will replace a log stream of the same name should one exist.
*/
API_EXPORT(mtev_log_stream_t)
  mtev_log_stream_new_on_fd(const char *, int, mtev_hash_table *);

/*! \fn mtev_log_stream_t mtev_log_stream_new_on_file(const char *path, mtev_hash_table *options)
    \brief Create a new file-based log stream.
    \param path the path to the file. This is also used as the log stream's name
    \param options a table of options attached to the log stream
    \return a new log stream, `NULL` on error
*/
API_EXPORT(mtev_log_stream_t)
  mtev_log_stream_new_on_file(const char *, mtev_hash_table *);

/*! \fn mtev_log_stream_t mtev_log_speculate(int nlogs, int nbytes)
    \brief Create a new speculative logging buffer.
    \param nlogs store at most `nlogs` log lines
    \param nbytes store at most `nbytes` bytes.
    \return a new log stream
*/
API_EXPORT(mtev_log_stream_t) mtev_log_speculate(int nlogs, int nbytes);
/*! \fn void mtev_log_speculate_finish(mtev_log_stream_t ls, mtev_log_stream_t speculation)
    \brief Finish speculation on a speculative log stream
    \param ls a log stream to which you wish to commit the speculation, `MTEV_LOG_SPECULATE_ROLLBACK` to discard
    \param speculation a speculative log stream created with `mtev_log_speculate`
*/
API_EXPORT(void)
  mtev_log_speculate_finish(mtev_log_stream_t ls, mtev_log_stream_t speculation);

/*! \fn mtev_boolean mtev_log_stream_exists(const char *name)
    \brief Check the existence of a log stream in the logging system.
    \param name a possible name of a log stream
    \return `mtev_true` if a log stream of name `name` is configured
*/
API_EXPORT(mtev_boolean) mtev_log_stream_exists(const char *);

/*! \fn mtev_log_stream_t mtev_log_stream_find(const char *name)
    \brief Find a log stream in the logging system
    \param name a name of a log stream
    \return a log stream, creating a virtual one if no such name already exists.

    Log streams that are implicitly created will be enabled by default and outlet to
    a log stream above it in its slash-delimited hierarchy.  For example: `debug/foo/bar`
    will be implicitly created to outlet to `debug/foo` which will be implicitly created
    to outlet to `debug`.  If a new top-level stream is implicitly created, it is
    enabled but will have no outlets and thus be immaterial until connected.
*/
API_EXPORT(mtev_log_stream_t) mtev_log_stream_find(const char *);

/*! \fn mtev_log_stream mtev_log_stream_findf(const char *fmt, ...)
    \brief Find a log stream with `printf(3)` style.
    \param fmt a `printf`-style format string with appropriate trailing arguments
    \return a log stream

    This formats the stream and calls `mtev_log_string_find`.
*/
API_EXPORT(mtev_log_stream_t) mtev_log_stream_findf(const char *fmt, ...);

/*! \fn void mtev_log_stream_remove(const char *name)
    \brief Remove a log stream from the logging system.
    \param name name of a log stream to remove
*/
API_EXPORT(void) mtev_log_stream_remove(const char *name);

/*! \fn void mtev_log_stream_add_stream(mtev_log_stream_t ls, mtev_log_stream_t outlet)
    \brief Connect a log stream to another log stream.
    \param ls a log stream whose output should be sent to `outlet`
    \param outlet a log stream
*/
API_EXPORT(void) mtev_log_stream_add_stream(mtev_log_stream_t ls,
                                            mtev_log_stream_t outlet);

/*! \fn mtev_boolean mtev_log_stream_add_stream_filtered(mtev_log_stream_t ls, mtev_log_stream_t outlet, const char *filter)
    \brief Connect a log stream to another log stream with a filter.
    \param ls a log stream whose output should be sent to `outlet`
    \param outlet a log stream
    \param filter an expression parsable by `mtev_logic`
    \return `mtev_true` if the log streams could be connected with the give filter.
*/
API_EXPORT(mtev_boolean)
  mtev_log_stream_add_stream_filtered(mtev_log_stream_t ls,
                                      mtev_log_stream_t outlet,
                                      const char *filter);

/*! \fn void mtev_log_stream_removeall_streams(mtev_log_stream_t ls)
    \brief Remove all outlets from a log stream
    \param ls a log stream
*/
API_EXPORT(void) mtev_log_stream_removeall_streams(mtev_log_stream_t ls);

/*! \fn mtev_log_stream_t mtev_log_stream_remove_stream(mtev_log_stream_t ls, const char *name)
    \brief Disconnect a specific outlet by name from a log stream
    \param ls a log stream from which to attempt removing an outlet
    \param name the name of the log stream that should no longer be in the outlet list
    \return a log stream that was disconnected, NULL if no log stream outlet was disconnected
*/
API_EXPORT(mtev_log_stream_t)
  mtev_log_stream_remove_stream(mtev_log_stream_t ls, const char *name);

/*! \fn void mtev_log_stream_reopen(mtev_log_stream_t ls)
    \brief Reopen a log stream
    \param ls a log stream to reopen
*/
API_EXPORT(void) mtev_log_stream_reopen(mtev_log_stream_t ls);

/*! \fn int mtev_log_stream_cull(mtev_log_stream_t ls, int age, ssize_t bytes)
    \brief Cull old and/or excessive log contents
    \param ls a log stream to cull
    \param age the maximum age in seconds to retain, -1 to skip the age assessment
    \param bytes the maximum bytes to retain, -1 to skip the size assessment
    \return -1 on error, positive if culling occurred, 0 if no action was taken

    Only certain `logops` support culling, if the `logops` do not support it -1 is usually returned.
*/
API_EXPORT(int) mtev_log_stream_cull(mtev_log_stream_t ls,
                                     int age, ssize_t bytes);

API_EXPORT(void) mtev_log_dedup_flush(const struct timeval *now) __attribute__((deprecated));
API_EXPORT(void) mtev_log_dedup_init(void) __attribute__((deprecated));

#define MTEV_LOG_RENAME_AUTOTIME ((const char *)-1)

/*! \fn int mtev_log_stream_rename(mtev_log_stream_t ls, const char *path)
    \brief Rename a log stream's target if supported
    \param ls a log stream
    \param path a new path name, `MTEV_LOG_RENAME_AUTOTIME` to automatically name it with the current timestamp (required for culling by age)
    \return 0 on success, -1 on failure.

    If called manually, a call to `mtev_log_stream_reopen` should follow.
*/
API_EXPORT(int) mtev_log_stream_rename(mtev_log_stream_t ls, const char *);

/*! \fn void mtev_log_stream_close(mtev_log_stream_t ls)
    \brief Close a log stream
    \param ls a log stream
*/
API_EXPORT(void) mtev_log_stream_close(mtev_log_stream_t ls);

/*! \fn size_t mtev_log_stream_size(mtev_log_stream_t ls)
    \brief Determine the space occupied by a log stream
    \param ls a log stream
    \return A size in bytes, if the `logops` of the given stream supports size assessment, 0 otherwise.
*/
API_EXPORT(size_t) mtev_log_stream_size(mtev_log_stream_t ls);

/*! \fn size_t mtev_log_stream_written(mtev_log_stream_t ls)
    \brief Report the number of bytes written to a log stream
    \param ls a log stream
    \return A size in bytes since the application started.
*/
API_EXPORT(size_t) mtev_log_stream_written(mtev_log_stream_t ls);

/*! \fn mtev_boolean mtev_log_stream_stats_enable(mtev_log_stream_t ls)
    \brief Request that the log stream register statistics with the `mtev_stats` system.
    \param ls a log stream
    \return `mtev_true` is successfully registered with the stats system.
*/
API_EXPORT(mtev_boolean) mtev_log_stream_stats_enable(mtev_log_stream_t ls);

/*! \fn const char * mtev_log_stream_get_property(mtev_log_stream_t ls, const char *key)
    \brief Retrieve configuration property values from a log stream.
    \param ls a log stream
    \param key the key to look up in the log stream's options
    \return A value associated with the provided key, `NULL` if not found.
*/
API_EXPORT(const char *) mtev_log_stream_get_property(mtev_log_stream_t ls,
                                                      const char *);

/*! \fn void mtev_log_stream_set_property(mtev_log_stream_t ls, const char *key, const char *value)
    \brief Set or replace a key-value property on a log stream
    \param ls a log stream
    \param key a key
    \param value a value, `NULL` is allowed.
*/
API_EXPORT(void) mtev_log_stream_set_property(mtev_log_stream_t ls,
                                              const char *, const char *);

/*! \fn void mtev_log_stream_free(mtev_log_stream_t ls)
    \brief Free the in-memory resources related to a log stream
    \param ls a log stream
*/
API_EXPORT(void) mtev_log_stream_free(mtev_log_stream_t ls);

/*! \fn int mtev_ex_vlog(mtev_log_stream_t ls, const struct timeval *now, const char *file, int line, const mtev_log_kv_t *kvpairs, const char *format, va_list arg)
    \brief Log to a log stream (metadata, `va_list`)
    \param ls a log stream
    \param now the current time
    \param file a source file name
    \param line a source file line number
    \param kvpairs a list of key-value metadata
    \param format a `printf`-style format string
    \param arg a `varargs` list
    \return The number of bytes written or an approximation

    See mtev_ex_log.
 */
API_EXPORT(int) mtev_ex_vlog(mtev_log_stream_t ls, const struct timeval *,
                          const char *file, int line,
                          const mtev_log_kv_t * const,
                          const char *format, va_list arg);

/*! \fn int mtev_ex_log(mtev_log_stream_t ls, const struct timeval *now, const char *file, int line, const mtev_log_kv_t *kvpairs, const char *format, ...)
    \brief Log to a log stream (metadata, va_list)
    \param ls a log stream
    \param now the current time
    \param file a source file name
    \param line a source file line number
    \param kvpairs a list of key-value metadata
    \param format a `printf`-style format string
    \param arg a `varargs` list
    \return The number of bytes written or an approximation

    This function (used by the `mtevL`, `mtevLT`, `mtevEL`, `mtevELT` macros) is responsible for logging.
    A variery of metadata fields are created internally including timestamp, `threadname`, `threadid`,
    facility (log name), file, and line.  These metadata fields are extended with those passed in
    as `kvpairs`.  These KV pairs should be created with the `MLKV, MLKV_NUM, MLKV_STR, MLKV_END`
    macros.  The message is formatted, filtering is applied and then the resulting payload is
    pushed through the directed acyclic graph of log streams.  See `mtevEL` for examples.
 */
API_EXPORT(int) mtev_ex_log(mtev_log_stream_t ls, const struct timeval *,
                          const char *file, int line,
                          const mtev_log_kv_t * const,
                          const char *format, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 6, 7)))
#endif
  ;

/*! \fn int mtev_vlog(mtev_log_stream_t ls, const struct timeval *now, const char *file, int line, const char *format, ...)
    \brief Log to a log stream (metadata, `va_list`)
    \param ls a log stream
    \param now the current time
    \param file a source file name
    \param line a source file line number
    \param format a `printf`-style format string
    \param arg a `varargs` list
    \return The number of bytes written or an approximation

    See mtev_ex_log.
 */
API_EXPORT(int) mtev_vlog(mtev_log_stream_t ls, const struct timeval *,
                          const char *file, int line,
                          const char *format, va_list arg);

/*! \fn int mtev_log(mtev_log_stream_t ls, const struct timeval *now, const char *file, int line, const char *format, ...)
    \brief Log to a log stream (metadata, `va_list`)
    \param ls a log stream
    \param now the current time
    \param file a source file name
    \param line a source file line number
    \param format a `printf`-style format string
    \param arg a `varargs` list
    \return The number of bytes written or an approximation

    See mtev_ex_log.
 */
API_EXPORT(int) mtev_log(mtev_log_stream_t ls, const struct timeval *,
                         const char *file, int line,
                         const char *format, ...)
#ifdef __GNUC__
  __attribute__ ((format (printf, 5, 6)))
#endif
  ;

/*! \fn int mtev_log_list(mtev_log_stream_t *loggers, int nsize)
    \brief Retrieve a list of log streams
    \param loggers an array of `nsize` log streams
    \param nsize the size of the `loggers` array
    \return The number of log streams placed in the `loggers` array.  If there was insufficient space, the number of elements required is made negative and returned.
*/
API_EXPORT(int) mtev_log_list(mtev_log_stream_t *loggers, int nsize);

/*! \fn mtev_json_object * mtev_log_stream_to_json(mtev_log_stream_t ls)
    \brief Get a JSON description of a log stream
    \param ls a log stream
    \return A mtev_json_object describing the log stream
*/
API_EXPORT(mtev_json_object *)
  mtev_log_stream_to_json(mtev_log_stream_t ls);

/*! \fn mtev_LogLine_fb_t mtev_log_flatbuffer_from_buffer(void *buff, size_t buff_len)
    \brief Given a `flatbuffer` serialization of a log line, convert it to the `flatcc` type.
    \param buff a pointer to memory containing the `flatbuffer` data.
    \param buff_len the length of the buffer `buff`
    \return a `flatcc` `flatbuffer` type
*/
API_EXPORT(mtev_LogLine_fb_t)
  mtev_log_flatbuffer_from_buffer(void *buff, size_t buff_len);

/*! \fn void mtev_log_flatbuffer_to_json(mtev_LogLine_fb_t ll, mtev_dyn_buffer_t *tgt)
    \brief Convert a `flatcc` typed log line into a textual `JSON` serialization
    \param ll a `flatcc` `flatbuffer` type
    \param tgt a target buffer to write the `JSON` serialization to
*/
API_EXPORT(void)
  mtev_log_flatbuffer_to_json(mtev_LogLine_fb_t ll, mtev_dyn_buffer_t *tgt);

/*! \fn int mtev_log_memory_lines(mtev_log_stream_t ls, int log_lines, int (*cb)(uint64_t logid, const struct timeval *whence, const char *text, size_t text_len, void *closure), void *closure)
    \brief Iterate over a fixed set of "memory" log lines invoking a callback for each.
    \param ls a log stream of type "memory"
    \param log_lines the number of most recent log lines to traverse
    \param cb a callback to invoke for each log line found
    \param closure a user-supplied closure to pass into the callback
    \return The number of log lines traversed, -1 on error.
*/
API_EXPORT(int)
  mtev_log_memory_lines(mtev_log_stream_t ls, int log_lines,
                        int (*f)(uint64_t, const struct timeval *,
                                 const char *, size_t, void *),
                        void *closure);

/*! \fn int mtev_log_memory_lines_since(mtev_log_stream_t ls, uint64_t afterwhich, int (*cb)(uint64_t logid, const struct timeval *whnce, const char *text, size_t text_len, void *closure), void *closure)
    \brief Iterate over a fixed set of "memory" log lines invoking a callback for each.
    \param ls a log stream of type "memory"
    \param afterwhich the the log id after which traversal should start (log id is the first argument to the callback)
    \param cb a callback to invoke for each log line found
    \param closure a user-supplied closure to pass into the callback
    \return The number of log lines traversed, -1 on error.
*/
API_EXPORT(int)
  mtev_log_memory_lines_since(mtev_log_stream_t ls, uint64_t afterwhich,
                              int (*f)(uint64_t, const struct timeval *,
                                      const char *, size_t, void *),
                              void *closure);

/*! \fn mtev_log_stream_pipe_t * mtev_log_stream_pipe_new(mtev_log_stream_t ls)
    \brief Create a `mtev_log_stream_pipe_t` suitable for cross-process logging
    \param ls the target log stream
    \return a new log stream pipe
*/
API_EXPORT(mtev_log_stream_pipe_t *)
  mtev_log_stream_pipe_new(mtev_log_stream_t);

/*! \fn void mtev_log_stream_pipe_close(mtev_log_stream_pipe_t *lp)
    \brief Close a log stream pipe that will not be used.
    \param lp a log stream pipe
*/
API_EXPORT(void)
  mtev_log_stream_pipe_close(mtev_log_stream_pipe_t *);
/*! \fn int mtev_log_stream_pipe_dup2(mtev_log_stream_pipe_t *lp, int fd)
    \brief Relocate the child end of the log stream pipe to a specific file descriptor
    \param lp a log stream pipe
    \param fd a target file descriptor, it's atomically closed and replaced
    \return The return of the internal `dup2(2)` system call.
*/
API_EXPORT(int)
  mtev_log_stream_pipe_dup2(mtev_log_stream_pipe_t *, int fd);

/*! \fn void mtev_log_stream_pipe_post_fork_parent(mtev_log_stream_pipe_t *lp)
    \brief Prepare a log stream pipe for use in the parent process post-fork
    \param lp a log stream pipe
*/
API_EXPORT(void)
  mtev_log_stream_pipe_post_fork_parent(mtev_log_stream_pipe_t *lp);

/*! \fn void mtev_log_stream_pipe_post_fork_child(mtev_log_stream_pipe_t *lp)
    \brief Prepare a log stream pipe for use in the child process post-fork
    \param lp a log stream pipe
*/
API_EXPORT(void)
  mtev_log_stream_pipe_post_fork_child(mtev_log_stream_pipe_t *lp);

/*! \fn void mtev_log_init_globals(void)
    \brief Initialize the logging system.
*/
API_EXPORT(void)
  mtev_log_init_globals(void);

/*! \fn void mtev_log_hexdump(mtev_log_stream_t ls, const void * addr, const size_t len)
    \brief Log a hex dump of memory
    \param ls a log stream
    \param addr a memory address
    \param len a size in bytes

    This calls `mtev_log_hexdump_ex()` with a width of 8.
*/
API_EXPORT(void)
  mtev_log_hexdump(mtev_log_stream_t ls, const void * addr, const size_t len);

/*! \fn void mtev_log_hexdump(mtev_log_stream_t ls, const void * addr, const size_t len, uint8_t width)
    \brief Log a hex dump of memory
    \param ls a log stream
    \param addr a memory address
    \param len a size in bytes
    \param width the number of bytes to show per line.
*/
API_EXPORT(void)
  mtev_log_hexdump_ex(mtev_log_stream_t ls, const void * addr, const size_t len, uint8_t width);

/*! \fn mtevELT(mtev_log_stream_t ls, const struct timeval *now, mtev_log_kv_t *meta, const char *fmt, ...)
    \brief MACRO write to a log stream
    \param ls a log stream
    \param now a timeval representing the current time
    \param meta extra metadata
    \param fmt a `printf`-style format string
    \param ... `printf` arguments
*/
#define mtevELT(ls, t, ex, args...) do { \
  if((ls)) { \
    bool mtevLT_doit = mtev_log_global_enabled() || N_L_S_ON((ls)); \
    if(!mtevLT_doit) { \
      Zipkin_Span *mtevLT_span = mtev_zipkin_active_span(NULL); \
      if(mtevLT_span != NULL) { \
        mtevLT_doit = mtev_zipkin_span_logs_attached(mtevLT_span); \
      } \
    } \
    if(mtevLT_doit) { \
      const mtev_log_kv_t __meta[] = ex; \
      mtev_ex_log((ls), t, __FILE__, __LINE__, __meta, args); \
    } \
  } \
} while(0)

/*! \fn mtevEL(mtev_log_stream_t ls, mtev_log_kv_t *meta, const char *fmt, ...)
    \brief MACRO write to a log stream
    \param ls a log stream
    \param meta extra metadata
    \param fmt a `printf`-style format string
    \param ... `printf` arguments

    This calls `mtevELT` with `NULL` as the time argument such that the current time is determined
    in the logging system.  These short-form macros should almost always be used as they will
    make efforts to skip evaluation of the arguments if the logging would not materialize anywhere.

    Example: `mtevEL(mtev_error, MLKV{ MLKV_NUM("answer", 42"), MLKV_STR("question", "what?"), MLKV_END }, "hello %s\n", name);`
*/
#define mtevEL(ls, ex, args...) do { \
  if((ls)) { \
    bool mtevLT_doit = mtev_log_global_enabled() || N_L_S_ON((ls)); \
    if(!mtevLT_doit) { \
      Zipkin_Span *mtevLT_span = mtev_zipkin_active_span(NULL); \
      if(mtevLT_span != NULL) { \
        mtevLT_doit = mtev_zipkin_span_logs_attached(mtevLT_span); \
      } \
    } \
    if(mtevLT_doit) { \
      const mtev_log_kv_t __meta[] = ex; \
      mtev_ex_log((ls), NULL, __FILE__, __LINE__, __meta, args); \
    } \
  } \
} while(0)

/*! \fn mtevLT(mtev_log_stream_t ls, const struct timeval *now, const char *fmt, ...)
    \brief MACRO write to a log stream
    \param ls a log stream
    \param now a timeval representing the current time
    \param fmt a `printf`-style format string
    \param ... `printf` arguments
*/
#define mtevLT(ls, t, args...) do { \
  if((ls)) { \
    bool mtevLT_doit = mtev_log_global_enabled() || N_L_S_ON((ls)); \
    if(!mtevLT_doit) { \
      Zipkin_Span *mtevLT_span = mtev_zipkin_active_span(NULL); \
      if(mtevLT_span != NULL) { \
        mtevLT_doit = mtev_zipkin_span_logs_attached(mtevLT_span); \
      } \
    } \
    if(mtevLT_doit) { \
      mtev_log((ls), t, __FILE__, __LINE__, args); \
    } \
  } \
} while(0)

/*! \fn mtevL(mtev_log_stream_t ls, const char *fmt, ...)
    \brief MACRO write to a log stream
    \param ls a log stream
    \param fmt a `printf`-style format string
    \param ... `printf` arguments
*/
#define mtevL(ls, args...) do { \
  if((ls)) { \
    bool mtevLT_doit = mtev_log_global_enabled() || N_L_S_ON((ls)); \
    if(!mtevLT_doit) { \
      Zipkin_Span *mtevLT_span = mtev_zipkin_active_span(NULL); \
      if(mtevLT_span != NULL) { \
        mtevLT_doit = mtev_zipkin_span_logs_attached(mtevLT_span); \
      } \
    } \
    if(mtevLT_doit) { \
      mtev_log((ls), NULL, __FILE__, __LINE__, args); \
    } \
  } \
} while(0)

/*! \fn mtevFatal(mtev_log_stream_t ls, const char *fmt, ...)
    \brief MACRO to abort after logging.

    This function will force the logging system into synchronous behavior, log with `mtevL`, and abort.
 */
#define mtevFatal(ls,args...) do {\
  mtev_log_go_synch(); \
  mtevL((ls), "[FATAL] " args); \
  abort(); \
} while(0)

/* inline prototype here so we don't have circular includes */
/*! \fn mtevTerminate(mtev_log_stream_t ls, const char *fmt, ...)
    \brief MACRO to abort after logging.

    This function will force the logging system into synchronous behavior, log with `mtevL`, and `exit(2)`.
 */
#define mtevTerminate(ls,args...) do {\
  mtev_log_go_synch(); \
  mtevL((ls), "[TERMINATE] " args); \
  exit(2); \
} while(0)

extern uint32_t mtev_watchdog_number_of_starts(void);
#define mtevStartupTerminate(ls,args...) do {\
  if(mtev_watchdog_number_of_starts() > 0) { \
    mtevFatal(ls,args); \
  } \
  mtevTerminate(ls,args); \
} while(0)

/*! \fn mtevAssert(condition)
    \brief MACRO that calls `mtevFatal` if the condition evaluates to false.
*/
/*! \fn mtevEvalAssert(condition)
    \brief MACRO that calls `mtevFatal` if the condition evaluates to false.
*/
#ifdef NDEBUG
#error "need to audit mtevAssert usage"
#define mtevAssert(condition) do {} while(0)
#define mtevEvalAssert(condition) do { if (!(condition)) ; } while(0)
#else
#define mtevAssert(condition) do {\
  if(!(condition)) { \
    mtevFatal(mtev_error, "assertion (%s) at %s:%d failed\n", #condition, __FILE__, __LINE__);\
  }\
} while(0)
#define mtevEvalAssert(condition) mtevAssert(condition)
#endif

#define SETUP_LOG(a, b) do { if(!a##_log) a##_log = mtev_log_stream_find(#a); \
                             if(!a##_log) { b; } } while(0)

MTEV_HOOK_PROTO(mtev_log_plain,
                (mtev_log_stream_t ls, const struct timeval *whence,
                 const char *buffer, size_t len),
                void *, closure,
                (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                 const char *buffer, size_t len))

MTEV_HOOK_PROTO(mtev_log_flatbuffer,
                (mtev_log_stream_t ls, const struct timeval *whence,
                 const uint8_t *buffer, size_t len),
                void *, closure,
                (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                 const uint8_t *buffer, size_t len))

/* This is legacy, but we should maintain it... timebuflen and debugbuflen
 * are always zero in the invocation.
 */
MTEV_HOOK_PROTO(mtev_log_line,
                (mtev_log_stream_t ls, const struct timeval *whence,
                 const char *timebuf, int timebuflen,
                 const char *debugbuf, int debugbuflen,
                 const char *buffer, size_t len),
                void *, closure,
                (void *closure, mtev_log_stream_t ls, const struct timeval *whence,
                 const char *timebuf, int timebuflen,
                 const char *debugbuf, int debugbuflen,
                 const char *buffer, size_t len))

#ifdef __cplusplus
}
#endif

#endif
