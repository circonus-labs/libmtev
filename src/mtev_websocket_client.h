#ifndef MTEV_WEBSOCKET_CLIENT_H
#define MTEV_WEBSOCKET_CLIENT_H

#include "mtev_defines.h"
#include "mtev_conf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtev_websocket_client mtev_websocket_client_t;

typedef mtev_boolean (*mtev_websocket_client_ready_callback)(mtev_websocket_client_t *client,
                                                             void *closure);

typedef mtev_boolean (*mtev_websocket_client_msg_callback)(mtev_websocket_client_t *client,
                                                           int opcode,
                                                           const unsigned char *msg,
                                                           size_t msg_len,
                                                           void *closure);

typedef void (*mtev_websocket_client_cleanup_callback)(mtev_websocket_client_t *client,
                                                       void *closure);

typedef struct {
  mtev_websocket_client_ready_callback ready_callback;
  mtev_websocket_client_msg_callback msg_callback;
  mtev_websocket_client_cleanup_callback cleanup_callback;
} mtev_websocket_client_callbacks;

/*! \fn mtev_websocket_client_t *mtev_websocket_client_new(const char *host, int port, const char *path, const char *service, mtev_websocket_client_callbacks *callbacks, void *closure, eventer_pool_t *pool, mtev_hash_table *sslconfig)
    \brief Construct a new websocket client
    \param host required, host to connect to(ipv4 or ipv6 address)
    \param port required, port to connect to on host
    \param path required, path portion of URI
    \param service required, protocol to connect with
    \param callbacks required, struct containing a msg_callback and optionally ready_callback and cleanup_callback
    \param closure optional, an opaque pointer that is passed through to the callbacks
    \param pool optional, specify an eventer pool; thread will be chosen at random from the pool
    \param sslconfig optional, enables SSL using the contained config
    \return a newly constructed mtev_websocket_client_t on success, NULL on failure

    ready_callback will be called immediately upon successful completion of the websocket handshake.
    msg_callback is called with the complete contents of each non-control frame received.
    cleanup_callback is called as the last step of cleaning up the client, after the connection has been torn down.
    A client returned from this constructor must be freed with `mtev_websocket_client_free`.
*/
API_EXPORT(mtev_websocket_client_t *)
  mtev_websocket_client_new(const char *host, int port,
                            const char *path, const char *service,
                            mtev_websocket_client_callbacks *callbacks,
                            void *closure,
                            eventer_pool_t *pool,
                            mtev_hash_table *sslconfig);

/*! \fn mtev_boolean mtev_websocket_client_new_noref(const char *host, int port, const char *path, const char *service, mtev_websocket_client_callbacks *callbacks, void *closure, eventer_pool_t *pool, mtev_hash_table *sslconfig)
    \brief Construct a new websocket client that will be freed automatically after cleanup
    \param host required, host to connect to(ipv4 or ipv6 address)
    \param port required, port to connect to on host
    \param path required, path portion of URI
    \param service required, protocol to connect with
    \param callbacks required, struct containing a msg_callback and optionally ready_callback and cleanup_callback
    \param closure optional, an opaque pointer that is passed through to the callbacks
    \param pool optional, specify an eventer pool; thread will be chosen at random from the pool
    \param sslconfig optional, enables SSL using the contained config
    \return boolean indicating success/failure

    Clients allocated by this function are expected to be interacted with solely through the provided callbacks. There are two guarantees the caller must make:
    1. The caller must not let a reference to the client escape from the provided callbacks.
    2. The caller must not call `mtev_websocket_client_free()` with a reference to this client.
*/
API_EXPORT(mtev_boolean)
  mtev_websocket_client_new_noref(const char *host, int port,
                                  const char *path, const char *service,
                                  mtev_websocket_client_callbacks *callbacks,
                                  void *closure,
                                  eventer_pool_t *pool,
                                  mtev_hash_table *sslconfig);

/*! \fn void mtev_websocket_client_set_ready_callback(mtev_websocket_client_t *client, mtev_websocket_client_ready_callback ready_callback)
    \brief Set a new ready_callback on an existing client
    \param client client to modify
    \param ready_callback new ready_callback to set
*/
API_EXPORT(void)
  mtev_websocket_client_set_ready_callback(mtev_websocket_client_t *client,
                                           mtev_websocket_client_ready_callback ready_callback);

/*! \fn void mtev_websocket_client_set_msg_callback(mtev_websocket_client_t *client, mtev_websocket_client_msg_callback msg_callback)
    \brief Set a new msg_callback on an existing client
    \param client client to modify
    \param msg_callback new msg_callback to set
*/
API_EXPORT(void)
  mtev_websocket_client_set_msg_callback(mtev_websocket_client_t *client,
                                         mtev_websocket_client_msg_callback msg_callback);

/*! \fn void mtev_websocket_client_set_cleanup_callback(mtev_websocket_client_t *client, mtev_websocket_client_cleanup_callback cleanup_callback)
    \brief Set a new cleanup_callback on an existing client
    \param client client to modify
    \param cleanup_callback new cleanup_callback to set
*/
API_EXPORT(void)
  mtev_websocket_client_set_cleanup_callback(mtev_websocket_client_t *client,
                                             mtev_websocket_client_cleanup_callback cleanup_callback);

/*! \fn mtev_boolean mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode, void *buf, size_t len)
    \brief Enqueue a message
    \param client client to send message over
    \param opcode opcode as defined in RFC 6455 and referenced in wslay.h
    \param buf pointer to buffer containing data to send
    \param len number of bytes of buf to send
    \return boolean indicating success/failure

    This function makes a copy of buf of length len.
    This function may fail for the following reasons:
    1. The client was not ready. See mtev_websocket_client_is_ready.
    2. The client was already closed. See mtev_websocket_client_is_closed.
    3. Out of memory.
*/
API_EXPORT(mtev_boolean)
  mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode,
                             void *buf, size_t len);

/*! \fn void mtev_websocket_client_free(mtev_websocket_client_t *client)
    \brief Free a client
    \param client client to be freed

    This function will cleanup the client(and hence trigger any set cleanup_callback) first.
    This function does nothing if called with NULL.
*/
API_EXPORT(void)
  mtev_websocket_client_free(mtev_websocket_client_t *client);

/*! \fn mtev_boolean mtev_websocket_client_is_ready(mtev_websocket_client_t *client)
    \brief Check if a client has completed its handshake and is ready to send messages
    \param client client to be checked
    \return boolean indicating whether the client is ready

    This function will continue to return true after the client has closed.
*/
API_EXPORT(mtev_boolean)
  mtev_websocket_client_is_ready(mtev_websocket_client_t *client);

/*! \fn mtev_boolean mtev_websocket_client_is_closed(mtev_websocket_client_t *client)
    \brief Check if a client has closed and can no longer send or receive
    \param client client to be checked
    \return boolean indicating whether the client is closed

    Only a return value of mtev_true can be trusted(once closed, a client
    cannot re-open). Because the caller is unable to check this status inside
    of a locked section, it is possible that the client closes and invalidates
    the result of this function call before the caller can act on it.
*/
API_EXPORT(mtev_boolean)
  mtev_websocket_client_is_closed(mtev_websocket_client_t *client);

/*! \fn void *mtev_websocket_client_get_closure(mtev_websocket_client_t *client)
    \brief Access the currently set closure, if any
    \param client client to be accessed
    \return most recently set closure, or NULL if never set
*/
API_EXPORT(void *)
  mtev_websocket_client_get_closure(mtev_websocket_client_t *client);

/*! \fn void mtev_websocket_client_set_closure(mtev_websocket_client_t *client, void *closure)
    \brief Set a new closure
    \param client client to be modified
    \param closure closure to be set

    If closure is NULL, this has the effect of removing a previously set closure.
*/
API_EXPORT(void)
  mtev_websocket_client_set_closure(mtev_websocket_client_t *client, void *closure);

/*! \fn void mtev_websocket_client_init_logs()
    \brief Enable debug logging to "debug/websocket_client"

    Error logging is always active to "error/websocket_client".
*/
API_EXPORT(void)
  mtev_websocket_client_init_logs(void);

#ifdef __cplusplus
}
#endif

#endif
