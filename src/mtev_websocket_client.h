#ifndef MTEV_WEBSOCKET_CLIENT_H
#define MTEV_WEBSOCKET_CLIENT_H

#include "mtev_defines.h"
#include "mtev_conf.h"

typedef struct mtev_websocket_client mtev_websocket_client_t;

typedef void (*mtev_websocket_client_ready_callback)(mtev_websocket_client_t *client);

typedef int (*mtev_websocket_client_msg_callback)(mtev_websocket_client_t *client,
                                            int opcode, const unsigned char *msg, size_t msg_len);

typedef void (*mtev_websocket_client_cleanup_callback)(mtev_websocket_client_t *client);

typedef struct {
  mtev_websocket_client_ready_callback ready_callback;
  mtev_websocket_client_msg_callback msg_callback;
  mtev_websocket_client_cleanup_callback cleanup_callback;
} mtev_websocket_client_callbacks;

// mtev_websocket_client_t *mtev_websocket_client_new(const char *url, int port);
API_EXPORT(mtev_websocket_client_t *)
  mtev_websocket_client_new(const char *url, int port,
                            const char *path, const char *service,
                            mtev_websocket_client_callbacks *callbacks);

API_EXPORT(void)
  mtev_websocket_client_set_ready_callback(mtev_websocket_client_t *client,
                                           mtev_websocket_client_ready_callback msg_callback);

API_EXPORT(void)
  mtev_websocket_client_set_msg_callback(mtev_websocket_client_t *client,
                                         mtev_websocket_client_msg_callback msg_callback);

API_EXPORT(void)
  mtev_websocket_client_set_cleanup_callback(mtev_websocket_client_t *client,
                                             mtev_websocket_client_cleanup_callback cleanup_callback);

API_EXPORT(mtev_boolean)
  mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode,
                             void *buf, size_t len);

API_EXPORT(void)
  mtev_websocket_client_free(mtev_websocket_client_t *client);

API_EXPORT(mtev_boolean)
  mtev_websocket_client_is_ready(mtev_websocket_client_t *client);

API_EXPORT(mtev_boolean)
  mtev_websocket_client_is_closed(mtev_websocket_client_t *client);

#endif
