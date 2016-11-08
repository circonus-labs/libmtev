#ifndef MTEV_WEBSOCKET_CLIENT_H
#define MTEV_WEBSOCKET_CLIENT_H

#include "mtev_conf.h"

typedef struct mtev_websocket_client mtev_websocket_client_t;

typedef int (*websocket_client_msg_handler)(mtev_websocket_client_t *ctx,
                                            int opcode, const unsigned char *msg, size_t msg_len);

// mtev_websocket_client_t *mtev_websocket_client_new(const char *url, int port);
mtev_websocket_client_t *mtev_websocket_client_new(const char *url, int port, const char *path, const char *service, websocket_client_msg_handler callback);

void mtev_websocket_client_set_recv_callback(mtev_websocket_client_t *client, websocket_client_msg_handler callback); // TODO callbacks type; also, what callbacks??

mtev_boolean mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode, void *buf, size_t len);

void mtev_websocket_client_close(mtev_websocket_client_t *client);

mtev_boolean mtev_websocket_client_is_ready(mtev_websocket_client_t *client);

mtev_boolean mtev_websocket_client_is_closed(mtev_websocket_client_t *client);

#endif
