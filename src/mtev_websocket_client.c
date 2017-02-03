#include "mtev_websocket_client.h"
#include "mtev_http.h"
#include "utils/mtev_log.h"
#include "utils/mtev_b64.h"

#include <errno.h>
#include <openssl/sha.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifdef HAVE_WSLAY
#include <wslay/wslay.h>
#endif

struct mtev_websocket_client {
  eventer_t e;
#ifdef HAVE_WSLAY
  wslay_event_context_ptr wslay_ctx;
#endif
  mtev_websocket_client_ready_callback ready_callback;
  mtev_websocket_client_msg_callback msg_callback;
  mtev_websocket_client_cleanup_callback cleanup_callback;
  mtev_boolean sent_handshake;
  mtev_boolean did_handshake;
  mtev_boolean should_close; /* used for communicating an error in wslay_on_msg_recv_callback */
  mtev_boolean closed;
  pthread_mutex_t lock;
  const char *path;
  const char *host;
  const char *service; /* protocol */
  int wanted_eventer_mask;
  char client_key[25];
  void *closure;
};

#ifdef HAVE_WSLAY
static ssize_t wslay_send_callback(wslay_event_context_ptr ctx,
                            const uint8_t *data, size_t len, int flags,
                            void *user_data);

static ssize_t wslay_recv_callback(wslay_event_context_ptr ctx,
                                   uint8_t *buf, size_t len,
                                   int flags, void *user_data);

static int wslay_genmask_callback(wslay_event_context_ptr ctx,
                                  uint8_t *buf, size_t len,
                                  void *user_data);

static void wslay_on_msg_recv_callback(wslay_event_context_ptr ctx,
                                       const struct wslay_event_on_msg_recv_arg *arg,
                                       void *user_data);

static struct wslay_event_callbacks wslay_callbacks = {
  wslay_recv_callback,
  wslay_send_callback,
  wslay_genmask_callback,
  NULL,
  NULL,
  NULL,
  wslay_on_msg_recv_callback
};

static ssize_t
wslay_send_callback(wslay_event_context_ptr ctx,
                    const uint8_t *data, size_t len, int flags,
                    void *user_data)
{
  ssize_t r;
  mtev_websocket_client_t *client = user_data;
  client->wanted_eventer_mask = 0;

  if(!client->e) {
    wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }

  while((r = client->e->opset->write(client->e->fd, data, len,
                                     &client->wanted_eventer_mask,
                                     client->e)) == -1
         && errno == EINTR);

  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      mtevL(mtev_error, "websocket client's wslay_send_callback failed: %s\n", strerror(errno));
      wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  }

  return r;
}

static ssize_t
wslay_recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
                    int flags, void *user_data)
{
  ssize_t r;
  mtev_websocket_client_t *client = user_data;
  client->wanted_eventer_mask = 0;

  if(!client->e) {
    wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }

  while((r = client->e->opset->read(client->e->fd,
                                    buf, len, &client->wanted_eventer_mask,
                                    client->e)) == -1
        && errno == EINTR);

  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      mtevL(mtev_error, "websocket client's wslay_recv_callback failed: %s\n", strerror(errno));
      wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (r == 0) {
    mtevL(mtev_error, "websocket client's wslay_recv_callback received zero bytes\n");
    wslay_event_set_error(client->wslay_ctx, WSLAY_ERR_CALLBACK_FAILURE);
    r = -1;
  }
  return r;
}

static int
wslay_genmask_callback(wslay_event_context_ptr ctx,
                       uint8_t *buf, size_t len,
                       void *user_data) {
  int i;
  for(i = 0; i < len; i++)
    buf[i] = lrand48();
  return 0;
}

static void
wslay_on_msg_recv_callback(wslay_event_context_ptr ctx,
                           const struct wslay_event_on_msg_recv_arg *arg,
                           void *user_data)
{
  mtev_websocket_client_t *client = user_data;
  mtev_boolean rv = 0;

  if (!wslay_is_ctrl_frame(arg->opcode)) {
    if (client->msg_callback != NULL) {
      rv = client->msg_callback(client, arg->opcode, arg->msg, arg->msg_length, client->closure);
      if (!rv) {
        mtevL(mtev_error, "Websocket client consumer handler failed, flagging for abort\n");
        client->should_close = mtev_true;
      }
    } else {
       mtevL(mtev_error, "Websocket client has no handler function set, aborting connection\n");
       client->should_close = mtev_true;
    }
  }
}

/* https://tools.ietf.org/html/rfc6455#section-4 */

static mtev_boolean
send_reqheader(eventer_t e, const char *buf, int len, int *mask)
{
  size_t off = 0;
  ssize_t r;
  while(off < len) {
    while((r = e->opset->write(e->fd, buf + off, len - off, mask, e)) == -1
          && errno == EINTR);
    if(r == -1) {
      mtevL(mtev_error, "Websocket client failed while sending headers: %s\n", strerror(errno));
      return mtev_false;
    }
    off += r;
  }
  return mtev_true;
}

static ssize_t
recv_resheader(eventer_t e, char *buf, int len, int *mask) {
  size_t off = 0;
  ssize_t r;
  while(off < len) {
    while((r = e->opset->read(e->fd, buf + off, len - off, mask, e)) == -1
          && errno == EINTR);
    if(r <= 0) {
      mtevL(mtev_error, "Websocket client failed while receiving headers: %s\n", strerror(errno));
      return -1;
    } else if(r > 0) {
      off += r;
    }
    if(off >= 4 && !strncmp(buf + off - 4, "\r\n\r\n", 4)) {
      return off;
    }
  }
  mtevL(mtev_error, "Websocket client received headers that were too long\n");
  return -1;
}

/* srand48 is called in an mtev_hash init function, which is called during a
 * few different init phases that will have been called before us */
static void
mtev_websocket_client_create_key(char *dest) {
  /* base64 encoded length is 4*ceil(n/3) so a pre-encoding length of 18 gives
   * us an encoded length of 24 */
  unsigned char buf[18];
  for(int i = 0; i < 18; i++)
    buf[i] = lrand48();
  mtev_b64_encode(buf, 18, dest, 24);
}

static mtev_boolean
mtev_websocket_client_send_handshake(mtev_websocket_client_t *client) {
  char reqheader[4096];

  mtev_websocket_client_create_key(client->client_key);

  int reqlen = snprintf(reqheader, sizeof(reqheader),
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Protocol: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        "\r\n",
                        client->path, client->host, client->client_key, client->service);

  return send_reqheader(client->e, reqheader, reqlen, &client->wanted_eventer_mask);
}

static mtev_boolean
mtev_websocket_client_recv_handshake(mtev_websocket_client_t *client) {
  char resheader[8192];
  char accept_key[mtev_b64_encode_len(SHA_DIGEST_LENGTH) + 1];

  mtev_http_create_websocket_accept_key(accept_key,
                                        mtev_b64_encode_len(SHA_DIGEST_LENGTH) + 1,
                                        client->client_key);

  if(recv_resheader(client->e, resheader, sizeof(resheader), &client->wanted_eventer_mask) == -1) {
    return mtev_false;
  }

  char *res_accept_key = strstr(resheader, "Sec-WebSocket-Accept");
  if(res_accept_key == NULL) {
    mtevL(mtev_error, "Websocket client couldn't find accept key in response headers\n");
    return mtev_false;
  }
  /* skip the header text */
  res_accept_key += 22; 

  if(!strncmp(accept_key, res_accept_key, mtev_b64_encode_len(SHA_DIGEST_LENGTH))) {
    return mtev_true;
  } else {
    mtevL(mtev_error, "Websocket client found incorrect accept key in response headers\n");
    return mtev_false;
  }
}

static void
mtev_websocket_client_cleanup(mtev_websocket_client_t *client);

static int
mtev_websocket_client_drive(eventer_t e, int mask, void *closure, struct timeval *now) {
  mtev_websocket_client_t *client = closure;

  if(mask & EVENTER_EXCEPTION || client->should_close || client->closed) {
abort_drive:
    mtev_websocket_client_cleanup(client);
    return 0;
  }

  if(!client->did_handshake) {
    if(!client->sent_handshake && mask & EVENTER_WRITE) {
      if(mtev_websocket_client_send_handshake(client) == mtev_false) {
        mtevL(mtev_error, "mtev_websocket_client_send_handshake failed, aborting drive\n");
        goto abort_drive;
      }
      client->sent_handshake = mtev_true;
    }
    
    if(client->sent_handshake && mask & EVENTER_READ) {
      if(mtev_websocket_client_recv_handshake(client) == mtev_false) {
        mtevL(mtev_error, "mtev_websocket_client_recv_handshake failed, aborting drive\n");
        goto abort_drive;
      }
      wslay_event_context_client_init(&client->wslay_ctx, &wslay_callbacks, client);
      client->did_handshake = mtev_true;
      if(client->ready_callback) {
        if(!client->ready_callback(client, client->closure)) goto abort_drive;
      }
    } else {
      return EVENTER_READ | EVENTER_EXCEPTION;
    }
  }

  if (wslay_event_want_read(client->wslay_ctx) == 0
      && wslay_event_want_write(client->wslay_ctx) == 0) {
    mtevL(mtev_error, "Websocket client's wslay context didn't want read or write, aborting drive\n");
    goto abort_drive;
  }

  /* wslay_on_msg_recv_callback may set client->should_close if the consumer handler fails */
  if (wslay_event_recv(client->wslay_ctx) != 0 || client->should_close) {
    mtevL(mtev_error, "Websocket client's wslay_event_recv failed, aborting drive\n");
    goto abort_drive;
  }

  if (wslay_event_send(client->wslay_ctx) != 0) {
    mtevL(mtev_error, "Websocket client's wslay_event_send failed, aborting drive\n");
    goto abort_drive;
  }

  return client->wanted_eventer_mask | EVENTER_EXCEPTION | EVENTER_WRITE;
  return 0;
}
#endif

mtev_websocket_client_t *
mtev_websocket_client_new(const char *host, int port, const char *path, const char *service,
                          mtev_websocket_client_callbacks *callbacks, void *closure, eventer_pool_t *pool) {
#ifdef HAVE_WSLAY
  int fd = -1, rv;
  int family = AF_INET;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } addr;
  union {
    struct sockaddr remote;
    struct sockaddr_in remote_in;
    struct sockaddr_in6 remote_in6;
  } remote;
  socklen_t remote_len;

  rv = inet_pton(family, host, &addr);
  if(rv != 1) {
    family = AF_INET6;
    rv = inet_pton(family, host, &addr);
    if(rv != 1) {
      mtevL(mtev_error, "Cannot translate '%s' to IP\n", host);
      return NULL;
    }
  }

  memset(&remote, 0, sizeof(remote));
  if(family == AF_INET) {
    struct sockaddr_in *s = &remote.remote_in;
    s->sin_family = family;
    s->sin_port = htons(port);
    memcpy(&s->sin_addr, &addr, sizeof(struct in_addr));
    remote_len = sizeof(*s);
  }
  else {
    struct sockaddr_in6 *s = &remote.remote_in6;
    s->sin6_family = family;
    s->sin6_port = htons(port);
    memcpy(&s->sin6_addr, &addr, sizeof(addr));
    remote_len = sizeof(*s);
  }

  if((fd = socket(family, SOCK_STREAM, 0)) == -1) {
    mtevL(mtev_error, "mtev_websocket_client_new failed to open socket: %s\n", strerror(errno));
    return NULL;
  }

  if(eventer_set_fd_nonblocking(fd)) {
    close(fd);
    mtevL(mtev_error, "mtev_websocket_client_new failed to set socket to non-blocking\n");
    return NULL;
  }

  rv = connect(fd, &remote.remote, remote_len);
  if(rv == -1 && errno != EINPROGRESS) {
    close(fd);
    fd = -1;
    mtevL(mtev_error, "mtev_websocket_client_new failed to connect to %s:%d\n", host, port);
    return NULL;
  }

  mtev_websocket_client_t *client = calloc(1, sizeof(mtev_websocket_client_t));
  client->did_handshake = mtev_false;
  client->should_close = mtev_false;
  client->closed = mtev_false;
  pthread_mutex_init(&client->lock, NULL);
  client->path = strdup(path);
  client->host = strdup(host);
  client->service = strdup(service);
  client->ready_callback = callbacks->ready_callback;
  client->msg_callback = callbacks->msg_callback;
  client->cleanup_callback = callbacks->cleanup_callback;
  client->closure = closure;

  eventer_t e = eventer_alloc();
  e->fd = fd;
  e->mask = EVENTER_READ | EVENTER_WRITE | EVENTER_EXCEPTION;
  e->callback = mtev_websocket_client_drive;
  e->closure = client;
  if(pool) e->thr_owner = eventer_choose_owner_pool(pool, lrand48());
  client->e = e;
  eventer_add(e);
  return client;
#else
  return NULL;
#endif
}

void
mtev_websocket_client_set_ready_callback(mtev_websocket_client_t *client,
                                        mtev_websocket_client_ready_callback ready_callback) {
#ifdef HAVE_WSLAY
  client->ready_callback = ready_callback;
#endif
}

void
mtev_websocket_client_set_msg_callback(mtev_websocket_client_t *client,
                                        mtev_websocket_client_msg_callback msg_callback) {
#ifdef HAVE_WSLAY
  client->msg_callback = msg_callback;
#endif
}

void
mtev_websocket_client_set_cleanup_callback(mtev_websocket_client_t *client,
                                           mtev_websocket_client_cleanup_callback cleanup_callback) {
#ifdef HAVE_WSLAY
  client->cleanup_callback = cleanup_callback;
#endif
}

void *
mtev_websocket_client_get_closure(mtev_websocket_client_t *client) {
#ifdef HAVE_WSLAY
  return client->closure;
#else
  return NULL;
#endif
}

void
mtev_websocket_client_set_closure(mtev_websocket_client_t *client, void *closure) {
#ifdef HAVE_WSLAY
  client->closure = closure;
#else
  return NULL;
#endif
}

mtev_boolean
mtev_websocket_client_is_ready(mtev_websocket_client_t *client) {
#ifdef HAVE_WSLAY
  return client->did_handshake;
#else
  return mtev_false;
#endif
}

// we lock in this function so that we do cannot return "closed" mid-cleanup
mtev_boolean
mtev_websocket_client_is_closed(mtev_websocket_client_t *client) {
#ifdef HAVE_WSLAY
  mtev_boolean rv;
  pthread_mutex_lock(&client->lock);
  rv = client->closed;
  pthread_mutex_unlock(&client->lock);
  return rv;
#else
  return mtev_false;
#endif
}

/* the reason for this function failing can be deduced by calling the above two
 * functions(*_is_ready and *_is_closed) */
mtev_boolean
mtev_websocket_client_send(mtev_websocket_client_t *client, int opcode,
                           void *msg, size_t msg_len) {
#ifdef HAVE_WSLAY
  int rv;
  pthread_mutex_lock(&client->lock);
  if (client->wslay_ctx == NULL) {
    pthread_mutex_unlock(&client->lock);
    return mtev_false;
  }
  struct wslay_event_msg msgarg = {
    opcode, msg, msg_len
  };
  rv = wslay_event_queue_msg(client->wslay_ctx, &msgarg);
  pthread_mutex_unlock(&client->lock);
  return rv ? mtev_false : mtev_true;
#else
  return mtev_false;
#endif
}

/* if we error and want to close our connection we can't actually free the
 * client, but we can do everything up until that point */
#ifdef HAVE_WSLAY
static void
mtev_websocket_client_cleanup(mtev_websocket_client_t *client) {
  int mask; /* value not used, just a dummy for the close() call below */
  pthread_mutex_lock(&client->lock);
  if(!client->closed) {
    eventer_remove_fd(client->e->fd);
    client->e->opset->close(client->e->fd, &mask, client->e);
    eventer_free(client->e);
    if(client->did_handshake)
      wslay_event_context_free(client->wslay_ctx);
    free((void *)client->path);
    free((void *)client->service);
    free((void *)client->host);
    client->closed = mtev_true;
    if(client->cleanup_callback) client->cleanup_callback(client, client->closure);
  }
  pthread_mutex_unlock(&client->lock);
}
#endif

/* consumer must call this, not us. preventing double free's is their
 * responsibility */
void
mtev_websocket_client_free(mtev_websocket_client_t *client) {
#ifdef HAVE_WSLAY
  if(client == NULL) return;
  if(!client->closed) mtev_websocket_client_cleanup(client);
  free(client);
#endif
}
