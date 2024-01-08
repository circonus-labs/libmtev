/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
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

#include "mtev_defines.h"
#include "eventer/eventer.h"
#include "mtev_log.h"
#include "mtev_conf.h"
#include "mtev_net_heartbeat.h"
#include "mtev_rand.h"

#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static mtev_log_stream_t nlerr = NULL;
static mtev_log_stream_t nldeb = NULL;

struct tgt {
  enum { TGT_DIRECT, TGT_BROADCAST, TGT_MULTICAST } type;
  struct sockaddr *addr;
  socklen_t len;
  int ttl;
  eventer_t e; /* only used for multicast */
};
struct mtev_net_heartbeat_context {
  unsigned short port;
  unsigned char key[32];
  int period_ms;
  struct tgt *targets;
  int n_targets;
  eventer_t receiver_v4;
  eventer_t receiver_v6;
  int       sender_v4;
  int       sender_v4_bcast;
  int       sender_v6;
  eventer_t hb_event;

  int (*create_output)(void *buf, int len, void *);
  void *create_output_closure;
  int (*process_input)(void *buf, int len, void *);
  void *process_input_closure;
};

static mtev_net_heartbeat_ctx *global;

static int log_ssl_decrypt_error(const char *s, size_t len, void *p) {
  (void)len;
  char *addr_str = (char *)p;

  mtevL(nlerr, "netheartbeat: received decrypt SSL error on message from IP %s: %s",
    addr_str ? addr_str : "[unknown]", s);

  return 0;
}
static int log_ssl_encrypt_error(const char *s, size_t len, void *p) {
  (void) len;
  (void) p;
  mtevL(nlerr, "netheartbeat: received encrypt SSL error: %s\n", s);
  return 0;
}
static inline void get_ip_addr_from_sockaddr(struct sockaddr *peer_addr,
                                             char *buf,
                                             size_t buflen) {
  switch (peer_addr->sa_family) {
    case AF_INET: {
      struct sockaddr_in *addr = (struct sockaddr_in *)peer_addr;
      inet_ntop(AF_INET, &(addr->sin_addr), buf, buflen);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)peer_addr;
      inet_ntop(AF_INET6, &(addr->sin6_addr), buf, buflen);
      break;
    }
    default: {
      memset(buf, 0, buflen);
      strncpy(buf, "unknown", buflen-1);
      break;
    }
  };
}


/* net_int, 16 byte IV, 16 byte magic */
#define HDR_LENSIZE 4
#define HDR_IVSIZE 16
#define HDR_MAGICSIZE 16
#define HDRLEN (HDR_LENSIZE+HDR_IVSIZE+HDR_MAGICSIZE)
#define HBPKTMAGIC1 0x7eb9a443
#define HBPKTMAGIC2 0x2882edba

static int
mtev_net_heartbeat_handler(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)mask;
  (void)now;
  mtev_net_heartbeat_ctx *ctx = closure;
  unsigned char ivec[16];
  char payload_buff[15000 + HDRLEN];
  void *payload = payload_buff;
  int payload_len = sizeof(payload_buff);
  int fd = eventer_get_fd(e);

  char text_buff[15000 + HDRLEN];
  void *text = text_buff;

  struct iovec iov[3];
  struct msghdr msg = { .msg_iov = iov };

  msg.msg_iov = iov;
  while(true) {
    EVP_CIPHER_CTX *evp_ctx = NULL;
    int len, expected, outlen1, outlen2;
    unsigned int netlen;
    uint32_t *hdr;

    msg.msg_iov[0].iov_len = HDR_LENSIZE;
    msg.msg_iov[0].iov_base = &netlen;
    msg.msg_iov[1].iov_len = HDR_IVSIZE;
    msg.msg_iov[1].iov_base = ivec;
    msg.msg_iovlen = 2;
    len = recvmsg(fd, &msg, MSG_PEEK);
    if(len == -1 && errno == EAGAIN) break;
    if(len < 0) {
      mtevL(nlerr, "netheartbeat: recvmsg error: %s\n", strerror(errno));
      break;
    }
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    recvfrom(fd, NULL, 0, MSG_PEEK, (struct sockaddr *) &peer_addr, &peer_addr_len);

    if(len < (HDR_LENSIZE + HDR_IVSIZE)) {
      /* discard */
      (void) recvmsg(fd, &msg, 0);
      continue;
    }
    len = ntohl(netlen);

    /* Nasty crap to grow buffers if needed */
    if(len > payload_len) {
      mtevL(nldeb, "netheartbeat: growing buffer in %s: old length %d, new length %d\n", __func__,
        payload_len, len);
      void *newpayload, *newtext;
      newpayload = malloc(len - HDR_IVSIZE);
      newtext = malloc(len - HDR_IVSIZE);
      if(!newpayload || !newtext) {
        free(newpayload);
        free(newtext);
        char addr_str[INET6_ADDRSTRLEN];
        get_ip_addr_from_sockaddr((struct sockaddr *)&peer_addr, addr_str, sizeof(addr_str));
        mtevL(nlerr, "netheartbeat: recvmsg error from %s: payload too large %d\n", addr_str, len);
        (void) recvmsg(fd, &msg, 0);
        continue;
      }
      if(payload != payload_buff) free(payload);
      payload = newpayload;
      payload_len = len;
      if(text != text_buff) free(text);
      text = newtext;
    }
    msg.msg_iov[2].iov_len = len - HDR_IVSIZE;
    msg.msg_iov[2].iov_base = payload;
    msg.msg_iovlen = 3;
    expected = msg.msg_iov[0].iov_len +
      msg.msg_iov[1].iov_len +
      msg.msg_iov[2].iov_len;
    len = recvmsg(fd, &msg, 0);
    if(len != expected) {
      char addr_str[INET6_ADDRSTRLEN];
      get_ip_addr_from_sockaddr((struct sockaddr *)&peer_addr, addr_str, sizeof(addr_str));
      mtevL(nlerr, "netheartbeat: bad read from %s: %d != %d\n", addr_str, len, expected);
      continue;
    }

    /* decrypt payload into text */
    len = msg.msg_iov[2].iov_len;
    evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(evp_ctx, EVP_aes_256_cbc(), ctx->key, ivec, false);
    mtevAssert(EVP_CIPHER_CTX_iv_length(evp_ctx) == HDR_IVSIZE);
    if ((!EVP_DecryptUpdate(evp_ctx,text,&outlen1,
                            (unsigned char *)payload,len)) ||
        (!EVP_DecryptFinal(evp_ctx,text+outlen1,&outlen2))) {
      char addr_str[INET6_ADDRSTRLEN];
      get_ip_addr_from_sockaddr((struct sockaddr *)&peer_addr, addr_str, sizeof(addr_str));
      ERR_print_errors_cb(log_ssl_decrypt_error, &addr_str);
      EVP_CIPHER_CTX_free(evp_ctx);
      continue;
    }
    EVP_CIPHER_CTX_free(evp_ctx);
    len = outlen1+outlen2;

    hdr = text;
    if(hdr[2] != htonl(HBPKTMAGIC1) || hdr[3] != htonl(HBPKTMAGIC2)) {
      char addr_str[INET6_ADDRSTRLEN];
      get_ip_addr_from_sockaddr((struct sockaddr *)&peer_addr, addr_str, sizeof(addr_str));
      mtevL(nlerr, "netheartbeat: malformed packet received from %s: expected %04x and %04x, got %04x "
                   "and %04x - len %d\n", addr_str, htonl(HBPKTMAGIC1), htonl(HBPKTMAGIC2), hdr[2], hdr[3],
                   len);
      continue;
    }
    if(ctx->process_input) {
      ctx->process_input(text + HDR_MAGICSIZE, len - HDR_MAGICSIZE,
                         ctx->process_input_closure);
    }
  }
  if(payload != payload_buff) free(payload);
  if(text != text_buff) free(text);
  return EVENTER_READ|EVENTER_EXCEPTION;
}

static int
mtev_net_headerbeat_sendall(mtev_net_heartbeat_ctx *ctx, void *payload, int payload_len) {
  int rv = 0;
  int i;
  for(i=0;i<ctx->n_targets;i++) {
    int fd = -1;
    struct tgt *tgt = &ctx->targets[i];
    switch(tgt->type) {
      case TGT_BROADCAST: 
        fd = ctx->sender_v4_bcast;
        mtevL(nldeb, "netheartbeat: sending %d byte payload (type TGT_BROADCAST) to fd %d\n", payload_len, fd);
        break;
      case TGT_MULTICAST:
        fd = eventer_get_fd(tgt->e);
        mtevL(nldeb, "netheartbeat: sending %d byte payload (type TGT_MULTICAST) to fd %d\n", payload_len, fd);
        break;
      case TGT_DIRECT:
        if(tgt->addr->sa_family == AF_INET) {
          fd = ctx->sender_v4;
          if (N_L_S_ON(nldeb)) {
            char addr_buf[INET_ADDRSTRLEN];
            struct sockaddr_in *addr_in = (struct sockaddr_in *)tgt->addr;
            inet_ntop(AF_INET, &(addr_in->sin_addr), addr_buf, INET_ADDRSTRLEN);
            mtevL(nldeb, "netheartbeat: sending %d byte payload (type TGT_DIRECT, ipv4) to fd %d (addr %s)\n", payload_len, fd, addr_buf);
          }
        }
        else if (tgt->addr->sa_family == AF_INET6) {
          fd = ctx->sender_v6;
          if (N_L_S_ON(nldeb)) {
            char addr_buf[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)tgt->addr;
            inet_ntop(AF_INET6, &(addr_in->sin6_addr), addr_buf, INET6_ADDRSTRLEN);
            mtevL(nldeb, "netheartbeat: sending %d byte payload (type TGT_DIRECT, ipv6) to fd %d (addr %s)\n", payload_len, fd, addr_buf);
          }
        }
        break;
    }
    if(fd >= 0) {
      int sent = sendto(fd, payload, payload_len, 0,
                 tgt->addr, tgt->len);
      if (sent != payload_len) {
        rv = -1;
        mtevL(nlerr, "netheartbeat: Bad send on mtev_net_heartbeat: sent bytes (%d) != payload_len (%d)\n", sent, payload_len);
      }
      else {
        mtevL(nldeb, "netheartbeat: successfully sent %d byte payload to fd %d\n", payload_len, fd);
      }
    }
  }
  return rv;
}

static int
mtev_net_heartbeat_serialize_and_send(mtev_net_heartbeat_ctx *ctx) {
  int i, len, blocksize, ivecsize, outlen1, outlen2, text_len;
  EVP_CIPHER_CTX *evp_ctx = NULL;
  unsigned char cipher_buf_static[16000];
  unsigned char *ivec, *cipher_buf = cipher_buf_static, *text;
  int *hdr;
  char buf[15000 + HDRLEN], *payload = buf;
  int cipher_buf_len = sizeof(cipher_buf_static);

  if(!ctx->create_output) return -1;
  len = ctx->create_output(payload + HDRLEN, sizeof(buf) - HDRLEN, ctx->create_output_closure);
  if(len < 0) {
    int needed = -len + HDRLEN;
    payload = malloc(needed);
    len = ctx->create_output(payload + HDRLEN, needed - HDRLEN, ctx->create_output_closure);
  }
  if(len < 0) goto bail;

  len += HDRLEN;
  i = 0;
  hdr = (int *)payload;
  hdr[i++] = htonl((unsigned int)(len - HDR_LENSIZE));

  /* 4 bytes of IV */
  ivec = (unsigned char *)payload + HDR_LENSIZE;
  hdr[i++] = mtev_rand();
  hdr[i++] = mtev_rand();
  hdr[i++] = mtev_rand();
  hdr[i++] = mtev_rand();
  /* 2 words of gibberish */
  hdr[i++] = mtev_rand();
  hdr[i++] = mtev_rand();
  /* 2 words of magic */
  hdr[i++] = htonl(HBPKTMAGIC1);
  hdr[i++] = htonl(HBPKTMAGIC2);
  mtevAssert(i==9);

  evp_ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit(evp_ctx, EVP_aes_256_cbc(), ctx->key, ivec, true);
  blocksize = EVP_CIPHER_CTX_block_size(evp_ctx);
  ivecsize = EVP_CIPHER_CTX_iv_length(evp_ctx);
  mtevAssert(ivecsize == HDR_IVSIZE);
  if(len + blocksize*2 > cipher_buf_len) {
    if(cipher_buf != cipher_buf_static) free(cipher_buf);
    cipher_buf = malloc(len + blocksize * 2);
    if(!cipher_buf) {
      mtevL(nlerr, "netheartbeat: malloc(%d) failure\n", len + blocksize * 2);
      goto bail;
    }
  }

  memcpy(cipher_buf, payload, HDRLEN);
  text = (unsigned char *)payload + HDR_LENSIZE + HDR_IVSIZE;
  text_len = len - (HDR_LENSIZE + HDR_IVSIZE);
  if ((!EVP_EncryptUpdate(evp_ctx,cipher_buf+HDR_LENSIZE+HDR_IVSIZE,&outlen1,
                          text,text_len)) ||
      (!EVP_EncryptFinal(evp_ctx,cipher_buf+HDR_LENSIZE+HDR_IVSIZE+outlen1,
                          &outlen2))) {
    ERR_print_errors_cb(log_ssl_encrypt_error, NULL);
  }
  EVP_CIPHER_CTX_free(evp_ctx);
  len = HDR_LENSIZE + HDR_IVSIZE + outlen1 + outlen2;

  /* Adjust the packet length */
  *((int *)cipher_buf) = htonl((unsigned int)(len - HDR_LENSIZE));
  mtev_net_headerbeat_sendall(ctx, cipher_buf, len);

 bail:
  if(cipher_buf != cipher_buf_static) free(cipher_buf);
  if(payload != buf) free(payload);
  return 0;
}

static void
mtev_net_heartbeat_pulse_namer(char *buf, int buflen, eventer_t e, void *closure) {
  (void)closure;
  mtev_net_heartbeat_ctx *ctx = eventer_get_closure(e);
  snprintf(buf, buflen, "mtev_net_heartbeat_pulse(:%d)", ctx->port);
}
static int
mtev_net_heartbeat_pulse(eventer_t e, int mask, void *closure, struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  mtev_net_heartbeat_ctx *ctx = closure;
  mtev_net_heartbeat_serialize_and_send(ctx);
  ctx->hb_event = eventer_add_in_s_us(mtev_net_heartbeat_pulse, ctx,
                      ctx->period_ms/1000,
                      (ctx->period_ms%1000)*1000);
  return 0;
}
void
mtev_net_heartbeat_context_start(mtev_net_heartbeat_ctx *ctx) {
  ctx->hb_event = eventer_add_in_s_us(mtev_net_heartbeat_pulse, ctx, 0, 0);
}

static void
drop_e(eventer_t e) {
  int mask;
  eventer_t tofree;
  if(!e) return;
  tofree = eventer_remove(e);
  eventer_close(e, &mask);
  if(tofree) eventer_free(tofree);
}

void
mtev_net_heartbeat_destroy(mtev_net_heartbeat_ctx *ctx) {
  int i;
  drop_e(ctx->receiver_v4);
  drop_e(ctx->receiver_v6);
  if(ctx->hb_event) {
    eventer_remove(ctx->hb_event);
    eventer_free(ctx->hb_event);
  }
  for(i=0;i<ctx->n_targets;i++)
    drop_e(ctx->targets[i].e);
  if(ctx->sender_v4_bcast >= 0)
    close(ctx->sender_v4_bcast);
  free(ctx->targets);
  free(ctx);
}

void
mtev_net_heartbeat_set_out(mtev_net_heartbeat_ctx *ctx,
                           int (*f)(void *buf, int buflen, void *),
                           void *closure) {
  ctx->create_output = f;
  ctx->create_output_closure = closure;
}
void
mtev_net_heartbeat_set_in(mtev_net_heartbeat_ctx *ctx,
                          int (*f)(void *buf, int buflen, void *),
                          void *closure) {
  ctx->process_input = f;
  ctx->process_input_closure = closure;
}
mtev_net_heartbeat_ctx *
mtev_net_heartbeat_context_create(unsigned short port,
                                  unsigned char key[32],
                                  int period_ms) {
  int fd, on=1;
  mtev_net_heartbeat_ctx *ctx;
  struct sockaddr_in addr4;
  //struct sockaddr_in6 addr6;

  ctx = calloc(1, sizeof(*ctx));
  memcpy(ctx->key, key, 32);
  ctx->period_ms = period_ms;
  ctx->port = port;

  /* sockets sockets sockets */
  addr4.sin_family = AF_INET;
  addr4.sin_addr.s_addr = htonl(INADDR_ANY);
  addr4.sin_port = htons(port);
  if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) >= 0) {
    if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0  ||
        bind(fd,(struct sockaddr *)&addr4,sizeof(addr4)) < 0 ||
        eventer_set_fd_nonblocking(fd)) {
      close(fd);
      fd = -1;
    }
  }
  if (fd >= 0) {
    ctx->receiver_v4 = eventer_alloc_fd(mtev_net_heartbeat_handler, ctx, fd,
                                        EVENTER_READ|EVENTER_EXCEPTION);
    eventer_add(ctx->receiver_v4);
  }
  ctx->sender_v4 = fd; /* yes, can be -1 if broken */
  
  if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) >= 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (void *)&on, sizeof(on)) < 0 ||
        eventer_set_fd_nonblocking(fd)) {
      close(fd);
      fd = -1;
    }
  }
  ctx->sender_v4_bcast = fd;

  /* addr6.sin6_family = AF_INET6; */
  /* addr6.sin6_addr = in6addr_any; */
  /* addr6.sin6_port = htons(port); */
  if ((fd = socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP)) >= 0) {
    if(eventer_set_fd_nonblocking(fd)) {
      close(fd);
      fd = -1;
    }
  }
  if (fd >= 0) {
    ctx->receiver_v6 = eventer_alloc_fd(mtev_net_heartbeat_handler, ctx, fd,
                                        EVENTER_READ|EVENTER_EXCEPTION);
    eventer_add(ctx->receiver_v6);
  }
  ctx->sender_v6 = fd;
  return ctx;
}

static struct tgt *
mtev_net_heartbeat_add_untyped(mtev_net_heartbeat_ctx *ctx,
                               struct sockaddr *addr, socklen_t len) {
  struct tgt *tgt;
  ctx->n_targets++;
  if(ctx->n_targets == 1) ctx->targets = calloc(1, sizeof(struct tgt));
  else ctx->targets = realloc(ctx->targets, (ctx->n_targets * sizeof(struct tgt)));
  tgt = &ctx->targets[ctx->n_targets-1];
  memset(tgt, 0, sizeof(*tgt));
  tgt->addr = malloc(len);
  memcpy(tgt->addr, addr, len);
  tgt->len = len;
  return tgt;
}
int
mtev_net_heartbeat_add_target(mtev_net_heartbeat_ctx *ctx,
                              struct sockaddr *addr, socklen_t len) {
  struct tgt *tgt;
  tgt = mtev_net_heartbeat_add_untyped(ctx, addr, len);
  tgt->type = TGT_DIRECT;
  return 0;
}

int
mtev_net_heartbeat_add_broadcast(mtev_net_heartbeat_ctx *ctx,
                                 struct sockaddr *addr, socklen_t len) {
  struct tgt *tgt;

  tgt = mtev_net_heartbeat_add_untyped(ctx, addr, len);
  tgt->type = TGT_BROADCAST;
  return 0;
}

int
mtev_net_heartbeat_add_multicast(mtev_net_heartbeat_ctx *ctx,
                                 struct sockaddr *addr, socklen_t len,
                                 unsigned char ttl) {
  int fd;
  struct tgt *tgt;
  struct ip_mreq mreq;
  struct sockaddr_in maddr, *addr4;
  long on = 1;

  if(addr->sa_family != AF_INET) return -1;
  addr4 = (struct sockaddr_in *)addr;
  if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) return -1;
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0) {
    close(fd);
    return -1;
  }
  maddr.sin_family=AF_INET;
  maddr.sin_addr.s_addr=htonl(INADDR_ANY);
  maddr.sin_port=addr4->sin_port;
  if (bind(fd,(struct sockaddr *)&maddr,sizeof(maddr)) < 0) {
    close(fd);
    return -1;
  }
  mreq.imr_multiaddr.s_addr=addr4->sin_addr.s_addr;
  mreq.imr_interface.s_addr=htonl(INADDR_ANY);
  if (setsockopt(fd,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0) {
    close(fd);
    return -1;
  }
  if (setsockopt(fd,IPPROTO_IP,IP_MULTICAST_TTL,(void *)&ttl,sizeof(ttl)) < 0) {
    close(fd);
    return -1;
  }

  if (eventer_set_fd_nonblocking(fd)) {
    close(fd);
    return -1;
  }
  tgt = mtev_net_heartbeat_add_untyped(ctx, addr, len);
  tgt->type = TGT_MULTICAST;
  tgt->ttl = ttl;

  tgt->e = eventer_alloc_fd(mtev_net_heartbeat_handler, ctx, fd,
                            EVENTER_READ|EVENTER_EXCEPTION);
  eventer_add(tgt->e);
  return 0;
}

mtev_net_heartbeat_ctx *
mtev_net_heartbeat_from_conf(const char *basepath) {
  mtev_net_heartbeat_ctx *ctx = NULL;
  int i, cnt;
  int32_t period = 200, port = 0;
  char *keyhex;
  unsigned char key[32] = { 0 };
  mtev_conf_section_t section, *notes;
  section = mtev_conf_get_section_read(MTEV_CONF_ROOT, basepath);
  if(mtev_conf_section_is_empty(section)) goto out;
  if(!mtev_conf_get_string(section, "self::node()/@key", &keyhex)) {
    mtevL(nlerr, "netheartbeat section found, but no key attribute!\n");
    goto out;
  }
  if(strlen(keyhex) != 64) {
    mtevL(nlerr, "netheartbeat key must be 32 bytes (64 hex)!\n");
    free(keyhex);
    goto out;
  }
  for(i=0;i<64;i++) {
    int v = 0;
    if(keyhex[i] >= '0' && keyhex[i] <= '9') v = keyhex[i] - '0';
    else if(keyhex[i] >= 'a' && keyhex[i] <= 'f') v = keyhex[i] - 'a' + 10;
    else if(keyhex[i] >= 'A' && keyhex[i] <= 'F') v = keyhex[i] - 'A' + 10;
    else {
      mtevL(nlerr, "netheartbeat key must be hexidecimal!\n");
      free(keyhex);
      goto out;
    }
    key[i/2] = (key[i/2] << 4) | v;
  }
  free(keyhex);

  (void)mtev_conf_get_int32(section, "self::node()/@port", &port);
  if(port == 0) {
    mtevL(nlerr, "netheartbeat section found, but no port attribute!\n");
    goto out;
  }
  (void)mtev_conf_get_int32(section, "self::node()/@period", &period);

  ctx = mtev_net_heartbeat_context_create(port, key, period);
  
  notes = mtev_conf_get_sections_read(section, "self::node()//notify", &cnt);
  for(i=0;i<cnt;i++) {
    char addr_str[INET6_ADDRSTRLEN];
    int32_t port = 0, ttl = 1;
    int rv;
    char type_str[32];
    int8_t family;
    union {
      struct in_addr addr4;
      struct in6_addr addr6;
    } a;
    struct sockaddr *in;
    socklen_t in_len;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;

    (void)mtev_conf_get_int32(notes[i], "self::node()/@ttl", &ttl);
    (void)mtev_conf_get_int32(notes[i], "self::node()/@port", &port);
    if(port <= 0 || port > 0xffff) {
      mtevL(nlerr, "netheartbeat bad port %d in notify\n", port);
      continue;
    }
    if(!mtev_conf_get_stringbuf(notes[i], "self::node()/@address", addr_str, sizeof(addr_str))) {
      mtevL(nlerr, "netheartbeat no address in notify\n");
      continue;
    }
    if(!mtev_conf_get_stringbuf(notes[i], "self::node()/@type", type_str, sizeof(type_str))) {
      strlcpy(type_str, "direct", sizeof(type_str));
    }

    family = AF_INET;
    rv = inet_pton(family, addr_str, &a);
    if(rv != 1) {
      family = AF_INET6;
      rv = inet_pton(family, addr_str, &a);
    }
    if(rv != 1) {
      mtevL(nlerr, "netheartbeat bad address: %s\n", addr_str);
      continue;
    }
    if(family == AF_INET) {
      in4.sin_family = family;
      in4.sin_addr = a.addr4;
      in4.sin_port = htons(port);
      in = (struct sockaddr *)&in4;
      in_len = sizeof(in4);
    }
    else if(family == AF_INET6) {
      in6.sin6_family = family;
      in6.sin6_addr = a.addr6;
      in6.sin6_port = htons(port);
      in = (struct sockaddr *)&in6;
      in_len = sizeof(in6);
    }
    else {
      mtevL(nlerr, "netheartbeat bad address family: %d\n", family);
      continue;
    }
    if(!strcmp(type_str, "direct")) {
      if(mtev_net_heartbeat_add_target(ctx, in, in_len)) {
        mtevL(nlerr, "netheartbeat error adding: %s:%d\n", addr_str, port);
      }
    }
    else if(!strcmp(type_str, "broadcast")) {
      if(mtev_net_heartbeat_add_broadcast(ctx, in, in_len)) {
        mtevL(nlerr, "netheartbeat error adding: %s:%d\n", addr_str, port);
      }
    }
    else if(!strcmp(type_str, "multicast")) {
      if(mtev_net_heartbeat_add_multicast(ctx, in, in_len, ttl)) {
        mtevL(nlerr, "netheartbeat error adding: %s:%d\n", addr_str, port);
      }
    }
    else {
      mtevL(nlerr, "netbroadcast notify type unknown: %s\n", type_str);
    }
  }
  mtev_conf_release_sections_read(notes, cnt);

  mtev_net_heartbeat_context_start(ctx);
 out:
  mtev_conf_release_section_read(section);
  return ctx;
}

void
mtev_net_heartbeat_init(void) {
  static int inited = 0;
  if(inited) return;

  inited = 1;
  nlerr = mtev_log_stream_find("error/netheartbeat");
  nldeb = mtev_log_stream_find("debug/netheartbeat");
  eventer_name_callback_ext("mtev_net_heartbeat_pulse",
                            mtev_net_heartbeat_pulse,
                            mtev_net_heartbeat_pulse_namer, NULL);
  eventer_name_callback("mtev_net_heartbeat_handler",
                        mtev_net_heartbeat_handler);
  mtev_rand_init();
  global = mtev_net_heartbeat_from_conf("/*/netheartbeat");
}
