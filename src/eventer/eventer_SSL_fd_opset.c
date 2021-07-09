/*
 * Copyright (c) 2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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
#include "eventer/eventer_impl_private.h"
#include "mtev_log.h"
#include "eventer/eventer_SSL_fd_opset.h"
#include "eventer/eventer_aco_opset.h"
#include "eventer/OETS_asn1_helper.h"
#include "libmtev_dtrace.h"

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdatomic.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/dh.h>

#define _OPENSSL_VERSION_1_1_0 0x10100000L
#define _OPENSSL_VERSION_1_0_2 0x10002000L
#define _OPENSSL_VERSION_1_0_1 0x10001000L

#define EVENTER_SSL_DATANAME "eventer_ssl"
#define DEFAULT_OPTS_STRING "all"
#ifndef SSL_TXT_SSLV2
#define DEFAULT_LAYER_STRING "tlsv1:all,!sslv3"
#else
#define DEFAULT_LAYER_STRING "tlsv1:all,!sslv2,!sslv3"
#endif
/* ERR_error_string(3): buf must be at least 120 bytes... */
#define MIN_ERRSTR_LEN 120

static mtev_log_stream_t ssldb;

#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_0_2
#include "pre-rfc5114-dh1024.h"
#include "pre-rfc5114-dh2048.h"
#endif

#define MAX_DHPARAMS 8
static struct dhparams_t {
  int bits;
  const char *file;
  DH *params;
  DH *(*builtin)();
} dhparams[MAX_DHPARAMS] = {
#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2
  { .bits = 2048, .builtin = DH_get_2048_224 },
#else
  { .bits = 2048, .builtin = get_dh2048 },
#endif
};
static int ndhparams = 1;


static const char *
internal_SSL_error(int err, char *scratch, int len) {
  switch(err) {
#ifdef SSL_ERROR_NONE
    case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
#endif
#ifdef SSL_ERROR_SSL
    case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
#endif
#ifdef SSL_ERROR_WANT_READ
    case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
#endif
#ifdef SSL_ERROR_WANT_WRITE
    case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
#endif
#ifdef SSL_ERROR_WANT_X509_LOOKUP
    case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
#endif
#ifdef SSL_ERROR_SYSCALL
    case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
#endif
#ifdef SSL_ERROR_ZERO_RETURN
    case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
#endif
#ifdef SSL_ERROR_WANT_CONNECT
    case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
#endif
#ifdef SSL_ERROR_WANT_ACCEPT
    case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
#endif
#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC: return "SSL_ERROR_WANT_ASYNC";
#endif
#ifdef SSL_ERROR_WANT_ASYNC_JOB
    case SSL_ERROR_WANT_ASYNC_JOB: return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
#endif
    default:
      if(scratch) snprintf(scratch, len, "%d", err);
      break;
  }
  return scratch ? scratch : "unknown";
}

#define SSL_CTX_KEYLEN (PATH_MAX * 4 + 5)
struct cache_finfo {
  ino_t ino;
  time_t mtime;
};

typedef struct {
  char *key;
  SSL_CTX *internal_ssl_ctx;
  time_t creation_time;
  time_t last_stat_time;
  unsigned crl_loaded:1;
  struct cache_finfo cert_finfo;
  struct cache_finfo key_finfo;
  struct cache_finfo ca_finfo;
  uint32_t refcnt;
} ssl_ctx_cache_node;

static mtev_hash_table alpn_funcs;
static mtev_hash_table ssl_ctx_cache;
static pthread_mutex_t ssl_ctx_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static int ssl_ctx_cache_expiry = 5;
static int ssl_ctx_cache_finfo_expiry = 5;

struct eventer_ssl_ctx_t {
  ssl_ctx_cache_node *ssl_ctx_cn;
  SSL     *ssl;
  char    *issuer;
  char    *subject;
  time_t   start_time;
  time_t   end_time;
  char    *cert_error;
  char    *san_list;
  char    *last_error;
  char    *sni_name;
  eventer_ssl_verify_func_t verify_cb;
  void    *verify_cb_closure;
  unsigned no_more_negotiations:1;
  unsigned renegotiated:1;
  uint8_t *npn;
  mtev_hash_table *alpn_funcs;
};

#define ssl_ctx ssl_ctx_cn->internal_ssl_ctx
#define ssl_ctx_crl_loaded ssl_ctx_cn->crl_loaded

/* Static function prototypes */
static void SSL_set_eventer_ssl_ctx(SSL *ssl, eventer_ssl_ctx_t *ctx);
static eventer_ssl_ctx_t *SSL_get_eventer_ssl_ctx(const SSL *ssl);
static void
_eventer_ssl_ctx_save_last_error(eventer_ssl_ctx_t *ctx, int note_errno,
                                const char *file, int line);

#define eventer_ssl_ctx_save_last_error(a,b) \
  _eventer_ssl_ctx_save_last_error((a),(b),__FILE__,__LINE__)
#define MAX_ERR_UNWIND 10

static void
populate_finfo(struct cache_finfo *f, const char *path) {
  struct stat sb;
  memset(&sb, 0, sizeof(sb));
  if(path) while(stat(path, &sb) == -1 && errno == EINTR);
  f->ino = sb.st_ino;
  f->mtime = sb.st_mtime;
}
static int
validate_finfo(const struct cache_finfo *f, const char *path) {
  struct stat sb;
  memset(&sb, 0, sizeof(sb));
  if(path) while(stat(path, &sb) == -1 && errno == EINTR);
  if(f->ino == sb.st_ino && f->mtime == sb.st_mtime) return 0;
  return -1;
}

static void
_eventer_ssl_ctx_save_last_error(eventer_ssl_ctx_t *ctx, int note_errno,
                                const char *file, int line) {
  /* ERR_error_string(3): buf must be at least 120 bytes...
   * no strerrno is more than 100 bytes...
   * file:line:code is never more than 80.
   * So, no line will be longer than 200.
   */
  int used, i = 0, allocd = 0;
  unsigned long err = 0, errors[MAX_ERR_UNWIND] = { 0 };
  char errstr[MIN_ERRSTR_LEN + 100 + 80], scratch[MIN_ERRSTR_LEN + 80];
  errstr[0] = '\0';
  if(note_errno && errno)
    snprintf(errstr, sizeof(errstr), "[%d] %s, ", errno, strerror(errno));
  /* Unwind all, storing up to MAX_ERR_UNWIND */
  while((err = ERR_get_error()) != 0) {
    if(i < MAX_ERR_UNWIND) errors[i] = err;
    i++;
  }
  used = (i > MAX_ERR_UNWIND) ? MAX_ERR_UNWIND : i;

  if(ctx->last_error) {
    free(ctx->last_error);
    ctx->last_error = NULL;
  }
  allocd = 300 * (((errstr[0] == '\0') ? 0 : 1) + used);
  if(allocd == 0) return;
  ctx->last_error = malloc(allocd);
  ctx->last_error[0] = '\0';
  if(errstr[0] != '\0')
    strlcat(ctx->last_error, errstr, allocd);
  for(i=0;i<used;i++) {
    ERR_error_string(errors[i], scratch);
    snprintf(errstr, sizeof(errstr), "%s[%s], ",
             ctx->last_error[0] ? "\n -> " : "", scratch);
    strlcat(ctx->last_error, errstr, allocd);
  }
  /* now clip off the last ", " */
  i = strlen(ctx->last_error);
  if(i>=2) ctx->last_error[i-2] = '\0';
  mtev_log(ssldb, NULL, file, line, "ssl error: %s\n", ctx->last_error);
}

static DH *
load_dh_params(const char *filename, long bits) {
  (void)bits;
  BIO *bio;
  DH *dh = NULL;
  if(filename == NULL) return NULL;
  bio = BIO_new_file(filename, "r");
  if(bio == NULL) return NULL;
  mtevL(ssldb, "Loading DH parameters from %s.\n", filename);
  PEM_read_bio_DHparams(bio, &dh, 0, NULL);
  BIO_free(bio);
  if(dh) {
    int code = 0;
    if(DH_check(dh, &code) != 1 || code != 0) {
      mtevL(eventer_err, "DH Parameter in %s is bad [%x], not using.\n",
            filename, code);
      DH_free(dh);
      dh = NULL;
    }
#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_1_0
    const BIGNUM *p, *q, *g;
    int foundbits = 0;
    DH_get0_pqg(dh, &p, &q, &g);
    if(!p || (foundbits = BN_num_bits(p)) != bits) {
      mtevL(eventer_err, "DH Parameter in %s has %d bits, not using.\n",
            filename, foundbits);
      DH_free(dh);
      dh = NULL;
    }
#endif
  }
  return dh;
}
static void
save_dh_params(DH *p, const char *filename) {
  int fd;
  BIO *bio;
  if(p == NULL || filename == NULL) return;
  fd = open(filename, O_CREAT|O_TRUNC|O_RDWR, 0600);
  if(fd < 0) return;
  bio = BIO_new_fd(fd, 0);
  if(bio == NULL) { close(fd); return; }
  mtevL(mtev_notice, "Saving DH parameters to %s.\n", filename);
  PEM_write_bio_DHparams(bio,p);
  BIO_free(bio);
  fchmod(fd, 0400);
  close(fd);
  return;
}

static int
generate_dh_params(eventer_t e, int mask, void *cl, struct timeval *now) {
  (void)e;
  (void)now;
  struct stat sb;
  char errstr[MIN_ERRSTR_LEN];
  unsigned int err;
  int rv;
  if(mask != EVENTER_ASYNCH_WORK) return 0;
  ERR_clear_error();
  struct dhparams_t *tgt = (struct dhparams_t *)cl;

  ERR_clear_error();
  if(tgt->file) {
    memset(&sb, 0, sizeof(sb));
    if(!tgt->params) {
      while((rv = stat(tgt->file, &sb)) == -1 && errno == EINTR);
      if(rv == 0 || errno != ENOENT) {
        tgt->params = load_dh_params(tgt->file, tgt->bits);
      }
    }
    if(!tgt->params) {
      mtevL(mtev_notice, "Generating %d bit DH parameters.\n", tgt->bits);
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
      tgt->params = DH_generate_parameters(tgt->bits, 2, NULL, NULL);
      if(!tgt->params) {
        while(0 != (err = ERR_get_error())) {
          mtevL(eventer_err, " -> %s\n", ERR_error_string(err, errstr));
        }
      }
#else
      int problems = 0;
      DH *dh_tmp_trans = DH_new();
      DH_generate_parameters_ex(dh_tmp_trans, tgt->bits, 2, NULL);
      if(DH_check(dh_tmp_trans, &problems) == 1 && problems == 0) {
        tgt->params = dh_tmp_trans;
      } else {
        while(0 != (err = ERR_get_error())) {
          mtevL(eventer_err, " -> %s\n", ERR_error_string(err, errstr));
        }
        DH_free(dh_tmp_trans);
      }
#endif
      if(tgt->params) {
        save_dh_params(tgt->params, tgt->file);
        mtevL(mtev_notice, "Finished generating %d bit DH parameters.\n", tgt->bits);
      } else {
        mtevL(mtev_notice, "Failed generating %d bit DH parameters.\n", tgt->bits);
      }
    }
  }
  else if(tgt->builtin) {
    tgt->params = tgt->builtin();
    if(tgt->params) {
      mtevL(ssldb, "Using builtin %d bit DH parameters.\n", tgt->bits);
    }
    else {
      mtevL(mtev_notice, "Failed using builtin %d bit DH parameters.\n", tgt->bits);
    }
  }
  return 0;
}

static int
eventer_ssl_verify_dates(eventer_ssl_ctx_t *ctx, int ok,
                         X509_STORE_CTX *x509ctx, void *closure) {
  (void)ok;
  (void)closure;
  time_t now;
  int err;
  X509 *peer;
  ASN1_TIME *t;
  if(!x509ctx) return X509_V_ERR_APPLICATION_VERIFICATION;
  peer = X509_STORE_CTX_get_current_cert(x509ctx);
  time(&now);
  t = X509_get_notBefore(peer);
  ctx->start_time = OETS_ASN1_TIME_get(t, &err);
  if(X509_cmp_time(t, &now) > 0) return X509_V_ERR_CERT_NOT_YET_VALID;
  t = X509_get_notAfter(peer);
  ctx->end_time = OETS_ASN1_TIME_get(t, &err);
  if(X509_cmp_time(t, &now) < 0) return X509_V_ERR_CERT_HAS_EXPIRED;
  return 0;
}

X509 *
eventer_ssl_get_peer_certificate(eventer_ssl_ctx_t *ctx) {
  X509 *peer = SSL_get_peer_certificate(ctx->ssl);
  return peer;
}

SSL_SESSION *
eventer_ssl_get_session(eventer_ssl_ctx_t *ctx) {
  return SSL_get_session(ctx->ssl);
}

int
eventer_ssl_get_san_values(eventer_ssl_ctx_t *ctx,
                        X509_STORE_CTX *x509ctx) {
  STACK_OF(GENERAL_NAME) * altnames;
  X509 *peer;
  int pos = 0;

  if(!x509ctx) return 0;
  peer = X509_STORE_CTX_get_current_cert(x509ctx);
  altnames = X509_get_ext_d2i(peer, NID_subject_alt_name, NULL, NULL);
  if (altnames) {
    int i;
    int numalts = sk_GENERAL_NAME_num(altnames);
    char cn[4096];
    mtev_boolean written = mtev_false;

    memset(cn, 0, 4096);
    for (i = 0; i < numalts; i++) {
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);
      if (check->type != GEN_DNS) {
        continue;
      }
      ASN1_STRING *data = check->d.dNSName;
      if (written) {
        /* Leave space for comma, space, data, and null byte */
        if (data->length + pos > (int)sizeof(cn) - 3) {
          continue;
        }
        cn[pos] = ',';
        cn[pos+1] = ' ';
        pos+=2;
      }
      else {
        /* Leave space for data and null byte */
        if (data->length + pos > (int)sizeof(cn) - 1) {
          continue;
        }
        written = mtev_true;
      }
      memcpy(cn+pos, data->data, data->length);
      cn[data->length+pos] = '\0';
      pos = strlen(cn);
    }
    if (pos > 0) {
      if (ctx->san_list != NULL) {
        free(ctx->san_list);
      }
      ctx->san_list = strdup(cn);
    }
    sk_GENERAL_NAME_pop_free(altnames, GENERAL_NAME_free);
  }
  return 1;
}
int
eventer_ssl_verify_cert(eventer_ssl_ctx_t *ctx, int ok,
                        X509_STORE_CTX *x509ctx, void *closure) {
  mtev_hash_table *options = closure;
  const char *opt_no_ca, *ignore_dates;
  int v_res = 0;

  /* Clear any previous error */
  if(ctx->cert_error) free(ctx->cert_error);
  ctx->cert_error = NULL;

  if(!x509ctx) {
    int err;
    if((err = SSL_get_verify_result(ctx->ssl)) != X509_V_OK) {
      X509 *peer;
      peer = SSL_get_peer_certificate(ctx->ssl);
      mtevL(ssldb, "SSL post-accept reverification failure%s\n", peer ? "" : ": no peer");
      if(peer) {
        ctx->cert_error = strdup(X509_verify_cert_error_string(err));
        X509_free(peer);
        ok = 0;
        goto set_out;
      }
    }
    ctx->cert_error = strdup("No certificate store present.");
    ok = 0;
    goto set_out;
  }

  if(!mtev_hash_retr_str(options, "optional_no_ca", strlen("optional_no_ca"),
                         &opt_no_ca))
    opt_no_ca = "false";
  if(!mtev_hash_retr_str(options, "ignore_dates", strlen("ignore_dates"),
                         &ignore_dates))
    ignore_dates = "false";
  if(options == NULL) {
    /* Don't care about anything */
    opt_no_ca = "true";
    ignore_dates = "true";
  }
  eventer_ssl_get_san_values(ctx, x509ctx);
  v_res = X509_STORE_CTX_get_error(x509ctx);

  if((v_res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||
     (v_res == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||
     (v_res == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||
     (v_res == X509_V_ERR_CERT_UNTRUSTED) ||
     (v_res == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)) {
    if(!strcmp(opt_no_ca, "true")) ok = 1;
    else {
      mtevL(ssldb, "SSL client cert invalid: %s\n",
            X509_verify_cert_error_string(v_res));
      ctx->cert_error = strdup(X509_verify_cert_error_string(v_res));
      ok = 0;
      goto set_out;
    }
  }
  v_res = eventer_ssl_verify_dates(ctx, ok, x509ctx, closure);
  if(v_res != 0) {
    if(!strcmp(ignore_dates, "true")) ok = 1;
    else {
      mtevL(ssldb, "SSL client cert is %s valid.\n",
            (v_res < 0) ? "not yet" : "no longer");
      ctx->cert_error = strdup((v_res < 0) ?
                               "Certificate not yet valid." :
                               "Certificate expired.");
      ok = 0;
      goto set_out;
    }
  }
 set_out:
  if(ok) SSL_set_verify_result(ctx->ssl, X509_V_OK);
  else if(v_res != 0) SSL_set_verify_result(ctx->ssl, v_res);
  return ok;
}

#define GET_SET_X509_NAME(type) \
static void \
eventer_ssl_set_peer_##type(eventer_ssl_ctx_t *ctx, \
                             X509_STORE_CTX *x509ctx) { \
  char buffer[1024]; \
  X509 *peer; \
  peer = X509_STORE_CTX_get_current_cert(x509ctx); \
  X509_NAME_oneline(X509_get_##type##_name(peer), buffer, sizeof(buffer)-1); \
  buffer[sizeof(buffer)-1] = '\0'; \
  if(ctx->type) free(ctx->type); \
  ctx->type = strdup(buffer); \
} \
const char * \
eventer_ssl_get_peer_##type(eventer_ssl_ctx_t *ctx) { \
  if(ctx->type == NULL) { \
    char buffer[1024]; \
    X509 *peer = SSL_get_peer_certificate(ctx->ssl); \
    if(peer != NULL) { \
      X509_NAME_oneline(X509_get_##type##_name(peer), buffer, sizeof(buffer)-1); \
      buffer[sizeof(buffer)-1] = '\0'; \
      if(ctx->type) free(ctx->type); \
      ctx->type = strdup(buffer); \
    } \
  } \
  return ctx->type; \
}

GET_SET_X509_NAME(issuer)
GET_SET_X509_NAME(subject)

time_t
eventer_ssl_get_peer_start_time(eventer_ssl_ctx_t *ctx) {
  return ctx->start_time;
}
time_t
eventer_ssl_get_peer_end_time(eventer_ssl_ctx_t *ctx) {
  return ctx->end_time;
}
const char *
eventer_ssl_get_peer_error(eventer_ssl_ctx_t *ctx) {
  return ctx->cert_error;
}
const char *
eventer_ssl_get_last_error(eventer_ssl_ctx_t *ctx) {
  return ctx->last_error;
}
const char *
eventer_ssl_get_peer_san_list(eventer_ssl_ctx_t *ctx) {
  return ctx->san_list;
}
const char *
eventer_ssl_get_sni_name(eventer_ssl_ctx_t *ctx) {
  return ctx->sni_name;
}
const char *
eventer_ssl_get_cipher_list(eventer_ssl_ctx_t *ctx, int prio) {
  return SSL_get_cipher_list(ctx->ssl, prio);
}
const char *
eventer_ssl_get_current_cipher(eventer_ssl_ctx_t *ctx) {
  return SSL_get_cipher_name(ctx->ssl);
}
int
eventer_ssl_get_method(eventer_ssl_ctx_t *ctx) {
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
  return SSL_get_ssl_method(ctx->ssl)->version;
#else
  return SSL_get_min_proto_version(ctx->ssl);
#endif
}
int
eventer_ssl_get_local_commonname(eventer_ssl_ctx_t *ctx, char *buff, int len) {
  char *out = NULL;
  X509_NAME *name;
  X509 *cert = SSL_get_certificate(ctx->ssl);
  if(cert == NULL) return -1;
  name = X509_get_subject_name(cert);
  if(name) {
    int pos;
    if(-1 != (pos = X509_NAME_get_index_by_NID(name, NID_commonName, -1))) {
      X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, pos);
      if(entry) {
        ASN1_STRING *entryData = X509_NAME_ENTRY_get_data( entry );
        unsigned char *utf8;
        int length = ASN1_STRING_to_UTF8( &utf8, entryData );
        strlcpy(buff, (const char *)utf8, MIN(length+1,len));
        out = buff;
        OPENSSL_free( utf8 );
      }
    }
  }
  X509_free(cert);
  if(out) return strlen(out);
  return -1;
}

static int
verify_cb(int ok, X509_STORE_CTX *x509ctx) {
  char buf[256], issuer[256], errstr[1024];
  X509 *err_cert;
  int err, depth;
  eventer_ssl_ctx_t *ctx;
  SSL *ssl;

  err_cert = X509_STORE_CTX_get_current_cert(x509ctx);
  err = X509_STORE_CTX_get_error(x509ctx);
  depth = X509_STORE_CTX_get_error_depth(x509ctx);
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, sizeof(buf));

  /* Fetch the handle and containing context and fill in some blanks */
  ssl = X509_STORE_CTX_get_ex_data(x509ctx,
                                   SSL_get_ex_data_X509_STORE_CTX_idx());
  if(!ssl) return 0;
  ctx = SSL_get_eventer_ssl_ctx(ssl);
  if(!ctx) return 0;
  eventer_ssl_set_peer_subject(ctx, x509ctx);
  eventer_ssl_set_peer_issuer(ctx, x509ctx);

  if(!ok) {
    issuer[0] = '\0';
    if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
      X509 *curr_cert = NULL;
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
      curr_cert = x509ctx->current_cert;
#else
      curr_cert = X509_STORE_CTX_get_current_cert(x509ctx);
#endif
      X509_NAME_oneline(X509_get_issuer_name(curr_cert), issuer+1, sizeof(issuer)-1);
      issuer[0] = ':';
    }
    snprintf(errstr, sizeof(errstr), "verify error:num=%d:%s:depth=%d%s:%s\n", err,
             X509_verify_cert_error_string(err), depth, issuer, buf);
    if(ctx->cert_error) free(ctx->cert_error);
    ctx->cert_error = strdup(errstr);
  }

  if(ctx->verify_cb)
    return ctx->verify_cb(ctx, ok, x509ctx, ctx->verify_cb_closure);
  return ok;
}

/*
 * Helpers to create and destroy our context.
 */
static void
ssl_ctx_cache_node_free(ssl_ctx_cache_node *node) {
  bool zero;
  if(!node) return;
  ck_pr_dec_32_zero(&node->refcnt, &zero);
  if(zero) {
    mtevL(ssldb, "ssl_ctx_cache_node_free(%p -> 0) freeing\n", node);
    SSL_CTX_free(node->internal_ssl_ctx);
    free(node->key);
    free(node);
  }
  else {
    mtevL(ssldb, "ssl_ctx_cache_node_free(%p -> %u)\n", node, ck_pr_load_32(&node->refcnt));
  }
}

void
eventer_ssl_ctx_free(eventer_ssl_ctx_t *ctx) {
  if(ctx->ssl) {
    SSL_set_eventer_ssl_ctx(ctx->ssl, NULL); // in case it has more references
    SSL_free(ctx->ssl);
  }
  if(ctx->npn) free(ctx->npn);
  if(ctx->ssl_ctx_cn) ssl_ctx_cache_node_free(ctx->ssl_ctx_cn);
  if(ctx->alpn_funcs) {
    mtev_hash_destroy(ctx->alpn_funcs, free, NULL);
    free(ctx->alpn_funcs);
  }
  if(ctx->issuer) free(ctx->issuer);
  if(ctx->subject) free(ctx->subject);
  if(ctx->cert_error) free(ctx->cert_error);
  if(ctx->last_error) free(ctx->last_error);
  if(ctx->san_list) free(ctx->san_list);
  if(ctx->sni_name) free(ctx->sni_name);
  free(ctx);
}

#if defined(SSL3_ST_SR_CLNT_HELLO_A)
static void
eventer_SSL_server_info_callback(const SSL *ssl, int type, int val) {
  (void)type;
  (void)val;
  eventer_ssl_ctx_t *ctx;

  if(!ssl) return;

  if (ssl->state != SSL3_ST_SR_CLNT_HELLO_A &&
      ssl->state != SSL23_ST_SR_CLNT_HELLO_A)
    return;

  ctx = SSL_get_eventer_ssl_ctx(ssl);
  if(ctx && ctx->no_more_negotiations) {
    mtevL(ssldb, "eventer_SSL_server_info_callback ... reneg is bad\n");
    ctx->renegotiated = 1;
  }
}
#endif

static void
ssl_ctx_key_write(char *b, int blen, eventer_ssl_orientation_t type,
                  const char *layer, const char **parts) {
  unsigned char sig[SHA256_DIGEST_LENGTH];
  char hexsig[SHA256_DIGEST_LENGTH*2+1];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  int i=0;
  for(const char *part = parts[i]; part; part = parts[++i]) {
    if(part) SHA256_Update(&ctx, part, strlen(part));
  }
  SHA256_Final(sig, &ctx);
  static const char *hexdigits = "0123456789abcdef";
  for(int i=0; i<SHA256_DIGEST_LENGTH; i++) {
    hexsig[i*2] = hexdigits[sig[i] >> 4];
    hexsig[i*2+1] = hexdigits[sig[i] & 0xf];
  }
  hexsig[SHA256_DIGEST_LENGTH*2] = '\0';
  snprintf(b, blen, "%c:%s:%s",
           (type == SSL_SERVER) ? 'S' : 'C', layer ? layer : "", hexsig);
}

static void
ssl_ctx_cache_remove(const char *key) {
  mtevL(ssldb, "ssl_ctx_cache->remove(%s)\n", key);
  pthread_mutex_lock(&ssl_ctx_cache_lock);
  mtev_hash_delete(&ssl_ctx_cache, key, strlen(key),
                   NULL, (void (*)(void *))ssl_ctx_cache_node_free);
  pthread_mutex_unlock(&ssl_ctx_cache_lock);
}

static ssl_ctx_cache_node *
ssl_ctx_cache_get(const char *key) {
  void *vnode;
  ssl_ctx_cache_node *node = NULL;
  pthread_mutex_lock(&ssl_ctx_cache_lock);
  if(mtev_hash_retrieve(&ssl_ctx_cache, key, strlen(key), &vnode)) {
    node = vnode;
    ck_pr_inc_32(&node->refcnt);
  }
  pthread_mutex_unlock(&ssl_ctx_cache_lock);
  if(node) mtevL(ssldb, "ssl_ctx_cache->get(%p -> %u)\n", node, ck_pr_load_32(&node->refcnt));
  return node;
}

static ssl_ctx_cache_node *
ssl_ctx_cache_set(ssl_ctx_cache_node *node) {
  void *vnode;
  pthread_mutex_lock(&ssl_ctx_cache_lock);
  if(mtev_hash_retrieve(&ssl_ctx_cache, node->key, strlen(node->key),
                        &vnode)) {
    node = vnode;
  }
  else {
    mtev_hash_store(&ssl_ctx_cache, node->key, strlen(node->key), node);
  }
  ck_pr_inc_32(&node->refcnt);
  pthread_mutex_unlock(&ssl_ctx_cache_lock);
  mtevL(ssldb, "ssl_ctx_cache->set(%p -> %u)\n", node, ck_pr_load_32(&node->refcnt));
  return node;
}

static
int eventer_ssl_ctx_get_sni(SSL *ssl, int *ad, void *arg) {
  (void)ad;
  (void)arg;
  if(!ssl) return SSL_TLSEXT_ERR_OK;
  eventer_ssl_ctx_t *ctx = SSL_get_eventer_ssl_ctx(ssl);
  if(!ctx) return SSL_TLSEXT_ERR_OK;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if(name) {
    free(ctx->sni_name);
    ctx->sni_name = strdup(name);
  }
  return SSL_TLSEXT_ERR_OK;
}

eventer_ssl_ctx_t *
eventer_ssl_ctx_new(eventer_ssl_orientation_t type,
                    const char *layer,
                    const char *certificate, const char *key,
                    const char *ca_chain, const char *ciphers) {
  mtev_hash_table settings;
  mtev_hash_init(&settings);
  mtev_hash_store(&settings, "layer", strlen("layer"), layer);
  mtev_hash_store(&settings, "certificate", strlen("certificate"), certificate);
  mtev_hash_store(&settings, "key", strlen("key"), key);
  mtev_hash_store(&settings, "ca_chain", strlen("ca_chain"), ca_chain);
  mtev_hash_store(&settings, "ciphers", strlen("ciphers"), ciphers);
  eventer_ssl_ctx_t *ctx = eventer_ssl_ctx_new_ex(type, &settings);
  mtev_hash_destroy(&settings,NULL,NULL);
  return ctx;
}

eventer_ssl_ctx_t *
eventer_ssl_ctx_new_ex(eventer_ssl_orientation_t type,
                       mtev_hash_table *settings) {
  const char *layer = mtev_hash_dict_get(settings, "layer");
  const char *certificate = mtev_hash_dict_get(settings, "certificate");
  if(!certificate) certificate = mtev_hash_dict_get(settings, "certificate_file");
  const char *key = mtev_hash_dict_get(settings, "key");
  if(!key) key = mtev_hash_dict_get(settings, "key_file");
  const char *ca = mtev_hash_dict_get(settings, "ca_chain");
  if(!ca) mtev_hash_dict_get(settings, "ca_file");
  const char *ciphers = mtev_hash_dict_get(settings, "ciphers");
  const char *ca_accept = mtev_hash_dict_get(settings, "ca_accept");
  if(!ca_accept) ca_accept = ca;
  const char *crl = mtev_hash_dict_get(settings, "crl");
  const char *npn = mtev_hash_dict_get(settings, "alpn");
  if(!npn) npn = mtev_hash_dict_get(settings, "npn");
  if(!npn) npn="h2,http/1.1";

  char ssl_ctx_key[SSL_CTX_KEYLEN];
  eventer_ssl_ctx_t *ctx;
  const char *layer_str;
  char *opts, ctx_layer[256], opts_buf[256];
  char *opts_fallback = DEFAULT_OPTS_STRING;
  time_t now;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) return NULL;

  layer_str = layer ? layer : DEFAULT_LAYER_STRING;
  strlcpy(ctx_layer, layer_str, sizeof(ctx_layer));
  opts = strchr(ctx_layer,':');
  if(opts) *opts++ = '\0';
  else {
    strlcpy(opts_buf, opts_fallback, sizeof(opts_buf));
    opts = opts_buf;
  }

  const char *certificate_file = (certificate && NULL == strchr(certificate, '\n')) ? certificate : NULL;
  const char *key_file = (key && NULL == strchr(key, '\n')) ? key : NULL;
  const char *ca_file = (ca && NULL == strchr(ca, '\n')) ? ca : NULL;
  const char *ca_accept_file = (ca_accept && NULL == strchr(ca_accept, '\n')) ? ca_accept : NULL;

  now = time(NULL);
  ssl_ctx_key_write(ssl_ctx_key, sizeof(ssl_ctx_key), type, layer,
                    (const char *[]){ certificate, key, ca, ca_accept, ciphers, npn, crl, NULL });
  ctx->ssl_ctx_cn = ssl_ctx_cache_get(ssl_ctx_key);
  if(ctx->ssl_ctx_cn) {
    if(now - ctx->ssl_ctx_cn->creation_time > ssl_ctx_cache_expiry ||
       (now - ctx->ssl_ctx_cn->last_stat_time > ssl_ctx_cache_finfo_expiry &&
           (validate_finfo(&ctx->ssl_ctx_cn->cert_finfo, certificate_file) ||
            validate_finfo(&ctx->ssl_ctx_cn->key_finfo, key_file) ||
            validate_finfo(&ctx->ssl_ctx_cn->ca_finfo, ca_file) || 
            (ctx->ssl_ctx_cn->last_stat_time = now) == 0))) { /* assignment */
      ssl_ctx_cache_remove(ssl_ctx_key);
      ssl_ctx_cache_node_free(ctx->ssl_ctx_cn);
      ctx->ssl_ctx_cn = NULL;
    }
  }

  if(!ctx->ssl_ctx_cn) {
    char *part = NULL, *brkt = NULL;
    long ctx_options = 0;
    ssl_ctx_cache_node *existing_ctx_cn;
    ctx->ssl_ctx_cn = calloc(1, sizeof(*ctx->ssl_ctx_cn));
    ctx->ssl_ctx_cn->key = strdup(ssl_ctx_key);
    ctx->ssl_ctx_cn->refcnt = 1;
    ctx->ssl_ctx_cn->creation_time = now;
    ctx->ssl_ctx_cn->last_stat_time = now;
    populate_finfo(&ctx->ssl_ctx_cn->cert_finfo, certificate_file);
    populate_finfo(&ctx->ssl_ctx_cn->key_finfo, key_file);
    populate_finfo(&ctx->ssl_ctx_cn->ca_finfo, ca_file);
    ctx->ssl_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
    if(0)
      ;
#if defined(SSL_TXT_SSLV3) && defined(HAVE_SSLV3_SERVER) && defined(HAVE_SSLV3_CLIENT)
    else if(layer && !strcasecmp(layer, SSL_TXT_SSLV3))
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 SSLv3_server_method()
                                 : SSLv3_client_method());
#endif
#if defined(SSL_TXT_SSLV2) && defined(HAVE_SSLV2_SERVER) && defined(HAVE_SSLV2_CLIENT)
    else if(layer && !strcasecmp(layer, SSL_TXT_SSLV2))
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 SSLv2_server_method() : SSLv2_client_method());
#endif
#if defined(SSL_TXT_TLSV1) && defined(HAVE_TLSV1_SERVER) && defined(HAVE_TLSV1_CLIENT)
    else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1))
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 TLSv1_server_method() : TLSv1_client_method());
#endif
#if defined(SSL_TXT_TLSV1_1) && defined(HAVE_TLSV1_1_SERVER) && defined(HAVE_TLSV1_1_CLIENT)
    else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1_1))
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 TLSv1_1_server_method() : TLSv1_1_client_method());
#endif
#if defined(SSL_TXT_TLSV1_2) && defined(HAVE_TLSV1_2_SERVER) && defined(HAVE_TLSV1_2_CLIENT)
    else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1_2))
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 TLSv1_2_server_method() : TLSv1_2_client_method());
#endif
#else
    /* openssl 1.1 and higher */
  ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ? TLS_server_method() : TLS_client_method());
  if(layer && !strcasecmp(layer, SSL_TXT_SSLV3)) {
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, SSL3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, SSL3_VERSION);
  }
  else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1)) {
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_VERSION);
  }
  else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1_1)) {
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_1_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_1_VERSION);
  }
  else if(layer && !strcasecmp(layer, SSL_TXT_TLSV1_2)) {
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_2_VERSION);
  }
#if defined(TLS1_3_VERSION)
  else if(layer && !strcasecmp(layer, "TLSv1.3")) {
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
  }
#endif
#endif

    if(ctx->ssl_ctx == NULL)
      ctx->ssl_ctx = SSL_CTX_new(type == SSL_SERVER ?
                                 SSLv23_server_method() : SSLv23_client_method());
    if(!ctx->ssl_ctx) {
      mtevL(eventer_err, "Could not create SSL_CTX\n");
      goto bail;
    }

    for(part = strtok_r(opts, ",", &brkt);
        part;
        part = strtok_r(NULL, ",", &brkt)) {
      char *optname = part;
      int neg = 0;
      if(*optname == '!') neg = 1, optname++;

#define SETBITOPT(name, neg, opt) \
  if(!strcasecmp(optname, name)) { \
    if(neg) ctx_options &= ~(opt); \
    else    ctx_options |= (opt); \
  }

      SETBITOPT("all", neg, SSL_OP_ALL)
#ifdef SSL_TXT_SSLV2
      else SETBITOPT(SSL_TXT_SSLV2, !neg, SSL_OP_NO_SSLv2)
#endif
#ifdef SSL_TXT_SSLV3
      else SETBITOPT(SSL_TXT_SSLV3, !neg, SSL_OP_NO_SSLv3)
#endif
#ifdef SSL_TXT_TLSV1
      else SETBITOPT(SSL_TXT_TLSV1, !neg, SSL_OP_NO_TLSv1)
#endif
#ifdef SSL_TXT_TLSV1_1
      else SETBITOPT(SSL_TXT_TLSV1_1, !neg, SSL_OP_NO_TLSv1_1)
#endif
#ifdef SSL_TXT_TLSV1_2
      else SETBITOPT(SSL_TXT_TLSV1_2, !neg, SSL_OP_NO_TLSv1_2)
#endif
#ifdef SSL_OP_NO_TLSv1_3
      else SETBITOPT("TLSv1.3", !neg, SSL_OP_NO_TLSv1_3)
#endif
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
      else SETBITOPT("cipher_server_preference", neg, SSL_OP_CIPHER_SERVER_PREFERENCE)
#endif
      else {
        mtevL(neg ? eventer_deb : eventer_err, "SSL layer part '%s' not understood.\n", optname);
      }
    }

    if (type == SSL_SERVER) {
      SSL_CTX_set_tlsext_servername_callback(ctx->ssl_ctx, eventer_ssl_ctx_get_sni);
      SSL_CTX_set_session_id_context(ctx->ssl_ctx,
              (unsigned char *)EVENTER_SSL_DATANAME,
              sizeof(EVENTER_SSL_DATANAME)-1);
    }
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#endif
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
#endif
#ifdef SSL_OP_NO_COMPRESSION
    ctx_options |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_NO_TICKET
    ctx_options |= SSL_OP_NO_TICKET;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
    ctx_options |= SSL_OP_SINGLE_DH_USE;
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
    ctx_options |= SSL_OP_SINGLE_ECDH_USE;
#endif
    SSL_CTX_set_options(ctx->ssl_ctx, ctx_options);
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    if(certificate) {
      if(certificate_file) {
        if(SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, certificate_file) != 1) {
          mtevL(eventer_err, "Failed to read TLS certificate chain from %s\n", certificate_file);
          goto bail;
        }
        mtevL(ssldb, "Loaded certificate from file: %s\n", certificate_file);
      } else {
        /* certificate is PEM x509 */
        int certno = 1;
        const char *cptr = certificate;
        BIO *bio = NULL;
        ERR_clear_error();
        bio = BIO_new_mem_buf((void *)cptr, -1);
        BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
        X509 *crt = NULL;
        crt = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if(!crt ||
            SSL_CTX_use_certificate(ctx->ssl_ctx, crt) != 1 ||
            ERR_peek_error() != 0) {
          if(crt) X509_free(crt);
          BIO_free(bio);
          mtevL(eventer_err, "Failed to read TLS certificate [#%d] from memory\n", certno);
          goto bail;
        }
        X509_free(crt);

#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_0_2 && OPENSSL_VERSION_NUMER >= _OPENSSL_VERSION_1_0_1
        if(SSL_CTX_clear_extra_chain_certs(ctx->ssl_ctx) == 0) {
#elif OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2
        if(SSL_CTX_clear_chain_certs(ctx->ssl_ctx) == 0) {
#else
        if(0) {
#endif
          mtevL(eventer_err, "Failed to initialize TLS certificate chain\n");
          BIO_free(bio);
          goto bail;
        }
        certno++;
        while(NULL != (crt = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_0_2
          if(!SSL_CTX_add_extra_chain_cert(ctx->ssl_ctx, crt)) {
#else
          if(!SSL_CTX_add0_chain_cert(ctx->ssl_ctx, crt)) {
#endif
            X509_free(crt);
            BIO_free(bio);
            mtevL(eventer_err, "Failed to add to TLS certificate [#%d] to chain\n", certno);
            goto bail;
          }
          certno++;
        }
        BIO_free(bio);
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
          ERR_clear_error();
        if(ERR_peek_last_error()) {
          mtevL(eventer_err, "Error loading TLS certificate [#%d] into chain\n", certno);
          goto bail;
        }
        mtevL(ssldb, "Loaded certificate and %d chained certs from memory\n", certno-2);
      }
    }
    if(key) {
      if(key_file) {
        if(SSL_CTX_use_RSAPrivateKey_file(ctx->ssl_ctx, key_file,
                                          SSL_FILETYPE_PEM) != 1) {
          mtevL(eventer_err, "Failed to read TLS key from %s\n", key_file);
          goto bail;
        }
        mtevL(ssldb, "Loaded private key from file: %s\n", key_file);
      } else {
        /* key is a PEM key, pust read it */
        BIO *bio = BIO_new_mem_buf((void *)key, -1);
        BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
        EVP_PKEY *pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if(!pk) {
          mtevL(eventer_err, "Failed to read TLS key from memory\n");
          goto bail;
        }
        if(SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pk) != 1) {
          mtevL(eventer_err, "Failed to use TLS key from memory\n");
          EVP_PKEY_free(pk);
          goto bail;
        }
        EVP_PKEY_free(pk);
        mtevL(ssldb, "Loaded private key from memmory\n");
      }
    }
    if(ca) {
      if(ca_file) {
        if(!SSL_CTX_load_verify_locations(ctx->ssl_ctx,ca_file,NULL)) {
          mtevL(eventer_err, "Failed to load CA file: %s\n", ca_file);
          goto bail;
        }
        mtevL(ssldb, "Loaded CA file: %s\n", ca_accept_file);
      }
      else {
        int ncerts = 0;
        BIO *bio = NULL;
        ERR_clear_error();
        bio = BIO_new_mem_buf((void *)ca, -1);
        BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
        X509 *crt = NULL;
        X509_STORE *vfy = X509_STORE_new();
        while(NULL != (crt = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
          if(X509_check_ca(crt)) {
            X509_STORE_add_cert(vfy, crt);
          }
          X509_free(crt);
          ncerts++;
        }
        BIO_free(bio);
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
          ERR_clear_error();
        if(ERR_peek_last_error()) {
          mtevL(eventer_err, "Error loading TLS certificate [#%d] into ca chain\n", ncerts);
          goto bail;
        }
        mtevL(ssldb, "Loaded %d certs into ca chain\n", ncerts);
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_0_2
        SSL_CTX_set_cert_store(ctx->ssl_ctx, vfy);
#else
        SSL_CTX_set0_verify_cert_store(ctx->ssl_ctx, vfy);
#endif
      }
    }
    if(type == SSL_SERVER && ca_accept && ca_accept[0]) { /* blank means no advertisements */
      STACK_OF(X509_NAME) *cert_stack = NULL;
      if(ca_accept_file) {
        if((cert_stack = SSL_load_client_CA_file(ca_accept_file)) == NULL) {
          mtevL(eventer_err, "Failed to load CA client accept file: %s\n", ca_accept_file);
          goto bail;
        }
        mtevL(ssldb, "Loaded %d certs in CA client accept file: %s\n", sk_X509_NAME_num(cert_stack), ca_accept_file);
      }
      else {
        int ncerts = 0;
        BIO *bio = NULL;
        ERR_clear_error();
        bio = BIO_new_mem_buf((void *)ca_accept, -1);
        BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);
        X509 *crt = NULL;
        while(NULL != (crt = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL))) {
          X509_NAME *name = X509_get_subject_name(crt);
          if(cert_stack == NULL) cert_stack = sk_X509_NAME_new_null();
          sk_X509_NAME_push(cert_stack, name);
          ncerts++;
        }
        BIO_free(bio);
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
          ERR_clear_error();
        if(ERR_peek_last_error()) {
          mtevL(eventer_err, "Error loading TLS certificate [#%d] into ca chain\n", ncerts);
          goto bail;
        }
        mtevL(ssldb, "Loaded %d certs into client accept list\n", ncerts);
      }
      SSL_CTX_set_client_CA_list(ctx->ssl_ctx, cert_stack);
    }
    if(crl) eventer_ssl_use_crl(ctx, crl);
    SSL_CTX_set_cipher_list(ctx->ssl_ctx, ciphers ? ciphers : "DEFAULT");
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, verify_cb);
#ifndef OPENSSL_NO_EC
#if defined(SSL_CTX_set_ecdh_auto)
    SSL_CTX_set_ecdh_auto(ctx->ssl_ctx, 1);
#elif defined(NID_X9_62_prime256v1)
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx->ssl_ctx, ec_key);
    EC_KEY_free(ec_key);
#endif
#endif
    const char *dh_bits = mtev_hash_dict_get(settings, "dhparam_bits");
    int dh_bits_demand = dhparams[0].bits;
    if(dh_bits) dh_bits_demand = atoi(dh_bits);
    mtev_boolean dh_set = mtev_false;
    for(int i=0; i<ndhparams; i++) {
      if(dhparams[i].params && dhparams[i].bits == dh_bits_demand) {
        dh_set = mtev_true;
        SSL_CTX_set_tmp_dh(ctx->ssl_ctx, dhparams[i].params);
        break;
      }
    }
    if(dh_bits && dh_bits_demand && !dh_set) {
      mtevL(eventer_err, "Could not set %d bit dh params on SSL context\n", dh_bits_demand);
      goto bail;
    }

    if(strcasecmp(npn, "none")) {
      eventer_ssl_alpn_advertise(ctx, npn);
    }

    existing_ctx_cn = ssl_ctx_cache_set(ctx->ssl_ctx_cn);
    if(existing_ctx_cn != ctx->ssl_ctx_cn) {
      ssl_ctx_cache_node_free(ctx->ssl_ctx_cn);
      ctx->ssl_ctx_cn = existing_ctx_cn;
    }
  }

  ctx->ssl = SSL_new(ctx->ssl_ctx);
  if(!ctx->ssl) {
    mtevL(eventer_err, "Could not create SSL context\n");
    goto bail;
  }
#ifdef SSL3_ST_SR_CLNT_HELLO_A
  SSL_set_info_callback(ctx->ssl, eventer_SSL_server_info_callback);
#endif
  SSL_set_eventer_ssl_ctx(ctx->ssl, ctx);
  return ctx;

 bail:
  eventer_ssl_ctx_save_last_error(ctx, 1);
  mtevL(eventer_err, "SSL context creation failed: %s\n",
        ctx->last_error ? ctx->last_error : "unknown cause");
  eventer_ssl_ctx_free(ctx);
  return NULL;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int next_proto_cb(SSL *ssl, const unsigned char **data,
                         unsigned int *len, void *arg) {
  (void)arg;
  if(!ssl) return SSL_TLSEXT_ERR_NOACK;
  eventer_ssl_ctx_t *ctx = SSL_get_eventer_ssl_ctx(ssl);
  if(!ctx) return SSL_TLSEXT_ERR_NOACK;
  if(!ctx->npn) return SSL_TLSEXT_ERR_NOACK;

  *data = ctx->npn;
  *len = (unsigned int)(1 + *ctx->npn);
  return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2

static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)arg;
  if(!ssl) return SSL_TLSEXT_ERR_NOACK;
  eventer_ssl_ctx_t *ctx = SSL_get_eventer_ssl_ctx(ssl);
  if(!ctx) return SSL_TLSEXT_ERR_NOACK;
  if(!ctx->npn) return SSL_TLSEXT_ERR_NOACK;

  eventer_SSL_alpn_func_t f = NULL;
  void *vf = NULL;
  for (unsigned int i = 0; i < inlen; i += (unsigned int)(in[i] + 1)) {
    if((ctx->alpn_funcs && mtev_hash_retrieve(ctx->alpn_funcs, in+i+1, in[i], &vf)) ||
       mtev_hash_retrieve(&alpn_funcs, in+i+1, in[i], &vf)) {
      f = vf;
    }
    if(f) {
      int rv = f(out, outlen, in, inlen);
      mtevL(ssldb, "alpn <- (%u:%u) %.*s -> %d\n", inlen, i, (int)in[i], in+i+1, rv);
      if (rv < 0) return SSL_TLSEXT_ERR_NOACK;
      if (rv == 1) return SSL_TLSEXT_ERR_OK;
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}
#endif

static int
eventer_alpn_select_always(const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen) {
  (void)inlen;
  *out = in+1;
  *outlen = in[0];
  return 1;
}

void
eventer_ssl_alpn_register(const char *name, eventer_SSL_alpn_func_t f) {
  if(f == NULL) f = eventer_alpn_select_always;
  mtev_hash_replace(&alpn_funcs, strdup(name), strlen(name), f, free, NULL);
}

void
eventer_ssl_ctx_alpn_register(eventer_ssl_ctx_t *ctx, const char *name, eventer_SSL_alpn_func_t f) {
  if(f == NULL) f = eventer_alpn_select_always;
  if(!ctx->alpn_funcs) {
    mtev_hash_table *t = calloc(1, sizeof(*t));
    mtev_hash_init_locks(t, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
    if(!ck_pr_cas_ptr(&ctx->alpn_funcs, NULL, t)) {
      mtev_hash_destroy(t, free, NULL);
      free(t);
    }
  }
  mtev_hash_replace(ctx->alpn_funcs, strdup(name), strlen(name), f, free, NULL);
}

int
eventer_ssl_alpn_advertise(eventer_ssl_ctx_t *ctx, const char *npn) {
  eventer_SSL_alpn_func_t f = NULL;
  unsigned int off = 0;
  char *newnpn = NULL;
  if(npn) {
    int npnlen = strlen(npn);
    newnpn = malloc(1+npnlen+1);
    char *copy = strdup(npn);
    char *brkt = NULL, *part;
    for(part = strtok_r(copy, ",", &brkt); part;
        part = strtok_r(NULL, ",", &brkt)) {
      void *vf = NULL;
      mtevL(ssldb, "ALPN checking %s\n", part);
      if((ctx->alpn_funcs && mtev_hash_retrieve(ctx->alpn_funcs, part, strlen(part), &vf)) ||
         mtev_hash_retrieve(&alpn_funcs, part, strlen(part), &vf)) {
        f = vf;
        unsigned int partlen = strlen(part);
        if(f && off + partlen + 1 < 0xff) {
          newnpn[off] = partlen;
          memcpy(newnpn+off+1, part, partlen);
          off += partlen+1;
        }
      }
    }
    free(copy);
  }
  if(off > 0) {
    ctx->npn = (unsigned char *)newnpn;
    newnpn = NULL;
#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_CTX_set_next_protos_advertised_cb(ctx->ssl_ctx, next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2
    SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, alpn_select_proto_cb, f);
#endif
  }
  else {
    free(ctx->npn);
    ctx->npn = NULL;
  }
  free(newnpn);
  return 0;
}

void
eventer_ssl_get_alpn_selected(eventer_ssl_ctx_t *ctx, const uint8_t **alpn, uint8_t *len) {
  if(!ctx || !ctx->ssl) return;
  (void)alpn;
  unsigned int ilen = 0;
#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(ctx->ssl, alpn, &ilen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2
  if (*alpn == NULL) {
    SSL_get0_alpn_selected(ctx->ssl, alpn, &ilen);
  }
#endif
  *len = ilen;
}

int
eventer_ssl_use_crl(eventer_ssl_ctx_t *ctx, const char *crl_file) {
  int ret;
  X509_STORE *store;
  X509_LOOKUP *lookup;
  if(ctx->ssl_ctx_crl_loaded) return 1;
  store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
  lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  ret = X509_load_crl_file(lookup, crl_file, X509_FILETYPE_PEM); 
  X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
                              X509_V_FLAG_CRL_CHECK_ALL);
  if(!ret) eventer_ssl_ctx_save_last_error(ctx, 1);
  else ctx->ssl_ctx_crl_loaded = 1;
  return ret;
}

/*
 * This is a set of helpers to tie the SSL stuff to the eventer_t.
 */
inline static int
init_data_id(void) {
  static atomic_int ssl_ctx_data_id = -1;
  int data_id = atomic_load_explicit(&ssl_ctx_data_id, memory_order_consume);

  if (data_id == -1) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mutex);
    data_id = atomic_load_explicit(&ssl_ctx_data_id, memory_order_acquire);

    if (data_id == -1) {
      data_id = SSL_get_ex_new_index(0, EVENTER_SSL_DATANAME, NULL, NULL, NULL);
      atomic_store_explicit(&ssl_ctx_data_id, data_id, memory_order_release);
    }

    pthread_mutex_unlock(&mutex);
  }

  return data_id;
}

static void
SSL_set_eventer_ssl_ctx(SSL *ssl, eventer_ssl_ctx_t *ctx) {
  SSL_set_ex_data(ssl, init_data_id(), ctx);
}

static eventer_ssl_ctx_t *
SSL_get_eventer_ssl_ctx(const SSL *ssl) {
  eventer_ssl_ctx_t *ctx = SSL_get_ex_data(ssl, init_data_id());
  return ctx;
}

eventer_ssl_ctx_t *
eventer_get_eventer_ssl_ctx(const eventer_t e) {
  /* This is a hacky layering violation, but there's only one so don't generalize yet. */
  if((e->opset == eventer_aco_fd_opset && eventer_aco_get_opset(e) != eventer_SSL_fd_opset) ||
     e->opset != eventer_SSL_fd_opset) {
    return NULL;
  }
  return e->opset->get_opset_ctx(e);
}

void
eventer_set_eventer_ssl_ctx(eventer_t e, eventer_ssl_ctx_t *ctx) {
  e->opset->set_opset(e, eventer_SSL_fd_opset);
  e->opset->set_opset_ctx(e, ctx);
  SSL_set_fd(ctx->ssl, e->fd);
}

void
eventer_ssl_ctx_set_sni(eventer_ssl_ctx_t *ctx, const char *snivalue) {
#ifdef SSL_CTRL_SET_TLSEXT_SERVERNAME_CB
  SSL_set_tlsext_host_name(ctx->ssl, snivalue);
#endif
}

void
eventer_ssl_ctx_set_verify(eventer_ssl_ctx_t *ctx,
                           eventer_ssl_verify_func_t f, void *c) {
  ctx->verify_cb = f;
  ctx->verify_cb_closure = c;
}

/* Accept will perform the usual BSD socket accept and then
 * hand it into the SSL system.
 */
static int
_noallowed_eventer_SSL_accept(int fd, struct sockaddr *addr, socklen_t *len,
                              int *mask, void *closure) {
  (void)fd;
  (void)addr;
  (void)len;
  (void)mask;
  (void)closure;
  return -1;
}

static void
eventer_SSL_set_opset(void *closure, struct _fd_opset *v) {
  eventer_t e = closure;
  e->opset= v;
}

static void *
eventer_SSL_get_opset_ctx(void *closure) {
  eventer_t e = closure;
  return e->opset_ctx;
}

static void
eventer_SSL_set_opset_ctx(void *closure, void *v) {
  eventer_t e = closure;
  e->opset_ctx = v;
}

static int 
eventer_SSL_setup(eventer_ssl_ctx_t *ctx) {
  X509 *peer = NULL;
  SSL_set_mode(ctx->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  peer = SSL_get_peer_certificate(ctx->ssl);

  /* If have no peer, or the peer cert isn't okay, our
   * callback won't fire, so fire it explicitly here.
   * Learnt this from mod_ssl.
   */
  if(!peer) {
    if(!peer) mtevL(ssldb, "eventer_SSL_setup without peer certificate!\n");
    if(ctx->verify_cb) {
      return ctx->verify_cb(ctx, 0, NULL, ctx->verify_cb_closure);
    }
  }
  if(peer) X509_free(peer);
  return 0;
}

/* The read and write operations for ssl are almost identical.
 * We read or write, depending on the need and if the SSL subsystem
 * says we need more data to continue we mask for read, if it says
 * we need need to write data to continue we mask for write.  Either
 * way, we EAGAIN.
 * If there is an SSL error, we spit it out and return EIO as that
 * seems most appropriate.
 */
static int
eventer_SSL_rw(int op, int fd, void *buffer, size_t len, int *mask,
               void *closure) {
  int rv, sslerror;
  eventer_t e = closure;
  eventer_ssl_ctx_t *ctx = e->opset->get_opset_ctx(e);
  int (*sslop)(SSL *) = NULL;
  const char *opstr = NULL;

  ERR_clear_error();
  switch(op) {
    case SSL_OP_READ:
      opstr = "read";
      if((rv = SSL_read(ctx->ssl, buffer, len)) > 0) return rv;
      break;
    case SSL_OP_WRITE:
      opstr = "write";
      if((rv = SSL_write(ctx->ssl, buffer, len)) > 0) return rv;
      break;

    case SSL_OP_CONNECT:
      opstr = "connect";
      if(!sslop) sslop = SSL_connect;
      /* fall through */
    case SSL_OP_ACCEPT:
      if(!opstr) opstr = "accept";
      /* only set if we didn't fall through */
      if(!sslop) sslop = SSL_accept;

      if((rv = sslop(ctx->ssl)) > 0) {
        if(eventer_SSL_setup(ctx)) {
          errno = EIO;
          eventer_ssl_ctx_save_last_error(ctx, 1);
          return -1;
        }
        ctx->no_more_negotiations = 1;
        return rv;
      }
      break;

    default:
      mtevFatal(eventer_err, "error: unknown SSL operation (%d)\n", op);
  }
  /* This can't happen as we'd have already aborted... */
  if(!opstr) opstr = "none";

  if(ctx->renegotiated) {
    mtevL(eventer_err, "SSL renogotiation attempted on %d\n", fd);
    errno = EIO;
    eventer_ssl_ctx_save_last_error(ctx, 1);
    return -1;
  }

  sslerror = SSL_get_error(ctx->ssl, rv);
  char errbuf[30];
  switch(sslerror) {
    case SSL_ERROR_NONE:
      mtevL(ssldb, "SSL[%s of %d] -> %d, rw error: %s\n", opstr,
            (int)len, rv, internal_SSL_error(sslerror,errbuf,sizeof(errbuf)));
      return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      *mask = (sslerror == SSL_ERROR_WANT_READ) ?
                EVENTER_READ : EVENTER_WRITE;
      errno = EAGAIN;
      break;
    case SSL_ERROR_SYSCALL:
      if(errno == 0) {
        mtevL(ssldb, "SSL error (syscall) no error?!\n");
        return -1;
      }
      /* FALLTHROUGH */
    default:
      mtevL(ssldb, "SSL[%s of %d] -> %d, rw error: %s%s%s\n", opstr,
            (int)len, rv, internal_SSL_error(sslerror,errbuf,sizeof(errbuf)),
            errno ? "/" : "", errno ? strerror(errno) : "");
      eventer_ssl_ctx_save_last_error(ctx, 1);
      errno = EIO;
  }
  return -1;
}

int
eventer_SSL_renegotiate(eventer_t e) {
  eventer_ssl_ctx_t *ctx;
  ctx = eventer_get_eventer_ssl_ctx(e);
  if(!ctx) return -1;
  ERR_clear_error();
  SSL_renegotiate(ctx->ssl);
  return 0;
}

int
eventer_SSL_accept(eventer_t e, int *mask) {
  int rv;
  LIBMTEV_EVENTER_ACCEPT_ENTRY(e->fd, NULL, 0, *mask, e->opset->get_opset_ctx(e));
  rv = eventer_SSL_rw(SSL_OP_ACCEPT, e->fd, NULL, 0, mask, e);
  LIBMTEV_EVENTER_ACCEPT_RETURN(e->fd, NULL, 0, *mask, e->opset->get_opset_ctx(e), rv);
  return rv;
}
int
eventer_SSL_connect(eventer_t e, int *mask) {
  return eventer_SSL_rw(SSL_OP_CONNECT, e->fd, NULL, 0, mask, e);
}
static int
eventer_SSL_read(int fd, void *buffer, size_t len, int *mask,
                 void *closure) {
  int rv;
  LIBMTEV_EVENTER_READ_ENTRY(fd, buffer, len, *mask, closure);
  rv = eventer_SSL_rw(SSL_OP_READ, fd, buffer, len, mask, closure);
  LIBMTEV_EVENTER_READ_RETURN(fd, buffer, len, *mask, closure, rv);
  return rv;
}
static int
eventer_SSL_write(int fd, const void *buffer, size_t len, int *mask,
                  void *closure) {
  int rv;
  LIBMTEV_EVENTER_WRITE_ENTRY(fd, (char *)buffer, len, *mask, closure);
  rv = eventer_SSL_rw(SSL_OP_WRITE, fd, (void *)buffer, len, mask, closure);
  LIBMTEV_EVENTER_WRITE_RETURN(fd, (char *)buffer, len, *mask, closure, rv);
  return rv;
}

/* Close simply shuts down the SSL site and closes the file descriptor. */
static int
eventer_SSL_close(int fd, int *mask, void *closure) {
  int rv = -1;
  eventer_t e = closure;
  eventer_ssl_ctx_t *ctx = e->opset->get_opset_ctx(e);
  LIBMTEV_EVENTER_CLOSE_ENTRY(fd, *mask, closure);
  ERR_clear_error();
  SSL_shutdown(ctx->ssl);
  e->opset->set_opset_ctx(e, NULL);
  eventer_ssl_ctx_free(ctx);
  if(fd < 0) {
#ifdef EBADFD
    errno = EBADFD;
#elif EBADF
    errno = EBADF;
#else
#error Need errno definition for bad filedescriptor
#endif
  } else {
    posix_asynch_shutdown_close(fd);
    rv = 0;
  }
  *mask = 0;
  LIBMTEV_EVENTER_CLOSE_RETURN(fd, *mask, closure, rv);
  e->fd = -1;
  (void)rv;
  return 0;
}

struct _fd_opset _eventer_SSL_fd_opset = {
  _noallowed_eventer_SSL_accept,
  eventer_SSL_read,
  eventer_SSL_write,
  eventer_SSL_close,
  eventer_SSL_set_opset,
  eventer_SSL_get_opset_ctx,
  eventer_SSL_set_opset_ctx,
  "SSL"
};

eventer_fd_opset_t eventer_SSL_fd_opset = &_eventer_SSL_fd_opset;


#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
/* Locking stuff to make libcrypto thread safe */
/* This stuff cribbed from the openssl examples */
struct CRYPTO_dynlock_value { pthread_mutex_t lock; };
static struct CRYPTO_dynlock_value *__lcks = NULL;
static void lock_static(int mode, int type, const char *f, int l) {
  (void)f;
  (void)l;
  if(mode & CRYPTO_LOCK) pthread_mutex_lock(&__lcks[type].lock);
  else pthread_mutex_unlock(&__lcks[type].lock);
}
static struct CRYPTO_dynlock_value *dynlock_create(const char *f, int l) {
  struct CRYPTO_dynlock_value *lock = CRYPTO_malloc(sizeof(*lock),f,l);
  pthread_mutex_init(&lock->lock,  NULL);
  return lock;
}
static void dynlock_destroy(struct CRYPTO_dynlock_value *lock,
                            const char *f, int l) {
  (void)f;
  (void)l;
  pthread_mutex_destroy(&lock->lock);
  CRYPTO_free(lock);
}
static void lock_dynamic(int mode, struct CRYPTO_dynlock_value *lock,
                         const char *f, int l) {
  (void)f;
  (void)l;
  if(mode & CRYPTO_LOCK) pthread_mutex_lock(&lock->lock);
  else pthread_mutex_unlock(&lock->lock);
}
#endif

void eventer_ssl_set_ssl_ctx_cache_expiry(int timeout) {
  ssl_ctx_cache_expiry = timeout;
}
int eventer_ssl_config(const char *key, const char *value) {
  if(!strncmp(key, "ssl_dhparam", strlen("ssl_dhparam"))) {
    char *endptr = NULL;
    unsigned long bits = strtoul(key + strlen("ssl_dhparam"), &endptr, 10);
    if(bits > 0 && endptr && (*endptr == '\0' || !strcmp(endptr, "_file"))) {
      int i;
      for(i=0; i<ndhparams; i++) {
        if(dhparams[i].bits == (int)bits) {
          dhparams[i].file = strlen(value) ? strdup(value) : NULL;
          return 0;
        }
      }
      if(i < MAX_DHPARAMS) {
        mtevL(mtev_notice, "Config requesting %lu bit dhparams\n", bits);
        dhparams[i].bits = (int)bits;
        dhparams[i].file = strlen(value) ? strdup(value) : NULL;
        /* special case 1024 to use the openssl NIST builtin */
#if OPENSSL_VERSION_NUMBER >= _OPENSSL_VERSION_1_0_2
        if(bits == 1024) dhparams[i].builtin = DH_get_1024_160;
#else
        if(bits == 1024) dhparams[i].builtin = get_dh1024;
#endif
        ndhparams++;
        return 0;
      }
    }
  }
  if(!strcmp(key, "ssl_ctx_cache_expiry")) {
    eventer_ssl_set_ssl_ctx_cache_expiry(atoi(value));
    return 0;
  }
  return 1;
}

static int32_t initialized = 0;
void eventer_ssl_init(void) {
  eventer_t e;
  if(initialized) return;
  ssldb = mtev_log_stream_find("debug/eventer/ssl");
  initialized = 1;
#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
  int i, numlocks;
  numlocks = CRYPTO_num_locks();
  __lcks = CRYPTO_malloc(numlocks * sizeof(*__lcks),__FILE__,__LINE__);
  for(i=0; i<numlocks; i++)
    pthread_mutex_init(&__lcks[i].lock, NULL);
  CRYPTO_set_dynlock_create_callback(dynlock_create);
  CRYPTO_set_dynlock_destroy_callback(dynlock_destroy);
  CRYPTO_set_dynlock_lock_callback(lock_dynamic);
  CRYPTO_set_locking_callback(lock_static);
#endif
  CRYPTO_set_id_callback((unsigned long (*)(void)) pthread_self);

#if OPENSSL_VERSION_NUMBER < _OPENSSL_VERSION_1_1_0
  SSL_load_error_strings();
  SSL_library_init();
#else
  OPENSSL_init_ssl(
    OPENSSL_INIT_LOAD_SSL_STRINGS|
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS|
    OPENSSL_INIT_ADD_ALL_CIPHERS|
    OPENSSL_INIT_ADD_ALL_DIGESTS|
    OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#endif
  OpenSSL_add_all_ciphers();

  for(int i=0; i<ndhparams; i++) {
    e = eventer_alloc();
    e->mask = EVENTER_ASYNCH;
    e->callback = generate_dh_params;
    e->closure = (void *)&dhparams[i];
    eventer_add_asynch(NULL, e);
  }
  return;
}

void eventer_ssl_init_globals(void) {
  mtev_hash_init(&ssl_ctx_cache);
  mtev_hash_init(&alpn_funcs);
}

