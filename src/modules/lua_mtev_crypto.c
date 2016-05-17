/*
 * Copyright (c) 2014-2015, Circonus, Inc. All rights reserved.
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
 *     * Neither the name Circonus, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this
 *       software without specific prior written permission.
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

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "mtev_conf.h"

#include "lua_mtev.h"
#ifndef sk_OPENSSL_STRING_num
#define sk_OPENSSL_STRING_num sk_num
#endif

#ifndef sk_OPENSSL_STRING_value
#define sk_OPENSSL_STRING_value sk_value
#endif

static __thread BN_CTX *tls_bn_ctx = NULL;
static BN_CTX *bn_ctx() {
  if(!tls_bn_ctx) tls_bn_ctx = BN_CTX_new();
  return tls_bn_ctx;
}


#define PUSH_OBJ(L, tname, obj) do { \
  *(void **)(lua_newuserdata(L, sizeof(void *))) = (obj); \
  luaL_getmetatable(L, tname); \
  lua_setmetatable(L, -2); \
} while(0)

int
mtev_lua_crypto_newx509(lua_State *L, X509 *x509) {
  if(x509 == NULL) return 0;
  PUSH_OBJ(L, "crypto.x509", x509);
  return 1;
}

static int
mtev_lua_crypto_x509_index_func(lua_State *L) {
  const char *k;
  void *udata;
  X509 *cert;
  int j;

  assert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "crypto.x509")) {
    luaL_error(L, "metatable error, arg1 not a crypto.x509!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  cert = *((X509 **)udata);
  if(!strcmp(k, "signature_algorithm")) {
    int nid;
    nid = OBJ_obj2nid(cert->sig_alg->algorithm);
    lua_pushstring(L, OBJ_nid2sn(nid));
    return 1;
  }
  if(!strcmp(k, "purpose")) {
    int i, j, pret;
    int cnt = X509_PURPOSE_get_count();
    lua_newtable(L);
    for(i=0; i<cnt; i++) {
      int id;
      char *pname;
      X509_PURPOSE *pt;
      pt = X509_PURPOSE_get0(i);
      id = X509_PURPOSE_get_id(pt);
      pname = X509_PURPOSE_get0_name(pt);
      for(j=0; j<2; j++) {
        char name_full[1024];
        pret = X509_check_purpose(cert, id, j);
        snprintf(name_full, sizeof(name_full), "%s%s", pname, j ? "_ca" : "");
        lua_pushstring(L, name_full);
        lua_pushinteger(L, pret);
        lua_settable(L, -3);
      }
    }
    return 1;
  }
  if(!strcmp(k, "serial")) {
    lua_pushinteger(L, ASN1_INTEGER_get(X509_get_serialNumber(cert)));
    return 1;
  }
  if(!strcmp(k, "bits")) {
    EVP_PKEY *pkey;
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) return 0;
    else if (pkey->type == EVP_PKEY_RSA && pkey->pkey.rsa)
      lua_pushinteger(L, BN_num_bits(pkey->pkey.rsa->n));
    else if (pkey->type == EVP_PKEY_DSA && pkey->pkey.dsa)
      lua_pushinteger(L, BN_num_bits(pkey->pkey.dsa->p));
    else lua_pushnil(L);
    EVP_PKEY_free(pkey);
    return 1;
  }
  if(!strcmp(k, "type")) {
    EVP_PKEY *pkey;
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) return 0;
    else if (pkey->type == EVP_PKEY_RSA) lua_pushstring(L, "rsa");
    else if (pkey->type == EVP_PKEY_DSA) lua_pushstring(L, "dsa");
    else lua_pushstring(L, "unknown");
    EVP_PKEY_free(pkey);
    return 1;
  }
  if(!strcmp(k, "ocsp")) {
    STACK_OF(OPENSSL_STRING) *emlst;
    emlst = X509_get1_ocsp(cert);
    for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++) {
      lua_pushstring(L, sk_OPENSSL_STRING_value(emlst, j));
    }
    X509_email_free(emlst);
    return j;
  }
  luaL_error(L, "crypto.x509 no such element: %s", k);
  return 0;
}

static int
mtev_lua_crypto_x509_gc(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L,1);
  X509_free((X509 *)*udata);
  return 0;
}

int
mtev_lua_crypto_new_ssl_session(lua_State *L, SSL_SESSION *ssl_session) {
  if(ssl_session == NULL) return 0;
  PUSH_OBJ(L, "crypto.ssl_session", ssl_session);
  return 1;
}

static int
mtev_lua_crypto_ssl_session_release(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1))
    luaL_error(L, "must be called as method");
  *udata = NULL;
  return 0;
}

static int
mtev_lua_crypto_ssl_session_index_func(lua_State *L) {
  const char *k;
  void *udata;
  SSL_SESSION *ssl_session;
  int j;

  assert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "crypto.ssl_session")) {
    luaL_error(L, "metatable error, arg1 not a crypto.ssl_session!");
  }
  udata = lua_touserdata(L, 1);
  if(!*(void **)udata)
    luaL_error(L, "crypto.ssl_session already released");
  k = lua_tostring(L, 2);
  ssl_session = *((SSL_SESSION **)udata);
  switch(*k) {
    case 'c':
      if(!strcmp(k, "cipher")) {
        if(ssl_session->cipher == NULL) {
          if (((ssl_session->cipher_id) & 0xff000000) == 0x02000000)
            lua_pushinteger(L, ssl_session->cipher_id & 0xffffff);
          else
            lua_pushinteger(L, ssl_session->cipher_id & 0xffff);
        }
        else {
          lua_pushstring(L, ssl_session->cipher->name ?
                              ssl_session->cipher->name : "unknown");
        }
        return 1;
      }
      break;
    case 'm':
      if(!strcmp(k, "master_key")) {
        lua_pushlstring(L, (char *)ssl_session->master_key,
                        ssl_session->master_key_length);
        return 1;
      }
      if(!strcmp(k, "master_key_bits")) {
        lua_pushinteger(L, ssl_session->master_key_length * 8);
        return 1;
      }
      break;
    case 'r':
      if(!strcmp(k, "release")) {
        lua_pushlightuserdata(L, udata);
        lua_pushcclosure(L, mtev_lua_crypto_ssl_session_release, 1);
        return 1;
      }
      break;
    case 's':
      if(!strcmp(k, "ssl_version")) {
        const char *s = "unknown";
        if (ssl_session->ssl_version == SSL2_VERSION) s="SSLv2";
        else if (ssl_session->ssl_version == SSL3_VERSION) s="SSLv3";
#ifdef TLS1_2_VERSION
        else if (ssl_session->ssl_version == TLS1_2_VERSION) s="TLSv1.2";
#endif
#ifdef TLS1_1_VERSION
        else if (ssl_session->ssl_version == TLS1_1_VERSION) s="TLSv1.1";
#endif
        else if (ssl_session->ssl_version == TLS1_VERSION) s="TLSv1";
        else if (ssl_session->ssl_version == DTLS1_VERSION) s="DTLSv1";
        else if (ssl_session->ssl_version == DTLS1_BAD_VER) s="DTLSv1-bad";
        lua_pushstring(L, s);
        return 1;
      }
      break;

    default:
      break;
  }
  luaL_error(L, "crypto.ssl_session no such element: %s", k);
  return 0;
}

static int
mtev_lua_crypto_ssl_session_gc(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L,1);
  *udata = NULL;
  return 0;
}

static int
mtev_lua_crypto_newrsa(lua_State *L) {
  int bits = 2048;
  int e = 65537;
  BIGNUM *bn = NULL;
  RSA *rsa = NULL;

  if(lua_gettop(L) > 0) {
    if(lua_isnumber(L,1))
      bits = lua_tointeger(L,1);
    else {
      BIO *bio;
      size_t len;
      const char *key;
      key = lua_tolstring(L,1,&len);
      bio = BIO_new_mem_buf((void *)key,len);
      if(bio && PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL)) {
        PUSH_OBJ(L, "crypto.rsa", rsa);
        return 1;
      }
      lua_pushnil(L);
      return 1;
    }
  }
  if(lua_gettop(L) > 1) e = lua_tointeger(L,2);

  rsa = RSA_new();
  if(!rsa) goto fail;
  bn = BN_new();
  if(!bn) goto fail;
  if(!BN_set_word(bn, e)) goto fail;
  if(!RSA_generate_key_ex(rsa, bits, bn, NULL)) goto fail;
  BN_free(bn);

  PUSH_OBJ(L, "crypto.rsa", rsa);
  return 1;

 fail:
  if(bn) BN_free(bn);
  if(rsa) RSA_free(rsa);
  lua_pushnil(L);
  return 1;
}

static int
mtev_lua_crypto_newreq(lua_State *L) {
  X509_REQ *req = NULL;
  const char *pem;
  size_t len;
  BIO *bio;

  pem = lua_tolstring(L, 1, &len);
  if(pem == NULL) luaL_error(L, "crypto.newreq needs string");
  bio = BIO_new_mem_buf((void *)pem, len);
  if(bio && PEM_read_bio_X509_REQ(bio, &req, NULL, NULL)) {
    BIO_free(bio);
    PUSH_OBJ(L, "crypto.req", req);
    return 1;
  }
  if(bio) BIO_free(bio);
  lua_pushnil(L);
  return 1;
}

static int
mtev_lua_crypto_rsa_gencsr(lua_State *L) {
  RSA *rsa;
  X509_REQ *req = NULL;
  X509_NAME *subject = NULL;
  const EVP_MD *md = NULL;
  EVP_PKEY *pkey = NULL;
  const char *lua_string;
  char buf[1024];
  const char *error = buf;
  char *errbuf;
  void **udata;

  strlcpy(buf, "crypto.rsa:gencsr ", sizeof(buf));
  errbuf = buf + strlen(buf);
#define REQERR(err) do { \
  strlcpy(errbuf, err, sizeof(buf) - (errbuf - buf)); \
  goto fail; \
} while(0)

  if(!luaL_checkudata(L, 1, "crypto.rsa")) {
    luaL_error(L, "metatable error, arg1 not a crypto.rsa!");
  }

  if(!lua_istable(L,2)) REQERR("requires table as second argument");
  lua_pushvalue(L,2);
  udata = lua_touserdata(L, lua_upvalueindex(1));
  rsa = (RSA *)*udata;

#define GET_OR(str, name,fallback) do { \
  lua_getfield(L,-1,name); \
  str = lua_isstring(L,-1) ? lua_tostring(L,-1) : fallback; \
  lua_pop(L,1); \
} while(0)
  GET_OR(lua_string, "digest", "sha256");
  md = EVP_get_digestbyname(lua_string);
  if(!md) REQERR("unknown digest");
  pkey = EVP_PKEY_new();
  if(!EVP_PKEY_assign_RSA(pkey, RSAPrivateKey_dup(rsa)))
    REQERR("crypto.rsa:gencsr could not use private key");
  req = X509_REQ_new();
  if(!req) REQERR("crypto.rsa:gencsr allocation failure");
  if (!X509_REQ_set_version(req,0L)) /* version 1 */
    REQERR("crypto.rsa:gencsr could not set request version");
  lua_getfield(L,-1,"subject");
  if(!lua_istable(L,-1)) REQERR("subject value must be a table");

  subject = X509_NAME_new();
  lua_pushnil(L);
  while(lua_next(L, -2)) {
    int nid;
    const char *subj_part = lua_tostring(L, -2);
    const char *subj_value = lua_tostring(L, -1);

    if((nid=OBJ_txt2nid(subj_part)) == NID_undef) {
      mtevL(mtev_error, "crypto.rsa:gencsr unknown subject part %s\n", subj_part);
    }
    else if(subj_value == NULL || *subj_value == '\0') {
      mtevL(mtev_error, "crypto.rsa:gencsr subject part %s is blank\n", subj_part);
    }
    else if(!X509_NAME_add_entry_by_NID(subject, nid, MBSTRING_ASC,
                                        (unsigned char*)subj_value,-1,-1,0)) {
      REQERR("failure building subject");
    }
    lua_pop(L,1);
  }
  if(!X509_REQ_set_subject_name(req, subject)) {
    ERR_error_string(ERR_get_error(), errbuf);
    goto fail;
  }
  X509_NAME_free(subject);
  subject = NULL;
  if(!X509_REQ_set_pubkey(req,pkey)) {
    ERR_error_string(ERR_get_error(), errbuf);
    goto fail;
  }
  if(!X509_REQ_sign(req,pkey,md)) {
    pkey = NULL;
    ERR_error_string(ERR_get_error(), errbuf);
    goto fail;
  }
  pkey = NULL;
  PUSH_OBJ(L, "crypto.req", req);
  return 1;

 fail:
  if(subject) X509_NAME_free(subject);
  if(pkey) EVP_PKEY_free(pkey);
  if(req) X509_REQ_free(req);
  luaL_error(L, error);
  return 0;
}

static int
mtev_lua_crypto_rsa_as_pem(lua_State *L) {
  BIO *bio;
  RSA *rsa;
  long len;
  char *pem;
  void **udata;
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1))
    luaL_error(L, "must be called as method");
  rsa = (RSA *)*udata;

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
  len = BIO_get_mem_data(bio, &pem);
  lua_pushlstring(L, pem, len);
  BIO_free(bio);
  return 1;
}

static int
mtev_lua_crypto_rsa_index_func(lua_State *L) {
  const char *k;
  void *udata;
  assert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "crypto.rsa")) {
    luaL_error(L, "metatable error, arg1 not a crypto.rsa!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  if(!strcmp(k,"pem")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_crypto_rsa_as_pem, 1);
    return 1;
  }
  if(!strcmp(k,"gencsr")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_crypto_rsa_gencsr, 1);
    return 1;
  }
  luaL_error(L, "crypto.rsa no such element: %s", k);
  return 0;
}

static int
mtev_lua_crypto_rsa_gc(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L,1);
  RSA_free((RSA *)*udata);
  return 0;
}

static int
mtev_lua_crypto_req_as_pem(lua_State *L) {
  BIO *bio;
  X509_REQ *req;
  long len;
  char *pem;
  void **udata;
  udata = lua_touserdata(L, lua_upvalueindex(1));
  if(udata != lua_touserdata(L, 1))
    luaL_error(L, "must be called as method");
  req = (X509_REQ *)*udata;

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509_REQ(bio, req);
  len = BIO_get_mem_data(bio, &pem);
  lua_pushlstring(L, pem, len);
  BIO_free(bio);
  return 1;
}

static int
mtev_lua_crypto_req_index_func(lua_State *L) {
  const char *k;
  void **udata;
  assert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "crypto.req")) {
    luaL_error(L, "metatable error, arg1 not a crypto.req!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
  if(!strcmp(k,"pem")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_crypto_req_as_pem, 1);
    return 1;
  }
  if(!strcmp(k,"subject")) {
    char buf[1024];
    X509_NAME *name;
    X509_REQ *req = ((X509_REQ *)*udata);
    name = X509_REQ_get_subject_name(req);
    X509_NAME_oneline(name, buf, sizeof(buf)-1);
    lua_pushstring(L, buf);
    return 1;
  }
  luaL_error(L, "crypto.req no such element: %s", k);
  return 0;
}

static int
mtev_lua_crypto_req_gc(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L,1);
  X509_REQ_free((X509_REQ *)*udata);
  return 0;
}

#define BN_METH_DECL(n) \
  BIGNUM *bn, *args[4]; \
  void **udata; \
  udata = lua_touserdata(L, lua_upvalueindex(1)); \
  if(udata != lua_touserdata(L, 1)) \
    luaL_error(L, "must be called as method"); \
  else if(lua_gettop(L) != (1+n)) \
    luaL_error(L, "must be called with " #n " arguments"); \
  else { \
    int i; \
    for(i=0;i<n;i++) { \
      void **vu = lua_touserdata(L, i+2); \
      if(!luaL_checkudata(L, i+2, "crypto.bignum")) \
        luaL_error(L, "arguments must be crypto.bignum"); \
      args[i] = (BIGNUM *)*vu; \
    } \
  } \
  bn = (BIGNUM *)*udata
#define BN_METH_DECL_INT(n) \
  BIGNUM *bn; \
  int args[4]; \
  void **udata; \
  udata = lua_touserdata(L, lua_upvalueindex(1)); \
  if(udata != lua_touserdata(L, 1)) \
    luaL_error(L, "must be called as method"); \
  else if(lua_gettop(L) != (1+n)) \
    luaL_error(L, "must be called with " #n " arguments"); \
  else { \
    int i; \
    for(i=0;i<n;i++) { \
      if(!lua_isnumber(L, i+2)) \
        luaL_error(L, "arguments must be integers"); \
      args[i] = lua_tointeger(L, i+2); \
    } \
  } \
  bn = (BIGNUM *)*udata
#define BN_INT(func, params...) (lua_pushinteger(L, func(params)), 1)

#define BN_SIMPLE_BN(name,n,sargs...) \
static int mtev_lua_crypto_bn_##name(lua_State *L) { \
  BN_METH_DECL(n); \
  return BN_INT(BN_##name,sargs); \
}
#define BN_SIMPLE_INT(name,n,sargs...) \
static int mtev_lua_crypto_bn_##name(lua_State *L) { \
  BN_METH_DECL_INT(n); \
  return BN_INT(BN_##name,sargs); \
}

static int mtev_lua_crypto_bn_is_negative(lua_State *L) {
  BN_METH_DECL_INT(0);
  lua_pushboolean(L, BN_is_negative(bn));
  lua_pushboolean(L, bn->neg ? 1 : 0);
  return 2;
}
static int mtev_lua_crypto_bn_set_negative(lua_State *L) {
  BN_METH_DECL_INT(1);
  BN_set_negative(bn,args[0]);
  return 0;
}
static int mtev_lua_crypto_bn_copy(lua_State *L) {
  BN_METH_DECL(1);
  lua_pushinteger(L, (NULL != BN_copy(bn, args[0])));
  return 1;
}
static int mtev_lua_crypto_bn_mod_inverse(lua_State *L) {
  BN_METH_DECL(2);
  lua_pushinteger(L, (NULL != BN_mod_inverse(bn, args[0], args[1], bn_ctx())));
  return 1;
}
static int mtev_lua_crypto_bn_mod_sqrt(lua_State *L) {
  BN_METH_DECL(2);
  lua_pushinteger(L, (NULL != BN_mod_sqrt(bn, args[0], args[1], bn_ctx())));
  return 1;
}
static int mtev_lua_crypto_bn_swap(lua_State *L) {
  BN_METH_DECL(1);
  BN_swap(bn, args[0]);
  return 0;
}
static int mtev_lua_crypto_bn_dup(lua_State *L) {
  BN_METH_DECL(0);
  bn = BN_dup(bn);
  if(bn) PUSH_OBJ(L, "crypto.bignum", bn);
  else lua_pushnil(L);
  return 1;
}
static int mtev_lua_crypto_bn_tobin(lua_State *L) {
  unsigned char buf[1024], *ptr = buf;
  int len;
  BN_METH_DECL(0);
  len = BN_num_bytes(bn);
  if(len > sizeof(buf)) ptr = malloc(len);
  if(ptr == NULL) luaL_error(L, "out of memory");
  len = BN_bn2bin(bn, ptr);
  lua_pushlstring(L, (char *)ptr, len);
  if(ptr != buf) free(ptr);
  return 1;
}
static int mtev_lua_crypto_bn_tompi(lua_State *L) {
  unsigned char buf[1024], *ptr = buf;
  int len;
  BN_METH_DECL(0);
  len = BN_bn2mpi(bn, NULL);
  if(len > sizeof(buf)) ptr = malloc(len);
  if(ptr == NULL) luaL_error(L, "out of memory");
  len = BN_bn2mpi(bn, ptr);
  lua_pushlstring(L, (char *)ptr, len);
  if(ptr != buf) free(ptr);
  return 1;
}
static int mtev_lua_crypto_bn_tohex(lua_State *L) {
  char *ptr;
  BN_METH_DECL(0);
  ptr = BN_bn2hex(bn);
  if(ptr) {
    lua_pushstring(L, ptr);
    OPENSSL_free(ptr);
  }
  else lua_pushnil(L);
  return 1;
}
static int mtev_lua_crypto_bn_todec(lua_State *L) {
  char *ptr;
  BN_METH_DECL(0);
  ptr = BN_bn2dec(bn);
  if(ptr) {
    lua_pushstring(L, ptr);
    OPENSSL_free(ptr);
  }
  else lua_pushnil(L);
  return 1;
}
/* dual_math_meta */
#define BN_MATH_META_2(name, func, args...) \
static int mtev_lua_crypto_bn___##name(lua_State *L) { \
  void **udata_a, **udata_b; \
  BIGNUM *r, *a, *b; \
  if(lua_gettop(L) != 2) \
    luaL_error(L, "bignum.__" #name " called with wrong args"); \
  if(!luaL_checkudata(L,1,"crypto.bignum")) \
    luaL_error(L, "bignum.__" #name " called on non-bignum"); \
  udata_a = lua_touserdata(L, 1); \
  a = (BIGNUM *)*udata_a; \
  if(lua_isnumber(L,2)) { \
    r = b = BN_new(); \
    BN_set_word(r,lua_tointeger(L,2)); \
  } \
  else if(!luaL_checkudata(L,2,"crypto.bignum")) { \
    luaL_error(L, "bignum.__" #name " called on non-bignum"); \
  } \
  else { \
    udata_b = lua_touserdata(L, 2); \
    r = BN_new(); \
    b = (BIGNUM *)*udata_b; \
  } \
  BN_##func(args); \
  PUSH_OBJ(L,"crypto.bignum",r); \
  return 1; \
}
BN_MATH_META_2(add,add,r,a,b)
BN_MATH_META_2(sub,sub,r,a,b)
BN_MATH_META_2(mul,mul,r,a,b,bn_ctx())
BN_MATH_META_2(div,div,r,NULL,a,b,bn_ctx())
BN_MATH_META_2(mod,mod,r,a,b,bn_ctx())
BN_MATH_META_2(pow,exp,r,a,b,bn_ctx())
#define BN_MATH_TEST(name, op, expected) \
static int mtev_lua_crypto_bn___##name(lua_State *L) { \
  void **udata_a, **udata_b; \
  BIGNUM *a, *b; \
  if(lua_gettop(L) != 2) \
    luaL_error(L, "bignum.__" #name " called with wrong args"); \
  if(!luaL_checkudata(L,1,"crypto.bignum") || \
     !luaL_checkudata(L,2,"crypto.bignum")) \
    luaL_error(L, "bignum.__" #name " called on non-bignum"); \
  udata_a = lua_touserdata(L, 1); \
  a = (BIGNUM *)*udata_a; \
  udata_b = lua_touserdata(L, 2); \
  b = (BIGNUM *)*udata_b; \
  lua_pushboolean(L, (BN_cmp(a,b) op expected)); \
  return 1; \
}
BN_MATH_TEST(eq, ==, 0)
BN_MATH_TEST(le, <=, 0)
BN_MATH_TEST(lt, <, 0)

static int mtev_lua_crypto_bn___tostring(lua_State *L) {
  if(lua_gettop(L) != 1 ||
     !luaL_checkudata(L,1,"crypto.bignum")) {
    lua_pushnil(L);
  }
  else {
    void **udata = lua_touserdata(L, 1);
    void *ptr = BN_bn2dec((BIGNUM *)*udata);
    if(ptr) {
      lua_pushstring(L, ptr);
      OPENSSL_free(ptr);
    }
    else lua_pushnil(L);
  }
  return 1;
}

/*
DO: BN_mod_lshift
DO: BN_mod_lshift_query
DO: BN_lshift
DO: BN_rshift
DO: BN_reciprocal
*/

BN_SIMPLE_BN(num_bytes,0,bn)
BN_SIMPLE_BN(mod_exp,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(mod_exp_simple,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(exp,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(rand_range,1,bn,args[0])
BN_SIMPLE_BN(pseudo_rand_range,1,bn,args[0])
BN_SIMPLE_BN(num_bits,0,bn)
BN_SIMPLE_BN(sub,2,bn,args[0],args[1])
BN_SIMPLE_BN(add,2,bn,args[0],args[1])
BN_SIMPLE_BN(usub,2,bn,args[0],args[1])
BN_SIMPLE_BN(uadd,2,bn,args[0],args[1])
BN_SIMPLE_BN(mul,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(div,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(mod,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(nnmod,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(mod_add,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(mod_add_quick,3,bn,args[0],args[1],args[2])
BN_SIMPLE_BN(mod_sub,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(mod_sub_quick,3,bn,args[0],args[1],args[2])
BN_SIMPLE_BN(mod_mul,3,bn,args[0],args[1],args[2],bn_ctx())
BN_SIMPLE_BN(mod_sqr,1,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(mod_lshift1,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_BN(mod_lshift1_quick,2,bn,args[0],args[1])
BN_SIMPLE_BN(sqr,1,bn,args[0],bn_ctx())
BN_SIMPLE_BN(lshift1,1,bn,args[0])
BN_SIMPLE_BN(rshift1,1,bn,args[0])
BN_SIMPLE_BN(cmp,1,bn,args[0])
BN_SIMPLE_BN(ucmp,1,bn,args[0])
BN_SIMPLE_BN(gcd,2,bn,args[0],args[1],bn_ctx())
BN_SIMPLE_INT(rand,3,bn,args[0],args[1],args[2])
BN_SIMPLE_INT(pseudo_rand,3,bn,args[0],args[1],args[2])
BN_SIMPLE_INT(mod_word,1,bn,args[0])
BN_SIMPLE_INT(div_word,1,bn,args[0])
BN_SIMPLE_INT(mul_word,1,bn,args[0])
BN_SIMPLE_INT(add_word,1,bn,args[0])
BN_SIMPLE_INT(sub_word,1,bn,args[0])
BN_SIMPLE_INT(set_word,1,bn,args[0])
BN_SIMPLE_INT(get_word,0,bn)
BN_SIMPLE_INT(is_bit_set,1,bn,args[0])
BN_SIMPLE_INT(mask_bits,1,bn,args[0])
BN_SIMPLE_INT(set_bit,1,bn,args[0])
BN_SIMPLE_INT(clear_bit,1,bn,args[0])

static int
mtev_lua_crypto_bignum_index_func(lua_State *L) {
  const char *k;
  void **udata;
  assert(lua_gettop(L) == 2);
  if(!luaL_checkudata(L, 1, "crypto.bignum")) {
    luaL_error(L, "metatable error, arg1 not a crypto.req!");
  }
  udata = lua_touserdata(L, 1);
  k = lua_tostring(L, 2);
#define BN_DISPATCH(meth) if(!strcmp(k, #meth)) { \
  lua_pushlightuserdata(L, udata); \
  lua_pushcclosure(L, mtev_lua_crypto_bn_##meth, 1); \
  return 1; \
}
  BN_DISPATCH(tobin)
  else BN_DISPATCH(num_bytes)
  else BN_DISPATCH(tompi)
  else BN_DISPATCH(todec)
  else BN_DISPATCH(tohex)
  else BN_DISPATCH(mod_exp)
  else BN_DISPATCH(mod_exp_simple)
  else BN_DISPATCH(copy)
  else BN_DISPATCH(swap)
  else BN_DISPATCH(dup)
  else BN_DISPATCH(add)
  else BN_DISPATCH(sub)
  else BN_DISPATCH(uadd)
  else BN_DISPATCH(usub)
  else BN_DISPATCH(mul)
  else BN_DISPATCH(div)
  else BN_DISPATCH(mod)
  else BN_DISPATCH(nnmod)
  else BN_DISPATCH(mod_add)
  else BN_DISPATCH(mod_add_quick)
  else BN_DISPATCH(mod_sub)
  else BN_DISPATCH(mod_sub_quick)
  else BN_DISPATCH(mod_mul)
  else BN_DISPATCH(mod_sqr)
  else BN_DISPATCH(mod_lshift1)
  else BN_DISPATCH(mod_lshift1_quick)
  else BN_DISPATCH(sqr)
  else BN_DISPATCH(num_bits)
  else BN_DISPATCH(rand)
  else BN_DISPATCH(pseudo_rand)
  else BN_DISPATCH(rand_range)
  else BN_DISPATCH(pseudo_rand_range)
  else BN_DISPATCH(mod_word)
  else BN_DISPATCH(div_word)
  else BN_DISPATCH(mul_word)
  else BN_DISPATCH(add_word)
  else BN_DISPATCH(sub_word)
  else BN_DISPATCH(set_word)
  else BN_DISPATCH(get_word)
  else BN_DISPATCH(is_bit_set)
  else BN_DISPATCH(is_negative)
  else BN_DISPATCH(set_negative)
  else BN_DISPATCH(mask_bits)
  else BN_DISPATCH(lshift1)
  else BN_DISPATCH(rshift1)
  else BN_DISPATCH(exp)
  else BN_DISPATCH(cmp)
  else BN_DISPATCH(ucmp)
  else BN_DISPATCH(set_bit)
  else BN_DISPATCH(gcd)
  else BN_DISPATCH(mod_inverse)
  else BN_DISPATCH(mod_sqrt)

  luaL_error(L, "crypto.bignum no such element: %s", k);
  return 0;
}
static int
mtev_lua_crypto_bignum_gc(lua_State *L) {
  void **udata;
  udata = lua_touserdata(L,1);
  BN_free((BIGNUM *)*udata);
  return 0;
}

#define MK_BIGNUM(name, block) \
static int \
mtev_lua_crypto_bignum_##name(lua_State *L) { \
  BIGNUM *bn = NULL; \
  if(lua_gettop(L) == 1) { \
    size_t len; \
    const char *n; \
    n = lua_tolstring(L,1,&len); \
    block \
  } \
  if(bn) PUSH_OBJ(L, "crypto.bignum", bn); \
  else lua_pushnil(L); \
  return 1; \
}
MK_BIGNUM(bin2bn, { bn = BN_bin2bn((const void *)n, len, NULL); })
MK_BIGNUM(mpi2bn, { bn = BN_mpi2bn((const void *)n, len, NULL); })
MK_BIGNUM(dec2bn, { if(BN_dec2bn(&bn, (const void *)n) == 0) bn = NULL; })
MK_BIGNUM(hex2bn, { if(BN_hex2bn(&bn, (const void *)n) == 0) bn = NULL; })

static int
mtev_lua_crypto_bignum_new(lua_State *L) {
  BIGNUM *bn = BN_new();
  if(lua_gettop(L) == 1) {
    int i;
    if(!lua_isnumber(L,1))
      luaL_error(L, "bignum_new require no argument or an integer");
    i = lua_tointeger(L,1);
    if(i < 0) {
      BN_set_word(bn, (i * -1));
      BN_set_negative(bn, 1);
    }
    else BN_set_word(bn, i);
  }
  PUSH_OBJ(L, "crypto.bignum", bn);
  return 1;
}
static int
mtev_lua_crypto_rand_bytes(lua_State *L) {
  int nbytes;
  char *errstr;
  char errbuf[120];
  unsigned char buff[1024], *ptr = buff;

  if(lua_gettop(L) != 1 ||
     !lua_isnumber(L,1) ||
     (nbytes = lua_tointeger(L,1)) <= 0) {
    luaL_error(L, "crypto.rand_bytes takes a positive integer argument");
  }
  if(nbytes > sizeof(buff)) {
    ptr = malloc(nbytes);
    if(!ptr) luaL_error(L, "crypto.rand_bytes out-of-memory");
  }

  if(RAND_bytes(buff, nbytes) == 0) {
    if(ptr != buff) free(ptr);
    errstr = ERR_error_string(ERR_get_error(), errbuf);
    luaL_error(L, errstr ? errstr : "unknown crypto error");
  }
  lua_pushlstring(L, (char *)ptr, nbytes);
  if(ptr != buff) free(ptr);
  return 1;
}

static int
mtev_lua_crypto_pseudo_rand_bytes(lua_State *L) {
  int nbytes;
  char *errstr;
  char errbuf[120];
  unsigned char buff[1024], *ptr = buff;

  if(lua_gettop(L) != 1 ||
     !lua_isnumber(L,1) ||
     (nbytes = lua_tointeger(L,1)) <= 0) {
    luaL_error(L, "crypto.rand_bytes takes a positive integer argument");
  }
  if(nbytes > sizeof(buff)) {
    ptr = malloc(nbytes);
    if(!ptr) luaL_error(L, "crypto.pseudo_rand_bytes out-of-memory");
  }

  if(RAND_pseudo_bytes(buff, nbytes) == 0) {
    if(ptr != buff) free(ptr);
    errstr = ERR_error_string(ERR_get_error(), errbuf);
    luaL_error(L, errstr ? errstr : "unknown crypto error");
  }
  lua_pushlstring(L, (char *)ptr, nbytes);
  if(ptr != buff) free(ptr);
  return 1;
}

static const struct luaL_Reg crypto_funcs[] = {
  { "newrsa",  mtev_lua_crypto_newrsa },
  { "newreq",  mtev_lua_crypto_newreq },
  { "rand_bytes", mtev_lua_crypto_rand_bytes },
  { "pseudo_rand_bytes", mtev_lua_crypto_pseudo_rand_bytes },
  { "bignum_new", mtev_lua_crypto_bignum_new },
  { "bignum_bin2bn", mtev_lua_crypto_bignum_bin2bn },
  { "bignum_dec2bn", mtev_lua_crypto_bignum_dec2bn },
  { "bignum_hex2bn", mtev_lua_crypto_bignum_hex2bn },
  { "bignum_mpi2bn", mtev_lua_crypto_bignum_mpi2bn },
  { NULL, NULL }
};

int luaopen_mtev_crypto(lua_State *L) {
  luaL_newmetatable(L, "crypto.x509");
  lua_pushcclosure(L, mtev_lua_crypto_x509_index_func, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, mtev_lua_crypto_x509_gc);
  lua_setfield(L, -2, "__gc");

  luaL_newmetatable(L, "crypto.ssl_session");
  lua_pushcclosure(L, mtev_lua_crypto_ssl_session_index_func, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, mtev_lua_crypto_ssl_session_gc);
  lua_setfield(L, -2, "__gc");

  luaL_newmetatable(L, "crypto.rsa");
  lua_pushcclosure(L, mtev_lua_crypto_rsa_index_func, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, mtev_lua_crypto_rsa_gc);
  lua_setfield(L, -2, "__gc");

  luaL_newmetatable(L, "crypto.req");
  lua_pushcclosure(L, mtev_lua_crypto_req_index_func, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, mtev_lua_crypto_req_gc);
  lua_setfield(L, -2, "__gc");

  luaL_newmetatable(L, "crypto.bignum");
  lua_pushcclosure(L, mtev_lua_crypto_bignum_index_func, 0);
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, mtev_lua_crypto_bignum_gc);
  lua_setfield(L, -2, "__gc");
  lua_pushcfunction(L, mtev_lua_crypto_bn___tostring);
  lua_setfield(L, -2, "__tostring");
  lua_pushcfunction(L, mtev_lua_crypto_bn___add);
  lua_setfield(L, -2, "__add");
  lua_pushcfunction(L, mtev_lua_crypto_bn___sub);
  lua_setfield(L, -2, "__sub");
  lua_pushcfunction(L, mtev_lua_crypto_bn___mul);
  lua_setfield(L, -2, "__mul");
  lua_pushcfunction(L, mtev_lua_crypto_bn___div);
  lua_setfield(L, -2, "__div");
  lua_pushcfunction(L, mtev_lua_crypto_bn___mod);
  lua_setfield(L, -2, "__mod");
  lua_pushcfunction(L, mtev_lua_crypto_bn___pow);
  lua_setfield(L, -2, "__pow");
  lua_pushcfunction(L, mtev_lua_crypto_bn___eq);
  lua_setfield(L, -2, "__eq");
  lua_pushcfunction(L, mtev_lua_crypto_bn___lt);
  lua_setfield(L, -2, "__lt");
  lua_pushcfunction(L, mtev_lua_crypto_bn___le);
  lua_setfield(L, -2, "__le");

  luaL_openlib(L, "mtev", crypto_funcs, 0);
  return 0;
}
