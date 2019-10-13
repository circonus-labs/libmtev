/*
 * Copyright (c) 2019, Circonus, Inc. All rights reserved.
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
#include "mtev_b64.h"
#include "mtev_url.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_http.h"
#include "mtev_rand.h"
#include "mtev_rest.h"
#include "mtev_dso.h"
#include "mtev_memory.h"
#include "mtev_str.h"

#include <ctype.h>
#include <ck_pr.h>
#include <pcre.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define COOKIE_HEADER "hmac_cookie"
#define NONCE_LEN 8

static mtev_log_stream_t debugls, errorls;
static uint8_t key[32];
static EVP_PKEY *hmac_key = NULL;
static const EVP_MD *md;
static uint32_t max_age = 86400;
static char *domain = NULL;
static mtev_hash_table testusers;
static char *login_template =
  "<!DOCTYPE html>"
  "<html>"
  "<head>"
  "<title>%1$s Access Denied</title>"
  "<meta http-equiv=\"Cache-Control\" content=\"no-cache, no-store, must-revalidate\" />"
  "<meta http-equiv=\"Pragma\" content=\"no-cache\" />"
  "<meta http-equiv=\"Expires\" content=\"0\" />"
  "<style>"
  "div.form{position:absolute;margin:auto;width:fit-content;height:fit-content;border:1px solid #aaa;padding:8px;top:0;left:0;right:0;bottom:0;border-radius:6px;}"
  "form{text-align:right;line-height:2em;}"
  "div.error{text-align:center;text-transform:capitalize;color:#c33;}"
  "label{padding-right:0.5em;}"
  "</style>"
  "</head>"
  "<body>"
  "<div class=\"form\">"
  "<div class=\"error\">%3$s</div>"
  "<form method=\"POST\" action=\"/login\" enctype=\"application/x-www-form-urlencoded\">"
  "<input type=\"hidden\" name=\"whereto\" value=\"%2$s\"/>"
  "<label for=\"username\">Username:</label><input type=\"text\" name=\"username\"/><br/>"
  "<label for=\"password\">Password:</label><input type=\"password\" name=\"password\"/><br/>"
  "<button type=\"submit\">Log In</button>"
  "</form>"
  "</div>"
  "</body>"
  "</html>";
static char *reset_template =
  "<!DOCTYPE html>"
  "<html>"
  "<head>"
  "<title>%1$s Login</title>"
  "<style>"
  "div.form{position:absolute;margin:auto;width:fit-content;height:fit-content;border:1px solid #aaa;padding:8px;top:0;left:0;right:0;bottom:0;border-radius:6px;}"
  "form{text-align:right;line-height:2em;}"
  "div.error{text-align:center;color:#c33;}"
  "label{padding-right:0.5em;}"
  "</style>"
  "</head>"
  "<body>"
  "<div class=\"form\">"
  "<div class=\"error\">"
  "You are authenticated as '%2$s', but your access is denied.<br/>"
  "You may <a href=\"%3$s\">log in as a different user</a> and try again."
  "</div>"
  "</div>"
  "</body>"
  "</html>";



struct rest_auth {
  mtev_http_rest_closure_t *restc;
  const char *user_in;
  const char *pass_in;
  char *error;
};

static ssize_t
signit(const void *buf, size_t buflen, void *out, size_t outlen) {
#define SSLERR(a) do { long err = ERR_get_error(); mtevL(errorls, a ": 0x%lx %s\n", err, ERR_reason_error_string(err)); goto done; } while(0)
  size_t req;
  mtevL(debugls, "signing %zu byte auth cookie\n", buflen);
  EVP_MD_CTX* evpctx = EVP_MD_CTX_create();
  if(!evpctx) SSLERR("Error creating creating context");
  if(1 != EVP_DigestInit_ex(evpctx, md, NULL)) SSLERR("Error initializing digest context");
  if(1 != EVP_DigestSignInit(evpctx, NULL, md, NULL, hmac_key)) SSLERR("Error initialing signature");
  if(1 != EVP_DigestSignUpdate(evpctx, buf, buflen)) SSLERR("Error updating signature");
  if(1 != EVP_DigestSignFinal(evpctx, NULL, &req)) SSLERR("Error finalizing signature");
  if(req > 256 || req > outlen) {
    mtevL(errorls, "signature too long\n");
    goto done;
  }
  if(1 != EVP_DigestSignFinal(evpctx, out, &req))
    SSLERR("Error copying signature");
  if(evpctx) EVP_MD_CTX_destroy(evpctx);
  return req;
#undef SSLERR
done:
  if(evpctx) EVP_MD_CTX_destroy(evpctx);
  return -1;
}

static void
build_login_buff(mtev_dyn_buffer_t *dst, mtev_http_request *req) {
  size_t start;
  const char *current = mtev_http_request_uri_str(req);
  const char *orig_qs = mtev_http_request_orig_querystring(req);
  mtev_dyn_buffer_add(dst, "/login?whereto=", strlen("/login?whereto="));
  start = mtev_dyn_buffer_used(dst);
  if(orig_qs) {
    mtev_dyn_buffer_add_printf(dst, "%s?%s", current, orig_qs);
  } else {
    mtev_dyn_buffer_add_printf(dst, "%s", current);
  }
  size_t explen = mtev_url_encode_len(mtev_dyn_buffer_used(dst) - start) + start;
  mtev_dyn_buffer_ensure(dst, explen);
  explen = mtev_url_encode(mtev_dyn_buffer_data(dst) + start, mtev_dyn_buffer_used(dst) - start,
                           (char *)mtev_dyn_buffer_data(dst) + start, explen - start);
  mtev_dyn_buffer_reset(dst);
  mtev_dyn_buffer_advance(dst, start + explen);
  mtev_dyn_buffer_add(dst, "", 0);
}
static int
http_reset_message(mtev_http_rest_closure_t *restc, int argc, char **argv) {
  (void)argc;
  (void)argv;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_dyn_buffer_t dst;
  mtev_dyn_buffer_init(&dst);
  build_login_buff(&dst, req);
  mtev_http_response_denied(ctx, "text/html");
  mtev_http_response_appendf(ctx, reset_template,
                             mtev_get_app_name(), mtev_http_request_user(req),
                             (char *)mtev_dyn_buffer_data(&dst));
  mtev_http_response_end(ctx);
  mtev_dyn_buffer_destroy(&dst);
  return 0;
}
static int
http_login_redirect(mtev_http_rest_closure_t *restc, int argc, char **argv) {
  (void)argc;
  (void)argv;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_dyn_buffer_t dst;
  mtev_dyn_buffer_init(&dst);
  build_login_buff(&dst, req);
  mtev_http_response_standard(ctx, 302, "REDIRECT", "text/html");
  mtev_http_response_header_set(ctx, "Location", (char *)mtev_dyn_buffer_data(&dst));
  mtev_http_response_end(ctx);
  mtev_dyn_buffer_destroy(&dst);
  return 0;
}

static mtev_hook_return_t
http_hmac_cookie_auth_denied(void *cl, mtev_http_rest_closure_t *restc, rest_request_handler *func) {
  (void)cl;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  const char *user = mtev_http_request_user(req);
  /* If the user is not set, then go to the login page. */
  if(!user) {
    *func = http_login_redirect;
    return MTEV_HOOK_DONE;
  }

  /* If the user is set, we were actually denied (not lacking auth), so provide
   * an option to the user to reset their cookie and log in again.
   */
  *func = http_reset_message;
  return MTEV_HOOK_DONE;
}
static mtev_hook_return_t
http_hmac_http_request_complete(void *cl, mtev_http_session_ctx *ctx) {
  (void)cl;
  mtev_http_request *req = mtev_http_session_request(ctx);
  mtev_hash_table *headers = mtev_http_request_headers_table(req);
  const char *cookie = mtev_hash_dict_get(headers,"cookie");
  if(cookie) {
    char *ccopy = strdup(cookie);
    char *part, *brk=NULL;
    for(part = strtok_r(ccopy, " ;", &brk); part; part = strtok_r(NULL, " ;", &brk)) {
      if(!strncmp(part, "mtevauth=", 9)) {
        part += 9;
        size_t roff = 0;
        size_t payload_len = mtev_url_max_decode_len(strlen(part));
        unsigned char *payload = malloc(payload_len);
        uint8_t part_l;
        unsigned char *part_u;
        char *part_s;
        payload_len = mtev_url_decode(part, strlen(part), payload, payload_len);
#define ADVPART(pname) do { \
  if(roff + 1 > payload_len) { \
    mtevL(debugls, "error reading %s len from signature\n", pname); \
    goto malformed; \
  } \
  part_l = payload[roff++]; \
  if(roff + part_l > payload_len) { \
    mtevL(debugls, "error reading %s from signature\n", pname); \
    goto malformed; \
  } \
  part_u = payload + roff; \
  part_s = (char *)part_u; \
  roff += part_l; \
} while(0)
        ADVPART("header");
        if(part_l != strlen(COOKIE_HEADER) || memcmp(part_s, COOKIE_HEADER, strlen(COOKIE_HEADER))) {
          mtevL(debugls, "not by cookie\n");
          goto malformed;
        }
        ADVPART("nonce");
        ADVPART("user");
        char user[257];
        memcpy(user, part_s, part_l);
        user[part_l] = '\0';
        ADVPART("auth");
        char auth[256];
        memcpy(auth, part_s, part_l);
        auth[part_l] = '\0';
        char timestr[257];
        ADVPART("expiry");
        memcpy(timestr, part_s, part_l);
        timestr[part_l] = '\0';
        uint64_t expiry = strtoull(timestr, NULL, 10);
        time_t now = time(NULL);
        if(now > 0 && expiry > (uint64_t)now) {
          char newsig[256];
          ssize_t slen = signit(payload, roff, newsig, sizeof(newsig));
          ADVPART("signature");
          if(slen == part_l && 0 == memcmp(newsig, part_u, slen)) {
            mtev_http_request_set_auth(req, user, auth);
          } else {
            mtevL(debugls, "auth signature invalid\n");
          }
        } else {
          mtevL(debugls, "auth signature expired\n");
        }

      malformed:
        free(payload);
        break;
      }
    }
    free(ccopy);
  }
  return MTEV_HOOK_CONTINUE;
}
static void
do_auth(void *cl) {
  struct rest_auth *ra = (struct rest_auth *)cl;
  mtevL(debugls, "Attempting asynch auth for hmac_cookie: %s\n", ra->user_in);
  mtev_http_session_ctx *ctx = ra->restc->http_ctx;
  switch(http_auth_hook_invoke(ctx, ra->user_in, ra->pass_in, &ra->error)) {
    case MTEV_HOOK_DONE:
      mtevL(debugls, "hook fired and finished\n");
      return;
    case MTEV_HOOK_ABORT:
      if(ra->error == NULL) ra->error = strdup("authentication error");
      mtevL(debugls, "hook fired and aborted\n");
      return;
    case MTEV_HOOK_CONTINUE: break;
  }
  mtevL(debugls, "hook fired and did nothing, fallback to testusers\n");
  const char *passcheck = mtev_hash_dict_get(&testusers, ra->user_in);
  if(passcheck && 0 == strcmp(passcheck, ra->pass_in)) {
    mtev_http_request_set_auth(mtev_http_session_request(ctx), ra->user_in, "hmac_cookie_test");
  }
}

static mtev_hook_return_t
http_hmac_http_refresh_cookie(void *cl, mtev_http_session_ctx *ctx) {
  (void)cl;
  mtev_http_request *req = mtev_http_session_request(ctx);
  const char *user = mtev_http_request_user(req);
  const char *auth = mtev_http_request_auth(req);
  if(user && auth) {
    time_t expires = time(NULL) + max_age;
    char timestr[64];
    snprintf(timestr, sizeof(timestr), "%zu", (size_t)expires);
    mtev_dyn_buffer_t cookie;
    mtev_dyn_buffer_t hdr;
    mtev_dyn_buffer_init(&cookie);
    mtev_dyn_buffer_init(&hdr);
    uint8_t len = strlen(COOKIE_HEADER);
    mtev_dyn_buffer_add(&cookie, &len, 1);
    mtev_dyn_buffer_add(&cookie, COOKIE_HEADER, len);
    unsigned char nonce[NONCE_LEN];
    len = sizeof(nonce);
    (void)mtev_rand_buf_secure(nonce, 8);
    mtev_dyn_buffer_add(&cookie, &len, 1);
    mtev_dyn_buffer_add(&cookie, nonce, len);
    len = strlen(user);
    mtev_dyn_buffer_add(&cookie, &len, 1);
    mtev_dyn_buffer_add(&cookie, user, len);
    len = strlen(auth);
    mtev_dyn_buffer_add(&cookie, &len, 1);
    mtev_dyn_buffer_add(&cookie, auth, len);
    len = strlen(timestr);
    mtev_dyn_buffer_add(&cookie, &len, 1);
    mtev_dyn_buffer_add(&cookie, timestr, len);

    size_t sign_len = mtev_dyn_buffer_used(&cookie);
    uint8_t *delayed_len = mtev_dyn_buffer_write_pointer(&cookie);
    mtev_dyn_buffer_add(&cookie, &len, 1); // this is the wrong len
    mtev_dyn_buffer_ensure(&cookie, 256);
    ssize_t slen = signit(mtev_dyn_buffer_data(&cookie), sign_len,
                          mtev_dyn_buffer_write_pointer(&cookie), 256);
    if(slen < 0 || slen > 256) {
      mtevL(debugls, "bad signature\n");
    }
    *delayed_len = (uint8_t)slen;
    mtev_dyn_buffer_advance(&cookie, slen);

    mtev_dyn_buffer_ensure(&cookie, mtev_url_encode_len(mtev_dyn_buffer_used(&cookie)));
    if(mtev_url_encode(mtev_dyn_buffer_data(&cookie), mtev_dyn_buffer_used(&cookie),
                       (char *)mtev_dyn_buffer_data(&cookie), mtev_dyn_buffer_size(&cookie)) == 0) {
      mtevL(debugls, "failed to encode signature\n");
      goto done;
    }
    mtev_dyn_buffer_add_printf(&hdr, "mtevauth=%s; Max-Age=%u",
                               (const char *)mtev_dyn_buffer_data(&cookie),
                               max_age);
    if(domain) {
      mtev_dyn_buffer_add_printf(&hdr, "; Domain=%s", domain);
    } else {
      mtev_hash_table *headers = mtev_http_request_headers_table(req);
      const char *host = mtev_hash_dict_get(headers,"host");
      if(host && NULL != (host = strchr(host, '.'))) {
        int hlen = strlen(host);
        const char *hlast = strrchr(host, ':');
        if(!hlast) hlast = host + hlen;
        hlast--;
        if(hlen > 2 && NULL!=strchr(host+1, '.') && isalpha(*hlast)) {
          /* it has to exist, have two dots, and end in a letter */
          mtev_dyn_buffer_add_printf(&hdr, "; Domain=%s", host+1);
        }
      }
    }
    mtev_http_response_header_set(ctx, "Set-Cookie", (const char *)mtev_dyn_buffer_data(&hdr));
  done:
    mtev_dyn_buffer_destroy(&cookie);
    mtev_dyn_buffer_destroy(&hdr);
  }
  return MTEV_HOOK_CONTINUE;
}

static int
http_login(mtev_http_rest_closure_t *restc, int argc, char **argv) {
  (void)argc;
  (void)argv;
  mtev_http_session_ctx *ctx = restc->http_ctx;
  mtev_http_request *req = mtev_http_session_request(ctx);
  int mask;
  char *buf = NULL;
  const char *user = NULL, *pass = NULL, *to = NULL;
  char *encoded_whereto = NULL, *error = NULL;
  if(!mtev_rest_complete_upload(restc, &mask)) return mask;

  int64_t size;
  const void *form = mtev_http_request_get_upload(req, &size);
  if(size && form) {
    char *kvp, *brk=NULL;
    mtevL(debugls, "auth form(%.*s)\n", (int)size, (const char *)form);
    buf = mtev_strndup(form, size);
    for(kvp = strtok_r(buf, "&", &brk); kvp; kvp = strtok_r(NULL, "&", &brk)) {
      char *val = strchr(kvp, '=');
      if(val) *val++ = '\0';
      int len = mtev_url_decode(kvp, strlen(kvp), (unsigned char *)kvp, strlen(kvp)+1);
      if(len > 0) {
        kvp[len] = '\0';
        if(val) {
          len = mtev_url_decode(val, strlen(val), (unsigned char *)val, strlen(val)+1);
          if(len < 0) val = NULL;
          else val[len] = '\0';
        }
        mtevL(debugls, "auth form (%s -> %s)\n", kvp, val);
        if(!strcmp(kvp, "username")) user = val;
        else if(!strcmp(kvp, "password")) pass = val;
        else if(!strcmp(kvp, "whereto")) to = val;
      }
    }

    if(user && pass) {
      struct rest_auth *ra = calloc(1, sizeof(*ra));
      ra->restc = restc;
      ra->user_in = user;
      ra->pass_in = pass;
      eventer_aco_simple_asynch(do_auth, ra);
      error = ra->error; /* this gets freed in done: */
      if(mtev_http_request_user(req) != NULL) {
        mtev_http_response_standard(ctx, 302, "REDIRECT", "text/html");
        mtev_http_response_header_set(ctx, "Location", (to && *to) ? to : "/");
        mtevL(debugls, "post-auth redirect -> (%s)\n", (to && *to) ? to : "/");
        mtev_http_response_end(ctx);
        goto done;
      }
      if(!error) error = strdup("authentication failed");
      free(ra);
    }
  }
  if(!to) to = mtev_http_request_querystring(req, "whereto");
  if(!to) to = "/";
  mtev_http_response_ok(ctx, "text/html");
  /* to needs to be html entity encoded */
  size_t html_to_len = mtev_html_encode_len(strlen(to));
  char *html_to = malloc(html_to_len);
  if(mtev_html_encode(to, strlen(to), html_to, html_to_len) <= 0) {
    strlcpy(html_to, "/", html_to_len);
  }
  mtev_http_response_appendf(ctx, login_template, mtev_get_app_name(), html_to, error ? error : "");
  mtev_http_response_end(ctx);
done:
  free(error);
  free(encoded_whereto);
  free(buf);
  return 0;
}
static int
http_hmac_cookie_config(mtev_dso_generic_t *img, mtev_hash_table *config) {
  (void)img;
  mtev_boolean key_set = mtev_false;
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(config, &iter)) {
    if(!strcmp(iter.key.str, "key")) {
      const char *b64_key = iter.value.str;
      if(b64_key) {
        int dlen = 0;
        memset(key, 0, sizeof(key));
        dlen = mtev_b64_decode(b64_key, strlen(b64_key), key, sizeof(key));
        if(dlen != sizeof(key)) {
          mtevL(errorls, "http_hmac_cookie key of wrong sie %d bytes, should be %d bytes\n",
                dlen, (int)sizeof(key));
          return -1;
        }
        key_set = mtev_true;
      }
    }
    else if(!strcmp(iter.key.str, "max_age")) {
      const char *max_age_str = iter.value.str;
      if(max_age_str) {
        max_age = strtoul(max_age_str, NULL, 10);
      }
    }
    else if(!strcmp(iter.key.str, "max_age")) {
      free(domain);
      domain = strdup(iter.value.str);
    }
    else if(!strncmp(iter.key.str, "user_", 5)) {
      const char *user = iter.key.str + 5;
      mtev_hash_replace(&testusers, strdup(user), strlen(user), strdup(iter.value.str), free, free);
    }
  }
  if(key_set == mtev_false) {
    if(mtev_rand_buf_secure(key, sizeof(key)) < sizeof(key)) {
      mtevL(errorls, "http_hmac_coookie insufficient entropy\n");
      return -1;
    }
  }
  return 0;
}
static int
http_hmac_cookie_onload(mtev_image_t *img) {
  (void)img;
  debugls = mtev_log_stream_find("debug/http/hmac_auth");
  errorls = mtev_log_stream_find("error/http/hmac_auth");
  mtev_hash_init(&testusers);
  return 0;
}
static int
http_hmac_cookie_init(mtev_dso_generic_t *img) {
  (void)img;
  mtev_rest_mountpoint_t *rule;

  rest_auth_denied_hook_register("http_hmac_cookie", http_hmac_cookie_auth_denied, NULL);
  http_request_complete_hook_register("http_hmac_cookie", http_hmac_http_request_complete, NULL);
  http_response_starting_hook_register("http_hmac_cookie", http_hmac_http_refresh_cookie, NULL);

  rule = mtev_http_rest_new_rule(
    "GET", "/", "login", http_login
  );
  mtev_rest_mountpoint_set_aco(rule, mtev_true);
  rule = mtev_http_rest_new_rule(
    "POST", "/", "login", http_login
  );
  mtev_rest_mountpoint_set_aco(rule, mtev_true);

  hmac_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, sizeof(key));
  if(!hmac_key) {
    mtevL(errorls, "Failed to establish HMAC key for mtev_hmac_cookie module\n");
    return -1;
  }
  md = EVP_sha256();
  if(!md) {
    mtevL(errorls, "Failed to load SHA265 HMAC\n");
    return -1;
  }
  return 0;
}

#include "http_hmac_cookie.xmlh"

mtev_dso_generic_t http_hmac_cookie = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "http_observer",
    .description = "An hmac-cookie based authentication engine",
    .xml_description = http_hmac_cookie_xml_description,
    .onload = http_hmac_cookie_onload,
  },
  http_hmac_cookie_config,
  http_hmac_cookie_init
};
