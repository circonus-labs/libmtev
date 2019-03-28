/*
 * Copyright (c) 2010, OmniTI Computer Consulting, Inc.
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

#include <math.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include "mtev_conf.h"

#include "lua_mtev.h"
#include <udns.h>

static mtev_hash_table dns_rtypes;
static mtev_hash_table dns_ctypes;
static __thread mtev_hash_table *dns_ctx_store = NULL;

typedef struct dns_ctx_handle {
  char *ns;
  struct dns_ctx *ctx;
  uint32_t refcnt;
  eventer_t e; /* eventer handling UDP traffic */
  eventer_t timeout; /* the timeout managed by libudns */
} dns_ctx_handle_t;

typedef struct dns_lookup_ctx {
  mtev_lua_resume_info_t *ci;
  dns_ctx_handle_t *h;
  char *error;
  char *results;
  int results_len;
  unsigned char dn[DNS_MAXDN];
  enum dns_class query_ctype;
  enum dns_type query_rtype;
  int active;
  int in_lua;         /* If we're in a lua C call */
  int in_lua_direct;  /* Should we return or yield */
  int in_lua_nrr;     /* possible return val */
  uint32_t refcnt;
} dns_lookup_ctx_t;

static __thread dns_ctx_handle_t *default_ctx_handle = NULL;

static int mtev_lua_dns_eventer(eventer_t e, int mask, void *closure,
                                struct timeval *now) {
  (void)e;
  (void)mask;
  dns_ctx_handle_t *h = closure;
  dns_ioevent(h->ctx, now->tv_sec);
  return EVENTER_READ | EVENTER_EXCEPTION;
}

static int mtev_lua_dns_timeouts(eventer_t e, int mask, void *closure,
                                 struct timeval *now) {
  (void)mask;
  dns_ctx_handle_t *h = closure;
  mtevAssert(h->timeout == e);
  h->timeout = NULL; /* freed upon return */
  dns_timeouts(h->ctx, 0, now->tv_sec);
  return 0;
}

static void eventer_dns_utm_fn(struct dns_ctx *ctx, int timeout, void *data) {
  dns_ctx_handle_t *h = data;
  if(h == NULL) return;
  if(h->timeout) {
    eventer_remove(h->timeout);
    eventer_free(h->timeout);
    h->timeout = NULL;
  }
  if(ctx == NULL) return;

  mtevAssert(h->ctx == ctx);
  if(timeout < 0) return;
  h->timeout = eventer_in_s_us(mtev_lua_dns_timeouts, h, timeout, 0);
  eventer_add(h->timeout);
}

static void dns_ctx_handle_free(void *vh) {
  dns_ctx_handle_t *h = vh;
  free(h->ns);
  eventer_remove_fde(h->e);
  eventer_free(h->e);
  h->e = NULL;
  if(h->timeout) {
    eventer_remove(h->timeout);
    eventer_free(h->timeout);
    h->timeout = NULL;
  }
  dns_close(h->ctx);
  dns_free(h->ctx);
  mtevAssert(h->timeout == NULL);
  free(h);
}

static dns_ctx_handle_t *dns_ctx_alloc(const char *ns) {
  void *vh;
  dns_ctx_handle_t *h = NULL;
  if(!dns_ctx_store) dns_ctx_store = calloc(1, sizeof(*dns_ctx_store));
  if(ns == NULL && default_ctx_handle != NULL) {
    /* special case -- default context */
    h = default_ctx_handle;
    ck_pr_inc_32(&h->refcnt);
    goto bail;
  }
  if(ns &&
     mtev_hash_retrieve(dns_ctx_store, ns, strlen(ns), &vh)) {
    h = (dns_ctx_handle_t *)vh;
    ck_pr_inc_32(&h->refcnt);
  }
  else {
    int failed = 0;
    h = calloc(1, sizeof(*h));
    h->ns = ns ? strdup(ns) : NULL;
    h->ctx = dns_new(NULL);
    if(dns_init(h->ctx, 0) != 0) failed++;
    if(ns) {
      if(dns_add_serv(h->ctx, NULL) < 0) failed++;
      if(dns_add_serv(h->ctx, ns) < 0) failed++;
    }
    if(dns_open(h->ctx) < 0) failed++;
    if(failed) {
      mtevL(mtev_error, "dns_open failed\n");
      free(h->ns);
      free(h);
      h = NULL;
      goto bail;
    }
    dns_set_tmcbck(h->ctx, eventer_dns_utm_fn, h);
    h->e = eventer_alloc_fd(mtev_lua_dns_eventer, h, dns_sock(h->ctx),
                            EVENTER_READ | EVENTER_EXCEPTION);
    eventer_add(h->e);
    h->refcnt = 1;
    if(!ns)
      default_ctx_handle = h;
    else
      mtev_hash_store(dns_ctx_store, h->ns, strlen(h->ns), h);
  }
 bail:
  return h;
}

static void dns_ctx_release(dns_ctx_handle_t *h) {
  if(h->ns == NULL) {
    /* Special case for the default */
    ck_pr_dec_32(&h->refcnt);
    return;
  }
  if(!dns_ctx_store) dns_ctx_store = calloc(1, sizeof(*dns_ctx_store));
  bool zero;
  ck_pr_dec_32_zero(&h->refcnt, &zero);
  if(zero) {
    /* I was the last one */
    mtevAssert(mtev_hash_delete(dns_ctx_store, h->ns, strlen(h->ns),
                            NULL, dns_ctx_handle_free));
  }
}

void lookup_ctx_release(dns_lookup_ctx_t *v) {
  if(!v) return;
  bool zero;
  ck_pr_dec_32_zero(&v->refcnt, &zero);
  if(zero) {
    if(v->results) free(v->results);
    v->results = NULL;
    if(v->error) free(v->error);
    v->error = NULL;
    dns_ctx_release(v->h);
    free(v);
  }
}
/*! \lua mtev.dns = mtev.dns(nameserver = nil)
\brief Create an `mtev.dns` object for DNS lookups.
\param nameserver an optional argument specifying the nameserver to use.
\return an `mtev.dns` object.

This function creates an `mtev.dns` object that can be used to perform
lookups and IP address validation.
*/
int nl_dns_lookup(lua_State *L) {
  dns_lookup_ctx_t *dlc, **holder;
  const char *nameserver = NULL;
  mtev_lua_resume_info_t *ci;

  ci = mtev_lua_get_resume_info(L);
  mtevAssert(ci);
  if(lua_gettop(L) > 0)
    nameserver = lua_tostring(L, 1);
  holder = (dns_lookup_ctx_t **)lua_newuserdata(L, sizeof(*holder));
  dlc = calloc(1, sizeof(*dlc));
  dlc->refcnt = 1;
  dlc->ci = ci;
  dlc->h = dns_ctx_alloc(nameserver);
  *holder = dlc;
  luaL_getmetatable(L, "mtev.dns");
  lua_setmetatable(L, -2);
  return 1;
}

static char *encode_txt(char *dst, const unsigned char *src, int len) {
  int i;
  for(i=0; i<len; i++) {
    if(src[i] >= 127 || src[i] <= 31) {
      snprintf(dst, 4, "\\%02x", src[i]);
      dst += 3;
    }
    else if(src[i] == '\\') {
      *dst++ = '\\';
      *dst++ = '\\';
    }
    else {
      *dst++ = (char)src[i];
    }
  }
  *dst = '\0';
  return dst;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
static void dns_resume(dns_lookup_ctx_t *dlc) {
  int r = dlc->results_len;
  void *result = dlc->results;
  struct dns_parse p;
  struct dns_rr rr;
  unsigned nrr = 0;
  unsigned char dn[DNS_MAXDN];
  const unsigned char *pkt, *cur, *end;
  lua_State *L;

  dlc->results = NULL; /* We will free 'result' in cleanup */
  if(!dlc->active) goto cleanup;
  if(!result) goto cleanup;

  L = dlc->ci->coro_state;

  pkt = result; end = pkt + r; cur = dns_payload(pkt);
  dns_getdn(pkt, &cur, end, dn, sizeof(dn));
  dns_initparse(&p, NULL, pkt, cur, end);
  p.dnsp_qcls = 0;
  p.dnsp_qtyp = 0;

  while(dns_nextrr(&p, &rr) > 0) {
    const char *fieldname = NULL;
    char buff[DNS_MAXDN], *txt_str, *c;
    int totalsize;
    const unsigned char *pkt = p.dnsp_pkt;
    const unsigned char *end = p.dnsp_end;
    const unsigned char *dptr = rr.dnsrr_dptr;
    const unsigned char *dend = rr.dnsrr_dend;
    unsigned char *dn = rr.dnsrr_dn;
    const unsigned char *tmp;

    memset(buff, 0, sizeof(buff));

    if (!dns_dnequal(dn, rr.dnsrr_dn)) continue;
    if ((dlc->query_ctype == DNS_C_ANY || dlc->query_ctype == rr.dnsrr_cls) &&
        (dlc->query_rtype == DNS_T_ANY || dlc->query_rtype == rr.dnsrr_typ)) {
      lua_newtable(L);
      lua_pushinteger(L, rr.dnsrr_ttl);
      lua_setfield(L, -2, "ttl");

      switch(rr.dnsrr_typ) {
        case DNS_T_A:
          if(rr.dnsrr_dsz == 4) {
            snprintf(buff, sizeof(buff), "%d.%d.%d.%d",
                     dptr[0], dptr[1], dptr[2], dptr[3]);
            lua_pushstring(L, buff);
            lua_setfield(L, -2, "a");
          }
          break;

        case DNS_T_AAAA:
          if(rr.dnsrr_dsz == 16) {
            inet_ntop(AF_INET6, dptr, buff, 16);
            lua_pushstring(L, buff);
            lua_setfield(L, -2, "aaaa");
          }
          break;

        case DNS_T_TXT:
          totalsize = 0;
          for(tmp = dptr; tmp < dend; totalsize += *tmp, tmp += *tmp + 1)
            if(tmp + *tmp + 1 > dend) break;
          /* worst case: every character escaped + '\0' */
          txt_str = alloca(totalsize * 3 + 1);
          if(!txt_str) break;
          c = txt_str;
          for(tmp = dptr; tmp < dend; tmp += *tmp + 1)
            c = encode_txt(c, tmp+1, *tmp);
          lua_pushstring(L, txt_str);
          lua_setfield(L, -2, "txt");
          break;

        case DNS_T_MX:
          lua_pushinteger(L, dns_get16(dptr));
          lua_setfield(L, -2, "preference");
          tmp = dptr + 2;
          if(dns_getdn(pkt, &tmp, end, dn, DNS_MAXDN) <= 0 || tmp != dend)
            break;
          dns_dntop(dn, buff + strlen(buff), sizeof(buff) - strlen(buff));
          lua_pushstring(L, buff);
          lua_setfield(L, -2, "mx");
          break;

        case DNS_T_CNAME: if(!fieldname) fieldname = "cname";
        case DNS_T_PTR: if(!fieldname) fieldname = "ptr";
        case DNS_T_NS: if(!fieldname) fieldname = "ns";
        case DNS_T_MB: if(!fieldname) fieldname = "mb";
        case DNS_T_MD: if(!fieldname) fieldname = "md";
        case DNS_T_MF: if(!fieldname) fieldname = "mf";
        case DNS_T_MG: if(!fieldname) fieldname = "mg";
        case DNS_T_MR: if(!fieldname) fieldname = "mr";
         if(dns_getdn(pkt, &dptr, end, dn, DNS_MAXDN) <= 0) break;
         dns_dntop(dn, buff, sizeof(buff));
         lua_pushstring(L, buff);
         lua_setfield(L, -2, fieldname);
         break;

        default:
          break;
      }
      ++nrr;
    }
    else if (rr.dnsrr_typ == DNS_T_CNAME && !nrr) {
      if (dns_getdn(pkt, &rr.dnsrr_dptr, end,
                    p.dnsp_dnbuf, sizeof(p.dnsp_dnbuf)) <= 0 ||
          rr.dnsrr_dptr != rr.dnsrr_dend) {
        break;
      }
    }
  }

 cleanup:
  if(result) free(result);
  if(dlc->active) {
    if(dlc->in_lua) {
      dlc->in_lua_direct = 1;
      dlc->in_lua_nrr = nrr;
    }
    else dlc->ci->lmc->resume(dlc->ci, nrr);
  }
  lookup_ctx_release(dlc);
}
static int dns_resume_event(eventer_t e, int mask, void *closure,
                            struct timeval *now) {
  (void)e;
  (void)mask;
  (void)now;
  dns_resume(closure);
  return 0;
}
#pragma GCC diagnostic push

static void dns_cb(struct dns_ctx *ctx, void *result, void *data) {
  eventer_t e;
  int r = dns_status(ctx);
  dns_lookup_ctx_t *dlc = data;
  if(dlc->results) free(dlc->results);
  dlc->results = NULL;
  if (r == 0) {
    dlc->results_len = r;
  }
  else if (r > 0) {
    dlc->results_len = r;
    dlc->results = result;
  }
  if(pthread_equal(dlc->ci->bound_thread, pthread_self()))
    return dns_resume(dlc);

  if(dlc->active) {
    mtevL(mtev_error, "lua_dns cross-thread resume (should never happend)\n");
    /* We need to schedule this to run on another eventer thread */
    e = eventer_in_s_us(dns_resume_event, dlc, 0, 0);
    eventer_set_owner(e, dlc->ci->bound_thread);
    eventer_add(e);
  }
  lookup_ctx_release(dlc);
}

/*! \lua bool, family = mtev.dns:is_valid_ip(ipstr)
\brief Determine address family of an IP address.
\param ipstr a string of an potential IP address.
\return if the address is valid and, if it is, the family.

The first return is true if the suplied string is a valid IPv4 or IPv6
address, otherwise false.  If the address is valid, the second argument
will be the address family as an integer, otherwise nil.
*/
int
mtev_dns_lua_is_valid_ip(lua_State *L) {
  int8_t family;
  int rv;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } a;

  const char *target = lua_tostring(L,1);
  if(!target) {
    lua_pushboolean(L, 0);
    lua_pushnil(L);
    return 2;
  }

  family = AF_INET;
  rv = inet_pton(family, target, &a);
  if(rv != 1) {
    family = AF_INET6;
    rv = inet_pton(family, target, &a);
    if(rv != 1) {
      lua_pushboolean(L, 0);
      lua_pushnil(L);
      return 2;
    }
  }
  lua_pushboolean(L, 1);
  lua_pushinteger(L, family);
  return 2;
}

/*! \lua record = mtev.dns:lookup(query, rtype = "A", ctype = "IN")
\brief Perform a DNS lookup.
\param query a string representing the DNS query.
\param rtype the DNS resource type (default "A").
\param ctype the DNS class type (default "IN").
\return a lua table, nil if the lookup fails.

DNS lookup works cooperatively with the eventer to schedule an
lookup and yield the current coroutine to the event loop.  If
successful the table returned will contain field(s) for the
requested resource. Possible fields are:

* `a` and `ttl`
* `aaaa` and `ttl`
* `mx` and `preference`
* `cname` and `ttl`
* `ptr` and `ttl`
* `ns` and `ttl`
* `mb` and `ttl`
* `md` and `ttl`
* `mf` and `ttl`
* `mg` and `ttl`
* `mr` and `ttl`
*/
static int mtev_lua_dns_lookup(lua_State *L) {
  dns_lookup_ctx_t *dlc, **holder;
  const char *c, *query = "", *ctype = "IN", *rtype = "A";
  char *ctype_up, *rtype_up, *d;
  void *vnv_pair;
  mtev_lua_resume_info_t *ci;
  int rv;

  ci = mtev_lua_get_resume_info(L);
  mtevAssert(ci);

  holder = (dns_lookup_ctx_t **)lua_touserdata(L, lua_upvalueindex(1));
  if(holder != lua_touserdata(L,1))
    luaL_error(L, "Must be called as method\n");
  dlc = *holder;

  if(lua_gettop(L) > 1) query = lua_tostring(L, 2);
  if(lua_gettop(L) > 2) rtype = lua_tostring(L, 3);
  if(lua_gettop(L) > 3) ctype = lua_tostring(L, 4);

  if(query == NULL || rtype == NULL || ctype == NULL) {
    lua_pushnil(L);
    return 1;
  }

  dlc->in_lua = 1;
  /* We own this at least until return */
  ck_pr_inc_32(&dlc->refcnt);

  ctype_up = alloca(strlen(ctype)+1);
  for(d = ctype_up, c = ctype; *c; d++, c++) *d = toupper(*c);
  *d = '\0';
  rtype_up = alloca(strlen(rtype)+1);
  for(d = rtype_up, c = rtype; *c; d++, c++) *d = toupper(*c);
  *d = '\0';

  if(!mtev_hash_retrieve(&dns_ctypes, ctype_up, strlen(ctype_up), &vnv_pair))
    dlc->error = strdup("bad class");
  else
    dlc->query_ctype = (enum dns_class)((struct dns_nameval *)vnv_pair)->val;

  if(!mtev_hash_retrieve(&dns_rtypes, rtype_up, strlen(rtype_up), &vnv_pair)) 
    dlc->error = strdup("bad rr type");
  else
    dlc->query_rtype = (enum dns_type)((struct dns_nameval *)vnv_pair)->val;

  dlc->active = 1;
  ck_pr_inc_32(&dlc->refcnt);
  if(!dlc->error) {
    int abs;
    if(!dns_ptodn(query, strlen(query), dlc->dn, sizeof(dlc->dn), &abs) ||
       !dns_submit_dn(dlc->h->ctx, dlc->dn, dlc->query_ctype, dlc->query_rtype,
                      abs | DNS_NOSRCH, NULL, dns_cb, dlc)) {
      dlc->error = strdup("submission error");
    }
    else {
      /* There is potential that dlc->h was set to NULL as a side-effet of the
       * dns_cb callback within dns_submit_db in the prior predicate */
      if(dlc->h) {
        struct timeval now;
        mtev_gettimeofday(&now, NULL);
        dns_timeouts(dlc->h->ctx, -1, now.tv_sec);
      }
    }
  }
  if(dlc->error) {
    dlc->active = 0;
    luaL_error(L, "dns: %s\n", dlc->error);
    lookup_ctx_release(dlc);
  }
  if(dlc->in_lua_direct) {
    rv = dlc->in_lua_nrr;
  }
  else {
    rv = mtev_lua_yield(ci, 0);
  }

  dlc->in_lua_direct = dlc->in_lua_nrr = dlc->in_lua = 0;
  lookup_ctx_release(dlc);
  return rv;
}

int mtev_lua_dns_gc(lua_State *L) {
  dns_lookup_ctx_t **holder;
  holder = (dns_lookup_ctx_t **)lua_touserdata(L,1);
  (*holder)->active = 0;
  lookup_ctx_release(*holder);
  return 0;
}

int mtev_lua_dns_index_func(lua_State *L) {
  int n;
  const char *k;
  dns_lookup_ctx_t **udata;

  n = lua_gettop(L);
  mtevAssert(n == 2);
  if(!luaL_checkudata(L, 1, "mtev.dns"))
    luaL_error(L, "metatable error, arg1 is not a mtev.dns");
  udata = lua_touserdata(L, 1);
  if(!lua_isstring(L, 2))
    luaL_error(L, "metatable error, arg2 is not a string");
  k = lua_tostring(L, 2);
  if(!strcmp(k, "is_valid_ip")) {
    lua_pushcclosure(L, mtev_dns_lua_is_valid_ip, 0);
    return 1;
  }
  if(!strcmp(k, "lookup")) {
    lua_pushlightuserdata(L, udata);
    lua_pushcclosure(L, mtev_lua_dns_lookup, 1);
    return 1;
  }
  luaL_error(L, "mtev.dns no such element: %s", k);
  return 0;
}

void mtev_lua_init_dns_globals(void) {
  mtev_hash_init_locks(&dns_rtypes, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  mtev_hash_init_locks(&dns_ctypes, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
}

void mtev_lua_init_dns(void) {
  int i;
  const struct dns_nameval *nv;
  struct dns_ctx *pctx;

  mtev_lua_init_dns_globals();

  /* HASH the rr types */
  for(i=0, nv = &dns_typetab[i]; nv->name; nv = &dns_typetab[++i])
    mtev_hash_store(&dns_rtypes,
                    nv->name, strlen(nv->name),
                    (void *)nv);
  /* HASH the class types */
  for(i=0, nv = &dns_classtab[i]; nv->name; nv = &dns_classtab[++i])
    mtev_hash_store(&dns_ctypes,
                    nv->name, strlen(nv->name),
                    (void *)nv);

  eventer_name_callback("lua/dns_eventer", mtev_lua_dns_eventer);
  eventer_name_callback("lua/dns_timeouts", mtev_lua_dns_timeouts);

  if (dns_init(NULL, 0) < 0 || (pctx = dns_new(NULL)) == NULL) {
    mtevL(mtev_error, "Unable to initialize dns subsystem\n");
  }
  else
    dns_free(pctx);
}

