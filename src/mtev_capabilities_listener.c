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
#include "mtev_version.h"
#include "eventer/eventer.h"
#include "mtev_listener.h"
#include "mtev_hash.h"
#include "mtev_log.h"
#include "mtev_sem.h"
#include "mtev_capabilities_listener.h"
#include "mtev_xml.h"
#include "mtev_rest.h"
#include "mtev_dso.h"
#include "mtev_json.h"
#include "mtev_console.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/utsname.h>

#include <libxml/xmlsave.h>
#include <libxml/tree.h>

static char *capabilities_namespace = "mtev_capabilities";

void mtev_capabilities_set_namespace(char *c) {
  capabilities_namespace = c;
}

typedef struct mtev_capsvc_closure {
  char *buff;
  size_t written;
  size_t towrite;
} mtev_capsvc_closure_t;

static mtev_hash_table features;
static int
  mtev_capabilities_rest(mtev_http_rest_closure_t *, int, char **);
static void
  mtev_capabilities_tobuff(mtev_capsvc_closure_t *, eventer_func_t);
static void
  mtev_capabilities_tobuff_json(mtev_capsvc_closure_t *, eventer_func_t);

void
mtev_capabilities_listener_init() {
  eventer_name_callback("capabilities_transit/1.0", mtev_capabilities_handler);
  mtev_control_dispatch_delegate(mtev_control_dispatch,
                                 MTEV_CAPABILITIES_SERVICE,
                                 mtev_capabilities_handler);
  mtevAssert(mtev_http_rest_register("GET", "/", "capa(\\.json)?",
                                 mtev_capabilities_rest) == 0);
}

void
mtev_capabilities_add_feature(const char *feature, const char *version) {
  feature = strdup(feature);
  if(version) version = strdup(version);
  if(!mtev_hash_store(&features, feature, strlen(feature), (void *)version))
    mtevL(mtev_error, "Feature conflict! %s version %s\n",
          feature, version ? version : "unpecified");
}

const mtev_hash_table *
mtev_capabilities_get_features()
{
  return &features;
}

static int
mtev_capabilities_rest(mtev_http_rest_closure_t *restc, int n, char **p) {
  mtev_capsvc_closure_t cl = { 0 };
  const char *mtype = "application/xml";
  if(n > 0 && !strcmp(p[0], ".json")) {
    mtev_capabilities_tobuff_json(&cl, NULL);
    mtype = "application/json";
  }
  else mtev_capabilities_tobuff(&cl, NULL);
  if(!cl.buff) goto error;
  mtev_http_response_ok(restc->http_ctx, mtype);
  mtev_http_response_append(restc->http_ctx, cl.buff, cl.towrite);
  mtev_http_response_end(restc->http_ctx);
  free(cl.buff);
  return 0;

 error:
  mtev_http_response_server_error(restc->http_ctx, "text/html");
  mtev_http_response_end(restc->http_ctx);
  return 0;
}

void
mtev_capabilities_features_ncprint(mtev_console_closure_t ncct) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  while(mtev_hash_adv(&features, &iter)) {
    if(iter.value.str)
      nc_printf(ncct, "feature:\t%s:%s\n", iter.key.str, iter.value.str);
    else
      nc_printf(ncct, "feature:\t%s\n", iter.key.str);
  }
}

static void
mtev_capabilities_tobuff_json(mtev_capsvc_closure_t *cl, eventer_func_t curr) {
    const char **mod_names;
    struct utsname utsn;
    char vbuff[128];
    mtev_hash_table *lc;
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    int i, nmods;
    struct timeval now;
    struct dso_type *t;

    mtev_json_object *doc, *svcs, *bi, *ri, *mods, *feat;

    /* fill out capabilities */
    doc = MJ_OBJ();

    /* Fill in the document */
    mtev_build_version(vbuff, sizeof(vbuff));
    MJ_KV(doc, "version", MJ_STR(vbuff));

    /* Build info */
    MJ_KV(doc, "unameBuild", bi = MJ_OBJ());
    MJ_KV(bi, "bitwidth", MJ_INT(sizeof(void *)*8));
    MJ_KV(bi, "sysname", MJ_STR(UNAME_S));
    MJ_KV(bi, "nodename", MJ_STR(UNAME_N));
    MJ_KV(bi, "release", MJ_STR(UNAME_R));
    MJ_KV(bi, "version", MJ_STR(UNAME_V));
    MJ_KV(bi, "machine", MJ_STR(UNAME_M));

    /* Run info */
    MJ_KV(doc, "unameRun", ri = MJ_OBJ());
    MJ_KV(ri, "bitwidth", MJ_INT(sizeof(void *)*8));
    if(uname(&utsn) < 0) {
      MJ_KV(ri, "error", MJ_STR(strerror(errno)));
    } else {
      MJ_KV(ri, "sysname", MJ_STR(utsn.sysname));
      MJ_KV(ri, "nodename", MJ_STR(utsn.nodename));
      MJ_KV(ri, "release", MJ_STR(utsn.release));
      MJ_KV(ri, "version", MJ_STR(utsn.version));
      MJ_KV(ri, "machine", MJ_STR(utsn.machine));
    }

    /* features */
    MJ_KV(doc, "features", feat = MJ_OBJ());
    if(mtev_hash_size(&features)) {
      mtev_hash_iter iter2 = MTEV_HASH_ITER_ZERO;
      while(mtev_hash_adv(&features, &iter2)) {
        mtev_json_object *featnode;
        MJ_KV(feat, iter2.key.str, featnode = MJ_OBJ());
        if(iter2.value.str) MJ_KV(featnode, "version", MJ_STR(iter2.value.str));
      }
    }

    /* time (poor man's time check) */
    mtev_gettimeofday(&now, NULL);
    MJ_KV(doc, "current_time", MJ_UINT64((now.tv_sec*1000) + (now.tv_usec/1000)));

    lc = mtev_listener_commands();
    MJ_KV(doc, "services", svcs = MJ_OBJ());
    while(mtev_hash_adv(lc, &iter)) {
      mtev_json_object *cnode, *cmds;
      char hexcode[11];
      const char *name;
      eventer_func_t *f = (eventer_func_t *)iter.key.ptr;
      mtev_hash_table *sc = (mtev_hash_table *)iter.value.ptr;
      mtev_hash_iter sc_iter = MTEV_HASH_ITER_ZERO;

      name = eventer_name_for_callback(*f);
      if(iter.klen == 8)
        snprintf(hexcode, sizeof(hexcode), "0x%0llx",
                 (unsigned long long int)(uintptr_t)**f);
      else
        snprintf(hexcode, sizeof(hexcode), "0x%0x",
                 (unsigned int)(uintptr_t)**f);
      MJ_KV(svcs, hexcode, cnode = MJ_OBJ());
      if(name) MJ_KV(cnode, name, MJ_STR(name));
      MJ_KV(cnode, "commands", cmds = MJ_OBJ());
      while(mtev_hash_adv(sc, &sc_iter)) {
        mtev_json_object *scnode;
        char *name_copy, *version = NULL;
        eventer_func_t *f = (eventer_func_t *)sc_iter.value.ptr;

        snprintf(hexcode, sizeof(hexcode), "0x%08x", *((uint32_t *)sc_iter.key.ptr));
        name = eventer_name_for_callback(*f);
        name_copy = strdup(name ? name : "[[unknown]]");
        version = strchr(name_copy, '/');
        if(version) *version++ = '\0';

        MJ_KV(cmds, hexcode, scnode = MJ_OBJ());
        MJ_KV(scnode, "name", MJ_STR(name_copy));
        if(version) MJ_KV(scnode, "version", MJ_STR(version));
        free(name_copy);
      }
    }

    MJ_KV(doc, "modules", mods = MJ_OBJ());

#define list_modules_json(func, name) do { \
    nmods = func(&mod_names); \
    for(i=0; i<nmods; i++) { \
      mtev_json_object *pnode; \
      MJ_KV(mods, mod_names[i], pnode = MJ_OBJ()); \
      MJ_KV(pnode, "type", MJ_STR(name)); \
    } \
    if(mod_names) free(mod_names); \
} while(0)

    for(t = mtev_dso_get_types(); t; t = t->next) {
      list_modules_json(t->list, t->name);
    }

    /* Write it out to a buffer and copy it for writing */
    cl->buff = strdup(mtev_json_object_to_json_string(doc));
    cl->towrite = strlen(cl->buff);

    /* Clean up after ourselves */
    MJ_DROP(doc);
}
static void
mtev_capabilities_tobuff(mtev_capsvc_closure_t *cl, eventer_func_t curr) {
    const char **mod_names;
    struct utsname utsn;
    char vbuff[128], bwstr[4];
    mtev_hash_table *lc;
    mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
    int i, nmods;
    struct timeval now;
    struct dso_type *t;

    xmlDocPtr xmldoc;
    xmlNodePtr root, cmds, bi, ri, mods, feat;

    /* fill out capabilities */

    /* Create an XML Document */
    xmldoc = xmlNewDoc((xmlChar *)"1.0");
    root = xmlNewDocNode(xmldoc, NULL, (xmlChar *)capabilities_namespace, NULL);
    xmlDocSetRootElement(xmldoc, root);

    /* Fill in the document */
    mtev_build_version(vbuff, sizeof(vbuff));
    xmlNewTextChild(root, NULL, (xmlChar *)"version", (xmlChar *)vbuff);

    snprintf(bwstr, sizeof(bwstr), "%d", (int)sizeof(void *)*8);
    /* Build info */
    bi = xmlNewNode(NULL, (xmlChar *)"unameBuild");
    xmlSetProp(bi, (xmlChar *)"bitwidth", (xmlChar *)bwstr);
    xmlAddChild(root, bi);
    xmlNewTextChild(bi, NULL, (xmlChar *)"sysname", (xmlChar *)UNAME_S);
    xmlNewTextChild(bi, NULL, (xmlChar *)"nodename", (xmlChar *)UNAME_N);
    xmlNewTextChild(bi, NULL, (xmlChar *)"release", (xmlChar *)UNAME_R);
    xmlNewTextChild(bi, NULL, (xmlChar *)"version", (xmlChar *)UNAME_V);
    xmlNewTextChild(bi, NULL, (xmlChar *)"machine", (xmlChar *)UNAME_M);

    /* Run info */
    ri = xmlNewNode(NULL, (xmlChar *)"unameRun");
    xmlSetProp(ri, (xmlChar *)"bitwidth", (xmlChar *)bwstr);
    xmlAddChild(root, ri);
    if(uname(&utsn) < 0) {
      xmlNewTextChild(ri, NULL, (xmlChar *)"error", (xmlChar *)strerror(errno));
    } else {
      xmlNewTextChild(ri, NULL, (xmlChar *)"sysname", (xmlChar *)utsn.sysname);
      xmlNewTextChild(ri, NULL, (xmlChar *)"nodename", (xmlChar *)utsn.nodename);
      xmlNewTextChild(ri, NULL, (xmlChar *)"release", (xmlChar *)utsn.release);
      xmlNewTextChild(ri, NULL, (xmlChar *)"version", (xmlChar *)utsn.version);
      xmlNewTextChild(ri, NULL, (xmlChar *)"machine", (xmlChar *)utsn.machine);
    }

    /* features */
    feat = xmlNewNode(NULL, (xmlChar *)"features");
    xmlAddChild(root, feat);
    if(mtev_hash_size(&features)) {
      mtev_hash_iter iter2 = MTEV_HASH_ITER_ZERO;
      while(mtev_hash_adv(&features, &iter2)) {
        xmlNodePtr featnode;
        featnode = xmlNewNode(NULL, (xmlChar *)"feature");
        xmlSetProp(featnode, (xmlChar *)"name", (xmlChar *)iter2.key.str);
        if(iter2.value.str)
          xmlSetProp(featnode, (xmlChar *)"version", (xmlChar *)iter2.value.str);
        xmlAddChild(feat, featnode);
      }
    }

    /* time (poor man's time check) */
    mtev_gettimeofday(&now, NULL);
    snprintf(vbuff, sizeof(vbuff), "%llu.%03d", (unsigned long long)now.tv_sec,
             (int)(now.tv_usec / 1000));
    xmlNewTextChild(root, NULL, (xmlChar *)"current_time", (xmlChar *)vbuff);

    cmds = xmlNewNode(NULL, (xmlChar *)"services");
    xmlAddChild(root, cmds);
    lc = mtev_listener_commands();
    while(mtev_hash_adv(lc, &iter)) {
      xmlNodePtr cnode;
      char hexcode[11];
      const char *name;
      eventer_func_t *f = (eventer_func_t *)iter.key.ptr;
      mtev_hash_table *sc = (mtev_hash_table *)iter.value.ptr;
      mtev_hash_iter sc_iter = MTEV_HASH_ITER_ZERO;

      name = eventer_name_for_callback(*f);
      cnode = xmlNewNode(NULL, (xmlChar *)"service");
      xmlSetProp(cnode, (xmlChar *)"name", name ? (xmlChar *)name : NULL);
      if(*f == curr)
        xmlSetProp(cnode, (xmlChar *)"connected", (xmlChar *)"true");
      xmlAddChild(cmds, cnode);
      while(mtev_hash_adv(sc, &sc_iter)) {
        xmlNodePtr scnode;
        char *name_copy, *version = NULL;
        eventer_func_t *f = (eventer_func_t *)sc_iter.value.ptr;

        snprintf(hexcode, sizeof(hexcode), "0x%08x", *((uint32_t *)sc_iter.key.ptr));
        name = eventer_name_for_callback(*f);
        name_copy = strdup(name ? name : "[[unknown]]");
        version = strchr(name_copy, '/');
        if(version) *version++ = '\0';

        scnode = xmlNewNode(NULL, (xmlChar *)"command");
        xmlSetProp(scnode, (xmlChar *)"name", (xmlChar *)name_copy);
        if(version)
          xmlSetProp(scnode, (xmlChar *)"version", (xmlChar *)version);
        xmlSetProp(scnode, (xmlChar *)"code", (xmlChar *)hexcode);
        xmlAddChild(cnode, scnode);
        free(name_copy);
      }
    }

    mods = xmlNewNode(NULL, (xmlChar *)"modules");
    xmlAddChild(root, mods);

#define list_modules(func, name) do { \
    nmods = func(&mod_names); \
    for(i=0; i<nmods; i++) { \
      xmlNodePtr pnode; \
      pnode = xmlNewNode(NULL, (xmlChar *)"module"); \
      xmlSetProp(pnode, (xmlChar *)"type", (xmlChar *)name); \
      xmlSetProp(pnode, (xmlChar *)"name", (xmlChar *)mod_names[i]); \
      xmlAddChild(mods, pnode); \
    } \
    if(mod_names) free(mod_names); \
} while(0)
    for(t = mtev_dso_get_types(); t; t = t->next)
      list_modules(t->list, t->name);

    /* Write it out to a buffer and copy it for writing */
    cl->buff = mtev_xmlSaveToBuffer(xmldoc);
    cl->towrite = strlen(cl->buff);

    /* Clean up after ourselves */
    xmlFreeDoc(xmldoc);
}

int
mtev_capabilities_handler(eventer_t e, int mask, void *closure,
                          struct timeval *now) {
  int newmask = EVENTER_WRITE | EVENTER_EXCEPTION;
  acceptor_closure_t *ac = closure;
  mtev_capsvc_closure_t *cl = ac->service_ctx;

  if(mask & EVENTER_EXCEPTION) {
socket_error:
    /* Exceptions cause us to simply snip the connection */
cleanup_shutdown:
    eventer_remove_fd(e->fd);
    e->opset->close(e->fd, &newmask, e);
    if(cl) {
      if(cl->buff) free(cl->buff);
      free(cl);
    }
    acceptor_closure_free(ac);
    return 0;
  }

  if(!ac->service_ctx) {
    cl = ac->service_ctx = calloc(1, sizeof(*cl));
    mtev_capabilities_tobuff(cl, ac->dispatch);
  }

  while(cl->towrite > cl->written) {
    int len;
    while((len = e->opset->write(e->fd, cl->buff + cl->written,
                                 cl->towrite - cl->written,
                                 &newmask, e)) == -1 && errno == EINTR);
    if(len < 0) {
      if(errno == EAGAIN) return newmask | EVENTER_EXCEPTION;
      goto socket_error;
    }
    cl->written += len;
  }
  goto cleanup_shutdown;
}

void
mtev_capabilities_init_globals() {
  mtev_hash_init_locks(&features, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
}
