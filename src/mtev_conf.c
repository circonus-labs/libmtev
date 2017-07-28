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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <zlib.h>

#include "mtev_conf.h"
#include "mtev_console.h"
#include "mtev_version.h"
#include "mtev_xml.h"
#include "mtev_hash.h"
#include "mtev_log.h"
#include "mtev_b64.h"
#include "mtev_watchdog.h"
#include "mtev_security.h"
#include "mtev_hooks.h"
#include "mtev_str.h"

MTEV_HOOK_IMPL(mtev_conf_delete_section,
                (const char *root, const char *path,
                 const char *name, const char **err),
                void *, closure,
                (void *closure, const char *root, const char *path,
                 const char *name, const char **err),
                (closure, root, path, name, err));

const char *_mtev_branch = MTEV_BRANCH;
const char *_mtev_version = MTEV_VERSION;

static const int globflags = 0 |
#ifdef GLOB_NOMAGIC
  GLOB_NOMAGIC |
#else
  0 |
#endif
#ifdef GLOB_BRACE
  GLOB_BRACE |
#else
  0 |
#endif
  0;

/* tmp hash impl, replace this with something nice */
static mtev_log_stream_t xml_debug = NULL;
#define XML2LOG(log) do { \
  xmlSetGenericErrorFunc(log, mtev_conf_xml_error_func); \
  xmlSetStructuredErrorFunc(log, mtev_conf_xml_error_ext_func); \
} while(0)
#define XML2CONSOLE(ncct) do { \
  xmlSetGenericErrorFunc(ncct, mtev_conf_xml_console_error_func); \
  xmlSetStructuredErrorFunc(ncct, mtev_conf_xml_console_error_ext_func); \
} while(0)
static xmlDocPtr master_config = NULL;
static int config_include_cnt = -1;
static int backingstore_include_cnt = -1;

struct include_node_t{
  xmlNodePtr insertion_point;
  xmlNodePtr old_children;
  xmlDocPtr doc;
  xmlNodePtr root;
  int snippet;
  int ro;
  char path[255];
  int glob_idx;
  int child_count;
  struct include_node_t *children;
};

typedef struct include_node_t include_node_t;

static include_node_t *config_include_nodes = NULL,
                      *backingstore_include_nodes = NULL;

typedef struct mtev_xml_userdata {
  char       *name;
  char       *path;
  uint64_t   dirty_time;
  struct mtev_xml_userdata *freelist;
  include_node_t *container;
} mtev_xml_userdata_t;

static mtev_xml_userdata_t *backingstore_freelist = NULL;
static uint64_t last_config_flush = 0;

static int default_is_stopword(const char *f) { return 0; }
static int (*is_stopnode_name)(const char *) = default_is_stopword; 

void mtev_override_console_stopword(int (*f)(const char *)) {
  is_stopnode_name = f;
}
#define is_stopnode(node) ((node) && is_stopnode_name((const char *)(node)->name))

static char *root_node_name = NULL;
static char master_config_file[PATH_MAX] = "";
static xmlXPathContextPtr xpath_ctxt = NULL;

/* coalesced writing allows internals to change the XML structure and mark
 * the tree dirty, but only write the config out once per second.
 */
static uint32_t __coalesce_write = 0;
static mtev_boolean config_writes_disabled = mtev_false;

/* This is used to notice config changes and journal the config out
 * using a user-specified function.  It supports allowing multiple config
 * changed to coalesce so you don't write out 1000 changes in a few seconds.
 */
static uint32_t __config_gen = 0;
static uint32_t __config_coalesce = 0;
static uint32_t __config_coalesce_time = 0;
static uint64_t max_gen_count = 0;

void mtev_conf_coalesce_changes(uint32_t seconds) {
  __config_coalesce_time = seconds;
}

void mtev_conf_request_write(void) {
  __coalesce_write = 1;
}

uint32_t mtev_conf_config_gen(void) {
  return __config_gen;
}

void mtev_conf_mark_changed(void) {
  /* increment the change counter -- in case anyone cares */
  __config_gen++;
  /* reset the coalesce counter.  It is decremented each second and
   * the journal function fires on a transition from 1 => 0
   */
  __config_coalesce = __config_coalesce_time;
}

struct recurrent_journaler {
  int (*journal_config)(void *);
  void *jc_closure;
};

void mtev_conf_write_section(mtev_conf_section_t node, int fd) {
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;

  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateFd(fd, enc);
  xmlNodeDumpOutput(out, master_config, node, 2, 0, "utf8");
  xmlOutputBufferClose(out);
  if(write(fd, "\n", 1) < 0) {
    mtevL(mtev_debug, "Odd error writeing LF to conf\n");
  }
  xmlFree(enc);
}

static void
write_out_include_files(include_node_t *include_nodes, int include_node_cnt) {
  int i;
  for(i=0; i<include_node_cnt; i++) {
    xmlOutputBufferPtr out;
    xmlCharEncodingHandlerPtr enc;
    mode_t mode = 0640;
    char filename[500];
    int len, fd;
    struct stat st;
    uid_t uid = 0;
    gid_t gid = 0;

    if(include_nodes[i].ro || !include_nodes[i].doc) {
      write_out_include_files(include_nodes[i].children, include_nodes[i].child_count);
      continue;
    }
    if(stat(include_nodes[i].path, &st) == 0) {
      mode = st.st_mode;
      uid = st.st_uid;
      gid = st.st_gid;
    }

    sprintf(filename, "%s.tmp", include_nodes[i].path);
    fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, mode);
    if (fd < 0) {
      mtevL(mtev_error, "failed to open file %s: %s\n", filename, strerror(errno));
      continue;
    }
    if(fchown(fd, uid, gid) < 0) {
      mtevL(mtev_error, "failed to fchown file %s: %s\n", filename, strerror(errno));
      close(fd);
      continue;
    }

    enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
    out = xmlOutputBufferCreateFd(fd, enc);
    len = xmlSaveFormatFileTo(out, include_nodes[i].doc, "utf8", 1);
    if (len < 0) {
      mtevL(mtev_error, "couldn't write out %s\n", include_nodes[i].path);
      close(fd);
      continue;
    }
    close(fd);
    write_out_include_files(include_nodes[i].children, include_nodes[i].child_count);
    if(rename(filename, include_nodes[i].path) != 0) {
      mtevL(mtev_error, "Failed to replace file %s: %s\n", include_nodes[i].path, strerror(errno));
    }
  }
}

static void
mtev_xml_userdata_free(mtev_xml_userdata_t *n) {
  if(n->name) free(n->name);
  if(n->path) free(n->path);
  free(n);
}

static void
clean_xml_private_node_data(xmlNodePtr node) {
  xmlNodePtr n;
  if(node == NULL) return;
  if(node->_private) mtev_xml_userdata_free(node->_private);
  node->_private = NULL;
  for(n = node->children; n; n = n->next) {
    clean_xml_private_node_data(n);
  }
}
static void
clean_xml_private_doc_data(xmlDocPtr doc) {
  xmlNodePtr node = xmlDocGetRootElement(doc);
  if(doc->_private) mtev_xml_userdata_free(doc->_private);
  clean_xml_private_node_data(node);
}

static char *mtev_xml_ns = NULL;

void
mtev_conf_use_namespace(const char *ns) {
  if(mtev_xml_ns) free(mtev_xml_ns);
  mtev_xml_ns = strdup(ns);
}

void
mtev_conf_set_namespace(const char *ns) {
  xmlNsPtr nsptr;
  xmlNodePtr root;
  root = xmlDocGetRootElement(master_config);
  nsptr = xmlSearchNs(master_config, root, (xmlChar *)ns);
  if(!nsptr) {
    char url[128];
    snprintf(url, sizeof(url), "%s://module/%s", mtev_xml_ns ? mtev_xml_ns : "mtev", ns);
    xmlNewNs(root, (xmlChar *)url, (xmlChar *)ns);
  }
}

void
mtev_conf_correct_namespace(mtev_conf_section_t cp, mtev_conf_section_t cc) {
  xmlNodePtr parent = cp, child = cc;
  if(child->ns) {
    xmlNsPtr oldns = child->ns;
    child->ns = NULL;
    while(oldns) {
      xmlNsPtr newns = xmlSearchNs(parent->doc, xmlDocGetRootElement(parent->doc), oldns->prefix);
      if(!newns) newns = xmlNewNs(xmlDocGetRootElement(parent->doc), oldns->href, oldns->prefix);
      oldns = oldns->next;
    }
    child->ns = parent->ns;
  }
  if(child->children) mtev_conf_correct_namespace(parent, child->children);
  if(child->next) mtev_conf_correct_namespace(parent, child->next);
}

static int
mtev_conf_watch_config_and_journal(eventer_t e, int mask, void *closure,
                                   struct timeval *now) {
  struct recurrent_journaler *rj = closure;

  if(rj && rj->journal_config && __config_coalesce == 1)
    rj->journal_config(rj->jc_closure);
  if(__config_coalesce > 0)
    __config_coalesce--;

  if(__coalesce_write) {
    mtev_conf_write_file(NULL);
    __coalesce_write = 0;
  }

  /* Schedule the same event to fire a second from now */
  eventer_add_in_s_us(mtev_conf_watch_config_and_journal, closure, 1, 0);
  return 0;
}

void
mtev_conf_watch_and_journal_watchdog(int (*f)(void *), void *c) {
  static int callbacknamed = 0;
  struct recurrent_journaler *rj = NULL;
  struct timeval __now;

  if(!callbacknamed) {
    callbacknamed = 1;
    eventer_name_callback("mtev_conf_watch_config_and_journal",
                          mtev_conf_watch_config_and_journal);
  }
  if(f) {
    rj = calloc(1, sizeof(*rj));
    rj->journal_config = f;
    rj->jc_closure = c;
  }
  mtev_gettimeofday(&__now, NULL);
  mtev_conf_watch_config_and_journal(NULL, EVENTER_TIMER, rj, &__now);
}

static mtev_hash_table _compiled_fallback;

static struct {
  const char *key;
  const char *val;
} config_info[] = {
  /*
   * These are compile-time fallbacks to be used in the event
   * that the current running config does not have values for
   * these config paths.
   *
   * PLEASE: keep them alphabetically sorted.
   */
  { "/%s/eventer/@implementation", DEFAULT_EVENTER },
  { "/%s/modules/@directory", MTEV_MODULES_DIR },

  { NULL, NULL }
};

#define MAX_SUPPRESSIONS 128
static struct {
  xmlErrorDomain domain;
  xmlParserErrors  code;
} suppressions[MAX_SUPPRESSIONS];

static void
mtev_conf_xml_console_error_func(void *ctx, const char *format, ...) {
  mtev_console_closure_t ncct = ctx;
  va_list arg;
  if(!ncct) return;
  va_start(arg, format);
  nc_vprintf(ncct, format, arg);
  va_end(arg);
}

static void
mtev_conf_xml_console_error_ext_func(void *ctx, xmlErrorPtr err) {
  int i;
  mtev_console_closure_t ncct = ctx;
  if(!ctx) return;
  for(i=0;i<MAX_SUPPRESSIONS;i++)
    if(suppressions[i].domain == err->domain && suppressions[i].code == err->code) return;
  if(err->file)
    nc_printf(ncct, "XML error [%d/%d] in %s on line %d %s\n",
              err->domain, err->code, err->file, err->line, err->message);
  else
    nc_printf(ncct, "XML error [%d/%d] %s\n",
              err->domain, err->code, err->message);
}

static void
mtev_conf_suppress_xml_error(xmlErrorDomain domain, xmlParserErrors code) {
  int i, first_hole = -1;
  for(i=0;i<MAX_SUPPRESSIONS;i++) {
    if(suppressions[i].domain == domain && suppressions[i].code == code) return;
    if(first_hole == -1 &&
       suppressions[i].domain == XML_FROM_NONE &&
       suppressions[i].code == XML_ERR_OK)
      first_hole = i;
  }
  if(first_hole >= 0) {
    suppressions[first_hole].domain = domain;
    suppressions[first_hole].code = code;
  }
}

static void
mtev_conf_express_xml_error(xmlErrorDomain domain, xmlParserErrors code) {
  int i;
  for(i=0;i<MAX_SUPPRESSIONS;i++) {
    if(suppressions[i].domain == domain && suppressions[i].code == code) {
      suppressions[i].domain = XML_FROM_NONE;
      suppressions[i].code = XML_ERR_OK;
      return;
    }
  }
}

static void
mtev_conf_xml_error_func(void *ctx, const char *format, ...) {
  struct timeval __now;
  mtev_log_stream_t ls = ctx;
  va_list arg;
  if(!ls) return;
  va_start(arg, format);
  mtev_gettimeofday(&__now,  NULL);
  mtev_vlog(ls, &__now, __FILE__, __LINE__, format, arg);
  va_end(arg);
}

static void
mtev_conf_xml_error_ext_func(void *ctx, xmlErrorPtr err) {
  int i;
  struct timeval __now;
  mtev_log_stream_t ls = ctx;
  if(!ls) return;
  for(i=0;i<MAX_SUPPRESSIONS;i++)
    if(suppressions[i].domain == err->domain && suppressions[i].code == err->code) return;
  mtev_gettimeofday(&__now,  NULL);
  if(err->file)
    mtev_log(ls, &__now, err->file, err->line,
             "XML error [%d/%d] in %s on line %d %s\n",
             err->domain, err->code, err->file, err->line, err->message);
  else
    mtev_log(ls, &__now, err->file, err->line,
             "XML error [%d/%d] %s\n",
             err->domain, err->code, err->message);
}

void
mtev_conf_xml_errors_to_debug(void) {
  XML2LOG(xml_debug);
}

void
mtev_conf_poke(const char *toplevel, const char *key, const char *val) {
  char keystr[256];
  snprintf(keystr, sizeof(keystr), key, toplevel);
  mtev_hash_store(&_compiled_fallback,
                  strdup(keystr), strlen(keystr),
                  (void *)strdup(val));
}

DECLARE_CHECKER(name)
void mtev_conf_init(const char *toplevel) {
  int i;

  xml_debug = mtev_log_stream_find("debug/xml");

  COMPILE_CHECKER(name, "^[-_\\.:/a-zA-Z0-9]+$");
  XML2LOG(mtev_error);
  for(i = 0; config_info[i].key != NULL; i++)
    mtev_conf_poke(toplevel, config_info[i].key, config_info[i].val);
  xmlKeepBlanksDefault(0);
  xmlInitParser();
  xmlXPathInit();
}

static void
mtev_conf_magic_separate_includes(include_node_t **root_include_nodes, int *cnt) {
  include_node_t *include_nodes = *root_include_nodes;
  mtevAssert(*cnt != -1);
  if(include_nodes) {
    int i;
    for(i=0; i<*cnt; i++) {
      mtev_conf_magic_separate_includes(&(include_nodes[i].children), &(include_nodes[i].child_count));
      if(include_nodes[i].doc) {
        xmlNodePtr n, prev = NULL;
        for(n=include_nodes[i].insertion_point->children;
            n; n = n->next) {
          mtev_xml_userdata_t *udata;
          if(n->_private == NULL && prev) n->_private = prev->_private;
          udata = n->_private;
          assert(udata);
          include_node_t *owner = udata->container;
          assert(owner);
          n->parent = owner->snippet ? (xmlNodePtr)owner->doc : owner->root;
          prev = n;
        }
        /* unlink the conjunction of lists */
        prev = NULL;
        for(n=include_nodes[i].insertion_point->children;
            n; n = n->next) {
          include_node_t *prev_cont = NULL, *n_cont = NULL;
          if(prev && prev->_private)
            prev_cont = ((mtev_xml_userdata_t *)prev->_private)->container;
          if(n->_private)
            n_cont = ((mtev_xml_userdata_t *)n->_private)->container;
          if(prev && (prev_cont != n_cont)) {
            n->prev = NULL;
            prev->next = NULL;
          }
          prev = n;
        }
        if(include_nodes[i].glob_idx == 0) {
          include_nodes[i].insertion_point->children =
            include_nodes[i].old_children;
        }
        clean_xml_private_doc_data(include_nodes[i].doc);
        xmlFreeDoc(include_nodes[i].doc);

        /* We've already done the work for subsequent globbed includes */
        while((i+1) < *cnt && include_nodes[i+1].glob_idx > 0) {
          i++;
          clean_xml_private_doc_data(include_nodes[i].doc);
          xmlFreeDoc(include_nodes[i].doc);
        }
      }
    }
    free(include_nodes);
  }
  *root_include_nodes = NULL;
  *cnt = -1;
}

static void
mtev_conf_magic_separate(void) {
  mtev_conf_magic_separate_includes(&config_include_nodes, &config_include_cnt);
  mtevAssert(config_include_nodes == NULL);
  if(backingstore_include_nodes) {
    int i;
    for(i=0; i<backingstore_include_cnt; i++) {
      if(backingstore_include_nodes[i].doc) {
        xmlNodePtr n;
        for(n=backingstore_include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent = backingstore_include_nodes[i].root;
          n->parent->last = n;
        }
        backingstore_include_nodes[i].insertion_point->children =
          backingstore_include_nodes[i].old_children;
        for(n=backingstore_include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent->last = n; /* sets it to the last child */
        }
        clean_xml_private_doc_data(backingstore_include_nodes[i].doc);
        xmlFreeDoc(backingstore_include_nodes[i].doc);
      }
    }
    free(backingstore_include_nodes);
  }
  backingstore_include_nodes = NULL;
  backingstore_include_cnt = -1;
}

static void
mtev_conf_kansas_city_shuffle_redo(include_node_t *include_nodes, int include_node_cnt) {
  if(include_nodes) {
    int i;
    for(i=0; i<include_node_cnt; i++) {
      mtev_conf_kansas_city_shuffle_redo(include_nodes[i].children, include_nodes[i].child_count);
      if(include_nodes[i].doc) {
        xmlNodePtr n, more_kids;

        if (!include_nodes[i].snippet)
          more_kids = include_nodes[i].root->children;
        else
          more_kids = include_nodes[i].root;

        if(include_nodes[i].glob_idx == 0 || include_nodes[i].insertion_point->children == NULL) {
          include_nodes[i].insertion_point->children = more_kids;
        }
        else {
          for(n=include_nodes[i].insertion_point->children; n->next; n = n->next);
          more_kids->prev = n->next;
          n->next = more_kids;
        }

        for(n=include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent = include_nodes[i].insertion_point;
          n->parent->last = n;
        }
      }
    }
  }
}

static void
mtev_conf_kansas_city_shuffle_undo(include_node_t *include_nodes, int include_node_cnt) {
  if(include_nodes) {
    int i;
    for(i=0; i<include_node_cnt; i++) {
      mtev_conf_kansas_city_shuffle_undo(include_nodes[i].children, include_nodes[i].child_count);
      if(include_nodes[i].doc) {
        xmlNodePtr n, prev = NULL;
        for(n=include_nodes[i].insertion_point->children;
            n; n = n->next) {
          if(n->_private == NULL && prev) n->_private = prev->_private;
          mtev_xml_userdata_t *udata = n->_private;
          assert(udata);
          include_node_t *owner = udata->container;
          assert(owner);
          n->parent = owner->snippet ? (xmlNodePtr)owner->doc : owner->root;
          prev = n;
        }
        /* unlink the conjunction of lists */
        prev = NULL;
        for(n=include_nodes[i].insertion_point->children;
            n; n = n->next) {
          include_node_t *prev_cont = NULL, *n_cont = NULL;
          if(prev && prev->_private)
            prev_cont = ((mtev_xml_userdata_t *)prev->_private)->container;
          if(n->_private)
            n_cont = ((mtev_xml_userdata_t *)n->_private)->container;
          if(prev && (prev_cont != n_cont)) {
            n->prev = NULL;
            prev->next = NULL;
          }
          prev = n;
        }
        if(include_nodes[i].glob_idx == 0)
          include_nodes[i].insertion_point->children =
            include_nodes[i].old_children;
      }
    }
  }
}

static uint64_t
usec_now(void) {
  uint64_t usec;
  struct timeval tv;
  mtev_gettimeofday(&tv, NULL);
  usec = tv.tv_sec * 1000000UL;
  usec += tv.tv_usec;
  return usec;
}

static void
remove_emancipated_child_node(xmlNodePtr oldp, xmlNodePtr node) {
  /* node was once a child of oldp... it's still in it's children list
   * but node's parent isn't this child.
   */
  mtevAssert(node->parent != oldp);
  if(oldp->children == NULL) return;
  if(oldp->children == node) {
    oldp->children = node->next;
    if (node->next) node->next->prev = node->prev;
  }
  else {
    xmlNodePtr prev;
    for(prev = oldp->children; prev->next && prev->next != node; prev = prev->next);
    if(prev) prev->next = node->next;
    if(node->next) node->next->prev = prev;
  }
}

void
mtev_conf_include_remove(mtev_conf_section_t vnode) {
  int i;
  xmlNodePtr node = vnode;
  for(i=0;i<config_include_cnt;i++) {
    if(node->parent == config_include_nodes[i].insertion_point) {
      remove_emancipated_child_node(config_include_nodes[i].root, node);
    }
  }
}

void
mtev_conf_backingstore_remove(mtev_conf_section_t vnode) {
  int i;
  xmlNodePtr node = vnode;
  mtev_xml_userdata_t *subctx = node->_private;
  for(i=0;i<backingstore_include_cnt;i++) {
    if(node->parent == backingstore_include_nodes[i].insertion_point) {
      remove_emancipated_child_node(backingstore_include_nodes[i].root, node);
    }
  }
  if(subctx) {
    mtevL(mtev_debug, "marking %s for removal\n", subctx->path);
    if(!backingstore_freelist) backingstore_freelist = subctx;
    else {
      mtev_xml_userdata_t *fl = backingstore_freelist;
      while(fl->freelist) fl = fl->freelist;
      fl->freelist = subctx;
    }
    node->_private = NULL;
  }
  /* If we're deleted, we'll mark the parent as dirty */
  if(node->parent) mtev_conf_backingstore_dirty(node->parent);
}

void
mtev_conf_backingstore_dirty(mtev_conf_section_t vnode) {
  xmlNodePtr node = vnode;
  mtev_xml_userdata_t *subctx = node->_private;
  if(subctx) {
    mtevL(mtev_debug, "backingstore[%s] marked dirty\n", subctx->path);
    subctx->dirty_time = usec_now();
    return;
  }
  if(node->parent) mtev_conf_backingstore_dirty(node->parent);
}

static int
mtev_conf_backingstore_write(mtev_xml_userdata_t *ctx, mtev_boolean skip,
                             xmlAttrPtr attrs, xmlNodePtr node) {
  int failure = 0;
  char newpath[PATH_MAX];
  xmlNodePtr n;
  snprintf(newpath, sizeof(newpath), "%s/.attrs", ctx->path);
  if(attrs) {
    xmlDocPtr tmpdoc;
    xmlNodePtr tmpnode;
    mtevL(mtev_debug, " **> %s\n", newpath);
    tmpdoc = xmlNewDoc((xmlChar *)"1.0");
    tmpnode = xmlNewNode(NULL, ctx->name ? (xmlChar *)ctx->name : (xmlChar *)"stub");
    xmlDocSetRootElement(tmpdoc, tmpnode);
    tmpnode->properties = attrs;
    failure = mtev_xmlSaveToFile(tmpdoc, newpath);
    tmpnode->properties = NULL;
    xmlFreeDoc(tmpdoc);
    if(failure) return -1;
  }
  else if(!skip) {
    unlink(newpath);
  }
  for(n = node; n; n = n->next) {
    int leaf;
    mtev_xml_userdata_t *subctx;
    subctx = n->_private;
    leaf = is_stopnode(n);
    if(!subctx) { /* This has never been written out */
      subctx = calloc(1, sizeof(*subctx));
      subctx->name = strdup((char *)n->name);
      snprintf(newpath, sizeof(newpath), "%s/%s#%llu", ctx->path, n->name,
               (unsigned long long)++max_gen_count);
      if(leaf) strlcat(newpath, ".xml", sizeof(newpath));
      subctx->path = strdup(newpath);
      subctx->dirty_time = usec_now();
      n->_private = subctx;
      mtevL(mtev_debug, " !!> %s\n", subctx->path);
    }
    if(leaf) {
      xmlDocPtr tmpdoc;
      xmlNodePtr tmpnode;
      if(subctx->dirty_time > last_config_flush) {
        xmlNsPtr *parent_nslist, iter_ns;
        xmlNodePtr root;
        root = xmlDocGetRootElement(master_config);
        parent_nslist = xmlGetNsList(master_config, root);

        tmpdoc = xmlNewDoc((xmlChar *)"1.0");
        tmpnode = xmlNewNode(NULL, n->name);
        xmlDocSetRootElement(tmpdoc, tmpnode);
        if(parent_nslist) {
          for(iter_ns = *parent_nslist; iter_ns; iter_ns = iter_ns->next)
            xmlNewNs(tmpnode, iter_ns->href, iter_ns->prefix);
          xmlFree(parent_nslist);
        }
        tmpnode->properties = n->properties;
        tmpnode->children = n->children;
        failure = mtev_xmlSaveToFile(tmpdoc, subctx->path);
        tmpnode->properties = NULL;
        tmpnode->children = NULL;
        xmlFreeDoc(tmpdoc);
        mtevL(mtev_debug, " ==> %s\n", subctx->path);
        if(failure) return -1;
      }
    }
    else {
      mtev_boolean skip_attrs;
      skip_attrs = leaf || (subctx->dirty_time <= last_config_flush);
      mtevL(mtev_debug, " --> %s\n", subctx->path);
      if(mtev_conf_backingstore_write(subctx, skip_attrs, skip_attrs ? NULL : n->properties, n->children))
        return -1;
    }
  }
  return 0;
}

static void
mtev_conf_shatter_write(xmlDocPtr doc) {
  if(backingstore_freelist) {
    mtev_xml_userdata_t *fl, *last;
    for(fl = backingstore_freelist; fl; ) {
      last = fl;
      fl = fl->freelist;
      /* If it is a file, we'll unlink it, otherwise,
       * we need to delete the attributes and the directory.
       */
      if(unlink(last->path)) {
        char attrpath[PATH_MAX];
        snprintf(attrpath, sizeof(attrpath), "%s/.attrs", last->path);
        unlink(attrpath);
        if(rmdir(last->path) && errno != ENOENT) {
          /* This shouldn't happen, but if it does we risk
           * leaving a mess. Don't do that.
           */
          mtevL(mtev_error, "backingstore mess %s: %s\n",
                last->path, strerror(errno));
        }
      }
      mtev_xml_userdata_free(last);
    }
    backingstore_freelist = NULL;
  }
  if(backingstore_include_nodes) {
    int i;
    for(i=0; i<backingstore_include_cnt; i++) {
      if(backingstore_include_nodes[i].doc) {
        xmlNodePtr n;
        mtev_xml_userdata_t *what = backingstore_include_nodes[i].doc->_private;

        for(n=backingstore_include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent = backingstore_include_nodes[i].root;
          n->parent->last = n;
        }
        backingstore_include_nodes[i].root->children =
          backingstore_include_nodes[i].insertion_point->children;
        backingstore_include_nodes[i].insertion_point->children =
          backingstore_include_nodes[i].old_children;
        for(n=backingstore_include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent->last = n; /* sets it to the last child */
        }
        mtev_conf_backingstore_write(what, mtev_false, NULL, backingstore_include_nodes[i].root->children);
      }
    }
    last_config_flush = usec_now();
  }
}

static void
mtev_conf_shatter_postwrite(xmlDocPtr doc) {
  if(backingstore_include_nodes) {
    int i;
    for(i=0; i<backingstore_include_cnt; i++) {
      if(backingstore_include_nodes[i].doc) {
        xmlNodePtr n;
        backingstore_include_nodes[i].insertion_point->children =
          backingstore_include_nodes[i].root->children;
        for(n=backingstore_include_nodes[i].insertion_point->children;
            n; n = n->next) {
          n->parent = backingstore_include_nodes[i].insertion_point;
          n->parent->last = n;
        }
      }
    }
  }
}

static int
mtev_conf_read_into_node(xmlNodePtr node, const char *path) {
  DIR *dirroot;
  struct dirent *de, *entry;
  char filepath[PATH_MAX];
  xmlDocPtr doc;
  xmlNodePtr root = NULL;
  struct stat sb;
  int size, rv;

  mtevL(mtev_debug, "read backing store: %s\n", path);
  snprintf(filepath, sizeof(filepath), "%s/.attrs", path);
  while((rv = stat(filepath, &sb)) < 0 && errno == EINTR);
  if(rv == 0) {
    doc = xmlReadFile(filepath, "utf8", XML_PARSE_NOENT);
    if(doc) root = xmlDocGetRootElement(doc);
    if(doc && root) {
      node->properties = xmlCopyPropList(node, root->properties);
      xmlFreeDoc(doc);
      doc = NULL;
    }
  }
#ifdef _PC_NAME_MAX
  size = pathconf(path, _PC_NAME_MAX);
#endif
  size = MAX(size, PATH_MAX + 128);
  de = alloca(size);
  dirroot = opendir(path);
  if(!dirroot) return -1;
  while(portable_readdir_r(dirroot, de, &entry) == 0 && entry != NULL) {
    mtev_xml_userdata_t *udata;
    char name[PATH_MAX];
    char *sep;
    xmlNodePtr child;
    uint64_t gen;

    mtev_watchdog_child_heartbeat();

    sep = strchr(entry->d_name, '#');
    if(!sep) continue;
    snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
    while((rv = stat(filepath, &sb)) < 0 && errno == EINTR);
    if(rv == 0) {
      strlcpy(name, entry->d_name, sizeof(name));
      name[sep - entry->d_name] = '\0';
      gen = strtoull(sep+1, NULL, 10);
      if(gen > max_gen_count) max_gen_count = gen;

      if(S_ISDIR(sb.st_mode)) {
        mtevL(mtev_debug, "<DIR< %s\n", entry->d_name);
        child = xmlNewNode(NULL, (xmlChar *)name);
        mtev_conf_read_into_node(child, filepath);
        udata = calloc(1, sizeof(*udata));
        udata->name = strdup(name);
        udata->path = strdup(filepath);
        child->_private = udata;
        xmlAddChild(node, child);
      }
      else if(S_ISREG(sb.st_mode)) {
        xmlDocPtr cdoc;
        xmlNodePtr cnode = NULL;
        mtevL(mtev_debug, "<FILE< %s\n", entry->d_name);
        cdoc = xmlParseFile(filepath);
        if(cdoc) {
          cnode = xmlDocGetRootElement(cdoc);
          xmlDocSetRootElement(cdoc, xmlNewNode(NULL, (xmlChar *)"dummy"));
          if(cnode) {
            udata = calloc(1, sizeof(*udata));
            udata->name = strdup(name);
            udata->path = strdup(filepath);
            cnode->_private = udata;
            xmlAddChild(node, cnode);
          }
          xmlFreeDoc(cdoc);
        }
      }
    }
  }
  closedir(dirroot);
  return 0;
}

static xmlDocPtr
mtev_conf_read_backing_store(const char *path) {
  xmlDocPtr doc;
  xmlNodePtr root;
  mtev_xml_userdata_t *what;

  doc = xmlNewDoc((xmlChar *)"1.0");
  what = calloc(1, sizeof(*what));
  what->path = strdup(path);
  doc->_private = what;
  root = xmlNewNode(NULL, (xmlChar *)"stub");
  xmlDocSetRootElement(doc, root);
  mtev_conf_read_into_node(root, path);
  return doc;
}

static int
mtev_conf_magic_mix(const char *parentfile, xmlDocPtr doc, include_node_t* inc_node) {
  char infile[PATH_MAX];
  char globpat[PATH_MAX];
  xmlXPathContextPtr mix_ctxt = NULL;
  xmlXPathObjectPtr pobj = NULL;
  xmlNodePtr node;
  int i, j, cnt = 0, rv = 0, master = 0;
  int inc_idx = 0;
  int *include_cnt;
  include_node_t* include_nodes;
  glob_t *tl_globs = NULL;
  int nglobs = 0;

  if (inc_node) {
    include_cnt = &(inc_node->child_count);
    include_nodes = inc_node->children;
  }
  else {
    include_cnt = &(config_include_cnt);
    include_nodes = config_include_nodes;
    master = 1;
  }

  mtevAssert(*include_cnt == -1);

  if (master) {
    mtevAssert(backingstore_include_cnt == -1);
    backingstore_include_cnt = 0;
  }
  mix_ctxt = xmlXPathNewContext(doc);
  if (master)
    pobj = xmlXPathEval((xmlChar *)"//*[@backingstore]", mix_ctxt);
  else
    pobj = NULL;

  if(!pobj) goto includes;
  if(pobj->type != XPATH_NODESET) goto includes;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto includes;

  cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  if(cnt > 0)
    backingstore_include_nodes = calloc(cnt, sizeof(*backingstore_include_nodes));
  for(i=0; i<cnt; i++) {
    char *path, *infile;
    node = xmlXPathNodeSetItem(pobj->nodesetval, i);
    path = (char *)xmlGetProp(node, (xmlChar *)"backingstore");
    if(!path) continue;
    if(*path == '/') infile = strdup(path);
    else {
      char *cp;
      infile = malloc(PATH_MAX);
      strlcpy(infile, parentfile, PATH_MAX);
      for(cp = infile + strlen(infile) - 1; cp > infile; cp--) {
        if(*cp == '/') { *cp = '\0'; break; }
        else *cp = '\0';
      }
      strlcat(infile, "/", PATH_MAX);
      strlcat(infile, path, PATH_MAX);
    }
    xmlFree(path);
    backingstore_include_nodes[i].doc = mtev_conf_read_backing_store(infile);
    if(backingstore_include_nodes[i].doc) {
      xmlNodePtr n, lchild;
      backingstore_include_nodes[i].insertion_point = node;
      backingstore_include_nodes[i].root = xmlDocGetRootElement(backingstore_include_nodes[i].doc);
      /* for backing store, they are permanently reattached under the backing store.
       * so for any children, we need to glue them into the new parent document.
       */
      lchild = backingstore_include_nodes[i].root->children;
      while(lchild && lchild->next) lchild = lchild->next;
      if(lchild) {
        lchild->next = node->children;
        if(node->children) node->children->prev = lchild;
      }
      else
        backingstore_include_nodes[i].root->children = node->children;
      for(n=node->children; n; n = n->next) {
        n->parent = backingstore_include_nodes[i].root; /* this gets mapped right back, just for clarity */
        n->doc = backingstore_include_nodes[i].doc;
      }
      backingstore_include_nodes[i].old_children = NULL;
      node->children = backingstore_include_nodes[i].root->children;
      for(n=node->children; n; n = n->next) {
        n->parent = backingstore_include_nodes[i].insertion_point;
        n->parent->last = n;
      }
    }
    else {
      mtevL(mtev_error, "Could not load: '%s'\n", infile);
      rv = -1;
    }
    free(infile);
  }
  if(mix_ctxt) xmlXPathFreeContext(mix_ctxt);
  mix_ctxt = xmlXPathNewContext(doc);
  backingstore_include_cnt = cnt;
  mtevL(mtev_debug, "Processed %d backing stores.\n", backingstore_include_cnt);

 includes:
  if(pobj) xmlXPathFreeObject(pobj);
  *include_cnt = 0;
  pobj = xmlXPathEval((xmlChar *)"//include[@file]", mix_ctxt);
  if(!pobj) goto out;
  if(pobj->type != XPATH_NODESET) goto out;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto out;
  nglobs = xmlXPathNodeSetGetLength(pobj->nodesetval);
  cnt = 0;
  if(nglobs > 0) {
    tl_globs = calloc(sizeof(*tl_globs), nglobs);
    for (i=0; i<nglobs; i++) {
      node = xmlXPathNodeSetItem(pobj->nodesetval, i);
      char *path = (char *)xmlGetProp(node, (xmlChar *)"file");
      if(*path == '/') strlcpy(globpat, path, PATH_MAX);
      else {
        char *cp;
        strlcpy(globpat, parentfile, PATH_MAX);
        for(cp = globpat + strlen(globpat) - 1; cp > globpat; cp--) {
          if(*cp == '/') { *cp = '\0'; break; }
          else *cp = '\0';
        }
        strlcat(globpat, "/", PATH_MAX);
        strlcat(globpat, path, PATH_MAX);
      }
      if(glob(globpat, globflags, NULL, &tl_globs[i])) {
        mtevL(mtev_debug, "config include glob failure: %s\n", globpat);
      }
      xmlFree(path);
      cnt += tl_globs[i].gl_pathc;
    }

    include_nodes = calloc(cnt, sizeof(*include_nodes));
    if (master) {
      config_include_nodes = include_nodes;
    }
    else {
      inc_node->children = include_nodes;
    }
    for (i=0; i < cnt; i++) {
      include_nodes[i].child_count = -1;
    }
  }

  for(i=0; i<nglobs; i++) {
    mtev_boolean is_snippet, is_ro = mtev_false;
    char *path, *snippet, *ro;
    node = xmlXPathNodeSetItem(pobj->nodesetval, i);

    ro = (char *)xmlGetProp(node, (xmlChar *)"readonly");
    if (ro && !strcmp(ro, "true")) is_ro = mtev_true;
    if (ro) xmlFree(ro);

    snippet = (char *)xmlGetProp(node, (xmlChar *)"snippet");
    is_snippet = (snippet && strcmp(snippet, "false"));
    if(snippet) xmlFree(snippet);

    for (j=0; j<tl_globs[i].gl_pathc; j++) {
      path = tl_globs[i].gl_pathv[j];
      if(!path) continue;
      include_nodes[inc_idx].snippet = is_snippet;
      include_nodes[inc_idx].ro = is_ro;
      if(*path == '/') strlcpy(infile, path, PATH_MAX);
      else {
        char *cp;
        strlcpy(infile, parentfile, PATH_MAX);
        for(cp = infile + strlen(infile) - 1; cp > infile; cp--) {
          if(*cp == '/') { *cp = '\0'; break; }
          else *cp = '\0';
        }
        strlcat(infile, "/", PATH_MAX);
        strlcat(infile, path, PATH_MAX);
      }
      mtevL(mtev_debug, "Reading include[%d] file: %s\n", inc_idx, infile);
      if (include_nodes[inc_idx].snippet) {
        mtev_conf_suppress_xml_error(XML_FROM_IO, XML_IO_LOAD_ERROR);
        include_nodes[inc_idx].doc = xmlParseEntity(infile);
        mtev_conf_express_xml_error(XML_FROM_IO, XML_IO_LOAD_ERROR);
      }
      else
        include_nodes[inc_idx].doc = xmlReadFile(infile, "utf8", XML_PARSE_NOENT);
      if((include_nodes[inc_idx].doc) || (include_nodes[inc_idx].snippet)) {
        xmlNodePtr n, more_kids;
        mtev_conf_magic_mix(infile, include_nodes[inc_idx].doc, &(include_nodes[inc_idx]));
        strncpy(include_nodes[inc_idx].path, infile, sizeof(include_nodes[inc_idx].path) - 1); // room for NUL 
        include_nodes[inc_idx].insertion_point = node;
        include_nodes[inc_idx].root = xmlDocGetRootElement(include_nodes[inc_idx].doc);
        include_nodes[inc_idx].old_children = (j == 0) ? node->children : NULL;
        include_nodes[inc_idx].glob_idx = j;
        if(j==0) {
          node->children = NULL;
        }
        more_kids = include_nodes[inc_idx].snippet ? include_nodes[inc_idx].root : include_nodes[inc_idx].root->children;
        for(n=more_kids; n; n = n->next) {
          n->parent = include_nodes[inc_idx].insertion_point;
          mtev_xml_userdata_t *udata = calloc(1, sizeof(mtev_xml_userdata_t));
          udata->container = &include_nodes[inc_idx];
          n->_private = udata;
        }
        if (node->children == NULL) node->children = more_kids;
        else {
          assert(node->children != more_kids);
          for(n = node->children; n->next != NULL; n = n->next);
          n->next = more_kids;
        }
      }
      else {
        mtevL(mtev_error, "Could not load: '%s'\n", infile);
        rv = -1;
      }
      inc_idx++;
    }
    globfree(&tl_globs[i]);
  }
  free(tl_globs);
  *include_cnt = inc_idx;
  mtevL(mtev_debug, "Processed %d includes\n", *include_cnt);
 out:
  if(pobj) xmlXPathFreeObject(pobj);
  if(mix_ctxt) xmlXPathFreeContext(mix_ctxt);
  return rv;
}

static int
mtev_conf_load_internal(const char *path) {
  int rv = 0;
  xmlDocPtr new_config;
  xmlNodePtr root;
  new_config = xmlParseFile(path);
  if(new_config) {
    root = xmlDocGetRootElement(new_config);
    if(root_node_name) free(root_node_name);
    root_node_name = strdup((char *)root->name);

    if(master_config) {
      /* separate all includes */
      mtev_conf_magic_separate();
      clean_xml_private_doc_data(master_config);
      xmlFreeDoc(master_config);
    }
    if(xpath_ctxt) xmlXPathFreeContext(xpath_ctxt);

    master_config = new_config;
    /* mixin all the includes */
    if(mtev_conf_magic_mix(path, master_config, NULL)) rv = -1;

    xpath_ctxt = xmlXPathNewContext(master_config);
    if(path != master_config_file)
      if(realpath(path, master_config_file) == NULL)
        mtevL(mtev_error, "realpath failed: %s\n", strerror(errno));
    mtev_conf_mark_changed();
    return rv;
  }
  rv = -1;
  return rv;
}

void
mtev_conf_disable_writes(mtev_boolean state) {
  config_writes_disabled = state;
}

int
mtev_conf_load(const char *path) {
  char actual_path[PATH_MAX];
  int rv;

  if(path == NULL && master_config_file[0])
    path = master_config_file;
  else if(realpath(path, actual_path) != NULL) path = actual_path;
  if(!path) {
    mtevL(mtev_error, "no config file specified\n");
    return -1;
  }
  if(!strcmp(path, master_config_file)) path = master_config_file;

  XML2LOG(mtev_error);
  rv = mtev_conf_load_internal(path);
  XML2LOG(xml_debug);
  return rv;
}
static int mtev_conf_check_value(mtev_conf_description_t* description) {
  int rv = 0;
  switch (description->type) {
  case MTEV_CONF_TYPE_BOOLEAN:
    rv = mtev_conf_get_boolean(description->section, description->path,
        &description->value.val_bool);
    break;
  case MTEV_CONF_TYPE_INT:
    rv = mtev_conf_get_int(description->section, description->path,
        &description->value.val_int);
    break;
  case MTEV_CONF_TYPE_INT64:
    rv = mtev_conf_get_int64(description->section, description->path,
        &description->value.val_int64);
    break;
  case MTEV_CONF_TYPE_FLOAT:
    rv = mtev_conf_get_float(description->section, description->path,
        &description->value.val_float);
    break;
  case MTEV_CONF_TYPE_DOUBLE:
    rv = mtev_conf_get_double(description->section, description->path,
        &description->value.val_double);
    break;
  case MTEV_CONF_TYPE_STRING:
    rv = mtev_conf_get_string(description->section, description->path,
        &description->value.val_string);
    break;
  case MTEV_CONF_TYPE_UUID:
    rv = mtev_conf_get_uuid(description->section, description->path,
        description->value.val_uuid);
    break;
  default:
    rv = -1;
  }
  return rv;
}

static int
get_descendant_id(xmlNode* node) {
  xmlNode* sibling = node->prev;

  int id = 0;
  while(sibling) {
    if(strcmp((const char *)node->name, (const char *)sibling->name)==0){
      id++;
    }
    sibling = sibling->prev;
  }
  return id+1;
}

char*
mtev_conf_section_to_xpath(mtev_conf_section_t* section) {
  if (section == NULL) {
    return NULL;
  }

  mtev_prependable_str_buff_t *xpath = mtev_prepend_str_alloc();
  xmlNode* node = (xmlNode*) section;
  int buff_len = 512;
  char *buff = alloca(buff_len);
  char *onheap = NULL;
  while (node && node->name) {
    int desc_id = get_descendant_id(node);
    int current_entry_len = strlen((const char *)node->name);
    char* current_entry;
    if (current_entry_len < buff_len) {
      current_entry = buff;
    } else {
      buff_len = current_entry_len + sizeof("/descendant::[999999]\0");
      current_entry = malloc(buff_len);
      free(onheap);
      buff = onheap = current_entry;
    }

    if (desc_id > 1) {
      current_entry_len = sprintf(current_entry, "/descendant::%s[%d]",
          node->name, desc_id);
    } else {
      current_entry_len = sprintf(current_entry, "/%s", node->name);
    }

    mtev_prepend_str(xpath, current_entry, current_entry_len);
    node = node->parent;
  }

  free(onheap);
  char *result = strndup(xpath->string, (size_t)mtev_prepend_strlen(xpath));
  mtev_prepend_str_free(xpath);
  return result;
}

#define mtev_conf_default(name, type) \
mtev_conf_default_or_optional_t \
mtev_conf_default_##name (type default_value) { \
  mtev_conf_default_or_optional_t doo = {0}; \
  memcpy(&doo.value, &default_value, sizeof(type)); \
  return doo; \
}

mtev_conf_default(boolean, int)
mtev_conf_default(int, int)
mtev_conf_default(int64, int64_t)
mtev_conf_default(float, float)
mtev_conf_default(double, double)
mtev_conf_default(string, char*)
mtev_conf_default(uuid, uuid_t)

mtev_conf_default_or_optional_t
mtev_conf_optional(void) {
  mtev_conf_default_or_optional_t doo = {1};
  return doo;
}

#define mtev_conf_description(name, type_enum) \
mtev_conf_description_t \
mtev_conf_description_##name (mtev_conf_section_t section, char *path, \
  char* description, mtev_conf_default_or_optional_t default_or_optional) { \
  mtev_conf_description_t desc = { section, path, type_enum, \
      description }; \
  desc.default_or_optional = default_or_optional; \
  return desc; \
}

mtev_conf_description(boolean, MTEV_CONF_TYPE_BOOLEAN)
mtev_conf_description(int, MTEV_CONF_TYPE_INT)
mtev_conf_description(int64, MTEV_CONF_TYPE_INT64)
mtev_conf_description(float, MTEV_CONF_TYPE_FLOAT)
mtev_conf_description(double, MTEV_CONF_TYPE_DOUBLE)
mtev_conf_description(string, MTEV_CONF_TYPE_STRING)
mtev_conf_description(uuid, MTEV_CONF_TYPE_UUID)

int mtev_conf_get_value(mtev_conf_description_t* description,
    void *return_value) {
  if (mtev_conf_check_value(description) == 0) {
    char *section = mtev_conf_section_to_xpath(description->section);
    if (description->default_or_optional.is_optional == 0) {
      mtevL(mtev_stderr,
          "Path does not exist in config: '%s/%s'. Using default value instead. It should contain the following config: %s\n",
          section, description->path, description->description);
      description->value = description->default_or_optional.value;
    } else {
      mtevL(mtev_stderr,
          "The following optional config has not been set: '%s/%s'\nIt should contain the following config: %s\n",
          section, description->path, description->description);
      return 0;
    }
  }

  switch (description->type) {
  case MTEV_CONF_TYPE_BOOLEAN:
    memcpy(return_value, &description->value.val_bool,
        sizeof(description->value.val_bool));
    break;
  case MTEV_CONF_TYPE_INT:
    memcpy(return_value, &description->value.val_int,
        sizeof(description->value.val_int));
    break;
  case MTEV_CONF_TYPE_INT64:
    memcpy(return_value, &description->value.val_int64,
        sizeof(description->value.val_int64));
    break;
  case MTEV_CONF_TYPE_FLOAT:
    memcpy(return_value, &description->value.val_float,
        sizeof(description->value.val_float));
    break;
  case MTEV_CONF_TYPE_DOUBLE:
    memcpy(return_value, &description->value.val_double,
        sizeof(description->value.val_double));
    break;
  case MTEV_CONF_TYPE_STRING:
    memcpy(return_value, &description->value.val_string,
        sizeof(description->value.val_string));
    break;
  case MTEV_CONF_TYPE_UUID:
    memcpy(return_value, &description->value.val_uuid,
        sizeof(description->value.val_uuid));
    break;
  default:
    return 0;
  }

  return 1;
}

char *
mtev_conf_config_filename(void) {
  return strdup(master_config_file);
}

int
mtev_conf_xml_xpath(xmlDocPtr *mc, xmlXPathContextPtr *xp) {
  if(mc) *mc = master_config;
  if(xp) *xp = xpath_ctxt;
  return 0;
}

int
mtev_conf_save(const char *path) {
  return -1;
}

void
mtev_conf_get_elements_into_hash(mtev_conf_section_t section,
                                 const char *path,
                                 mtev_hash_table *table,
                                 const char *namespace) {
  int i, cnt;
  mtev_hash_table collide;
  char *same_space_collision = NULL;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr current_ctxt;
  xmlNodePtr current_node = (xmlNodePtr)section;
  xmlNodePtr node;

  current_ctxt = xpath_ctxt;
  if(!xpath_ctxt) return;
  if(current_node) {
    current_ctxt = xmlXPathNewContext(master_config);
    current_ctxt->node = current_node;
  }
  mtev_hash_init(&collide);
  pobj = xmlXPathEval((xmlChar *)path, current_ctxt);
  if(!pobj) goto out;
  if(pobj->type != XPATH_NODESET) goto out;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto out;
  cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  for(i=0; i<cnt; i++) {
    const xmlChar *name;
    int freename = 0;
    char *value;
    node = xmlXPathNodeSetItem(pobj->nodesetval, i);
    if(namespace && node->ns && !strcmp((char *)node->ns->prefix, namespace)) {
      name = node->name;
      if(!strcmp((char *)name, "value")) {
        name = xmlGetProp(node, (xmlChar *)"name");
        if(!name) name = node->name;
        else freename = 1;
      }
      value = (char *)xmlXPathCastNodeToString(node);
      if(same_space_collision == NULL &&
         !mtev_hash_store(&collide, strdup((char *)name),
                          strlen((const char *)name), NULL)) {
        same_space_collision = strdup((char *)name);
      }
      mtev_hash_replace(table,
                        strdup((char *)name), strlen((char *)name),
                        strdup(value), free, free);
      xmlFree(value);
    }
    else if(!namespace && !node->ns) {
      name = node->name;
      if(!strcmp((char *)name, "value")) {
        name = xmlGetProp(node, (xmlChar *)"name");
        if(!name) name = node->name;
        else freename = 1;
      }
      value = (char *)xmlXPathCastNodeToString(node);
      if(same_space_collision == NULL &&
         !mtev_hash_store(&collide, strdup((char *)name),
                          strlen((const char *)name), NULL)) {
        same_space_collision = strdup((char *)name);
      }
      mtev_hash_replace(table,
                        strdup((char *)name), strlen((char *)name),
                        strdup(value), free, free);
      xmlFree(value);
    }
    if(freename) xmlFree((void *)name);
  }
  if(same_space_collision) {
    mtevL(mtev_notice, "XML to hash collision on key: %s\n",
          same_space_collision);
  }
 out:
  free(same_space_collision);
  mtev_hash_destroy(&collide, free, NULL);
  if(pobj) xmlXPathFreeObject(pobj);
  if(current_ctxt && current_ctxt != xpath_ctxt)
    xmlXPathFreeContext(current_ctxt);
}

void
mtev_conf_get_into_hash(mtev_conf_section_t section,
                        const char *path,
                        mtev_hash_table *table,
                        const char *namespace) {
  unsigned int cnt;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr current_ctxt;
  xmlNodePtr current_node = (xmlNodePtr)section;
  xmlNodePtr node, parent_node;
  char xpath_expr[1024];
  char *inheritid;

  current_ctxt = xpath_ctxt;
  if(!xpath_ctxt) return;
  if(current_node) {
    current_ctxt = xmlXPathNewContext(master_config);
    current_ctxt->node = current_node;
  }
  if(path[0] == '/')
    strlcpy(xpath_expr, path, sizeof(xpath_expr));
  else
    snprintf(xpath_expr, sizeof(xpath_expr),
             "ancestor-or-self::node()/%s", path);
  pobj = xmlXPathEval((xmlChar *)xpath_expr, current_ctxt);
  if(!pobj) goto out;
  if(pobj->type != XPATH_NODESET) goto out;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto out;
  cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  /* These are in the order of root to leaf
   * We want to recurse... apply:
   *   1. our parent's config
   *   2. our "inherit" config if it exists.
   *   3. our config.
   */
  node = xmlXPathNodeSetItem(pobj->nodesetval, cnt-1);
  /* 1. */
  if(cnt > 1 && node) {
    parent_node = xmlXPathNodeSetItem(pobj->nodesetval, cnt-2);
    if(parent_node != current_node)
      mtev_conf_get_into_hash(parent_node, (const char *)node->name, table, namespace);
  }
  /* 2. */
  inheritid = (char *)xmlGetProp(node, (xmlChar *)"inherit");
  if(inheritid) {
    snprintf(xpath_expr, sizeof(xpath_expr), "//*[@id=\"%s\"]", inheritid);
    mtev_conf_get_into_hash(NULL, xpath_expr, table, namespace);
    xmlFree(inheritid);
  }
  /* 3. */
  mtev_conf_get_elements_into_hash(node, "*", table, namespace);

 out:
  if(pobj) xmlXPathFreeObject(pobj);
  if(current_ctxt && current_ctxt != xpath_ctxt)
    xmlXPathFreeContext(current_ctxt);
}

mtev_hash_table *
mtev_conf_get_namespaced_hash(mtev_conf_section_t section,
                              const char *path, const char *ns) {
  mtev_hash_table *table = NULL;

  table = calloc(1, sizeof(*table));
  mtev_hash_init(table);
  mtev_conf_get_into_hash(section, path, table, ns);
  if(mtev_hash_size(table) == 0) {
    mtev_hash_destroy(table, free, free);
    free(table);
    table = NULL;
  }
  return table;
}

mtev_hash_table *
mtev_conf_get_hash(mtev_conf_section_t section, const char *path) {
  mtev_hash_table *table = NULL;

  table = calloc(1, sizeof(*table));
  mtev_hash_init(table);
  mtev_conf_get_into_hash(section, path, table, NULL);
  return table;
}

mtev_conf_section_t
mtev_conf_get_section(mtev_conf_section_t section, const char *path) {
  mtev_conf_section_t subsection = NULL;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr current_ctxt;
  xmlNodePtr current_node = (xmlNodePtr)section;

  current_ctxt = xpath_ctxt;
  if(!xpath_ctxt) return NULL;
  if(current_node) {
    current_ctxt = xmlXPathNewContext(master_config);
    current_ctxt->node = current_node;
  }
  pobj = xmlXPathEval((xmlChar *)path, current_ctxt);
  if(!pobj) goto out;
  if(pobj->type != XPATH_NODESET) goto out;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto out;
  subsection = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, 0);
 out:
  if(pobj) xmlXPathFreeObject(pobj);
  if(current_ctxt && current_ctxt != xpath_ctxt)
    xmlXPathFreeContext(current_ctxt);
  return subsection;
}

mtev_conf_section_t *
mtev_conf_get_sections(mtev_conf_section_t section,
                       const char *path, int *cnt) {
  int i;
  mtev_conf_section_t *sections = NULL;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr current_ctxt;
  xmlNodePtr current_node = (xmlNodePtr)section;

  *cnt = 0;
  current_ctxt = xpath_ctxt;
  if(!xpath_ctxt) return NULL;
  if(current_node) {
    current_ctxt = xmlXPathNewContext(master_config);
    current_ctxt->node = current_node;
  }
  pobj = xmlXPathEval((xmlChar *)path, current_ctxt);
  if(!pobj) goto out;
  if(pobj->type != XPATH_NODESET) goto out;
  if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto out;
  *cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  sections = calloc(*cnt, sizeof(*sections));
  for(i=0; i<*cnt; i++)
    sections[i] = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, i);
 out:
  if(pobj) xmlXPathFreeObject(pobj);
  if(current_ctxt && current_ctxt != xpath_ctxt)
    xmlXPathFreeContext(current_ctxt);
  return sections;
}

int
mtev_conf_remove_section(mtev_conf_section_t section) {
  if (!section) return -1;
  xmlNodePtr node = (xmlNodePtr) section;
  xmlUnlinkNode(node);
  xmlFreeNode(node);
  mtev_conf_mark_changed();
  return 0;
}

/* This is private, but exposed */
int
_mtev_conf_get_string(mtev_conf_section_t section, xmlNodePtr *vnode,
                      const char *path, char **value) {
  const char *str, *interest;
  char fullpath[1024];
  int rv = 1, i;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr current_ctxt;
  xmlNodePtr current_node = (xmlNodePtr)section;

  current_ctxt = xpath_ctxt;
  if(!xpath_ctxt) return 0;
  if(current_node) {
    current_ctxt = xmlXPathNewContext(master_config);
    current_ctxt->node = current_node;
  }
  pobj = xmlXPathEval((xmlChar *)path, current_ctxt);
  if(pobj) {
    xmlNodePtr node;
    switch(pobj->type) {
      case XPATH_NODESET:
        if(xmlXPathNodeSetIsEmpty(pobj->nodesetval)) goto fallback;
        i = xmlXPathNodeSetGetLength(pobj->nodesetval);
        node = xmlXPathNodeSetItem(pobj->nodesetval, i-1);
        if(vnode) *vnode = node;
        *value = (char *)xmlXPathCastNodeToString(node);
        break;
      default:
        *value = (char *)xmlXPathCastToString(pobj);
    }
    goto found;
  }
 fallback:
  interest = path;
  if(*interest != '/' && current_node) {
    xmlChar *basepath = xmlGetNodePath(current_node);
    snprintf(fullpath, sizeof(fullpath), "%s/%s", (char *)basepath, path);
    free(basepath);
    interest = fullpath;
  }
  if(mtev_hash_retr_str(&_compiled_fallback,
                        interest, strlen(interest), &str)) {
    *value = (char *)xmlStrdup((xmlChar *)str);
    goto found;
  }
  rv = 0;
 found:
  if(pobj) xmlXPathFreeObject(pobj);
  if(current_ctxt && current_ctxt != xpath_ctxt)
    xmlXPathFreeContext(current_ctxt);
  return rv;
}

int
mtev_conf_get_uuid(mtev_conf_section_t section,
                   const char *path, uuid_t out) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    if(uuid_parse(str, out) == 0) return 1;
    return 0;
  }
  return 0;
}

int
mtev_conf_get_string(mtev_conf_section_t section,
                     const char *path, char **value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    *value = strdup(str);
    xmlFree(str);
    return 1;
  }
  return 0;
}

int
mtev_conf_get_stringbuf(mtev_conf_section_t section,
                        const char *path, char *buf, int len) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    strlcpy(buf, str, len);
    xmlFree(str);
    return 1;
  }
  return 0;
}

int
mtev_conf_property_iter(mtev_conf_section_t section,
                        int (*f)(const char *key, const char *val, void *closure),
                        void *closure) {
  int cnt = 0;
  xmlNodePtr node = (xmlNodePtr)section;
  xmlAttr *prop;
  if(!node) return 0;
  for(prop = node->properties; prop; prop = prop->next) {
    const char *key = (const char *)prop->name;
    char *value = (char *)xmlGetProp(node, prop->name);
    cnt += f(key,value,closure);
    xmlFree(value);
  }
  return cnt;
}

int
mtev_conf_set_string(mtev_conf_section_t section,
                     const char *path, const char *value) 
{
  mtev_conf_section_t *sections = NULL;
  xmlNodePtr current_node = (xmlNodePtr)section;

  if(!current_node) return 0;
  if(strchr(path, '/')) return 0;
  if(path[0] == '@') {
    xmlSetProp(current_node, (xmlChar *)path+1, (xmlChar *)value);
    CONF_DIRTY(current_node);
  }
  else {
    int cnt;
    xmlNodePtr child_node = NULL;
    sections = mtev_conf_get_sections(section, path, &cnt);
    if(cnt > 1) {
      char *spath = section ? (char *)xmlGetNodePath(section) : strdup("(root)");
      mtevL(mtev_error, "Ambiguous set_string \"%s\" \"%s\"\n", spath, path);
      free(spath);
      free(sections);
      return 0;
    }
    if(cnt == 0) {
      if(value) {
        child_node = xmlNewTextChild(current_node, NULL, (xmlChar *)path, (xmlChar *)value);
      }
      else {
        child_node = xmlNewChild(current_node, NULL, (xmlChar *)path, NULL);
      }
    }
    else if(cnt == 1) {
      xmlChar *encoded;
      encoded = xmlEncodeEntitiesReentrant(current_node->doc, (xmlChar *)value);
      xmlNodeSetContent((xmlNodePtr)sections[0], encoded);
      child_node = sections[0];
      xmlFree(encoded);
    }
    if(child_node != NULL)
      CONF_DIRTY(child_node);
  }
  mtev_conf_mark_changed();
  char *err;
  if(mtev_conf_write_file(&err) != 0) {
    mtevL(mtev_error, "local config write failed: %s\n", err ? err : "unkown");
    free(err);
  }
  free(sections);
  return 1;
}

int
mtev_conf_string_to_int(const char *str) {
  int base = 10;
  if(!str) return 0;
  if(str[0] == '0') {
    if(str[1] == 'x') base = 16;
    else base = 8;
  }
  return strtol(str, NULL, base);
}

int
mtev_conf_get_int(mtev_conf_section_t section,
                  const char *path, int *value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    *value = (int)mtev_conf_string_to_int(str);
    xmlFree(str);
    return 1;
  }
  return 0;
}

int
mtev_conf_get_int64(mtev_conf_section_t section,
                    const char *path, int64_t *value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    *value = strtoll(str, NULL, 10);
    xmlFree(str);
    return 1;
  }
  return 0;
}

int
mtev_conf_set_int(mtev_conf_section_t section,
                  const char *path, int value) {
  char buffer[32];
  snprintf(buffer, 32, "%d", value);
  return mtev_conf_set_string(section,path,buffer);
}

double
mtev_conf_string_to_double(const char *str) {
  if(!str) return 0.0;
  return strtod(str,NULL);
}

int
mtev_conf_get_double(mtev_conf_section_t section,
                    const char *path, double *value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    double val;
    char *endptr;
    val = strtod(str, &endptr);
    if(endptr) *value = val;
    xmlFree(str);
    return (endptr) ? 1 : 0;
  }
  return 0;
}

float
mtev_conf_string_to_float(const char *str) {
  if(!str) return 0.0;
  return atof(str);
}

int
mtev_conf_get_float(mtev_conf_section_t section,
                    const char *path, float *value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    float val;
    char *endptr;
    val = strtof(str, &endptr);
    if(endptr) *value = val;
    xmlFree(str);
    return (endptr) ? 1 : 0;
  }
  return 0;
}

int
mtev_conf_set_float(mtev_conf_section_t section,
                    const char *path, float value) {
  char buffer[32];
  snprintf(buffer, 32, "%f", value);
  return mtev_conf_set_string(section,path,buffer);
}

int
mtev_conf_set_double(mtev_conf_section_t section,
                     const char *path, double value) {
  char buffer[32];
  snprintf(buffer, 32, "%f", value);
  return mtev_conf_set_string(section,path,buffer);
}

mtev_boolean
mtev_conf_string_to_boolean(const char *str) {
  if(!str) return mtev_false;
  if(!strcasecmp(str, "true") || !strcasecmp(str, "on")) return mtev_true;
  return mtev_false;
}

int
mtev_conf_get_boolean(mtev_conf_section_t section,
                      const char *path, mtev_boolean *value) {
  char *str;
  if(_mtev_conf_get_string(section,NULL,path,&str)) {
    *value = mtev_conf_string_to_boolean(str);
    xmlFree(str);
    return 1;
  }
  return 0;
}

int
mtev_conf_set_boolean(mtev_conf_section_t section,
                      const char *path, mtev_boolean value) {
  if(value == mtev_true)
    return mtev_conf_set_string(section,path,"true");
  return mtev_conf_set_string(section,path,"false");
}

struct config_line_vstr {
  char *buff;
  int raw_len;
  int len;
  int allocd;
  mtev_conf_enc_type_t target, encoded;
};

static int
mtev_config_log_write_xml(void *vstr, const char *buffer, int len) {
  struct config_line_vstr *clv = vstr;
  mtevAssert(clv->encoded == CONFIG_XML);
  if(!clv->buff) {
    clv->allocd = 8192;
    clv->buff = malloc(clv->allocd);
  }
  while(len + clv->len > clv->allocd) {
    char *newbuff;
    int newsize = clv->allocd;
    newsize <<= 1;
    newbuff = realloc(clv->buff, newsize);
    if(!newbuff) {
      return -1;
    }
    clv->allocd = newsize;
    clv->buff = newbuff;
  }
  memcpy(clv->buff + clv->len, buffer, len);
  clv->len += len;
  return len;
}

static int
mtev_config_log_close_xml(void *vstr) {
  struct config_line_vstr *clv = vstr;
  uLong initial_dlen, dlen;
  char *compbuff, *b64buff;

  if(clv->buff == NULL) {
    clv->encoded = clv->target;
    return 0;
  }
  clv->raw_len = clv->len;
  mtevAssert(clv->encoded == CONFIG_XML);
  if(clv->encoded == clv->target) return 0;

  /* Compress */
  initial_dlen = dlen = compressBound(clv->len);
  compbuff = malloc(initial_dlen);
  if(!compbuff) return -1;
  if(Z_OK != compress2((Bytef *)compbuff, &dlen,
                       (Bytef *)clv->buff, clv->len, 9)) {
    mtevL(mtev_error, "Error compressing config for transmission.\n");
    free(compbuff);
    return -1;
  }
  free(clv->buff);
  clv->buff = compbuff;
  clv->allocd = initial_dlen;
  clv->len = dlen;
  clv->encoded = CONFIG_COMPRESSED;
  if(clv->encoded == clv->target) return 0;

  /* Encode */
  initial_dlen = ((clv->len + 2) / 3) * 4;
  b64buff = malloc(initial_dlen);
  dlen = mtev_b64_encode((unsigned char *)clv->buff, clv->len,
                         b64buff, initial_dlen);
  if(dlen == 0) {
    free(b64buff);
    return -1;
  }
  free(clv->buff);
  clv->buff = b64buff;
  clv->allocd = initial_dlen;
  clv->len = dlen;
  clv->encoded = CONFIG_B64;
  if(clv->encoded == clv->target) return 0;
  return -1;
}

int
mtev_conf_reload(mtev_console_closure_t ncct,
                 int argc, char **argv,
                 mtev_console_state_t *state, void *closure) {
  XML2CONSOLE(ncct);
  if(mtev_conf_load_internal(master_config_file)) {
    XML2LOG(xml_debug);
    nc_printf(ncct, "error loading config\n");
    return -1;
  }
  XML2LOG(xml_debug);
  return 0;
}

int
mtev_conf_write_terminal(mtev_console_closure_t ncct,
                         int argc, char **argv,
                         mtev_console_state_t *state, void *closure) {
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;
  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateIO(mtev_console_write_xml,
                                mtev_console_close_xml,
                                ncct, enc);

  mtev_conf_kansas_city_shuffle_undo(config_include_nodes, config_include_cnt);
  xmlSaveFormatFileTo(out, master_config, "utf8", 1);
  mtev_conf_kansas_city_shuffle_redo(config_include_nodes, config_include_cnt);
  return 0;
}

int
mtev_conf_write_file_console(mtev_console_closure_t ncct,
                             int argc, char **argv,
                             mtev_console_state_t *state, void *closure) {
  int rv;
  char *err = NULL;
  rv = mtev_conf_write_file(&err);
  nc_printf(ncct, "%s\n", err);
  if(err) free(err);
  return rv;
}

int
mtev_conf_write_file(char **err) {
  int fd, len;
  char master_file_tmp[PATH_MAX];
  char errstr[1024];
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;
  struct stat st;
  mode_t mode = 0640; /* the default */

  if(config_writes_disabled) return 0;

  uid_t uid = geteuid();
  gid_t gid = getegid();

  if(stat(master_config_file, &st) == 0) {
    mode = st.st_mode;
    uid = st.st_uid;
    gid = st.st_gid;
  }
  snprintf(master_file_tmp, sizeof(master_file_tmp),
           "%s.tmp", master_config_file);
  unlink(master_file_tmp);
  fd = open(master_file_tmp, O_CREAT|O_EXCL|O_WRONLY|NE_O_CLOEXEC, mode);
  if(fd < 0) {
    snprintf(errstr, sizeof(errstr), "Failed to open tmp file: %s",
             strerror(errno));
    if(err) *err = strdup(errstr);
    return -1;
  }
  if(fchown(fd, uid, gid) < 0) {
    close(fd);
    unlink(master_file_tmp);
    if(err) *err = strdup("internal error: fchown failed");
    return -1;
  }

  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateFd(fd, enc);
  if(!out) {
    close(fd);
    unlink(master_file_tmp);
    if(err) *err = strdup("internal error: OutputBufferCreate failed");
    return -1;
  }
  mtev_conf_kansas_city_shuffle_undo(config_include_nodes, config_include_cnt);
  mtev_conf_shatter_write(master_config);
  len = xmlSaveFormatFileTo(out, master_config, "utf8", 1);
  mtev_conf_shatter_postwrite(master_config);
  write_out_include_files(config_include_nodes, config_include_cnt);
  mtev_conf_kansas_city_shuffle_redo(config_include_nodes, config_include_cnt);
  close(fd);
  if(len <= 0) {
    if(err) *err = strdup("internal error: writing to tmp file failed.");
    return -1;
  }
  if(rename(master_file_tmp, master_config_file) != 0) {
    snprintf(errstr, sizeof(errstr), "Failed to replace file: %s",
             strerror(errno));
    if(err) *err = strdup(errstr);
    return -1;
  }
  snprintf(errstr, sizeof(errstr), "%d bytes written.", len);
  if(err) *err = strdup(errstr);
  return 0;
}

char *
mtev_conf_xml_in_mem(size_t *len) {
  struct config_line_vstr *clv;
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;
  char *rv;

  clv = calloc(1, sizeof(*clv));
  clv->target = CONFIG_XML;
  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateIO(mtev_config_log_write_xml,
                                mtev_config_log_close_xml,
                                clv, enc);
  mtev_conf_kansas_city_shuffle_undo(config_include_nodes, config_include_cnt);
  xmlSaveFormatFileTo(out, master_config, "utf8", 1);
  mtev_conf_kansas_city_shuffle_redo(config_include_nodes, config_include_cnt);
  if(clv->encoded != CONFIG_XML) {
    mtevL(mtev_error, "Error logging configuration\n");
    if(clv->buff) free(clv->buff);
    free(clv);
    return NULL;
  }
  rv = clv->buff;
  *len = clv->len;
  free(clv);
  return rv;
}

char *
mtev_conf_enc_in_mem(size_t *raw_len, size_t *len, mtev_conf_enc_type_t target, mtev_boolean inline_includes) {
  struct config_line_vstr *clv;
  xmlOutputBufferPtr out;
  xmlCharEncodingHandlerPtr enc;
  char *rv;

  clv = calloc(1, sizeof(*clv));
  clv->target = target;
  enc = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
  out = xmlOutputBufferCreateIO(mtev_config_log_write_xml,
                                mtev_config_log_close_xml,
                                clv, enc);
  if(!inline_includes) mtev_conf_kansas_city_shuffle_undo(config_include_nodes, config_include_cnt);
  xmlSaveFormatFileTo(out, master_config, "utf8", 1);
  if(!inline_includes) mtev_conf_kansas_city_shuffle_redo(config_include_nodes, config_include_cnt);
  if(clv->encoded != target) {
    mtevL(mtev_error, "Error logging configuration\n");
    if(clv->buff) free(clv->buff);
    free(clv);
    return NULL;
  }
  rv = clv->buff;
  *raw_len = clv->raw_len;
  *len = clv->len;
  free(clv);
  return rv;
}

int
mtev_conf_write_log(void) {
  /* This is deprecated */
  return -1;
}

struct log_rotate_crutch {
  mtev_log_stream_t ls;
  int seconds;
  int retain_seconds;
  size_t max_size;
  ssize_t retain_size;
};

static int
mtev_conf_log_cull(eventer_t e, int mask, void *closure,
                   struct timeval *now) {
  struct log_rotate_crutch *lrc = closure;
  if(!(mask & EVENTER_ASYNCH_WORK)) return 0;
  mtev_log_stream_cull(lrc->ls, lrc->retain_seconds, lrc->retain_size);
  return 0;
}

static void
schedule_background_log_cull(struct log_rotate_crutch *lrc) {
  eventer_t e;
  if(lrc->retain_size < 0 && lrc->retain_seconds < 0) return;
  e = eventer_alloc_asynch(mtev_conf_log_cull, lrc);
  eventer_add(e);
}

static int
mtev_conf_log_rotate_size(eventer_t e, int mask, void *closure,
                          struct timeval *now) {
  struct log_rotate_crutch *lrc = closure;
  if(mtev_log_stream_written(lrc->ls) > lrc->max_size) {
    mtev_log_stream_rename(lrc->ls, MTEV_LOG_RENAME_AUTOTIME);
    mtev_log_stream_reopen(lrc->ls);
    schedule_background_log_cull(lrc);
  }
  /* Yes the 5 is arbitrary, but this is cheap */
  eventer_add_in_s_us(mtev_conf_log_rotate_size, closure, 5, 0);
  return 0;
}

static int
mtev_conf_log_rotate_time(eventer_t e, int mask, void *closure,
                          struct timeval *now) {
  struct timeval lnow, whence;
  eventer_t newe;
  struct log_rotate_crutch *lrc = closure;

  if(now) {
    mtev_log_stream_rename(lrc->ls, MTEV_LOG_RENAME_AUTOTIME);
    mtev_log_stream_reopen(lrc->ls);
    schedule_background_log_cull(lrc);
  }
  
  if(!now) { mtev_gettimeofday(&lnow, NULL); now = &lnow; }
  if(e)
    whence = eventer_get_whence(e);
  else if(now) {
    memcpy(&whence, now, sizeof(whence));
    whence.tv_sec = (whence.tv_sec / lrc->seconds) * lrc->seconds;
  }
  whence.tv_sec += lrc->seconds;

  newe = eventer_alloc_timer(mtev_conf_log_rotate_time, closure, &whence);
  eventer_add(newe);
  return 0;
}

int
mtev_conf_log_init_rotate(const char *toplevel, mtev_boolean validate) {
  int i, cnt = 0, max_time, max_size, retain_seconds = -1, retain_size = -1, rv = 0;
  mtev_conf_section_t *log_configs;
  char path[256];

  snprintf(path, sizeof(path), "/%s/logs//log|/%s/include/logs//log", toplevel, toplevel);
  log_configs = mtev_conf_get_sections(NULL, path, &cnt);
  mtevL(mtev_debug, "Found %d %s stanzas\n", cnt, path);
  for(i=0; i<cnt; i++) {
    mtev_log_stream_t ls;
    char name[256];

    if(!mtev_conf_get_stringbuf(log_configs[i],
                                "ancestor-or-self::node()/@name",
                                name, sizeof(name))) {
      mtevL(mtev_error, "log section %d does not have a name attribute\n", i+1);
      if(validate) { rv = -1; break; }
      else exit(-2);
    }

    if(mtev_conf_env_off(log_configs[i], NULL)) {
      mtevL(mtev_debug, "log %s environmentally disabled.\n", name);
      continue;
    }

    ls = mtev_log_stream_find(name);
    if(!ls) continue;

    if(mtev_conf_get_int(log_configs[i],    
                         "ancestor-or-self::node()/@rotate_seconds",
                         &max_time) && max_time) {
      struct log_rotate_crutch *lrc;
      if(max_time < 600) {
        fprintf(stderr, "rotate_seconds must be >= 600s (10 minutes)\n");
        if(validate) { rv = -1; break; }
        else exit(-2);
      }
      mtev_conf_get_int(log_configs[i],
                        "ancestor-or-self::node()/@retain_seconds",
                        &retain_seconds);
      if(!validate) {
        lrc = calloc(1, sizeof(*lrc));
        lrc->ls = ls;
        lrc->seconds = max_time;
        lrc->retain_size = -1;
        lrc->retain_seconds = retain_seconds;
        mtev_conf_log_rotate_time(NULL, EVENTER_TIMER, lrc, NULL);
      }
    }

    if(mtev_conf_get_int(log_configs[i],    
                         "ancestor-or-self::node()/@rotate_bytes",
                         &max_size) && max_size) {
      struct log_rotate_crutch *lrc;
      if(max_size < 102400) {
        fprintf(stderr, "rotate_bytes must be >= 102400 (100k)\n");
        if(validate) { rv = -1; break; }
        else exit(-2);
      }
      mtev_conf_get_int(log_configs[i],
                        "ancestor-or-self::node()/@retain_bytes",
                        &retain_size);
      if(!validate) {
        lrc = calloc(1, sizeof(*lrc));
        lrc->ls = ls;
        lrc->max_size = max_size;
        lrc->retain_seconds = -1;
        lrc->retain_size = retain_size;
        mtev_conf_log_rotate_size(NULL, EVENTER_TIMER, lrc, NULL);
      }
    }
  }
  free(log_configs);
  return rv;
}

void
mtev_conf_log_init(const char *toplevel,
                   const char *drop_to_user, const char *drop_to_group) {
  int i, cnt = 0, o, ocnt = 0;
  mtev_conf_section_t *log_configs, *outlets;
  char path[256], user[128], group[128];

  snprintf(user, sizeof(user), "%d", getuid());
  snprintf(group, sizeof(group), "%d", getgid());
  if(!drop_to_user) drop_to_user = user;
  if(!drop_to_group) drop_to_group = group;
  if(mtev_security_usergroup(drop_to_user, drop_to_group, mtev_true)) {
    mtevL(mtev_stderr, "Failed to drop privileges, exiting.\n");
    exit(-1);
  }

  snprintf(path, sizeof(path), "/%s/logs//log|/%s/include/logs//log", toplevel, toplevel);
  log_configs = mtev_conf_get_sections(NULL, path, &cnt);
  mtevL(mtev_debug, "Found %d %s stanzas\n", cnt, path);
  for(i=0; i<cnt; i++) {
    int flags;
    mtev_log_stream_t ls;
    char name[256], type[256], path[256];
    mtev_hash_table *config;
    mtev_boolean disabled, debug, timestamps, facility;

    if(!mtev_conf_get_stringbuf(log_configs[i],
                                "ancestor-or-self::node()/@name",
                                name, sizeof(name))) {
      mtevL(mtev_error, "log section %d does not have a name attribute\n", i+1);
      exit(-1);
    }

    if(mtev_conf_env_off(log_configs[i], NULL)) {
      mtevL(mtev_debug, "log %s environmentally disabled.\n", name);
      continue;
    }

    if(!mtev_conf_get_stringbuf(log_configs[i],
                                "ancestor-or-self::node()/@type",
                                type, sizeof(type))) {
      type[0] = '\0';
    }
    if(!mtev_conf_get_stringbuf(log_configs[i],
                                "ancestor-or-self::node()/@path",
                                path, sizeof(path))) {
      path[0] = '\0';
    }
    config = mtev_conf_get_hash(log_configs[i],
                                "ancestor-or-self::node()/config");
    ls = mtev_log_stream_new(name, type[0] ? type : NULL,
                             path[0] ? path : NULL, NULL, config);
    if(!ls) {
      fprintf(stderr, "Error configuring log: %s[%s:%s]\n", name, type, path);
      exit(-1);
    }

    flags = mtev_log_stream_get_flags(ls);
    if(mtev_conf_get_boolean(log_configs[i],
                             "ancestor-or-self::node()/@disabled",
                             &disabled)) {
      if(disabled) flags &= ~MTEV_LOG_STREAM_ENABLED;
      else         flags |= MTEV_LOG_STREAM_ENABLED;
    }
    if(mtev_conf_get_boolean(log_configs[i],
                             "ancestor-or-self::node()/@debug",
                             &debug)) {
      if(debug) flags |= MTEV_LOG_STREAM_DEBUG;
      else      flags &= ~MTEV_LOG_STREAM_DEBUG;
    }
    if(mtev_conf_get_boolean(log_configs[i],
                             "ancestor-or-self::node()/@timestamps",
                             &timestamps)) {
      if(timestamps) flags |= MTEV_LOG_STREAM_TIMESTAMPS;
      else           flags &= ~MTEV_LOG_STREAM_TIMESTAMPS;
    }
    if(mtev_conf_get_boolean(log_configs[i],
                             "ancestor-or-self::node()/@facility",
                             &facility)) {
      if(facility) flags |= MTEV_LOG_STREAM_FACILITY;
      else         flags &= ~MTEV_LOG_STREAM_FACILITY;
    }
    mtev_log_stream_set_flags(ls, flags);

    outlets = mtev_conf_get_sections(log_configs[i],
                                     "ancestor-or-self::node()/outlet", &ocnt);
    mtevL(mtev_debug, "Found %d outlets for log '%s'\n", ocnt, name);

    mtev_log_stream_removeall_streams(ls);
    for(o=0; o<ocnt; o++) {
      mtev_log_stream_t outlet;
      char oname[256];
      mtev_conf_get_stringbuf(outlets[o], "@name",
                              oname, sizeof(oname));
      outlet = mtev_log_stream_find(oname);
      if(!outlet) {
        fprintf(stderr, "Cannot find outlet '%s' for %s[%s:%s]\n", oname,
              name, type, path);
        exit(-1);
      }
      else
        mtev_log_stream_add_stream(ls, outlet);
    }
    if(outlets) free(outlets);
  }
  if(log_configs) free(log_configs);
  if(mtev_conf_log_init_rotate(toplevel, mtev_true)) exit(-1);

  if(mtev_security_usergroup(user, group, mtev_true)) {
    mtevL(mtev_stderr, "Failed to regain privileges, exiting.\n");
    exit(-1);
  }
}

void
mtev_conf_security_init(const char *toplevel, const char *user,
                        const char *group, const char *chrootpath) {
  int i, ccnt = 0;
  mtev_conf_section_t *secnode, *caps;
  char path[256];
  char username[128], groupname[128], chrootpathname[PATH_MAX];

  snprintf(path, sizeof(path), "/%s/security|/%s/include/security",
           toplevel, toplevel);
  secnode = mtev_conf_get_section(NULL, path);

  if(user) {
    strlcpy(username, user, sizeof(username));
    user = username;
  }
  else if(secnode &&
          mtev_conf_get_stringbuf(secnode, "self::node()/@user",
                                  username, sizeof(username))) {
    user = username;
  }
  if(group) {
    strlcpy(groupname, group, sizeof(groupname));
    group = groupname;
  }
  else if(secnode &&
          mtev_conf_get_stringbuf(secnode, "self::node()/@group",
                                  groupname, sizeof(groupname))) {
    group = groupname;
  }
  if(chrootpath) {
    strlcpy(chrootpathname, chrootpath, sizeof(chrootpathname));
    chrootpath = chrootpathname;
  }
  else if(secnode &&
          mtev_conf_get_stringbuf(secnode, "self::node()/@chrootpath",
                                  chrootpathname, sizeof(chrootpathname))) {
    chrootpath = chrootpathname;
  }

  /* chroot first */
  if(chrootpath && mtev_security_chroot(chrootpath)) {
    mtevL(mtev_stderr, "Failed to chroot(), exiting.\n");
    exit(2);
  }

  caps = mtev_conf_get_sections(secnode,
                                "self::node()//capabilities//capability", &ccnt);
  mtevL(mtev_debug, "Found %d capabilities.\n", ccnt);

  for(i=0; i<ccnt; i++) {
    /* articulate capabilities */
    char platform[32], captype_str[32];
    char *capstring;
    mtev_security_captype_t captype;
    if(mtev_conf_get_stringbuf(caps[i], "ancestor-or-self::node()/@platform",
                               platform, sizeof(platform)) &&
       strcasecmp(platform, CAP_PLATFORM)) {
      mtevL(mtev_debug, "skipping cap for platform %s\n", platform);
      continue;
    }

    if(mtev_conf_env_off(caps[i], NULL)) {
      mtevL(mtev_debug, "capability %d environmentally disabled.\n", i);
      continue;
    }

    captype_str[0] = '\0'; 
    mtev_conf_get_stringbuf(caps[i], "ancestor-or-self::node()/@type",
                            captype_str, sizeof(captype_str));
    if(!strcasecmp(captype_str, "permitted"))
      captype = MTEV_SECURITY_CAP_PERMITTED;
    else if(!strcasecmp(captype_str, "effective"))
      captype = MTEV_SECURITY_CAP_EFFECTIVE;
    else if(!strcasecmp(captype_str, "inheritable"))
      captype = MTEV_SECURITY_CAP_INHERITABLE;
    else {
      mtevL(mtev_error, "Unsupport capability type: '%s'\n", captype_str);
      exit(2);
    }

    capstring = NULL;
    mtev_conf_get_string(caps[i], "self::node()", &capstring);
    if(capstring) {
      if(mtev_security_setcaps(captype, capstring) != 0) {
        mtevL(mtev_error, "Failed to set security capabilities: %s / %s\n",
              captype_str, capstring);
        exit(2);
      }
      free(capstring);
    }
  }
  if(caps) free(caps);

  /* drop uid/gid last */
  if(mtev_security_usergroup(user, group, mtev_false)) { /* no take backs */
    mtevL(mtev_stderr, "Failed to drop privileges, exiting.\n");
    exit(2);
  }
}

static void
conf_t_userdata_free(void *data) {
  mtev_conf_t_userdata_t *info = data;
  if(info) {
    if(info->path) free(info->path);
    free(info);
  }
}

static int
mtev_console_state_conf_terminal(mtev_console_closure_t ncct,
                                 int argc, char **argv,
                                 mtev_console_state_t *state, void *closure) {
  mtev_conf_t_userdata_t *info;
  if(argc) {
    nc_printf(ncct, "extra arguments not expected.\n");
    return -1;
  }
  info = calloc(1, sizeof(*info));
  info->path = strdup("/");
  mtev_console_userdata_set(ncct, MTEV_CONF_T_USERDATA, info,
                            conf_t_userdata_free);
  mtev_console_state_push_state(ncct, state);
  mtev_console_state_init(ncct);
  return 0;
}

static int
mtev_console_config_section(mtev_console_closure_t ncct,
                            int argc, char **argv,
                            mtev_console_state_t *state, void *closure) {
  const char *err = "internal error";
  char *path, xpath[1024];
  mtev_conf_t_userdata_t *info;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr xpath_ctxt = NULL;
  xmlNodePtr node = NULL, newnode;
  intptr_t delete = (intptr_t)closure;

  mtev_conf_xml_xpath(NULL, &xpath_ctxt);
  if(argc != 1) {
    nc_printf(ncct, "requires one argument\n");
    return -1;
  }
  if(strchr(argv[0], '/')) {
    nc_printf(ncct, "invalid section name\n");
    return -1;
  }
  if(is_stopnode_name(argv[0])) {
    nc_printf(ncct, "%s is reserved.\n", argv[0]);
    return -1;
  }
  info = mtev_console_userdata_get(ncct, MTEV_CONF_T_USERDATA);
  if(!strcmp(info->path, "/")) {
    nc_printf(ncct, "manipulation of toplevel section disallowed\n");
    return -1;
  }

  if(delete) {
    if(mtev_conf_delete_section_hook_invoke(root_node_name,
                                            info->path, argv[0],
                                            &err) == MTEV_HOOK_ABORT) {
       goto bad;
    }
  }

  snprintf(xpath, sizeof(xpath), "/%s%s/%s", root_node_name,
           info->path, argv[0]);
  pobj = xmlXPathEval((xmlChar *)xpath, xpath_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET) {
    err = "internal error: cannot detect section";
    goto bad;
  }
  if(!delete && !xmlXPathNodeSetIsEmpty(pobj->nodesetval)) {
    if(xmlXPathNodeSetGetLength(pobj->nodesetval) == 1) {
      node = xmlXPathNodeSetItem(pobj->nodesetval, 0);
      free(info->path);
      info->path = strdup((char *)xmlGetNodePath(node) +
                          1 + strlen(root_node_name));
      goto cdout;
    }
    err = "cannot create section";
    goto bad;
  }
  if(delete && xmlXPathNodeSetIsEmpty(pobj->nodesetval)) {
    err = "no such section";
    goto bad;
  }
  if(delete) {
    node = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, 0);
    if(node) {
      CONF_REMOVE(node);
      xmlUnlinkNode(node);
      mtev_conf_mark_changed();
    }
    return 0;
  }
  if(pobj) xmlXPathFreeObject(pobj);
  pobj = NULL;

  if(!strcmp(argv[0],"include")) {
    err = "include is a reserved section name";
    goto bad;
  }
  path = strcmp(info->path, "/") ? info->path : "";
  snprintf(xpath, sizeof(xpath), "/%s%s", root_node_name, path);
  pobj = xmlXPathEval((xmlChar *)xpath, xpath_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET ||
     xmlXPathNodeSetGetLength(pobj->nodesetval) != 1) {
    err = "path invalid?";
    goto bad;
  }
  node = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, 0);
  if((newnode = xmlNewChild(node, NULL, (xmlChar *)argv[0], NULL)) != NULL) {
    mtev_conf_mark_changed();
    free(info->path);
    info->path = strdup((char *)xmlGetNodePath(newnode) + 1 +
                        strlen(root_node_name));
  }
  else {
    err = "failed to create section";
    goto bad;
  }
 cdout:
  if(pobj) xmlXPathFreeObject(pobj);
  return 0;
 bad:
  if(pobj) xmlXPathFreeObject(pobj);
  nc_printf(ncct, "%s\n", err);
  return -1;
}

int
mtev_console_generic_show(mtev_console_closure_t ncct,
                          int argc, char **argv,
                          mtev_console_state_t *state, void *closure) {
  int i, cnt, titled = 0, cliplen = 0;
  const char *path = "", *basepath = NULL;
  char xpath[1024];
  mtev_conf_t_userdata_t *info = NULL;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr xpath_ctxt = NULL, current_ctxt;
  xmlDocPtr master_config = NULL;
  xmlNodePtr node = NULL;

  mtev_conf_xml_xpath(&master_config, &xpath_ctxt);
  if(argc > 1) {
    nc_printf(ncct, "too many arguments\n");
    return -1;
  }

  info = mtev_console_userdata_get(ncct, MTEV_CONF_T_USERDATA);
  if(info && info->path) path = basepath = info->path;
  if(!info && argc == 0) {
    nc_printf(ncct, "argument required when not in configuration mode\n");
    return -1;
  }

  if(argc == 1) path = argv[0];
  if(!basepath) basepath = path;

  /* { / } is a special case */
  if(!strcmp(basepath, "/")) basepath = "";
  if(!strcmp(path, "/")) path = "";

  if(!master_config || !xpath_ctxt) {
    nc_printf(ncct, "no config\n");
    return -1;
  }

  /* { / } is the only path that will end with a /
   * in XPath { / / * } means something _entirely different than { / * }
   * Ever notice how it is hard to describe xpath in C comments?
   */
  /* We don't want to show the root node */
  cliplen = strlen(root_node_name) + 2; /* /name/ */

  /* If we are in configuration mode
   * and we are without an argument or the argument is absolute,
   * clip the current path off */
  if(info && (argc == 0 || path[0] != '/')) cliplen += strlen(basepath);
  if(!path[0] || path[0] == '/') /* base only, or absolute path requested */
    snprintf(xpath, sizeof(xpath), "/%s%s/@*", root_node_name, path);
  else
    snprintf(xpath, sizeof(xpath), "/%s%s/%s/@*", root_node_name,
             basepath, path);

  current_ctxt = xpath_ctxt;
  pobj = xmlXPathEval((xmlChar *)xpath, current_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET) {
    nc_printf(ncct, "no such object\n");
    goto bad;
  }
  cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  titled = 0;
  for(i=0; i<cnt; i++) {
    node = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, i);
    if(node->children && node->children == xmlGetLastChild(node) &&
      xmlNodeIsText(node->children)) {
      if(!titled++) nc_printf(ncct, "== Section Settings ==\n");
      nc_printf(ncct, "%s: %s\n", xmlGetNodePath(node) + cliplen,
                xmlXPathCastNodeToString(node->children));
    }
  }
  xmlXPathFreeObject(pobj);

  /* _shorten string_ turning last { / @ * } to { / * } */
  if(!path[0] || path[0] == '/') /* base only, or absolute path requested */
    snprintf(xpath, sizeof(xpath), "/%s%s/*", root_node_name, path);
  else
    snprintf(xpath, sizeof(xpath), "/%s%s/%s/*",
             root_node_name, basepath, path);
  pobj = xmlXPathEval((xmlChar *)xpath, current_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET) {
    nc_printf(ncct, "no such object\n");
    goto bad;
  }
  cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);
  titled = 0;
  for(i=0; i<cnt; i++) {
    node = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, i);
    if(!(node->children && node->children == xmlGetLastChild(node) &&
         xmlNodeIsText(node->children))) {
      if(!titled++) nc_printf(ncct, "== Subsections ==\n");
      nc_printf(ncct, "%s\n", xmlGetNodePath(node) + cliplen);
    }
  }
  xmlXPathFreeObject(pobj);
  return 0;
 bad:
  if(pobj) xmlXPathFreeObject(pobj);
  return -1;
}

int
mtev_console_config_cd(mtev_console_closure_t ncct,
                       int argc, char **argv,
                       mtev_console_state_t *state, void *closure) {
  const char *err = "internal error";
  char *path = NULL, xpath[1024];
  mtev_conf_t_userdata_t *info;
  xmlXPathObjectPtr pobj = NULL;
  xmlXPathContextPtr xpath_ctxt = NULL, current_ctxt;
  xmlNodePtr node = NULL;
  char *dest;

  mtev_conf_xml_xpath(NULL, &xpath_ctxt);
  if(!master_config || !xpath_ctxt) {
    nc_printf(ncct, "no config\n");
    return -1;
  }
  if(argc != 1 && !closure) {
    nc_printf(ncct, "requires one argument\n");
    return -1;
  }
  dest = argc ? argv[0] : (char *)closure;
  info = mtev_console_userdata_get(ncct, MTEV_CONF_T_USERDATA);
  if(dest[0] == '/')
    snprintf(xpath, sizeof(xpath), "/%s%s", root_node_name, dest);
  else {
    snprintf(xpath, sizeof(xpath), "/%s%s/%s", root_node_name,
             info->path, dest);
  }
  if(xpath[strlen(xpath)-1] == '/') xpath[strlen(xpath)-1] = '\0';

  current_ctxt = xpath_ctxt;
  pobj = xmlXPathEval((xmlChar *)xpath, current_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET ||
     xmlXPathNodeSetIsEmpty(pobj->nodesetval)) {
    err = "no such section";
    goto bad;
  }
  if(xmlXPathNodeSetGetLength(pobj->nodesetval) > 1) {
    err = "ambiguous section";
    goto bad;
  }

  node = (mtev_conf_section_t)xmlXPathNodeSetItem(pobj->nodesetval, 0);
  if(!node) {
    err = "internal XML error";
    goto bad;
  }
  if(is_stopnode(node)) {
    err = "reserved word";
    goto bad;
  }
  path = (char *)xmlGetNodePath(node);
  if(strlen(path) < strlen(root_node_name) + 1 ||
     strncmp(path + 1, root_node_name, strlen(root_node_name)) ||
     (path[strlen(root_node_name) + 1] != '/' &&
      path[strlen(root_node_name) + 1] != '\0')) {
    err = "new path outside out tree";
    goto bad;
  }
  free(info->path);
  if(!strcmp(path + 1, root_node_name))
    info->path = strdup("/");
  else {
    char *xmlpath = (char *)xmlGetNodePath(node);
    info->path = strdup(xmlpath + 1 +
                        strlen(root_node_name));
    free(xmlpath);
  }

  free(path);
  if(pobj) xmlXPathFreeObject(pobj);
  if(closure) mtev_console_state_pop(ncct, argc, argv, NULL, NULL);
  return 0;
 bad:
  if(path) free(path);
  if(pobj) xmlXPathFreeObject(pobj);
  nc_printf(ncct, "%s [%s]\n", err, xpath);
  return -1;
}

static int
mtev_console_conf_show_xpath(mtev_console_closure_t ncct,
                             int argc, char **argv,
                             mtev_console_state_t *state, void *closure) {
  xmlXPathObjectPtr pobj = NULL;
  xmlNodePtr node = NULL;
  mtev_boolean xmlOut = mtev_false;

  mtev_conf_xml_xpath(NULL, &xpath_ctxt);
  if(argc == 2 && !strcmp(argv[0], "-x")) {
    xmlOut = mtev_true;
  }
  else if(argc != 1) {
    nc_printf(ncct, "show xpath [-x] <xpath expression>\n");
    return -1;
  }
  nc_printf(ncct, "Looking for '%s'\n", argv[argc-1]);
  pobj = xmlXPathEval((xmlChar *)argv[argc-1], xpath_ctxt);
  if(!pobj || pobj->type != XPATH_NODESET ||
     xmlXPathNodeSetIsEmpty(pobj->nodesetval)) {
    nc_printf(ncct, "no elements found\n");
    goto out;
  }
  int i, cnt = xmlXPathNodeSetGetLength(pobj->nodesetval);

  for(i=0; i<cnt; i++) {
    char *path;
    node = xmlXPathNodeSetItem(pobj->nodesetval, i);
    path = (char *)xmlGetNodePath(node);
    nc_printf(ncct, "== %d: %s ==\n", i+1, path);
    if(xmlOut) {
      xmlChar *xmlbuff;
      int buffersize;
      xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
      xmlDocSetRootElement(doc, xmlDocCopyNodeList(doc,node));
      xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
      nc_printf(ncct, "%s", xmlbuff);
      xmlFree(xmlbuff);
      xmlFreeDoc(doc);
    }
    else {
      nc_printf(ncct, "%s\n", xmlXPathCastNodeToString(node));
    }
    xmlFree(path);
  }
 out:
  if(pobj) xmlXPathFreeObject(pobj);
  return 0;
}
static char *
conf_t_prompt(EditLine *el) {
  mtev_console_closure_t ncct;
  mtev_conf_t_userdata_t *info;
  static char *tl = "mtev(conf)# ";
  static char *pfmt = "mtev(conf:%s%s)# ";
  int path_len, max_len;

  el_get(el, EL_USERDATA, (void *)&ncct);
  if(!ncct) return tl;
  info = mtev_console_userdata_get(ncct, MTEV_CONF_T_USERDATA);
  if(!info) return tl;

  path_len = strlen(info->path);
  max_len = sizeof(info->prompt) - (strlen(pfmt) - 4 /* %s%s */) - 1 /* \0 */;
  if(path_len > max_len)
    snprintf(info->prompt, sizeof(info->prompt),
             pfmt, "...", info->path + path_len - max_len + 3 /* ... */);
  else
    snprintf(info->prompt, sizeof(info->prompt), pfmt, "", info->path);
  return info->prompt;
}

#define NEW_STATE(a) (a) = mtev_console_state_alloc()
#define ADD_CMD(a,cmd,func,ac,ss,c) \
  mtev_console_state_add_cmd((a), \
    NCSCMD(cmd, func, ac, ss, c))
#define DELEGATE_CMD(a,cmd,ac,ss) \
  mtev_console_state_add_cmd((a), \
    NCSCMD(cmd, mtev_console_state_delegate, ac, ss, NULL))

void mtev_console_conf_init(void) {
  mtev_console_state_t *tl, *_conf_state, *_conf_t_state,
                       *_write_state, *_unset_state;

  tl = mtev_console_state_initial();

  /* write <terimal|memory|file> */
  NEW_STATE(_write_state);
  ADD_CMD(_write_state, "terminal", mtev_conf_write_terminal, NULL, NULL, NULL);
  ADD_CMD(_write_state, "file", mtev_conf_write_file_console, NULL, NULL, NULL);
  /* write memory?  It's to a file, but I like router syntax */
  ADD_CMD(_write_state, "memory", mtev_conf_write_file_console, NULL, NULL, NULL);

  NEW_STATE(_unset_state);
  ADD_CMD(_unset_state, "section",
          mtev_console_config_section, NULL, NULL, (void *)1);

  NEW_STATE(_conf_t_state); 
  _conf_t_state->console_prompt_function = conf_t_prompt;
  mtev_console_state_add_cmd(_conf_t_state, &console_command_exit);

  ADD_CMD(_conf_t_state, "ls", mtev_console_generic_show, NULL, NULL, NULL);
  ADD_CMD(_conf_t_state, "cd", mtev_console_config_cd, NULL, NULL, NULL);
  ADD_CMD(_conf_t_state, "section",
          mtev_console_config_section, NULL, NULL, (void *)0);

  DELEGATE_CMD(_conf_t_state, "write",
               mtev_console_opt_delegate, _write_state);
  DELEGATE_CMD(_conf_t_state, "no", mtev_console_opt_delegate, _unset_state);

  NEW_STATE(_conf_state);
  ADD_CMD(_conf_state, "terminal",
          mtev_console_state_conf_terminal, NULL, _conf_t_state, NULL);

  ADD_CMD(tl, "configure",
          mtev_console_state_delegate, mtev_console_opt_delegate,
          _conf_state, NULL);
  ADD_CMD(tl, "write",
          mtev_console_state_delegate, mtev_console_opt_delegate,
          _write_state, NULL);

  cmd_info_t *showcmd;
  showcmd = mtev_console_state_get_cmd(tl, "show");
  mtevAssert(showcmd && showcmd->dstate);

  mtev_console_state_add_cmd(showcmd->dstate,
    NCSCMD("conf", mtev_console_conf_show_xpath,
           NULL, NULL, NULL));
}

mtev_boolean mtev_conf_env_off(mtev_conf_section_t node, const char *attr) {
  char xpath[128];
  char buff[4096], *expr = buff, *key, *val, *envval;
  mtev_boolean negate = mtev_false;
  mtev_conf_section_t *reqs;
  pcre *regex = NULL;
  int erroff, ovector[30];
  int i, cnt;

  snprintf(xpath, sizeof(xpath), "ancestor-or-self::node()/@%s",
           attr ? attr : "require_env");
  if(!mtev_conf_get_stringbuf(node, xpath, buff, sizeof(buff)))
    return mtev_false;

  reqs = mtev_conf_get_sections(node, "ancestor-or-self::node()", &cnt);

  snprintf(xpath, sizeof(xpath), "@%s", attr ? attr : "require_env");
  for(i=0;i<cnt;i++) {
    if(!mtev_conf_get_stringbuf(reqs[i], xpath, buff, sizeof(buff))) continue;
    if(buff[0] == '!') {
      negate = mtev_true;
      expr++;
    }
    key = expr;
    val = strchr(key, '=');
    if(val) {
      *val++ = '\0';
    }
    else {
      val = strchr(key, '~');
      if(val) {
        *val++ = '\0';
        const char *pcre_err;
        regex = pcre_compile(val, 0, &pcre_err, &erroff, NULL);
        if(!regex) {
          mtevL(mtev_error, "pcre_compile(%s) failed offset %d: %s\n", val, erroff, pcre_err);
          goto quickoff;
        }
      }
    }

    envval = getenv(key);

    if(val == NULL) {
      /* existence checking */
      if((envval != NULL) ? negate : !negate) goto quickoff;
    }
    else if(envval) {
      if(regex) {
        int rv = pcre_exec(regex, NULL, envval, strlen(envval),
                           0, 0, ovector, sizeof(ovector)/sizeof(*ovector));
        if((rv >= 0) ? negate : !negate) {
          goto quickoff;
        }
      }
      else if((!strcmp(envval, val)) ? negate : !negate) {
        goto quickoff;
      }
    }
    if(regex) {
      pcre_free(regex);
      regex = NULL;
    }
  }

  return mtev_false;

 quickoff:
  if(regex) pcre_free(regex);
  free(reqs);
  return mtev_true;
}

void mtev_conf_init_globals(void) {
  mtev_hash_init_locks(&_compiled_fallback, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
}

