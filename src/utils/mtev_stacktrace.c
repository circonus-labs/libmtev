/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
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
#include "mtev_log.h"
#include "mtev_stacktrace.h"
#include "mtev_sort.h"
#include "mtev_skiplist.h"
#include "mtev_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#if defined(linux) || defined(__linux) || defined(__linux__)
#include <sys/types.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <link.h>
#endif
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <execinfo.h>
#if defined(__sun__)
#include <ucontext.h>
#include <sys/lwp.h>
#include <procfs.h>
#endif
#if defined(__MACH__) && defined(__APPLE__)
#include <libproc.h>
#endif
#ifdef HAVE_LIBDWARF
#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>
#endif
#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif
#include "android-demangle/demangle.h"
#include "android-demangle/cp-demangle.h"

MTEV_HOOK_IMPL(mtev_stacktrace_frame,
               (void (*cb)(void *, const char *, size_t), void *cb_closure,
                uintptr_t pc, const char *file, const char *func, int frame, int nframes),
               void *, closure,
               (void *closure, void (*cb)(void *, const char *, size_t), void *cb_closure,
                uintptr_t pc, const char *file, const char *func, int frame, int nframes),
               (closure, cb, cb_closure, pc, file, func, frame, nframes));

static mtev_boolean (*global_file_filter)(const char *);
static mtev_boolean (*global_file_symbol_filter)(const char *);

typedef enum { NOT_SET, ADDR_MAP_LINE, ADDR_MAP_FUNCTION } addr_map_type_t;

struct addr_map
{
  uintptr_t addr;
  int lineno;
  const char *file_or_fn;
  struct addr_map *next;
  addr_map_type_t type;
};
#ifdef HAVE_LIBDWARF
static void *addr_map_next(void *c) {
  return ((struct addr_map *)c)->next;
}
static void addr_map_set_next(void *c, void *n) {
  ((struct addr_map *)c)->next = n;
}
static int addr_map_cmp(void *left, void *right) {
  struct addr_map *l = left;
  struct addr_map *r = right;
  if(l->addr < r->addr) return -1;
  return (l->addr == r->addr) ? 0 : 1;
}
struct dmap_node {
  char *file;
  uintptr_t base;
  Dwarf_Debug dbg;
  struct dmap_node *next;
  struct srcfilelist {
    char **srcfiles;
    struct srcfilelist *next;
  } *files;
  struct addr_map *addr_map;
  mtev_hash_table types;
  int count;
};
static struct dmap_node *debug_maps = NULL;

struct typenode {
  Dwarf_Off id;
  Dwarf_Half tag;
  char *name;
  size_t size;
  struct typenode *resolved;
};
struct symnode {
  uintptr_t low, high;
  Dwarf_Off type;
  char *name;
};
static mtev_skiplist *symtable;

static void
dw_mtev_log(Dwarf_Error err, Dwarf_Ptr closure) {
  mtevL((mtev_log_stream_t)closure, "dwarf init error: %s\n", dwarf_errmsg(err));
}

static char *
dup_filename(const char *in) {
  const char *str = in, *n;
  n = strstr(str, "/tmp/");
  if(n) {
    n = strchr(n+5, '/');
    if(n) str = n-3;
  }
  else {
    n = strstr(str, "/home/");
    if(n) n = strchr(n+6, '/');
    if(n) str = n-3;
  }
  char *out = strdup(str);
  if(in != str && strlen(out) > 3) {
    out[0] = out[1] = out[2] = '.';
  }
  return out;
}
static void
mtev_register_die(struct dmap_node *node, Dwarf_Die die, int level) {
  (void)level;
  Dwarf_Line *lines;
  char **srcfiles;
  Dwarf_Signed nlines = 0, nsrcfiles = 0;
  Dwarf_Error error = 0;
  if(dwarf_srcfiles(die, &srcfiles, &nsrcfiles, &error)) {
    return;
  }
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
  struct srcfilelist *mylist = calloc(1, sizeof(*mylist));
  mylist->next = node->files;
  node->files = mylist;
  mylist->srcfiles = calloc(nsrcfiles, sizeof(char *));
  for(int i=0; i<nsrcfiles; i++) mylist->srcfiles[i] = dup_filename(srcfiles[i]);
  if(dwarf_srclines(die, &lines, &nlines, &error) == DW_DLV_OK) {
    for(int i = 0; i < nlines; i++) {
      Dwarf_Unsigned uno;
      Dwarf_Addr addr;
      struct addr_map li = { .next = NULL, .type = ADDR_MAP_LINE };
      char *filename;
      Dwarf_Bool begin_line;
      Dwarf_Bool end_die;
      mtev_boolean line_error = mtev_false;
      if (dwarf_linesrc(lines[i], &filename, &error) != DW_DLV_OK) {
        line_error = mtev_true;
        filename = "?";
      }
      if (dwarf_linebeginstatement(lines[i], &begin_line, &error) != DW_DLV_OK) {
        line_error = mtev_true;
        begin_line = 0;
      }
      if (dwarf_lineendsequence(lines[i], &end_die, &error) != DW_DLV_OK) {
        line_error = mtev_true;
        end_die = 0;
      }
      Dwarf_Bool  prol_end = 0;
      Dwarf_Bool  epi_begin = 0;
      Dwarf_Unsigned isa = 0;
      Dwarf_Unsigned discrim = 0;
      if (dwarf_prologue_end_etc(lines[i], &prol_end, &epi_begin, &isa, &discrim, &error) != DW_DLV_OK) {
        line_error = mtev_true;
      }
      if(dwarf_lineno(lines[i], &uno, &error) != DW_DLV_OK) {
        line_error = mtev_true;
      }
      else {
        li.lineno = (int)uno;
      }
      if(dwarf_line_srcfileno(lines[i], &uno, &error) != DW_DLV_OK) {
        line_error = mtev_true;
      }
      else {
        li.file_or_fn = mylist->srcfiles[uno-1];
      }
      if(dwarf_lineaddr(lines[i], &addr, &error) != DW_DLV_OK) {
        line_error = mtev_true;
      }
      else {
        li.addr = (uintptr_t)addr;
      }
      if (strstr(node->file, "snowth")) {
      mtevL(dwarf_log, "%s dwarf_linesrc: %s:%u(%p) %llu %llu %s%s%s%s\n", line_error ? "BAD" : "GOOD", filename, li.lineno, (void *)addr, isa, discrim, begin_line ? "BEGIN " : "", end_die ? "END " : "", prol_end ? "PROL" : "", epi_begin ? "EPI" : "");
      }
      if (!line_error && li.lineno > 0) {
        struct addr_map *head = calloc(1, sizeof(struct addr_map));
        memcpy(head, &li, sizeof(struct addr_map));
        head->next = node->addr_map;
        node->addr_map = head;
        node->count++;
      }
    }
  }
  dwarf_srclines_dealloc(node->dbg, lines, nlines);
  return;
}
const char *mtev_function_name(uintptr_t addr) {
  if(!symtable) return NULL;
  mtev_skiplist_node *iter, *prev, *next;
  if(mtev_skiplist_find_neighbors(symtable, &addr, &iter, &prev, &next)) {
    if(!iter) iter = prev;
    if(iter) {
      struct symnode *n = mtev_skiplist_data(iter);
      if(n && n->low <= addr && n->high >= addr) return n->name;
    }
  }
  return NULL;
}
static struct typenode *cache_type(struct dmap_node *node, Dwarf_Off off) {
  const char *tag_name = "unknown";
  char *die_name;
  Dwarf_Die die = 0;
  Dwarf_Error err;
  Dwarf_Attribute attr;

  if(dwarf_offdie(node->dbg, off, &die, &err) == DW_DLV_OK) {
    Dwarf_Half tag;
    if(dwarf_diename(die, &die_name, &err) == DW_DLV_OK &&
       dwarf_tag(die, &tag, &err) == DW_DLV_OK &&
       dwarf_get_TAG_name(tag, &tag_name) == DW_DLV_OK) {
      void *vptr;
      if(!mtev_hash_retrieve(&node->types, (const char *)&off, sizeof(off), &vptr)) {
        struct typenode *n = calloc(1, sizeof(*n));
        n->id = off;
        mtev_hash_replace(&node->types, (const char *)&n->id, sizeof(n->id), n, NULL, free);
        n->tag = tag;
        n->name = strdup(die_name);
        n->resolved = n;
        if(n->tag == DW_TAG_typedef) {
          if(dwarf_attr(die, DW_AT_type, &attr, &err) == DW_DLV_OK) {
            Dwarf_Off off;
            dwarf_global_formref(attr, &off, &err);
            n->resolved = cache_type(node, off);
          }
        }
        if(dwarf_attr(die, DW_AT_byte_size, &attr, &err) == DW_DLV_OK) {
          Dwarf_Unsigned size;
          dwarf_formudata(attr, &size, &err);
          n->size = size;
        }
        vptr = n;
      }
      return vptr;
    }
  }
  return NULL;
}
static void extract_symbols(struct dmap_node *node, Dwarf_Die sib, mtev_log_stream_t dwarf_log) {
  const char *tag_name;
  char *die_name;
  Dwarf_Error err;
  Dwarf_Half tag;
  Dwarf_Die child_die = 0;

if (strstr(node->file, "libmtev")) {
  mtevL(dwarf_log, "**** EXTRACT SYMBOLS\n");
}
  if(global_file_symbol_filter && global_file_symbol_filter(node->file)) return;

  if(dwarf_child(sib, &child_die, &err) == DW_DLV_OK) {
    do {
      extract_symbols(node, child_die, dwarf_log);
    } while(dwarf_siblingof(node->dbg, child_die, &child_die, &err) == DW_DLV_OK);
  }
  if(dwarf_tag(sib, &tag, &err) == DW_DLV_OK &&
     dwarf_get_TAG_name(tag, &tag_name) == DW_DLV_OK &&
     dwarf_diename(sib, &die_name, &err) == DW_DLV_OK) {
    Dwarf_Attribute* attrs;
    Dwarf_Addr pc = 0;
    Dwarf_Off off = 0;
    Dwarf_Attribute attr;
    Dwarf_Signed attrcount, i;
    Dwarf_Bool flag;
    struct symnode n = { .low = 0 };
    switch(tag) {
      case DW_TAG_variable:
if (strstr(node->file, "libmtev")) {
  mtevL(dwarf_log, "**** EXTRACT SYMBOLS variable\n");
}
        if(dwarf_attr(sib, DW_AT_external, &attr, &err) != DW_DLV_OK ||
           dwarf_formflag(attr, &flag, &err) != DW_DLV_OK ||
           flag == 0) break;
        n.low = (uintptr_t)dlsym(NULL, die_name);
        /* fall through */
      case DW_TAG_subprogram:
if (strstr(node->file, "libmtev")) {
  mtevL(dwarf_log, "**** EXTRACT SYMBOLS subprogram\n");
}
        if(dwarf_attrlist(sib, &attrs, &attrcount, &err) == DW_DLV_OK) {
          for(i=0; i<attrcount; i++) {
            Dwarf_Half attrcode;            
            if (dwarf_whatattr(attrs[i], &attrcode, &err) == DW_DLV_OK)
            {
              if (attrcode == DW_AT_type)
              {
                dwarf_global_formref(attrs[i], &off, &err);
                n.type = off;
                struct typenode *t = cache_type(node, off);
                if(t) {
                  while(t->resolved && t->resolved != t) t = t->resolved;
                  n.high = n.low + t->size;
                }
if (strstr(node->file, "libmtev")) {
                mtevL(dwarf_log, "T Lo: %p Hi: %p NB: %p T: %p\n", (void *)n.low, (void *)n.high, (void *)node->base, t);
}
              } else if(attrcode == DW_AT_low_pc) {
                dwarf_formaddr(attrs[i], &pc, &err);
                n.low = pc + node->base;
if (strstr(node->file, "libmtev")) {
                mtevL(dwarf_log, "L Lo: %p Hi: %p NB: %p\n", (void *)n.low, (void *)n.high, (void *)node->base);
}
              } else if(attrcode == DW_AT_high_pc) {
                Dwarf_Half form;
                Dwarf_Unsigned offset = 0;
                dwarf_whatform(attrs[i], &form, &err);
                switch(form) {
                  default:
                  case DW_FORM_addr:
                    dwarf_formaddr(attrs[i], &pc, &err);
                    n.high = pc + node->base;
                  break;
                  case DW_FORM_data8:
                    dwarf_formudata(attrs[i], &offset, &err);
                    n.high = n.low + offset;
                  break;
                }
if (strstr(node->file, "libmtev")) {
                mtevL(dwarf_log, "H Lo: %p Hi: %p NB: %p\n", (void *)n.low, (void *)n.high, (void *)node->base);
}
              }
            }
          }
          if(n.low) {
if (strstr(node->file, "libmtev")) {
            mtevL(dwarf_log, "symbol: %llu:%s, %p-%p\n", n.type, die_name, (void *)n.low, (void *)n.high);
}
            struct addr_map *head = calloc(1, sizeof(struct addr_map));
            head->addr = n.low - node->base;
            head->type = ADDR_MAP_FUNCTION;
            head->file_or_fn = strdup(die_name);
            head->next = node->addr_map;
            node->addr_map = head;
            if(n.high) {
              struct symnode *copy = malloc(sizeof(*copy));
              copy->name = strdup(die_name);
              copy->low = n.low;
              copy->high = n.high;
              copy->type = n.type;
              if (mtev_skiplist_insert(symtable, copy) == NULL)
              {
                free(copy->name);
                free(copy);
              }
            }
          }
        }
        break;
      default:
        break;
    }
  }
}

static struct dmap_node *
mtev_dwarf_load(const char *file, uintptr_t base) {
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
  mtevL(dwarf_log, "***** DWARF LOAD %s\n", file);
  struct dmap_node *node = calloc(1, sizeof(*node));
  mtev_hash_init(&node->types);
  node->file = strdup(file);
  node->base = base;
  mtevL(dwarf_log, "dwarf loading %s @ %p\n", file, (void *)base);
  int fd = open(node->file, O_RDONLY);
  // try to handle where no path is given because it is the main binary
  // and our current working folder is not where the main binary is
  if (fd < 0) {
    char fullpath[PATH_MAX];
    int length = readlink("/proc/self/exe", fullpath, sizeof(fullpath));
    if (length && length < PATH_MAX) {
      fullpath[length] = '\0';
      char *bin_name = strrchr(fullpath, '/');
      if (!bin_name) bin_name = fullpath;
      else bin_name++;
      if (!strcmp(bin_name, node->file)) {
        fd = open(fullpath, O_RDONLY);
      }
    }
  }
  Dwarf_Error err;
  if(fd >= 0) {
    if(dwarf_init(fd, DW_DLC_READ, dw_mtev_log, mtev_error, &node->dbg, &err) == DW_DLV_OK) {
      while(1) {
        Dwarf_Unsigned cu_header_length = 0;
        Dwarf_Half version_stamp = 0;
        Dwarf_Unsigned abbrev_offset = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Half length_size = 0;
        Dwarf_Half extension_size = 0;
        Dwarf_Unsigned next_cu_header = 0;
        Dwarf_Error error;
        Dwarf_Die no_die = 0;
        Dwarf_Die cu_die = 0;
        if(dwarf_next_cu_header_b(node->dbg, &cu_header_length,
                                  &version_stamp, &abbrev_offset, &address_size,
                                  &length_size, &extension_size,
                                  &next_cu_header, &error) != DW_DLV_OK) break;
        if(dwarf_siblingof(node->dbg, no_die, &cu_die, &error) != DW_DLV_OK) break;
        /* tag extract */
        extract_symbols(node, cu_die, dwarf_log);
        mtev_register_die(node, cu_die, 0);
        dwarf_dealloc(node->dbg, cu_die, DW_DLA_DIE);
      }
    }
    dwarf_finish(node->dbg, &err);
    mtevL(dwarf_log, "dwarf loaded %s @ %p (%d items)\n", file, (void *)base, node->count);
    node->dbg = 0;
    close(fd);
  }
  mtev_merge_sort((void **)&node->addr_map, addr_map_next, addr_map_set_next, addr_map_cmp);
  return node;
}
void
mtev_dwarf_refresh_file(const char *file, uintptr_t base) {
  struct dmap_node *node;
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
  mtevL(dwarf_log, "**** DWARF REFRESH FILE %s\n", file);
  if(!file || strlen(file) == 0) return;
  mtevL(dwarf_log, "**** DWARF REFRESH FILE2 %s\n", file);
  if(global_file_filter && global_file_filter(file)) return;
  mtevL(dwarf_log, "**** DWARF REFRESH FILE3 %s\n", file);
  if(!debug_maps) {
  mtevL(dwarf_log, "**** DWARF REFRESH FILE4 %s\n", file);
    debug_maps = mtev_dwarf_load(file, base);
  }
  else {
  mtevL(dwarf_log, "**** DWARF REFRESH FILE5 %s\n", file);
    struct dmap_node *prev = NULL;
    for(node = debug_maps; node; node = node->next) {
      prev = node;
      if(!strcmp(node->file, file) && node->base == base) return;
    }
    if(prev) prev->next = mtev_dwarf_load(file, base);
  }
  mtevL(dwarf_log, "Addr map info mapping is %p\n", debug_maps);
}
static void
mtev_dwarf_walk_map(void (*f)(const char *, uintptr_t)) {
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
  mtevL(dwarf_log, "***** DWARF WALK MAP\n");
#if defined(linux) || defined(__linux) || defined(__linux__)
  Dl_info dlip;
  struct link_map *map;
  void *main_f = dlsym(NULL, "main");
  if(dladdr1(main_f, &dlip, (void **)&map, RTLD_DL_LINKMAP)) {
    /* The executable maps at 0x0, regardless of other claims */
    f(dlip.dli_fname, 0);
    for(;map;map=map->l_next) {
      f(map->l_name, map->l_addr);
    }
  }
#elif defined(__sun__)
  char mapname[PATH_MAX];
  int pid = getpid();
  snprintf(mapname, sizeof(mapname), "/proc/%d/xmap", pid);
  int mapfd = open(mapname, O_RDONLY);
  if(mapfd >= 0) {
    int rv;
    struct stat st;
    while(-1 == (rv = fstat(mapfd, &st)) && errno == EINTR) {}
    if(rv >= 0) {
      int nmap = st.st_size / sizeof(prxmap_t);
      prxmap_t *maps = calloc(nmap, sizeof(prxmap_t));
      if(read(mapfd, (void *)maps, st.st_size) == st.st_size) {
        for(int i=0; i<nmap; i++) {
          char inname[PATH_MAX];
          char pathname[4096];
          /* We're debugging instruction pointers, they have to be executable */
          if((maps[i].pr_mflags & MA_EXEC) == 0) continue;
          /* Illumos has the annoying thing where it will map a lib in
           * several separate, but otherwise contiguous, chunks.
           * skip those as we mapped the whole object at the base addr. */
          if(i > 0 &&
             !strcmp(maps[i-1].pr_mapname, maps[i].pr_mapname) &&
             maps[i-1].pr_vaddr + maps[i-1].pr_size == maps[i].pr_vaddr &&
             maps[i-1].pr_offset + (ssize_t)maps[i-1].pr_size == maps[i].pr_offset) {
            continue;
          }
          /* The map name is an object that soft links to the path, resolve it. */
          snprintf(inname, sizeof(inname), "/proc/%d/path/%s", pid, maps[i].pr_mapname);
          if((rv = resolvepath(inname, pathname, sizeof(pathname))) != -1) {
            pathname[rv] = '\0'; /* pathname isn't terminated by resolvepath, sigh. */
            /* a.out (our exec) might be mapped above one, but for addr resolution
             * it still must be treated like a 0x0 mapping. */
            uintptr_t base_addr = !strcmp(maps[i].pr_mapname, "a.out") ? 0 : maps[i].pr_vaddr;
            f(pathname, base_addr);
          }
        }
      }
      free(maps);
    }
    close(mapfd);
  }
#else
#endif
}
#else
const char *mtev_function_name(uintptr_t addr) {
  (void)addr;
  return NULL;
}
#endif

void
mtev_dwarf_filter(mtev_boolean (*f)(const char *file)) {
  global_file_filter = f;
}
void
mtev_dwarf_filter_symbols(mtev_boolean (*f)(const char *file)) {
  global_file_symbol_filter = f;
}
#ifdef HAVE_LIBDWARF
static int loc_comp(const void *va, const void *vb) {
  const struct symnode *a = va;
  const struct symnode *b = vb;
  if(a->low < b->low) return -1;
  if(a->low == b->low) return 0;
  return 1;
}
static int loc_comp_key(const void *vakey, const void *vb) {
  const uintptr_t *akey = vakey;
  const struct symnode *b = vb;
  if(*akey < b->low) return -1;
  if(*akey == b->low) return 0;
  return 1;
}
#endif
void
mtev_dwarf_refresh(void) {
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
  mtevL(dwarf_log, "***** DWARF REFRESH\n");
#ifdef HAVE_LIBDWARF
  if(!symtable) {
    mtev_skiplist *st = mtev_skiplist_alloc();
    mtev_skiplist_set_compare(st, loc_comp, loc_comp_key);
    symtable = st;
  }
  mtev_dwarf_walk_map(mtev_dwarf_refresh_file);
#else
  return;
#endif
}

static struct addr_map *
find_addr_map(uintptr_t addr, ssize_t *offset, const char **fn_name, uintptr_t *fn_offset) {
  struct addr_map *found_line = NULL;
  struct addr_map *found_function = NULL;
  mtev_log_stream_t dwarf_log = mtev_log_stream_find("debug/dwarf");
#ifdef HAVE_LIBDWARF
  struct dmap_node *node = NULL, *iter;
  for(iter = debug_maps; iter; iter = iter->next) {
  mtevL(dwarf_log, "Checking node: %s (%08lx, %08lx)\n", iter->file, addr, iter->base);
    if(iter->base <= addr) {
      if(!node) node = iter;
      else if(iter->base > node->base) node = iter;
    }
  }
  if(!node)
  {
    mtevL(dwarf_log, "Node not found: %08lx: %p\n", addr, debug_maps);
    return NULL;
  }
  mtevL(dwarf_log, "Found node: %s (%08lx, %08lx) %p\n", node->file, addr, node->base, node->addr_map);
  for (struct addr_map *addr_map = node->addr_map; addr_map; addr_map = addr_map->next)
  {
    if (strstr(node->file, "snowth")) { mtevL(dwarf_log, "Addr: %u %08lx : %s\n", addr_map->lineno, addr_map->addr, addr_map->file_or_fn); }
    if(node->base + addr_map->addr <= addr) {
      if (addr_map->type == ADDR_MAP_LINE) {
        found_line = addr_map;
      }
      else if (addr_map->type == ADDR_MAP_FUNCTION) {
        found_function = addr_map;
      }
    }
    else {
      if (found_line) mtevL(dwarf_log, "Found line! %u %08lx : %s\n", found_line->lineno, found_line->addr, found_line->file_or_fn);
      break;
    }
    if (!addr_map->next) { mtevL(dwarf_log, "Last addr: %u %08lx : %s\n", addr_map->lineno, addr_map->addr, addr_map->file_or_fn); }
  }
  if(found_line) {
    uintptr_t faddr = found_line->addr + node->base;
    ssize_t off = addr > faddr ? (ssize_t)(addr - faddr) : (ssize_t)(-(faddr - addr));
    // throw away clearly badly resolved source lines (more than 4k offset)
    if (off > 0x1000) found_line = NULL;
    else if (offset) *offset = off;
  }
  if (found_function) {
    mtevL(dwarf_log, "Found function! %08lx -> %08lx : %s\n", addr, found_function->addr, found_function->file_or_fn);
    *fn_name = found_function->file_or_fn;
    *fn_offset = addr - node->base - found_function->addr;
  }
#else
  (void)addr;
  (void)offset;
  *fn_name = NULL;
#endif
  return found_line;
}

static void
mtev_print_stackline(mtev_log_stream_t ls, uintptr_t self,
                     const char *extra_thr, const char *addrline) {
  char *tick;
  char addrpostline[16384], scratch[8192], postfix_copy[32], trailer_copy[32];
  strlcpy(addrpostline, addrline, sizeof(addrpostline));
  if(isspace(addrpostline[0])) goto print;
  tick = strchr(addrpostline, '\'');
  if(!tick) tick = strchr(addrpostline, '(');
  if(!tick) tick = strchr(addrpostline, '[');
  if(tick) {
    char *trailer = NULL;
    char *postfix;
    if(*tick == '(') {
      postfix = strchr(tick, ')');
      if(postfix) {
        *postfix++ = '\0';
        trailer = postfix;
        strlcpy(trailer_copy, trailer, sizeof(trailer_copy));
      }
    }
    if(*tick == '[') {
      postfix = strchr(tick, ']');
      if(postfix) {
        *postfix++ = '\0';
        trailer = postfix;
        strlcpy(trailer_copy, trailer, sizeof(trailer_copy));
      }
    }
    *tick++ = '\'';
    postfix = strrchr(tick, '+');
    if(postfix) {
     if(strlen(postfix) > sizeof(postfix_copy)-1) goto print;
     *postfix++ = '\0';
     strlcpy(postfix_copy, postfix, sizeof(postfix_copy));
    }
    scratch[0] = '\0';
    cplus_demangle_set_buf(scratch, sizeof(scratch));
    char *decoded = cplus_demangle_v3(tick, DMGL_PARAMS|DMGL_ANSI|DMGL_TYPES);
    if(decoded != NULL) {
      snprintf(tick, sizeof(addrpostline) - (int)(tick-addrpostline), "%s%s%s%s%s",
               decoded, postfix?"+":"", postfix_copy, trailer ? " " : "", trailer_copy);
    }
    else {
      if(postfix) *(postfix-1) = '+';
    }
  }
 print:
  mtevL(ls, "t@%"PRIu64"%s> %s\n", self, extra_thr ? extra_thr : "", addrpostline);
}
#if !defined(__sun__)
static __thread int _global_stack_trace_fd = -1;
#endif
static void append_global_stacktrace(void *closure, const char *line, size_t line_len) {
#if defined(__sun__)
  mtev_log_stream_t ls = closure;
  mtevL(ls, "%.*s", (int)line_len, line);
#else
  mtev_log_stream_t ls = closure;
  if(write(_global_stack_trace_fd, line, line_len) < 0) {
    mtevL(ls, "Error recording stacktrace.\n");
  }
#endif
}

#if defined(__sun__)
struct walkinfo {
  mtev_log_stream_t ls;
  int frame;
  int nframes;
  int stop;
};
int mtev_simple_stack_frame_count(uintptr_t pc, int sig, void *usrarg) {
  (void)pc;
  (void)sig;
  struct walkinfo *wi = usrarg;
  wi->nframes++;
  return 0;
}
int mtev_simple_stack_print(uintptr_t pc, int sig, void *usrarg) {
  (void)sig;
  lwpid_t self;
  struct walkinfo *wi = usrarg;
  if(wi->stop) return 0;
  mtev_log_stream_t ls = wi->ls;
  char addrpreline[16384];
  self = _lwp_self();
  addrtosymstr((void *)pc, addrpreline, sizeof(addrpreline));
  ssize_t line_off = 0;
  char *fn_name;
  uintptr_t fn_off = 0;
  struct addr_map *line_map = find_addr_map((uintptr_t)pc, &line_off, &fn_name, &fn_off);
  mtev_print_stackline(ls, self, NULL, addrpreline);
  if(line_map) {
    char fn_info[1024] = {'\0'};
    char buff[1024];
    if (fn_name) snprintf(fn_info, sizeof(fn_info), "%s+%"PRIx64":", fn_name, fn_off);
    if(line_off > 256 || line_off < -256)
      snprintf(buff, sizeof(buff), "\t(%s:%s%d off: %zd)", line_map->file_or_fn, fn_info, line_map->lineno, line_off);
    else
      snprintf(buff, sizeof(buff), "\t(%s:%s%d)", line_map->file_or_fn, fn_info, line_map->lineno);
    mtev_print_stackline(ls, self, NULL, buff);
  }
  char *symname = strchr(addrpreline, '\'');
  if(symname) *symname++ = '\0';
  if(mtev_stacktrace_frame_hook_invoke(append_global_stacktrace, NULL,
                                       (uintptr_t)pc, addrpreline, symname,
                                       wi->frame++, wi->nframes) == MTEV_HOOK_ABORT) {
    wi->stop = 1;
  }
  return 0;
}
#endif

static void
mtev_stacktrace_internal(mtev_log_stream_t ls, void *caller,
                         const char *extra_thr, void *vucp, void **callstack, int frames) {
#if defined(__sun__)
  (void)caller;
  (void)callstack;
  (void)frames;
  struct walkinfo walkinfo = { ls, 0, 0, 0 };
  ucontext_t ucp;
  getcontext(&ucp);
  mtevL(ls, "STACKTRACE(%d%s):\n", getpid(), extra_thr);
  walkcontext(vucp ? vucp : &ucp, mtev_simple_stack_frame_count, &walkinfo);
  if(walkinfo.nframes <= 1) {
    vucp = &ucp;
    walkinfo.nframes = 0;
    walkcontext(vucp ? vucp : &ucp, mtev_simple_stack_frame_count, &walkinfo);
  }
  walkcontext(vucp ? vucp : &ucp, mtev_simple_stack_print, &walkinfo);
#else
  (void)vucp;
  if(_global_stack_trace_fd < 0) {
    /* Last ditch effort to open this up */
    /* This is Async-Signal-Safe (at least on Illumos) */
    char tmpfilename[MAXPATHLEN];
    snprintf(tmpfilename, sizeof(tmpfilename), "/var/tmp/mtev_%d_XXXXXX", (int)getpid());
    /* Coverity warns about calling `mkstemp` in a tmp directory without setting the umask,
     * but it is impossible to set the umask for a single thread, and code running in other
     * threads may rely on the umask having a specific value. It is unsafe to set umask here.
     * The vulnerability that coverity is concerned with will have to do with opening a file
     * with too-wide permissions, but `mkstemp` uses narrow permissions of 0600 on every
     * platform that libmtev supports, so this is not a vulnerability for us. */
    /* coverity[secure_temp] */
    _global_stack_trace_fd = mkstemp(tmpfilename);
    if(_global_stack_trace_fd >= 0) unlink(tmpfilename);
  }
  if(_global_stack_trace_fd >= 0) {
    struct stat sb;
    char stackbuff[65536];
    int unused __attribute__((unused));
    int i;
    lseek(_global_stack_trace_fd, 0, SEEK_SET);
    unused = ftruncate(_global_stack_trace_fd, 0);
    for(i=0; i<frames; i++) {
      Dl_info dlip;
      void *base = NULL;
      int len = 0;
      ssize_t line_off = 0;
      const char *sname_dwarf = NULL;
      uintptr_t sname_off = 0;
      struct addr_map *line_map = find_addr_map((uintptr_t)callstack[i], &line_off, &sname_dwarf, &sname_off);
      char buff[256];
      buff[0] = '\0';
      if(line_map) {
        if(line_off > 256 || line_off < -256)
          snprintf(buff, sizeof(buff), "\n\t(%s:%d off: %zd)", line_map->file_or_fn, line_map->lineno, line_off);
        else
          snprintf(buff, sizeof(buff), "\n\t(%s:%d)", line_map->file_or_fn, line_map->lineno);
      }
      mtevL(ls, "buff is %s\n", buff);
      const char *fname = NULL;
      const char *sname = NULL;
#if defined(linux) || defined(__linux) || defined(__linux__)
      struct link_map *map;
      if(dladdr1((void *)callstack[i], &dlip, (void **)&map, RTLD_DL_LINKMAP)) {
        while(map) {
          if(dlip.dli_fbase == (void *)map->l_addr) {
            base = dlip.dli_fbase;
            break;
          }
          map = map->l_next;;
        }
#else
      if(dladdr((void *)callstack[i], &dlip)) {
#endif
        fname = dlip.dli_fname;
        sname = dlip.dli_sname;
        if (sname_dwarf || sname)
        {
          //base = dlip.dli_saddr ? dlip.dli_saddr : base;
          uintptr_t offset = 0;
          if (sname_dwarf) offset = sname_off;
          else offset = (uintptr_t)(callstack[i] - dlip.dli_saddr);
          len = snprintf(stackbuff, sizeof(stackbuff), "%s'%s+0x%" PRIx64 "[0x%" PRIx64 "]%s\n",
                         fname, sname ? sname : sname_dwarf,
                         sname ? (uintptr_t)(callstack[i] - dlip.dli_saddr) : offset,
                         (uintptr_t)(callstack[i] - base), buff);
        } else {
          len = snprintf(stackbuff, sizeof(stackbuff), "%s[0x%"PRIx64"]%s\n",
                         fname, (uintptr_t)(callstack[i]-base), buff);
        }
        mtevL(ls, "stackbuff is %s\n", stackbuff);
        if(dlip.dli_saddr == caller && i == 0) continue;
      } else {
        len = snprintf(stackbuff, sizeof(stackbuff), "%016"PRIx64"\n", (uintptr_t)callstack[i]);
        mtevL(ls, "stackbuff is %s\n", stackbuff);
      }
      if(write(_global_stack_trace_fd, stackbuff, len) < 0) {
        mtevL(ls, "Error recording stacktrace.\n");
      }
      if(mtev_stacktrace_frame_hook_invoke(append_global_stacktrace, NULL,
                                           (uintptr_t)callstack[i], fname, sname,
                                           i, frames) == MTEV_HOOK_ABORT) break;
      stackbuff[0] = '\0';
    }
    memset(&sb, 0, sizeof(sb));
    while((i = fstat(_global_stack_trace_fd, &sb)) == -1 && errno == EINTR);
    if(i != 0 || sb.st_size <= 0) mtevL(ls, "error writing stacktrace\n");
    lseek(_global_stack_trace_fd, SEEK_SET, 0);
    i = read(_global_stack_trace_fd, stackbuff, MIN(sizeof(stackbuff)-1, (size_t)sb.st_size));
    if (i >= 0) {
      stackbuff[i] = '\0';
    } else {
      snprintf(stackbuff, sizeof(stackbuff) - 1, "*** Cannot read stacktrace from %d ***", _global_stack_trace_fd);
    }
    char *prevcp = stackbuff, *cp;
    mtevL(ls, "STACKTRACE(%d%s):\n", getpid(), extra_thr ? extra_thr : "");
#if defined(linux) || defined(__linux) || defined(__linux__)
    uintptr_t self = syscall(SYS_gettid);
#else
    pthread_t self = pthread_self();
#endif
    while(NULL != (cp = strchr(prevcp, '\n'))) {
      *cp++ = '\0';
      mtev_print_stackline(ls, self, extra_thr, prevcp);
      prevcp = cp;
    }
    mtev_print_stackline(ls, self, extra_thr, prevcp);
  }
  else {
    mtevL(ls, "stacktrace unavailable\n");
  }
#endif
}

int mtev_backtrace(void **callstack, int cnt) {
  int frames = 0;
#if defined(HAVE_LIBUNWIND)
  unw_cursor_t cursor;
  unw_context_t context;

  // Initialize cursor to current frame for local unwinding.
  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  // Unwind frames one by one, going up the frame stack.
  while (unw_step(&cursor) > 0 && frames<cnt) {
    unw_word_t pc;
    unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (pc == 0) {
      break;
    }
    callstack[frames++] = (void *)pc;
  }
#else
  frames = backtrace(callstack, cnt);
#endif
  return frames;
}
#if defined(__sun__)
void mtev_stacktrace_ucontext(mtev_log_stream_t ls, ucontext_t *ucp) {
  void* callstack[128];
  int frames = mtev_backtrace(callstack, 128);
  mtev_stacktrace_internal(ls, mtev_stacktrace, NULL, (void *)ucp, callstack, frames);
}
#endif
void mtev_stacktrace(mtev_log_stream_t ls) {
  void* callstack[128];
  int frames = mtev_backtrace(callstack, 128);
  mtev_stacktrace_internal(ls, mtev_stacktrace, NULL, NULL, callstack, frames);
}

int
mtev_aco_stacktrace(mtev_log_stream_t ls, aco_t *co) {
  void *ips[128];
  char extra_thr[32];
  int cnt = mtev_aco_backtrace(co, ips, sizeof(ips)/sizeof(*ips));
  snprintf(extra_thr, sizeof(extra_thr), "/%" PRIx64, (uintptr_t)co);
  mtev_stacktrace_internal(ls, mtev_aco_stacktrace, extra_thr, NULL, ips, cnt);
  return cnt;
}

int mtev_aco_backtrace(aco_t *co, void **addrs, int addrs_len) {
    void *stk;
    size_t stksz;
    size_t offset = 0;
    int i = 0;

    if(co->is_end) return 0;
    if(aco_get_co() == co) return 0;
    if(addrs_len < 1) return 0;

    // sp points to the next frame back
    void *sp = co->reg[ACO_REG_IDX_SP];
    if(co->share_stack->owner == co) {
        stk = co->reg[ACO_REG_IDX_SP];
        stksz = co->share_stack->align_retptr - sp;
    } else {
        stk = co->save_stack.ptr;
        stksz = co->save_stack.valid_sz;
        // saved stack is offset from one on which it usually functions
        offset = co->reg[ACO_REG_IDX_SP] - co->save_stack.ptr;
        // we're not active so look off into the save stack
        sp -= offset;
    }
    void *ip = co->reg[ACO_REG_IDX_RETADDR];

#if defined(HAVE_LIBUNWIND)
    unw_cursor_t cursor;
    unw_context_t uc;

#ifdef __x86_64__
    /* r12 r13 r14 r15 rip rsp rbx rbp */
    uc.uc_mcontext.gregs[REG_R12] = (uintptr_t)co->reg[0];
    uc.uc_mcontext.gregs[REG_R13] = (uintptr_t)co->reg[1];
    uc.uc_mcontext.gregs[REG_R14] = (uintptr_t)co->reg[2];
    uc.uc_mcontext.gregs[REG_R15] = (uintptr_t)co->reg[3];
    uc.uc_mcontext.gregs[REG_RIP] = (uintptr_t)ip;
    uc.uc_mcontext.gregs[REG_RSP] = (uintptr_t)sp;
    uc.uc_mcontext.gregs[REG_RBX] = (uintptr_t)co->reg[6];
    uc.uc_mcontext.gregs[REG_RBP] = (uintptr_t)co->reg[7] - offset;
    uc.uc_stack.ss_sp = (void *)sp;
    uc.uc_stack.ss_size = stksz;
#else
#error "Unimplemented architecture."
#endif
    unw_init_local(&cursor, &uc);
    addrs[i++] = co->reg[ACO_REG_IDX_RETADDR];
    //mtevL(mtev_debug, "STK CHECK: %p << [%p,%p] << %p\n", stk, sp, (void *) uc.uc_mcontext.gregs[REG_RBP], stk+stksz);
    while (unw_step(&cursor) > 0 && i < addrs_len) {
      unw_word_t uip, usp, urbp;
      unw_get_reg(&cursor, UNW_REG_IP, &uip);
      unw_get_reg(&cursor, UNW_REG_SP, &usp);
      unw_get_reg(&cursor, UNW_X86_64_RBP, &urbp);

      sp = (void *)(urbp - offset); // This is where we're about to jump to
      //mtevL(mtev_debug, "STK CHECK: %p << [%p,%p] << %p\n", stk, (void *)(usp - offset), sp, stk+stksz);
      if(sp < stk || sp >= stk + stksz) break;

      addrs[i++] = (void *)uip;
      if(addrs[i-1] == co->share_stack->align_retptr) break;

      // At each step, we must jump back into our saved stack
      // this effects out stack pointer and our return frame pointer
      unw_set_reg(&cursor, UNW_REG_SP, usp - offset);
      unw_set_reg(&cursor, UNW_X86_64_RBP, urbp - offset);
    }
    /* This worked... */
    if(addrs_len > 1 && i > 1) return i;
    i = 0;
#endif

    // This will only work (mostly) with -fno-omit-framepointers
    sp = co->reg[ACO_REG_IDX_BP] - offset;
    while(i < addrs_len) {
      addrs[i++] = ip;
      // we could be at the top of the unwind, so we're done.
      if(ip == co->share_stack->align_retptr) break;
      // if for some reason we're outside of our stack, there's a smash
      if(sp < stk || sp >= stk + stksz || *((void **)sp) == NULL) break;

      // IP is the RBP + WORD
      ip = *(void **)(sp + sizeof(void *));
      // prior stack point is RBP.
      sp = *(void **)sp - offset;
    }
    return i;
}
