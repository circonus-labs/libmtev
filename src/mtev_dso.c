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
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>

#include "mtev_dso.h"
#include "mtev_conf.h"
#include "mtev_hash.h"
#include "mtev_log.h"

MTEV_HOOK_IMPL(dso_post_init,
  (),
  void *, closure,
  (void *closure),
  (closure))

static mtev_image_t *
mtev_load_generic_image(mtev_dso_loader_t *loader,
                        char *g_name,
                        mtev_conf_section_t section);

mtev_dso_loader_t __mtev_image_loader = {
  {
    MTEV_LOADER_MAGIC,
    MTEV_LOADER_ABI_VERSION,
    "image",
    "Basic binary image loader",
    NULL
  },
  NULL,
  NULL,
  mtev_load_generic_image
};

static mtev_hash_table loaders;
static mtev_hash_table generics;
static int mtev_dso_load_failure_count = 0;

int mtev_dso_load_failures() {
  return mtev_dso_load_failure_count;
}
mtev_dso_loader_t * mtev_loader_lookup(const char *name) {
  void *vloader;

  if(mtev_hash_retrieve(&loaders, name, strlen(name), &vloader))
    return (mtev_dso_loader_t *)vloader;
  return NULL;
}

int
mtev_dso_list(mtev_hash_table *t, const char ***f) {
  mtev_hash_iter iter = MTEV_HASH_ITER_ZERO;
  const char *name;
  int klen, i = 0;
  void *vhdr;

  if(mtev_hash_size(t) == 0) {
    *f = NULL;
    return 0;
  }

  *f = calloc(mtev_hash_size(t), sizeof(**f));
  while(mtev_hash_next(t, &iter, (const char **)&name, &klen,
                       &vhdr)) {
    (*f)[i++] = name;
  }
  return i;
}

static int
mtev_dso_list_loaders(const char ***f) {
  return mtev_dso_list(&loaders, f);
}

static int
mtev_dso_list_generics(const char ***f) {
  return mtev_dso_list(&generics, f);
}

mtev_dso_generic_t *mtev_dso_generic_lookup(const char *name) {
  void *vmodule;

  if(mtev_hash_retrieve(&generics, name, strlen(name), &vmodule))
    return (mtev_dso_generic_t *)vmodule;
  return NULL;
}

static int mtev_dso_generic_validate_magic(mtev_image_t *obj) {
  if (MTEV_IMAGE_MAGIC(obj) != MTEV_GENERIC_MAGIC) return -1;
  if (MTEV_IMAGE_VERSION(obj) != MTEV_GENERIC_ABI_VERSION) return -1;
  return 0;
}

static int mtev_dso_loader_validate_magic(mtev_image_t *obj) {
  if (MTEV_IMAGE_MAGIC(obj) != MTEV_LOADER_MAGIC) return -1;
  if (MTEV_IMAGE_VERSION(obj) != MTEV_LOADER_ABI_VERSION) return -1;
  return 0;
}

int mtev_load_image(const char *file, const char *name,
                    mtev_hash_table *registry,
                    int (*validate)(mtev_image_t *),
                    size_t obj_size) {
  char module_file[PATH_MAX];
  const char *dlsymname;
  void *dlhandle = NULL;
  void *dlsymbol;
  mtev_image_t *obj;

  if(file[0] == '/') {
    strlcpy(module_file, file, sizeof(module_file));
    dlhandle = dlopen(module_file, RTLD_LAZY | RTLD_GLOBAL);
  }
  else {
    char *basepath, *base, *brk;
    if(!mtev_conf_get_string(NULL, "//modules/@directory", &basepath))
      basepath = strdup("");
    for (base = strtok_r(basepath, ";:", &brk);
         base;
         base = strtok_r(NULL, ";:", &brk)) {
      snprintf(module_file, sizeof(module_file), "%s/%s.%s",
               base, file, MODULEEXT);
      dlhandle = dlopen(module_file, RTLD_LAZY | RTLD_GLOBAL);
      if(dlhandle) break;
      if(!dlhandle) {
         mtevL(mtev_debug, "Cannot open image '%s': %s\n",
               module_file, dlerror());
      }
    }
    free(basepath);
    if(!dlhandle) {
      snprintf(module_file, sizeof(module_file), "%s/%s.%s",
               MTEV_MODULES_DIR, file, MODULEEXT);
      dlhandle = dlopen(module_file, RTLD_LAZY | RTLD_GLOBAL);
    }
  }

  if(!dlhandle) {
    mtevL(mtev_stderr, "Cannot open image '%s': %s\n",
          module_file, dlerror());
    return -1;
  }

  dlsymname = strrchr(name, ':');
  if(!dlsymname) dlsymname = name;
  else dlsymname++;
  dlsymbol = dlsym(dlhandle, dlsymname);
  if(!dlsymbol) {
    mtevL(mtev_stderr, "Cannot find '%s' in image '%s': %s\n",
          dlsymname, module_file, dlerror());
    dlclose(dlhandle);
    return -1;
  }

  if(validate(dlsymbol) == -1) {
    mtevL(mtev_stderr, "I can't understand module %s\n", name);
    dlclose(dlhandle);
    return -1;
  }

  obj = calloc(1, obj_size);
  memcpy(obj, dlsymbol, obj_size);
  obj->opaque_handle = calloc(1, sizeof(struct __extended_image_data));

  if(obj->onload && obj->onload(obj)) {
    free(obj->opaque_handle);
    free(obj);
    dlclose(dlhandle);
    return -1;
  }
  char *namecopy = strdup(name);
  if(!mtev_hash_store(registry, namecopy, strlen(namecopy), obj)) {
    mtevL(mtev_error, "Attempted to load module %s more than once.\n", name);
    dlclose(dlhandle);
    free(namecopy);
    return -1;
  }
  ((struct __extended_image_data *)obj->opaque_handle)->dlhandle = dlhandle;
  return 0;
}

static mtev_image_t *
mtev_load_generic_image(mtev_dso_loader_t *loader,
                        char *g_name,
                        mtev_conf_section_t section) {
  char g_file[PATH_MAX];

  if(!mtev_conf_get_stringbuf(section, "ancestor-or-self::node()/@image",
                              g_file, sizeof(g_file))) {
    mtevL(mtev_stderr, "No image defined for %s\n", g_name);
    return NULL;
  }
  if(mtev_load_image(g_file, g_name, &generics,
                     mtev_dso_generic_validate_magic,
                     sizeof(mtev_dso_generic_t))) {
    mtevL(mtev_stderr, "Could not load generic %s:%s\n", g_file, g_name);
    return NULL;
  }
  return (mtev_image_t *)mtev_dso_generic_lookup(g_name);
}

static mtev_image_t *
mtev_load_loader_image(mtev_dso_loader_t *loader,
                       char *loader_name,
                       mtev_conf_section_t section) {
  char loader_file[PATH_MAX];

  if(!mtev_conf_get_stringbuf(section, "ancestor-or-self::node()/@image",
                              loader_file, sizeof(loader_file))) {
    mtevL(mtev_stderr, "No image defined for %s\n", loader_name);
    return NULL;
  }
  if(mtev_load_image(loader_file, loader_name, &loaders,
                     mtev_dso_loader_validate_magic,
                     sizeof(mtev_dso_loader_t))) {
    mtevL(mtev_stderr, "Could not load loader %s:%s\n", loader_file, loader_name);
    mtev_dso_load_failure_count++;
    return NULL;
  }
  return (mtev_image_t *)mtev_loader_lookup(loader_name);
}

void mtev_dso_init() {
  mtev_conf_section_t *sections;
  int i, cnt = 0;

  mtev_dso_add_type("loader", mtev_dso_list_loaders);
  mtev_dso_add_type("generic", mtev_dso_list_generics);

  /* Load our generic modules */
  sections = mtev_conf_get_sections(NULL, "//modules//generic", &cnt);
  for(i=0; i<cnt; i++) {
    char g_name[256];
    mtev_dso_generic_t *gen;
    mtev_conf_section_t *include_sections = NULL;
    int section_cnt;

    if(!mtev_conf_get_stringbuf(sections[i], "ancestor-or-self::node()/@name",
                                g_name, sizeof(g_name))) {
      mtevL(mtev_stderr, "No name defined in generic stanza %d\n", i+1);
      continue;
    }
    gen = (mtev_dso_generic_t *)
      mtev_load_generic_image(&__mtev_image_loader, g_name,
                              sections[i]);
    if(!gen) {
      mtevL(mtev_stderr, "Failed to load generic %s\n", g_name);
      mtev_dso_load_failure_count++;
      continue;
    }
    if(gen->config) {
      int rv;
      mtev_hash_table *config;
      include_sections = mtev_conf_get_sections(sections[i], "include", &section_cnt);
      if ((include_sections) && (section_cnt == 1)) {
        config = mtev_conf_get_hash(*include_sections, "config");
      }
      else {
        config = mtev_conf_get_hash(sections[i], "config");
      }
      rv = gen->config(gen, config);
      if(rv == 0) {
        mtev_hash_destroy(config, free, free);
        free(config);
      }
      else if(rv < 0) {
        mtevL(mtev_stderr, "Failed to config generic %s\n", g_name);
        continue;
      }
    }
    if(gen->init && gen->init(gen)) {
      mtevL(mtev_stderr, "Failed to init generic %s\n", g_name);
      mtev_dso_load_failure_count++;
    }
    else
      mtevL(mtev_debug, "Generic module %s successfully loaded.\n", g_name);
  }
  if(sections) free(sections);
  /* Load our module loaders */
  sections = mtev_conf_get_sections(NULL, "//modules//loader", &cnt);
  for(i=0; i<cnt; i++) {
    char loader_name[256];
    mtev_dso_loader_t *loader;
    mtev_conf_section_t *include_sections = NULL;
    int section_cnt;

    if(!mtev_conf_get_stringbuf(sections[i], "ancestor-or-self::node()/@name",
                                loader_name, sizeof(loader_name))) {
      mtevL(mtev_stderr, "No name defined in loader stanza %d\n", i+1);
      continue;
    }
    loader = (mtev_dso_loader_t *)
      mtev_load_loader_image(&__mtev_image_loader, loader_name,
                             sections[i]);
    if(!loader) {
      mtevL(mtev_stderr, "Failed to load loader %s\n", loader_name);
      mtev_dso_load_failure_count++;
      continue;
    }
    if(loader->config) {
      int rv;
      mtev_hash_table *config;
      include_sections = mtev_conf_get_sections(sections[i], "include", &section_cnt);
      if ((include_sections) && (section_cnt == 1)) {
        config = mtev_conf_get_hash(*include_sections, "config");
      }
      else {
        config = mtev_conf_get_hash(sections[i], "config");
      }
      rv = loader->config(loader, config);
      if(rv == 0) {
        mtev_hash_destroy(config, free, free);
        free(config);
      }
      else if(rv < 0) {
        mtevL(mtev_stderr, "Failed to config loader %s\n", loader_name);
        mtev_dso_load_failure_count++;
        continue;
      }
    }
    if(loader->init && loader->init(loader))
      mtevL(mtev_stderr, "Failed to init loader %s\n", loader_name);
  }
  if(sections) free(sections);
}

void mtev_dso_post_init() {
  if(dso_post_init_hook_invoke() == MTEV_HOOK_ABORT) {
    mtevL(mtev_stderr, "Module post initialization phase failed.\n");
    mtev_dso_load_failure_count++;
  }
  if(mtev_log_final_resolve() == mtev_false) {
    mtevL(mtev_stderr, "Some loggers remain disconnected.\n");
  }
}

void *
mtev_dso_alloc_opaque_handle() {
  return calloc(1, sizeof(struct __extended_image_data));
}

static struct dso_type *dso_types = NULL;
struct dso_type *mtev_dso_get_types() { return dso_types; }

void mtev_dso_add_type(const char *name, int (*list)(const char ***)) {
  struct dso_type *node;
  node = calloc(1, sizeof(*node));
  node->name = strdup(name);
  node->list = list;
  node->next = dso_types;
  dso_types = node;
}

void mtev_dso_init_globals() {
  mtev_hash_init_locks(&loaders, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
  mtev_hash_init_locks(&generics, MTEV_HASH_DEFAULT_SIZE, MTEV_HASH_LOCK_MODE_MUTEX);
}

#define userdata_accessors(type, field) \
void *mtev_##type##_get_userdata(mtev_##type##_t *mod) { \
  return mod->field->userdata; \
} \
void mtev_##type##_set_userdata(mtev_##type##_t *mod, void *newdata) { \
  mod->field->userdata = newdata; \
}

userdata_accessors(image, opaque_handle)
userdata_accessors(dso_loader, hdr.opaque_handle)
