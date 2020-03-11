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

#ifndef _MTEV_CONF_H
#define _MTEV_CONF_H

#include "mtev_defines.h"
#include "mtev_hash.h"
#include "mtev_console.h"
#include "mtev_hooks.h"
#include "mtev_uuid.h"

#include <pcre.h>

#ifndef mtev_conf_section_t
#define mtev_conf_section_t mtev_conf_section_opaque_t
#endif
typedef struct mtev_conf_section_opaque {
  void *opaque1;
  void *opaque2;
} mtev_conf_section_opaque_t;

API_EXPORT(mtev_conf_section_t) MTEV_CONF_ROOT;
API_EXPORT(mtev_conf_section_t) MTEV_CONF_EMPTY;

typedef enum {
  MTEV_PARAM_INT8,
  MTEV_PARAM_UINT8,
  MTEV_PARAM_INT16,
  MTEV_PARAM_UINT16,
  MTEV_PARAM_INT32,
  MTEV_PARAM_UINT32,
  MTEV_PARAM_INT64,
  MTEV_PARAM_UINT64,
  MTEV_PARAM_FLOAT,
  MTEV_PARAM_DOUBLE,
  MTEV_PARAM_BOOLEAN
} mtev_param_type_t;

typedef mtev_boolean (*mtev_param_validator_t)(mtev_param_type_t, void *mem);
typedef mtev_boolean (*mtev_param_parser_t)(const char *, mtev_param_type_t, void *mem);
mtev_boolean
mtev_conf_register_global_param(const char *name, const char *xpath,
                                mtev_param_type_t ptype, void *mem,
                                mtev_param_parser_t parser,
                                mtev_param_validator_t validator);

#define MTEV_CONF_T_USERDATA "mtev::state::conf_t"
typedef struct {
  char *path;
  uuid_t current_check;
  char filter_name[50];
  char prompt[80];
} mtev_conf_t_userdata_t;

enum mtev_conf_type {
  MTEV_CONF_TYPE_BOOLEAN,
  MTEV_CONF_TYPE_INT32,
  MTEV_CONF_TYPE_INT64,
  MTEV_CONF_TYPE_FLOAT,
  MTEV_CONF_TYPE_DOUBLE,
  MTEV_CONF_TYPE_STRING,
  MTEV_CONF_TYPE_UUID,
  MTEV_CONF_TYPE_UINT32,
  MTEV_CONF_TYPE_UINT64
};

typedef union mtev_conf_value_t {
  mtev_boolean val_bool;
  int32_t val_int32;
  int64_t val_int64;
  uint32_t val_uint32;
  uint64_t val_uint64;
  float val_float;
  double val_double;
  char* val_string;
  uuid_t val_uuid;
} mtev_conf_value_t;

typedef struct mtev_conf_default_or_optional_t {
  int is_optional;
  mtev_conf_value_t value;
} mtev_conf_default_or_optional_t;

typedef struct mtev_conf_description_t {
  mtev_conf_section_t section;
  char* path;
  enum mtev_conf_type type;
  char* description;
  mtev_conf_default_or_optional_t default_or_optional;
  mtev_conf_value_t value;
} mtev_conf_description_t;

/* allow an app name to be registered for config root node identification */
API_EXPORT(void) mtev_set_app_name(const char *new_name);
API_EXPORT(const char *) mtev_get_app_name(void);

API_EXPORT(void) mtev_set_app_version(const char *version);
API_EXPORT(const char *)mtev_get_app_version(void);

/* seconds == 0 disable config journaling watchdog */
API_EXPORT(void) mtev_conf_coalesce_changes(uint32_t seconds);
/* Start the watchdog */
API_EXPORT(void) mtev_conf_watch_and_journal_watchdog(int (*f)(void *), void *c);
/* expose the current "generation" of the config */
API_EXPORT(uint32_t) mtev_conf_config_gen(void);

/* marks the config as changed.. if you manipulate the XML tree in any way
 * you must call this function to "let the system know."  This is used
 * to notice changes which are in turn flushed out.
 */
API_EXPORT(void) mtev_conf_mark_changed(void);

API_EXPORT(void) mtev_conf_init(const char *toplevel);
API_EXPORT(void) mtev_conf_init_globals(void);
API_EXPORT(void)
  mtev_override_console_stopword(int (*f)(const char *));
API_EXPORT(int) mtev_conf_load(const char *path);

#define mtev_conf_default_hdr(name, type) \
API_EXPORT(mtev_conf_default_or_optional_t) \
  mtev_conf_default_##name (type default_value);

mtev_conf_default_hdr(boolean, int)
mtev_conf_default_hdr(int32, int32_t)
mtev_conf_default_hdr(int64, int64_t)
mtev_conf_default_hdr(float, float)
mtev_conf_default_hdr(double, double)
mtev_conf_default_hdr(string, char*)
mtev_conf_default_hdr(uuid, uuid_t)

API_EXPORT(mtev_conf_default_or_optional_t)
  mtev_conf_optional(void);


#define mtev_conf_description_hdr(name, type) \
extern mtev_conf_description_t \
  mtev_conf_description_##name (mtev_conf_section_t section, char *path, \
    char* description, mtev_conf_default_or_optional_t default_or_optional);

mtev_conf_description_hdr(boolean, int)
mtev_conf_description_hdr(int32, int32_t)
mtev_conf_description_hdr(int64, int64_t)
mtev_conf_description_hdr(float, float)
mtev_conf_description_hdr(double, double)
mtev_conf_description_hdr(string, char*)
mtev_conf_description_hdr(uuid, uuid_t)

API_EXPORT(int)
  mtev_conf_get_value(mtev_conf_description_t* description, void *return_value);
API_EXPORT(int) mtev_conf_save(const char *path);
API_EXPORT(char *) mtev_conf_config_filename(void);
API_EXPORT(void) mtev_conf_write_section(mtev_conf_section_t node, int fd);

API_EXPORT(void) mtev_console_conf_init(void);

/* Compatibility */
API_EXPORT(mtev_conf_section_t)
  mtev_conf_get_section(mtev_conf_section_t section, const char *path)
  __attribute__((deprecated));
API_EXPORT(void)
  mtev_conf_release_section(mtev_conf_section_t section)
  __attribute__((deprecated));
API_EXPORT(mtev_conf_section_t *)
  mtev_conf_get_sections(mtev_conf_section_t section, const char *path,
                         int *cnt) __attribute__((deprecated));
API_EXPORT(void)
  mtev_conf_release_sections(mtev_conf_section_t *sections, int cnt)
  __attribute__((deprecated));

API_EXPORT(mtev_conf_section_t)
  mtev_conf_get_section_write(mtev_conf_section_t section, const char *path);
API_EXPORT(void)
  mtev_conf_release_section_write(mtev_conf_section_t section);
API_EXPORT(mtev_conf_section_t *)
  mtev_conf_get_sections_write(mtev_conf_section_t section, const char *path,
                         int *cnt);
API_EXPORT(void)
  mtev_conf_release_sections_write(mtev_conf_section_t *sections, int cnt);

API_EXPORT(mtev_conf_section_t)
  mtev_conf_get_section_read(mtev_conf_section_t section, const char *path);
API_EXPORT(void)
  mtev_conf_release_section_read(mtev_conf_section_t section);
API_EXPORT(mtev_conf_section_t *)
  mtev_conf_get_sections_read(mtev_conf_section_t section, const char *path,
                         int *cnt);
API_EXPORT(void)
  mtev_conf_release_sections_read(mtev_conf_section_t *sections, int cnt);

struct _xmlNode;
API_EXPORT(mtev_conf_section_t)
  mtev_conf_section_from_xmlnodeptr(struct _xmlNode *node);
API_EXPORT(struct _xmlNode *)
  mtev_conf_section_to_xmlnodeptr(mtev_conf_section_t section);
API_EXPORT(mtev_boolean)
  mtev_conf_section_is_empty(mtev_conf_section_t section);

API_EXPORT(int)
  mtev_conf_remove_section(mtev_conf_section_t section);

API_EXPORT(mtev_hash_table *)
  mtev_conf_get_hash(mtev_conf_section_t section, const char *path);
API_EXPORT(mtev_hash_table *)
  mtev_conf_get_namespaced_hash(mtev_conf_section_t section,
                                const char *path, const char *ns);

API_EXPORT(char*)
  mtev_conf_section_to_xpath(mtev_conf_section_t section);

API_EXPORT(int) mtev_conf_get_string(mtev_conf_section_t section,
                                     const char *path, char **value);

API_EXPORT(int) mtev_conf_get_stringbuf(mtev_conf_section_t section,
                                        const char *path, char *value, int len);
API_EXPORT(int) mtev_conf_get_int32(mtev_conf_section_t section,
                                  const char *path, int32_t *value);
API_EXPORT(int) mtev_conf_get_int64(mtev_conf_section_t section,
                                    const char *path, int64_t *value);
API_EXPORT(int) mtev_conf_get_uint32(mtev_conf_section_t section,
                                     const char *path, uint32_t *value);
API_EXPORT(int) mtev_conf_get_uint64(mtev_conf_section_t section,
                                     const char *path, uint64_t *value);
API_EXPORT(int32_t) mtev_conf_string_to_int32(const char *str);
API_EXPORT(int) mtev_conf_get_float(mtev_conf_section_t section,
                                    const char *path, float *value);
API_EXPORT(float) mtev_conf_string_to_float(const char *str);
API_EXPORT(int) mtev_conf_get_double(mtev_conf_section_t section,
                                    const char *path, double *value);
API_EXPORT(double) mtev_conf_string_to_double(const char *str);
API_EXPORT(int) mtev_conf_get_boolean(mtev_conf_section_t section,
                                      const char *path, mtev_boolean *value);
API_EXPORT(mtev_boolean) mtev_conf_string_to_boolean(const char *str);

API_EXPORT(int) mtev_conf_should_resolve_targets(mtev_boolean *);

API_EXPORT(int)
  mtev_conf_get_uuid(mtev_conf_section_t section,
                     const char *path, uuid_t out);

API_EXPORT(int)
  mtev_conf_property_iter(mtev_conf_section_t section,
                          int (*f)(const char *key, const char *val, void *closure),
                          void *closure);

API_EXPORT(int) mtev_conf_set_string(mtev_conf_section_t section,
                                     const char *path, const char *value);
API_EXPORT(int) mtev_conf_set_int32(mtev_conf_section_t section,
                                    const char *path, int32_t value);
API_EXPORT(int) mtev_conf_set_float(mtev_conf_section_t section,
                                    const char *path, float value);
API_EXPORT(int) mtev_conf_set_double(mtev_conf_section_t section,
                                     const char *path, double value);
API_EXPORT(int) mtev_conf_set_boolean(mtev_conf_section_t section,
                                      const char *path, mtev_boolean value);

API_EXPORT(int)
  mtev_console_config_cd(mtev_console_closure_t ncct,
                         int argc, char **argv,
                         mtev_console_state_t *state, void *closure);

API_EXPORT(int)
  mtev_conf_reload(mtev_console_closure_t ncct,
                   int argc, char **argv,
                   mtev_console_state_t *state, void *closure);
API_EXPORT(int)
  mtev_conf_write_terminal(mtev_console_closure_t ncct,
                           int argc, char **argv,
                           mtev_console_state_t *state, void *closure);
API_EXPORT(int)
  mtev_conf_write_file_console(mtev_console_closure_t ncct,
                               int argc, char **argv,
                               mtev_console_state_t *state, void *closure);

API_EXPORT(void)
  mtev_conf_disable_writes(mtev_boolean state);

API_EXPORT(int)
  mtev_conf_write_file(char **err);

API_EXPORT(void)
  mtev_conf_request_write(void);

API_EXPORT(char *)
  mtev_conf_xml_in_mem(size_t *len);

typedef enum { CONFIG_XML = 0, CONFIG_COMPRESSED, CONFIG_B64 } mtev_conf_enc_type_t;
API_EXPORT(char *)
  mtev_conf_enc_in_mem(size_t *raw_len, size_t *len, mtev_conf_enc_type_t target, mtev_boolean inline_includes);

API_EXPORT(void)
  mtev_conf_xml_errors_to_debug(void);

API_EXPORT(int)
  mtev_conf_write_log(void);

API_EXPORT(mtev_boolean)
  mtev_conf_env_off(mtev_conf_section_t node, const char *attr);

API_EXPORT(void) mtev_conf_log_init(const char *toplevel,
                                    const char *user, const char *group);
API_EXPORT(int) mtev_conf_log_init_rotate(const char *, mtev_boolean);

API_EXPORT(void)
  mtev_conf_security_init(const char *toplevel, const char *user,
                          const char *group, const char *chrootpath);

API_EXPORT(void) mtev_conf_include_remove(mtev_conf_section_t node);
API_EXPORT(void) mtev_conf_backingstore_remove(mtev_conf_section_t node);
API_EXPORT(void) mtev_conf_backingstore_dirty(mtev_conf_section_t node);

API_EXPORT(void) mtev_conf_use_namespace(const char *ns);
API_EXPORT(void) mtev_conf_set_namespace(const char *ns);

#define CONF_REMOVE(n) do { \
  mtev_conf_backingstore_remove(n); \
  mtev_conf_include_remove(n); \
} while(0)

#define CONF_DIRTY(n) do { \
 mtev_conf_backingstore_dirty(n); \
 mtev_conf_mark_changed(); \
} while(0)

#define EXPOSE_CHECKER(name) \
  API_EXPORT(pcre *) mtev_conf_get_valid_##name##_checker(void)
#define DECLARE_CHECKER(name) \
static pcre *checker_valid_##name; \
pcre *mtev_conf_get_valid_##name##_checker(void) { return checker_valid_##name; }
#define COMPILE_CHECKER(name, expr) do { \
  const char *errorstr; \
  int erroff; \
  checker_valid_##name = pcre_compile(expr, 0, &errorstr, &erroff, NULL); \
  if(! checker_valid_##name) { \
    mtevL(mtev_error, "mtev_conf error: compile checker %s failed: %s\n", \
          #name, errorstr); \
    exit(-1); \
  } \
} while(0)

EXPOSE_CHECKER(name);

MTEV_HOOK_PROTO(mtev_conf_value_fixup,
                (mtev_conf_section_t section, const char *xpath,
                 const char *nodepath, int set, char **value),
                void *, closure,
                (void *closure, mtev_conf_section_t section, const char *xpath,
                 const char *nodepath, int set, char **value));

/* Called when someone attempts to delete a section from the config.
 * The section is <root><path>/<name>
 * return MTEV_HOOK_ABORT to prevent it
 */
MTEV_HOOK_PROTO(mtev_conf_delete_section,
                (const char *root, const char *path,
                 const char *name, const char **err),
                void *, closure,
                (void *closure, const char *root, const char *path,
                 const char *name, const char **err));

#endif
