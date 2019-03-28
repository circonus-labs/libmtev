/*
 * $Id: mtev_json_object.c,v 1.17 2006/07/25 03:24:50 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#include "mtev_defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "mtev_debug.h"
#include "mtev_printbuf.h"
#include "mtev_linkhash.h"
#include "mtev_arraylist.h"
#include "mtev_json_object.h"
#include "mtev_json_object_private.h"

#ifndef HAVE_STRNDUP
  char* strndup(const char* str, size_t n);
#endif

/* #define REFCOUNT_DEBUG 1 */

const char *mtev_json_number_chars = "0123456789.+-eE";
const char *mtev_json_hex_chars = "0123456789abcdef";

#ifdef REFCOUNT_DEBUG
static const char* mtev_json_type_name[] = {
  "null",
  "boolean",
  "double",
  "int",
  "object",
  "array",
  "string",
};
#endif /* REFCOUNT_DEBUG */

static void mtev_json_object_generic_delete(struct mtev_json_object* jso);
static struct mtev_json_object* mtev_json_object_new(enum mtev_json_type o_type);


/* ref count debugging */

#ifdef REFCOUNT_DEBUG

static struct jl_lh_table *mtev_json_object_table;

static void mtev_json_object_init(void) __attribute__ ((constructor));
static void mtev_json_object_init(void) {
  MC_DEBUG("mtev_json_object_init: creating object table\n");
  mtev_json_object_table = jl_lh_kptr_table_new(128, "mtev_json_object_table", NULL);
}

static void mtev_json_object_fini(void) __attribute__ ((destructor));
static void mtev_json_object_fini(void) {
  struct jl_lh_entry *ent;
  if(MC_GET_DEBUG()) {
    if (mtev_json_object_table->count) {
      MC_DEBUG("mtev_json_object_fini: %d referenced objects at exit\n",
  	       mtev_json_object_table->count);
      jl_lh_foreach(mtev_json_object_table, ent) {
        struct mtev_json_object* obj = (struct mtev_json_object*)ent->v;
        MC_DEBUG("\t%s:%p\n", mtev_json_type_name[obj->o_type], obj);
      }
    }
  }
  MC_DEBUG("mtev_json_object_fini: freeing object table\n");
  jl_lh_table_free(mtev_json_object_table);
}
#endif /* REFCOUNT_DEBUG */


/* string escaping */

static int mtev_json_escape_str(struct jl_printbuf *pb, char *str)
{
  int pos = 0, start_offset = 0;
  unsigned char c;
  do {
    c = str[pos];
    switch(c) {
    case '\0':
      break;
    case '\b':
    case '\n':
    case '\r':
    case '\t':
    case '"':
    case '\\':
    case '/':
      if(pos - start_offset > 0)
	jl_printbuf_memappend(pb, str + start_offset, pos - start_offset);
      if(c == '\b') jl_printbuf_memappend(pb, "\\b", 2);
      else if(c == '\n') jl_printbuf_memappend(pb, "\\n", 2);
      else if(c == '\r') jl_printbuf_memappend(pb, "\\r", 2);
      else if(c == '\t') jl_printbuf_memappend(pb, "\\t", 2);
      else if(c == '"') jl_printbuf_memappend(pb, "\\\"", 2);
      else if(c == '\\') jl_printbuf_memappend(pb, "\\\\", 2);
      else if(c == '/') jl_printbuf_memappend(pb, "\\/", 2);
      start_offset = ++pos;
      break;
    default:
      if(c < ' ') {
	if(pos - start_offset > 0)
	  jl_printbuf_memappend(pb, str + start_offset, pos - start_offset);
	jl_sprintbuf(pb, "\\u00%c%c",
		  mtev_json_hex_chars[c >> 4],
		  mtev_json_hex_chars[c & 0xf]);
	start_offset = ++pos;
      } else pos++;
    }
  } while(c);
  if(pos - start_offset > 0)
    jl_printbuf_memappend(pb, str + start_offset, pos - start_offset);
  return 0;
}


/* reference counting */

extern struct mtev_json_object* mtev_json_object_get(struct mtev_json_object *jso)
{
  if(jso) {
    jso->_ref_count++;
  }
  return jso;
}

extern void mtev_json_object_put(struct mtev_json_object *jso)
{
  if(jso) {
    jso->_ref_count--;
    if(!jso->_ref_count) jso->_delete(jso);
  }
}


/* generic object construction and destruction parts */

static void mtev_json_object_generic_delete(struct mtev_json_object* jso)
{
#ifdef REFCOUNT_DEBUG
  MC_DEBUG("mtev_json_object_delete_%s: %p\n",
	   mtev_json_type_name[jso->o_type], jso);
  jl_lh_table_delete(mtev_json_object_table, jso);
#endif /* REFCOUNT_DEBUG */
  jl_printbuf_free(jso->_pb);
  free(jso);
}

static struct mtev_json_object* mtev_json_object_new(enum mtev_json_type o_type)
{
  struct mtev_json_object *jso;

  jso = (struct mtev_json_object*)calloc(sizeof(struct mtev_json_object), 1);
  if(!jso) return NULL;
  jso->o_type = o_type;
  jso->_ref_count = 1;
  jso->_delete = &mtev_json_object_generic_delete;
#ifdef REFCOUNT_DEBUG
  jl_lh_table_insert(mtev_json_object_table, jso, jso);
  MC_DEBUG("mtev_json_object_new_%s: %p\n", mtev_json_type_name[jso->o_type], jso);
#endif /* REFCOUNT_DEBUG */
  return jso;
}


/* type checking functions */

int mtev_json_object_is_type(struct mtev_json_object *jso, enum mtev_json_type type)
{
  return (jso->o_type == type);
}

enum mtev_json_type mtev_json_object_get_type(struct mtev_json_object *jso)
{
  return jso->o_type;
}


/* mtev_json_object_to_json_string */

const char* mtev_json_object_to_json_string(struct mtev_json_object *jso)
{
  if(!jso) return "null";
  if(!jso->_pb) {
    if(!(jso->_pb = jl_printbuf_new())) return NULL;
  } else {
    jl_printbuf_reset(jso->_pb);
  }
  if(jso->_to_json_string(jso, jso->_pb) < 0) return NULL;
  return jso->_pb->buf;
}


/* mtev_json_object_object */

static int mtev_json_object_object_to_json_string(struct mtev_json_object* jso,
					     struct jl_printbuf *pb)
{
  int i=0;
  struct mtev_json_object_iter iter;
  jl_sprintbuf(pb, "{");

  /* CAW: scope operator to make ANSI correctness */
  /* CAW: switched to mtev_json_object_object_foreachC which uses an iterator struct */
	mtev_json_object_object_foreachC(jso, iter) {
			if(i) jl_sprintbuf(pb, ",");
			jl_sprintbuf(pb, " \"");
			mtev_json_escape_str(pb, iter.key);
			jl_sprintbuf(pb, "\": ");
			if(iter.val == NULL) jl_sprintbuf(pb, "null");
			else iter.val->_to_json_string(iter.val, pb);
			i++;
	}

  return jl_sprintbuf(pb, " }");
}

static void mtev_json_object_lh_entry_free(struct jl_lh_entry *ent)
{
  free(ent->k);
  mtev_json_object_put((struct mtev_json_object*)ent->v);
}

static void mtev_json_object_object_delete(struct mtev_json_object* jso)
{
  jl_lh_table_free(jso->o.c_object);
  mtev_json_object_generic_delete(jso);
}

struct mtev_json_object* mtev_json_object_new_object(void)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_object);
  if(!jso) return NULL;
  jso->_delete = &mtev_json_object_object_delete;
  jso->_to_json_string = &mtev_json_object_object_to_json_string;
  jso->o.c_object = jl_lh_kchar_table_new(JSON_OBJECT_DEF_HASH_ENTRIES,
					NULL, &mtev_json_object_lh_entry_free);
  return jso;
}

struct jl_lh_table* mtev_json_object_get_object(struct mtev_json_object *jso)
{
  if(!jso) return NULL;
  switch(jso->o_type) {
  case mtev_json_type_object:
    return jso->o.c_object;
  default:
    return NULL;
  }
}

void mtev_json_object_object_add(struct mtev_json_object* jso, const char *key,
			    struct mtev_json_object *val)
{
  jl_lh_table_delete(jso->o.c_object, key);
  jl_lh_table_insert(jso->o.c_object, strdup(key), val);
}

struct mtev_json_object* mtev_json_object_object_get(struct mtev_json_object* jso, const char *key)
{
  return (struct mtev_json_object*) jl_lh_table_lookup(jso->o.c_object, key);
}

void mtev_json_object_object_del(struct mtev_json_object* jso, const char *key)
{
  jl_lh_table_delete(jso->o.c_object, key);
}


/* mtev_json_object_boolean */

static int mtev_json_object_boolean_to_json_string(struct mtev_json_object* jso,
					      struct jl_printbuf *pb)
{
  if(jso->o.c_boolean) return jl_sprintbuf(pb, "true");
  else return jl_sprintbuf(pb, "false");
}

struct mtev_json_object* mtev_json_object_new_boolean(boolean b)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_boolean);
  if(!jso) return NULL;
  jso->_to_json_string = &mtev_json_object_boolean_to_json_string;
  jso->o.c_boolean = b;
  return jso;
}

boolean mtev_json_object_get_boolean(struct mtev_json_object *jso)
{
  if(!jso) return FALSE;
  switch(jso->o_type) {
  case mtev_json_type_boolean:
    return jso->o.c_boolean;
  case mtev_json_type_int:
    return (jso->o.c_int != 0);
  case mtev_json_type_double:
    return (jso->o.c_double != 0);
  case mtev_json_type_string:
    return (strlen(jso->o.c_string) != 0);
  default:
    return FALSE;
  }
}


/* mtev_json_object_int */

static int mtev_json_object_int_to_json_string(struct mtev_json_object* jso,
					  struct jl_printbuf *pb)
{
  if(jso->o_ioverflow == mtev_json_overflow_uint64)
    return jl_sprintbuf(pb, "%" PRIu64 "", jso->overflow.c_uint64);
  else if(jso->o_ioverflow == mtev_json_overflow_int64)
    return jl_sprintbuf(pb, "%" PRId64 "", jso->overflow.c_int64);
  return jl_sprintbuf(pb, "%d", jso->o.c_int);
}

struct mtev_json_object* mtev_json_object_new_int(int i)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_int);
  if(!jso) return NULL;
  jso->o_ioverflow = mtev_json_overflow_int;
  jso->_to_json_string = &mtev_json_object_int_to_json_string;
  jso->o.c_int = i;
  return jso;
}

mtev_json_int_overflow mtev_json_object_get_int_overflow(struct mtev_json_object *jso)
{
  return jso->o_ioverflow;
}
void mtev_json_object_set_int_overflow(struct mtev_json_object *jso,
					  mtev_json_int_overflow o) {
  jso->o_ioverflow = o;
}

struct mtev_json_object *mtev_json_object_new_int64(int64_t i)
{
  struct mtev_json_object *o = mtev_json_object_new_int(0);
  if(!o) return NULL;
  mtev_json_object_set_int64(o, i);
  mtev_json_object_set_int_overflow(o, mtev_json_overflow_int64);
  return o;
}

struct mtev_json_object *mtev_json_object_new_uint64(uint64_t i)
{
  struct mtev_json_object *o = mtev_json_object_new_int(0);
  if(!o) return NULL;
  mtev_json_object_set_uint64(o, i);
  mtev_json_object_set_int_overflow(o, mtev_json_overflow_uint64);
  return o;
}

uint64_t mtev_json_object_get_uint64(struct mtev_json_object *jso)
{
  return jso->overflow.c_uint64;
}
void mtev_json_object_set_uint64(struct mtev_json_object *jso, uint64_t v)
{
  jso->overflow.c_uint64 = v;
}
int64_t mtev_json_object_get_int64(struct mtev_json_object *jso)
{
  return jso->overflow.c_int64;
}
void mtev_json_object_set_int64(struct mtev_json_object *jso, int64_t v)
{
  jso->overflow.c_int64 = v;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
int mtev_json_object_get_int(struct mtev_json_object *jso)
{
  int cint;

  if(!jso) return 0;
  switch(jso->o_type) {
  case mtev_json_type_int:
    return jso->o.c_int;
  case mtev_json_type_double:
    return (int)jso->o.c_double;
  case mtev_json_type_boolean:
    return jso->o.c_boolean;
  case mtev_json_type_string:
    if(sscanf(jso->o.c_string, "%d", &cint) == 1) return cint;
  default:
    return 0;
  }
}


/* mtev_json_object_double */

static int mtev_json_object_double_to_json_string(struct mtev_json_object* jso,
					     struct jl_printbuf *pb)
{
  if(isnan(jso->o.c_double) || isinf(jso->o.c_double)) {
    return jl_sprintbuf(pb, "null");
  }
  return jl_sprintbuf(pb, "%lf", jso->o.c_double);
}

struct mtev_json_object* mtev_json_object_new_double(double d)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_double);
  if(!jso) return NULL;
  jso->_to_json_string = &mtev_json_object_double_to_json_string;
  jso->o.c_double = d;
  return jso;
}

double mtev_json_object_get_double(struct mtev_json_object *jso)
{
  double cdouble;

  if(!jso) return 0.0;
  switch(jso->o_type) {
  case mtev_json_type_double:
    return jso->o.c_double;
  case mtev_json_type_int:
    return jso->o.c_int;
  case mtev_json_type_boolean:
    return jso->o.c_boolean;
  case mtev_json_type_string:
    if(sscanf(jso->o.c_string, "%lf", &cdouble) == 1) return cdouble;
  default:
    return 0.0;
  }
}
#pragma GCC diagnostic pop


/* mtev_json_object_string */

static int mtev_json_object_string_to_json_string(struct mtev_json_object* jso,
					     struct jl_printbuf *pb)
{
  jl_sprintbuf(pb, "\"");
  mtev_json_escape_str(pb, jso->o.c_string);
  jl_sprintbuf(pb, "\"");
  return 0;
}

static void mtev_json_object_string_delete(struct mtev_json_object* jso)
{
  free(jso->o.c_string);
  mtev_json_object_generic_delete(jso);
}

struct mtev_json_object* mtev_json_object_new_string(const char *s)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_string);
  if(!jso) return NULL;
  jso->_delete = &mtev_json_object_string_delete;
  jso->_to_json_string = &mtev_json_object_string_to_json_string;
  jso->o.c_string = strdup(s);
  return jso;
}

struct mtev_json_object* mtev_json_object_new_string_len(const char *s, int len)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_string);
  if(!jso) return NULL;
  jso->_delete = &mtev_json_object_string_delete;
  jso->_to_json_string = &mtev_json_object_string_to_json_string;
  jso->o.c_string = strndup(s, (size_t)len);
  return jso;
}

const char* mtev_json_object_get_string(struct mtev_json_object *jso)
{
  if(!jso) return NULL;
  switch(jso->o_type) {
  case mtev_json_type_string:
    return jso->o.c_string;
  default:
    return mtev_json_object_to_json_string(jso);
  }
}


/* mtev_json_object_array */

static int mtev_json_object_array_to_json_string(struct mtev_json_object* jso,
					    struct jl_printbuf *pb)
{
  int i;
  jl_sprintbuf(pb, "[");
  for(i=0; i < mtev_json_object_array_length(jso); i++) {
	  struct mtev_json_object *val;
	  if(i) { jl_sprintbuf(pb, ", "); }
	  else { jl_sprintbuf(pb, " "); }

      val = mtev_json_object_array_get_idx(jso, i);
	  if(val == NULL) { jl_sprintbuf(pb, "null"); }
	  else { val->_to_json_string(val, pb); }
  }
  return jl_sprintbuf(pb, " ]");
}

static void mtev_json_object_array_entry_free(void *data)
{
  mtev_json_object_put((struct mtev_json_object*)data);
}

static void mtev_json_object_array_delete(struct mtev_json_object* jso)
{
  jl_array_list_free(jso->o.c_array);
  mtev_json_object_generic_delete(jso);
}

struct mtev_json_object* mtev_json_object_new_array(void)
{
  struct mtev_json_object *jso = mtev_json_object_new(mtev_json_type_array);
  if(!jso) return NULL;
  jso->_delete = &mtev_json_object_array_delete;
  jso->_to_json_string = &mtev_json_object_array_to_json_string;
  jso->o.c_array = jl_array_list_new(&mtev_json_object_array_entry_free);
  return jso;
}

struct jl_array_list* mtev_json_object_get_array(struct mtev_json_object *jso)
{
  if(!jso) return NULL;
  switch(jso->o_type) {
  case mtev_json_type_array:
    return jso->o.c_array;
  default:
    return NULL;
  }
}

int mtev_json_object_array_length(struct mtev_json_object *jso)
{
  return jl_array_list_length(jso->o.c_array);
}

int mtev_json_object_array_add(struct mtev_json_object *jso,struct mtev_json_object *val)
{
  return jl_array_list_add(jso->o.c_array, val);
}

int mtev_json_object_array_put_idx(struct mtev_json_object *jso, int idx,
			      struct mtev_json_object *val)
{
  return jl_array_list_put_idx(jso->o.c_array, idx, val);
}

struct mtev_json_object* mtev_json_object_array_get_idx(struct mtev_json_object *jso,
					      int idx)
{
  return (struct mtev_json_object*)jl_array_list_get_idx(jso->o.c_array, idx);
}

