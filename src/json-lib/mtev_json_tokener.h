/*
 * $Id: mtev_json_tokener.h,v 1.10 2006/07/25 03:24:50 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _mtev_json_tokener_h_
#define _mtev_json_tokener_h_

#include <stddef.h>
#include "mtev_json_object.h"

#ifdef __cplusplus
extern "C" {
#endif

enum mtev_json_tokener_error {
  mtev_json_tokener_success,
  mtev_json_tokener_continue,
  mtev_json_tokener_error_depth,
  mtev_json_tokener_error_parse_eof,
  mtev_json_tokener_error_parse_unexpected,
  mtev_json_tokener_error_parse_null,
  mtev_json_tokener_error_parse_boolean,
  mtev_json_tokener_error_parse_number,
  mtev_json_tokener_error_parse_array,
  mtev_json_tokener_error_parse_object_key_name,
  mtev_json_tokener_error_parse_object_key_sep,
  mtev_json_tokener_error_parse_object_value_sep,
  mtev_json_tokener_error_parse_string,
  mtev_json_tokener_error_parse_comment
};

enum mtev_json_tokener_state {
  mtev_json_tokener_state_eatws,
  mtev_json_tokener_state_start,
  mtev_json_tokener_state_finish,
  mtev_json_tokener_state_null,
  mtev_json_tokener_state_comment_start,
  mtev_json_tokener_state_comment,
  mtev_json_tokener_state_comment_eol,
  mtev_json_tokener_state_comment_end,
  mtev_json_tokener_state_string,
  mtev_json_tokener_state_string_escape,
  mtev_json_tokener_state_escape_unicode,
  mtev_json_tokener_state_boolean,
  mtev_json_tokener_state_number,
  mtev_json_tokener_state_array,
  mtev_json_tokener_state_array_add,
  mtev_json_tokener_state_array_sep,
  mtev_json_tokener_state_object_field_start,
  mtev_json_tokener_state_object_field,
  mtev_json_tokener_state_object_field_end,
  mtev_json_tokener_state_object_value,
  mtev_json_tokener_state_object_value_add,
  mtev_json_tokener_state_object_sep
};

struct mtev_json_tokener_srec
{
  enum mtev_json_tokener_state state, saved_state;
  struct mtev_json_object *obj;
  struct mtev_json_object *current;
  char *obj_field_name;
};

#define JSON_TOKENER_MAX_DEPTH 32

struct mtev_json_tokener
{
  char *str;
  struct jl_printbuf *pb;
  int depth, is_double, st_pos, char_offset;
  ptrdiff_t err;
  unsigned int ucs_char;
  char quote_char;
  struct mtev_json_tokener_srec stack[JSON_TOKENER_MAX_DEPTH];
};

extern const char* mtev_json_tokener_errors[];

extern struct mtev_json_tokener* mtev_json_tokener_new(void);
extern void mtev_json_tokener_free(struct mtev_json_tokener *tok);
extern void mtev_json_tokener_reset(struct mtev_json_tokener *tok);
extern struct mtev_json_object* mtev_json_tokener_parse(const char *str);
extern struct mtev_json_object* mtev_json_tokener_parse_ex(struct mtev_json_tokener *tok,
						 const char *str, int len);

#ifdef __cplusplus
}
#endif

#endif
