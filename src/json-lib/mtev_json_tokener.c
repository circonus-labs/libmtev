/*
 * $Id: mtev_json_tokener.c,v 1.20 2006/07/25 03:24:50 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 *
 * Copyright (c) 2008-2009 Yahoo! Inc.  All rights reserved.
 * The copyrights to the contents of this file are licensed under the MIT License
 * (http://www.opensource.org/licenses/mit-license.php)
 */

#include "mtev_defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>

#include "internal_bits.h"
#include "internal_debug.h"
#include "internal_printbuf.h"
#include "internal_arraylist.h"
#include "mtev_json_object.h"
#include "mtev_json_tokener.h"

#define hexdigit(x) (((x) <= '9') ? (x) - '0' : ((x) & 7) + 9)

static const char* mtev_json_null_str = "null";
static const char* mtev_json_true_str = "true";
static const char* mtev_json_false_str = "false";

const char* mtev_json_tokener_errors[] = {
  "success",
  "continue",
  "nesting to deep",
  "unexpected end of data",
  "unexpected character",
  "null expected",
  "boolean expected",
  "number expected",
  "array value separator ',' expected",
  "quoted object property name expected",
  "object property name separator ':' expected",
  "object value separator ',' expected",
  "invalid string sequence",
  "expected comment",
};


struct mtev_json_tokener* mtev_json_tokener_new(void)
{
  struct mtev_json_tokener *tok;

  tok = (struct mtev_json_tokener*)calloc(1, sizeof(struct mtev_json_tokener));
  if (!tok) return NULL;
  tok->pb = jl_printbuf_new();
  mtev_json_tokener_reset(tok);
  return tok;
}

void mtev_json_tokener_free(struct mtev_json_tokener *tok)
{
  mtev_json_tokener_reset(tok);
  if (tok) {
    if(tok->pb) jl_printbuf_free(tok->pb);
    free(tok);
  }
}

static void mtev_json_tokener_reset_level(struct mtev_json_tokener *tok, int depth)
{
  if (tok) {
    tok->stack[depth].state = mtev_json_tokener_state_eatws;
    tok->stack[depth].saved_state = mtev_json_tokener_state_start;
    mtev_json_object_put(tok->stack[depth].current);
    tok->stack[depth].current = NULL;
    if (tok->stack[depth].obj_field_name) 
      free(tok->stack[depth].obj_field_name);
    tok->stack[depth].obj_field_name = NULL;
  }
}

void mtev_json_tokener_reset(struct mtev_json_tokener *tok)
{
  int i;
  if (!tok)
    return;

  for(i = tok->depth; i >= 0; i--)
    mtev_json_tokener_reset_level(tok, i);
  tok->depth = 0;
  tok->err = mtev_json_tokener_success;
}

struct mtev_json_object* mtev_json_tokener_parse(const char *str,  enum mtev_json_tokener_error *err)
{
  struct mtev_json_tokener* tok;
  struct mtev_json_object* obj;

  tok = mtev_json_tokener_new();
  obj = mtev_json_tokener_parse_ex(tok, str, -1);
  if(tok->err != mtev_json_tokener_success) {
    if(err) *err = tok->err;
  }
  mtev_json_tokener_free(tok);
  return obj;
}


#if !HAVE_STRNDUP
/* CAW: compliant version of strndup() */
char* strndup(const char* str, size_t n)
{
  if(str) {
    size_t len = strlen(str);
    size_t nn = mtev_json_min(len,n);
    char* s = (char*)malloc(sizeof(char) * (nn + 1));

    if(s) {
      memcpy(s, str, nn);
      s[nn] = '\0';
    }

    return s;
  }

  return NULL;
}
#endif


#define state  tok->stack[tok->depth].state
#define saved_state  tok->stack[tok->depth].saved_state
#define current tok->stack[tok->depth].current
#define obj_field_name tok->stack[tok->depth].obj_field_name

/* Optimization:
 * mtev_json_tokener_parse_ex() consumed a lot of CPU in its main loop,
 * iterating character-by character.  A large performance boost is
 * achieved by using tighter loops to locally handle units such as
 * comments and strings.  Loops that handle an entire token within 
 * their scope also gather entire strings and pass them to 
 * jl_printbuf_memappend() in a single call, rather than calling
 * jl_printbuf_memappend() one char at a time.
 *
 * POP_CHAR() and ADVANCE_CHAR() macros are used for code that is
 * common to both the main loop and the tighter loops.
 */

/* POP_CHAR(dest, tok) macro:
 *   Not really a pop()...peeks at the current char and stores it in dest.
 *   Returns 1 on success, sets tok->err and returns 0 if no more chars.
 *   Implicit inputs:  str, len vars
 */
#define POP_CHAR(dest, tok)                                                  \
  (((tok)->char_offset == len) ?                                          \
   (((tok)->depth == 0 && state == mtev_json_tokener_state_eatws && saved_state == mtev_json_tokener_state_finish) ? \
    (((tok)->err = mtev_json_tokener_success), 0)                              \
    :                                                                   \
    (((tok)->err = mtev_json_tokener_continue), 0)                             \
    ) :                                                                 \
   (((dest) = *str), 1)                                                 \
   )
 
/* ADVANCE_CHAR() macro:
 *   Incrementes str & tok->char_offset.
 *   For convenience of existing conditionals, returns the old value of c (0 on eof)
 *   Implicit inputs:  c var
 */
#define ADVANCE_CHAR(str, tok) \
  ( ++(str), ((tok)->char_offset)++, c)

/* End optimization macro defs */


struct mtev_json_object* mtev_json_tokener_parse_ex(struct mtev_json_tokener *tok,
					  const char *str, int len)
{
  struct mtev_json_object *obj = NULL;
  char c = '\1';

  tok->char_offset = 0;
  tok->err = mtev_json_tokener_success;

  while (POP_CHAR(c, tok)) {

  redo_char:
    switch(state) {

    case mtev_json_tokener_state_eatws:
      /* Advance until we change state */
      while (isspace(c)) {
	if ((!ADVANCE_CHAR(str, tok)) || (!POP_CHAR(c, tok)))
	  goto out;
      }
      if(c == '/') {
	jl_printbuf_reset(tok->pb);
	jl_printbuf_memappend_fast(tok->pb, &c, 1);
	state = mtev_json_tokener_state_comment_start;
      } else {
	state = saved_state;
	goto redo_char;
      }
      break;

    case mtev_json_tokener_state_start:
      switch(c) {
      case '{':
	state = mtev_json_tokener_state_eatws;
	saved_state = mtev_json_tokener_state_object_field_start;
	current = mtev_json_object_new_object();
	break;
      case '[':
	state = mtev_json_tokener_state_eatws;
	saved_state = mtev_json_tokener_state_array;
	current = mtev_json_object_new_array();
	break;
      case 'N':
      case 'n':
	state = mtev_json_tokener_state_null;
	jl_printbuf_reset(tok->pb);
	tok->st_pos = 0;
	goto redo_char;
      case '"':
      case '\'':
	state = mtev_json_tokener_state_string;
	jl_printbuf_reset(tok->pb);
	tok->quote_char = c;
	break;
      case 'T':
      case 't':
      case 'F':
      case 'f':
	state = mtev_json_tokener_state_boolean;
	jl_printbuf_reset(tok->pb);
	tok->st_pos = 0;
	goto redo_char;
#if defined(__GNUC__)
	  case '0' ... '9':
#else
	  case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
#endif
      case '-':
	state = mtev_json_tokener_state_number;
	jl_printbuf_reset(tok->pb);
	tok->is_double = 0;
	goto redo_char;
      default:
	tok->err = mtev_json_tokener_error_parse_unexpected;
	goto out;
      }
      break;

    case mtev_json_tokener_state_finish:
      if(tok->depth == 0) goto out;
      obj = mtev_json_object_get(current);
      mtev_json_tokener_reset_level(tok, tok->depth);
      tok->depth--;
      goto redo_char;

    case mtev_json_tokener_state_null:
      jl_printbuf_memappend_fast(tok->pb, &c, 1);
      if(strncasecmp(mtev_json_null_str, tok->pb->buf,
		     mtev_json_min(tok->st_pos+1, (int)strlen(mtev_json_null_str))) == 0) {
	if(tok->st_pos == (int)strlen(mtev_json_null_str)) {
	  current = NULL;
	  saved_state = mtev_json_tokener_state_finish;
	  state = mtev_json_tokener_state_eatws;
	  goto redo_char;
	}
      } else {
	tok->err = mtev_json_tokener_error_parse_null;
	goto out;
      }
      tok->st_pos++;
      break;

    case mtev_json_tokener_state_comment_start:
      if(c == '*') {
	state = mtev_json_tokener_state_comment;
      } else if(c == '/') {
	state = mtev_json_tokener_state_comment_eol;
      } else {
	tok->err = mtev_json_tokener_error_parse_comment;
	goto out;
      }
      jl_printbuf_memappend_fast(tok->pb, &c, 1);
      break;

    case mtev_json_tokener_state_comment:
              {
          /* Advance until we change state */
          const char *case_start = str;
          while(c != '*') {
            if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok)) {
              jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
              goto out;
            } 
          }
          jl_printbuf_memappend_fast(tok->pb, case_start, 1+str-case_start);
          state = mtev_json_tokener_state_comment_end;
        }
            break;

    case mtev_json_tokener_state_comment_eol:
      {
	/* Advance until we change state */
	const char *case_start = str;
	while(c != '\n') {
	  if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok)) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    goto out;
	  }
	}
	jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	MC_DEBUG("mtev_json_tokener_comment: %s\n", tok->pb->buf);
	state = mtev_json_tokener_state_eatws;
      }
      break;

    case mtev_json_tokener_state_comment_end:
      jl_printbuf_memappend_fast(tok->pb, &c, 1);
      if(c == '/') {
	MC_DEBUG("mtev_json_tokener_comment: %s\n", tok->pb->buf);
	state = mtev_json_tokener_state_eatws;
      } else {
	state = mtev_json_tokener_state_comment;
      }
      break;

    case mtev_json_tokener_state_string:
      {
	/* Advance until we change state */
	const char *case_start = str;
	while(1) {
	  if(c == tok->quote_char) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    current = mtev_json_object_new_string(tok->pb->buf);
	    saved_state = mtev_json_tokener_state_finish;
	    state = mtev_json_tokener_state_eatws;
	    break;
	  } else if(c == '\\') {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    saved_state = mtev_json_tokener_state_string;
	    state = mtev_json_tokener_state_string_escape;
	    break;
	  }
	  if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok)) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    goto out;
	  }
	}
      }
      break;

    case mtev_json_tokener_state_string_escape:
      switch(c) {
      case '"':
      case '\\':
      case '/':
	jl_printbuf_memappend_fast(tok->pb, &c, 1);
	state = saved_state;
	break;
      case 'b':
      case 'n':
      case 'r':
      case 't':
	if(c == 'b') jl_printbuf_memappend_fast(tok->pb, "\b", 1);
	else if(c == 'n') jl_printbuf_memappend_fast(tok->pb, "\n", 1);
	else if(c == 'r') jl_printbuf_memappend_fast(tok->pb, "\r", 1);
	else if(c == 't') jl_printbuf_memappend_fast(tok->pb, "\t", 1);
	state = saved_state;
	break;
      case 'u':
	tok->ucs_char = 0;
	tok->st_pos = 0;
	state = mtev_json_tokener_state_escape_unicode;
	break;
      default:
	tok->err = mtev_json_tokener_error_parse_string;
	goto out;
      }
      break;

    case mtev_json_tokener_state_escape_unicode:
            /* Note that the following code is inefficient for handling large
       * chunks of extended chars, calling jl_printbuf_memappend() once
       * for each multi-byte character of input.
       * This is a good area for future optimization.
       */
	{
	  /* Advance until we change state */
	  while(1) {
	    if(strchr(mtev_json_hex_chars, c)) {
	      tok->ucs_char += ((unsigned int)hexdigit(c) << ((3-tok->st_pos++)*4));
	      if(tok->st_pos == 4) {
		unsigned char utf_out[3];
		if (tok->ucs_char < 0x80) {
		  utf_out[0] = tok->ucs_char;
		  jl_printbuf_memappend_fast(tok->pb, (char*)utf_out, 1);
		} else if (tok->ucs_char < 0x800) {
		  utf_out[0] = 0xc0 | (tok->ucs_char >> 6);
		  utf_out[1] = 0x80 | (tok->ucs_char & 0x3f);
		  jl_printbuf_memappend_fast(tok->pb, (char*)utf_out, 2);
		} else {
		  utf_out[0] = 0xe0 | (tok->ucs_char >> 12);
		  utf_out[1] = 0x80 | ((tok->ucs_char >> 6) & 0x3f);
		  utf_out[2] = 0x80 | (tok->ucs_char & 0x3f);
		  jl_printbuf_memappend_fast(tok->pb, (char*)utf_out, 3);
		}
		state = saved_state;
		break;
	      }
	    } else {
	      tok->err = mtev_json_tokener_error_parse_string;
	      goto out;
	      	  }
	  if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok))
	    goto out;
	}
      }
      break;

    case mtev_json_tokener_state_boolean:
      jl_printbuf_memappend_fast(tok->pb, &c, 1);
      if(strncasecmp(mtev_json_true_str, tok->pb->buf,
		     mtev_json_min(tok->st_pos+1, (int)strlen(mtev_json_true_str))) == 0) {
	if(tok->st_pos == (int)strlen(mtev_json_true_str)) {
	  current = mtev_json_object_new_boolean(1);
	  saved_state = mtev_json_tokener_state_finish;
	  state = mtev_json_tokener_state_eatws;
	  goto redo_char;
	}
      } else if(strncasecmp(mtev_json_false_str, tok->pb->buf,
			    mtev_json_min(tok->st_pos+1, (int)strlen(mtev_json_false_str))) == 0) {
	if(tok->st_pos == (int)strlen(mtev_json_false_str)) {
	  current = mtev_json_object_new_boolean(0);
	  saved_state = mtev_json_tokener_state_finish;
	  state = mtev_json_tokener_state_eatws;
	  goto redo_char;
	}
      } else {
	tok->err = mtev_json_tokener_error_parse_boolean;
	goto out;
      }
      tok->st_pos++;
      break;

    case mtev_json_tokener_state_number:
      {
	/* Advance until we change state */
	const char *case_start = str;
	int case_len=0;
	while(c && strchr(mtev_json_number_chars, c)) {
	  ++case_len;
	  if(c == '.' || c == 'e') tok->is_double = 1;
	  if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok)) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, case_len);
	    goto out;
	  }
	}
        if (case_len>0)
          jl_printbuf_memappend_fast(tok->pb, case_start, case_len);
      }
      {
        int numi;
        double numd;
        if(!tok->is_double && sscanf(tok->pb->buf, "%d", &numi) == 1) {
          current = mtev_json_object_new_int(numi);
          if(tok->pb->buf[0] == '-') {
            int64_t i64;
            i64 = strtoll(tok->pb->buf, NULL, 10);
            mtev_json_object_set_int64(current, i64);
            if(i64 != numi)
              mtev_json_object_set_int_overflow(current, mtev_json_overflow_int64);
          }
          else {
            uint64_t u64;
            u64 = strtoull(tok->pb->buf, NULL, 10);
            mtev_json_object_set_uint64(current, u64);
            if(numi < 0 || u64 != (size_t)numi)
              mtev_json_object_set_int_overflow(current, mtev_json_overflow_uint64);
          }
        } else if(tok->is_double && sscanf(tok->pb->buf, "%lf", &numd) == 1) {
          current = mtev_json_object_new_double(numd);
        } else {
          tok->err = mtev_json_tokener_error_parse_number;
          goto out;
        }
        saved_state = mtev_json_tokener_state_finish;
        state = mtev_json_tokener_state_eatws;
        goto redo_char;
      }
      break;

    case mtev_json_tokener_state_array:
      if(c == ']') {
	saved_state = mtev_json_tokener_state_finish;
	state = mtev_json_tokener_state_eatws;
      } else {
	if(tok->depth >= MTEV_JSON_TOKENER_MAX_DEPTH-1) {
	  tok->err = mtev_json_tokener_error_depth;
	  goto out;
	}
	state = mtev_json_tokener_state_array_add;
	tok->depth++;
	mtev_json_tokener_reset_level(tok, tok->depth);
	goto redo_char;
      }
      break;

    case mtev_json_tokener_state_array_add:
      mtev_json_object_array_add(current, obj);
      saved_state = mtev_json_tokener_state_array_sep;
      state = mtev_json_tokener_state_eatws;
      goto redo_char;

    case mtev_json_tokener_state_array_sep:
      if(c == ']') {
	saved_state = mtev_json_tokener_state_finish;
	state = mtev_json_tokener_state_eatws;
      } else if(c == ',') {
	saved_state = mtev_json_tokener_state_array;
	state = mtev_json_tokener_state_eatws;
      } else {
	tok->err = mtev_json_tokener_error_parse_array;
	goto out;
      }
      break;

    case mtev_json_tokener_state_object_field_start:
      if(c == '}') {
	saved_state = mtev_json_tokener_state_finish;
	state = mtev_json_tokener_state_eatws;
      } else if (c == '"' || c == '\'') {
	tok->quote_char = c;
	jl_printbuf_reset(tok->pb);
	state = mtev_json_tokener_state_object_field;
      } else {
	tok->err = mtev_json_tokener_error_parse_object_key_name;
	goto out;
      }
      break;

    case mtev_json_tokener_state_object_field:
      {
	/* Advance until we change state */
	const char *case_start = str;
	while(1) {
	  if(c == tok->quote_char) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    obj_field_name = strdup(tok->pb->buf);
	    saved_state = mtev_json_tokener_state_object_field_end;
	    state = mtev_json_tokener_state_eatws;
	    break;
	  } else if(c == '\\') {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    saved_state = mtev_json_tokener_state_object_field;
	    state = mtev_json_tokener_state_string_escape;
	    break;
	  }
	  if (!ADVANCE_CHAR(str, tok) || !POP_CHAR(c, tok)) {
	    jl_printbuf_memappend_fast(tok->pb, case_start, str-case_start);
	    goto out;
	  }
	}
      }
      break;

    case mtev_json_tokener_state_object_field_end:
      if(c == ':') {
	saved_state = mtev_json_tokener_state_object_value;
	state = mtev_json_tokener_state_eatws;
      } else {
	tok->err = mtev_json_tokener_error_parse_object_key_sep;
	goto out;
      }
      break;

    case mtev_json_tokener_state_object_value:
      if(tok->depth >= MTEV_JSON_TOKENER_MAX_DEPTH-1) {
	tok->err = mtev_json_tokener_error_depth;
	goto out;
      }
      state = mtev_json_tokener_state_object_value_add;
      tok->depth++;
      mtev_json_tokener_reset_level(tok, tok->depth);
      goto redo_char;

    case mtev_json_tokener_state_object_value_add:
      mtev_json_object_object_add(current, obj_field_name, obj);
      free(obj_field_name);
      obj_field_name = NULL;
      saved_state = mtev_json_tokener_state_object_sep;
      state = mtev_json_tokener_state_eatws;
      goto redo_char;

    case mtev_json_tokener_state_object_sep:
      if(c == '}') {
	saved_state = mtev_json_tokener_state_finish;
	state = mtev_json_tokener_state_eatws;
      } else if(c == ',') {
	saved_state = mtev_json_tokener_state_object_field_start;
	state = mtev_json_tokener_state_eatws;
      } else {
	tok->err = mtev_json_tokener_error_parse_object_value_sep;
	goto out;
      }
      break;

    }
    if (!ADVANCE_CHAR(str, tok))
      goto out;
  } /* while(POP_CHAR) */

 out:
  if (!c) { /* We hit an eof char (0) */
    if(state != mtev_json_tokener_state_finish &&
       saved_state != mtev_json_tokener_state_finish)
      tok->err = mtev_json_tokener_error_parse_eof;
  }

  if(tok->err == mtev_json_tokener_success) return mtev_json_object_get(current);
  MC_DEBUG("mtev_json_tokener_parse_ex: error %s at offset %d\n",
	   mtev_json_tokener_errors[tok->err], tok->char_offset);
  return NULL;
}
