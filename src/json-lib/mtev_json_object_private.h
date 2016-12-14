/*
 * $Id: mtev_json_object_private.h,v 1.4 2006/01/26 02:16:28 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _mtev_json_object_private_h_
#define _mtev_json_object_private_h_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef void (mtev_json_object_delete_fn)(struct mtev_json_object *o);
typedef int (mtev_json_object_to_json_string_fn)(struct mtev_json_object *o,
					    struct jl_printbuf *pb);

struct mtev_json_object
{
  enum mtev_json_type o_type;
  enum mtev_json_int_overflow o_ioverflow;
  mtev_json_object_delete_fn *_delete;
  mtev_json_object_to_json_string_fn *_to_json_string;
  int _ref_count;
  struct jl_printbuf *_pb;
  union data {
    boolean c_boolean;
    double c_double;
    int c_int;
    struct jl_lh_table *c_object;
    struct jl_array_list *c_array;
    char *c_string;
  } o;
  union {
    uint64_t c_uint64;
    int64_t c_int64;
  } overflow;
};

/* CAW: added for ANSI C iteration correctness */
struct mtev_json_object_iter
{
	char *key;
	struct mtev_json_object *val;
	struct jl_lh_entry *entry;
};

#ifdef __cplusplus
}
#endif

#endif
