/*
 * $Id: json.h,v 1.6 2006/01/26 02:16:28 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _mtev_json_h_
#define _mtev_json_h_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef JSON_LIB_COMPAT
/* Unless JSON_LIB_COMPAT is defined as 0, turn it on */
#define JSON_LIB_COMPAT 1
#endif

#include "mtev_bits.h"
#include "mtev_debug.h"
#include "mtev_linkhash.h"
#include "mtev_arraylist.h"
#include "mtev_json_util.h"
#include "mtev_json_object.h"
#include "mtev_json_tokener.h"


/* MACROS for making terse work of creating objects */
#define MJ_OBJ() mtev_json_object_new_object()
#define MJ_ARR() mtev_json_object_new_array()
#define MJ_DOUBLE(i) mtev_json_object_new_double(i)
#define MJ_INT(i) mtev_json_object_new_int(i)
#define MJ_INT64(i) mtev_json_object_new_int64(i)
#define MJ_UINT64(i) mtev_json_object_new_uint64(i)
#define MJ_BOOL(i) mtev_json_object_new_boolean(i)
#define MJ_NULL() NULL
#define MJ_STR(i) mtev_json_object_new_string(i)
#define MJ_STRN(i, len) mtev_json_object_new_string_len(i, len)
#define MJ_KV(o, k, v) mtev_json_object_object_add(o, k, v)
#define MJ_ADD(o, v) mtev_json_object_array_add(o, v)
#define MJ_DROP(o) mtev_json_object_put(o)

#ifdef __cplusplus
}
#endif

#endif
