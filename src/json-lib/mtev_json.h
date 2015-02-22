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

#ifdef __cplusplus
}
#endif

#endif
