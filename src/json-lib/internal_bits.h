/*
 * $Id: bits.h,v 1.10 2006/01/30 23:07:57 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _bits_h_
#define _bits_h_

#ifndef mtev_json_min
#define mtev_json_min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef mtev_json_max
#define mtev_json_max(a,b) ((a) > (b) ? (a) : (b))
#endif

#endif
