/*
 * $Id: mtev_json_util.h,v 1.4 2006/01/30 23:07:57 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _mtev_json_util_h_
#define _mtev_json_util_h_

#include "mtev_json_object.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_FILE_BUF_SIZE 4096

/* utility functions */

/* opens and closes the filename */
extern struct mtev_json_object* mtev_json_object_from_file(char *filename);

/* does not close the fd after completion, leaves it open */
extern struct mtev_json_object* mtev_json_object_from_fd(int fd);

/* opens and closes the filename */
extern int mtev_json_object_to_file(char *filename, struct mtev_json_object *obj);

  /* does not close the fd after completion, leaves it open */
extern int mtev_json_object_to_fd(int fd, struct mtev_json_object *obj);

#ifdef __cplusplus
}
#endif

#endif
