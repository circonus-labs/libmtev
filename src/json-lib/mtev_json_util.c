/*
 * $Id: mtev_json_util.c,v 1.4 2006/01/30 23:07:57 mclark Exp $
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
#include <limits.h>
#include <string.h>
#include <errno.h>

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */

#if HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <io.h>
#endif /* defined(WIN32) */

#if !HAVE_OPEN && defined(WIN32)
# define open _open
#endif


#include "internal_bits.h"
#include "internal_debug.h"
#include "internal_printbuf.h"
#include "mtev_json_object.h"
#include "mtev_json_tokener.h"
#include "mtev_json_util.h"

struct mtev_json_object *mtev_json_object_from_fd(int fd,  enum mtev_json_tokener_error *err)
{
  struct jl_printbuf *pb;
  struct mtev_json_object *obj;
  char buf[JSON_FILE_BUF_SIZE];
  int ret;

  if(!(pb = jl_printbuf_new())) {
    MC_ERROR("mtev_json_object_from_fd: jl_printbuf_new failed%s\n", "");
    return (struct mtev_json_object*)NULL;
  }
  while((ret = read(fd, buf, JSON_FILE_BUF_SIZE)) > 0) {
    jl_printbuf_memappend(pb, buf, ret);
  }
  if(ret < 0) {
    MC_ABORT("mtev_json_object_from_fd: error reading fd %d: %s\n",
	     fd, strerror(errno));
    jl_printbuf_free(pb);
    return (struct mtev_json_object*)NULL;
  }
  obj = mtev_json_tokener_parse(pb->buf, err);
  jl_printbuf_free(pb);
  return obj;
}

struct mtev_json_object* mtev_json_object_from_file(const char *filename,  enum mtev_json_tokener_error *err)
{
  struct mtev_json_object *obj;
  int fd;

  if((fd = open(filename, O_RDONLY)) < 0) {
    MC_ERROR("mtev_json_object_from_file: error reading file %s: %s\n",
	     filename, strerror(errno));
    return NULL;
  }
  obj = mtev_json_object_from_fd(fd, err);
  close(fd);
  return obj;
}

int mtev_json_object_to_fd(int fd, struct mtev_json_object *obj)
{
  const char *mtev_json_str;
  int ret;
  unsigned int wpos, wsize;

  if(!obj) {
    MC_ERROR("mtev_json_object_to_fd: object is null%s\n", "");
    return -1;
  }

  if(!(mtev_json_str = mtev_json_object_to_json_string(obj))) {
    return -1;
  }

  wsize = (unsigned int)(strlen(mtev_json_str) & UINT_MAX); /* CAW: probably unnecessary, but the most 64bit safe */
  wpos = 0;
  while(wpos < wsize) {
    if((ret = write(fd, mtev_json_str + wpos, wsize-wpos)) < 0) {
      MC_ERROR("mtev_json_object_to_fd: error writing fd %d: %s\n",
	     fd, strerror(errno));
      return -1;
    }

    /* because of the above check for ret < 0, we can safely cast and add */
    wpos += (unsigned int)ret;
  }

  return 0;

}

int mtev_json_object_to_file(const char *filename, struct mtev_json_object *obj)
{
  int fd, ret;

  if((fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {
    MC_ERROR("mtev_json_object_to_file: error opening file %s: %s\n",
	     filename, strerror(errno));
    return -1;
  }

  ret = mtev_json_object_to_fd(fd, obj);
  close(fd);
  return ret;
}
