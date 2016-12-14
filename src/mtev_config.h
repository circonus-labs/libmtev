/*
 * Copyright (c) 2005-2009, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
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

#ifndef __MTEV_CONFIG_H
#define __MTEV_CONFIG_H

#include "config.h"

#define IFS_CH '/'

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#ifndef DTRACE_ENABLED
#define DTRACE_PROBES_DISABLED 1
#endif

/* The number of bytes in a void * (workaround for OpenBSD). */
#undef SIZEOF_VOID__
#if !defined(SIZEOF_VOID_P) && defined(SIZEOF_VOID__)
#  define SIZEOF_VOID_P SIZEOF_VOID__
#endif

/* BIND, Kerberos and Berkeley DB use __BIT_TYPES_DEFINED__ to protect
 * against multiple redefinitions of these types (uint{8,16,32,64}_t)
 * and so shall we.
 */
#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__
#endif

#ifdef MAKE_HTOBE64_HTONLL
#undef htonll
#define htonll htobe64
#endif

#ifdef MAKE_BE64TOH_NTOHLL
#undef ntohll
#define ntohll be64toh
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif

typedef enum { mtev_false = 0, mtev_true } mtev_boolean;

#endif
