/*
 * $Id: arraylist.c,v 1.4 2006/01/26 02:16:28 mclark Exp $
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

#if STDC_HEADERS
# include <stdlib.h>
# include <string.h>
#endif /* STDC_HEADERS */

#if defined HAVE_STRINGS_H && !defined _STRING_H && !defined __USE_BSD
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "internal_bits.h"
#include "internal_arraylist.h"

struct jl_array_list*
jl_array_list_new(jl_array_list_free_fn *free_fn)
{
  struct jl_array_list *arr;

  arr = (struct jl_array_list*)calloc(1, sizeof(struct jl_array_list));
  if(!arr) return NULL;
  arr->size = MTEV_ARRAY_LIST_DEFAULT_SIZE;
  arr->length = 0;
  arr->free_fn = free_fn;
  if(!(arr->array = (void**)calloc(sizeof(void*), arr->size))) {
    free(arr);
    return NULL;
  }
  return arr;
}

extern void
jl_array_list_free(struct jl_array_list *arr)
{
  int i;
  for(i = 0; i < arr->length; i++)
    if(arr->array[i]) arr->free_fn(arr->array[i]);
  free(arr->array);
  free(arr);
}

void*
jl_array_list_get_idx(struct jl_array_list *arr, int i)
{
  if(i >= arr->length) return NULL;
  return arr->array[i];
}

static int jl_array_list_expand_internal(struct jl_array_list *arr, int max)
{
  void *t;
  int new_size;

  if(max < arr->size) return 0;
  new_size = mtev_json_max(arr->size << 1, max);
  if(!(t = realloc(arr->array, new_size*sizeof(void*)))) return -1;
  arr->array = (void**)t;
  (void)memset(arr->array + arr->size, 0, (new_size-arr->size)*sizeof(void*));
  arr->size = new_size;
  return 0;
}

int
jl_array_list_put_idx(struct jl_array_list *arr, int idx, void *data)
{
  if(jl_array_list_expand_internal(arr, idx)) return -1;
  if(arr->array[idx]) arr->free_fn(arr->array[idx]);
  arr->array[idx] = data;
  if(arr->length <= idx) arr->length = idx + 1;
  return 0;
}

int
jl_array_list_add(struct jl_array_list *arr, void *data)
{
  return jl_array_list_put_idx(arr, arr->length, data);
}

int
jl_array_list_length(struct jl_array_list *arr)
{
  return arr->length;
}
