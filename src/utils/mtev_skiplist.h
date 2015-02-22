/* ======================================================================
 * Copyright (c) 2000,2006 Theo Schlossnagle
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * The following code was written by Theo Schlossnagle for use in the
 * Backhand project at The Center for Networking and Distributed Systems
 * at The Johns Hopkins University.
 *
 * This is a skiplist implementation to be used for abstract structures
 * and is release under the LGPL license version 2.1 or later.  A copy
 * of this license can be found file LGPL.
 *
 * Alternatively, this file may be licensed under the new BSD license.
 * A copy of this license can be found file BSD.
 *
 * ======================================================================
*/

#ifndef _MTEV_SKIPLIST_P_H
#define _MTEV_SKIPLIST_P_H

/* This is a skiplist implementation to be used for abstract structures
   within the Spread multicast and group communication toolkit

   This portion written by -- Theo Schlossnagle <jesus@cnds.jhu.eu>
*/

/* This is the function type that must be implemented per object type
   that is used in a skiplist for comparisons to maintain order */
typedef int (*mtev_skiplist_comparator_t)(const void *, const void *);
typedef void (*mtev_freefunc_t)(void *);

struct _mtev_skiplist_node;

typedef struct _iskiplist {
  mtev_skiplist_comparator_t compare;
  mtev_skiplist_comparator_t comparek;
  int height;
  int preheight;
  int size;
  struct _mtev_skiplist_node *top;
  struct _mtev_skiplist_node *bottom;
  struct _iskiplist *index;
} mtev_skiplist;

typedef struct _mtev_skiplist_node {
  void *data;
  struct _mtev_skiplist_node *next;
  struct _mtev_skiplist_node *prev;
  struct _mtev_skiplist_node *down;
  struct _mtev_skiplist_node *up;
  struct _mtev_skiplist_node *previndex;
  struct _mtev_skiplist_node *nextindex;
  mtev_skiplist *sl;
} mtev_skiplist_node;


void mtev_skiplist_init(mtev_skiplist *sl);
void mtev_skiplist_set_compare(mtev_skiplist *sl, mtev_skiplist_comparator_t,
                               mtev_skiplist_comparator_t);
void mtev_skiplist_add_index(mtev_skiplist *sl, mtev_skiplist_comparator_t,
                             mtev_skiplist_comparator_t);
mtev_skiplist_node *mtev_skiplist_getlist(mtev_skiplist *sl);
void *mtev_skiplist_find_compare(mtev_skiplist *sl, const void *data,
                                 mtev_skiplist_node **iter,
		                 mtev_skiplist_comparator_t func);
void *mtev_skiplist_find_neighbors_compare(mtev_skiplist *sl, const void *data,
                                           mtev_skiplist_node **iter,
                                           mtev_skiplist_node **prev,
                                           mtev_skiplist_node **next,
		                           mtev_skiplist_comparator_t func);
void *mtev_skiplist_find(mtev_skiplist *sl, const void *data,
                         mtev_skiplist_node **iter);
void *mtev_skiplist_find_neighbors(mtev_skiplist *sl, const void *data,
                                   mtev_skiplist_node **iter,
                                   mtev_skiplist_node **prev,
                                   mtev_skiplist_node **next);
void *mtev_skiplist_next(mtev_skiplist *sl, mtev_skiplist_node **);
void *mtev_skiplist_previous(mtev_skiplist *sl, mtev_skiplist_node **);

mtev_skiplist_node *mtev_skiplist_insert_compare(mtev_skiplist *sl,
                                                 const void *data,
                                                 mtev_skiplist_comparator_t comp);
mtev_skiplist_node *mtev_skiplist_insert(mtev_skiplist *sl, const void *data);
int mtev_skiplist_remove_compare(mtev_skiplist *sl, const void *data,
                                 mtev_freefunc_t myfree,
                                 mtev_skiplist_comparator_t comp);
int mtev_skiplist_remove(mtev_skiplist *sl, const void *data,
                         mtev_freefunc_t myfree);
int mtev_skiplisti_remove(mtev_skiplist *sl, mtev_skiplist_node *m,
                          mtev_freefunc_t myfree);
void mtev_skiplist_destroy(mtev_skiplist *sl, mtev_freefunc_t myfree);

void *mtev_skiplist_pop(mtev_skiplist * a, mtev_freefunc_t myfree);
void *mtev_skiplist_peek(mtev_skiplist * a);

int mtev_compare_voidptr(const void *, const void *);

#endif
