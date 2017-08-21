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

#include "mtev_defines.h"
#include "mtev_skiplist.h"
#include "mtev_log.h"
#include "mtev_rand.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#ifndef MIN
#define MIN(a,b) ((a<b)?(a):(b))
#endif

struct _iskiplist {
  mtev_skiplist_comparator_t compare;
  mtev_skiplist_comparator_t comparek;
  int height;
  int preheight;
  int size;
  struct _mtev_skiplist_node *top;
  struct _mtev_skiplist_node *bottom;
  struct _iskiplist *index;
};

struct _mtev_skiplist_node {
  void *data;
  struct _mtev_skiplist_node *next;
  struct _mtev_skiplist_node *prev;
  struct _mtev_skiplist_node *down;
  struct _mtev_skiplist_node *up;
  struct _mtev_skiplist_node *previndex;
  struct _mtev_skiplist_node *nextindex;
  mtev_skiplist *sl;
};

static int mtev_skiplisti_find_compare(mtev_skiplist *sl, const void *data,
                                       mtev_skiplist_node **ret,
                                       mtev_skiplist_node **prev,
                                       mtev_skiplist_node **next,
                                       mtev_skiplist_comparator_t comp);
int mtev_skiplisti_remove(mtev_skiplist *sl, mtev_skiplist_node *m,
                          mtev_freefunc_t myfree);

int mtev_compare_voidptr(const void *a, const void *b) {
  if(a < b) return -1;
  if(a == b) return 0;
  return 1;
}

static int get_b_rand(void) {
  static int ph=32; /* More bits than we will ever use */
  static unsigned long randseq;
  if(ph > 31) { /* Num bits in return of mtev_rand() */
    ph=0;
    randseq = mtev_rand();
  }
  ph++;
  return ((randseq & (1 << (ph-1))) >> (ph-1));
}

void mtev_skiplisti_init(mtev_skiplist *sl) {
  memset(sl, 0, sizeof(*sl));
}

static int indexing_comp(const void *av, const void *bv) {
  const mtev_skiplist *a = av;
  const mtev_skiplist *b = bv;
  if(a->compare == b->compare) return 0;
  return (void *)(a->compare)>(void *)(b->compare) ? 1 : -1;
}
static int indexing_compk(const void *a, const void *bv) {
  const mtev_skiplist *b = bv;
  if(a == (const void *)b->compare) return 0;
  return a>(void *)(b->compare) ? 1 : -1;
}

mtev_skiplist *mtev_skiplist_alloc(void) {
  mtev_skiplist *sl;
  sl = calloc(1, sizeof(*sl));
  mtev_skiplist_init(sl);
  return sl;
}

void mtev_skiplist_init(mtev_skiplist *sl) {
  mtev_rand_init();
  mtev_skiplisti_init(sl);
  sl->index = (mtev_skiplist *)malloc(sizeof(mtev_skiplist));
  mtev_skiplisti_init(sl->index);
  mtev_skiplist_set_compare(sl->index, indexing_comp, indexing_compk);
}

mtev_skiplist *mtev_skiplist_indexes(mtev_skiplist *sl) {
  return sl->index;
}
void mtev_skiplist_set_compare(mtev_skiplist *sl,
                               mtev_skiplist_comparator_t comp,
                              mtev_skiplist_comparator_t compk) {
  if(sl->compare && sl->comparek) {
    mtev_skiplist_add_index(sl, comp, compk);
  } else {
    sl->compare = comp;
    sl->comparek = compk;
  }
}

void mtev_skiplist_add_index(mtev_skiplist *sl,
                             mtev_skiplist_comparator_t comp,
                             mtev_skiplist_comparator_t compk) {
  mtev_skiplist_node *m = NULL;
  mtev_skiplist *ni;
  int icount=0;
  mtev_skiplist_find(sl->index, (void *)comp, &m);
  if(m) return; /* Index already there! */
  ni = (mtev_skiplist *)malloc(sizeof(mtev_skiplist));
  mtev_skiplisti_init(ni);
  mtev_skiplist_set_compare(ni, comp, compk);
  /* Build the new index... This can be expensive! */
  m = mtev_skiplist_insert(sl->index, ni);
  while(m->prev) m=m->prev, icount++;
  for(m=mtev_skiplist_getlist(sl); m; mtev_skiplist_next(sl, &m)) {
    int j=icount-1;
    mtev_skiplist_node *nsln;
    nsln = mtev_skiplist_insert(ni, m->data);
    /* skip from main index down list */
    while(j>0) m=m->nextindex, j--;
    /* insert this node in the indexlist after m */
    nsln->nextindex = m->nextindex;
    if(m->nextindex) m->nextindex->previndex = nsln;
    nsln->previndex = m;
    m->nextindex = nsln;
  } 
}

mtev_skiplist_node *mtev_skiplist_getlist(mtev_skiplist *sl) {
  if(!sl->bottom) return NULL;
  return sl->bottom->next;
}

void *mtev_skiplist_find(mtev_skiplist *sl,
                         const void *data,
                         mtev_skiplist_node **iter) {
  return mtev_skiplist_find_neighbors(sl, data, iter, NULL, NULL);
}
void *mtev_skiplist_find_neighbors(mtev_skiplist *sl,
                                   const void *data,
                                   mtev_skiplist_node **iter,
                                   mtev_skiplist_node **prev,
                                   mtev_skiplist_node **next) {
  void *ret;
  mtev_skiplist_node *aiter;
  if(!sl->compare) return 0;
  if(iter)
    ret = mtev_skiplist_find_neighbors_compare(sl, data, iter,
                                               prev, next, sl->compare);
  else
    ret = mtev_skiplist_find_neighbors_compare(sl, data, &aiter,
                                               prev, next, sl->compare);
  return ret;
}

void *mtev_skiplist_find_compare(mtev_skiplist *sli,
                                 const void *data,
                                 mtev_skiplist_node **iter,
                                 mtev_skiplist_comparator_t comp) {
  return mtev_skiplist_find_neighbors_compare(sli, data, iter,
                                              NULL, NULL, comp);
}
void *mtev_skiplist_find_neighbors_compare(mtev_skiplist *sli,
                                           const void *data,
                                           mtev_skiplist_node **iter,
                                           mtev_skiplist_node **prev,
                                           mtev_skiplist_node **next,
                                           mtev_skiplist_comparator_t comp) {
  mtev_skiplist_node *m = NULL;
  mtev_skiplist *sl;
  if(iter) *iter = NULL;
  if(prev) *prev = NULL;
  if(next) *next = NULL;
  if(comp==sli->compare || !sli->index) {
    sl = sli;
  } else {
    mtev_skiplist_find(sli->index, (void *)comp, &m);
    mtevAssert(m);
    sl= (mtev_skiplist *) m->data;
  }
  mtev_skiplisti_find_compare(sl, data, iter, prev, next, sl->comparek);
  return (iter && *iter)?((*iter)->data):NULL;
}
static int mtev_skiplisti_find_compare(mtev_skiplist *sl,
                                       const void *data,
                                       mtev_skiplist_node **ret,
                                       mtev_skiplist_node **prev,
                                       mtev_skiplist_node **next,
                                       mtev_skiplist_comparator_t comp) {
  mtev_skiplist_node *m = NULL;
  int count=0;
  if(ret) *ret = NULL;
  if(prev) *prev = NULL;
  if(next) *next = NULL;
  m = sl->top;
  while(m) {
    int compared;
    compared = (m->next) ? comp(data, m->next->data) : -1;
    if(compared == 0) { /* Found */
      m=m->next; /* m->next is the match */
      while(m->down) m=m->down; /* proceed to the bottom-most */
      if(ret) *ret = m;
      /* We have to be careful when setting *prev: the first column is a
       * place-holder element with NULL data that we don't want to expose
       * to clients. So check that m->prev isn't the first column before
       * filling in *prev. */
      if(prev) *prev = (m->prev && m->prev->prev) ? m->prev : NULL;
      if(next) *next = m->next;
      return count;
    }
    if((m->next == NULL) || (compared<0)) {
      if(m->down == NULL) {
        /* This is... we're about to bail, figure out our neighbors.
         * Also, see comment above: need to be careful with *prev. */
        if(prev) *prev = (m == sl->bottom) ? NULL : (m->prev ? m : NULL);
        if(next) *next = m->next;
      }
      m = m->down;
      count++;
    }
    else
      m = m->next, count++;
  }
  if(ret) *ret = NULL;
  return count;
}
void *mtev_skiplist_next(mtev_skiplist *sl, mtev_skiplist_node **iter) {
  if(!*iter) return NULL;
  *iter = (*iter)->next;
  return (*iter)?((*iter)->data):NULL;
}
void *mtev_skiplist_previous(mtev_skiplist *sl, mtev_skiplist_node **iter) {
  if(!*iter) return NULL;
  *iter = (*iter)->prev;
  /* do not expose the first, "placeholder" column to users. */
  if(!(*iter)->prev) *iter = NULL;
  return (*iter)?((*iter)->data):NULL;
}
void *mtev_skiplist_data(mtev_skiplist_node *m) {
  return m->data;
}
int mtev_skiplist_size(mtev_skiplist *sl) {
  if(!sl) return 0;
  return sl->size;
}
mtev_skiplist_node *mtev_skiplist_insert(mtev_skiplist *sl,
                                         const void *data) {
  if(!sl->compare) return 0;
  return mtev_skiplist_insert_compare(sl, data, sl->compare);
}

mtev_skiplist_node *mtev_skiplist_insert_compare(mtev_skiplist *sl,
                                                 const void *data,
                                                 mtev_skiplist_comparator_t comp) {
  mtev_skiplist_node *m, *p, *tmp, *ret = NULL, **stack;
  int nh=1, ch, stacki;
  if(!sl->top) {
    sl->height = 1;
    sl->top = sl->bottom = 
      calloc(1, sizeof(mtev_skiplist_node));
    sl->top->sl = sl;
  }
  if(sl->preheight) {
    while(nh < sl->preheight && get_b_rand()) nh++;
  } else {
    while(nh <= sl->height && get_b_rand()) nh++;
  }
  /* Now we have the new height at which we wish to insert our new node */
  /* Let us make sure that our tree is a least that tall (grow if necessary)*/
  for(;sl->height<nh;sl->height++) {
    sl->top->up = (mtev_skiplist_node *)calloc(1, sizeof(mtev_skiplist_node));
    sl->top->up->down = sl->top;
    sl->top = sl->top->up;
    sl->top->sl = sl;
  }
  ch = sl->height;
  /* Find the node (or node after which we would insert) */
  /* Keep a stack to pop back through for insertion */
  m = sl->top;
  stack = (mtev_skiplist_node **)alloca(sizeof(mtev_skiplist_node *)*(nh));
  stacki=0;
  while(m) {
    int compared=-1;
    if(m->next) compared=comp(data, m->next->data);
    if(compared == 0) {
      return 0;
    }
    if(compared<0) {
      if(ch<=nh) {
	/* push on stack */
	stack[stacki++] = m;
      }
      m = m->down;
      ch--;
    } else {
      m = m->next;
    }
  }
  /* Pop the stack and insert nodes */
  p = NULL;
  for(;stacki>0;stacki--) {
    m = stack[stacki-1];
    tmp = calloc(1, sizeof(*tmp));
    tmp->next = m->next;
    if(m->next) m->next->prev=tmp;
    tmp->prev = m;
    tmp->down = p;
    if(p) p->up=tmp;
    tmp->data = (void *)data;
    tmp->sl = sl;
    m->next = tmp;
    /* This sets ret to the bottom-most node we are inserting */
    if(!p) ret=tmp;
    p = tmp;
  }
  if(sl->index != NULL) {
    /* this is a external insertion, we must insert into each index as well */
    mtev_skiplist_node *p, *ni, *li;
    mtevAssert(ret);
    li=ret;
    for(p = mtev_skiplist_getlist(sl->index); p; mtev_skiplist_next(sl->index, &p)) {
      ni = mtev_skiplist_insert((mtev_skiplist *)p->data, ret->data);
      mtevAssert(ni);
      li->nextindex = ni;
      ni->previndex = li;
      li = ni;
    }
  }
  sl->size++;
  return ret;
}
int mtev_skiplist_remove(mtev_skiplist *sl,
                         const void *data, mtev_freefunc_t myfree) {
  if(!sl->compare) return 0;
  return mtev_skiplist_remove_compare(sl, data, myfree, sl->comparek);
}
int mtev_skiplist_remove_node(mtev_skiplist *sl, mtev_skiplist_node *m,
                              mtev_freefunc_t myfree) {
  while(m->previndex) m = m->previndex;
  mtevAssert(sl == m->sl);
  return mtev_skiplisti_remove(sl, m, myfree);
}
int mtev_skiplisti_remove(mtev_skiplist *sl, mtev_skiplist_node *m, mtev_freefunc_t myfree) {
  mtev_skiplist_node *p;
  if(!m) return 0;
  if(m->nextindex) mtev_skiplisti_remove(m->nextindex->sl, m->nextindex, NULL);
  while(m->up) m=m->up;
  while(m) {
    p=m;
    p->prev->next = p->next; /* take me out of the list */
    if(p->next) p->next->prev = p->prev; /* take me out of the list */
    m=m->down;
    /* This only frees the actual data in the bottom one */
    if(!m && myfree && p->data) myfree(p->data);
    free(p);
  }
  sl->size--;
  while(sl->top && sl->top->next == NULL) {
    /* While the row is empty and we are not on the bottom row */
    p = sl->top;
    sl->top = sl->top->down; /* Move top down one */
    if(sl->top) sl->top->up = NULL; /* Make it think its the top */
    free(p);
    sl->height--;
  }
  if(!sl->top) sl->bottom = NULL;
  return 1;
}
int mtev_skiplist_remove_compare(mtev_skiplist *sli,
                                 const void *data,
                                 mtev_freefunc_t myfree,
                                 mtev_skiplist_comparator_t comp) {
  mtev_skiplist_node *m;
  mtev_skiplist *sl;
  if(comp==sli->comparek || !sli->index) {
    sl = sli;
  } else {
    mtev_skiplist_find(sli->index, (void *)comp, &m);
    mtevAssert(m);
    sl= (mtev_skiplist *) m->data;
  }
  mtev_skiplisti_find_compare(sl, data, &m, NULL, NULL, sl->comparek);
  if(!m) return 0;
  while(m->previndex) m=m->previndex;
  return mtev_skiplisti_remove(m->sl, m, myfree);
}
void mtev_skiplist_remove_all(mtev_skiplist *sl, mtev_freefunc_t myfree) {
  mtev_skiplist_node *m, *p, *u;
  m=sl->bottom;
  while(m) {
    p = m->next;
    if(p && myfree && p->data) myfree(p->data);
    while(m) {
      u = m->up;
      free(m);
      m=u;
    }
    m = p;
  }
  sl->top = sl->bottom = NULL;
  sl->height = 0;
  sl->size = 0;
}
static void mtev_skiplisti_destroy(void *vsl) {
  mtev_skiplist_destroy((mtev_skiplist *)vsl, NULL);
  free(vsl);
}
void mtev_skiplist_destroy(mtev_skiplist *sl, mtev_freefunc_t myfree) {
  if(sl->index) {
    while(mtev_skiplist_pop(sl->index, mtev_skiplisti_destroy) != NULL);
    free((void *) sl->index);
  }
  mtev_skiplist_remove_all(sl, myfree);
}

void mtev_skiplist_free(mtev_skiplist *sl) {
  mtev_skiplist_destroy(sl, NULL);
  free(sl);
}

void *mtev_skiplist_pop(mtev_skiplist * a, mtev_freefunc_t myfree)
{
  mtev_skiplist_node *sln;
  void *data = NULL;
  sln = mtev_skiplist_getlist(a);
  if (sln) {
    data = sln->data;
    mtev_skiplisti_remove(a, sln, myfree);
  }
  return data;
}
void *mtev_skiplist_peek(mtev_skiplist * a)
{
  mtev_skiplist_node *sln;
  sln = mtev_skiplist_getlist(a);
  if (sln) {
    return sln->data;
  }
  return NULL;
}
