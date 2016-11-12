#ifndef MTEV_SORT_H
#define MTEV_SORT_H

/**
 * interface to call for a merge sort.  given:
 * 
 * struct foo {
 *   int data;
 *   struct foo *next;
 * }
 * 
 * You would define a compare function:
 * 
 * int compare_function(void* left, void *right) {
 *   struct foo *l = (struct foo *)left;
 *   struct foo *r = (struct foo *)right;
 *   return l->data - r->data;
 * }
 * 
 * And a next_function
 * 
 * void *next_function(void *x) {
 *   struct foo *y = (struct foo*)x;
 *   return y->next;
 * }
 * 
 * And a set_next function
 * 
 * void set_next(void *current, void *value) {
 *   struct foo *y = (struct foo*)current;
 *   y->next = (struct foo *)value;
 * }
 * 
 * And then merge sort like:
 * 
 * struct foo *list = ...;
 * 
 * mtev_merge_sort(&list, next_function, set_next, compare_function);
 * 
 * 'list' will be modified to contain the sorted list based on compare_function
 */ 

typedef void *(*mtev_sort_next_function)(void *current);
typedef void (*mtev_sort_set_next_function)(void *current, void *value);
typedef int (*mtev_sort_compare_function)(void *left, void *right);

void mtev_merge_sort(void **head_ptr_ptr, 
                            mtev_sort_next_function next,
                            mtev_sort_set_next_function set_next,
                            mtev_sort_compare_function compare);
#endif
