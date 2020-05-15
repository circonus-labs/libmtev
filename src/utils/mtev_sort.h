#ifndef MTEV_SORT_H
#define MTEV_SORT_H

#ifdef __cplusplus
extern "C" {
#endif

/*! \file mtev_sort.h
 * 
 * Interface to call for a merge sort.
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

/*! \fn void *mtev_sort_next_function(void *current)
    \brief Function definition to get the next item from current
    \param current the current node
    \return the item after current
*/
typedef void *(*mtev_sort_next_function)(void *current);
/*! \fn int mtev_sort_set_next_function(void *current, void *value)
    \brief Function definition to re-order objects
    \param current the current node
    \param value the value that should be directly after current
*/

typedef void (*mtev_sort_set_next_function)(void *current, void *value);

/*! \fn int mtev_sort_compare_function(void *left, void *right)
    \brief Function definition to compare sortable entries
    \param left one object to compare
    \param right the other object to compare
    \return less than zero, zero, or greater than zero if left is less than, equal, or greater than right.
*/
typedef int (*mtev_sort_compare_function)(void *left, void *right);


/*! \fn void mtev_merge_sort(void **head_ptr_ptr, mtev_sort_next_function next, mtev_sort_set_next_function set_next, mtev_sort_compare_function compare)
    \brief Merge sort data starting at head_ptr_ptr, iteratively
    \param next the function to call to get the next pointer from a node
    \param set_next the function to call to alter the item directly after current
    \param compare the function to call to compare 2 nodes
*/
void mtev_merge_sort(void **head_ptr_ptr, 
                            mtev_sort_next_function next,
                            mtev_sort_set_next_function set_next,
                            mtev_sort_compare_function compare);
#ifdef __cplusplus
}
#endif

#endif
