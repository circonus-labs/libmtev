#include <mtev_sort.h>

#ifndef NULL
#define NULL 0x0
#endif

static void mtev_sort_split(void *node, void **front, void **back, 
                            mtev_sort_next_function next, mtev_sort_set_next_function set_next)
{
  void* fast;
  void* slow;
  if (node == NULL || next(node) == NULL) {
    *front = node;
    *back = NULL;
  }
  else {
    slow = node;
    fast = next(node);
 
    while (fast != NULL) {
      fast = next(fast);
      if (fast != NULL) {
        slow = next(slow);
        fast = next(fast);
      }
    }
 
    *front = node;
    *back = next(slow);
    set_next(slow, NULL);
  }
}

static void* mtev_sort_merge(void* a, void* b, 
                             mtev_sort_next_function next,
                             mtev_sort_set_next_function set_next,
                             mtev_sort_compare_function compare)
{
  void* result = NULL;
 
  if (a == NULL) {
    return b;
  } else if (b == NULL) {
    return a;
  }
 
  if (compare(a, b) <= 0) {
    result = a;
    set_next(result, mtev_sort_merge(next(a), b, next, set_next, compare));
  } else {
    result = b;
    set_next(result, mtev_sort_merge(a, next(b), next, set_next, compare));
  }
  return result;
}


void mtev_merge_sort(void **head_ptr_ptr, 
                     mtev_sort_next_function next,
                     mtev_sort_set_next_function set_next,
                     mtev_sort_compare_function compare) 
{
  void *head = *head_ptr_ptr; 
  void *a;
  void *b; 
  if (head == NULL || next(head) == NULL) {
    return;
  }
  mtev_sort_split(head, &a, &b, next, set_next);
  mtev_merge_sort(&a, next, set_next, compare);
  mtev_merge_sort(&b, next, set_next, compare);
  *head_ptr_ptr = mtev_sort_merge(a, b, next, set_next, compare);
}
