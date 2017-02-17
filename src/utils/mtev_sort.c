#include <mtev_sort.h>

#ifndef NULL
#define NULL 0x0
#endif

/* 
 * Stable, O(N log N) time complexity, no auxiliary space
 * 
 * see: http://www.chiark.greenend.org.uk/~sgtatham/algorithms/listsort.html 
 */

void mtev_merge_sort(void **head_ptr_ptr,
                     mtev_sort_next_function get_next,
                     mtev_sort_set_next_function set_next,
                     mtev_sort_compare_function compare) 
{
  int list_size = 1, num_merges, left_size, right_size;
  void *tail, *left, *right, *next, *head = *head_ptr_ptr; 
  if (head == NULL || get_next(head) == NULL) {
    return;
  }

  do { // For each power of two <= list length
    num_merges = 0;
    left = head;
    tail = head = NULL; 

    while (left != NULL) { 
      num_merges++;
      right = left;
      left_size = 0;
      right_size = list_size;

      while (right != NULL && left_size < list_size) {
        left_size++;
        right = get_next(right);
      }

      while (left_size > 0 || (right_size > 0 && right != NULL)) {
        if (left_size == 0) {
          next = right;
          right = get_next(right);
          right_size--;
        }
        else if (right_size == 0 || right == NULL) {
          next = left;
          left = get_next(left);
          left_size--;
        }
        else if (compare(left,right) < 0) {
          next = left;
          left = get_next(left);
          left_size--;
        }
        else {
          next = right;
          right = get_next(right);
          right_size--;
        }
        if (tail) {
          set_next(tail,next);  
        }
        else {
          head = next;
        }
        tail = next;          
      }
      left = right;
    }
    set_next(tail, NULL);
    list_size <<= 1;
  } while (num_merges > 1); 
  *head_ptr_ptr = head;
}
