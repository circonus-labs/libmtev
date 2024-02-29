#include "mtev_sort.h"
#include "mtev_time.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);


struct foo {
  int data;
  struct foo *next;
};

int compare_function(void* l, void* r) {
  struct foo *left = (struct foo *)l;
  struct foo *right = (struct foo *)r;
  return left->data - right->data;
}

void *next_function(void *x) {
  struct foo *f = (struct foo *)x;
  return f->next;
}

void set_next_function(void *x, void *v) {
  struct foo *f = (struct foo *)x;
  f->next = (struct foo*)v;
}

#define DEFAULT_SORT_SIZE 300000

int main(int argc, char **argv) 
{
  int sort_size = DEFAULT_SORT_SIZE;
  srand(time(NULL));
  struct foo *list, *head;
  list = head = malloc(sizeof(struct foo));
  list->data = rand();

  if (argc > 1) {
    sort_size = atoi(argv[1]);
  }

  for (int i = 0; i < sort_size; i++) {
    list->next = malloc(sizeof(struct foo));
    list->next->data = rand();
    list = list->next;
  }

  /*terminate the list */
  list->next = 0x0;

  mtev_hrtime_t start = mtev_gethrtime();
  mtev_merge_sort((void **)&head, next_function, set_next_function, compare_function);
  mtev_hrtime_t end = mtev_gethrtime();

  printf("Sort %d entries took: %llu nanos\n", sort_size, end - start);

  int begin = 0;
  struct foo *iter = head;
  while( iter ) {
    if (iter->data < begin) {
      FAIL("List not in order");
    }
    begin = iter->data;
    iter = iter->next;
  }
  printf("SUCCESS\n");
}
