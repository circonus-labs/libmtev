#include <mtev_lru.h>
#include <mtev_time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);

struct data{
  int i;
  char key[10];
};

void
noop_free(void *x)
{
  (void)x;
  return;
}

int main(int argc, char **argv) 
{
  uuid_t uuid;
  char s[PATH_MAX];
  srand(time(NULL));

  struct data datas[10] = 
    {
      {0, "zero"},
      {1, "one"},
      {2, "two"},
      {3, "three"},
      {4, "four"},
      {5, "five"},
      {6, "six"},
      {7, "seven"},
      {8, "eight"},
      {9, "nine"}
    };

  /* test max entries */
  mtev_lru_t *lru = mtev_lru_create(5, noop_free);
  
  for (int j = 0; j < 10; j++) {
    mtev_lru_put(lru, datas[j].key, strlen(datas[j].key), &datas[j]);
  }

  if (mtev_lru_size(lru) != 5) {
    FAIL("LRU size is not 5");
  }

  /* test that the last 5 entries are what remains in the LRU */
  for (int j = 5; j < 10; j++) {
    void *d = NULL;
    mtev_lru_entry_token t = mtev_lru_get(lru, datas[j].key, strlen(datas[j].key), &d);
    struct data* dd = (struct data *)d;
    if (dd->i != datas[j].i) {
      FAIL("LRU expected %d, got %d", datas[j].i, dd->i);
    }
    mtev_lru_release(lru, t);
  }

  mtev_lru_invalidate(lru);
  if (mtev_lru_size(lru) != 0) {
    FAIL("LRU size is not 0");
  }

  mtev_lru_destroy(lru);
  printf("SUCCESS\n");

}
