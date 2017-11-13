#include <mtev_lfu.h>
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
  mtev_lfu_t *lfu = mtev_lfu_create(5, noop_free);
  
  for (int j = 0; j < 10; j++) {
    mtev_lfu_put(lfu, datas[j].key, strlen(datas[j].key), &datas[j]);
  }

  if (mtev_lfu_size(lfu) != 5) {
    FAIL("LFU size is not 5");
  }

  /* test that the last 5 entries are what remains in the LRU */
  for (int j = 5; j < 10; j++) {
    void *d = NULL;
    mtev_lfu_entry_token token = mtev_lfu_get(lfu, datas[j].key, strlen(datas[j].key), &d);
    struct data* dd = (struct data *)d;
    if (dd->i != datas[j].i) {
      FAIL("LFU expected %d, got %d", datas[j].i, dd->i);
    }
    mtev_lfu_release(lfu, token);
  }


  /* now get 3 of the items to bump their frequency count up */
  void *x, *y, *z;
  mtev_lfu_entry_token t = mtev_lfu_get(lfu, "five", 4, &x);
  mtev_lfu_release(lfu, t);
  t = mtev_lfu_get(lfu, "six", 3, &y);
  mtev_lfu_release(lfu, t);
  t = mtev_lfu_get(lfu, "seven", 5, &z);
  mtev_lfu_release(lfu, t);

  /* add zero through four items.. these will evict themselves and shouldn't touch five->nine
   * since five->nine have higher frequency counts */
  for (int j = 0; j < 5; j++) {
    mtev_lfu_put(lfu, datas[j].key, strlen(datas[j].key), &datas[j]);
  }

  /* five->nine should remain */
  void *dx, *dy, *dz, *db;
  t = mtev_lfu_get(lfu, "five", 4, &dx);
  mtev_lfu_release(lfu, t);
  t = mtev_lfu_get(lfu, "six", 3, &dy);
  mtev_lfu_release(lfu, t);
  t = mtev_lfu_get(lfu, "seven", 5, &dz);
  mtev_lfu_release(lfu, t);
  t = mtev_lfu_get(lfu, "nine", 4, &db);
  mtev_lfu_release(lfu, t);

  if (x != dx) {
    FAIL("LFU expected five to be in cache");
  }
  if (y != dy) {
    FAIL("LFU expected six to be in cache");
  }
  if (z != dz) {
    FAIL("LFU expected seven to be in cache");
  }
  /* eight was removed by the puts on line 75 as it would have been in the lowest frequency list on the 
   * first insert, thereafter the newly inserted item became the low freq item so it was replaced
   *
   * Nine should be here however.
   */
  if (db == NULL) {
    FAIL("LFU expected nine to be in cache");
  }

  mtev_lfu_invalidate(lfu);
  if (mtev_lfu_size(lfu) != 0) {
    FAIL("LRU size is not 0");
  }

  mtev_lfu_destroy(lfu);

  lfu = mtev_lfu_create(0, noop_free);

  for (int j = 0; j < 10; j++) {
    mtev_lfu_put(lfu, datas[j].key, strlen(datas[j].key), &datas[j]);
  }

  for (int j = 0; j < 10; j++) {
    void *d = NULL;
    t = mtev_lfu_get(lfu, datas[j].key, strlen(datas[j].key), &d);
    if (d != NULL) {
      FAIL("Zero sized LFU should always return NULL");
    }
  }

  mtev_lfu_destroy(lfu);

  lfu = mtev_lfu_create(10, noop_free);

  mtev_lfu_put(lfu, datas[0].key, strlen(datas[0].key), &datas[0]);

  void *d;
  t = mtev_lfu_get(lfu, datas[0].key, strlen(datas[0].key), &d);
  mtev_lfu_release(lfu, t);
  if (d != &datas[0]) {
    FAIL("get failed after put");
  }
  t = mtev_lfu_get(lfu, datas[0].key, strlen(datas[0].key), &d);
  mtev_lfu_release(lfu, t);
  if (d != &datas[0]) {
    FAIL("2nd get failed after put");
  }
  mtev_lfu_destroy(lfu);

  printf("SUCCESS\n");

}
