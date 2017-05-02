#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <mtev_dyn_buffer.h>

int chkmem(mtev_dyn_buffer_t *buff, size_t len, char exp) {
  const char *cp;
  const char *ptr = mtev_dyn_buffer_data(buff);
  for(cp = ptr; cp < ptr+len; cp++) if(*cp != exp) return 0;
  return 1;
}
int main(int argc, char *argv[]) {
  int a = 12345;
  int b = 54321;
  mtev_dyn_buffer_t buff;

  mtev_dyn_buffer_init(&buff);

  assert(mtev_dyn_buffer_size(&buff) > 1892);

  memset(mtev_dyn_buffer_write_pointer(&buff), 1, 1892);
  mtev_dyn_buffer_advance(&buff, 1892);
  assert(chkmem(&buff, 1892, 1));

  mtev_dyn_buffer_reset(&buff);
  memset(mtev_dyn_buffer_write_pointer(&buff), 2, 1892);
  mtev_dyn_buffer_advance(&buff, 1892);
  assert(chkmem(&buff, 1892, 2));

  mtev_dyn_buffer_ensure(&buff, 100000);
  assert(chkmem(&buff, 1892, 2));

  assert(mtev_dyn_buffer_size(&buff) >= 100000);
  mtev_dyn_buffer_reset(&buff);
  memset(mtev_dyn_buffer_write_pointer(&buff), 3, 100000);
  mtev_dyn_buffer_advance(&buff, 100000);

  assert(chkmem(&buff, 100000, 3));

  assert(a == 12345);
  assert(b == 54321);

  mtev_dyn_buffer_destroy(&buff);


  mtev_dyn_buffer_t b2;
  mtev_dyn_buffer_init(&b2);

  char c = 34;
  for (int i = 0; i < 8192; i++) {
    /* trigger a growth from static space to heap space halfway through */
    mtev_dyn_buffer_add(&b2, &c, 1);
  }

  assert(chkmem(&b2, 8192, 34));
  assert(mtev_dyn_buffer_used(&b2) == 8192);
  assert(mtev_dyn_buffer_size(&b2) >= 8192);

  return 0;
}
