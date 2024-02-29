#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <mtev_dyn_buffer.h>

int chkmem(mtev_dyn_buffer_t *buff, size_t len, char exp) {
  const char *cp;
  const char *ptr = (const char*)mtev_dyn_buffer_data(buff);
  for(cp = ptr; cp < ptr+len; cp++) if(*cp != exp) return 0;
  return 1;
}
int vprint_test_function(mtev_dyn_buffer_t *buff, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int to_return = mtev_dyn_buffer_maybe_add_vprintf(buff, fmt, args);
  va_end(args);
  return to_return;
}
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

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

  mtev_dyn_buffer_destroy(&b2);

  mtev_dyn_buffer_t b3;
  mtev_dyn_buffer_init(&b3);

  size_t buffer_size = mtev_dyn_buffer_size(&b3);
  assert(buffer_size <= 8192);
  size_t initial_test_buffer_size = buffer_size - 5;

  char test_buffer[8192];
  memset(test_buffer, 0, 8192);
  memset(test_buffer, 'a', initial_test_buffer_size);

  int needed = vprint_test_function(&b3, "%s", test_buffer);
  assert(needed == 0);
  assert(mtev_dyn_buffer_used(&b3) == initial_test_buffer_size);
  assert(mtev_dyn_buffer_size(&b3) == buffer_size);
  const char *data = (const char*)mtev_dyn_buffer_data(&b3);
  assert(memcmp(data, test_buffer, initial_test_buffer_size) == 0);

  char next_test_buffer[11];
  memset(next_test_buffer, 0, 11);
  memset(next_test_buffer, 'b', 10);

  needed = vprint_test_function(&b3, "%s", next_test_buffer);
  assert(needed == 11);
  data = (const char*)mtev_dyn_buffer_data(&b3);
  assert(memcmp(data, test_buffer, initial_test_buffer_size) == 0);
  assert(data[initial_test_buffer_size] == 0);

  mtev_dyn_buffer_ensure(&b3, needed);
  needed = vprint_test_function(&b3, "%s", next_test_buffer);
  assert(needed == 0);
  data = (const char*)mtev_dyn_buffer_data(&b3);
  assert(memcmp(data, test_buffer, initial_test_buffer_size) == 0);
  assert(memcmp(data+initial_test_buffer_size, next_test_buffer, 10) == 0);
  assert(data[initial_test_buffer_size + 10] == 0);

  mtev_dyn_buffer_destroy(&b3);

  return 0;
}
