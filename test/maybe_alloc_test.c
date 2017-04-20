#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <mtev_maybe_alloc.h>

int chkmem(const char *ptr, size_t len, char exp) {
  const char *cp;
  for(cp = ptr; cp < ptr+len; cp++) if(*cp != exp) return 0;
  return 1;
}
int main(int argc, char *argv[]) {
  int a = 12345;
  MTEV_MAYBE_DECL(char, buff, 1892);
  int b = 54321;

  assert(MTEV_MAYBE_SIZE(buff) == 1892);
  memset(buff, 1, MTEV_MAYBE_SIZE(buff));
  assert(chkmem(buff, 1892, 1));

  MTEV_MAYBE_REALLOC(buff, 100); /* noop */
  assert(chkmem(buff, 1892, 1));

  assert(MTEV_MAYBE_SIZE(buff) == 1892);
  memset(buff, 2, MTEV_MAYBE_SIZE(buff));
  assert(chkmem(buff, 1892, 2));

  MTEV_MAYBE_REALLOC(buff, 100000);
  assert(chkmem(buff, 1892, 2));

  assert(MTEV_MAYBE_SIZE(buff) == 100000);
  memset(buff, 3, MTEV_MAYBE_SIZE(buff));
  assert(chkmem(buff, 100000, 3));

  assert(a == 12345);
  assert(b == 54321);

  MTEV_MAYBE_FREE(buff);
  return 0;
}
