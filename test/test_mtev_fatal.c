#include "../src/utils/mtev_log.h"

int main() {
  // Test mtevFatal
  mtevFatal(mtev_error, "this is a fatal error: %s\n", "fatal test");

  // Test mtevAssert
  mtevAssert(0); // This will trigger the assertion failure.

  return 0;
}
