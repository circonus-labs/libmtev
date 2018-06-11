
#include "mtev_uuid_generate.h"
#include "mtev_rand.h"
#include <assert.h>

/* Pseudo-Random generation per the RFC 4122 spec re: v4
 * https://tools.ietf.org/html/rfc4122
 */
void mtev_uuid_generate(uuid_t uu)
{
  uint8_t *p = uu;
  size_t ss = mtev_rand_buf(p, sizeof(uuid_t));
  assert(ss == 16);
  p[6] = (p[6] & 0x0f) | 0x40;
  p[8] = (p[8] & 0x3f) | 0x80;
}
