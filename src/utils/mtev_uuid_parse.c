
#include "mtev_uuid_parse.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

struct uuid {
  uint32_t time_low;
  uint16_t time_mid;
  uint16_t time_hi_and_version;
  uint16_t clock_seq;
  uint8_t  node[6];
};

static unsigned char lut[256] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // gap before first hex digit
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
  0,1,2,3,4,5,6,7,8,9,       // 0123456789
  0,0,0,0,0,0,0,             // :;<=>?@ (gap)
  10,11,12,13,14,15,         // ABCDEF 
  0,0,0,0,0,0,0,0,0,0,0,0,0, // GHIJKLMNOPQRS (gap)
  0,0,0,0,0,0,0,0,0,0,0,0,0, // TUVWXYZ[/]^_` (gap)
  10,11,12,13,14,15          // abcdef 
};

#define hexvalue(c) ((unsigned long)lut[(unsigned char)(c)])

static inline void uuid_pack(const struct uuid *uu, uuid_t ptr)
{
  register uint32_t tmp;
  register unsigned char *out = ptr;

  tmp = uu->time_low;
  out[3] = (unsigned char) tmp;
  tmp >>= 8;
  out[2] = (unsigned char) tmp;
  tmp >>= 8;
  out[1] = (unsigned char) tmp;
  tmp >>= 8;
  out[0] = (unsigned char) tmp;

  tmp = uu->time_mid;
  out[5] = (unsigned char) tmp;
  tmp >>= 8;
  out[4] = (unsigned char) tmp;

  tmp = uu->time_hi_and_version;
  out[7] = (unsigned char) tmp;
  tmp >>= 8;
  out[6] = (unsigned char) tmp;

  tmp = uu->clock_seq;
  out[9] = (unsigned char) tmp;
  tmp >>= 8;
  out[8] = (unsigned char) tmp;

  memcpy(out+10, uu->node, 6);
}

int mtev_uuid_parse(const char *in, uuid_t uu)
{
  const char *p;
  int len;
  unsigned char *out;

  for (p = in, len = 0, out = uu; len < 36; ) {
    switch (len) {
    case 8:
    case 13:
    case 18:
    case 23:
      if (*p != '-') {
        return -1;
      }
      p++;
      len++;
      continue;
    }
    if (! (isxdigit(p[0]) && isxdigit(p[1])))
      return -1;
    *out = (hexvalue(p[0]) * 0x10) | hexvalue(p[1]);
    p += 2;
    len += 2;
    out++;
  }
  return 0;
}
