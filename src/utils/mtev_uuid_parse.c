
#include "mtev_uuid_parse.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

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

static unsigned char reverse_lut[16] = {
  '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};

#define hexvalue(c) ((unsigned long)lut[(unsigned char)(c)])

static unsigned char reverse_uut[16] = {
  '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
};

#define HEXvalue(c) ((unsigned long)uut[(unsigned char)(c)])

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
  if (*p != '\0') return -1;
  return 0;
}

void mtev_uuid_unparse_lower(const uuid_t uu, char *out)
{
  char *w = out;
  /* dash after 4 then every 2 for a few steps */
  for (int i = 0; i < 16; i++) {
    *w++ = reverse_lut[(uu[i] & 0xf0) >> 4];
    *w++ = reverse_lut[uu[i] & 0x0f];
    switch (i) {
    case 3:
    case 5:
    case 7:
    case 9:
      *w++ = '-';
      break;
    };
  }
  *w = '\0';
}

void mtev_uuid_unparse(const uuid_t uu, char *out)
{
  char *w = out;
  /* dash after 4 then every 2 for a few steps */
  for (int i = 0; i < 16; i++) {
    *w++ = reverse_uut[(uu[i] & 0xf0) >> 4];
    *w++ = reverse_uut[uu[i] & 0x0f];
    switch (i) {
    case 3:
    case 5:
    case 7:
    case 9:
      *w++ = '-';
      break;
    };
  }
  *w = '\0';
}
