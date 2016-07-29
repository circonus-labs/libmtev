
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

/* optimized version of strtoul which ignores checking since we already did it */
static inline unsigned long hextoul(const char *str, size_t len)
{
  unsigned long value = 0;
   
  /* we are guaranteed to not get a string longer than 8 in hex. */
  switch(len) {
  case 8:
    value += (hexvalue(str[len - 8])) * 268435456;
  case 7:
    value += (hexvalue(str[len - 7])) * 16777216;
  case 6:
    value += (hexvalue(str[len - 6])) * 1048576;
  case 5:
    value += (hexvalue(str[len - 5])) * 65536;
  case 4:
    value += (hexvalue(str[len - 4])) * 4096;
  case 3:
    value += (hexvalue(str[len - 3])) * 256;
  case 2:
    value += (hexvalue(str[len - 2])) * 16;
  case 1:    
    value += (hexvalue(str[len - 1]));
  };

  return value;
}


int mtev_uuid_parse(const char *in, uuid_t uu)
{
  const char    *p;
  int           i;
  int           len;
  char          buf[3] = {0};
  struct uuid   uuid;
  const char    *cp;


  for (p = in, len = 0; *p != '\0'; p++, len++) {

    switch (len) {
    case 8:
    case 13:
    case 18:
    case 23:
      if (*p != '-') {
        return -1;
      }

      break;
    default:
      if (isxdigit(*p) == 0) {
        return -1;
      }
      break;
    }
  }

  if (len != 36) {
    return -1;
  }

  uuid.time_low = hextoul(in, 8);
  uuid.time_mid = hextoul(in + 9, 4);
  uuid.time_hi_and_version = hextoul(in+14, 4); 
  uuid.clock_seq = hextoul(in + 19, 4); 
  cp = in+24;
  for (i=0; i < 6; i++) {
    buf[0] = *cp++;
    buf[1] = *cp++;
    uuid.node[i] = hextoul(buf, 2); 
  }

  uuid_pack(&uuid, uu);
  return 0;
}
