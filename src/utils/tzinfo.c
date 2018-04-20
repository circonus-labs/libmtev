/*
 * Copyright (c) 2018, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "libtz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>

struct tzzone {
  int offset;
  int8_t dst;
  int8_t idx;
  const char *name;
};

struct tzinfo {
  int leapcnt;
  int timecnt;
  int typecnt;
  int charcnt;
  int *trans_times;
  uint8_t *trans_types;
  char *strbuf;
  struct tzzone *tz, *normaltz;
  int *leap_secs;
};

#ifndef DEFAULT_ZONEINFO
#ifdef __sun
#define DEFAULT_ZONEINFO "/usr/share/lib/zoneinfo"
#else
#define DEFAULT_ZONEINFO "/usr/share/zoneinfo"
#endif
#endif
static const char *base_default = DEFAULT_ZONEINFO;
static char *base = NULL;

void libtz_setbase(const char *newbase) {
  if(base) free(base);
  base = strdup(newbase);
}

static int tzfile_open(const char *zonename) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", base ? base : base_default, zonename);
  int fd = open(path, O_RDONLY);
  return fd;
}

static void activate_zone(struct tzinfo *zi) {
  int n = 0;
  if(zi->typecnt == 0) return;
  while(n < zi->typecnt && zi->tz[n].dst) ++n;
  zi->normaltz = &zi->tz[n];
}

static int readInt(int fd, int *target) {
  if(read(fd, target, 4) != 4) return -1;
  *target = ntohl(*target);
  return 0;
}
#undef ERR
#define ERR(str) do { \
  if(err) *err = (str); \
  libtz_free_tzinfo(zi); \
  return NULL; \
} while(0)
static struct tzinfo *parse_tzfile(int fd, const char **err) {
  struct tzinfo *zi = calloc(1, sizeof(*zi));
  if(err) *err = NULL;
  if(fd < 0) ERR("bad file");
  char buf[5];
  if(read(fd, buf, 4) != 4) ERR("failure to read header");
  if(memcmp(buf, "TZif", 4)) ERR("invalid header");
  if(lseek(fd, 28, SEEK_SET) != 28) ERR("data missing");
  if(readInt(fd, &zi->leapcnt) != 0) ERR("missing leap cnt");
  if(readInt(fd, &zi->timecnt) != 0) ERR("missing time cnt");
  if(readInt(fd, &zi->typecnt) != 0) ERR("missing type cnt");
  if(readInt(fd, &zi->charcnt) != 0) ERR("missing char cnt");
  if(zi->timecnt < 1 || zi->timecnt > 10240) ERR("bad time cnt");
  if(zi->typecnt < 1 || zi->typecnt > 10240) ERR("bad type cnt");
  if(zi->leapcnt < 0 || zi->leapcnt > 10240) ERR("bad leap cnt");
  if(zi->charcnt < 1 || zi->charcnt > 256000) ERR("bad char cnt");
  zi->trans_times = calloc(zi->timecnt, sizeof(int));
  zi->trans_types = calloc(zi->timecnt, sizeof(int));
  zi->leap_secs = calloc(zi->leapcnt * 2, sizeof(int));
  zi->tz = calloc(zi->typecnt, sizeof(*zi->tz));
  int i;
  for(i=0; i<zi->timecnt; i++)
    if(readInt(fd, &zi->trans_times[i]) != 0) ERR("short file");
  for(i=0; i<zi->timecnt; i++) {
    if(read(fd, &zi->trans_types[i], 1) != 1) ERR("short file");
    if(zi->trans_types[i] >= zi->typecnt) ERR("bad data");
  }
  for(i=0; i<zi->typecnt; i++) {
    if(readInt(fd, &zi->tz[i].offset) != 0) ERR("short file");
    if(read(fd, &zi->tz[i].dst, 1) != 1) ERR("short file");
    if(read(fd, &zi->tz[i].idx, 1) != 1) ERR("short file");
  }
  zi->strbuf = malloc(zi->charcnt);
  if(read(fd, zi->strbuf, zi->charcnt) != zi->charcnt) ERR("short file");
  for(i=0; i<zi->typecnt; i++) {
    int pos = zi->tz[i].idx;
    int end = pos;
    if(pos >= zi->charcnt) ERR("malformed file");
    while(end < zi->charcnt && zi->strbuf[end] != 0) end++;
    if(zi->strbuf[end] != 0) ERR("malformed file");
    zi->tz[i].name = zi->strbuf + pos;
  }
  int leapcnt = zi->leapcnt;
  for(i=0; leapcnt > 0; --leapcnt) {
    if(readInt(fd, &zi->leap_secs[i++]) != 0) ERR("short file");
    if(readInt(fd, &zi->leap_secs[i++]) != 0) ERR("short file");
  }

  activate_zone(zi);
  return zi;
}

tzinfo_t *libtz_open(const char *zonename, const char **err) {
  tzinfo_t *zi;
  int fd = tzfile_open(zonename);
  if(fd < 0) {
    if(err) *err = "open failed";
    return NULL;
  }
  zi = parse_tzfile(fd, err);
  close(fd);
  return zi;
}

void libtz_free_tzinfo(struct tzinfo *zi) {
  free(zi->strbuf);
  free(zi->tz);
  free(zi->leap_secs);
  free(zi->trans_times);
  free(zi->trans_types);
  free(zi);
}

const char *
libtz_tzinfo_name(const tzinfo_t *zi) {
  if(!zi || !zi->normaltz) return NULL;
  return zi->normaltz->name;
}

const char *
libtz_tzzone_name(const tzzone_t *tz) {
  return tz ? tz->name : NULL;
}

int
libtz_tzzone_offset(const tzzone_t *tz) {
  return tz ? tz->offset : 0;
}
bool
libtz_tzzone_dst(const tzzone_t *tz) {
  return tz ? tz->dst : 0;
}

tzzone_t *libtz_tzzone_at(const tzinfo_t *zi, int64_t whence) {
  int l = 1, r = zi->timecnt;
  if(r == 0) return &zi->tz[0];
  int i = (l+r)/2;
  while(i > l) {
    if(l >= zi->timecnt) {
      i = zi->timecnt;
      break;
    }
    if(l == i) break;
    if(zi->trans_times[i] == whence) { i++; break; }
    else if(zi->trans_times[i] > whence) r = i-1;
    else l = i+1;
    i = (l+r)/2;
  }
  if(i > zi->timecnt) i = zi->timecnt;
  if(whence > zi->trans_times[i]) i++;
  return &zi->tz[zi->trans_types[i-1]];
}

struct tm *
libtz_zonetime(const tzinfo_t *zi, const time_t *timep, struct tm *result, const tzzone_t **tzr) {
  struct tm *rv;
  time_t whence;
  if(!zi) return NULL;
  whence = timep ? *timep : time(NULL);
  tzzone_t *tz = libtz_tzzone_at(zi, whence);
  if(!tz) return NULL;
  whence += tz->offset;
  rv = gmtime_r(&whence, result);
  if(!rv) return NULL;
  rv->tm_isdst = tz->dst;
  if(tzr) *tzr = tz;
  return rv;
}

size_t
libtz_strftime(char *buf, size_t buflen, const char *fmt, const struct tm *tm, const tzzone_t *tz) {
  char pfmt[2048];
  int in, out;
  for(in=0, out=0; fmt[in] != '\0' && out < sizeof(pfmt)-1;) {
    if(fmt[in] == '%') {
      if(fmt[in+1] == 'Z') {
        size_t len = snprintf(pfmt+out, sizeof(pfmt)-out, "%s", libtz_tzzone_name(tz));
        if(len < 0) return len;
        out += len;
        in += 2;
        continue;
      }
      else if(fmt[in+1] == 'z') {
        int offset = libtz_tzzone_offset(tz);
        int sign = offset >= 0 ? 1 : - 1;
        offset *= sign;
        int hours = offset / 3600;
        int minutes = (offset - 3600*hours) / 60;
        size_t len = snprintf(pfmt+out, sizeof(pfmt)-out, "%c%02d%02d", sign > 0 ? '+' : '-', hours, minutes);
        if(len < 0) return len;
        out += len;
        in += 2;
        continue;
      }
      else if(fmt[in+1] == '%') {
        pfmt[out++] = fmt[in++];
      }
    }
    pfmt[out++] = fmt[in++];
  }
  if(out >= sizeof(pfmt)) out = sizeof(pfmt)-1;
  pfmt[out] = '\0';
  return strftime(buf, buflen, pfmt, tm);
}
