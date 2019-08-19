#include "mtev_confstr.h"
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define DURATION_US_MUL(NS_BASE) (((uint64_t) 1000) * DURATION_ ## NS_BASE ## _NS)
#define DURATION_MS_MUL(US_BASE) (((uint64_t) 1000) * DURATION_ ## US_BASE ## _US)
#define DURATION_SEC_MUL(MS_BASE) (((uint64_t) 1000) * DURATION_ ## MS_BASE ## _MS)
#define DURATION_MIN_MUL(SEC_BASE) (((uint64_t) 60) * DURATION_ ## SEC_BASE ## _SEC)
#define DURATION_HR_MUL(MIN_BASE) (((uint64_t) 60) * DURATION_ ## MIN_BASE ## _MIN)
#define DURATION_DAY_MUL(HR_BASE) (((uint64_t) 24) * DURATION_ ## HR_BASE ## _HR)
#define DURATION_WEEK_MUL(DAY_BASE) (((uint64_t) 7) * DURATION_ ## DAY_BASE ## _DAY)

#define DURATION_NS_NS 1
#define DURATION_NS_US DURATION_US_MUL(NS)
#define DURATION_NS_MS DURATION_MS_MUL(NS)
#define DURATION_NS_SEC DURATION_SEC_MUL(NS)
#define DURATION_NS_MIN DURATION_MIN_MUL(NS)
#define DURATION_NS_HR DURATION_HR_MUL(NS)

#define DURATION_US_US 1
#define DURATION_US_MS DURATION_MS_MUL(US)
#define DURATION_US_SEC DURATION_SEC_MUL(US)
#define DURATION_US_MIN DURATION_MIN_MUL(US)
#define DURATION_US_HR DURATION_HR_MUL(US)
#define DURATION_US_DAY DURATION_DAY_MUL(US)

#define DURATION_MS_MS 1
#define DURATION_MS_SEC DURATION_SEC_MUL(MS)
#define DURATION_MS_MIN DURATION_MIN_MUL(MS)
#define DURATION_MS_HR DURATION_HR_MUL(MS)
#define DURATION_MS_DAY DURATION_DAY_MUL(MS)
#define DURATION_MS_WEEK DURATION_WEEK_MUL(MS)

#define DURATION_SEC_SEC 1
#define DURATION_SEC_MIN DURATION_MIN_MUL(SEC)
#define DURATION_SEC_HR DURATION_HR_MUL(SEC)
#define DURATION_SEC_DAY DURATION_DAY_MUL(SEC)
#define DURATION_SEC_WEEK DURATION_WEEK_MUL(SEC)

#define DURATION_DECL_NS(BASE)                  \
  { "ns", 2, DURATION_ ## BASE ## _NS }
#define DURATION_DECL_US(BASE) \
  { "us", 2, DURATION_ ## BASE ## _US }
#define DURATION_DECL_MS(BASE) \
  { "ms", 2, DURATION_ ## BASE ## _MS }
#define DURATION_DECL_SEC(BASE) \
  { "s", 1, DURATION_ ## BASE ## _SEC }, \
  { "sec", 3, DURATION_ ## BASE ## _SEC }
#define DURATION_DECL_MIN(BASE) \
  { "m", 1, DURATION_ ## BASE ## _MIN }, \
  { "min", 3, DURATION_ ## BASE ## _MIN }
#define DURATION_DECL_HR(BASE) \
  { "h", 1, DURATION_ ## BASE ## _HR }, \
  { "hr", 2, DURATION_ ## BASE ## _HR }, \
  { "hour", 4, DURATION_ ## BASE ## _HR }
#define DURATION_DECL_DAY(BASE) \
  { "d", 1, DURATION_ ## BASE ## _DAY }, \
  { "day", 3, DURATION_ ## BASE ## _DAY }
#define DURATION_DECL_WEEK(BASE) \
  { "w", 1, DURATION_ ## BASE ## _WEEK }, \
  { "wk", 2, DURATION_ ## BASE ## _WEEK }, \
  { "week", 4, DURATION_ ## BASE ## _WEEK }

struct _mtev_duration_definition_t {
  const char *key;
  size_t key_len;
  uint64_t mul;
};

static const mtev_duration_definition_t mtev_duration_definition_ns[] =
{
  DURATION_DECL_NS(NS),
  DURATION_DECL_US(NS),
  DURATION_DECL_MS(NS),
  DURATION_DECL_SEC(NS),
  DURATION_DECL_MIN(NS),
  DURATION_DECL_HR(NS),
  { 0, 0, 0 },
};

static const mtev_duration_definition_t mtev_duration_definition_us[] =
{
  DURATION_DECL_US(US),
  DURATION_DECL_MS(US),
  DURATION_DECL_SEC(US),
  DURATION_DECL_MIN(US),
  DURATION_DECL_HR(US),
  DURATION_DECL_DAY(US),
  { 0, 0, 0 },
};

static const mtev_duration_definition_t mtev_duration_definition_ms[] =
{
  DURATION_DECL_MS(MS),
  DURATION_DECL_SEC(MS),
  DURATION_DECL_MIN(MS),
  DURATION_DECL_HR(MS),
  DURATION_DECL_DAY(MS),
  DURATION_DECL_WEEK(MS),
  { 0, 0, 0 },
};

static const mtev_duration_definition_t mtev_duration_definition_s[] =
{
  DURATION_DECL_SEC(SEC),
  DURATION_DECL_MIN(SEC),
  DURATION_DECL_HR(SEC),
  DURATION_DECL_DAY(SEC),
  DURATION_DECL_WEEK(SEC),
  { 0, 0, 0 },
};

const mtev_duration_definition_t *mtev_get_durations_ns(void) {
  return mtev_duration_definition_ns;
}
const mtev_duration_definition_t *mtev_get_durations_us(void) {
  return mtev_duration_definition_us;
}
const mtev_duration_definition_t *mtev_get_durations_ms(void) {
  return mtev_duration_definition_ms;
}
const mtev_duration_definition_t *mtev_get_durations_s(void) {
  return mtev_duration_definition_s;
}

int
mtev_confstr_parse_boolean(const char *input, mtev_boolean *output) {
  if(!strcasecmp(input, "yes") || !strcasecmp(input, "true") || !strcasecmp(input, "on")) {
    *output = mtev_true;
    return MTEV_CONFSTR_PARSE_SUCCESS;
  }
  if(!strcasecmp(input, "no") || !strcasecmp(input, "false") || !strcasecmp(input, "off")) {
    *output = mtev_false;
    return MTEV_CONFSTR_PARSE_SUCCESS;
  }
  return MTEV_CONFSTR_PARSE_ERR_FORMAT;
}

/* sum of <number><unit> tokens, separated by spaces */
int
mtev_confstr_parse_duration(const char *input, uint64_t *output,
                            const mtev_duration_definition_t *durations) {
  unsigned long rd;
  const char *unit_str;
  int success = MTEV_CONFSTR_PARSE_ERR_FORMAT;
  int duration_idx;

  *output = 0;
  while(true) {
    /* white-space separated, null-terminated */
    while(*input && isspace(*input))
      input++;
    if(! *input)
      break;

    /* number */
    if(!isdigit(*input))
      return MTEV_CONFSTR_PARSE_ERR_FORMAT;
    rd = strtoul(input, (char **) &unit_str, 10);
    if(unit_str == input)
      return MTEV_CONFSTR_PARSE_ERR_FORMAT;

    /* unit string */
    input = unit_str;
    while(*input && isalpha(*input))
      input++;
    if(input == unit_str)
      return MTEV_CONFSTR_PARSE_ERR_FORMAT;

    /* find multiplier attached to unit string. */
    for(duration_idx=0;
        durations[duration_idx].key != 0 &&
          (input - unit_str != (ssize_t)durations[duration_idx].key_len ||
           memcmp(unit_str, durations[duration_idx].key, input - unit_str));
        duration_idx++) {
    }
    if(! durations[duration_idx].key)
      return MTEV_CONFSTR_PARSE_ERR_FORMAT;

    /* hooray! at least one component parsed successfully. */
    success = MTEV_CONFSTR_PARSE_SUCCESS;
    (*output) += ((uint64_t) rd) * durations[duration_idx].mul;
  }
  return success;
}

static mtev_boolean
is_valid_date(int year, int month, int day)
{
  int max_days;

  if(year < 0 || month < 0 || month > 11 || day < 1 || day > 31)
    return mtev_false;
  max_days = 31;
  switch(month)
  {
    case 1:
      max_days = 28;
      if((year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0)))
        max_days++;
      break;
    case 3:
    case 5:
    case 8:
    case 10:
      max_days = 30;
      break;
  }
  if(day > max_days)
    return mtev_false;
  return mtev_true;
}

static mtev_boolean
is_valid_time(int hour, int minute, int second)
{
  if(hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59)
    return mtev_false;
  return mtev_true;
}

/* borrowed from
 * http://www.catb.org/esr/time-programming/#_mktime_3_timelocal_3_timegm_3.
 * I don't want to deal with autoconf checking for timegm, and I don't
 * know for sure if all `timegm` implementations will expect all
 * `struct tm` fields to be filled in correctly.  Modified to return
 * uint64_t instead of time_t (time_t is 32-bit on some old
 * platforms) so that I don't need to worry about overflow from our
 * multiplications in the date ranges we're passed, and also to assume
 * that year, month, day, hour, minute, and second are all in valid
 * ranges. */
static int64_t
mtev_timegm(struct tm *t)
{
  long year;
  int64_t result;
#define MONTHSPERYEAR   12      /* months per calendar year */
  static const int cumdays[MONTHSPERYEAR] =
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

  year = 1900 + t->tm_year;
  result = (year - 1970) * 365 + cumdays[t->tm_mon];
  result += (year - 1968) / 4;
  result -= (year - 1900) / 100;
  result += (year - 1600) / 400;
  if((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) && t->tm_mon < 2)
    result--;
  result += t->tm_mday - 1;
  result *= 24;
  result += t->tm_hour;
  result *= 60;
  result += t->tm_min;
  result *= 60;
  result += t->tm_sec;
  return (result);
}

/* parses rfc3339 date-times. */
/* (year)-(month)-(day)T(hour):(minute):(second)(Z|[+-](offset)). */
int
mtev_confstr_parse_time_gm(const char *input, uint64_t *output)
{
  char *iter;
  char tzchr;
  int64_t base_time;
  int64_t tz_offset = 0;
  /* using different struct tm's since `strptime` can zero its input
   * argument on fields not included in the format. we'll union them
   * all at the end. */
  struct tm construct_date;
  struct tm construct_time;
  struct tm construct_tzoffs;

  iter = strptime(input, "%Y-%m-%d", &construct_date);
  if(! iter || toupper(*iter) != 'T')
    return MTEV_CONFSTR_PARSE_ERR_FORMAT;

  if(! is_valid_date(construct_date.tm_year, construct_date.tm_mon, construct_date.tm_mday))
    return MTEV_CONFSTR_PARSE_ERR_FORMAT;

  input = iter+1;
  iter = strptime(input, "%T", &construct_time);
  if(! iter)
    return MTEV_CONFSTR_PARSE_ERR_FORMAT;
  if(! is_valid_time(construct_time.tm_hour, construct_time.tm_min, construct_time.tm_sec))
    return MTEV_CONFSTR_PARSE_ERR_FORMAT;

  tzchr = *iter;
  input = iter+1;
  switch(tzchr)
  {
    case '-':
    case '+':
      iter = strptime(input, "%R", &construct_tzoffs);
      if(! iter)
        return MTEV_CONFSTR_PARSE_ERR_FORMAT;
      if(! is_valid_time(construct_tzoffs.tm_hour, construct_tzoffs.tm_min, 0))
        return MTEV_CONFSTR_PARSE_ERR_FORMAT;
      input = iter;
      tz_offset = ((int64_t) construct_tzoffs.tm_hour * 60 + construct_tzoffs.tm_min) * 60;
      if(tzchr == '-')
        tz_offset *= -1;
      break;
    case 'z':
    case 'Z':
      break;
    default:
      return MTEV_CONFSTR_PARSE_ERR_FORMAT;
  }
  if(*input)
    return MTEV_CONFSTR_PARSE_ERR_FORMAT;

  construct_date.tm_hour = construct_time.tm_hour;
  construct_date.tm_min = construct_time.tm_min;
  construct_date.tm_sec = construct_time.tm_sec;
  base_time = mtev_timegm(&construct_date);
  base_time -= tz_offset;
  if(base_time < 0)
    return MTEV_CONFSTR_PARSE_ERR_UNREPRESENTABLE;

  *output = base_time;
  return MTEV_CONFSTR_PARSE_SUCCESS;
}
