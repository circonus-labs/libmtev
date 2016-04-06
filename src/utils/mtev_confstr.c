#include "mtev_confstr.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define DURATION_US_MUL(NS_BASE) (((u_int64_t) 1000) * DURATION_ ## NS_BASE ## _NS)
#define DURATION_MS_MUL(US_BASE) (((u_int64_t) 1000) * DURATION_ ## US_BASE ## _US)
#define DURATION_SEC_MUL(MS_BASE) (((u_int64_t) 1000) * DURATION_ ## MS_BASE ## _MS)
#define DURATION_MIN_MUL(SEC_BASE) (((u_int64_t) 60) * DURATION_ ## SEC_BASE ## _SEC)
#define DURATION_HR_MUL(MIN_BASE) (((u_int64_t) 60) * DURATION_ ## MIN_BASE ## _MIN)
#define DURATION_DAY_MUL(HR_BASE) (((u_int64_t) 24) * DURATION_ ## HR_BASE ## _HR)
#define DURATION_WEEK_MUL(DAY_BASE) (((u_int64_t) 7) * DURATION_ ## DAY_BASE ## _DAY)

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
  { "min", 3, DURATION_ ## BASE ## _MIN }
#define DURATION_DECL_HR(BASE) \
  { "hr", 2, DURATION_ ## BASE ## _HR }
#define DURATION_DECL_DAY(BASE) \
  { "d", 1, DURATION_ ## BASE ## _DAY }
#define DURATION_DECL_WEEK(BASE) \
  { "w", 1, DURATION_ ## BASE ## _WEEK }

struct _mtev_duration_definition_t {
  const char *key;
  size_t key_len;
  u_int64_t mul;
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
    return 1;
  }
  if(!strcasecmp(input, "no") || !strcasecmp(input, "false") || !strcasecmp(input, "off")) {
    *output = mtev_false;
    return 1;
  }
  return 0;
}

/* sum of <number><unit> tokens, separated by spaces */
int
mtev_confstr_parse_duration(const char *input, u_int64_t *output,
                            const mtev_duration_definition_t *durations) {
  unsigned long rd;
  const char *unit_str;
  int success = 0;
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
      return 0;
    rd = strtoul(input, (char **) &unit_str, 10);
    if(unit_str == input)
      return 0;

    /* unit string */
    input = unit_str;
    while(*input && isalpha(*input))
      input++;
    if(input == unit_str)
      return 0;

    /* find multiplier attached to unit string. */
    for(duration_idx=0;
        durations[duration_idx].key != 0 &&
          (input - unit_str != durations[duration_idx].key_len ||
           memcmp(unit_str, durations[duration_idx].key, input - unit_str));
        duration_idx++) {
    }
    if(! durations[duration_idx].key)
      return 0;

    /* hooray! at least one component parsed successfully. */
    success = 1;
    (*output) += ((u_int64_t) rd) * durations[duration_idx].mul;
  }
  return success;
}
