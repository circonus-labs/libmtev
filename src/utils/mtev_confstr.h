/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
*/

#ifndef _MTEV_CONFSTR_H
#define _MTEV_CONFSTR_H

#include "mtev_defines.h"

typedef struct _mtev_duration_definition_t mtev_duration_definition_t;

API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_ns(void);
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_us(void);
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_ms(void);
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_s(void);

API_EXPORT(int)
  mtev_confstr_parse_boolean(const char *input, mtev_boolean *output);
API_EXPORT(int)
  mtev_confstr_parse_duration(const char *input, u_int64_t *output,
                              const mtev_duration_definition_t *durations);

#define mtev_confstr_parse_duration_ns(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_ns())
#define mtev_confstr_parse_duration_us(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_us())
#define mtev_confstr_parse_duration_ms(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_ms())
#define mtev_confstr_parse_duration_s(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_s())

#endif
