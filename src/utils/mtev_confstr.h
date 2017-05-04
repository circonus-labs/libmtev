/*
 * Copyright (c) 2016, Circonus, Inc. All rights reserved.
*/

#ifndef _MTEV_CONFSTR_H
#define _MTEV_CONFSTR_H

#include "mtev_defines.h"

typedef struct _mtev_duration_definition_t mtev_duration_definition_t;

/* return codes from mtev_confstr_parse routines */
#define MTEV_CONFSTR_PARSE_SUCCESS (0)
#define MTEV_CONFSTR_PARSE_ERR_UNREPRESENTABLE (-1)
#define MTEV_CONFSTR_PARSE_ERR_FORMAT (-2)

/*! \fn const mtev_duration_definition_t *mtev_get_durations_ns(void)
    \brief Return suffixes for nanosecond-resolution durations.

    Return value is suitable to pass as the second argument to
    mtev_confstr_parse_duration. Nanosecond-scale duration suffixes are:

    * `ns` (for nanoseconds);
    * `us` (for microseconds);
    * `ms` (for milliseconds);
    * `s` and `sec` (for seconds);
    * `min` (for minutes);
    * `hr` (for hours).
 */
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_ns(void);

/*! \fn const mtev_duration_definition_t *mtev_get_durations_us(void)
    \brief Return suffixes for microsecond-resolution durations.

    Return value is suitable to pass as the second argument to
    mtev_confstr_parse_duration. Microsecond-scale duration suffixes are:

    * `us` (for microseconds);
    * `ms` (for milliseconds);
    * `s` and `sec` (for seconds);
    * `min` (for minutes);
    * `hr` (for hours).
    * `d` (for days).
 */
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_us(void);

/*! \fn const mtev_duration_definition_t *mtev_get_durations_ms(void)
    \brief Return suffixes for millisecond-resolution durations.

    Return value is suitable to pass as the second argument to
    mtev_confstr_parse_duration. Millisecond-scale duration suffixes are:

    * `ms` (for milliseconds);
    * `s` and `sec` (for seconds);
    * `min` (for minutes);
    * `hr` (for hours).
    * `d` (for days).
    * `w` (for weeks).
 */
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_ms(void);

/*! \fn const mtev_duration_definition_t *mtev_get_durations_s(void)
    \brief Return suffixes for second-resolution durations.

    Return value is suitable to pass as the second argument to
    mtev_confstr_parse_duration. Second-scale duration suffixes are:

    * `s` and `sec` (for seconds);
    * `min` (for minutes);
    * `hr` (for hours).
    * `d` (for days).
    * `w` (for weeks).
 */
API_EXPORT(const mtev_duration_definition_t *) mtev_get_durations_s(void);

API_EXPORT(int)
  mtev_confstr_parse_boolean(const char *input, mtev_boolean *output);

/*! \fn int mtev_confstr_parse_duration(const char *input, uint64_t *output, const mtev_duration_definition_t *durations)
    \param `input` String representing a duration.
    \param `output` On successful parsing, filled in with the duration corresponding to `input`.
    \param `durations` Describes allowable duration suffixes when parsing.
    \return One of:
    * * MTEV_CONFSTR_PARSE_SUCCESS
        (`input` was parsed successfully, `output` filled in)
    * * MTEV_CONFSTR_PARSE_ERR_FORMAT (`input` was not well-formed.)

    Parses a string representing a duration. The string should be
    formatted as a set of (optionally) white-space separated duration
    elements, where a duration element is a number with a resolution
    suffix. For example, `"1s"` is a duration element representing one
    second, while `"3min"` is a duration element representing three
    minutes. The total duration is calculated by adding together all
    the duration elements. For example, `"1min 30sec"`, with
    resolution in seconds, would result in `output` of `90`; and
    `"1min5ms"`, at millisecond resolution, would result in `output`
    of `60005`.
 */
API_EXPORT(int)
  mtev_confstr_parse_duration(const char *input, uint64_t *output,
                              const mtev_duration_definition_t *durations);
API_EXPORT(int)
  mtev_confstr_parse_time_gm(const char *input, uint64_t *output);

/*! \fn int mtev_confstr_parse_duration_ns(const char *input, uint64_t *output)

    Convenience function for parsing a duration with resolution in nanoseconds.
    See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
    and <A HREF="#mtevgetdurationsns">mtev_get_durations_ns</A>.
 */
#define mtev_confstr_parse_duration_ns(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_ns())

/*! \fn int mtev_confstr_parse_duration_us(const char *input, uint64_t *output)

    Convenience function for parsing a duration with resolution in microseconds.
    See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
    and <A HREF="#mtevgetdurationsus">mtev_get_durations_us</A>.
 */
#define mtev_confstr_parse_duration_us(input, output) \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_us())

/*! \fn int mtev_confstr_parse_duration_ms(const char *input, uint64_t *output)

    Convenience function for parsing a duration with resolution in milliseconds.
    See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
    and <A HREF="#mtevgetdurationsms">mtev_get_durations_ms</A>.
 */
#define mtev_confstr_parse_duration_ms(input, output)                   \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_ms())

/*! \fn int mtev_confstr_parse_duration_s(const char *input, uint64_t *output)

    Convenience function for parsing a duration with resolution in seconds.
    See <A HREF="#mtevconfstrparseduration">mtev_confstr_parse_duration</A>
    and <A HREF="#mtevgetdurationss">mtev_get_durations_s</A>.
 */
#define mtev_confstr_parse_duration_s(input, output)                    \
  mtev_confstr_parse_duration(input, output, mtev_get_durations_s())

#endif
