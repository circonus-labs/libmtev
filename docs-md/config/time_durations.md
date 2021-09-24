# Time Durations

Many applications benefit from allowing operators to specify time durations in
human-readable form within configuration files, and libmtev provides a suite of
functions for parsing strings that represent a span of time into various
resolutions.

Duration strings are made up of individual elements, which take the form of an
integer with a resolution suffix, such as "1s" for one second, or "3min" for
three minutes. Multiple elements may be combined, with or without whitespace,
to represent the desired time period, for example, "1min 30sec", or "4w2d".

Developers may reference
[mtev_confstr_parse_duration](apireference/c.md##mtevconfstrparseduration) and
related convenience functions.

Note that parsed outputs are integers. Results with a fractional remainder will
be floored to the nearest integer. For example, `500ms` will be represented in
seconds as `0`.

## Duration Suffixes

* `ns`: nanoseconds
* `us`: microseconds
* `ms`: milliseconds
* `s`, `sec`, `second`, `seconds`: seconds
* `m`, `min`, `minute`, `minutes`: minutes
* `h`, `hr`, `hour`, `hours`: hours
* `d`, `day`, `days`: days
* `w`, `wk`, `week`, `weeks`: weeks

Longer time spans such as months and years should be represented as days and/or
weeks. These do not have suffixes because they do not represent a fixed number
of units (not all months have the same number of days, nor do all years).
