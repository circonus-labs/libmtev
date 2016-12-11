ffi.cdef([=[
  typedef enum { mtev_false = 0, mtev_true } mtev_boolean;
  typedef struct _mtev_duration_definition_t {
    const char *key;
    size_t key_len;
    uint64_t mul;
  } mtev_duration_definition_t;
  const mtev_duration_definition_t *mtev_get_durations_ns(void);
  const mtev_duration_definition_t *mtev_get_durations_us(void);
  const mtev_duration_definition_t *mtev_get_durations_ms(void);
  const mtev_duration_definition_t *mtev_get_durations_s(void);
  int mtev_confstr_parse_boolean(const char *input, mtev_boolean *output);
  int mtev_confstr_parse_duration(const char *input, uint64_t *output,
                                  const mtev_duration_definition_t *durations);
  int mtev_confstr_parse_time_gm(const char *input, uint64_t *output);
]=])

describe("mtev_confstr_parse_boolean", function()
  it("decodes \"true\" strings", function()
    local result = ffi.new("mtev_boolean[1]")
    assert.is_true(libmtev.mtev_confstr_parse_boolean("true", result) == 0)
    assert.are.equal(libmtev.mtev_true, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("TrUe", result) == 0)
    assert.are.equal(libmtev.mtev_true, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("yes", result) == 0)
    assert.are.equal(libmtev.mtev_true, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("on", result) == 0)
    assert.are.equal(libmtev.mtev_true, result[0]);
  end)
  it("decodes \"false\" strings", function()
    local result = ffi.new("mtev_boolean[1]")
    assert.is_true(libmtev.mtev_confstr_parse_boolean("false", result) == 0)
    assert.are.equal(libmtev.mtev_false, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("FaLsE", result) == 0)
    assert.are.equal(libmtev.mtev_false, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("no", result) == 0)
    assert.are.equal(libmtev.mtev_false, result[0]);
    assert.is_true(libmtev.mtev_confstr_parse_boolean("off", result) == 0)
    assert.are.equal(libmtev.mtev_false, result[0]);
  end)
  it("fails to decode invalid strings", function()
    local result = ffi.new("mtev_boolean[1]")
    assert.is_true(libmtev.mtev_confstr_parse_boolean("WAT!", result) ~= 0)
    assert.is_true(libmtev.mtev_confstr_parse_boolean("", result) ~= 0)
    assert.is_true(libmtev.mtev_confstr_parse_boolean("tru", result) ~= 0)
    assert.is_true(libmtev.mtev_confstr_parse_boolean("truee", result) ~= 0)
  end)
end)

describe("mtev_confstr_parse_duration", function()
  it("fails to decode empty", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("", result,
                                                    libmtev.mtev_get_durations_ms()) ~= 0)
  end)
  it("fails to decode unknown units", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1us", result,
                                                    libmtev.mtev_get_durations_ms()) ~= 0)
  end)
  it("fails to decode when no number before unit", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("ms", result,
                                                    libmtev.mtev_get_durations_ms()) ~= 0)
  end)
  it("decodes with ns units", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ns", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1us", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(1000 * 1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ms", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(1000 * 1000 * 1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1s", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(1000 * 1000 * 1000 * 1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1min", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(60 * 1000 * 1000 * 1000 * 1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1hr", result,
                                                    libmtev.mtev_get_durations_ns()) == 0)
    assert.are.equal(60 * 60 * 1000 * 1000 * 1000 * 1, result[0])
  end)
  it("decodes with ms units", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ms", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1s", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1min", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000 * 60, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1hr", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000 * 60 * 60, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1d", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000 * 60 * 60 * 24, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1w", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000 * 60 * 60 * 24 * 7, result[0])
  end)
  it("skips whitespace", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ms", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration(" 1ms", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ms ", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration(" 1ms ", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1, result[0])
  end)
  it("sums duration elements", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1s 1ms", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(1000 + 1, result[0])
    assert.is_true(libmtev.mtev_confstr_parse_duration("2s2ms", result,
                                                    libmtev.mtev_get_durations_ms()) == 0)
    assert.are.equal(2000 + 2, result[0])
  end)
  it("fails to decode with extra data", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_duration("1ms hello", result,
                                                    libmtev.mtev_get_durations_ms()) ~= 0)
  end)
end)

describe("mtev_confstr_parse_time_gm", function()
  it("parses unix epoch in GMT", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_time_gm("1970-01-01T00:00:00Z", result) == 0)
    assert.are.equal(0, result[0])
  end)
  it("parses unix epoch with positive offset", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_time_gm("1970-01-01T01:00:00+01:00", result) == 0)
    assert.are.equal(0, result[0])
  end)
  it("parses unix epoch with negative offset", function()
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_time_gm("1969-12-31T23:00:00-01:00", result) == 0)
    assert.are.equal(0, result[0])
  end)
  it("parses current time", function()
    local now = os.time()
    local date = os.date("!*t", now)
    local timestr =
      string.format("%04d-%02d-%02dT%02d:%02d:%02dZ",
                    date.year, date.month, date.day, date.hour, date.min, date.sec)
    local result = ffi.new("uint64_t[1]")
    assert.is_true(libmtev.mtev_confstr_parse_time_gm(timestr, result) == 0)
    assert.are.equal(now, result[0])
  end)
end)
