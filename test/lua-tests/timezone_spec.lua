describe("test timezones", function()

  it("Can use UTC", function()
    local zi = mtev.timezone("UTC")
    assert.is_not_nil(zi)
    local now = os.time()
    local hour = math.floor(now / 3600) % 24
    local uhour = zi:extract(now, 'hour')
    assert.are.equal(hour, uhour)
  end)

  it("Can use America/New_York", function()
    local zi = mtev.timezone("America/New_York")
    assert.is_not_nil(zi)
    local month, hour, year, dst, zonename =
      zi:extract(1520197275, 'month', 'hour', 'year', 'dst', 'zonename') -- Sun Mar  4 21:01:15 2018 UTC 
    assert.are.equal(month, 3)
    assert.are.equal(hour, 16)
    assert.are.equal(year, 2018)
    assert.are.equal(dst, false)
    assert.are.equal(zonename, "EST")
  end)

  it("Fails to load bad zone", function()
    assert.error(function() mtev.timezone("DC/Gotham_City") end)
  end)
end)
