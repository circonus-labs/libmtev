describe("test timezones", function()

  it("Can use US/Eastern", function()
    local zi = mtev.timezone("US/Eastern")
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
