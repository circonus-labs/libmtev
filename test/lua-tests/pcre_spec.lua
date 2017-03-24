describe("pcre testing", function()

  it("should match something", function()
    assert.is_not_nil(mtev.pcre(".")("hello"))
  end)

  it("should match several things globally", function()
    local matcher = mtev.pcre("(a)b")
    local string = "abababa"
    local cnt = 0
    local rv, m, p1
    for _=1,3 do
      rv, m, p1 = matcher(string)
      assert.is_equal(p1,"a")
    end
    assert.is_false(matcher(string))
  end)

  it("should reset on variable change", function()
    local matcher = mtev.pcre("(a)b")
    for i=1,10 do
      local string = "abababa" .. i
      local cnt = 0
      local rv, m, p1
      for _=1,3 do
        rv, m, p1 = matcher(string)
        assert.is_equal(p1,"a")
      end
      assert.is_false(matcher(string))
    end
  end)

  it("should reset", function()
    local matcher = mtev.pcre("(a)b")
    local string = "ababa"
    local cnt = 0
    local rv, m, p1
    assert.is_true(matcher(string))
    assert.is_true(matcher(string))
    assert.is_false(matcher(string))
    matcher(nil)
    assert.is_true(matcher(string))
    assert.is_true(matcher(string))
    assert.is_false(matcher(string))
  end)

end)
