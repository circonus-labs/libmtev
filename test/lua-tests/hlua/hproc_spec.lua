describe("high level process management", function()

  it("can start processes", function()
    local p = mtev.Proc:new {
      path = "/bin/bash",
      argv = { "bash", "-c", [[printf "BASH HELLO\nOK\n" > /dev/stderr; exit 0]] },
      boot_match = "OK",
    }
    assert.is_true(p:start():ready())
    assert.is_true(p:wait())
  end)

  it("kills hung processes", function()
       local p = mtev.Proc:new {
         path = "/bin/bash",
         argv = { "bash", "-c", [[ sleep 1000 ]] },
         boot_timeout = .1,
       }
       assert.is_false(p:start():ready())
       assert.same(p:pid(), -1)
  end)

  it("kills processes", function()
       local p = mtev.Proc:new {
         path = "/bin/bash",
         argv = { "bash", "-c", [[ printf "OK\n" > /dev/stderr; sleep 1000 ]] },
         boot_match = "OK",
         boot_timeout = .1,
       }
       assert.is_true(p:start():ready())
       assert.is_true(p:kill())
  end)

  it("Waits for signals", function()
       local p = mtev.Proc:new {
         path = "/bin/bash",
         argv = { "bash", "-c", [[ printf "OK\n" > /dev/stderr; sleep .1; printf "XXX SIGNAL XXX\n" > /dev/stderr]] },
         boot_match = "OK",
       }
       local w = p:logwatch("SIGNAL", 1)
       assert.is_true(p:start():ready())
       assert.truthy(w:wait())
  end)

end)
