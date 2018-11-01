describe("coro tear harness", function()

  it("20 coros", function()
    local cnt = 0
    for j = 1,10 do
      mtev.coroutine_spawn(function()
        for i = 1,1000 do
          mtev.sleep(0)
          cnt = cnt + 1
        end
        if cnt == 20000 then mtev.notify("done") end
        mtev.coroutine_spawn(function()
          for i = 1,1000 do
            mtev.sleep(0)
            cnt = cnt + 1
          end
          if cnt == 20000 then mtev.notify("done") end
        end)
      end)
    end
    mtev.waitfor("done", 10)
    assert.is_equal(20000, cnt)
  end)

  it("2000 coros", function()
    local cnt = 0
    for j = 1,1000 do
      mtev.coroutine_spawn(function()
        local key, v = mtev.waitfor("test-" .. j)
        cnt = cnt + v
        if cnt == 1000 then mtev.notify("done", "success") end
      end)
    end
    for j = 1,1000 do
      mtev.coroutine_spawn(function()
        mtev.notify("test-" .. j, 1)
      end)
    end
    local key, success = mtev.waitfor("done", 10)
    assert.is_equal("done", key)
    assert.is_equal("success", success)
  end)

end)
