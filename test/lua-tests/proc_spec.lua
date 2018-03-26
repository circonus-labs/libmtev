describe("process management", function()

  it("waits", function()
    local proc = mtev.spawn("/bin/sleep", { "sleep", "1" })
    local status, errno = proc:wait(2)
    assert.is_true(mtev.WIFEXITED(status))
    assert.is_equal(0, mtev.WEXITSTATUS(status))
  end)

  it("times out", function()
    local proc = mtev.spawn("/bin/sleep", { "sleep", "10" })
    local start = mtev.timeval.now()
    local status, errno = proc:wait(1)
    local elapsed = mtev.timeval.now() - start
    assert.is_nil(status)
    assert.is_true(mtev.timeval.seconds(elapsed) < 1.5)
    proc:kill(9)
    status, errno = proc:wait(1)
    assert.is_false(mtev.WIFEXITED(status))
    assert.is_true(mtev.WIFSIGNALED(status))
    assert.is_equal("Killed", strsignal(mtev.WTERMSIG(status)))
  end)

  it("errors", function()
    local proc = mtev.spawn("/bin/nopenope")
    local status, errno = proc:wait(1)
    assert.is_not_nil(status)
    assert.is_nil(errno)
    assert.is_true(mtev.WIFEXITED(status))
    -- "127" is what you get when you try to execute a
    -- process that doesn't exist
    assert.is_equal(127, mtev.WEXITSTATUS(status))
  end)

  it("fails", function()
    local proc = mtev.spawn("/bin/false")
    local status, errno = proc:wait(1)
    assert.is_true(mtev.WIFEXITED(status))
    assert.is_not_equal(0, mtev.WEXITSTATUS(status))
  end)

  it("succeeds", function()
    local proc = mtev.spawn("/bin/true")
    local status, errno = proc:wait(1)
    assert.is_true(mtev.WIFEXITED(status))
    assert.is_equal(0, mtev.WEXITSTATUS(status))
  end)

end)
