describe("Api test", function()

 it("can perform GET requests", function()
    local port = "10124"
    local key_read = "read-" .. mtev.uuid()
    local key_listen = "listen-" .. mtev.uuid()
    mtev.coroutine_spawn(function()
        local e = mtev.socket('inet','tcp')
        assert(e)
        local err, errno = e:setsockopt("SO_REUSEADDR", 1)
        if err ~= 0 then error("Can't se REUSEADDR -> " .. errno) end
        local err, errno = e:bind('0.0.0.0', port)
        if err ~= 0 then error("binding error -> " .. errno) end
        local err, errno, msg = e:listen(2)
        if err ~= 0 then error("listen error -> " .. msg) end
        mtev.notify(key_listen, "listening")
        for i = 1,2 do
          local client = e:accept()
          client:write([[HTTP/1.0 200
Content-Type: text/plain

{ "msg" : "Hello World!" }]])
          client:close()
        end
        e:close()
        mtev.notify(key_listen)
    end)
    assert.truthy(mtev.waitfor(key_listen, 3))
    local api = mtev.Api:http("localhost", port)
    assert.same(api:get("/"):check():text(), [[{ "msg" : "Hello World!" }]])
    assert.same(api:get("/"):check():json(), { msg = "Hello World!" })
    assert.truthy(mtev.waitfor(key_listen, 3))
 end)

end)
