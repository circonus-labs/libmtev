describe("semaphore tests", function()
           -- we (can) only tests semaphores between coros here, not between multiple lua states
           it("can gate access",
              function()
                local key = mtev.uuid()
                local A = 0 -- number of semaphore holders
                local hold_time = 0.01
                local slee_time = 0.001
                local n_coros = 50
                for i=1,n_coros do
                  mtev.coroutine_spawn(function()
                      local sem = mtev.semaphore("test", 3)
                      sem:acquire()
                      A = A + 1
                      local d = mtev.time() + hold_time
                      while mtev.time() < d do
                        assert(A <= 3)
                        mtev.sleep(sleep_time)
                      end
                      A = A - 1
                      sem:release()
                      assert(A <= 3)
                      mtev.notify(key)
                  end)
                end
                for i = 1,n_coros do
                  mtev.waitfor(key)
                end
              end
           )
end)
