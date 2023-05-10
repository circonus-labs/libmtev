local mtev = mtev

describe("crypto", function()

  it("return random bytes", function()
    local rand = mtev.rand_bytes(128)
    assert.is_not_nil(rand)
  end)

  it("return pseudo-random bytes", function()
    local prand = mtev.pseudo_rand_bytes(128)
    assert.is_not_nil(prand)
  end)

  it("create new RSA key", function()
    local rsa = mtev.newrsa()
    assert.is_not_nil(rsa:pem())
  end)

  it("create new 3072-bit RSA key", function()
    local rsa = mtev.newrsa(3072)
    assert.is_not_nil(rsa:pem())
  end)

  it("read RSA key from file", function()
    local keyfile = "crypto-support/test_private_key.pem"
    local inp = io.open(keyfile, "rb")
    assert.is_not_nil(inp)
    local keydata = inp:read("*all")
    inp:close()
    local key = mtev.newrsa(keydata)
    assert.is_not_nil(key)
  end)

  it("create new CSR", function()
    local keyfile = "crypto-support/test_private_key.pem"
    local inp = io.open(keyfile, "rb")
    assert.is_not_nil(inp)
    local keydata = inp:read("*all")
    inp:close()
    local key = mtev.newrsa(keydata)
    assert.is_not_nil(key)

    local subj = { C="US", ST="Pennsylvania", O="libmtev", CN="test" }
    local req = key:gencsr({ subject=subj })
    assert.is_not_nil(req)
  end)
end)
