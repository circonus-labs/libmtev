module(..., package.seeall)

function disable_compression(ctx)
  local req = ctx:request()
  -- Get the request and zero out gzip and deflate
  -- (it's like forcibly "undetecting" any accept-encoding that was sent)
  req:opts(bit.band(req:opts(), bit.bnot(bit.bor(ctx.GZIP, ctx.DEFLATE))))
end
