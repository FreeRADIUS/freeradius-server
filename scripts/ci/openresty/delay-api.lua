-- Simple API represending a slow response for testing timeouts

local t0 = os.clock()
while os.clock() - t0 <= 2 do end

ngx.say("Delayed response")
