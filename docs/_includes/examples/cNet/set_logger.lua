-- Setting Logger Example
local cNet = require "cNet"

local function log(text)
    print("prefix " .. text)
end

cNet.setLogger(log)