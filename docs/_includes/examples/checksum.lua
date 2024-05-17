-- Checksum Example
local cNet = require "cNet"

local a = { a=1, b=2, c=3 }
local b = { a=1, b=2, c=3 }
if cNet.checksum(a) == cNet.checksum(b) then
    print("A and B are equal")
else
    print("A and B are different")
end
