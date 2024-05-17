-- Split by Chunk Example
local utility = require "CopperUtility"

utility.splitByChunk("Hello, World!", 3)
-->> {"Hel", "lo,", " Wo", "rld", "!"}