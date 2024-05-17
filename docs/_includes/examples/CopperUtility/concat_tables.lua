-- Table Concatenation Example
local utility = require "CopperUtility"

local t1 = {"a", "b", "c"}
local t2 = {"d", "e", "f"}

utility.concatTables(t1, t2)
>> {"a", "b", "c", "d", "e", "f"}
