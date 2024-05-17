-- String Splitting Example
local utility = require "CopperUtility"

utility.splitString("string, seperated, by, seperators", ", ")
>> {"string", "seperated", "by", "seperators"}