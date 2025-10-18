local ErrorUtil = require("error")
local MathUtil = require("math")
local StringUtil = require("string")
local TableUtil = require("table")

local Package = {
    Error = ErrorUtil,
    Math = MathUtil,
    String = StringUtil,
    Table = TableUtil,
}

return Package
