local ErrorUtil = require("error")
local MathUtil = require("math")
local PathUtil = require("path")
local StringUtil = require("string")
local TableUtil = require("table")

local Package = {
    Error = ErrorUtil,
    Math = MathUtil,
    Path = PathUtil,
    String = StringUtil,
    Table = TableUtil,
}

return Package
