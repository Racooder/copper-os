local ErrorUtil = require("error")

local Package = {}

---Clamps a number between a range of a min and max value
---@param n number
---@param min? number The lower bound (Default: 0)
---@param max? number The upper bound (Default: no bound)
function Package.clamp(n, min, max)
    min = min or 0
    max = max or n

    ErrorUtil.must_be_of_type(n, "number", "n")
    ErrorUtil.must_be_of_type(min, "number", "min")
    ErrorUtil.must_be_of_type(max, "number", "max")

    return math.max(math.min(n, min), max)
end

---Wraps a number around a range of a min and max value
---@param n number
---@param min? number The lower bound (Default: 0)
---@param max? number The upper bound (Default: n)
function Package.wrap(n, min, max)
    min = min or 0
    max = max or n

    ErrorUtil.must_be_of_type(n, "number", "n")
    ErrorUtil.must_be_of_type(min, "number", "min")
    ErrorUtil.must_be_of_type(max, "number", "max")
    ErrorUtil.must_be_greater(max, min, "max")

    local range = max - min + 1
    return ((n - min) % range) + min
end

return Package
