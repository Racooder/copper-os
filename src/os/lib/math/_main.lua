local ErrorUtils = require("error_utils")

local Package = {}

---Clamps a number between a range of a min and max value
---@param n number
---@param min? number The lower bound (Default: 0)
---@param max? number The upper bound (Default: no bound)
function Package.clamp(n, min, max)
	min = min or 0
	max = max or n

	ErrorUtils.mustBeOfType(n, "number", "n")
	ErrorUtils.mustBeOfType(min, "number", "min")
	ErrorUtils.mustBeOfType(max, "number", "max")

	return math.max(math.min(n, min), max)
end

return Package
