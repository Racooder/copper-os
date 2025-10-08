local ErrorUtils = require("error_utils")

local Package = {}

--- Splits a string into a table of substrings based on a given pattern.
--- @param str string The string to split.
--- @param pattern string The pattern to use for splitting the string.
function Package.split(str, pattern)
	ErrorUtils.mustBeOfType(str, "string", "str")
	ErrorUtils.mustBeOfType(pattern, "string", "separator")

	local substrings = {}
	for s in str:gmatch(pattern) do
		table.insert(substrings, s)
	end
	return substrings
end

return Package
