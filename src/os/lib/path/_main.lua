local ErrorUtils = require("error")

local HOME_PATH = "/home"

---@param path string
return function(path)
	ErrorUtils.mustBeOfType(path, "string", "path")

	if (path:sub(1, 2) == "~/") then
		return HOME_PATH .. path:sub(2, -1)
	end
	return path
end
