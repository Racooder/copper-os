local ErrorUtil = require("util.error")
local System = require("system")

---@param path string
return function(path)
    ErrorUtil.must_be_of_type(path, "string", "path")

    if (path:sub(1, 2) == "~/") then
        return System.get_home_path() .. path:sub(2, -1)
    end
    return path
end
