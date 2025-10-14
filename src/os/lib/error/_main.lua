local Package = {}

---Throws an error if `v` is not of type `t`.
---Supports all native lua types and `"integer"`
---@param v any
---@param t string
---@param name string The name of the variable (used in the error message)
---@param level? integer (default = 2)
function Package.mustBeOfType(v, t, name, level)
    level = level or 2

    if t ~= "nil" and t ~= "number" and t ~= "string" and t ~= "boolean" and t ~= "table" and t ~= "function" and t ~= "thread" and t ~= "userdata" and t ~= "integer" then
        error("t must be a valid lua type or \"integer\"", 2)
    end
    if type(name) ~= "string" then
        error("name must be of type string but was " .. type(name), 2)
    end
    if type(level) ~= "number" or math.floor(level) ~= level then
        error("level must be an integer", 2)
    end

    if t == "integer" then
        if type(v) ~= "number" or math.floor(v) ~= v then
            error(name .. " must be an integer", level + 1)
        end
    elseif type(v) ~= t then
        error(name .. " must be of type " .. t .. " but was " .. type(v), level + 1)
    end
end

---Throws an error if `valid` does not contain `v`.
---@param v any
---@param valid any[]
---@param name string The name of the variable (used in the error message)
---@param level? integer (default = 2)
function Package.mustBeOneOf(v, valid, name, level)
    for _, value in ipairs(valid) do
        if value == v then
            return
        end
    end
    error(name .. " must be one of the following values: " .. textutils.serialise(valid))
end

return Package
