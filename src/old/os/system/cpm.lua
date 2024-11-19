---The copper OS import function
---@param name string
---@param version? integer
---@return any - The imported library
function _G.import(name, version)
    local versionQuery = version and tostring(version) or "*"
    local versions = fs.find("/libs/" .. name .. "@" .. versionQuery ..".lua")
    if versionQuery == "*" and #versions == 0 then
        error("No version of " .. name .. " found")
    elseif #versions == 0 then
        error("Version" .. versionQuery .. " of " .. name .. " not found")
    end
    return dofile(versions[#versions])
end
