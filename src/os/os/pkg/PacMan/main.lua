-- * Helper Functions

local function packagePath(packageId)
    return "/os/pkg/" .. packageId
end

-- * PackageManager

local PackageManager = {}

---Check if a package exists
---@param packageId string
---@return boolean exists
function PackageManager.exists(packageId)
    return fs.exists(packagePath(packageId))
end

---List all installed packages
---@return string[] packageIds
function PackageManager.list()
    return fs.list("/os/pkg")
end

---Get the meta data of a package
---@param packageId string
---@return PackageMeta|nil meta
function PackageManager.getMeta(packageId)
    if not PackageManager.exists(packageId) then
        return nil
    end
    local metaFile = fs.open(packagePath(packageId) .. "/meta.json", "r")
    local meta = textutils.unserialize(metaFile.readAll())
    metaFile.close()
    return meta
end

---Get the type of a package
---@param packageId string
---@return string|nil type
function PackageManager.getType(packageId)
    return PackageManager.getMeta(packageId).type
end

---Install a package
---@param packageId string
---@return boolean success
function PackageManager.install(packageId)
    -- TODO: Implement
    return false
end

---Delete a package
---@param packageId string
---@return boolean success
function PackageManager.delete(packageId)
    if not PackageManager.exists(packageId) then
        return false
    end
    fs.delete(packagePath(packageId))
    return true
end

return PackageManager

-- * Class Definitions

---@class PackageMeta
---@field title string
---@field type string
---@field dependencies string[]
