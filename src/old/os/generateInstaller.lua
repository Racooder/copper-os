local LibDeflate = require("LibDeflate")

local function getSystemTable()
    local systemTable = {}
    local startupFile = fs.open("/startup.lua", "r")
    systemTable["startup.lua"] = startupFile.readAll()
    startupFile.close()
    return systemTable
end

local systemTable = textutils.serialise(getSystemTable())
local compressedTable = LibDeflate:CompressGzip(systemTable, {level = 9})

local installer = "local compressedSystem = '" .. compressedTable .. "'"
installer = installer .. fs.open("/installerTemplate.lua", "r").readAll()

fs.open("/installer.lua", "w").write(installer)
