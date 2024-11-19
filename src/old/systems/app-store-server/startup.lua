local cNet = require "cNet"
local logger = require "copperLogger"

--* Logging

logger.logToMonitor(0.5, "monitor_10")
logger.setPrefix("[AS] ")
cNet.setLogger(logger.logInColumns)

--* Downloading

local appPaths = {}

local function isValidId(id)
    return string.match(id, "^[%da-zA-Z_-]+$") ~= nil
end

---Gets the path to the app
---@param id string
---@return string|nil
local function getAppPath(id)
    if appPaths[id] == nil then
        local f = fs.find("disk*/" .. id)
        if #f == 0 then
            return nil
        end
        appPaths[id] = f[1]
    end
    return appPaths[id]
end

---Gets the content of a file in the app
---@param id string The id of the app
---@param file string The path to the file
---@return string|nil
local function getAppFile(id, file)
    local path = getAppPath(id)
    if path == nil then
        return nil
    end
    if not fs.exists(path .. "/" .. file) then
        return nil
    end
    if fs.isDir(path .. "/" .. file) then
        return nil
    end
    return fs.open(path .. "/" .. file, "r").readAll()
end

--* Rest API
cNet.setRestApi("GET", "/app", function (args, header, data, socket)
    local id = args[1]

    if not isValidId(id) then
        return cNet.CttpResponse:new(cNet.CttpStatus.BAD_REQUEST)
    end
    local metaString = getAppFile(id, "app.meta")
    if metaString == nil then
        return cNet.CttpResponse:new(cNet.CttpStatus.NOT_FOUND)
    end
    local meta = textutils.unserialise(metaString)
    if type(meta) ~= "table" then
        return cNet.CttpResponse:new(cNet.CttpStatus.INTERNAL_SERVER_ERROR)
    end
    return cNet.CttpResponse:new(cNet.CttpStatus.OK, nil, meta)
end)

cNet.setRestApi("GET", "/file", function (args, header, data, socket)
    local id = args[1]
    local file = args[2]

    if not isValidId(id) then
        return cNet.CttpResponse:new(cNet.CttpStatus.BAD_REQUEST)
    end
    if string.find(file, "..") then
        return cNet.CttpResponse:new(cNet.CttpStatus.FORBIDDEN)
    end
    local fileData = getAppFile(id, file)
    if fileData == nil then
        return cNet.CttpResponse:new(cNet.CttpStatus.NOT_FOUND)
    end
    return cNet.CttpResponse:new(cNet.CttpStatus.OK, nil, fileData)
end)

cNet.setRestApi("GET", "/list", function (args, header, data, socket)
    local apps = fs.find("disk*/*")
    local result = {}
    for _, app in ipairs(apps) do
        table.insert(result, string.match(app, "disk%d*/(.*)"))
    end
    return cNet.CttpResponse:new(cNet.CttpStatus.OK, result)
end)

cNet.setRestApi("POST", "/app", function (args, header, data, socket)
    local id = args[1]
end)

cNet.setRestApi("POST", "/file", function (args, header, data, socket)
    local id = args[1]
    local file = args[2]
end)

cNet.startEventLoop(function ()
    cNet.host("cos-appstore", "modem_6")
end)
