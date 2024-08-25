CNet = require "cNet"

--- WARNING: This module is not compatible with the cNet module. Please use the cNet module integrated in this module.
---
--- The cttp module provides a simple way to create a REST API server and send requests to it.
local cttp = {}

--* Class Definitions

--- @class CttpRequest
--- @field method "GET"|"POST"|"DELETE"
--- @field path string
--- @field body? boolean|number|string|table

--- @class CttpResponse
--- @field status number
--- @field body? boolean|number|string|table

--* Helper Functions

local function isValidResponse(res)
    return type(res.status) == "number"
        and (res.body == nil or type(res.body) == "boolean" or type(res.body) == "number" or type(res.body) == "string" or type(res.body) == "table")
end

local function isValidRequest(req)
    return (req.method == "GET" or req.method == "POST" or req.method == "DELETE")
        and type(req.path) == "string"
        and (req.body == nil or type(req.body) == "boolean" or type(req.body) == "number" or type(req.body) == "string" or type(req.body) == "table")
end

--* Rest API

local restApi = {
    ["GET"] = {
        --- @param req CttpRequest
        --- @return number status
        --- @return boolean|number|string|table|nil body
        ["/"] = function (req)
            return 200, "Hello World!"
        end
    },
    ["POST"] = {},
    ["DELETE"] = {}
}

--- @param req CttpRequest
--- @return number status
--- @return boolean|number|string|table|nil body
local function handleRequest(req)
    local method = req.method
    local path = req.path
    local handler = restApi[method][path]

    if handler then
        local status, body = handler(req)
        if type(status) == "table" then
            --- Allow the handler to return a response object too.
            return status.status, status.body
        else
            return status, body
        end
    else
        return 404, "Not Found"
    end
end

--- WARNING: Please don't override this function. Use the rest API functionality instead.
--- @param message boolean|number|string|table|nil
--- @param socket Socket
--- @param server Server
CNet.eventHandlers.message = function (message, socket, server)
    if type(message) ~= "table" or not isValidRequest(message) then
        return
    end
    local res = cttp.Response(handleRequest(message))
    CNet.send(socket, res)
end

--* Module Exports

cttp.cNet = {
    send = CNet.send,
    sendUnencrypted = CNet.sendUnencrypted,
    listen = CNet.listen
}
cttp.auth = CNet.auth
cttp.close = CNet.close
cttp.closeAll = CNet.closeAll
cttp.connect = CNet.connect
--- WARNING: Don't override the message event. Use the rest API functionality instead.
cttp.eventHandlers = CNet.eventHandlers
cttp.host = CNet.host
cttp.setup = CNet.setup
cttp.system = CNet.system

--- Registers a rest API path.
--- @param method "GET"|"POST"|"DELETE"
--- @param path string
--- @param handler function A function that takes a CttpRequest as input and returns a status code and a response body.
function cttp.ApiMapping(method, path, handler)
    restApi[method][path] = handler
end

--- Registers a GET rest API path.
--- @param path string
--- @param handler function A function that takes a CttpRequest as input and returns a status code and a response body.
function cttp.GetMapping(path, handler)
    cttp.ApiMapping("GET", path, handler)
end

--- Registers a POST rest API path.
--- @param path string
--- @param handler function A function that takes a CttpRequest as input and returns a status code and a response body.
function cttp.PostMapping(path, handler)
    cttp.ApiMapping("POST", path, handler)
end

--- Registers a DELETE rest API path.
--- @param path string
--- @param handler function A function that takes a CttpRequest as input and returns a status code and a response body.
function cttp.DeleteMapping(path, handler)
    cttp.ApiMapping("DELETE", path, handler)
end

--- Creates a new response object.
--- @param status number
--- @param body? boolean|number|string|table
--- @return CttpResponse
function cttp.Response(status, body)
    return {
        status = status,
        body = body
    }
end

--- Creates a new request object.
--- @param method "GET"|"POST"|"DELETE"
--- @param path string
--- @param body? boolean|number|string|table
--- @return CttpRequest
function cttp.Request(method, path, body)
    return {
        method = method,
        path = path,
        body = body
    }
end

--- Creates a new GET request object.
---@param path string
---@param body? boolean|number|string|table
---@return CttpRequest
function cttp.GetRequest(path, body)
    return cttp.Request("GET", path, body)
end

--- Creates a new POST request object.
--- @param path string
--- @param body? boolean|number|string|table
--- @return CttpRequest
function cttp.PostRequest(path, body)
    return cttp.Request("POST", path, body)
end

--- Creates a new DELETE request object.
--- @param path string
--- @param body? boolean|number|string|table
--- @return CttpRequest
function cttp.DeleteRequest(path, body)
    return cttp.Request("DELETE", path, body)
end

--- Sends a request to a server. The callback is called when the response is received. If no callback is provided, the function will block until a response is received or the timeout is reached.
--- @param req CttpRequest
--- @param socket Socket
--- @param callback? function A function that takes a CttpResponse as input.
--- @param timeout? number (default = 5)
--- @return boolean success
--- @return CttpResponse|nil result
function cttp.sendRequest(socket, req, callback, timeout)
    if not isValidRequest(req) then
        return false
    end
    CNet.send(socket, req)
    local success, message = CNet.listen(socket, callback, timeout)
    if type(message) == "table" and isValidResponse(message) then
        return success, message
    end
    return false
end

--- Connects to a server and sends a request. The callback is called when the response is received. If no callback is provided, the function will block until a response is received or the timeout is reached.
--- @param serverName? string
--- @param req CttpRequest
--- @param callback function
--- @param responseTimeout? number (default = 5)
--- @param connectTimeout? number (default = 5)
--- @param certTimeout? number (default = 5)
--- @param certificate? string|Certificate
--- @param modemSide? string
--- @param certAuthKey? string|PublicKey
--- @param allowUnsigned? boolean
--- @return boolean success
--- @return CttpResponse|nil result
function cttp.connectAndRequest(serverName, req, callback, responseTimeout, connectTimeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
    local socket = CNet.connect(serverName, connectTimeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
    return cttp.sendRequest(socket, req, callback, responseTimeout)
end

return cttp
