local CNet = require "CNet"

---WARNING: This module is not compatible with the cNet module. Please use the cNet module integrated in this module.
---
---The cttp module provides a simple way to create a REST API server and send requests to it.
local Cttp = {}

--* Class Definitions

---@class CttpRequest
---@field method "GET"|"POST"|"DELETE"
---@field path string
---@field body? boolean|number|string|table

---@class CttpResponse
---@field status number
---@field body? boolean|number|string|table

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
        ---@param body boolean|number|string|table|nil The request body.
        ---@return number status
        ---@return boolean|number|string|table|nil body
        ["/"] = function (body)
            return 200, "Hello World!"
        end
    },
    ["POST"] = {},
    ["DELETE"] = {}
}

---@param req CttpRequest
---@return number status
---@return boolean|number|string|table|nil body
local function handleRequest(req)
    local method = req.method
    local path = req.path
    local handler = restApi[method][path]

    if handler then
        local status, body = handler(req.body)
        if type(status) == "table" then
            ---Allow the handler to return a response object too.
            return status.status, status.body
        else
            return status, body
        end
    else
        return 404, "Not Found"
    end
end

---WARNING: Please don't override this function. Use the rest API functionality instead.
---@param message boolean|number|string|table|nil
---@param socket Socket
---@param server Server
CNet.eventHandlers.message = function (message, socket, server)
    if type(message) ~= "table" or not isValidRequest(message) then
        return
    end
    local res = Cttp.Response(handleRequest(message))
    CNet.send(socket, res)
end

--* Module Exports

Cttp.setDebugMode = CNet.setDebugMode
Cttp.CNet = {
    send = CNet.send,
    sendUnencrypted = CNet.sendUnencrypted,
    listen = CNet.listen
}
Cttp.auth = CNet.auth
Cttp.close = CNet.close
Cttp.closeAll = CNet.closeAll
Cttp.connect = CNet.connect
---WARNING: Don't override the message event. Use the rest API functionality instead.
Cttp.eventHandlers = CNet.eventHandlers
Cttp.host = CNet.host
Cttp.setup = CNet.setup
Cttp.system = CNet.system

---Registers a rest API path.
---@param method "GET"|"POST"|"DELETE"
---@param path string
---@param handler function A function that takes a CttpRequest body as input and returns a status code and a response body.
function Cttp.ApiMapping(method, path, handler)
    restApi[method][path] = handler
end

---Registers a GET rest API path.
---@param path string
---@param handler function A function that takes a CttpRequest body as input and returns a status code and a response body.
function Cttp.GetMapping(path, handler)
    Cttp.ApiMapping("GET", path, handler)
end

---Registers a POST rest API path.
---@param path string
---@param handler function A function that takes a CttpRequest body as input and returns a status code and a response body.
function Cttp.PostMapping(path, handler)
    Cttp.ApiMapping("POST", path, handler)
end

---Registers a DELETE rest API path.
---@param path string
---@param handler function A function that takes a CttpRequest body as input and returns a status code and a response body.
function Cttp.DeleteMapping(path, handler)
    Cttp.ApiMapping("DELETE", path, handler)
end

---Creates a new response object.
---@param statusOrResponse number|CttpResponse
---@param body? boolean|number|string|table
---@return CttpResponse
function Cttp.Response(statusOrResponse, body)
    if type(statusOrResponse) == "table" and isValidResponse(statusOrResponse) then
        return statusOrResponse
    end
    return {
        status = statusOrResponse,
        body = body
    }
end

---Creates a new request object.
---@param method "GET"|"POST"|"DELETE"
---@param path string
---@param body? boolean|number|string|table
---@return CttpRequest
function Cttp.Request(method, path, body)
    return {
        method = method,
        path = path,
        body = body
    }
end

---Creates a new GET request object.
---@param path string
---@param body? boolean|number|string|table
---@return CttpRequest
function Cttp.GetRequest(path, body)
    return Cttp.Request("GET", path, body)
end

---Creates a new POST request object.
---@param path string
---@param body? boolean|number|string|table
---@return CttpRequest
function Cttp.PostRequest(path, body)
    return Cttp.Request("POST", path, body)
end

---Creates a new DELETE request object.
---@param path string
---@param body? boolean|number|string|table
---@return CttpRequest
function Cttp.DeleteRequest(path, body)
    return Cttp.Request("DELETE", path, body)
end

---Sends a request to a server. The callback is called when the response is received. If no callback is provided, the function will block until a response is received or the timeout is reached.
---@param socket Socket The socket to send the request on.
---@param req CttpRequest The request to send.
---@param callback? function A function that takes a CttpResponse as input.
---@param timeout? number (default = 5)
---@return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
---@return CttpResponse|nil result The response if it was received or the reason for failure.
function Cttp.sendRequest(socket, req, callback, timeout)
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

---Connects to a server and sends a request. The callback is called when the response is received. If no callback is provided, the function will block until a response is received or the timeout is reached.
---@param serverName string The name of the server to connect to.
---@param req CttpRequest The request to send.
---@param callback function The function to call when a response is received.
---@param timeout? number (default: 5) The number of seconds to wait for a response to be received. If no response is received in this time, the function will return nil.
---@return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
---@return CttpResponse|nil result The response if it was received or the reason for failure.
function Cttp.connectAndRequest(serverName, req, callback, timeout)
    local socket = CNet.connect(serverName)
    return Cttp.sendRequest(socket, req, callback, timeout)
end

return Cttp
