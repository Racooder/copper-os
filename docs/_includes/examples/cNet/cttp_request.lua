-- CTTP Request Example
local cNet = require "cNet"

cNet.startEventLoop(function ()
    local connection = cNet.connectCtcp("server-id", 10, "top")
    if connection == nil then
        print("Failed to connect")
        return
    end

    local request = cNet.CttpRequest:new("GET", "/path")
    local response = cNet.sendCttpRequest(connection, request, 10)
    if response == nil then
        print("Timeout was reached before receiving a response")
        return
    end

    print("Status: " .. response.statusCode)
    print("Status Message: " .. response.statusMessage)

    local acknowledged = cNet.disconnectCtcp(connection, 10)
    if not acknowledged then
        print("Server did not acknowledge the disconnect. Disconnected anyway.")
    end
end)