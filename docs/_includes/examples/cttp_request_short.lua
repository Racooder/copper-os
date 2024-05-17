local cNet = require "cNet"

cNet.startEventLoop(function ()
    local request = cNet.CttpRequest:new("GET", "/path")
    local response, connectAck, requestAck, disconnectAck = cNet.connectAndSendCttpRequest("server-id", request, 10, "top")
    if not connectAck then
        print("Failed to connect to server")
        return
    end
    if not requestAck then
        print("Failed to send request")
        return
    end
    if response == nil then
        print("Timeout was reached before receiving a response")
        return
    end
    if not disconnectAck then
        print("Disconnect was not acknowledged. Disconnected anyway.")
        return
    end
end)
