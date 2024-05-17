local cNet = require "cNet"
local logger = require "copperLogger"

--* Logging

logger.setPrefix("[AS] ")
cNet.setLogger(logger.logInColumns)

--* Main

cNet.startEventLoop(function ()
    local request = cNet.CttpRequest:new("GET", "/app/test")
    local response = cNet.connectAndSendCttpRequest("cos-appstore", request)
    if response == nil then
        print("No response")
        return
    end
    print(response.statusCode, textutils.serialise(response.data))
end)
