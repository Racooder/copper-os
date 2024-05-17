-- Hosting Example
local cNet = require "cNet"

cNet.setRestApi("GET", "/path", function ()
    return {
        status = 200,
        headers = {
            ["Content-Type"] = "text/plain"
        },
        body = "Hello, World!"
    }
end)

cNet.startEventLoop(function ()
    cNet.host("server-id", "top")
end)
