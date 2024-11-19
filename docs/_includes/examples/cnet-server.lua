CNet = require "CNet"

-- Receiving messages is possible by overriding the message event handler
CNet.eventHandlers.message = function (message, socket, server)
    print("Received message: " .. message)
    CNet.send(socket, "Response message")
    CNet.send(socket, {a = 1}) -- Messages can be any lua data type that can be serialized
end

-- Before hosting or sending messages is possible, CNet must be set up
CNet.setup(function ()
    CNet.host("server-name")
end)