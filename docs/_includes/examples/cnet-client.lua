CNet = require "CNet"

-- Before connecting or sending messages is possible, CNet must be set up
CNet.setup(function ()
    local socket = CNet.connect("server-name")
    CNet.send(socket, "Hello, server!")
    local response = CNet.listen(socket) -- Blocks until a message is received
    print("Received response: " .. response)

    -- Shorter version of the above code
    local socket2 = CNet.connectAndSend("server2", "Hello, server!")
    local response2 = CNet.listen(socket2)
    print("Received response: " .. response2)

    -- Even shorter version
    local response3 = CNet.connectSendAndListen("server3", "Hello, server!")
    print("Received response: " .. response3)

    -- It's also possible to define a callback function to prevent blocking
    CNet.connectSendAndListen("server4", "Hello, server!", function (response4)
        print("Received response: " .. response4)
    end)
    print("This message will be printed before the response is received")
end)