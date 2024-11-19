Cttp = require "Cttp"

-- Requests can be handled by defining Get, Post and Delete mappings
-- The request Cttp.GetRequest("/path", "Request message") will be handled by this function
Cttp.GetMapping("/path", function (body)
    print("Received request: " .. body)
    return 200, "Response message" -- Status code and response message
    -- Messages can be any lua data type that can be serialized
end)

-- Before hosting is possible, Cttp must be set up
Cttp.setup(function ()
    Cttp.host("server-name")
end)