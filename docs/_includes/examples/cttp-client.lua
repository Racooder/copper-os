Cttp = require "Cttp"

-- Before connecting or sending requests is possible, Cttp must be set up
Cttp.setup(function ()
    local socket = Cttp.connect("server-name")
    local response = Cttp.sendRequest(socket, Cttp.GetRequest("/path", "Request message"))
end)