local Cryptonet = require "cryptonet"

---The cNet module provides a simple way to create a secure network connection between two computers.
local Package = {}

--* Constants

local CERT_AUTH_SERVER = "certAuth"

--* Globals

local message_listeners = {}
local signed_certificate = false
local debug_mode = false
local signature_socket_key = nil

--* Helper functions

-- TODO: Maybe export
---@param o1 any|table First object to compare
---@param o2 any|table Second object to compare
---@param ignore_mt? boolean True to ignore metatables (a recursive function to tests tables inside tables)
local function equals(o1, o2, ignore_mt)
    if o1 == o2 then return true end
    local o1_type = type(o1)
    local o2_type = type(o2)
    if o1_type ~= o2_type then return false end
    if o1_type ~= 'table' then return false end

    if not ignore_mt then
        local mt_1 = getmetatable(o1)
        if mt_1 and mt_1.__eq then
            -- compare using built in method
            return o1 == o2
        end
    end

    local key_set = {}

    for key_1, value_1 in pairs(o1) do
        local value_2 = o2[key_1]
        if value_2 == nil or equals(value_1, value_2, ignore_mt) == false then
            return false
        end
        key_set[key_1] = true
    end

    for key_2, _ in pairs(o2) do
        if not key_set[key_2] then return false end
    end
    return true
end

--* System Exports

Package.system = {}

---Api functions get the parameters:
---- `data` — The data sent with the api call.
---- `socket` — The socket that sent or received the api call.
---- `server` — The server that sent or received the api call.
Package.system.api = {}

-- FIXME: Unsecure
Package.system.api["error"] = function (message)
    error(message)
end

---Send a package over the given socket.
---@param socket Socket
---@param message boolean|number|string|table|nil
---@param type string
function Package.system.send_package(socket, type, message)
    Cryptonet.send(socket, {type, message})
end

---Send a system message over the given socket.
---@param socket Socket
---@param api_function string
---@param data boolean|number|string|table|nil
function Package.system.sendApiCall(socket, api_function, data)
    Package.system.sendPackage(socket, "system", {api_function, data})
end

--* Certificate Signature

---Handle a certificate signature response from the CertAuth server.
---@param certificate Certificate
Package.system.api["cert_signature"] = function (certificate, socket)
    if not equals(socket.key, signature_socket_key, true) then
        return
    end
    local file = fs.open(certificate.name .. ".crt", "w")
    file.write(Cryptonet.serialize_cert_or_key(certificate))
    file.close()
    signed_certificate = true
end

---Request a signature for a certificate from the CertAuth server.
---@param cert Certificate The certificate to request a signature for.
local function request_cert_signature(cert)
    local socket = Cryptonet.connect(CERT_AUTH_SERVER)
    signature_socket_key = socket.key
    Package.system.send_api_call(socket, "sign_certificate", cert)
end

--* Helper Functions

local function key_to_string(key)
    local s = ""
    for index, value in ipairs(key) do
        if index > 1 then
            s = s .. ","
        end
        s = s .. value
    end
    return s
end

--* Event Handling

local event_handlers = {
    ---@param socket Socket
    ---@param server Server
    ["connection_opened"] = function (socket, server)
        Package.event_handlers.connect(socket, server)
    end,
    ---@param socket Socket
    ---@param server Server
    ["connection_closed"] = function (socket, server)
        Package.event_handlers.disconnect(socket, server)
    end,
    ---@param package table
    ---@param socket Socket
    ---@param server? Server
    ["encrypted_message"] = function (package, socket, server)
        local package_type = package[1]
        local message = package[2]

        if package_type == "system" then
            local api_function = message[1]
            if Package.system.api[api_function] then
                local response_function, response_data = Package.system.api[api_function](message[2], socket, server)
                if type(response_function) == "string" then
                    Package.system.send_api_call(socket, response_function, response_data)
                end
            else
                Package.system.send_api_call(socket, "error", "Invalid API function: " .. api_function)
            end
        elseif package_type == "normal" then
            local key_string = key_to_string(socket.key)
            if message_listeners[key_string] then
                message_listeners[key_string](message, socket, server)
                message_listeners[key_string] = nil
            else
                Package.event_handlers.message(message, socket, server)
            end
        end
    end,
    ---@param message boolean|number|string|table|nil
    ---@param socket Socket
    ---@param server? Server
    ["plain_message"] = function (message, socket, server)
        Package.event_handlers.plain_message(message, socket, server)
    end,
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    ["login"] = function (username, socket, server)
        Package.event_handlers.login(username, socket, server)
    end,
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    ["login_failed"] = function (username, socket, server)
        Package.event_handlers.login_failed(username, socket, server)
    end,
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    ["logout"] = function (username, socket, server)
        Package.event_handlers.logout(username, socket, server)
    end
}

local function on_event(event)
    if type(event) ~= "table" then
        return
    end
    if event_handlers[event[1]] then
        event_handlers[event[1]](event[2], event[3], event[4])
    end
end

--* Module Exports

Package.event_handlers = {
    ---Invoked on a server when a client successfully opens a connection.
    ---@param socket Socket
    ---@param server Server
    connect = function (socket, server) end,
    ---Invoked on a client or server when a socket is closed by the other end.
    ---@param socket Socket
    ---@param server? Server
    disconnect = function (socket, server) end,
    ---Invoked when a message sent by the send() function is received.
    ---@param message boolean|number|string|table|nil
    ---@param socket Socket
    ---@param server? Server
    message = function (message, socket, server) end,
    ---Invoked when a message sent by the sendUnencrypted() function is received.
    ---@param message boolean|number|string|table|nil
    ---@param socket Socket
    ---@param server? Server
    plain_message = function (message, socket, server) end,
    ---Invoked on both client and server when a user logs in successfully. The username and permission level of the logged in user are also stored in the socket.
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    login = function (username, socket, server) end,
    ---Invoked on both client and server when a user makes a failed login attempt.
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    login_failed = function (username, socket, server) end,
    ---Invoked when a user logs out.
    ---@param username string
    ---@param socket Socket
    ---@param server? Server
    logout = function (username, socket, server) end,
}

Package.auth = {
    add_user = Cryptonet.add_user,
    add_user_hashed = Cryptonet.add_user_hashed,
    check_password = Cryptonet.check_password,
    check_password_hashed = Cryptonet.check_password_hashed,
    delete_user = Cryptonet.delete_user,
    get_password_hash = Cryptonet.get_password_hash,
    get_permission_level = Cryptonet.get_permission_level,
    hash_password = Cryptonet.hash_password,
    load_user_table = Cryptonet.load_user_table,
    login = Cryptonet.login,
    login_hashed = Cryptonet.login_hashed,
    logout = Cryptonet.logout,
    save_user_table = Cryptonet.save_user_table,
    set_password = Cryptonet.set_password,
    set_password_hashed = Cryptonet.set_password_hashed,
    set_permission_level = Cryptonet.set_permission_level,
    user_exists = Cryptonet.user_exists,
    user_table_valid = Cryptonet.user_table_valid,
}

Package.close = Cryptonet.close
Package.close_all = Cryptonet.close_all

---Enable or disable debug logs
---@param enabled boolean The new state of debug mode
function Package.set_debug_mode(enabled)
    debug_mode = enabled
    Cryptonet.set_logging_enabled(enabled)
end

---Setup the cNet module.
---@param on_start function The function to call when the event loop starts.
function Package.setup(on_start)
    Cryptonet.set_logging_enabled(debug_mode)
    Cryptonet.start_event_loop(on_start, on_event)
end

---Setup and host a cNet server.
---@param server_name string The name of the server, which clients will use to connect to it. Also determines the channel that the server communicates on.
---@param discoverable? boolean (default: true) Whether this server responds to discover() requests. Disabling this is more secure as it means clients can't connect unless they already know the name of the server.
---@param hide_certificate? boolean (default: false) If true the server will not distribute its certificate to clients, either in discover() or connect() requests, meaning clients can only connect if they have already been given the certificate manually. Useful if you only want certain manually authorised clients to be able to connect.
---@param modem_side? string The modem the server should use.
---@param certificate? Certificate|string (default: "<serverName>.crt") The certificate of the server. This can either be the certificate table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
---@param private_key? PrivateKey|string (default: "<serverName>_private.key") The private key of the server. This can either be the key table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
---@param user_table_path? string (default: "<serverName>_users.tbl") Path at which to store the user login details table, if/when users are added to the server.
---@return Server # The server object.
function Package.host(server_name, discoverable, hide_certificate, modem_side, certificate, private_key, user_table_path)
    if server_name == nil or server_name == "" then
        error("server_name must be a non empty string")
    end
    if server_name:gmatch("[^%w%-%_%.]")() then
        error("server_name must only contain alphanumeric characters, hyphens, underscores, and periods")
    end
    local server = Cryptonet.host(server_name, discoverable, hide_certificate, modem_side, certificate, private_key, user_table_path)
    -- Sign the server's certificate if it is not already signed
    local cert = server.certificate
    if cert.signature == nil then
        request_cert_signature(cert)
        for i = 1, 100, 1 do
            if signed_certificate then
                break
            end
            os.sleep(0.1)
        end
        if not signed_certificate then
            error("Failed to sign certificate.")
        end
    else
        signed_certificate = true
    end
    return server
end

---Open an encrypted connection to a cNet server, returning a socket object that can be used to send and receive messages from the server.
---@param server_name? string (default: inferred from certificate) The name of the server to connect to.
---@param timeout? number (default: 5) The number of seconds to wait for a response to the connection request. Will terminate early if a response is received.
---@param cert_timeout? number (default: 1) The number of seconds to wait for certificate responses, if no certificate was provided.
---@param certificate? Certificate|string (default: "<serverName>.crt") The certificate of the server. Can either be the certificate of the server itself, or the name of a file that contains it. If no valid certificate is found a certificate request will be sent to the server.
---@param modem_side? string (default: a side with a modem) The modem to use to send and receive messages.
---@param cert_auth_key? PublicKey|string (default: "certAuth.key") The certificate authority public key used to verify signatures, or the path of the file to load it from. If no valid key is found the connection will still go ahead, but signatures will not be checked.
---@param allow_unsigned? boolean (default: false) Whether to accept certificates with no valid signature. If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key. This does not apply to the certificate provided by the user (if present), which is never verified (we trust them to get their own certificate right), only to certificates received through a certificate request.
---@return Socket
function Package.connect(server_name, timeout, cert_timeout, certificate, modem_side, cert_auth_key, allow_unsigned)
    return Cryptonet.connect(server_name, timeout, cert_timeout, certificate, modem_side, cert_auth_key, allow_unsigned)
end

-- Send an encrypted message over the given socket. The message can be pretty much any Lua data type.
---@param socket Socket
---@param message boolean|number|string|table|nil
function Package.send(socket, message)
    Package.system.send_package(socket, "normal", message)
end

---Send an unencrypted message over cNet. Useful for streams of high speed, non-sensitive data. Unencrypted messages have no security features applied, so can be easily exploited by attackers. Only use for non-critical messages.
---
---Unencrypted messages can't be received using `listen()`. Use the `plainMessage` event handler instead.
---@param socket Socket
---@param message boolean|number|string|table|nil
function Package.send_unencrypted(socket, message)
    Cryptonet.send_unencrypted(socket, message)
end

---Connect to a server and send a message in one function call. Returns the socket object for the connection.
---@param server_name string The name of the server to connect to.
---@param message boolean|number|string|table|nil The message to send.
---@return Socket socket The connection socket
function Package.connect_and_send(server_name, message)
    local socket = Package.connect(server_name)
    Package.send(socket, message)
    return socket
end

---Listen for incoming messages on the given socket. If no callback is provided, the function will block until a message is received or the timeout is reached. If a callback is provided, the function will return immediately, and the callback will be called when a message is received.
---@param socket Socket The socket to listen on.
---@param callback? function The function to call when a message is received.
---@param timeout? number (default: 5) The number of seconds to wait for a message to be received. If no message is received in this time, the function will return nil.
---@return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
---@return boolean|number|string|table|nil message The message if it was received or the reason for failure.
function Package.listen(socket, callback, timeout)
    timeout = timeout or 5
    local key_string = key_to_string(socket.key)
    if message_listeners[key_string] then
        return false, "Already listening on this socket."
    end
    -- If a responseHandler is provided, set up the listener and return nil
    if callback then
        message_listeners[key_string] = callback
        return false, "Callback provided."
    end
    -- If no responseHandler is provided, block until a message is received and return the message
    local result = "Timeout reached."
    local success = false
    message_listeners[key_string] = function(message)
        result = message
        success = true
        message_listeners[key_string] = nil
    end
    for i = 1, timeout * 10, 1 do
        if success then
            break
        end
        os.sleep(0.1)
    end
    return success, result
end

---Connect to a server, send a message and listen for a response in one function call. Returns the response message.
---@param server_name string The name of the server to connect to.
---@param message boolean|number|string|table|nil The message to send.
---@param callback? function The function to call when a response is received.
---@param timeout? number (default: 5) The number of seconds to wait for a response to be received. If no response is received in this time, the function will return nil.
---@return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
---@return boolean|number|string|table|nil message The message if it was received or the reason for failure.
function Package.connect_send_and_listen(server_name, message, callback, timeout)
    local socket = Package.connect(server_name)
    Package.send(socket, message)
    return Package.listen(socket, callback, timeout)
end

return Package
