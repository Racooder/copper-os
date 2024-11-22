local CryptoNet = require "CryptoNet"

--- The cNet module provides a simple way to create a secure network connection between two computers.
local CNet = {}

--* Constants

local CERT_AUTH_SERVER = "certAuth"

--* Globals

local messageListeners = {}
local signedCertificate = false
local debugMode = false
local signatureSocketKey = nil

--* Helper functions

-- TODO: Maybe export
--- @param o1 any|table First object to compare
--- @param o2 any|table Second object to compare
--- @param ignore_mt? boolean True to ignore metatables (a recursive function to tests tables inside tables)
local function equals(o1, o2, ignore_mt)
    if o1 == o2 then return true end
    local o1Type = type(o1)
    local o2Type = type(o2)
    if o1Type ~= o2Type then return false end
    if o1Type ~= 'table' then return false end

    if not ignore_mt then
        local mt1 = getmetatable(o1)
        if mt1 and mt1.__eq then
            -- compare using built in method
            return o1 == o2
        end
    end

    local keySet = {}

    for key1, value1 in pairs(o1) do
        local value2 = o2[key1]
        if value2 == nil or equals(value1, value2, ignore_mt) == false then
            return false
        end
        keySet[key1] = true
    end

    for key2, _ in pairs(o2) do
        if not keySet[key2] then return false end
    end
    return true
end

--* System Exports

CNet.system = {}

--- Api functions get the parameters:
--- - `data` — The data sent with the api call.
--- - `socket` — The socket that sent or received the api call.
--- - `server` — The server that sent or received the api call.
CNet.system.api = {}

-- FIXME: Unsecure
CNet.system.api["error"] = function (message)
    error(message)
end

--- Send a package over the given socket.
--- @param socket Socket
--- @param message boolean|number|string|table|nil
--- @param type string
function CNet.system.sendPackage(socket, type, message)
    CryptoNet.send(socket, {type, message})
end

--- Send a system message over the given socket.
--- @param socket Socket
--- @param apiFunction string
--- @param data boolean|number|string|table|nil
function CNet.system.sendApiCall(socket, apiFunction, data)
    CNet.system.sendPackage(socket, "system", {apiFunction, data})
end

--* Certificate Signature

--- Handle a certificate signature response from the CertAuth server.
--- @param certificate Certificate
CNet.system.api["certSignature"] = function (certificate, socket)
    if not equals(socket.key, signatureSocketKey, true) then
        return
    end
    local file = fs.open(certificate.name .. ".crt", "w")
    file.write(CryptoNet.serializeCertOrKey(certificate))
    file.close()
    signedCertificate = true
end

--- Request a signature for a certificate from the CertAuth server.
--- @param cert Certificate The certificate to request a signature for.
local function requestCertSignature(cert)
    local socket = CryptoNet.connect(CERT_AUTH_SERVER)
    signatureSocketKey = socket.key
    CNet.system.sendApiCall(socket, "signCertificate", cert)
end

--* Helper Functions

local function keyToString(key)
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

local eventHandlers = {
    --- @param socket Socket
    --- @param server Server
    ["connection_opened"] = function (socket, server)
        CNet.eventHandlers.connect(socket, server)
    end,
    --- @param socket Socket
    --- @param server Server
    ["connection_closed"] = function (socket, server)
        CNet.eventHandlers.disconnect(socket, server)
    end,
    --- @param package table
    --- @param socket Socket
    --- @param server? Server
    ["encrypted_message"] = function (package, socket, server)
        local packageType = package[1]
        local message = package[2]

        if packageType == "system" then
            local apiFunction = message[1]
            if CNet.system.api[apiFunction] then
                local responseFunction, responseData = CNet.system.api[apiFunction](message[2], socket, server)
                if type(responseFunction) == "string" then
                    CNet.system.sendApiCall(socket, responseFunction, responseData)
                end
            else
                CNet.system.sendApiCall(socket, "error", "Invalid API function: " .. apiFunction)
            end
        elseif packageType == "normal" then
            local keyString = keyToString(socket.key)
            if messageListeners[keyString] then
                messageListeners[keyString](message, socket, server)
                messageListeners[keyString] = nil
            else
                CNet.eventHandlers.message(message, socket, server)
            end
        end
    end,
    --- @param message boolean|number|string|table|nil
    --- @param socket Socket
    --- @param server? Server
    ["plain_message"] = function (message, socket, server)
        CNet.eventHandlers.plainMessage(message, socket, server)
    end,
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    ["login"] = function (username, socket, server)
        CNet.eventHandlers.login(username, socket, server)
    end,
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    ["login_failed"] = function (username, socket, server)
        CNet.eventHandlers.loginFailed(username, socket, server)
    end,
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    ["logout"] = function (username, socket, server)
        CNet.eventHandlers.logout(username, socket, server)
    end
}

local function onEvent(event)
    if type(event) ~= "table" then
        return
    end
    if eventHandlers[event[1]] then
        eventHandlers[event[1]](event[2], event[3], event[4])
    end
end

--* Module Exports

CNet.eventHandlers = {
    --- Invoked on a server when a client successfully opens a connection.
    --- @param socket Socket
    --- @param server Server
    connect = function (socket, server) end,
    --- Invoked on a client or server when a socket is closed by the other end.
    --- @param socket Socket
    --- @param server? Server
    disconnect = function (socket, server) end,
    --- Invoked when a message sent by the send() function is received.
    --- @param message boolean|number|string|table|nil
    --- @param socket Socket
    --- @param server? Server
    message = function (message, socket, server) end,
    --- Invoked when a message sent by the sendUnencrypted() function is received.
    --- @param message boolean|number|string|table|nil
    --- @param socket Socket
    --- @param server? Server
    plainMessage = function (message, socket, server) end,
    --- Invoked on both client and server when a user logs in successfully. The username and permission level of the logged in user are also stored in the socket.
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    login = function (username, socket, server) end,
    --- Invoked on both client and server when a user makes a failed login attempt.
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    loginFailed = function (username, socket, server) end,
    --- Invoked when a user logs out.
    --- @param username string
    --- @param socket Socket
    --- @param server? Server
    logout = function (username, socket, server) end,
}

CNet.auth = {
    addUser = CryptoNet.addUser,
    addUserHashed = CryptoNet.addUserHashed,
    checkPassword = CryptoNet.checkPassword,
    checkPasswordHashed = CryptoNet.checkPasswordHashed,
    deleteUser = CryptoNet.deleteUser,
    getPasswordHash = CryptoNet.getPasswordHash,
    getPermissionLevel = CryptoNet.getPermissionLevel,
    hashPassword = CryptoNet.hashPassword,
    loadUserTable = CryptoNet.loadUserTable,
    login = CryptoNet.login,
    loginHashed = CryptoNet.loginHashed,
    logout = CryptoNet.logout,
    saveUserTable = CryptoNet.saveUserTable,
    setPassword = CryptoNet.setPassword,
    setPasswordHashed = CryptoNet.setPasswordHashed,
    setPermissionLevel = CryptoNet.setPermissionLevel,
    userExists = CryptoNet.userExists,
    userTableValid = CryptoNet.userTableValid,
}

CNet.close = CryptoNet.close
CNet.closeAll = CryptoNet.closeAll

--- Enable or disable debug logs
--- @param enabled boolean The new state of debug mode
function CNet.setDebugMode(enabled)
    debugMode = enabled
    CryptoNet.setLoggingEnabled(enabled)
end

--- Setup the cNet module.
--- @param onStart function The function to call when the event loop starts.
function CNet.setup(onStart)
    CryptoNet.setLoggingEnabled(debugMode)
    CryptoNet.startEventLoop(onStart, onEvent)
end

--- Setup and host a cNet server.
--- @param serverName string The name of the server, which clients will use to connect to it. Also determines the channel that the server communicates on.
--- @param discoverable? boolean (default: true) Whether this server responds to discover() requests. Disabling this is more secure as it means clients can't connect unless they already know the name of the server.
--- @param hideCertificate? boolean (default: false) If true the server will not distribute its certificate to clients, either in discover() or connect() requests, meaning clients can only connect if they have already been given the certificate manually. Useful if you only want certain manually authorised clients to be able to connect.
--- @param modemSide? string The modem the server should use.
--- @param certificate? Certificate|string (default: "<serverName>.crt") The certificate of the server. This can either be the certificate table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
--- @param privateKey? PrivateKey|string (default: "<serverName>_private.key") The private key of the server. This can either be the key table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
--- @param userTablePath? string (default: "<serverName>_users.tbl") Path at which to store the user login details table, if/when users are added to the server.
--- @return Server # The server object.
function CNet.host(serverName, discoverable, hideCertificate, modemSide, certificate, privateKey, userTablePath)
    if serverName == nil or serverName == "" then
        error("serverName must be a non empty string")
    end
    if serverName:gmatch("[^%w%-%_%.]")() then
        error("serverName must only contain alphanumeric characters, hyphens, underscores, and periods")
    end
    local server = CryptoNet.host(serverName, discoverable, hideCertificate, modemSide, certificate, privateKey, userTablePath)
    -- Sign the server's certificate if it is not already signed
    local cert = server.certificate
    if cert.signature == nil then
        requestCertSignature(cert)
        for i = 1, 100, 1 do
            if signedCertificate then
                break
            end
            os.sleep(0.1)
        end
        if not signedCertificate then
            error("Failed to sign certificate.")
        end
    else
        signedCertificate = true
    end
    return server
end

--- Open an encrypted connection to a cNet server, returning a socket object that can be used to send and receive messages from the server.
--- @param serverName? string (default: inferred from certificate) The name of the server to connect to.
--- @param timeout? number (default: 5) The number of seconds to wait for a response to the connection request. Will terminate early if a response is received.
--- @param certTimeout? number (default: 1) The number of seconds to wait for certificate responses, if no certificate was provided.
--- @param certificate? Certificate|string (default: "<serverName>.crt") The certificate of the server. Can either be the certificate of the server itself, or the name of a file that contains it. If no valid certificate is found a certificate request will be sent to the server.
--- @param modemSide? string (default: a side with a modem) The modem to use to send and receive messages.
--- @param certAuthKey? PublicKey|string (default: "certAuth.key") The certificate authority public key used to verify signatures, or the path of the file to load it from. If no valid key is found the connection will still go ahead, but signatures will not be checked.
--- @param allowUnsigned? boolean (default: false) Whether to accept certificates with no valid signature. If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key. This does not apply to the certificate provided by the user (if present), which is never verified (we trust them to get their own certificate right), only to certificates received through a certificate request.
--- @return Socket
function CNet.connect(serverName, timeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
    return CryptoNet.connect(serverName, timeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
end

-- Send an encrypted message over the given socket. The message can be pretty much any Lua data type.
--- @param socket Socket
--- @param message boolean|number|string|table|nil
function CNet.send(socket, message)
    CNet.system.sendPackage(socket, "normal", message)
end

--- Send an unencrypted message over cNet. Useful for streams of high speed, non-sensitive data. Unencrypted messages have no security features applied, so can be easily exploited by attackers. Only use for non-critical messages.
---
--- Unencrypted messages can't be received using `listen()`. Use the `plainMessage` event handler instead.
--- @param socket Socket
--- @param message boolean|number|string|table|nil
function CNet.sendUnencrypted(socket, message)
    CryptoNet.sendUnencrypted(socket, message)
end

--- Connect to a server and send a message in one function call. Returns the socket object for the connection.
--- @param serverName string The name of the server to connect to.
--- @param message boolean|number|string|table|nil The message to send.
--- @return Socket socket The connection socket
function CNet.connectAndSend(serverName, message)
    local socket = CNet.connect(serverName)
    CNet.send(socket, message)
    return socket
end

--- Listen for incoming messages on the given socket. If no callback is provided, the function will block until a message is received or the timeout is reached. If a callback is provided, the function will return immediately, and the callback will be called when a message is received.
--- @param socket Socket The socket to listen on.
--- @param callback? function The function to call when a message is received.
--- @param timeout? number (default: 5) The number of seconds to wait for a message to be received. If no message is received in this time, the function will return nil.
--- @return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
--- @return boolean|number|string|table|nil message The message if it was received or the reason for failure.
function CNet.listen(socket, callback, timeout)
    timeout = timeout or 5
    local keyString = keyToString(socket.key)
    if messageListeners[keyString] then
        return false, "Already listening on this socket."
    end
    -- If a responseHandler is provided, set up the listener and return nil
    if callback then
        messageListeners[keyString] = callback
        return false, "Callback provided."
    end
    -- If no responseHandler is provided, block until a message is received and return the message
    local result = "Timeout reached."
    local success = false
    messageListeners[keyString] = function(message)
        result = message
        success = true
        messageListeners[keyString] = nil
    end
    for i = 1, timeout * 10, 1 do
        if success then
            break
        end
        os.sleep(0.1)
    end
    return success, result
end

--- Connect to a server, send a message and listen for a response in one function call. Returns the response message.
--- @param serverName string The name of the server to connect to.
--- @param message boolean|number|string|table|nil The message to send.
--- @param callback? function The function to call when a response is received.
--- @param timeout? number (default: 5) The number of seconds to wait for a response to be received. If no response is received in this time, the function will return nil.
--- @return boolean success If a callback is provided, `false`. Otherwise, `true` if a message was received or `false` if the timeout was reached.
--- @return boolean|number|string|table|nil message The message if it was received or the reason for failure.
function CNet.connectSendAndListen(serverName, message, callback, timeout)
    local socket = CNet.connect(serverName)
    CNet.send(socket, message)
    return CNet.listen(socket, callback, timeout)
end

return CNet
