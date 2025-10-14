---@diagnostic disable: duplicate-set-field, cast-local-type, undefined-global, undefined-field, need-check-nil

local Sha256 = require("cryptolib.sha256")
local RsaCrypt = require("cryptolib.rsaCrypt")
local RsaKeygen = require("cryptolib.rsaKeygen")
local Isaac = require("cryptolib.isaac")
local Aes = require("cryptolib.aes")

local Threading = require("threading")

-- CryptoNet Networking Framework by SiliconSloth (Modified by Racooder for CopperOS)
-- Licensed under the MIT license.
--
-- Copyright (c) 2019 SiliconSloth
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.


-- CryptoNet is a simple and secure framework for encrypted networking
-- between ComputerCraft computers, intended to be used as an alternative to Rednet.
-- For more information, see CryptoNet's GitHub repo at https://github.com/SiliconSloth/CryptoNet

-- Line numbers:
-- 50    CryptoNet
-- 81    - Accessors
-- 128   - Validity Checks
-- 237   - Helpers
-- 550   - Send Functions
-- 626   - Login System
-- 1176  - Core Networking
-- 2112  - Event Loop
-- 2199  - Certificate Authority
-- 2367  - Module Exports and Class Definitions

------- BEGIN CRYPTONET -------
-- The following code was written by me (SiliconSloth).


local cryptoNet = {}


-- Channel used to send discovery requests and responses.
DISCOVERY_CHANNEL = 65531
-- If set to true CryptoNet will also broadcast all messages over the Rednet
-- reapter channel, which allows CryptoNet messages to be repeated by the built-in
-- program repeat. Disabling this is a little more secure as an attacker won't know
-- which channel you are communicating over.
local repeatMessages = true
-- Whether to print log messages or not.
local loggingEnabled = true
-- Directory CryptoNet looks for files in.
local workingDir = ""
-- All servers currently open on this computer.
local allServers = {}
-- All client sockets (opened with connect()) open on this computer.
local allClientSockets = {}


local function log(message)
    if loggingEnabled then
        print("[CryptoNet] " .. message)
    end
end


--
-- ACCESSORS
--

---@return boolean
function cryptoNet.getLoggingEnabled()
    return loggingEnabled
end

---@param enabled boolean
function cryptoNet.setLoggingEnabled(enabled)
    loggingEnabled = enabled
end

---@return boolean
function cryptoNet.getRepeatMessages()
    return repeatMessages
end

---@param repMsgs boolean
function cryptoNet.setRepeatMessages(repMsgs)
    repeatMessages = repMsgs
end

---@return string
function cryptoNet.getWorkingDirectory()
    return workingDir
end

---@param dir string
function cryptoNet.setWorkingDirectory(dir)
    if type(dir) ~= "string" then
        error("Directory must be a string.", 2)
    end
    workingDir = dir
end

--- @return table<Server>
function cryptoNet.getAllServers()
    return allServers
end

--- @return table<Socket>
function cryptoNet.getAllClientSockets()
    return allClientSockets
end

--
-- VALIDITY CHECKS
--

--- Check that the key is a 16 element table of numbers.
--- @param key table<number>
--- @return boolean
function cryptoNet.keyValid(key)
    if not (type(key) == "table" and #key == 16) then
        return false
    end
    -- Make sure all elements are numbers.
    for _, v in pairs(key) do
        if type(v) ~= "number" then
            return false
        end
    end
    return true
end

--- Check that a table has all the parts required to be a valid private key.
--- @param key? table
--- @return boolean
function cryptoNet.privateKeyValid(key)
    return type(key) == "table" and type(key.private) == "string" and type(key.shared) == "string"
end

--- Check that a table has all the parts required to be a valid public key.
--- @param key? table
--- @return boolean
function cryptoNet.publicKeyValid(key)
    return type(key) == "table" and type(key.public) == "string" and type(key.shared) == "string"
end

--- Check that a table has all the parts required to be a valid server certificate. If ignoreKey is true it is acceptable for a server to have no key, but if present it must be valid. The signature is always optional but must be valid (syntactically, it isn't actually verified here) if present.
--- @param certificate? table
--- @param ignoreKey? boolean
--- @return boolean
function cryptoNet.certificateValid(certificate, ignoreKey)
    -- All certificates must contain the server name.
    if type(certificate) ~= "table" or type(certificate.name) ~= "string" then
        return false
    end

    -- A certificate must contain the server's public key, unless ignoreKey is true.
    if certificate.key == nil and not ignoreKey then
        return false
    end
    -- Ensure that the public key is valid, if present.
    if certificate.key ~= nil and not cryptoNet.publicKeyValid(certificate.key) then
        return false
    end

    -- A certificate should only have a signature if it also contains a key.
    if certificate.key == nil and certificate.signature ~= nil then
        return false
    end
    -- If a signature is present (which it doesn't need to be), it must be a string.
    if certificate.signature ~= nil and type(certificate.signature) ~= "string" then
        return false
    end

    return true
end

--- Check that a table has everything it needs to be a valid server.
--- @param server? table
--- @return boolean
function cryptoNet.serverValid(server)
    return type(server) == "table"
        and type(server.name) == "string"
        and cryptoNet.certificateValid(server.certificate)
        and cryptoNet.privateKeyValid(server.privateKey)
        and type(server.modemSide) == "string"
        and type(server.channel) == "number"
        and type(server.userTable) == "table"
        and type(server.userTablePath) == "string"
        and type(server.sockets) == "table"
end

--- Check that a table has everything it needs to be a valid socket.
--- @param socket? table
--- @return boolean
function cryptoNet.socketValid(socket)
    return type(socket) == "table"
        and type(socket.sender) == "string"
        and type(socket.target) == "string"
        and cryptoNet.keyValid(socket.key)
        and type(socket.modemSide) == "string"
        and type(socket.channel) == "number"
        and type(socket.permissionLevel) == "number"
        and type(socket.receivedMessages) == "table"
end

--- Check that all the entries in a user table are valid.
--- @param userTable? table
--- @return boolean
function cryptoNet.userTableValid(userTable)
    if type(userTable) ~= "table" then
        return false
    end
    for username, entry in pairs(userTable) do
        if type(username) ~= "string" or type(entry[1]) ~= "table" or type(entry[2]) ~= "number" then
            return false
        end
    end
    return true
end

--
-- HELPERS
--

--- Used to process modem side arguments passed to functions.
--- @param modemSide? string
--- @return string
function cryptoNet.resolveModemSide(modemSide)
    -- If no modem side argument is provided, search for a modem and use that side.
    if modemSide == nil then
        for _, side in pairs(peripheral.getNames()) do
            if peripheral.getType(side) == "modem" then
                modemSide = side
                break
            end
        end
        if modemSide == nil then
            error("Could not find a modem.", 3)
        end
    else
        -- If an argument was provided, check that it is a valid side.
        local found = false
        for _, side in pairs(redstone.getSides()) do
            if side == modemSide then
                found = true
                break
            end
        end
        if not found then
            error(tostring(modemSide) .. " is not a valid side.", 3)
        end
    end
    if peripheral.getType(modemSide) ~= "modem" then
        error("No modem on side " .. modemSide .. ".", 3)
    end

    log("Using modem " .. modemSide .. ".")
    return modemSide
end

--- Decides which channel a server should communicate on, based on its name. This function will always return the same channel for a given server name, allowing clients to find out the channel of a server without any prior communications with it.
--- @param serverName string
--- @return number
function cryptoNet.getChannel(serverName)
    local nameHash = Sha256.digest(serverName)
    -- Use the first two bytes of the hash as the channel number, so that the full range
    -- of acceptable channels can be used.
    local channel = nameHash[1] + nameHash[2] * 2 ^ 8
    -- Avoid clashing with the lower channels, which are likely being used by
    -- standard Rednet users.
    if channel < 100 then
        channel = channel + 100
        -- Reserve the highest channels for Rednet and CryptoNet's internal use.
    elseif channel > 65530 then
        channel = channel - 5
    end

    return channel
end

--- Check if any servers or sockets on this machine are using the specified channel on the specified modem.
--- @param channel number
--- @param modemSide string
--- @return boolean
function cryptoNet.channelInUse(channel, modemSide)
    -- Check the client sockets.
    for _, socket in pairs(allClientSockets) do
        if socket.channel == channel and socket.modemSide == modemSide then
            return true
        end
    end
    -- Check the server channels.
    for _, server in pairs(allServers) do
        if server.channel == channel and server.modemSide == modemSide then
            return true
        end
    end

    return false
end

-- Convert a table of bytes into a string.
local function bytesToString(bytes)
    local str = ""
    for _, byte in pairs(bytes) do
        local ok, char = pcall(string.char, byte)
        -- If there are invalid bytes in the string, return nil without raising an error.
        -- This is to prevent attackers from crashing the system by sending invalid characters
        -- in encrypted messages.
        if not ok then
            return nil
        end
        str = str .. char
    end
    return str
end


-- Serialize pretty much any Lua data type as a string so that it can be encrypted
-- and sent over CryptoNet.  The resulting string starts with a characer
-- identifying the type of the data, followed by a string representation of the data.
local function serializeAny(value)
    if type(value) == "nil" then
        return "x"
    elseif type(value) == "boolean" then
        return value and "b1" or "b0"
    elseif type(value) == "number" then
        return "n" .. tostring(value)
    elseif type(value) == "string" then
        return "s" .. value
    elseif type(value) == "table" then
        return "t" .. textutils.serialize(value)
    else
        error("Can't serialize " .. type(value) .. "s.", 2)
    end
end


-- Deserialize data serialized by serializeAny.
local function deserializeAny(str)
    local typeChar = str:sub(1, 1)
    local valueStr = str:sub(2)
    if typeChar == "x" then
        return nil
    elseif typeChar == "b" then
        return valueStr == "1"
    elseif typeChar == "n" then
        return tonumber(valueStr)
    elseif typeChar == "s" then
        return valueStr
    elseif typeChar == "t" then
        return textutils.unserialize(valueStr)
    else
        error("Invalid type character: " .. typeChar, 2)
    end
end


--- Serialize a certificate or RSA key into a string, for saving to a file. The textutils functions don't seem to like the huge strings of numbers in the keys, so quotation marks must be added to them before serialization, which is what this function does.
--- @param obj Certificate|Key|nil
--- @return string
function cryptoNet.serializeCertOrKey(obj)
    if type(obj) ~= "table" then
        error("Can only serialize tables.", 2)
    end
    -- Add the certificate name, if it exists.
    local output = { name = obj.name }

    -- If this is a key, add its number string parts with quotes around them
    -- to keep textutils happy.
    if type(obj.public) == "string" then
        output.public = "\"" .. obj.public .. "\""
    end
    if type(obj.private) == "string" then
        output.private = "\"" .. obj.private .. "\""
    end
    if type(obj.shared) == "string" then
        output.shared = "\"" .. obj.shared .. "\""
    end

    -- If this is a certificate with a key, do the above for the key.
    if type(obj.key) == "table" then
        output.key = {}
        if type(obj.key.public) == "string" then
            output.key.public = "\"" .. obj.key.public .. "\""
        end
        if type(obj.key.private) == "string" then
            output.key.private = "\"" .. obj.key.private .. "\""
        end
        if type(obj.key.shared) == "string" then
            output.key.shared = "\"" .. obj.key.shared .. "\""
        end
    end

    -- If the certificate has a signature, that must have quotes as well.
    if type(obj.signature) == "string" then
        output.signature = "\"" .. obj.signature .. "\""
    end

    -- Serialize the table as normal.
    return textutils.serialize(output)
end

--- Deserialize certificates or RSA keys serialized by serializeCertOrKey(). This involves deserializing as normal and removing the quotation marks added during serialization.
--- @param str string
--- @return Certificate|Key|nil
function cryptoNet.deserializeCertOrKey(str)
    if str == nil then return nil end
    -- Deserialize as normal.
    local output = textutils.unserialize(str)
    if type(output) ~= "table" then
        return output
    end

    -- If this is a key, remove the quotes from the number string parts.
    if type(output.public) == "string" then
        output.public = string.gsub(output.public, "\"", "")
    end
    if type(output.private) == "string" then
        output.private = string.gsub(output.private, "\"", "")
    end
    if type(output.shared) == "string" then
        output.shared = string.gsub(output.shared, "\"", "")
    end

    -- If this is a certificate with a key, do the above for the key.
    if output.key ~= nil then
        if type(output.key.public) == "string" then
            output.key.public = string.gsub(output.key.public, "\"", "")
        end
        if type(output.key.private) == "string" then
            output.key.private = string.gsub(output.key.private, "\"", "")
        end
        if type(output.key.shared) == "string" then
            output.key.shared = string.gsub(output.key.shared, "\"", "")
        end
    end

    if type(output.signature) == "string" then
        output.signature = string.gsub(output.signature, "\"", "")
    end

    return output
end

--- Generate random 16 byte sequence that can be used as a key or initialization vector for AES encryption.
--- @return table<number>
function cryptoNet.generateKey()
    local iv = {}
    -- Convert four 4-byte integers into 16 bytes.
    for j = 1, 4 do
        local num = Isaac.random()
        for i = 0, 3 do
            -- Extract 8 bits at a time, by shifting right and applying a mask.
            table.insert(iv, bit.band(bit.brshift(num, 8 * i), 2 ^ 8 - 1))
        end
    end
    return iv
end

--- Generate an unsigned certificate and corresponding private key for a server with the given name. The certificate is distributed to clients, who can use the public key it contains to encrypt messages using RSA such that only this server can read them, using the private key.
--- @param name string
--- @return Certificate, PrivateKey
function cryptoNet.generateCertificate(name)
    log("Generating keys... (may take some time)")
    local publicKey, privateKey = RsaKeygen.generateKeyPair()
    print("")
    log("Done!")
    -- The certificate contains the name and public key of the server.
    return { name = name, key = publicKey }, privateKey
end

--- Load a certificate authority public key from the specified file and validate it, or just validate the key itself if passed directly as the argument. If key is left nil, a default filename of "certAuth.key" is used.
--- @param key? string|PublicKey (default: "certAuth.key") The file to load the key from, or the key itself to validate.
--- @return Certificate|Key|nil
function cryptoNet.loadCertAuthKey(key)
    if key == nil then
        -- Default value.
        key = "certAuth.key"
    end
    -- If key is a file path...
    if type(key) == "string" then
        local keyFilename = key
        -- Make paths relative to the current CryptoNet working directory.
        local keyPath = workingDir == "" and keyFilename or workingDir .. "/" .. keyFilename
        log("Checking " .. keyPath .. " for cert auth key...")
        if fs.isDir(keyPath) or not fs.exists(keyPath) then
            if fs.isDir(keyPath) then
                log(keyFilename .. " is not a file, will not be able to verify signatures.")
            else
                log(keyFilename .. " does not exist, will not be able to verify signatures.")
            end
            return nil
        else
            local file = fs.open(keyPath, "r")
            key = cryptoNet.deserializeCertOrKey(file.readAll())
            file.close()

            if not cryptoNet.publicKeyValid(key) then
                log(keyFilename .. " does not contain a valid cert auth key, will not be able to verify signatures.")
                return nil
            else
                log("Loaded cert auth key from " .. keyFilename .. ".")
                return key
            end
        end
        -- If the argument is not a string it should be the key table itself,
        -- so just validate it and return unchanged if valid.
    elseif cryptoNet.publicKeyValid(key) then
        return key
    else
        log("Invalid cert auth key, won't be able to verify signatures.")
        return nil
    end
end

--- Verify that the signature on a certificate is valid, using the public key of the trusted certificate authority.
--- @param certificate Certificate
--- @param key PublicKey
--- @return boolean
function cryptoNet.verifyCertificate(certificate, key)
    -- Signatures are made by encrypting the certificate's hash using the cert auth's private key.
    -- If the signature was generated by the certificate authority that uses the provided public key,
    -- decrypting the signature with this key should yield the certificate's hash.

    -- Find the hash of the certificate.
    local hash = Sha256.digest(certificate.name .. certificate.key.public .. certificate.key.shared)
    -- Decrypt the signature using the provided public key.
    local sigHash = RsaCrypt.bytesToString(RsaCrypt.numberToBytes(RsaCrypt.crypt(key, certificate.signature), 32 * 8, 8))
    -- See whether the decrypted signature matches the expected hash.
    return tostring(hash) == sigHash
end

--
-- SEND FUNCTIONS
--

-- Send an unencrypted message in the Rednet format using the cryptoNet protocol.
-- CryptoNet uses this internally for sending various message types.
-- If enabled, this function will also send every message it sends on the Rednet
-- repeat channel, allowing the Rednet repeat command to repeat CryptoNet messages.
-- Since these messages are in the format Rednet uses, CryptoNet should be fully
-- compatible with any networking systems designed for Rednet.
local function sendInternal(modemSide, channel, target, message, msgType, sender)
    -- Generate the message in exactly the same format as Rednet.
    local nMessageID = math.random(1, 2147483647)
    local tMessage = {
        nMessageID = nMessageID,
        nRecipient = channel,
        message = { message = message, msgType = msgType, target = target, sender = sender },
        sProtocol = "cryptoNet",
    }

    local modem = peripheral.wrap(modemSide)
    modem.transmit(channel, channel, tMessage)
    -- Allow Rednet repeaters to repeat the message if enabled.
    if repeatMessages then
        modem.transmit(rednet.CHANNEL_REPEAT, channel, tMessage)
    end
end


-- Send an encrypted internal message. Unlike the user-facing send() function,
-- this one only allows strings to be sent.
local function sendEncryptedInternal(socket, message)
    if type(message) ~= "string" then
        error("Message must be a string.", 2)
    end
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end
    -- Use unique IVs for every message.
    local iv = cryptoNet.generateKey()
    local ok, encrypted = pcall(Aes.encrypt_str, message, socket.key, iv)
    if ok then
        -- Send the encrypted message and the IVs used to generate it.
        -- We have to send the encrypted string as a table of bytes, because some of
        -- the special characters in the string seem to get lost in transmission otherwise.
        sendInternal(socket.modemSide, socket.channel, socket.target, { { string.byte(encrypted, 1, encrypted:len()) },
            iv }, "encrypted_message", socket.sender)
    else
        error("Encryption failed: " .. encrypted:sub(8), 2)
    end
end


--- Send an encrypted message over the given socket. The message can be pretty much any Lua data type.
--- @param socket Socket
--- @param message any
function cryptoNet.send(socket, message)
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end
    -- Convert the message to a string before sending, so it can be encrypted.
    -- It will be deserialized at the other end.
    sendEncryptedInternal(socket, serializeAny(message))
end

--- Send an unencrypted message over CryptoNet. Useful for streams of high speed, non-sensitive data. Unencrypted messages have no security features applied, so can be easily exploited by attackers. Only use for non-critical messages.
--- @param socket Socket
--- @param message string
function cryptoNet.sendUnencrypted(socket, message)
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end
    -- Just send the message as-is.
    sendInternal(socket.modemSide, socket.channel, socket.target, message, "plain_message", socket.sender)
end

--
-- LOGIN SYSTEM
--

--- Hash a password using the username and server name as a salt. Used to secure passwords before they are sent over CryptoNet to a server. Technically this is unnecessary as the connection is encrypted anyway, but it means that even if this is somehow compromised (e.g. with a spoof attack) the attacker won't know the actual password and be able to use it on the user's other accounts, if they use the same password for multiple things.
--- @param username string
--- @param password string
--- @param serverName string
--- @return string
function cryptoNet.hashPassword(username, password, serverName)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end
    if type(serverName) ~= "string" then
        error("Server name must be a string.", 2)
    end

    return tostring(Sha256.digest(serverName .. username .. password))
end

--- Load the user table stored at the given path, defaulting to an empty table if the file does not exist.
--- @param path string
--- @return table
function cryptoNet.loadUserTable(path)
    if type(path) ~= "string" then
        error("Path must be a string.", 2)
    end
    if not fs.exists(path) then
        log(path .. " does not exist, creating empty user table.")
        return {}
    end
    if fs.isDir(path) then
        error(path .. " is not a file, could not load user table.", 2)
    end

    local file = fs.open(path, "r")
    local userTable = textutils.unserialize(file.readAll())
    file.close()

    if not cryptoNet.userTableValid(userTable) then
        error(path .. " does not contain a valid user table, user table could not be loaded.", 2)
    end

    log("Loaded user table from " .. path .. ".")
    return userTable
end

--- Save the given user table to the given file.
--- @param userTable table
--- @param path string
function cryptoNet.saveUserTable(userTable, path)
    if type(path) ~= "string" then
        error("Path must be a string.", 2)
    end
    if not cryptoNet.userTableValid(userTable) then
        error("Not a valid user table", 2)
    end

    if fs.isDir(path) then
        error(path .. " already exists and is a directory.", 2)
    end

    local file = fs.open(path, "w")
    file.write(textutils.serialize(userTable))
    file.close()
    log("Saved user table to " .. path .. ".")
end

--- Add a user to the given server with the provided details. The provided password should already have been hashed by hashPassword(). Default permission level is 1. If there is only one server running, that server will be used by default.
--- @param username string
--- @param passHash string
--- @param permissionLevel? number
--- @param server? Server
function cryptoNet.addUserHashed(username, passHash, permissionLevel, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(passHash) ~= "string" then
        error("Password hash must be a string.", 2)
    end
    if permissionLevel == nil then
        permissionLevel = 1
    elseif type(permissionLevel) ~= "number" then
        error("Permission level must be a number", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] ~= nil then
        error("User " .. username .. " already exists.", 2)
    end

    -- The password is hashed again before going in the database, so that even if
    -- an attacker has access to this file they do not have the original password
    -- required to log into the server from the outside.
    -- PBKDF2 is used over the standard SHA256 digest as it is theoretically harder
    -- to crack.
    server.userTable[username] = { Sha256.pbkdf2(passHash, server.name .. username, 8), permissionLevel }
    log("Added user " .. username .. ".")
    cryptoNet.saveUserTable(server.userTable, server.userTablePath)
end

--- Add a user to the given (local) server's user table with the provided details. The user table is saved to disk, so is non volatile. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param password string
--- @param permissionLevel? number
--- @param server? Server
function cryptoNet.addUser(username, password, permissionLevel, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end
    if permissionLevel == nil then
        permissionLevel = 1
    elseif type(permissionLevel) ~= "number" then
        error("Permission level must be a number", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] ~= nil then
        error("User " .. username .. " already exists.", 2)
    end

    -- When users log into the server remotely their passwords will be hashed
    -- before being sent, so we must perform the same process here before
    -- adding it to the table.
    cryptoNet.addUserHashed(username, cryptoNet.hashPassword(username, password, server.name), permissionLevel, server)
end

--- Remove a user from a server. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
function cryptoNet.deleteUser(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        error("No user called " .. username .. ".", 2)
    else
        server.userTable[username] = nil
        log("Deleted user " .. username .. ".")
        cryptoNet.saveUserTable(server.userTable, server.userTablePath)
    end
end

--- Check if a user exists on the server. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return boolean
function cryptoNet.userExists(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    return server.userTable[username] ~= nil
end

--- Get the hashed password of a user from the users table. The original password cannot be (easily) retrieved from this hash. Returns nil if the user does not exist. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return string|nil
function cryptoNet.getPasswordHash(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        return nil
    end
    return server.userTable[username][1]
end

--- Get the permission level of a user. Returns nil if the user does not exist. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return number|nil
function cryptoNet.getPermissionLevel(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        return nil
    end
    return server.userTable[username][2]
end

--- Set the hashed password of a user in the table. Assumes the provided passowrd has already been hashed with hashPassword(). The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param passHash string
--- @param server Server
function cryptoNet.setPasswordHashed(username, passHash, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(passHash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    -- Hash the password again before storing.
    server.userTable[username][1] = Sha256.pbkdf2(passHash, server.name .. username, 8)
    log("Updated password for " .. username .. ".")
    cryptoNet.saveUserTable(server.userTable, server.userTablePath)
end

--- Sets the password of a user in the table. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param password string
--- @param server Server
function cryptoNet.setPassword(username, password, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    -- Hash the password before adding, to mimic the hashing performed by clients
    -- logging in remotely.
    cryptoNet.setPasswordHashed(username, cryptoNet.hashPassword(username, password, server.name), server)
end

--- Set the permission level of a user in the table. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param permissionLevel number
--- @param server Server
function cryptoNet.setPermissionLevel(username, permissionLevel, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(permissionLevel) ~= "number" then
        error("Permission level must be a number.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    server.userTable[username][2] = permissionLevel
    log("Updated permission level for " .. username .. ".")
    cryptoNet.saveUserTable(server.userTable, server.userTablePath)
end

--- Check that the given password matches the one in the table. Assumes the password has already been hashed by hashPassword(). The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param passHash string
--- @param server Server
--- @return boolean|nil
function cryptoNet.checkPasswordHashed(username, passHash, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(passHash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    if server.userTable[username] == nil then
        return nil
    end

    -- Since we can't unhash the passwords in the table, we must instead
    -- hash the query password and compare it to the hash in the table.
    -- If they are the same, then the original passwords were the same.
    local hash = Sha256.pbkdf2(passHash, server.name .. username, 8)
    -- Check if all the bytes of the hashes are equal.
    for i = 1, #hash do
        if hash[i] ~= server.userTable[username][1][i] then
            return false
        end
    end
    return true
end

--- Check that the given password matches the one in the table. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param password string
--- @param server Server
--- @return boolean|nil
function cryptoNet.checkPassword(username, password, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #allServers == 0 then
            error("No servers running.", 2)
        elseif #allServers == 1 then
            server = allServers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not cryptoNet.serverValid(server) then
        error("Invalid server.", 2)
    end

    -- Mimic the client-side hashing before checking.
    return cryptoNet.checkPasswordHashed(username, cryptoNet.hashPassword(username, password, server.name), server)
end

--- Log into the server connected to this socket, remote or local, with the specified username and password. Assumes the password has already been hashed by hashPassword(). If executed on a server socket, the event details of the attempt are returned. If successful, the user's details will be stored in the socket. If the socket is already logged in, the username will be overwritten but the permission level will be set to the highest of the old and new one. This allows an admin account to log in then log in as a normal user to temporarily gain elevated privileges as that account.
--- @param socket Socket
--- @param username string
--- @param passHash string
--- @return string|nil
--- @return string|nil
--- @return Socket|nil
--- @return Server|nil
function cryptoNet.loginHashed(socket, username, passHash)
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(passHash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    if socket.server == nil then
        -- If this is a client socket, send a login request to the server.
        sendEncryptedInternal(socket, "lr" .. textutils.serialize({ username, passHash }))
        log("Sent login request for " .. username .. " to " .. socket.target .. ".")
    else
        -- If this is a server socket, try to log in as the user
        -- and send the result to the client.
        if socket.server.userTable[username] == nil then
            log("Failed login attempt for " .. username .. ".")
            sendEncryptedInternal(socket, "lf" .. username)
            return "login_failed", username, socket, socket.server
        else
            if cryptoNet.checkPasswordHashed(username, passHash, socket.server) then
                -- If the password was correct, log the user into the socket.
                socket.username = username
                -- Set the permission level to the greatest of the socket's original
                -- permission level and the new one, so admins can temporarily transfer
                -- their elevated rights to normal accounts.
                socket.permissionLevel = math.max(socket.permissionLevel, cryptoNet.getPermissionLevel(username, socket.server))
                -- Tell the client-side socket that the attempt was successful, so it can
                -- change its details as well.
                sendEncryptedInternal(socket, "ls" .. textutils.serialize({ username, socket.permissionLevel }))
                log(username .. " logged in successfully.")
                return "login", username, socket, socket.server
            else
                log("Failed login attempt for " .. username .. ".")
                sendEncryptedInternal(socket, "lf" .. username)
                return "login_failed", username, socket, socket.server
            end
        end
    end
end

--- Log into the server connected to this socket, remote or local,with the specified username and password. The password will be hashed before sending for extra security.If executed on a server socket, the event details of the attempt are returned. If successful, the user's details will be stored in the socket. If the socket is already logged in, the username will be overwrittenbut the permission level will be set to the highest of the old and new one.This allows an admin account to log in then log in as a normal userto temporarily gain elevated privileges as that account.
--- @param socket Socket
--- @param username string
--- @param password string
--- @return string|nil
--- @return string|nil
--- @return Socket|nil
--- @return Server|nil
function cryptoNet.login(socket, username, password)
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- Get the server name based on whether this is a client or server socket.
    local serverName = socket.server == nil and socket.target or socket.sender
    -- Hash the password before sending.
    return cryptoNet.loginHashed(socket, username, cryptoNet.hashPassword(username, password, serverName))
end

--- Log out of the user account currently logged in on this socket. If executed on a server socket, the event details are returned.
--- @param socket Socket|Server
function cryptoNet.logout(socket)
    if not cryptoNet.socketValid(socket) then
        error("Invalid socket.", 2)
    end

    -- Tell the other end to log out as well.
    sendEncryptedInternal(socket, "lo")
    if socket.server == nil then
        -- If this is a client socket, all we can do is ask the server to log out.
        -- The actual logging out is only performed once a response is received
        -- from the server.
        log("Sent logout request to " .. socket.target .. ".")
    else
        -- If this is a server socket, we can actually logout.
        local username = socket.username
        socket.username = nil
        socket.permissionLevel = 0

        if username == nil then
            log("Already logged out.")
        else
            log(username .. " logged out.")
        end
        return "logout", username, socket, server
    end
end

--
-- CORE NETWORKING
--

-- Check if a Rednet-format message is a CryptoNet one, and return its contents
-- if so. If it is invalid or has been processed before nil is returned.
local function extractMessage(message, receivedIDs)
    -- Check the list of alrady received message IDs to see if any of them are
    -- more than 5 seconds old and can be deleted. The purpose of this list is
    -- to avoid processing messages processed by Rednet's repeat program
    -- more than once, but repeat is unlikely to take 5 seconds to repeat a message.
    -- Since the message IDs are randomly generated, it is good to remove them
    -- from the list as soon as possible to reduce the chance of a future message
    -- with same ID from being blocked.
    -- Note that CryptoNet has a seperate more advanced system for preventing
    -- attackers from sending the same encrypted message twice, handled elsewhere.
    local toDelete = {}
    for id, time in pairs(receivedIDs) do
        -- List the ID for deletion if it is more than 5 seconds old.
        if os.clock() - time > 5 then
            table.insert(toDelete, id)
        end
    end
    -- Remove all the deleted IDs.
    for _, id in pairs(toDelete) do
        receivedIDs[id] = nil
    end

    -- Check that the message follows the Rednet format and is using the cryptoNet protocol.
    if type(message) == "table" and message.sProtocol == "cryptoNet" and type(message.message) == "table" and type(message.nMessageID) == "number" then
        -- If this message ID has not been received already recently,
        -- return the message contents.
        if not receivedIDs[message.nMessageID] then
            receivedIDs[message.nMessageID] = os.clock()
            return message.message
        end
        -- Always keep the latest timestamp of the ID.
        receivedIDs[message.nMessageID] = os.clock()
    end
    return
end


--- Create and host a CryptoNet server, which other machines can remotely connect to. This function will load the certificate and private key of the server from the specified files, or generate new ones if no existing files are found. Note that serverName is the only required parameter; all the others have sensible defaults.
--- @param serverName string The name of the server, which clients will use to connect to it.     Also determines the channel that the server communicates on.
--- @param discoverable? boolean (default: true) Whether this server responds to discover() requests. Disabling this is more secure as it means clients can't connect unless they already know the name of the server.
--- @param hideCertificate? boolean (default: false) If true the server will not distribute its certificate to clients,  either in discover() or connect() requests, meaning clients can only  connect if they have already been given the certificate manually.  Useful if you only want certain manually authorised clients to be able to connect.
--- @param modemSide? string (default: a side that has a modem) The modem the server should use. certificate (table or string, default: "<serverName>.crt") The certificate of the server. This can either be the certificate table itself, or the name of a file that contains it. If the certicate and key files do not  exist, new ones will be generated and saved to the specified files.
--- @param privateKey? table|string (default: "<serverName>_private.key") The private key of the server. This can either be the key table itself,  or the name of a file that contains it. If the certicate and key files do not  exist, new ones will be generated and saved to the specified files.
--- @param userTablePath? string (default: "<serverName>_users.tbl") Path at which to store the user login details table,   if/when users are added to the server.
--- @return Server # The server table
function cryptoNet.host(serverName, discoverable, hideCertificate, modemSide, certificate, privateKey, userTablePath)
    if type(serverName) ~= "string" then
        error("Server name must be a string.", 2)
    end
    -- Don't allow duplicate server names.
    for _, server in pairs(allServers) do
        if server.name == serverName then
            error("Server called " .. serverName .. " already exists.", 2)
        end
    end

    modemSide = cryptoNet.resolveModemSide(modemSide)
    local modem = peripheral.wrap(modemSide)

    -- Generate default file names if none were provided, then get the paths
    -- relative to the current working directory.
    local certFilename = type(certificate) == "string" and certificate or serverName .. ".crt"
    local keyFilename = type(privateKey) == "string" and privateKey or serverName .. "_private.key"
    local certificatePath = workingDir == "" and certFilename or workingDir .. "/" .. certFilename
    local keyPath = workingDir == "" and keyFilename or workingDir .. "/" .. keyFilename

    -- Now that we've extracted the filenames above, only store the actual certificate
    -- and key in these variables.
    if type(certificate) == "string" then certificate = nil end
    if type(privateKey) == "string" then privateKey = nil end

    if certificate ~= nil and not cryptoNet.certificateValid(certificate) then
        error("Invalid certificate.", 2)
    end
    if privateKey ~= nil and not cryptoNet.privateKeyValid(privateKey) then
        error("Invalid private key.", 2)
    end

    -- Try loading the certificate from file.
    if certificate == nil then
        log("Checking " .. certificatePath .. " for certificate...")
        if fs.isDir(certificatePath) then
            error(certFilename .. " already exists and is a directory, not a certificate.", 2)
        elseif fs.exists(certificatePath) then
            local file = fs.open(certificatePath, "r")
            certificate = cryptoNet.deserializeCertOrKey(file.readAll())
            file.close()

            if not cryptoNet.certificateValid(certificate) then
                error(certFilename .. " already exists and is not a valid certificate.", 2)
            else
                log("Loaded certificate from " .. certFilename .. ".")
            end
        else
            log("Certificate file not found, will need to generate a new one.")
        end
    end

    -- Try loading the private key from file.
    if privateKey == nil then
        log("Checking " .. keyPath .. " for private key...")
        if fs.isDir(keyPath) then
            error(keyFilename .. " already exists and is a directory, not a keyfile.", 2)
        elseif fs.exists(keyPath) then
            local file = fs.open(keyPath, "r")
            privateKey = cryptoNet.deserializeCertOrKey(file.readAll())
            file.close()

            if not cryptoNet.privateKeyValid(privateKey) then
                error(keyFilename .. " already exists and is not a valid keyfile.", 2)
            else
                log("Loaded private key from " .. keyFilename .. ".")
            end
        else
            log("Private keyfile not found, will need to generate a new one.")
        end
    end

    -- If we have no certificate or private key yet, generate them.
    -- You can't just provide one and not the other, as the public and private
    -- keys must be generated as a pair.
    if certificate == nil and privateKey == nil then
        log("No certificate or private key found, generating new ones.")
        certificate, privateKey = cryptoNet.generateCertificate(serverName)

        local file = fs.open(certificatePath, "w")
        file.write(cryptoNet.serializeCertOrKey(certificate))
        file.close()
        log("Saved certificate to " .. certificatePath .. ".")

        file = fs.open(keyPath, "w")
        file.write(cryptoNet.serializeCertOrKey(privateKey))
        file.close()
        log("Saved private key to " .. keyPath .. ".  Do not share this with anyone!")
    elseif certificate ~= nil and privateKey == nil then
        error("Have a certificate but not a private key, need both or neither.", 2)
    elseif certificate == nil and privateKey ~= nil then
        error("Have a private key but not a certificate, need both or neither.", 2)
    end

    -- It is possible for an attacker to host a server with the same name as yours,
    -- confusing and tricking clients. Having a certifiate authority sign
    -- the certificates of trusted servers prevents this.
    if certificate.signature == nil then
        log("Warning: Your certificate does not have a signature.")
    else
        log("Certificate is signed.")
    end

    -- Open the server's channel (derived from the server name) so it can be used
    -- for communication.
    local channel = cryptoNet.getChannel(serverName)
    modem.open(channel)
    log("Hosting on channel " .. channel .. ".")

    if hideCertificate then
        log("Your server is set to require clients to already have its certificate in order to connect to it.")
    end

    -- Allow clients to use discover() to get the name and certificate
    -- of this server without prior knowledge of it.
    if discoverable or discoverable == nil then
        modem.open(DISCOVERY_CHANNEL)
        log("Your server is discoverable.")
    else
        log("Your server is not discoverable.")
    end

    -- Load the server's user table from file, or create a new one if none was found.
    if userTablePath == nil then
        userTablePath = serverName .. "_users.tbl"
    end
    local userTable
    if type(userTablePath) == "string" then
        -- Append the current working directory to the table path.
        userTablePath = workingDir == "" and userTablePath or workingDir .. "/" .. userTablePath
        userTable = cryptoNet.loadUserTable(userTablePath)
    else
        error("userTablePath must be a string.", 2)
    end

    -- Create the server table.
    local server = {
        name = serverName,
        certificate = certificate,
        privateKey = privateKey,
        modemSide = modemSide,
        channel = channel,
        hideCertificate = hideCertificate,
        discoverable = discoverable or discoverable == nil, -- Default to true
        userTable = userTable,
        userTablePath = userTablePath,
        sockets = {} -- New servers have no connections yet.
    }

    table.insert(allServers, server)
    log("Server ready.")
    return server
end

--- Close a socket or server, such that it will not listen for messages anymore. Closing a server closes all its sockets.
--- @param socket Socket|Server The socket or server to close.
function cryptoNet.close(socket)
    if cryptoNet.socketValid(socket) then
        -- Let the other end of the socket know it has been closed.
        -- Don't send if this one was closed remotely, since the other end clearly
        -- already knows.
        if not socket.closedRemotely then
            sendEncryptedInternal(socket, "c")
        end
        if socket.server == nil then
            -- If this is a client socket, remove it from the list of client sockets.
            -- This will stop handleModemEvent() from processing messages for it.
            for i = 1, #allClientSockets do
                if allClientSockets[i] == socket then
                    table.remove(allClientSockets, i)
                    break
                end
            end
        else
            -- If this is a server socket, remove it from the server's socket list.
            -- This will stop handleModemEvent() from processing messages for it.
            socket.server.sockets[socket.target] = nil
        end

        -- If this was the only socket communicating on its channel, close the channel
        -- on the modem. Don't close the channel if another socket is still using it.
        if not cryptoNet.channelInUse(socket.channel, socket.modemSide) then
            peripheral.wrap(socket.modemSide).close(socket.channel)
            log("Closed socket channel " .. socket.channel .. " on modem " .. socket.modemSide .. ".")
        end
        log("Closed socket.")
    elseif cryptoNet.serverValid(socket) then
        -- If this is a server being closed...
        local server = socket
        -- Create a copy of the server's socket list and close them all.
        -- Closing a socket will remove it from the server's socket list,
        -- so we make a copy so it doesn't change while we're trying to iterate
        -- over it.
        local socketsCopy = {}
        for _, soc in pairs(server.sockets) do
            table.insert(socketsCopy, soc)
        end
        for _, soc in pairs(socketsCopy) do
            cryptoNet.close(soc)
        end

        -- Remove the closed server from the server list.
        -- This will stop handleModemEvent() from processing messages for it.
        for i = 1, #allServers do
            if allServers[i] == server then
                table.remove(allServers, i)
                break
            end
        end

        -- If this was the only server/socket communicating on its channel, close the channel
        -- on the modem. Don't close the channel if another socket is still using it.
        if not cryptoNet.channelInUse(server.channel, server.modemSide) then
            peripheral.wrap(server.modemSide).close(server.channel)
            log("Closed server channel " .. server.channel .. " on modem " .. server.modemSide .. ".")
        end

        -- If this was the only server using the discovery channel, close it.
        if server.discoverable then
            local found = false
            for _, srvr in pairs(allServers) do
                if srvr.discoverable and srvr.modemSide == server.modemSide then
                    found = true
                    break
                end
            end
            if not found then
                peripheral.wrap(server.modemSide).close(DISCOVERY_CHANNEL)
                log("Closed discovery channel.")
            end
        end
    else
        error("Must be a valid socket or server.", 2)
    end
end

-- Close all sockets and servers on this machine.
function cryptoNet.closeAll()
    -- Iteratve backwards so the list isn't chaning in front of us.
    for i = #allClientSockets, 1, -1 do
        cryptoNet.close(allClientSockets[i])
    end
    for i = #allServers, 1, -1 do
        cryptoNet.close(allServers[i])
    end
    log("Closed all sockets and servers.")
end

-- Process an encrypted message sent over CryptoNet to a socket, that has already been decrypted. Decrypted messages start with one or two characters that specify the type
-- of the message, which may either be an internal message (e.g. login requests)
-- or an encrypted message sent by a user using the send() function.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs. Also returns a status boolean to say whether the
-- message turned out to have a valid format.
local function handleDecryptedMessage(socket, message)
    local ok = true
    local result = nil
    if message == "c" then
        log("Connection closed by other end.")
        socket.closedRemotely = true
        -- Close our end of the socket too.
        cryptoNet.close(socket)
        socket.closedRemotely = nil
        result = { "connection_closed", socket, socket.server }
    elseif message:sub(1, 2) == "lr" then
        -- Login requests have the format lr{username,password}
        -- Note that the password will have already been hashed using hashPassword()
        -- by the client before sending.
        local request = textutils.unserialize(message:sub(3))
        if type(request) == "table" and type(request[1]) == "string" and type(request[2]) == "string" then
            result = { cryptoNet.loginHashed(socket, request[1], request[2]) }
        else
            ok = false
        end
    elseif message:sub(1, 2) == "lf" then
        -- Runs on client when server says the login failed. Format: lfusername
        log("Failed login attempt for " .. message:sub(3) .. ".")
        result = { "login_failed", message:sub(3), socket, socket.server }
    elseif message:sub(1, 2) == "ls" then
        -- Runs on client when server says the login was successful.
        -- Format: ls{username,permissionLevel}
        local details = textutils.unserialize(message:sub(3))
        if type(details) == "table" and type(details[1]) == "string" and type(details[2]) == "number" then
            socket.username = details[1]
            socket.permissionLevel = details[2]
            log(socket.username .. " logged in successfully.")
            result = { "login", socket.username, socket, socket.server }
        else
            -- Response was invalid.
            ok = false
        end
    elseif message == "lo" then
        -- Logout.
        if socket.server == nil then
            -- On client side just reset the user details, the server will already
            -- have logged out its socket.
            local username = socket.username
            socket.username = nil
            socket.permissionLevel = 0

            if username == nil then
                log("Already logged out.")
            else
                log(username .. " logged out.")
            end
            result = { "logout", username, socket, nil }
        else
            -- On server side call logout() to also send a message to the client
            -- to tell it to log out.
            result = { cryptoNet.logout(socket) }
        end
    else
        -- If the message had none of the above internal message types,
        -- it must be a user-generated encrypted message, which will start with
        -- a data type character. Attempt to deserialize the message as such.
        ok, message = pcall(deserializeAny, message)
        if ok then
            result = { "encrypted_message", message, socket, socket.server }
        end
    end
    return ok, result
end


-- See if the given CryptoNet message is relevant to this server, and act upon
-- it as needed. May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleServerMessage(server, message, messageChannel)
    -- Check if this message is a discovery request,
    -- and respond to it if and only if the server is discoverable.
    if messageChannel == DISCOVERY_CHANNEL and message.msgType == "discovery_request" and server.discoverable then
        -- Remove the public key and signature from the certificate if needed.
        local certificate = server.hideCertificate and { name = server.name } or server.certificate
        sendInternal(server.modemSide, DISCOVERY_CHANNEL, nil, certificate, "discovery_response")
        log("Responded to discovery request.")
        -- If this is a message directed at this server...
    elseif messageChannel == server.channel and message.target == server.name then
        if message.msgType == "certificate_request" and not server.hideCertificate then
            sendInternal(server.modemSide, server.channel, nil, server.certificate, "certificate_response")
            log("Responded to certificate request.")
        elseif message.msgType == "connection_request" and type(message.message) == "string" then
            -- The client will have sent a session key, encryped using the server's public key.
            -- We need to use the private key to decrypt it and use the session key to send
            -- an acknowledgement to the client.
            local encryptedKey = message.message
            if server.sockets[encryptedKey] ~= nil then
                -- This is probably a repeated message, as we have already processed it before.
                log("Received duplicate connection request, ignoring it.")
            else
                -- Try to decrypt the session key using the server's private key.
                local ok, numKey = pcall(RsaCrypt.crypt, server.privateKey, encryptedKey)
                local sessKey
                ok, sessKey = pcall(RsaCrypt.numberToBytes, numKey, 16 * 8, 8)
                -- Validate the key, which should be a table of 16 bytes.
                if ok and (sessKey == nil or #sessKey ~= 16) then
                    ok = false
                end
                if not ok then
                    log("Received invalid session key.")
                else
                    -- Send a message back to the client encrypted with the session key
                    -- to prove that we have received it correctly.
                    -- The client knows what the message is supposed to be,
                    -- allowing it to validate it.
                    local response = tostring(Sha256.digest(server.name ..
                    server.certificate.key.public .. server.certificate.key.shared .. numKey))
                    -- Encrypt the message.
                    local iv = cryptoNet.generateKey()
                    response = Aes.encrypt_str(response, sessKey, iv)
                    -- From now on the client will be identified by it's encrypted session key.
                    sendInternal(server.modemSide, server.channel, encryptedKey,
                        { { string.byte(response, 1, response:len()) }, iv }, "connection_response")
                    log("Responded to connection request.")

                    -- Create the socket object pointing to the client.
                    local socket = {
                        sender = server.name,
                        target = encryptedKey,
                        key = sessKey,
                        modemSide = server.modemSide,
                        channel = server.channel,
                        server = server,
                        permissionLevel = 0,
                        receivedMessages = {}
                    }
                    server.sockets[encryptedKey] = socket
                    return { "connection_opened", socket, server }
                end
            end
        elseif message.msgType == "encrypted_message" and type(message.message) == "table" and #message.message == 2
            and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
            -- If this is an encrypted message, try decrypting it with the session key
            -- and handle the decrypted message as needed.
            local socket = server.sockets[message.sender]
            local encrypted = bytesToString(message.message[1])
            local iv = message.message[2]
            if socket == nil then
                log("Received a message from a sender who has yet to open a connection.")
            elseif encrypted == nil then
                log("Received invalid message.")
            elseif socket.receivedMessages[encrypted] then
                -- The encryption algorithm adds random numbers to each message before
                -- encrypting it, so even if two messages are identical their encrypted
                -- versions will probably be different. Therefore if we receive the exact
                -- same encrypted message twice it is most likely a malicious duplicate
                -- made by someone without the session key, and so should be ignored.
                log("Received duplicate message, ignoring it.")
            else
                -- Remember we have received this message so we don't accept it again
                -- (see above).
                socket.receivedMessages[encrypted] = true
                local ok, decrypted = pcall(Aes.decrypt_str, encrypted, socket.key, iv)
                if ok then
                    local ok, result = handleDecryptedMessage(socket, decrypted)
                    if ok and result ~= null then
                        return result
                    end
                end
                if not ok then
                    log("Received invalid message.")
                end
            end
        elseif message.msgType == "plain_message" then
            local socket = server.sockets[message.sender]
            if socket ~= nil then
                return { "plain_message", message.message, socket, server }
            else
                log("Received a message from a sender who has yet to open a connection.")
            end
        end
    end
end


-- See if the given CryptoNet message is relevant to this client socket, and act upon
-- it as needed.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleClientMessage(socket, message, messageChannel)
    -- If this is a message directed at this socket...
    if messageChannel == socket.channel and message.sender == socket.target and message.target == socket.sender then
        if message.msgType == "encrypted_message" and type(message.message) == "table" and #message.message == 2
            and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
            local encrypted = bytesToString(message.message[1])
            local iv = message.message[2]
            if encrypted == nil then
                log("Received invalid message.")
            elseif socket.receivedMessages[encrypted] then
                -- The encryption algorithm adds random numbers to each message before
                -- encrypting it, so even if two messages are identical their encrypted
                -- versions will probably be different. Therefore if we receive the exact
                -- same encrypted message twice it is most likely a malicious duplicate
                -- made by someone without the session key, and so should be ignored.
                log("Received duplicate message, ignoring it.")
            else
                socket.receivedMessages[encrypted] = true
                -- Decrypt the message with the session key and handle as needed.
                local ok, decrypted = pcall(Aes.decrypt_str, encrypted, socket.key, iv)
                if ok then
                    local ok, result = handleDecryptedMessage(socket, decrypted)
                    if ok then
                        return result
                    end
                end
                if not ok then
                    log("Received invalid message.")
                end
            end
        elseif message.msgType == "plain_message" then
            return { "plain_message", message.message, socket, nil }
        end
    end
end


-- Check if the given modem_message event is a CryptoNet message, and if so
-- decrypt and act upon it as needed.
--
-- receivedIDs: A table of recently received message IDs, used to block any
--     more messages with the same ID within a cooldown period, on the basis that they
--    are probably the same message repeated.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleModemEvent(event, receivedIDs)
    -- Check if the modem message was a CryptoNet-formatted message, and extract
    -- the message contents.
    local message = extractMessage(event[5], receivedIDs)
    if message ~= nil then
        -- Try passing the message to all servers on this machine.
        for _, server in pairs(allServers) do
            local result = handleServerMessage(server, message, event[3])
            if result ~= nil then
                return result
            end
        end

        -- Try passing the message to all client sockets on this machine.
        for _, socket in pairs(allClientSockets) do
            local result = handleClientMessage(socket, message, event[3])
            if result ~= nil then
                return result
            end
        end
    end

    return nil
end


-- Listens for and handles CryptoNet messages for all sockets and servers
-- on this machine. Returns when a message is received that invokes a
-- user-facing CryptoNet event, with the details of said event.
-- Should ideally be executed inside a while loop alongside event handling logic.
--
-- It is recommended that users use startEventLoop() over a listen() loop,
-- as it creates a new thread for each event received, allowing for calls to sleep()
-- and pullEvent() in event handling code without freezing the rest of the server.
function cryptoNet.listen()
    -- Message IDs recently received by this machine that we don't want to
    -- process repeat copies of.
    local receivedIDs = {}
    -- Keep listening for and handling modem_messages until
    -- a CryptoNet event is raised.
    while true do
        local event = { os.pullEvent("modem_message") }
        local newEvent = handleModemEvent(event, receivedIDs)
        if newEvent ~= nil then
            return table.unpack(newEvent)
        end
    end
end

--- Request the certificates of all online CryptoNet servers on the network. Some servers may have been set to not respond to discovery requests, and some will only contain the server name in the certificate, excluding the public key required to connect to the server. This function can optionally use a certificate authority public key to verify the signatures of certificates, only returning certificates with valid signatures. By default discover() looks for the public key in "certAuth.key".
--- @param timeout? number (default: 1) The time in seconds to spend listening for responses.
--- @param certAuthKey? PublicKey|string (default: "certAuth.key") The certificate authority public key used to verify signatures,   or the path of the file to load it from. If no valid key is found   the discovery will still go ahead, but signatures will not be checked.
--- @param allowUnsigned? boolean (default: false) Whether to include certificates with no valid signature in the results.   If no valid cert auth key is provided this is ignored, as the certificates   cannot be checked without a key.
--- @param modemSide? string (default: a side with a modem) The modem to use to send and receive messages.
--- @return table # a table of the certificates received, all of which will include the name of server and possibly also the public key and signature.
function cryptoNet.discover(timeout, certAuthKey, allowUnsigned, modemSide)
    -- Load and validate the key.
    certAuthKey = cryptoNet.loadCertAuthKey(certAuthKey)

    modemSide = cryptoNet.resolveModemSide(modemSide)
    local modem = peripheral.wrap(modemSide)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local wasOpen = modem.isOpen(DISCOVERY_CHANNEL)
    modem.open(DISCOVERY_CHANNEL)

    log("Discovering...")
    sendInternal(modemSide, DISCOVERY_CHANNEL, nil, nil, "discovery_request")

    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local receivedIDs = {}
    -- The received certificates.
    local certificates = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == DISCOVERY_CHANNEL then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extractMessage(event[5], receivedIDs)
            -- If this is a discovery_response with a correctly formatted certifiate...
            if message ~= nil and message.msgType == "discovery_response" and cryptoNet.certificateValid(message.message, true) then
                local certificate = message.message
                local found = false
                -- If we have already received an identical certificate don't add this one.
                for _, cert in pairs(certificates) do
                    if certificate.name == cert.name and ((certificate.key == nil and cert.key == nil) or (certificate.key ~= nil and cert.key ~= nil
                            and certificate.key.public == cert.key.public and certificate.key.shared == cert.key.shared)) and certificate.signature == cert.signature then
                        found = true
                        break
                    end
                end

                if not found then
                    table.insert(certificates, certificate)
                end
            end
        elseif event[1] == "timer" and event[2] == timer then
            -- Stop listening for events once the time is up.
            break
        end
    end

    -- Close the discovery channel if it wasn't open before we started.
    if not wasOpen then
        modem.close(DISCOVERY_CHANNEL)
    end

    -- If we have a valid cert auth key to use,
    -- verify the signatures of the received certificates.
    -- If allowUnsigned is false any certificates without valid signatures
    -- will be removed.
    if certAuthKey ~= nil and #certificates > 0 then
        log("Checking signatures...")
        -- Iterate backwards as we will be deleting from the list.
        for i = #certificates, 1, -1 do
            local certificate = certificates[i]
            if certificate.signature == nil then
                if not allowUnsigned then
                    log("Discarding " .. certificate.name .. " as it has no signature.")
                    table.remove(certificates, i)
                end
            else
                local ok, valid = pcall(cryptoNet.verifyCertificate, certificate, certAuthKey)
                if ok and valid then
                    -- Keep the certificate.
                    log(certificate.name .. " has a valid signature.")
                else
                    log("Discarding " .. certificate.name .. " as it has an invalid signature.")
                    table.remove(certificates, i)
                end
            end
        end
    end

    return certificates
end

--- Request the certificate of a server with the given name. Note that some servers may not respond to these requests, expecting trusted clients to have been given the certificate manually. All the certificates returned will contain the public key of their server. If multiple certificates are received with the same server name, there is no way to tell which one is the real server (the others are probably malicious fakes), so none of them are returned. To avoid this situation, this function can optionally use a certificate authority public key to verify the signatures of received certificates, ignoring any with invalid signatures. By default requestCertificate() looks in "certAuth.key" for the key. If multiple signed certificates are received, this implies that the certificate authority has authorized an impersonator, so none of them are returned as we don't know which is the real one.
--- @param serverName string (required) The name of the server to request the certificate of.
--- @param timeout? number (default: 1) The length of time in seconds to wait for responses.   The function will always wait the full time (to allow for duplicates.
--- @param certAuthKey? table|string (default: "certAuth.key") The certificate authority public key used to verify signatures,   or the path of the file to load it from. If no valid key is found   the request will still go ahead, but signatures will not be checked.
--- @param allowUnsigned? boolean (default: false) Whether to accept certificates with no valid signature.   If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key.
--- @param modemSide? string (default: a side with a modem) The modem to use to send and receive messages.
--- @return Certificate|nil # certificate of the server if exactly one is received, or nil if zero or more than one acceptable certificates are found.
--- @return table # a table of all acceptable certificates received.
function cryptoNet.requestCertificate(serverName, timeout, certAuthKey, allowUnsigned, modemSide)
    if type(serverName) ~= "string" then
        error("Server name must be a string.", 2)
    end
    certAuthKey = cryptoNet.loadCertAuthKey(certAuthKey)

    modemSide = cryptoNet.resolveModemSide(modemSide)
    local modem = peripheral.wrap(modemSide)
    local channel = cryptoNet.getChannel(serverName)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local wasOpen = modem.isOpen(channel)
    modem.open(channel)

    log("Requesting certificate...")
    sendInternal(modemSide, channel, serverName, nil, "certificate_request")

    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local receivedIDs = {}
    -- The received certificates.
    local certificates = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == channel then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extractMessage(event[5], receivedIDs)
            -- If this is a certificate_response with a correctly formatted certifiate,
            -- for the correct server...
            if message ~= nil and message.msgType == "certificate_response" and cryptoNet.certificateValid(message.message) and message.message.name == serverName then
                local certificate = message.message
                local found = false
                -- If we have already received an identical certificate don't add this one.
                for _, cert in pairs(certificates) do
                    if certificate.key.public == cert.key.public and certificate.key.shared == cert.key.shared and certificate.signature == cert.signature then
                        found = true
                        break
                    end
                end

                if not found then
                    table.insert(certificates, certificate)
                end
            end
        elseif event[1] == "timer" and event[2] == timer then
            -- Stop listening for events once the time is up.
            break
        end
    end

    -- Close the channel if it wasn't open before we started.
    if not wasOpen then
        modem.close(channel)
    end

    -- If we have a valid cert auth key to use,
    -- verify the signatures of the received certificates.
    -- If allowUnsigned is false any certificates without valid signatures
    -- will be removed.
    local signedCount = 0
    if certAuthKey ~= nil and #certificates > 0 then
        log("Checking signatures...")
        -- Iterate backwards as we will be deleting from the list.
        for i = #certificates, 1, -1 do
            local certificate = certificates[i]
            if certificate.signature == nil then
                if not allowUnsigned then
                    log("Discarding a certificate as it has no signature.")
                    table.remove(certificates, i)
                end
            else
                local ok, valid = pcall(cryptoNet.verifyCertificate, certificate, certAuthKey)
                if ok and valid then
                    -- Keep the certificate.
                    log("This certificate has a valid signature.")
                    signedCount = signedCount + 1
                else
                    log("Discarding a certificate as it has an invalid signature.")
                    table.remove(certificates, i)
                end
            end
        end
    end

    if #certificates == 1 then
        log("One certificate found, good.")
        return certificates[1], certificates
    else
        if #certificates == 0 then
            log("No certificates found.")
        elseif signedCount > 1 then
            log("Multiple (" ..
            signedCount .. ") certificates had valid signatures, has the certificate authority authorized impersonators?")
        else
            log("Multiple (" .. #certificates .. ") certificates found, some may be malicious.")
        end
        -- Don't return any certificate as the chosen one, but still return the whole list.
        return nil, certificates
    end
end

--- Open an encrypted connection to a CryptoNet server, returning a socket object that can be used to send and receive messages from the server.
--- @param serverName? string (default: inferred from certificate) The name of the server to connect to.
--- @param timeout? number (default: 5) The number of seconds to wait for a response to the connection request. Will terminate early if a response is received.
--- @param certTimeout? number (default: 1) The number of seconds to wait for certificate responses, if no certificate was provided.
--- @param certificate? table|string (default: "<serverName>.crt") The certificate of the server. Can either be the certificate of the server itself, or the name of a file that contains it. If no valid certificate is found a certificate request will be sent to the server.
--- @param modemSide? string (default: a side with a modem) The modem to use to send and receive messages.
--- @param certAuthKey? table|string (default: "certAuth.key") The certificate authority public key used to verify signatures, or the path of the file to load it from. If no valid key is found the connection will still go ahead, but signatures will not be checked.
--- @param allowUnsigned? boolean (default: false) Whether to accept certificates with no valid signature. If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key. This does not apply to the certificate provided by the user (if present), which is never verified (we trust them to get their own certificate right), only to certificates received through a certificate request.
--- @return Socket # a socket object that can be used to communicate with the server.
function cryptoNet.connect(serverName, timeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
    if serverName ~= nil and type(serverName) ~= "string" then
        error("Server name must be a string or nil.", 2)
    end
    if certificate == nil then
        if type(serverName) == "string" then
            -- If a server name was given but not a certificate,
            -- try to load a corresponding certificate from file.
            certificate = serverName .. ".crt"
        else
            -- Need a way to identify the server.
            error("Server name and certificate can't both be nil.", 2)
        end
    end

    -- If the certificate is a file path...
    if type(certificate) == "string" then
        local certFilename = certificate
        -- Make paths relative to the current CryptoNet working directory.
        local certPath = workingDir == "" and certFilename or workingDir .. "/" .. certFilename
        log("Checking " .. certPath .. " for certificate...")
        if fs.isDir(certPath) or not fs.exists(certPath) then
            if fs.isDir(certPath) then
                log(certFilename .. " is not a file, will need to request certificate.")
            else
                log(certFilename .. " does not exist, will need to request certificate.")
            end
            certificate = nil
        else
            local file = fs.open(certPath, "r")
            certificate = cryptoNet.deserializeCertOrKey(file.readAll())
            file.close()

            if not cryptoNet.certificateValid(certificate) then
                log(certFilename .. " does not contain a valid certificate, will need to request certificate.")
                certificate = nil
            else
                log("Loaded certificate from " .. certFilename .. ".")
            end
        end
    elseif not cryptoNet.certificateValid(certificate) then
        -- If certificate was not a string, it should be a valid certificate.
        error("Invalid certificate.", 2)
    end

    -- Infer serverName from the certificate.
    if serverName == nil then
        if certificate ~= nil then
            serverName = certificate.name
        else
            error("Failed to load name from certificate, and no name was provided.", 2)
        end
    end

    modemSide = cryptoNet.resolveModemSide(modemSide)
    local modem = peripheral.wrap(modemSide)
    local channel = cryptoNet.getChannel(serverName)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local wasOpen = modem.isOpen(channel)
    modem.open(channel)

    -- If we have no certificate yet, request it from the server.
    if certificate == nil then
        certificate = cryptoNet.requestCertificate(serverName, certTimeout, certAuthKey, allowUnsigned, modemSide)
        if certificate == nil then
            -- Close the modem channel if it wasn't open before we started.
            if not wasOpen then
                modem.close(channel)
            end
            error("Failed to request certificate from server.", 2)
        end
    end

    -- An AES session key is used to encrypt the messages sent and received over
    -- this socket. Before sending messages we need to generate a session key
    -- and send it to the server. RSA encryption using the server's public key
    -- (contained in its certificate) is used to send the session key;
    -- the server will use its private key to decrypt the message.
    log("Generating session key...")
    local sessKey = cryptoNet.generateKey()
    local numKey = RsaCrypt.bytesToNumber(sessKey, 16 * 8, 8)
    local encryptedKey = RsaCrypt.crypt(certificate.key, numKey)
    -- The server will send a response encrypted with the session key to prove
    -- that it has received is successfully. We know what the response content
    -- is supposed to be, allowing us to verify the response.
    local expectedResponse = tostring(Sha256.digest(serverName .. certificate.key.public ..
    certificate.key.shared .. numKey))
    sendInternal(modemSide, channel, serverName, encryptedKey, "connection_request")

    log("Awaiting response...")
    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local receivedIDs = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 5)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == channel then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extractMessage(event[5], receivedIDs)
            -- If the message is a valid connection_response directed at this socket,
            -- containing a valid encrypted message...
            if message ~= nil and message.msgType == "connection_response" and message.target == encryptedKey and type(message.message) == "table"
                and #message.message == 2 and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
                -- Decrypt using the session key.
                local ok, actualResponse = pcall(Aes.decrypt_str, bytesToString(message.message[1]), sessKey,
                    message.message[2])
                -- Compare the response to what we know the response content is supposed
                -- to be, to see if the session key was received correctly.
                if ok and actualResponse == expectedResponse then
                    log("Connection successful.")
                    -- Once we have received a valid response we know the connection has
                    -- been opened on the server, so we can stop listening.
                    os.cancelTimer(timer)
                    break
                else
                    log("Received an invalid response.")
                end
            end
        elseif event[1] == "timer" and event[2] == timer then
            -- If the timeout expires abort the connection attempt.
            -- Close the modem channel if it wasn't open before we started.
            if not wasOpen then
                modem.close(channel)
            end
            error("Did not receive a response before timeout.", 2)
        end
    end

    -- Create and return the socket object.
    local socket = { sender = encryptedKey, target = serverName, key = sessKey, modemSide = modemSide, channel = channel, permissionLevel = 0, receivedMessages = {} }
    table.insert(allClientSockets, socket)
    return socket
end

--
-- EVENT LOOP
--

--- Run a background loop that listens for events of any kind, and calls an optional event handler on every event. The event handler is always called in a new thread, so it is okay to use blocking functions such as sleep() and pullEvent() within onEvent without freezing the whole program. Errors raised during event handling are printed without terminating the whole program, so errors processing one event won't bring down the entire system.
---
--- Any modem_message events are also sent to CryptoNet for handling, allowing all sockets and servers on this machine to listen for messages in the background. Both the modem_message itself and any CryptoNet events invoked by it are sent to the event handler, on seperate iterations of the event loop.
--- @param onEvent function The function to call on every event. Optional.
local function eventLoop(onEvent)
    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local receivedIDs = {}
    while true do
        -- Wrap everything in pcall so any errors won't exit the entire program,
        -- only this iteration of the loop.
        local ok, msg = pcall(function()
            -- Listen for all event types.
            local event = { os.pullEvent() }
            if event[1] == "modem_message" then
                local newEvent = handleModemEvent(event, receivedIDs)
                if newEvent ~= nil then
                    -- This event will be processed on a later iteration of the loop.
                    os.queueEvent(table.unpack(newEvent))
                end
            end
            -- Call the event handler in a new thread.
            if onEvent ~= nil then
                Threading.new(function()
                    -- We need another pcall here since this is in a different thread
                    -- to the outer pcall, so that one won't be able to catch errors
                    -- from the handler.
                    local ok, msg = pcall(onEvent, event)
                    if not ok then
                        -- Make sure pressing Ctrl+T can still terminate the program.
                        if msg == "Terminated" then
                            error("Terminated", 0)
                        else
                            -- Print the error without crashing.
                            print(msg)
                        end
                    end
                end)
            end
        end)
        if not ok then
            -- Make sure pressing Ctrl+T can still terminate the program.
            if msg == "Terminated" then
                error("Terminated", 0)
            else
                -- Print the error without crashing.
                print(msg)
            end
        end
    end
end


--- Run a background loop that listens for events of any kind, and calls the given event handler (which should take one argument) on them. The event handler is always called in a new thread, so it is okay to use blocking functions such as sleep() and pullEvent() within onEvent without freezing the whole program. Errors raised during event handling are printed without terminating the whole program, so errors processing one event won't bring down the entire system.
---
--- Any modem_message events are also sent to CryptoNet for handling, allowing all sockets and servers on this machine to listen for messages in the background. Both the modem_message itself and any CryptoNet events invoked by it are sent to the event handler, on separate iterations of the event loop.
---
--- The onStart function is called once after the loop starts, after the threading system has been started. onStart and onEvent are both optional. os.startThread() can be called from within onStart and onEvent (and any functions called by them) to start new threads without blocking the current one.
--- @param onStart function The function to call once after the loop starts. Optional.
--- @param onEvent function The function to call on every event. Optional.
function cryptoNet.startEventLoop(onStart, onEvent)
    if onStart ~= nil and type(onStart) ~= "function" then
        error("onStart is not a function.", 2)
    end
    if onEvent ~= nil and type(onEvent) ~= "function" then
        error("onEvent is not a function.", 2)
    end

    -- Start the event loop in a different thread.
    Threading.new(function() eventLoop(onEvent) end)
    -- Call onStart in this thread.
    if onStart ~= nil then
        local ok, msg = pcall(onStart)
        if not ok then
            -- Print the error without crashing.
            print(msg)
        end
    end
end

--
-- CERTIFICATE AUTHORITY
--

--- Generate the public and private keys used by a certificate authority to sign certificates. The keys will be written to the specified files, which both have sensible default names.
--- @param publicFilename string The name of the file to save the public key to. Defaults to "certAuth.key".
--- @param privateFilename string The name of the file to save the private key to. Defaults to "certAuth_private.key".
function cryptoNet.initCertificateAuthority(publicFilename, privateFilename)
    if publicFilename == nil then
        publicFilename = "certAuth.key"
    end
    if privateFilename == nil then
        privateFilename = "certAuth_private.key"
    end
    -- Math paths relative to the current CryptoNet working directory.
    local publicPath = workingDir == "" and publicFilename or workingDir .. "/" .. publicFilename
    local privatePath = workingDir == "" and privateFilename or workingDir .. "/" .. privateFilename

    if fs.exists(publicPath) then
        error(publicPath .. " already exists, please delete both your existing keyfiles in order to generate new ones.",
            2)
    end
    if fs.exists(privatePath) then
        error(privatePath .. " already exists, please delete both your existing keyfiles in order to generate new ones.",
            2)
    end

    log("Generating key pair... (may take some time)")
    local publicKey, privateKey = RsaKeygen.generateKeyPair()
    print("")
    log("Done!")

    local file = fs.open(publicPath, "w")
    file.write(cryptoNet.serializeCertOrKey(publicKey))
    file.close()
    log("Saved public key to " .. publicPath .. ".  Give this to client users.")

    file = fs.open(privatePath, "w")
    file.write(cryptoNet.serializeCertOrKey(privateKey))
    file.close()
    log("Saved private key to " .. privatePath .. ".  Do not share this with anyone!")

    log("Initialization successful.")
end

--- Sign a certificate using the certificate authority's private key. Both arguments can either be the certificate/key itself, or a path to a file that contains it. The signed certificate is returned, and written to the path the certificate was stored in, if it was loaded from file.
--- @param certificate Certificate|string The certificate to sign, or the path to the file that contains it.
--- @param privateKey PrivateKey|string The private key to sign the certificate with, or the path to the file that contains it.
function cryptoNet.signCertificate(certificate, privateKey)
    local certPath = nil
    if type(certificate) == "string" then
        -- Make paths relative to the current CryptoNet working directory.
        certPath = workingDir == "" and certificate or workingDir .. "/" .. certificate
        if not fs.exists(certPath) then
            error(certPath .. " does not exist.", 2)
        end
        if fs.isDir(certPath) then
            error(certPath .. " is not a file.", 2)
        end

        local file = fs.open(certPath, "r")
        certificate = cryptoNet.deserializeCertOrKey(file.readAll())
        file.close()

        if not cryptoNet.certificateValid(certificate) then
            error(certPath .. " does not contain a valid certificate.", 2)
        end
        log("Loaded certificate from " .. certPath .. ".")
    elseif not cryptoNet.certificateValid(certificate) then
        -- If certificate is not a file path it should be a valid certificate.
        error("Not a valid certificate or file.", 2)
    end

    -- Default value.
    if privateKey == nil then
        privateKey = "certAuth_private.key"
    end
    if type(privateKey) == "string" then
        -- Make paths relative to the current CryptoNet working directory.
        local keyPath = workingDir == "" and privateKey or workingDir .. "/" .. privateKey
        if not fs.exists(keyPath) then
            error(keyPath .. " does not exist.", 2)
        end
        if fs.isDir(keyPath) then
            error(keyPath .. " is not a file.", 2)
        end

        local file = fs.open(keyPath, "r")
        privateKey = cryptoNet.deserializeCertOrKey(file.readAll())
        file.close()

        if not cryptoNet.privateKeyValid(privateKey) then
            error(keyPath .. " does not contain a valid private key.", 2)
        end
        log("Loaded private key from " .. keyPath .. ".")
    elseif not cryptoNet.privateKeyValid(privateKey) then
        -- If privateKey is not a file path it should be a valid private key.
        error("Not a valid private key or file.", 2)
    end

    -- The signature is just the contents of the certificate hashed and encrypted.
    -- Clients can verify the signature by decrypting it with the cert auth public key
    -- and seeing if it matches the contents of the certificate.
    log("Generating signature...")
    local hash = Sha256.digest(certificate.name .. certificate.key.public .. certificate.key.shared)
    certificate.signature = RsaCrypt.crypt(privateKey, RsaCrypt.bytesToNumber(hash, 32 * 8, 8))

    -- If the certificate was loaded from a file, save it back there.
    if certPath ~= nil then
        local file = fs.open(certPath, "w")
        file.write(cryptoNet.serializeCertOrKey(certificate))
        file.close()
        log("Saved certificate to " .. certPath .. ".")
    end
    return certificate
end

-- CryptoNet's command line interface, used by a certificate authority
-- to sign certificates.
-- Supports two commands: initCertAuth and signCert.
--
-- initCertAuth is used to generate the keys used to sign and verify certificates.
-- The public key should be distributed to all clients using the certificate
-- authority, while the private key should be kept secure on the cert auth's
-- machine.
--
-- Certificates to be signed should be copied to the cert auth machine,
-- e.g. using floppy disks. signCert is then used to sign the certificate,
-- which can then be transferred back to the server machine.
-- Only sign the certificates of trusted servers, and don't sign two certificates
-- with the same name and different public keys.

-- Only run if executed on the command line, not when imported with os.loadAPI().
if not pcall(debug.getlocal, 4, 1) then
    cryptoNet.setLoggingEnabled(true)
    -- Set the CryptoNet working directory to match the system one.
    cryptoNet.setWorkingDirectory(shell.dir())

    local args = { ... }
    if args[1] == "signCert" then
        -- Sign a certificate loaded from a file.
        local certPath = args[2]
        if certPath == nil then
            log("Usage: cryptoNet signCert <file>")
            return
        end

        -- Make paths relative to the working directory.
        certPath = workingDir == "" and certPath or workingDir .. "/" .. certPath
        -- Optional private key file argument, can be omitted to use default.
        local keyPath = args[3]
        local ok, msg = pcall(cryptoNet.signCertificate, certPath, keyPath)

        if not ok then
            log("Error: " .. msg:sub(8))
        end
    elseif args[1] == "initCertAuth" then
        -- Generate the cert auth key pair and save them to the specified files.
        -- The file arguments can be omitted to use the default values.
        local ok, msg = pcall(cryptoNet.initCertificateAuthority, args[2], args[3])
        if not ok then
            log("Error: " .. msg:sub(8))
        end
    else
        log("Invalid command.")
    end
end

--
-- Module Exports and Class Definitions
--

--- @class Socket
--- @field sender string The encrypted session key of this socket, which acts as the client's temporary identity to the server
--- @field target string The name of the server
--- @field key string The session key for this socket's session
--- @field modemSide string The modem used by the socket
--- @field channel number The channel the server (and this socket) use to communicate
--- @field permissionLevel number The permission level of the user logged into the socket, initialized to 0.
--- @field receivedMessages table The encrypted messages received by this socket, used to prevent replay attacks using duplicate messages. Every time a message is encrypted the encrypted version will be different due to randomness in the algorithm, so if the socket gets the exact same message twice it is probably a malicious duplicate.
--- @field username string The username of the user logged into the socket, initialized to nil.

--- @class Server
--- @field name string The server name
--- @field certificate Certificate The server's certificate
--- @field privateKey string The server's private key
--- @field modemSide string The modem used by the server
--- @field channel number The channel number the server communicates on
--- @field hideCertificate boolean Whether the server distributes its certificate to clients
--- @field discoverable boolean Whether the server responds to discover() requests
--- @field userTable table The table of user login details for the server, loaded from file or empty by default
--- @field userTablePath string The name of the user table file
--- @field sockets table<Socket> The table of the server's sockets, used to communicate with clients. Starts empty and is populated as clients connect.


--- @class Certificate
--- @field key string The public key of the certificate
--- @field name string The name of the certificate
--- @field public private string The private key of the certificate
--- @field public public string The public key of the certificate
--- @field shared string The shared key of the certificate
--- @field signature string The signature of the certificate

--- @class Key
--- @field shared string The public key of the certificate

--- @class PrivateKey : Key
--- @field public private string The private key of the certificate

--- @class PublicKey : Key
--- @field public public string The public key of the certificate

return cryptoNet
