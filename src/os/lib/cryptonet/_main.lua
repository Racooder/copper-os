---@diagnostic disable: duplicate-set-field, cast-local-type, undefined-global, undefined-field, need-check-nil

local Sha256 = require("cryptolib.sha256")
local Rsa = require("cryptolib.rsa")
local Keygen = require("cryptolib.keygen")
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


local Package = {}


-- Channel used to send discovery requests and responses.
DISCOVERY_CHANNEL = 65531
-- If set to true CryptoNet will also broadcast all messages over the Rednet
-- reapter channel, which allows CryptoNet messages to be repeated by the built-in
-- program repeat. Disabling this is a little more secure as an attacker won't know
-- which channel you are communicating over.
local repeat_messages = true
-- Whether to print log messages or not.
local logging_enabled = true
-- Directory CryptoNet looks for files in.
local working_dir = ""
-- All servers currently open on this computer.
local all_servers = {}
-- All client sockets (opened with connect()) open on this computer.
local all_client_sockets = {}


local function log(message)
    if logging_enabled then
        print("[CryptoNet] " .. message)
    end
end


--
-- ACCESSORS
--

---@return boolean
function Package.get_logging_enabled()
    return logging_enabled
end

---@param enabled boolean
function Package.set_logging_enabled(enabled)
    logging_enabled = enabled
end

---@return boolean
function Package.get_repeat_messages()
    return repeat_messages
end

---@param rep_msgs boolean
function Package.set_repeat_messages(rep_msgs)
    repeat_messages = rep_msgs
end

---@return string
function Package.get_working_directory()
    return working_dir
end

---@param dir string
function Package.set_working_directory(dir)
    if type(dir) ~= "string" then
        error("Directory must be a string.", 2)
    end
    working_dir = dir
end

--- @return table<Server>
function Package.get_all_servers()
    return all_servers
end

--- @return table<Socket>
function Package.get_all_client_sockets()
    return all_client_sockets
end

--
-- VALIDITY CHECKS
--

--- Check that the key is a 16 element table of numbers.
--- @param key table<number>
--- @return boolean
function Package.key_valid(key)
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
function Package.private_key_valid(key)
    return type(key) == "table" and type(key.private) == "string" and type(key.shared) == "string"
end

--- Check that a table has all the parts required to be a valid public key.
--- @param key? table
--- @return boolean
function Package.public_key_valid(key)
    return type(key) == "table" and type(key.public) == "string" and type(key.shared) == "string"
end

--- Check that a table has all the parts required to be a valid server certificate. If ignoreKey is true it is acceptable for a server to have no key, but if present it must be valid. The signature is always optional but must be valid (syntactically, it isn't actually verified here) if present.
--- @param certificate? table
--- @param ignore_key? boolean
--- @return boolean
function Package.certificate_valid(certificate, ignore_key)
    -- All certificates must contain the server name.
    if type(certificate) ~= "table" or type(certificate.name) ~= "string" then
        return false
    end

    -- A certificate must contain the server's public key, unless ignore_key is true.
    if certificate.key == nil and not ignore_key then
        return false
    end
    -- Ensure that the public key is valid, if present.
    if certificate.key ~= nil and not Package.public_key_valid(certificate.key) then
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
function Package.server_valid(server)
    return type(server) == "table"
        and type(server.name) == "string"
        and Package.certificate_valid(server.certificate)
        and Package.private_key_valid(server.private_key)
        and type(server.modem_side) == "string"
        and type(server.channel) == "number"
        and type(server.user_table) == "table"
        and type(server.user_table_path) == "string"
        and type(server.sockets) == "table"
end

--- Check that a table has everything it needs to be a valid socket.
--- @param socket? table
--- @return boolean
function Package.socket_valid(socket)
    return type(socket) == "table"
        and type(socket.sender) == "string"
        and type(socket.target) == "string"
        and Package.key_valid(socket.key)
        and type(socket.modem_side) == "string"
        and type(socket.channel) == "number"
        and type(socket.permission_level) == "number"
        and type(socket.received_messages) == "table"
end

--- Check that all the entries in a user table are valid.
--- @param user_table? table
--- @return boolean
function Package.user_table_valid(user_table)
    if type(user_table) ~= "table" then
        return false
    end
    for username, entry in pairs(user_table) do
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
--- @param modem_side? string
--- @return string
function Package.resolve_modem_side(modem_side)
    -- If no modem side argument is provided, search for a modem and use that side.
    if modem_side == nil then
        for _, side in pairs(peripheral.getNames()) do
            if peripheral.getType(side) == "modem" then
                modem_side = side
                break
            end
        end
        if modem_side == nil then
            error("Could not find a modem.", 3)
        end
    else
        -- If an argument was provided, check that it is a valid side.
        local found = false
        for _, side in pairs(redstone.getSides()) do
            if side == modem_side then
                found = true
                break
            end
        end
        if not found then
            error(tostring(modem_side) .. " is not a valid side.", 3)
        end
    end
    if peripheral.getType(modem_side) ~= "modem" then
        error("No modem on side " .. modem_side .. ".", 3)
    end

    log("Using modem " .. modem_side .. ".")
    return modem_side
end

--- Decides which channel a server should communicate on, based on its name. This function will always return the same channel for a given server name, allowing clients to find out the channel of a server without any prior communications with it.
--- @param server_name string
--- @return number
function Package.get_channel(server_name)
    local name_hash = Sha256.digest(server_name)
    -- Use the first two bytes of the hash as the channel number, so that the full range
    -- of acceptable channels can be used.
    local channel = name_hash[1] + name_hash[2] * 2 ^ 8
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
--- @param modem_side string
--- @return boolean
function Package.channel_in_use(channel, modem_side)
    -- Check the client sockets.
    for _, socket in pairs(all_client_sockets) do
        if socket.channel == channel and socket.modem_side == modem_side then
            return true
        end
    end
    -- Check the server channels.
    for _, server in pairs(all_servers) do
        if server.channel == channel and server.modem_side == modem_side then
            return true
        end
    end

    return false
end

-- Convert a table of bytes into a string.
local function bytes_to_string(bytes)
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
local function serialize_any(value)
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
local function deserialize_any(str)
    local type_char = str:sub(1, 1)
    local value_str = str:sub(2)
    if type_char == "x" then
        return nil
    elseif type_char == "b" then
        return value_str == "1"
    elseif type_char == "n" then
        return tonumber(value_str)
    elseif type_char == "s" then
        return value_str
    elseif type_char == "t" then
        return textutils.unserialize(value_str)
    else
        error("Invalid type character: " .. type_char, 2)
    end
end


--- Serialize a certificate or RSA key into a string, for saving to a file. The textutils functions don't seem to like the huge strings of numbers in the keys, so quotation marks must be added to them before serialization, which is what this function does.
--- @param obj Certificate|Key|nil
--- @return string
function Package.serialize_cert_or_key(obj)
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

--- Deserialize certificates or RSA keys serialized by serialize_cert_or_key(). This involves deserializing as normal and removing the quotation marks added during serialization.
--- @param str string
--- @return Certificate|Key|nil
function Package.deserialize_cert_or_key(str)
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
function Package.generate_key()
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
function Package.generate_certificate(name)
    log("Generating keys... (may take some time)")
    local public_key, private_key = Keygen.generate_key_pair()
    print("")
    log("Done!")
    -- The certificate contains the name and public key of the server.
    return { name = name, key = public_key }, private_key
end

--- Load a certificate authority public key from the specified file and validate it, or just validate the key itself if passed directly as the argument. If key is left nil, a default filename of "certAuth.key" is used.
--- @param key? string|PublicKey (default: "certAuth.key") The file to load the key from, or the key itself to validate.
--- @return Certificate|Key|nil
function Package.load_cert_auth_key(key)
    if key == nil then
        -- Default value.
        key = "certAuth.key"
    end
    -- If key is a file path...
    if type(key) == "string" then
        local key_filename = key
        -- Make paths relative to the current CryptoNet working directory.
        local key_path = working_dir == "" and key_filename or working_dir .. "/" .. key_filename
        log("Checking " .. key_path .. " for cert auth key...")
        if fs.isDir(key_path) or not fs.exists(key_path) then
            if fs.isDir(key_path) then
                log(key_filename .. " is not a file, will not be able to verify signatures.")
            else
                log(key_filename .. " does not exist, will not be able to verify signatures.")
            end
            return nil
        else
            local file = fs.open(key_path, "r")
            key = Package.deserialize_cert_or_key(file.readAll())
            file.close()

            if not Package.public_key_valid(key) then
                log(key_filename .. " does not contain a valid cert auth key, will not be able to verify signatures.")
                return nil
            else
                log("Loaded cert auth key from " .. key_filename .. ".")
                return key
            end
        end
        -- If the argument is not a string it should be the key table itself,
        -- so just validate it and return unchanged if valid.
    elseif Package.public_key_valid(key) then
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
function Package.verify_certificate(certificate, key)
    -- Signatures are made by encrypting the certificate's hash using the cert auth's private key.
    -- If the signature was generated by the certificate authority that uses the provided public key,
    -- decrypting the signature with this key should yield the certificate's hash.

    -- Find the hash of the certificate.
    local hash = Sha256.digest(certificate.name .. certificate.key.public .. certificate.key.shared)
    -- Decrypt the signature using the provided public key.
    local sig_hash = Rsa.bytes_to_string(Rsa.number_to_bytes(Rsa.crypt(key, certificate.signature), 32 * 8, 8))
    -- See whether the decrypted signature matches the expected hash.
    return tostring(hash) == sig_hash
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
local function send_internal(modem_side, channel, target, message, msg_type, sender)
    -- Generate the message in exactly the same format as Rednet.
    local n_message_id = math.random(1, 2147483647)
    local t_message = {
        n_message_id = n_message_id,
        n_recipient = channel,
        message = { message = message, msg_type = msg_type, target = target, sender = sender },
        s_protocol = "cryptoNet",
    }

    local modem = peripheral.wrap(modem_side)
    modem.transmit(channel, channel, t_message)
    -- Allow Rednet repeaters to repeat the message if enabled.
    if repeat_messages then
        modem.transmit(rednet.CHANNEL_REPEAT, channel, t_message)
    end
end


-- Send an encrypted internal message. Unlike the user-facing send() function,
-- this one only allows strings to be sent.
local function send_encrypted_internal(socket, message)
    if type(message) ~= "string" then
        error("Message must be a string.", 2)
    end
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end
    -- Use unique IVs for every message.
    local iv = Package.generate_key()
    local ok, encrypted = pcall(Aes.encrypt_str, message, socket.key, iv)
    if ok then
        -- Send the encrypted message and the IVs used to generate it.
        -- We have to send the encrypted string as a table of bytes, because some of
        -- the special characters in the string seem to get lost in transmission otherwise.
        send_internal(socket.modem_side, socket.channel, socket.target, { { string.byte(encrypted, 1, encrypted:len()) },
            iv }, "encrypted_message", socket.sender)
    else
        error("Encryption failed: " .. encrypted:sub(8), 2)
    end
end


--- Send an encrypted message over the given socket. The message can be pretty much any Lua data type.
--- @param socket Socket
--- @param message any
function Package.send(socket, message)
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end
    -- Convert the message to a string before sending, so it can be encrypted.
    -- It will be deserialized at the other end.
    send_encrypted_internal(socket, serialize_any(message))
end

--- Send an unencrypted message over CryptoNet. Useful for streams of high speed, non-sensitive data. Unencrypted messages have no security features applied, so can be easily exploited by attackers. Only use for non-critical messages.
--- @param socket Socket
--- @param message string
function Package.send_unencrypted(socket, message)
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end
    -- Just send the message as-is.
    send_internal(socket.modem_side, socket.channel, socket.target, message, "plain_message", socket.sender)
end

--
-- LOGIN SYSTEM
--

--- Hash a password using the username and server name as a salt. Used to secure passwords before they are sent over CryptoNet to a server. Technically this is unnecessary as the connection is encrypted anyway, but it means that even if this is somehow compromised (e.g. with a spoof attack) the attacker won't know the actual password and be able to use it on the user's other accounts, if they use the same password for multiple things.
--- @param username string
--- @param password string
--- @param server_name string
--- @return string
function Package.hash_password(username, password, server_name)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end
    if type(server_name) ~= "string" then
        error("Server name must be a string.", 2)
    end

    return tostring(Sha256.digest(server_name .. username .. password))
end

--- Load the user table stored at the given path, defaulting to an empty table if the file does not exist.
--- @param path string
--- @return table
function Package.load_user_table(path)
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
    local user_table = textutils.unserialize(file.readAll())
    file.close()

    if not Package.user_table_valid(user_table) then
        error(path .. " does not contain a valid user table, user table could not be loaded.", 2)
    end

    log("Loaded user table from " .. path .. ".")
    return user_table
end

--- Save the given user table to the given file.
--- @param user_table table
--- @param path string
function Package.save_user_table(user_table, path)
    if type(path) ~= "string" then
        error("Path must be a string.", 2)
    end
    if not Package.user_table_valid(user_table) then
        error("Not a valid user table", 2)
    end

    if fs.isDir(path) then
        error(path .. " already exists and is a directory.", 2)
    end

    local file = fs.open(path, "w")
    file.write(textutils.serialize(user_table))
    file.close()
    log("Saved user table to " .. path .. ".")
end

--- Add a user to the given server with the provided details. The provided password should already have been hashed by hashPassword(). Default permission level is 1. If there is only one server running, that server will be used by default.
--- @param username string
--- @param pass_hash string
--- @param permission_level? number
--- @param server? Server
function Package.add_user_hashed(username, pass_hash, permission_level, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(pass_hash) ~= "string" then
        error("Password hash must be a string.", 2)
    end
    if permission_level == nil then
        permission_level = 1
    elseif type(permission_level) ~= "number" then
        error("Permission level must be a number", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] ~= nil then
        error("User " .. username .. " already exists.", 2)
    end

    -- The password is hashed again before going in the database, so that even if
    -- an attacker has access to this file they do not have the original password
    -- required to log into the server from the outside.
    -- PBKDF2 is used over the standard SHA256 digest as it is theoretically harder
    -- to crack.
    server.user_table[username] = { Sha256.pbkdf2(pass_hash, server.name .. username, 8), permission_level }
    log("Added user " .. username .. ".")
    Package.save_user_table(server.user_table, server.user_table_path)
end

--- Add a user to the given (local) server's user table with the provided details. The user table is saved to disk, so is non volatile. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param password string
--- @param permission_level? number
--- @param server? Server
function Package.add_user(username, password, permission_level, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end
    if permission_level == nil then
        permission_level = 1
    elseif type(permission_level) ~= "number" then
        error("Permission level must be a number", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] ~= nil then
        error("User " .. username .. " already exists.", 2)
    end

    -- When users log into the server remotely their passwords will be hashed
    -- before being sent, so we must perform the same process here before
    -- adding it to the table.
    Package.add_user_hashed(username, Package.hash_password(username, password, server.name), permission_level, server)
end

--- Remove a user from a server. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
function Package.delete_user(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        error("No user called " .. username .. ".", 2)
    else
        server.user_table[username] = nil
        log("Deleted user " .. username .. ".")
        Package.save_user_table(server.user_table, server.user_table_path)
    end
end

--- Check if a user exists on the server. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return boolean
function Package.user_exists(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    return server.user_table[username] ~= nil
end

--- Get the hashed password of a user from the users table. The original password cannot be (easily) retrieved from this hash. Returns nil if the user does not exist. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return string|nil
function Package.get_password_hash(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        return nil
    end
    return server.user_table[username][1]
end

--- Get the permission level of a user. Returns nil if the user does not exist. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param server? Server
--- @return number|nil
function Package.get_permission_level(username, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        return nil
    end
    return server.user_table[username][2]
end

--- Set the hashed password of a user in the table. Assumes the provided passowrd has already been hashed with hashPassword(). The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param pass_hash string
--- @param server Server
function Package.set_password_hashed(username, pass_hash, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(pass_hash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    -- Hash the password again before storing.
    server.user_table[username][1] = Sha256.pbkdf2(pass_hash, server.name .. username, 8)
    log("Updated password for " .. username .. ".")
    Package.save_user_table(server.user_table, server.user_table_path)
end

--- Sets the password of a user in the table. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param password string
--- @param server Server
function Package.set_password(username, password, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    -- Hash the password before adding, to mimic the hashing performed by clients
    -- logging in remotely.
    Package.set_password_hashed(username, Package.hash_password(username, password, server.name), server)
end

--- Set the permission level of a user in the table. The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param permission_level number
--- @param server Server
function Package.set_permission_level(username, permission_level, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(permission_level) ~= "number" then
        error("Permission level must be a number.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        error("No user called " .. username .. ".", 2)
    end

    server.user_table[username][2] = permission_level
    log("Updated permission level for " .. username .. ".")
    Package.save_user_table(server.user_table, server.user_table_path)
end

--- Check that the given password matches the one in the table. Assumes the password has already been hashed by hashPassword(). The server parameter can be left blank if exactly one server is running.
--- @param username string
--- @param pass_hash string
--- @param server Server
--- @return boolean|nil
function Package.check_password_hashed(username, pass_hash, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(pass_hash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    if server.user_table[username] == nil then
        return nil
    end

    -- Since we can't unhash the passwords in the table, we must instead
    -- hash the query password and compare it to the hash in the table.
    -- If they are the same, then the original passwords were the same.
    local hash = Sha256.pbkdf2(pass_hash, server.name .. username, 8)
    -- Check if all the bytes of the hashes are equal.
    for i = 1, #hash do
        if hash[i] ~= server.user_table[username][1][i] then
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
function Package.check_password(username, password, server)
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- If there is exactly one server running, default to it.
    if server == nil then
        if #all_servers == 0 then
            error("No servers running.", 2)
        elseif #all_servers == 1 then
            server = all_servers[1]
        else
            error("Please specify a server.", 2)
        end
    elseif not Package.server_valid(server) then
        error("Invalid server.", 2)
    end

    -- Mimic the client-side hashing before checking.
    return Package.check_password_hashed(username, Package.hash_password(username, password, server.name), server)
end

--- Log into the server connected to this socket, remote or local, with the specified username and password. Assumes the password has already been hashed by hashPassword(). If executed on a server socket, the event details of the attempt are returned. If successful, the user's details will be stored in the socket. If the socket is already logged in, the username will be overwritten but the permission level will be set to the highest of the old and new one. This allows an admin account to log in then log in as a normal user to temporarily gain elevated privileges as that account.
--- @param socket Socket
--- @param username string
--- @param pass_hash string
--- @return string|nil
--- @return string|nil
--- @return Socket|nil
--- @return Server|nil
function Package.login_hashed(socket, username, pass_hash)
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(pass_hash) ~= "string" then
        error("Password hash must be a string.", 2)
    end

    if socket.server == nil then
        -- If this is a client socket, send a login request to the server.
        send_encrypted_internal(socket, "lr" .. textutils.serialize({ username, pass_hash }))
        log("Sent login request for " .. username .. " to " .. socket.target .. ".")
    else
        -- If this is a server socket, try to log in as the user
        -- and send the result to the client.
        if socket.server.user_table[username] == nil then
            log("Failed login attempt for " .. username .. ".")
            send_encrypted_internal(socket, "lf" .. username)
            return "login_failed", username, socket, socket.server
        else
            if Package.check_password_hashed(username, pass_hash, socket.server) then
                -- If the password was correct, log the user into the socket.
                socket.username = username
                -- Set the permission level to the greatest of the socket's original
                -- permission level and the new one, so admins can temporarily transfer
                -- their elevated rights to normal accounts.
                socket.permission_level = math.max(socket.permission_level, Package.get_permission_level(username, socket.server))
                -- Tell the client-side socket that the attempt was successful, so it can
                -- change its details as well.
                send_encrypted_internal(socket, "ls" .. textutils.serialize({ username, socket.permission_level }))
                log(username .. " logged in successfully.")
                return "login", username, socket, socket.server
            else
                log("Failed login attempt for " .. username .. ".")
                send_encrypted_internal(socket, "lf" .. username)
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
function Package.login(socket, username, password)
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end
    if type(username) ~= "string" then
        error("Username must be a string.", 2)
    end
    if type(password) ~= "string" then
        error("Password must be a string.", 2)
    end

    -- Get the server name based on whether this is a client or server socket.
    local server_name = socket.server == nil and socket.target or socket.sender
    -- Hash the password before sending.
    return Package.login_hashed(socket, username, Package.hash_password(username, password, server_name))
end

--- Log out of the user account currently logged in on this socket. If executed on a server socket, the event details are returned.
--- @param socket Socket|Server
function Package.logout(socket)
    if not Package.socket_valid(socket) then
        error("Invalid socket.", 2)
    end

    -- Tell the other end to log out as well.
    send_encrypted_internal(socket, "lo")
    if socket.server == nil then
        -- If this is a client socket, all we can do is ask the server to log out.
        -- The actual logging out is only performed once a response is received
        -- from the server.
        log("Sent logout request to " .. socket.target .. ".")
    else
        -- If this is a server socket, we can actually logout.
        local username = socket.username
        socket.username = nil
        socket.permission_level = 0

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
local function extract_message(message, received_ids)
    -- Check the list of alrady received message IDs to see if any of them are
    -- more than 5 seconds old and can be deleted. The purpose of this list is
    -- to avoid processing messages processed by Rednet's repeat program
    -- more than once, but repeat is unlikely to take 5 seconds to repeat a message.
    -- Since the message IDs are randomly generated, it is good to remove them
    -- from the list as soon as possible to reduce the chance of a future message
    -- with same ID from being blocked.
    -- Note that CryptoNet has a seperate more advanced system for preventing
    -- attackers from sending the same encrypted message twice, handled elsewhere.
    local to_delete = {}
    for id, time in pairs(received_ids) do
        -- List the ID for deletion if it is more than 5 seconds old.
        if os.clock() - time > 5 then
            table.insert(to_delete, id)
        end
    end
    -- Remove all the deleted IDs.
    for _, id in pairs(to_delete) do
        received_ids[id] = nil
    end

    -- Check that the message follows the Rednet format and is using the cryptoNet protocol.
    if type(message) == "table" and message.s_protocol == "cryptoNet" and type(message.message) == "table" and type(message.n_message_id) == "number" then
        -- If this message ID has not been received already recently,
        -- return the message contents.
        if not received_ids[message.n_message_id] then
            received_ids[message.n_message_id] = os.clock()
            return message.message
        end
        -- Always keep the latest timestamp of the ID.
        received_ids[message.n_message_id] = os.clock()
    end
    return
end


--- Create and host a CryptoNet server, which other machines can remotely connect to. This function will load the certificate and private key of the server from the specified files, or generate new ones if no existing files are found. Note that serverName is the only required parameter; all the others have sensible defaults.
--- @param server_name string The name of the server, which clients will use to connect to it.     Also determines the channel that the server communicates on.
--- @param discoverable? boolean (default: true) Whether this server responds to discover() requests. Disabling this is more secure as it means clients can't connect unless they already know the name of the server.
--- @param hide_certificate? boolean (default: false) If true the server will not distribute its certificate to clients,  either in discover() or connect() requests, meaning clients can only  connect if they have already been given the certificate manually.  Useful if you only want certain manually authorised clients to be able to connect.
--- @param modem_side? string (default: a side that has a modem) The modem the server should use. certificate (table or string, default: "<serverName>.crt") The certificate of the server. This can either be the certificate table itself, or the name of a file that contains it. If the certicate and key files do not  exist, new ones will be generated and saved to the specified files.
--- @param private_key? table|string (default: "<serverName>_private.key") The private key of the server. This can either be the key table itself,  or the name of a file that contains it. If the certicate and key files do not  exist, new ones will be generated and saved to the specified files.
--- @param user_table_path? string (default: "<serverName>_users.tbl") Path at which to store the user login details table,   if/when users are added to the server.
--- @return Server # The server table
function Package.host(server_name, discoverable, hide_certificate, modem_side, certificate, private_key, user_table_path)
    if type(server_name) ~= "string" then
        error("Server name must be a string.", 2)
    end
    -- Don't allow duplicate server names.
    for _, server in pairs(all_servers) do
        if server.name == server_name then
            error("Server called " .. server_name .. " already exists.", 2)
        end
    end

    modem_side = Package.resolve_modem_side(modem_side)
    local modem = peripheral.wrap(modem_side)

    -- Generate default file names if none were provided, then get the paths
    -- relative to the current working directory.
    local cert_filename = type(certificate) == "string" and certificate or server_name .. ".crt"
    local key_filename = type(private_key) == "string" and private_key or server_name .. "_private.key"
    local certificate_path = working_dir == "" and cert_filename or working_dir .. "/" .. cert_filename
    local key_path = working_dir == "" and key_filename or working_dir .. "/" .. key_filename

    -- Now that we've extracted the filenames above, only store the actual certificate
    -- and key in these variables.
    if type(certificate) == "string" then certificate = nil end
    if type(private_key) == "string" then private_key = nil end

    if certificate ~= nil and not Package.certificate_valid(certificate) then
        error("Invalid certificate.", 2)
    end
    if private_key ~= nil and not Package.private_key_valid(private_key) then
        error("Invalid private key.", 2)
    end

    -- Try loading the certificate from file.
    if certificate == nil then
        log("Checking " .. certificate_path .. " for certificate...")
        if fs.isDir(certificate_path) then
            error(cert_filename .. " already exists and is a directory, not a certificate.", 2)
        elseif fs.exists(certificate_path) then
            local file = fs.open(certificate_path, "r")
            certificate = Package.deserialize_cert_or_key(file.readAll())
            file.close()

            if not Package.certificate_valid(certificate) then
                error(cert_filename .. " already exists and is not a valid certificate.", 2)
            else
                log("Loaded certificate from " .. cert_filename .. ".")
            end
        else
            log("Certificate file not found, will need to generate a new one.")
        end
    end

    -- Try loading the private key from file.
    if private_key == nil then
        log("Checking " .. key_path .. " for private key...")
        if fs.isDir(key_path) then
            error(key_filename .. " already exists and is a directory, not a keyfile.", 2)
        elseif fs.exists(key_path) then
            local file = fs.open(key_path, "r")
            private_key = Package.deserialize_cert_or_key(file.readAll())
            file.close()

            if not Package.private_key_valid(private_key) then
                error(key_filename .. " already exists and is not a valid keyfile.", 2)
            else
                log("Loaded private key from " .. key_filename .. ".")
            end
        else
            log("Private keyfile not found, will need to generate a new one.")
        end
    end

    -- If we have no certificate or private key yet, generate them.
    -- You can't just provide one and not the other, as the public and private
    -- keys must be generated as a pair.
    if certificate == nil and private_key == nil then
        log("No certificate or private key found, generating new ones.")
        certificate, private_key = Package.generate_certificate(server_name)

        local file = fs.open(certificate_path, "w")
        file.write(Package.serialize_cert_or_key(certificate))
        file.close()
        log("Saved certificate to " .. certificate_path .. ".")

        file = fs.open(key_path, "w")
        file.write(Package.serialize_cert_or_key(private_key))
        file.close()
        log("Saved private key to " .. key_path .. ".  Do not share this with anyone!")
    elseif certificate ~= nil and private_key == nil then
        error("Have a certificate but not a private key, need both or neither.", 2)
    elseif certificate == nil and private_key ~= nil then
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
    local channel = Package.get_channel(server_name)
    modem.open(channel)
    log("Hosting on channel " .. channel .. ".")

    if hide_certificate then
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
    if user_table_path == nil then
        user_table_path = server_name .. "_users.tbl"
    end
    local user_table
    if type(user_table_path) == "string" then
        -- Append the current working directory to the table path.
        user_table_path = working_dir == "" and user_table_path or working_dir .. "/" .. user_table_path
        user_table = Package.load_user_table(user_table_path)
    else
        error("userTablePath must be a string.", 2)
    end

    -- Create the server table.
    local server = {
        name = server_name,
        certificate = certificate,
        private_key = private_key,
        modem_side = modem_side,
        channel = channel,
        hide_certificate = hide_certificate,
        discoverable = discoverable or discoverable == nil, -- Default to true
        user_table = user_table,
        user_table_path = user_table_path,
        sockets = {} -- New servers have no connections yet.
    }

    table.insert(all_servers, server)
    log("Server ready.")
    return server
end

--- Close a socket or server, such that it will not listen for messages anymore. Closing a server closes all its sockets.
--- @param socket Socket|Server The socket or server to close.
function Package.close(socket)
    if Package.socket_valid(socket) then
        -- Let the other end of the socket know it has been closed.
        -- Don't send if this one was closed remotely, since the other end clearly
        -- already knows.
        if not socket.closed_remotely then
            send_encrypted_internal(socket, "c")
        end
        if socket.server == nil then
            -- If this is a client socket, remove it from the list of client sockets.
            -- This will stop handleModemEvent() from processing messages for it.
            for i = 1, #all_client_sockets do
                if all_client_sockets[i] == socket then
                    table.remove(all_client_sockets, i)
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
        if not Package.channel_in_use(socket.channel, socket.modem_side) then
            peripheral.wrap(socket.modem_side).close(socket.channel)
            log("Closed socket channel " .. socket.channel .. " on modem " .. socket.modem_side .. ".")
        end
        log("Closed socket.")
    elseif Package.server_valid(socket) then
        -- If this is a server being closed...
        local server = socket
        -- Create a copy of the server's socket list and close them all.
        -- Closing a socket will remove it from the server's socket list,
        -- so we make a copy so it doesn't change while we're trying to iterate
        -- over it.
        local sockets_copy = {}
        for _, soc in pairs(server.sockets) do
            table.insert(sockets_copy, soc)
        end
        for _, soc in pairs(sockets_copy) do
            Package.close(soc)
        end

        -- Remove the closed server from the server list.
        -- This will stop handleModemEvent() from processing messages for it.
        for i = 1, #all_servers do
            if all_servers[i] == server then
                table.remove(all_servers, i)
                break
            end
        end

        -- If this was the only server/socket communicating on its channel, close the channel
        -- on the modem. Don't close the channel if another socket is still using it.
        if not Package.channel_in_use(server.channel, server.modem_side) then
            peripheral.wrap(server.modem_side).close(server.channel)
            log("Closed server channel " .. server.channel .. " on modem " .. server.modem_side .. ".")
        end

        -- If this was the only server using the discovery channel, close it.
        if server.discoverable then
            local found = false
            for _, srvr in pairs(all_servers) do
                if srvr.discoverable and srvr.modem_side == server.modem_side then
                    found = true
                    break
                end
            end
            if not found then
                peripheral.wrap(server.modem_side).close(DISCOVERY_CHANNEL)
                log("Closed discovery channel.")
            end
        end
    else
        error("Must be a valid socket or server.", 2)
    end
end

-- Close all sockets and servers on this machine.
function Package.close_all()
    -- Iteratve backwards so the list isn't chaning in front of us.
    for i = #all_client_sockets, 1, -1 do
        Package.close(all_client_sockets[i])
    end
    for i = #all_servers, 1, -1 do
        Package.close(all_servers[i])
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
local function handle_decrypted_message(socket, message)
    local ok = true
    local result = nil
    if message == "c" then
        log("Connection closed by other end.")
        socket.closed_remotely = true
        -- Close our end of the socket too.
        Package.close(socket)
        socket.closed_remotely = nil
        result = { "connection_closed", socket, socket.server }
    elseif message:sub(1, 2) == "lr" then
        -- Login requests have the format lr{username,password}
        -- Note that the password will have already been hashed using hashPassword()
        -- by the client before sending.
        local request = textutils.unserialize(message:sub(3))
        if type(request) == "table" and type(request[1]) == "string" and type(request[2]) == "string" then
            result = { Package.login_hashed(socket, request[1], request[2]) }
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
            socket.permission_level = details[2]
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
            socket.permission_level = 0

            if username == nil then
                log("Already logged out.")
            else
                log(username .. " logged out.")
            end
            result = { "logout", username, socket, nil }
        else
            -- On server side call logout() to also send a message to the client
            -- to tell it to log out.
            result = { Package.logout(socket) }
        end
    else
        -- If the message had none of the above internal message types,
        -- it must be a user-generated encrypted message, which will start with
        -- a data type character. Attempt to deserialize the message as such.
        ok, message = pcall(deserialize_any, message)
        if ok then
            result = { "encrypted_message", message, socket, socket.server }
        end
    end
    return ok, result
end


-- See if the given CryptoNet message is relevant to this server, and act upon
-- it as needed. May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handle_server_message(server, message, message_channel)
    -- Check if this message is a discovery request,
    -- and respond to it if and only if the server is discoverable.
    if message_channel == DISCOVERY_CHANNEL and message.msg_type == "discovery_request" and server.discoverable then
        -- Remove the public key and signature from the certificate if needed.
        local certificate = server.hide_certificate and { name = server.name } or server.certificate
        send_internal(server.modem_side, DISCOVERY_CHANNEL, nil, certificate, "discovery_response")
        log("Responded to discovery request.")
        -- If this is a message directed at this server...
    elseif message_channel == server.channel and message.target == server.name then
        if message.msg_type == "certificate_request" and not server.hide_certificate then
            send_internal(server.modem_side, server.channel, nil, server.certificate, "certificate_response")
            log("Responded to certificate request.")
        elseif message.msg_type == "connection_request" and type(message.message) == "string" then
            -- The client will have sent a session key, encryped using the server's public key.
            -- We need to use the private key to decrypt it and use the session key to send
            -- an acknowledgement to the client.
            local encrypted_key = message.message
            if server.sockets[encrypted_key] ~= nil then
                -- This is probably a repeated message, as we have already processed it before.
                log("Received duplicate connection request, ignoring it.")
            else
                -- Try to decrypt the session key using the server's private key.
                local ok, num_key = pcall(Rsa.crypt, server.private_key, encrypted_key)
                local sess_key
                ok, sess_key = pcall(Rsa.number_to_bytes, num_key, 16 * 8, 8)
                -- Validate the key, which should be a table of 16 bytes.
                if ok and (sess_key == nil or #sess_key ~= 16) then
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
                    server.certificate.key.public .. server.certificate.key.shared .. num_key))
                    -- Encrypt the message.
                    local iv = Package.generate_key()
                    response = Aes.encrypt_str(response, sess_key, iv)
                    -- From now on the client will be identified by it's encrypted session key.
                    send_internal(server.modem_side, server.channel, encrypted_key,
                        { { string.byte(response, 1, response:len()) }, iv }, "connection_response")
                    log("Responded to connection request.")

                    -- Create the socket object pointing to the client.
                    local socket = {
                        sender = server.name,
                        target = encrypted_key,
                        key = sess_key,
                        modem_side = server.modem_side,
                        channel = server.channel,
                        server = server,
                        permission_level = 0,
                        received_messages = {}
                    }
                    server.sockets[encrypted_key] = socket
                    return { "connection_opened", socket, server }
                end
            end
        elseif message.msg_type == "encrypted_message" and type(message.message) == "table" and #message.message == 2
            and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
            -- If this is an encrypted message, try decrypting it with the session key
            -- and handle the decrypted message as needed.
            local socket = server.sockets[message.sender]
            local encrypted = bytes_to_string(message.message[1])
            local iv = message.message[2]
            if socket == nil then
                log("Received a message from a sender who has yet to open a connection.")
            elseif encrypted == nil then
                log("Received invalid message.")
            elseif socket.received_messages[encrypted] then
                -- The encryption algorithm adds random numbers to each message before
                -- encrypting it, so even if two messages are identical their encrypted
                -- versions will probably be different. Therefore if we receive the exact
                -- same encrypted message twice it is most likely a malicious duplicate
                -- made by someone without the session key, and so should be ignored.
                log("Received duplicate message, ignoring it.")
            else
                -- Remember we have received this message so we don't accept it again
                -- (see above).
                socket.received_messages[encrypted] = true
                local ok, decrypted = pcall(Aes.decrypt_str, encrypted, socket.key, iv)
                if ok then
                    local ok, result = handle_decrypted_message(socket, decrypted)
                    if ok and result ~= null then
                        return result
                    end
                end
                if not ok then
                    log("Received invalid message.")
                end
            end
        elseif message.msg_type == "plain_message" then
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
local function handle_client_message(socket, message, message_channel)
    -- If this is a message directed at this socket...
    if message_channel == socket.channel and message.sender == socket.target and message.target == socket.sender then
        if message.msg_type == "encrypted_message" and type(message.message) == "table" and #message.message == 2
            and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
            local encrypted = bytes_to_string(message.message[1])
            local iv = message.message[2]
            if encrypted == nil then
                log("Received invalid message.")
            elseif socket.received_messages[encrypted] then
                -- The encryption algorithm adds random numbers to each message before
                -- encrypting it, so even if two messages are identical their encrypted
                -- versions will probably be different. Therefore if we receive the exact
                -- same encrypted message twice it is most likely a malicious duplicate
                -- made by someone without the session key, and so should be ignored.
                log("Received duplicate message, ignoring it.")
            else
                socket.received_messages[encrypted] = true
                -- Decrypt the message with the session key and handle as needed.
                local ok, decrypted = pcall(Aes.decrypt_str, encrypted, socket.key, iv)
                if ok then
                    local ok, result = handle_decrypted_message(socket, decrypted)
                    if ok then
                        return result
                    end
                end
                if not ok then
                    log("Received invalid message.")
                end
            end
        elseif message.msg_type == "plain_message" then
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
local function handle_modem_event(event, received_ids)
    -- Check if the modem message was a CryptoNet-formatted message, and extract
    -- the message contents.
    local message = extract_message(event[5], received_ids)
    if message ~= nil then
        -- Try passing the message to all servers on this machine.
        for _, server in pairs(all_servers) do
            local result = handle_server_message(server, message, event[3])
            if result ~= nil then
                return result
            end
        end

        -- Try passing the message to all client sockets on this machine.
        for _, socket in pairs(all_client_sockets) do
            local result = handle_client_message(socket, message, event[3])
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
function Package.listen()
    -- Message IDs recently received by this machine that we don't want to
    -- process repeat copies of.
    local received_ids = {}
    -- Keep listening for and handling modem_messages until
    -- a CryptoNet event is raised.
    while true do
        local event = { os.pullEvent("modem_message") }
        local new_event = handle_modem_event(event, received_ids)
        if new_event ~= nil then
            return table.unpack(new_event)
        end
    end
end

--- Request the certificates of all online CryptoNet servers on the network. Some servers may have been set to not respond to discovery requests, and some will only contain the server name in the certificate, excluding the public key required to connect to the server. This function can optionally use a certificate authority public key to verify the signatures of certificates, only returning certificates with valid signatures. By default discover() looks for the public key in "certAuth.key".
--- @param timeout? number (default: 1) The time in seconds to spend listening for responses.
--- @param cert_auth_key? PublicKey|string (default: "certAuth.key") The certificate authority public key used to verify signatures,   or the path of the file to load it from. If no valid key is found   the discovery will still go ahead, but signatures will not be checked.
--- @param allow_unsigned? boolean (default: false) Whether to include certificates with no valid signature in the results.   If no valid cert auth key is provided this is ignored, as the certificates   cannot be checked without a key.
--- @param modem_side? string (default: a side with a modem) The modem to use to send and receive messages.
--- @return table # a table of the certificates received, all of which will include the name of server and possibly also the public key and signature.
function Package.discover(timeout, cert_auth_key, allow_unsigned, modem_side)
    -- Load and validate the key.
    cert_auth_key = Package.load_cert_auth_key(cert_auth_key)

    modem_side = Package.resolve_modem_side(modem_side)
    local modem = peripheral.wrap(modem_side)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local was_open = modem.isOpen(DISCOVERY_CHANNEL)
    modem.open(DISCOVERY_CHANNEL)

    log("Discovering...")
    send_internal(modem_side, DISCOVERY_CHANNEL, nil, nil, "discovery_request")

    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local received_ids = {}
    -- The received certificates.
    local certificates = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == DISCOVERY_CHANNEL then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extract_message(event[5], received_ids)
            -- If this is a discovery_response with a correctly formatted certifiate...
            if message ~= nil and message.msg_type == "discovery_response" and Package.certificate_valid(message.message, true) then
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
    if not was_open then
        modem.close(DISCOVERY_CHANNEL)
    end

    -- If we have a valid cert auth key to use,
    -- verify the signatures of the received certificates.
    -- If allowUnsigned is false any certificates without valid signatures
    -- will be removed.
    if cert_auth_key ~= nil and #certificates > 0 then
        log("Checking signatures...")
        -- Iterate backwards as we will be deleting from the list.
        for i = #certificates, 1, -1 do
            local certificate = certificates[i]
            if certificate.signature == nil then
                if not allow_unsigned then
                    log("Discarding " .. certificate.name .. " as it has no signature.")
                    table.remove(certificates, i)
                end
            else
                local ok, valid = pcall(Package.verify_certificate, certificate, cert_auth_key)
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
--- @param server_name string (required) The name of the server to request the certificate of.
--- @param timeout? number (default: 1) The length of time in seconds to wait for responses.   The function will always wait the full time (to allow for duplicates.
--- @param cert_auth_key? table|string (default: "certAuth.key") The certificate authority public key used to verify signatures,   or the path of the file to load it from. If no valid key is found   the request will still go ahead, but signatures will not be checked.
--- @param allow_unsigned? boolean (default: false) Whether to accept certificates with no valid signature.   If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key.
--- @param modem_side? string (default: a side with a modem) The modem to use to send and receive messages.
--- @return Certificate|nil # certificate of the server if exactly one is received, or nil if zero or more than one acceptable certificates are found.
--- @return table # a table of all acceptable certificates received.
function Package.request_certificate(server_name, timeout, cert_auth_key, allow_unsigned, modem_side)
    if type(server_name) ~= "string" then
        error("Server name must be a string.", 2)
    end
    cert_auth_key = Package.load_cert_auth_key(cert_auth_key)

    modem_side = Package.resolve_modem_side(modem_side)
    local modem = peripheral.wrap(modem_side)
    local channel = Package.get_channel(server_name)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local was_open = modem.isOpen(channel)
    modem.open(channel)

    log("Requesting certificate...")
    send_internal(modem_side, channel, server_name, nil, "certificate_request")

    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local received_ids = {}
    -- The received certificates.
    local certificates = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == channel then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extract_message(event[5], received_ids)
            -- If this is a certificate_response with a correctly formatted certifiate,
            -- for the correct server...
            if message ~= nil and message.msg_type == "certificate_response" and Package.certificate_valid(message.message) and message.message.name == server_name then
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
    if not was_open then
        modem.close(channel)
    end

    -- If we have a valid cert auth key to use,
    -- verify the signatures of the received certificates.
    -- If allowUnsigned is false any certificates without valid signatures
    -- will be removed.
    local signed_count = 0
    if cert_auth_key ~= nil and #certificates > 0 then
        log("Checking signatures...")
        -- Iterate backwards as we will be deleting from the list.
        for i = #certificates, 1, -1 do
            local certificate = certificates[i]
            if certificate.signature == nil then
                if not allow_unsigned then
                    log("Discarding a certificate as it has no signature.")
                    table.remove(certificates, i)
                end
            else
                local ok, valid = pcall(Package.verify_certificate, certificate, cert_auth_key)
                if ok and valid then
                    -- Keep the certificate.
                    log("This certificate has a valid signature.")
                    signed_count = signed_count + 1
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
        elseif signed_count > 1 then
            log("Multiple (" ..
            signed_count .. ") certificates had valid signatures, has the certificate authority authorized impersonators?")
        else
            log("Multiple (" .. #certificates .. ") certificates found, some may be malicious.")
        end
        -- Don't return any certificate as the chosen one, but still return the whole list.
        return nil, certificates
    end
end

--- Open an encrypted connection to a CryptoNet server, returning a socket object that can be used to send and receive messages from the server.
--- @param server_name? string (default: inferred from certificate) The name of the server to connect to.
--- @param timeout? number (default: 5) The number of seconds to wait for a response to the connection request. Will terminate early if a response is received.
--- @param cert_timeout? number (default: 1) The number of seconds to wait for certificate responses, if no certificate was provided.
--- @param certificate? table|string (default: "<serverName>.crt") The certificate of the server. Can either be the certificate of the server itself, or the name of a file that contains it. If no valid certificate is found a certificate request will be sent to the server.
--- @param modem_side? string (default: a side with a modem) The modem to use to send and receive messages.
--- @param cert_auth_key? table|string (default: "certAuth.key") The certificate authority public key used to verify signatures, or the path of the file to load it from. If no valid key is found the connection will still go ahead, but signatures will not be checked.
--- @param allow_unsigned? boolean (default: false) Whether to accept certificates with no valid signature. If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key. This does not apply to the certificate provided by the user (if present), which is never verified (we trust them to get their own certificate right), only to certificates received through a certificate request.
--- @return Socket # a socket object that can be used to communicate with the server.
function Package.connect(server_name, timeout, cert_timeout, certificate, modem_side, cert_auth_key, allow_unsigned)
    if server_name ~= nil and type(server_name) ~= "string" then
        error("Server name must be a string or nil.", 2)
    end
    if certificate == nil then
        if type(server_name) == "string" then
            -- If a server name was given but not a certificate,
            -- try to load a corresponding certificate from file.
            certificate = server_name .. ".crt"
        else
            -- Need a way to identify the server.
            error("Server name and certificate can't both be nil.", 2)
        end
    end

    -- If the certificate is a file path...
    if type(certificate) == "string" then
        local cert_filename = certificate
        -- Make paths relative to the current CryptoNet working directory.
        local cert_path = working_dir == "" and cert_filename or working_dir .. "/" .. cert_filename
        log("Checking " .. cert_path .. " for certificate...")
        if fs.isDir(cert_path) or not fs.exists(cert_path) then
            if fs.isDir(cert_path) then
                log(cert_filename .. " is not a file, will need to request certificate.")
            else
                log(cert_filename .. " does not exist, will need to request certificate.")
            end
            certificate = nil
        else
            local file = fs.open(cert_path, "r")
            certificate = Package.deserialize_cert_or_key(file.readAll())
            file.close()

            if not Package.certificate_valid(certificate) then
                log(cert_filename .. " does not contain a valid certificate, will need to request certificate.")
                certificate = nil
            else
                log("Loaded certificate from " .. cert_filename .. ".")
            end
        end
    elseif not Package.certificate_valid(certificate) then
        -- If certificate was not a string, it should be a valid certificate.
        error("Invalid certificate.", 2)
    end

    -- Infer serverName from the certificate.
    if server_name == nil then
        if certificate ~= nil then
            server_name = certificate.name
        else
            error("Failed to load name from certificate, and no name was provided.", 2)
        end
    end

    modem_side = Package.resolve_modem_side(modem_side)
    local modem = peripheral.wrap(modem_side)
    local channel = Package.get_channel(server_name)
    -- Remember if the modem was already open so we can
    -- close it afterwards if it wasn't.
    local was_open = modem.isOpen(channel)
    modem.open(channel)

    -- If we have no certificate yet, request it from the server.
    if certificate == nil then
        certificate = Package.request_certificate(server_name, cert_timeout, cert_auth_key, allow_unsigned, modem_side)
        if certificate == nil then
            -- Close the modem channel if it wasn't open before we started.
            if not was_open then
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
    local sess_key = Package.generate_key()
    local num_key = Rsa.bytes_to_number(sess_key, 16 * 8, 8)
    local encrypted_key = Rsa.crypt(certificate.key, num_key)
    -- The server will send a response encrypted with the session key to prove
    -- that it has received is successfully. We know what the response content
    -- is supposed to be, allowing us to verify the response.
    local expected_response = tostring(Sha256.digest(server_name .. certificate.key.public ..
    certificate.key.shared .. num_key))
    send_internal(modem_side, channel, server_name, encrypted_key, "connection_request")

    log("Awaiting response...")
    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local received_ids = {}
    -- Set a timer for when the timeout expires.
    local timer = os.startTimer((type(timeout) == "number") and timeout or 5)
    while true do
        -- Wait for either a modem_message or timer event.
        local event = { os.pullEvent() }
        if event[1] == "modem_message" and event[3] == channel then
            -- See if this is a CryptoNet-formatted message and exract its contents.
            local message = extract_message(event[5], received_ids)
            -- If the message is a valid connection_response directed at this socket,
            -- containing a valid encrypted message...
            if message ~= nil and message.msg_type == "connection_response" and message.target == encrypted_key and type(message.message) == "table"
                and #message.message == 2 and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
                -- Decrypt using the session key.
                local ok, actual_response = pcall(Aes.decrypt_str, bytes_to_string(message.message[1]), sess_key,
                    message.message[2])
                -- Compare the response to what we know the response content is supposed
                -- to be, to see if the session key was received correctly.
                if ok and actual_response == expected_response then
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
            if not was_open then
                modem.close(channel)
            end
            error("Did not receive a response before timeout.", 2)
        end
    end

    -- Create and return the socket object.
    local socket = { sender = encrypted_key, target = server_name, key = sess_key, modem_side = modem_side, channel = channel, permission_level = 0, received_messages = {} }
    table.insert(all_client_sockets, socket)
    return socket
end

--
-- EVENT LOOP
--

--- Run a background loop that listens for events of any kind, and calls an optional event handler on every event. The event handler is always called in a new thread, so it is okay to use blocking functions such as sleep() and pullEvent() within onEvent without freezing the whole program. Errors raised during event handling are printed without terminating the whole program, so errors processing one event won't bring down the entire system.
---
--- Any modem_message events are also sent to CryptoNet for handling, allowing all sockets and servers on this machine to listen for messages in the background. Both the modem_message itself and any CryptoNet events invoked by it are sent to the event handler, on seperate iterations of the event loop.
--- @param on_event function The function to call on every event. Optional.
local function event_loop(on_event)
    -- List of response message IDs we've already received
    -- so we can ignore duplicates.
    local received_ids = {}
    while true do
        -- Wrap everything in pcall so any errors won't exit the entire program,
        -- only this iteration of the loop.
        local ok, msg = pcall(function()
            -- Listen for all event types.
            local event = { os.pullEvent() }
            if event[1] == "modem_message" then
                local new_event = handle_modem_event(event, received_ids)
                if new_event ~= nil then
                    -- This event will be processed on a later iteration of the loop.
                    os.queueEvent(table.unpack(new_event))
                end
            end
            -- Call the event handler in a new thread.
            if on_event ~= nil then
                Threading.new(function()
                    -- We need another pcall here since this is in a different thread
                    -- to the outer pcall, so that one won't be able to catch errors
                    -- from the handler.
                    local ok, msg = pcall(on_event, event)
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
--- @param on_start function The function to call once after the loop starts. Optional.
--- @param on_event function The function to call on every event. Optional.
function Package.start_event_loop(on_start, on_event)
    if on_start ~= nil and type(on_start) ~= "function" then
        error("on_start is not a function.", 2)
    end
    if on_event ~= nil and type(on_event) ~= "function" then
        error("on_event is not a function.", 2)
    end

    -- Start the event loop in a different thread.
    Threading.new(function() event_loop(on_event) end)
    -- Call on_start in this thread.
    if on_start ~= nil then
        local ok, msg = pcall(on_start)
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
--- @param public_filename string The name of the file to save the public key to. Defaults to "certAuth.key".
--- @param private_filename string The name of the file to save the private key to. Defaults to "certAuth_private.key".
function Package.init_certificate_authority(public_filename, private_filename)
    if public_filename == nil then
        public_filename = "certAuth.key"
    end
    if private_filename == nil then
        private_filename = "certAuth_private.key"
    end
    -- Math paths relative to the current CryptoNet working directory.
    local public_path = working_dir == "" and public_filename or working_dir .. "/" .. public_filename
    local private_path = working_dir == "" and private_filename or working_dir .. "/" .. private_filename

    if fs.exists(public_path) then
        error(public_path .. " already exists, please delete both your existing keyfiles in order to generate new ones.",
            2)
    end
    if fs.exists(private_path) then
        error(private_path .. " already exists, please delete both your existing keyfiles in order to generate new ones.",
            2)
    end

    log("Generating key pair... (may take some time)")
    local public_key, private_key = Keygen.generate_key_pair()
    print("")
    log("Done!")

    local file = fs.open(public_path, "w")
    file.write(Package.serialize_cert_or_key(public_key))
    file.close()
    log("Saved public key to " .. public_path .. ".  Give this to client users.")

    file = fs.open(private_path, "w")
    file.write(Package.serialize_cert_or_key(private_key))
    file.close()
    log("Saved private key to " .. private_path .. ".  Do not share this with anyone!")

    log("Initialization successful.")
end

--- Sign a certificate using the certificate authority's private key. Both arguments can either be the certificate/key itself, or a path to a file that contains it. The signed certificate is returned, and written to the path the certificate was stored in, if it was loaded from file.
--- @param certificate Certificate|string The certificate to sign, or the path to the file that contains it.
--- @param private_key PrivateKey|string The private key to sign the certificate with, or the path to the file that contains it.
function Package.sign_certificate(certificate, private_key)
    local cert_path = nil
    if type(certificate) == "string" then
        -- Make paths relative to the current CryptoNet working directory.
        cert_path = working_dir == "" and certificate or working_dir .. "/" .. certificate
        if not fs.exists(cert_path) then
            error(cert_path .. " does not exist.", 2)
        end
        if fs.isDir(cert_path) then
            error(cert_path .. " is not a file.", 2)
        end

        local file = fs.open(cert_path, "r")
        certificate = Package.deserialize_cert_or_key(file.readAll())
        file.close()

        if not Package.certificate_valid(certificate) then
            error(cert_path .. " does not contain a valid certificate.", 2)
        end
        log("Loaded certificate from " .. cert_path .. ".")
    elseif not Package.certificate_valid(certificate) then
        -- If certificate is not a file path it should be a valid certificate.
        error("Not a valid certificate or file.", 2)
    end

    -- Default value.
    if private_key == nil then
        private_key = "certAuth_private.key"
    end
    if type(private_key) == "string" then
        -- Make paths relative to the current CryptoNet working directory.
        local key_path = working_dir == "" and private_key or working_dir .. "/" .. private_key
        if not fs.exists(key_path) then
            error(key_path .. " does not exist.", 2)
        end
        if fs.isDir(key_path) then
            error(key_path .. " is not a file.", 2)
        end

        local file = fs.open(key_path, "r")
        private_key = Package.deserialize_cert_or_key(file.readAll())
        file.close()

        if not Package.private_key_valid(private_key) then
            error(key_path .. " does not contain a valid private key.", 2)
        end
        log("Loaded private key from " .. key_path .. ".")
    elseif not Package.private_key_valid(private_key) then
        -- If privateKey is not a file path it should be a valid private key.
        error("Not a valid private key or file.", 2)
    end

    -- The signature is just the contents of the certificate hashed and encrypted.
    -- Clients can verify the signature by decrypting it with the cert auth public key
    -- and seeing if it matches the contents of the certificate.
    log("Generating signature...")
    local hash = Sha256.digest(certificate.name .. certificate.key.public .. certificate.key.shared)
    certificate.signature = Rsa.crypt(private_key, Rsa.bytes_to_number(hash, 32 * 8, 8))

    -- If the certificate was loaded from a file, save it back there.
    if cert_path ~= nil then
        local file = fs.open(cert_path, "w")
        file.write(Package.serialize_cert_or_key(certificate))
        file.close()
        log("Saved certificate to " .. cert_path .. ".")
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
    Package.set_logging_enabled(true)
    -- Set the CryptoNet working directory to match the system one.
    Package.set_working_directory(shell.dir())

    local args = { ... }
    if args[1] == "signCert" then
        -- Sign a certificate loaded from a file.
        local cert_path = args[2]
        if cert_path == nil then
            log("Usage: cryptoNet signCert <file>")
            return
        end

        -- Make paths relative to the working directory.
        cert_path = working_dir == "" and cert_path or working_dir .. "/" .. cert_path
        -- Optional private key file argument, can be omitted to use default.
        local key_path = args[3]
        local ok, msg = pcall(Package.sign_certificate, cert_path, key_path)

        if not ok then
            log("Error: " .. msg:sub(8))
        end
    elseif args[1] == "initCertAuth" then
        -- Generate the cert auth key pair and save them to the specified files.
        -- The file arguments can be omitted to use the default values.
        local ok, msg = pcall(Package.init_certificate_authority, args[2], args[3])
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
--- @field modem_side string The modem used by the socket
--- @field channel number The channel the server (and this socket) use to communicate
--- @field permission_level number The permission level of the user logged into the socket, initialized to 0.
--- @field received_messages table The encrypted messages received by this socket, used to prevent replay attacks using duplicate messages. Every time a message is encrypted the encrypted version will be different due to randomness in the algorithm, so if the socket gets the exact same message twice it is probably a malicious duplicate.
--- @field username string The username of the user logged into the socket, initialized to nil.

--- @class Server
--- @field name string The server name
--- @field certificate Certificate The server's certificate
--- @field private_key string The server's private key
--- @field modem_side string The modem used by the server
--- @field channel number The channel number the server communicates on
--- @field hide_certificate boolean Whether the server distributes its certificate to clients
--- @field discoverable boolean Whether the server responds to discover() requests
--- @field user_table table The table of user login details for the server, loaded from file or empty by default
--- @field user_table_path string The name of the user table file
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

return Package
