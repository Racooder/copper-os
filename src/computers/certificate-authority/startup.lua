CryptoNet = require "CryptoNet"

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

local SERVER_NAME = "certAuth"

local function loadCertMap()
    print("Loading certificate map...")
    if fs.exists("certMap.tbl") then
        local f = fs.open("certMap.tbl", "r");
        local cm = textutils.unserialize(f.readAll())
        f.close()
        return cm
    end
    return {}
end

--- A map of hostnames to their public key
local certMap = loadCertMap()

local function saveCertMap()
    local f = fs.open("certMap.tbl", "w")
    f.write(textutils.serialize(certMap))
    f.close()
end

local function handleSignatureRequest(unsigned, socket)
    -- Check if certificate is valid
    if not CryptoNet.certificateValid(unsigned) then
        return
    end
    -- Check if certificate is used
    if certMap[unsigned.name] ~= nil and not equals(certMap[unsigned.name], unsigned.key, true) then
        print("Signature request for occupied hostname: " .. unsigned["name"])
        CryptoNet.send(socket, {"system", {"error", "Hostname already used!"}})
        return
    end
    -- Sign certificate
    certMap[unsigned.name] = unsigned.key
    local signed = CryptoNet.signCertificate(unsigned)
    CryptoNet.send(socket, {"system", {"certSignature", signed}})
    saveCertMap()
end

local function onEvent(event)
    -- Reject unwanted events
    if type(event) ~= "table" or event[1] ~= "encrypted_message" then
        return
    end
    local package = event[2]
    -- Reject non system packages
    if type(package) ~= "table" or package[1] ~= "system" then
        return
    end
    local message = package[2]
    -- Reject malformed messages
    if type(message) ~= "table" then
        return
    end
    -- Handle Messages
    if message[1] == "signCertificate" and type(message[2]) == "table" then
        handleSignatureRequest(message[2], event[3])
    end
end

local function onStart()
    CryptoNet.host(SERVER_NAME)
end

-- Setup
if (not fs.exists("certAuth.key")) then
    print("Setting up Certificate Authority...")
    CryptoNet.initCertificateAuthority()
    local keyFile = fs.open("certAuth.key", "r")
    local key = keyFile.readAll()
    keyFile.close()
    local cert = "{\nname = \"certAuth\",\nkey = " .. key .. ",\n}"
    local certFile = fs.open("certAuth.crt", "w")
    certFile.write(cert)
    certFile.close()
    CryptoNet.signCertificate("certAuth.crt")
end

CryptoNet.startEventLoop(onStart, onEvent)
