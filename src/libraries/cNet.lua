local CryptoNet = require "cryptoNet"
local utility = require "copperUtility"

--* Crc32 by SafeteeWoW (https://gist.github.com/SafeteeWoW/080e784e5ebfda42cad486c58e6d26e4)

local LibDeflate = {}
local string_byte = string.byte

-- Calculate xor for two unsigned 8bit numbers (0 <= a,b <= 255)
local function Xor8(a, b)
	local ret = 0
	local fact = 128
	while fact > a and fact > b do
		fact = fact / 2
	end
	while fact >= 1 do
        ret = ret + (((a >= fact or b >= fact)
			and (a < fact or b < fact)) and fact or 0)
        a = a - ((a >= fact) and fact or 0)
        b = b - ((b >= fact) and fact or 0)
	    fact = fact / 2
	end
	return ret
end

-- table to cache the result of uint8 xor(x, y)  (0<=x,y<=255)
local _xor8_table

local function GenerateXorTable()
	assert(not _xor8_table)
	_xor8_table = {}
	for i = 0, 255 do
		local t = {}
		_xor8_table[i] = t
		for j = 0, 255 do
			t[j] = Xor8(i, j)
		end
	end
end


-- 4 CRC tables.
-- Each table one byte of the value in the traditional crc32 table.
-- _crc_table0 stores the least significant byte.
-- _crc_table3 stores the most significant byte.
local _crc_table0 = {
	[0]=0,150,44,186,25,143,53,163,50,164,30,136,43,189,7,145,100,242,72,222,
	125,235,81,199,86,192,122,236,79,217,99,245,200,94,228,114,209,71,253,107,
	250,108,214,64,227,117,207,89,172,58,128,22,181,35,153,15,158,8,178,36,135,
	17,171,61,144,6,188,42,137,31,165,51,162,52,142,24,187,45,151,1,244,98,216,
	78,237,123,193,87,198,80,234,124,223,73,243,101,88,206,116,226,65,215,109,
	251,106,252,70,208,115,229,95,201,60,170,16,134,37,179,9,159,14,152,34,180,
	23,129,59,173,32,182,12,154,57,175,21,131,18,132,62,168,11,157,39,177,68,
	210,104,254,93,203,113,231,118,224,90,204,111,249,67,213,232,126,196,82,241,
	103,221,75,218,76,246,96,195,85,239,121,140,26,160,54,149,3,185,47,190,
	40,146,4,167,49,139,29,176,38,156,10,169,63,133,19,130,20,174,56,155,13,183,
	33,212,66,248,110,205,91,225,119,230,112,202,92,255,105,211,69,120,238,84,
	194,97,247,77,219,74,220,102,240,83,197,127,233,28,138,48,166,5,147,41,191,
	46,184,2,148,55,161,27,141}
local _crc_table1 = {
	[0]=0,48,97,81,196,244,165,149,136,184,233,217,76,124,45,29,16,32,113,65,
	212,228,181,133,152,168,249,201,92,108,61,13,32,16,65,113,228,212,133,181,
	168,152,201,249,108,92,13,61,48,0,81,97,244,196,149,165,184,136,217,233,124,
	76,29,45,65,113,32,16,133,181,228,212,201,249,168,152,13,61,108,92,81,97,48,
	0,149,165,244,196,217,233,184,136,29,45,124,76,97,81,0,48,165,149,196,244,
	233,217,136,184,45,29,76,124,113,65,16,32,181,133,212,228,249,201,152,168,
	61,13,92,108,131,179,226,210,71,119,38,22,11,59,106,90,207,255,174,158,147,
	163,242,194,87,103,54,6,27,43,122,74,223,239,190,142,163,147,194,242,103,87,
	6,54,43,27,74,122,239,223,142,190,179,131,210,226,119,71,22,38,59,11,90,106,
	255,207,158,174,194,242,163,147,6,54,103,87,74,122,43,27,142,190,239,223,
	210,226,179,131,22,38,119,71,90,106,59,11,158,174,255,207,226,210,131,179,
	38,22,71,119,106,90,11,59,174,158,207,255,242,194,147,163,54,6,87,103,122,
	74,27,43,190,142,223,239}
local _crc_table2 = {
	[0]=0,7,14,9,109,106,99,100,219,220,213,210,182,177,184,191,183,176,185,190,
	218,221,212,211,108,107,98,101,1,6,15,8,110,105,96,103,3,4,13,10,181,178,
	187,188,216,223,214,209,217,222,215,208,180,179,186,189,2,5,12,11,111,104,
	97,102,220,219,210,213,177,182,191,184,7,0,9,14,106,109,100,99,107,108,101,
	98,6,1,8,15,176,183,190,185,221,218,211,212,178,181,188,187,223,216,209,214,
	105,110,103,96,4,3,10,13,5,2,11,12,104,111,102,97,222,217,208,215,179,180,
	189,186,184,191,182,177,213,210,219,220,99,100,109,106,14,9,0,7,15,8,1,6,98,
	101,108,107,212,211,218,221,185,190,183,176,214,209,216,223,187,188,181,178,
	13,10,3,4,96,103,110,105,97,102,111,104,12,11,2,5,186,189,180,179,215,208,
	217,222,100,99,106,109,9,14,7,0,191,184,177,182,210,213,220,219,211,212,221,
	218,190,185,176,183,8,15,6,1,101,98,107,108,10,13,4,3,103,96,105,110,209,
	214,223,216,188,187,178,181,189,186,179,180,208,215,222,217,102,97,104,111,
	11,12,5,2}
local _crc_table3 = {
	[0]=0,119,238,153,7,112,233,158,14,121,224,151,9,126,231,144,29,106,243,132,
	26,109,244,131,19,100,253,138,20,99,250,141,59,76,213,162,60,75,210,165,53,
	66,219,172,50,69,220,171,38,81,200,191,33,86,207,184,40,95,198,177,47,88,
	193,182,118,1,152,239,113,6,159,232,120,15,150,225,127,8,145,230,107,28,133,
	242,108,27,130,245,101,18,139,252,98,21,140,251,77,58,163,212,74,61,164,211,
	67,52,173,218,68,51,170,221,80,39,190,201,87,32,185,206,94,41,176,199,89,46,
	183,192,237,154,3,116,234,157,4,115,227,148,13,122,228,147,10,125,240,135,
	30,105,247,128,25,110,254,137,16,103,249,142,23,96,214,161,56,79,209,166,63,
	72,216,175,54,65,223,168,49,70,203,188,37,82,204,187,34,85,197,178,43,92,
	194,181,44,91,155,236,117,2,156,235,114,5,149,226,123,12,146,229,124,11,134,
	241,104,31,129,246,111,24,136,255,102,17,143,248,97,22,160,215,78,57,167,
	208,73,62,174,217,64,55,169,222,71,48,189,202,83,36,186,205,84,35,179,196,
	93,42,180,195,90,45}

---Calculate the CRC-32 checksum of the string.
---@param str string the input string to calculate its CRC-32 checksum.
---@param init_value integer|nil The initial crc32 value. If nil, use 0
---@return integer The CRC-32 checksum, which is greater or equal to 0, and less than 2^32 (4294967296).
function LibDeflate:Crc32(str, init_value)
	-- TODO: Check argument
	local crc = (init_value or 0) % 4294967296
	if not _xor8_table then
		GenerateXorTable()
	end
    -- The value of bytes of crc32
	-- crc0 is the least significant byte
	-- crc3 is the most significant byte
    local crc0 = crc % 256
    crc = (crc - crc0) / 256
    local crc1 = crc % 256
    crc = (crc - crc1) / 256
    local crc2 = crc % 256
    local crc3 = (crc - crc2) / 256

	local _xor_vs_255 = _xor8_table[255]
	crc0 = _xor_vs_255[crc0]
	crc1 = _xor_vs_255[crc1]
	crc2 = _xor_vs_255[crc2]
	crc3 = _xor_vs_255[crc3]
    for i=1, #str do
		local byte = string_byte(str, i)
		local k = _xor8_table[crc0][byte]
		crc0 = _xor8_table[_crc_table0[k] ][crc1]
		crc1 = _xor8_table[_crc_table1[k] ][crc2]
		crc2 = _xor8_table[_crc_table2[k] ][crc3]
		crc3 = _crc_table3[k]
    end
	crc0 = _xor_vs_255[crc0]
	crc1 = _xor_vs_255[crc1]
	crc2 = _xor_vs_255[crc2]
	crc3 = _xor_vs_255[crc3]
    crc = crc0 + crc1*256 + crc2*65536 + crc3*16777216
    return crc
end

--* cNet

local log = function (text)
    print("[cNet] " .. text)
end

local messageEventHandlers = {}
local ctcpAckListeners = {}
local cttpResponseListeners = {}
local restApi = {}

---@enum MessageEventType
local MessageEventType = {
    CONNECTION_OPENED = "connection_opened",
    CONNECTION_CLOSED = "connection_closed",
    ENCRYPTED_MESSAGE = "encrypted_message",
    PLAIN_MESSAGE = "plain_message",
    LOGIN = "login",
    LOGIN_FAILED = "login_failed",
    LOGOUT = "logout",
    MODEM_MESSAGE = "modem_message"
}

--* CNP (Copper Network Protocol)

---@enum Protocol
local Protocol = {
    CNP = "CNP",
    CTCP = "CTCP",
    CTTP = "CTTP",
    CLOG = "CLOG",
}

---@class CnpMessage
---@field protocol Protocol
---@field payload any
local CnpMessage = {
    protocol = Protocol.CTCP,
    payload = nil
}

---@param protocol Protocol
---@param payload any
---@return CnpMessage
function CnpMessage:new(protocol, payload)
    local o = {}
    setmetatable(o, self)
    o.protocol = protocol
    o.payload = payload
    return o
end

local function isValidCnpMessage(message)
    return type(message) == "table" and type(message.protocol) == "string" and message.payload ~= nil
end

--* CTCP (Copper Transmission Control Protocol)

local generateSequenceNumber = function()
    return math.random(1, 1000)
end

---@enum CtcpFlag
local CtcpFlag = {
    SYN = 1,
    ACK = 2,
    FIN = 3,
    LOG = 4,
    REG = 5
}

---@class CtcpMessage
local CtcpMessage = {
    seqNumber = nil,
    ackNumber = nil,
    flags = {},
    protocol = nil,
    payload = nil
}

---@param seqNumber integer
---@param ackNumber integer
---@param flags CtcpFlag[]
---@param protocol? Protocol
---@param payload? any
---@return CtcpMessage
function CtcpMessage:new(seqNumber, ackNumber, flags, protocol, payload)
    flags = flags or {}
    local o = {}
    setmetatable(o, self)
    o.seqNumber = seqNumber
    o.ackNumber = ackNumber
    o.flags = {}
    for _, flag in ipairs(flags) do
        o.flags[flag] = true
    end
    o.protocol = protocol
    o.payload = payload
    return o
end

local function isValidCtcpMessage(message)
    return type(message.seqNumber) == "number" and type(message.ackNumber) == "number" and type(message.flags) == "table"
end

---@class CtcpConnection
---@field socket table
---@field seqNumber integer
---@field ackNumber integer
local CtcpConnection = {
    socket = {},
    seqNumber = 0,
    ackNumber = 0
}

---@param socket table
---@param seqNumber integer
---@param ackNumber integer
---@return CtcpConnection
function CtcpConnection:new(socket, seqNumber, ackNumber)
    local o = {}
    setmetatable(o, self)
    o.socket = socket
    o.seqNumber = seqNumber
    o.ackNumber = ackNumber
    return o
end

local function isValidCtcpConnection(connection)
    return type(connection) ~= "nil" and type(connection.socket) == "table" and type(connection.seqNumber) == "number" and type(connection.ackNumber) == "number"
end

local function sendCtcpMessage(socket, message)
    if not isValidCtcpMessage(message) then
        error("Invalid CTCP message")
    end
    CryptoNet.send(socket, CnpMessage:new(Protocol.CTCP, message))
end

---Listens for a CTCP message.
---@param ackNumber? integer The sequence number to listen for.
---@param timeout? number The timeout in seconds. Default is 5.
---@return integer - sequence number
local function listenCtcpAck(ackNumber, timeout)
    ackNumber = ackNumber or -1
    timeout = timeout or 5

    local receivedSeq
    local function listener(seq)
        receivedSeq = seq
        os.queueEvent("")
    end
    ctcpAckListeners[ackNumber] = listener

    -- Wait for acknowledgement or timeout
    local timer = os.startTimer(timeout)
    while receivedSeq == nil do
        local eventType, eventTimer = os.pullEvent()
        if eventType == "timer" and eventTimer == timer then
            break
        end
    end
    return receivedSeq
end

local function incrementCtcpConnectionNumbers(connection)
    connection.seqNumber = connection.seqNumber + 1
    connection.ackNumber = connection.ackNumber + 2
end

--* CTTP (Copper Text Transfer Protocol)

---@enum CttpRequestMethod
local CttpRequestMethod = {
    GET = "GET",
    POST = "POST",
    DELETE = "DELETE",
}

---@class CttpRequest
---@field requestMethod CttpRequestMethod
---@field path string
---@field header table
---@field data any
local CttpRequest = {
    requestMethod = CttpRequestMethod.GET,
    path = "",
    header = {},
    data = nil
}

---@param requestMethod CttpRequestMethod
---@param path string
---@param header? table
---@param data? any
---@return CttpRequest
function CttpRequest:new(requestMethod, path, header, data)
    header = header or {}
    local o = {}
    setmetatable(o, self)
    o.requestMethod = requestMethod
    o.path = path
    o.header = header
    o.data = data
    return o
end

local function isValidCttpRequest(request)
    return type(request) ~= "nil" and type(request.requestMethod) == "string" and type(request.path) == "string" and type(request.header) == "table"
end

---@class CttpResponse
---@field statusCode integer
---@field statusMessage string
---@field header table
---@field data any
local CttpResponse = {
    statusCode = 0,
    statusMessage = "",
    header = {},
    data = nil
}

---@param status table
---@param header? table
---@param data? any
---@return CttpResponse
function CttpResponse:new(status, header, data)
    if type(status.code) ~= "number" or type(status.message) ~= "string" then
        error("Invalid status")
    end
    header = header or {}
    local o = {}
    setmetatable(o, self)
    o.statusCode = status.code
    o.statusMessage = status.message
    o.header = header
    o.data = data
    return o
end

local function isValidCttpResponse(response)
    return type(response) ~= "nil" and type(response.statusCode) == "number" and type(response.statusMessage) == "string" and type(response.header) == "table"
end

---Listens for a CTTP response.
---@param seqNumber integer The sequence number to listen for.
---@param ackNumber integer The acknowledgement number to listen for.
---@param timeout? number The timeout in seconds. Default is 5.
---@return CttpResponse|nil - The response or nil if the response is invalid.
local function listenCttpResponse(seqNumber, ackNumber, timeout)
    seqNumber = seqNumber or -1
    ackNumber = ackNumber or -1
    timeout = timeout or 5

    local recievedPayload
    local function listener(payload)
        recievedPayload = payload
        os.queueEvent("")
    end
    if cttpResponseListeners[seqNumber] == nil then
        cttpResponseListeners[seqNumber] = {}
    end
    cttpResponseListeners[seqNumber][ackNumber] = listener

    -- Wait for acknowledgement or timeout
    local timer = os.startTimer(timeout)
    while recievedPayload == nil do
        local eventType, eventTimer = os.pullEvent()
        if eventType == "timer" and eventTimer == timer then
            break
        end
    end
    return recievedPayload
end

---@enum CttpStatus
local CttpStatus = {
    CONTINUE = {
        code = 100,
        message = "CONTINUE"
    },
    PROCESSING = {
        code = 102,
        message = "PROCESSING"
    },
    EARLY_HINTS = {
        code = 103,
        message = "EARLY_HINTS"
    },
    OK = {
        code = 200,
        message = "OK"
    },
    CREATED = {
        code = 201,
        message = "CREATED"
    },
    ACCEPTED = {
        code = 202,
        message = "ACCEPTED"
    },
    MOVED_PERMANENTLY = {
        code = 301,
        message = "MOVED_PERMANENTLY"
    },
    TEMPORARY_REDIRECT = {
        code = 307,
        message = "TEMPORARY_REDIRECT"
    },
    PERMANENT_REDIRECT = {
        code = 308,
        message = "PERMANENT_REDIRECT"
    },
    BAD_REQUEST = {
        code = 400,
        message = "BAD_REQUEST"
    },
    UNAUTHORIZED = {
        code = 401,
        message = "UNAUTHORIZED"
    },
    FORBIDDEN = {
        code = 403,
        message = "FORBIDDEN"
    },
    NOT_FOUND = {
        code = 404,
        message = "NOT_FOUND"
    },
    CONFLICT = {
        code = 409,
        message = "CONFLICT"
    },
    GONE = {
        code = 410,
        message = "GONE"
    },
    ENHANCE_YOUR_CALM = {
        code = 420,
        message = "ENHANCE_YOUR_CALM"
    },
    TOO_MANY_REQUESTS = {
        code = 429,
        message = "TOO_MANY_REQUESTS"
    },
    TOKEN_EXPIRED = {
        code = 440,
        message = "TOKEN_EXPIRED"
    },
    INTERNAL_SERVER_ERROR = {
        code = 500,
        message = "INTERNAL_SERVER_ERROR"
    },
    NOT_IMPLEMENTED = {
        code = 501,
        message = "NOT_IMPLEMENTED"
    },
    SERVICE_UNAVAILABLE = {
        code = 503,
        message = "SERVICE_UNAVAILABLE"
    },
    INSUFFICIENT_STORAGE = {
        code = 507,
        message = "INSUFFICIENT_STORAGE"
    },
    SERVER_IS_DOWN = {
        code = 521,
        message = "SERVER_IS_DOWN"
    },
    CONNECTION_TIMED_OUT = {
        code = 522,
        message = "CONNECTION_TIMED_OUT"
    },
}

--* Handlers

local function handleCttpMessage(requestMethod, path, header, data, socket)
    if type(restApi[requestMethod]) == "table" then
        local matchedPath = ""
        local mergedPath = ""
        local pathParts = utility.splitString(path, "/")
        for _, pathPart in ipairs(pathParts) do
            mergedPath = mergedPath .. "/" .. pathPart
            if type(restApi[requestMethod][mergedPath]) == "function" then
                matchedPath = mergedPath
            end
        end
        local args = utility.splitString(path:sub(#matchedPath + 1), "/")
        log("Received " .. requestMethod .. " request for " .. matchedPath)
        return restApi[requestMethod][matchedPath](args, header, data, socket)
    end
end

local ctcpProtocolHandlers = {
    [Protocol.CTTP] = function(payload, seqNumber, ackNumber, socket)
        if isValidCttpRequest(payload) then
            local response = handleCttpMessage(payload.requestMethod, payload.path, payload.header, payload.data, socket)
            if response ~= nil then
                return Protocol.CTTP, response
            end
        elseif isValidCttpResponse(payload) then
            if type(cttpResponseListeners[seqNumber]) == "table" and type(cttpResponseListeners[seqNumber][ackNumber]) == "function" then
                cttpResponseListeners[seqNumber][ackNumber](payload)
                cttpResponseListeners[seqNumber][ackNumber] = nil
            end
        end
    end
}

local function handleAcknowledgements(seqNumber, ackNumber)
    if type(ctcpAckListeners[ackNumber]) == "function" then
        ctcpAckListeners[ackNumber](seqNumber)
        ctcpAckListeners[ackNumber] = nil
    end
end

local function handleCtcpFlags(flags, protocol, payload, server)
    local responseFlags = nil
    if flags[CtcpFlag.SYN] then
        if flags[CtcpFlag.ACK] then
            -- Handle SYN-ACK
            return { CtcpFlag.ACK }
        else
            -- Handle SYN
            return { CtcpFlag.SYN, CtcpFlag.ACK }
        end
    elseif flags[CtcpFlag.FIN] then
        if flags[CtcpFlag.ACK] then
            -- Handle FIN-ACK
            return { CtcpFlag.ACK }
        else
            -- Handle FIN
            return { CtcpFlag.FIN, CtcpFlag.ACK }
        end
    elseif flags[CtcpFlag.REG] and Protocol.CLOG then
        if flags[CtcpFlag.ACK] then
            -- Handle REG-ACK
            return { CtcpFlag.ACK }
        else
            CryptoNet.addUserHashed(payload.username, payload.password, 1, server.name)

            -- Handle REG
            return { CtcpFlag.REG, CtcpFlag.ACK }
        end
    elseif not flags[CtcpFlag.ACK] then
        -- Acknowledge message
        return { CtcpFlag.ACK }
    end
end

local function handleCtcpMessage(seqNumber, ackNumber, flags, protocol, payload, socket, server)
    handleAcknowledgements(seqNumber, ackNumber)

    local responseFlags = handleCtcpFlags(flags, protocol, payload, server)
    if responseFlags ~= nil then
        if ackNumber == 0 then
            ackNumber = generateSequenceNumber()
        end
        sendCtcpMessage(socket, CtcpMessage:new(ackNumber, seqNumber + 1, responseFlags, protocol))

        if payload == nil then
            return
        end
    end

    -- Handle payload
    if type(ctcpProtocolHandlers[protocol]) ~= "function" then
        return
    end
    local responseProtocol, response = ctcpProtocolHandlers[protocol](payload, seqNumber, ackNumber, socket)
    if response ~= nil then
        sendCtcpMessage(socket, CtcpMessage:new(seqNumber + 1, ackNumber + 1, {}, responseProtocol, response))
    end
end

local protocolHandlers = {
    [Protocol.CTCP] = function(message, socket, server)
        if not isValidCtcpMessage(message) then
            -- Invalid message
            return
        end

        handleCtcpMessage(message.seqNumber, message.ackNumber, message.flags, message.protocol, message.payload, socket, server)
    end,
}

local function onEvent(event)
    local eventType = event[1]
    -- Call custom event handler if available
    if type(messageEventHandlers[eventType]) == "function" then
        messageEventHandlers[eventType](table.unpack(event, 2))
    end
    -- Handle message events
    if eventType == MessageEventType.ENCRYPTED_MESSAGE then
        local message, socket, server = table.unpack(event, 2)
        if not isValidCnpMessage(message) then
            -- Invalid message
            return
        end
        protocolHandlers[message.protocol](message.payload, socket, server)
    end
end

--* Exports

---The copper os networking library.
local cNet = {
    CryptoNet = CryptoNet,
    MessageEventType = MessageEventType,
    CttpRequestMethod = CttpRequestMethod,
    CttpStatus = CttpStatus,
    CtcpConnection = CtcpConnection,
    CttpRequest = CttpRequest,
    CttpResponse = CttpResponse,
}

---Calculates the checksum of an object.
---@param object any A serializable object
---@return integer
function cNet.checksum(object)
    local objectString = textutils.serialise(object)
    return LibDeflate:Crc32(objectString)
end

---Starts the cryptoNet event loop.
---@param onStart function A callback when cryptoNet is ready.
function cNet.startEventLoop(onStart)
    if type(onStart) ~= "function" then
        error("onStart must be a function")
    end

    CryptoNet.setLoggingEnabled(false)
    CryptoNet.startEventLoop(function ()
        log("Started event loop")
        onStart()
    end, onEvent)
end

---@param serverId string
---@param modemQuery? string Any wrapable string to query the modem.
function cNet.host(serverId, modemQuery)
    log("Hosting '" .. serverId .. "'...")
    CryptoNet.host(serverId, nil, nil, modemQuery)
end

---Connects to a server using the CTCP handshake.
---@param serverId string The server ID.
---@param timeout? number The timeout in seconds. Default is 5.
---@param modemQuery? string Any wrapable string to query the modem.
---@return CtcpConnection|nil - The CTCP connection or nil if the connection failed.
function cNet.connectCtcp(serverId, timeout, modemQuery)
    timeout = timeout or 5
    log("Connecting...")
    local socket = CryptoNet.connect(serverId, nil, nil, nil, modemQuery)

    -- Send SYN
    local seqNumber = generateSequenceNumber()
    sendCtcpMessage(socket, CtcpMessage:new(seqNumber, 0, { CtcpFlag.SYN }, Protocol.CTTP))

    -- Wait for SYN-ACK
    local receivedSeqNumber = listenCtcpAck(seqNumber + 1, timeout)
    if receivedSeqNumber == nil then
        return nil
    end

    return CtcpConnection:new(socket, seqNumber, receivedSeqNumber + 1)
end

---Disconnects from a server using the CTCP handshake.
---@param ctcpConnection CtcpConnection
---@param timeout? number The timeout in seconds. Default is 5.
---@return boolean - If the server acknowledged the disconnection. In both cases, the connection is closed.
function cNet.disconnectCtcp(ctcpConnection, timeout)
    timeout = timeout or 5
    log("Disconnecting...")
    sendCtcpMessage(ctcpConnection.socket, CtcpMessage:new(ctcpConnection.seqNumber, ctcpConnection.ackNumber, { CtcpFlag.FIN }, Protocol.CTTP))

    -- Wait for FIN-ACK
    local receivedSeqNumber = listenCtcpAck(ctcpConnection.seqNumber + 1, timeout)
    CryptoNet.close(ctcpConnection.socket)
    if receivedSeqNumber == nil then
        return false
    end
    return true
end

---Sends a CTTP request to the server.
---@param ctcpConnection CtcpConnection
---@param request CttpRequest
---@param timeout? number The timeout in seconds. Default is 5.
---@return CttpResponse|nil, boolean - The response or nil if the timeout was reached.
function cNet.sendCttpRequest(ctcpConnection, request, timeout)
    log("Sending CTTP request...")
    sendCtcpMessage(ctcpConnection.socket, CtcpMessage:new(ctcpConnection.seqNumber, ctcpConnection.ackNumber, {}, Protocol.CTTP, request))
    local acknowledged = listenCtcpAck(ctcpConnection.seqNumber + 1, timeout)
    log("Waiting for CTTP response...")
    local response = listenCttpResponse(ctcpConnection.seqNumber + 1, ctcpConnection.ackNumber + 1, timeout)

    incrementCtcpConnectionNumbers(ctcpConnection)

    return response, acknowledged ~= nil
end

---Connects to a server, sends a CTTP request, and disconnects.
---@param serverId string The server ID.
---@param request CttpRequest
---@param timeout? number The timeout for connect and disconnect in seconds. Default is 5.
---@param modemQuery? string Any wrapable string to query the modem.
---@return CttpResponse|nil, boolean, boolean, boolean - The response, if the connection was successful, if the request was acknowledged and if the server acknowledged the disconnect.
function cNet.connectAndSendCttpRequest(serverId, request, timeout, modemQuery)
    local connection = cNet.connectCtcp(serverId, timeout, modemQuery)
    if connection == nil then
        return nil, false, false, false
    end
    local response, acknowledged = cNet.sendCttpRequest(connection, request, timeout)
    local disconnected = cNet.disconnectCtcp(connection, timeout)
    return response, true, acknowledged, disconnected
end

---Sets a custom handler for cryptoNet messages.
---@param eventType MessageEventType
---@param handler function
function cNet.setMessageHandler(eventType, handler)
    messageEventHandlers[eventType] = handler
    log("Registered message handler: " .. eventType)
end

---Sets a handler for a CTTP request.
---@param requestMethod CttpRequestMethod
---@param path string
---@param handler function - The handler function that takes the args, the header, data and the socket as arguments and returns a CTTP response.
function cNet.setRestApi(requestMethod, path, handler)
    if path:sub(1, 1) ~= "/" then
        path = "/" .. path
    end
    if #path > 1 and path:sub(-1) == "/" then
        path = path:sub(1, -2)
    end

    if type(restApi[requestMethod]) ~= "table" then
        restApi[requestMethod] = {}
    end
    restApi[requestMethod][path] = handler
    log("Registered REST API: " .. requestMethod .. " " .. path)
end

---Registers a user on a server using the cryptoNet register.
---@param serverId string The server ID.
---@param username string The username.
---@param password string The password.
---@param timeout? number The timeout in seconds. Default is 5.
---@param modemQuery? string Any wrapable string to query the modem.
---@return integer - The status code. `0` if successful, `1` if the connection failed, `2` if the registration failed, `3` if the disconnection failed.
function cNet.register(serverId, username, password, timeout, modemQuery)
    username = string.lower(utility.trimString(username))
    password = utility.trimString(password)

    local ctcpConnection = cNet.connectCtcp(serverId, timeout, modemQuery)
    if ctcpConnection == nil then
        return 1
    end

    log("Registering...")
    local passwordHash = CryptoNet.hashPassword(username, password, serverId)
    local message = CtcpMessage:new(ctcpConnection.seqNumber, ctcpConnection.ackNumber, { CtcpFlag.REG }, Protocol.CLOG, { username = username, passwordHash = passwordHash })
    sendCtcpMessage(ctcpConnection.socket, message)
    local acknowledgement = listenCtcpAck(ctcpConnection.seqNumber + 1)
    if acknowledgement == nil then
        return 2
    end

    local disconnected = cNet.disconnectCtcp(ctcpConnection)
    if not disconnected then
        return 3
    end
    return 0
end

---Logs in to a server using the cryptoNet login.
---The password is hashed before sending.
---@param connection CtcpConnection|table The CTCP connection or the socket.
---@param username string
---@param password string
function cNet.login(connection, username, password)
    local socket = connection.socket or connection
    if socket.username ~= nil then
        error("Already logged in")
    end
    log("Logging in...")
    CryptoNet.login(socket, username, password)
    if socket.username == nil then
        error("Login failed")
    end
end

---Logs out from a server using the cryptoNet logout.
---@param connection CtcpConnection|table The CTCP connection or the socket.
function cNet.logout(connection)
    local socket = connection.socket or connection
    if socket.username == nil then
        error("Not logged in")
    end
    log("Logging out...")
    CryptoNet.logout(socket)
    if socket.username ~= nil then
        error("Logout failed")
    end
end

function cNet.setLogger(logger)
    log = logger
end

return cNet
