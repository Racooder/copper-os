---@type {string: Thread}
local threadPool = {}
---@type {string: boolean}
local suspendedThreads = {}
local currentThreadId = 0
local started = false

-- * Thread Class

---@class Thread
---@field __id integer
---@field __thread thread
---@field __attachedThreads table
---@field __parentThread Thread
local Thread = {}
Thread.__index = Thread

function Thread:kill()
    threadPool[self.__id] = nil
    for _, thread in ipairs(self.__attachedThreads) do
        thread:kill()
    end
end

function Thread:suspend()
    suspendedThreads[self.__id] = true
    for _, thread in ipairs(self.__attachedThreads) do
        thread:suspend()
    end
end

function Thread:resume()
    suspendedThreads[self.__id] = nil
    for _, thread in ipairs(self.__attachedThreads) do
        thread:resume()
    end
end

function Thread:status()
    if not threadPool[self.__id] then
        return "dead"
    end
    if suspendedThreads[self.__id] then
        return "suspended"
    end
    return "running"
end

---@param thread Thread
function Thread:attach(thread)
    thread:detach()
    self.__attachedThreads[thread.__id] = thread
    thread.__parentThread = self
end

function Thread:detach()
    self.__parentThread.__attachedThreads[self.__id] = nil
    self.__parentThread = nil
end

--* Package

local Threading = {}

---@param func function
---@return Thread
function Threading.new(func)
    local id = #threadPool + 1
    local thread = coroutine.create(func)

    local o = {
        __id = id,
        __thread = thread,
        __attachedThreads = {},
        __parentThread = nil
    }
    setmetatable(o, Thread)

    threadPool[id] = o
    return o
end

---@return Thread
function Threading.current()
    return threadPool[currentThreadId]
end

--- Starts the threading system, running the given main thread function.
---@param mainThread function
---@throws if threading has already been started
function Threading.start(mainThread)
    if type(mainThread) ~= "function" then
        error("Expected function, got " .. type(mainThread), 2)
    end
    if started then
        error("Threading has already been started", 2)
    end

    local eventFilters = {}
    local eventData = { nil }

    while true do
        if #threadPool == 0 then
            return
        end

        local eventType = eventData[1]

        for id, thread in pairs(threadPool) do
            currentThreadId = id
            if (not suspendedThreads[id] and (not eventFilters[id] or eventFilters[id] == eventType)) or eventType == "terminate" then
                local ok, param = coroutine.resume(thread.__thread, table.unpack(eventData))
                if ok then
                    if type(param) == "string" then
                        eventFilters[id] = param
                    end
                else
                    error(param, 0)
                end
                if coroutine.status(thread.__thread) == "dead" then
                    threadPool[id] = nil
                end
            end
        end

        for id, thread in pairs(threadPool) do
            if coroutine.status(thread.__thread) == "dead" then
                threadPool[id] = nil
            end
        end

        eventData = { os.pullEventRaw() }
    end
end

return Threading
