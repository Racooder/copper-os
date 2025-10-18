---@type {string: Thread}
local thread_pool = {}
---@type {string: boolean}
local suspended_threads = {}
local current_thread_id = 0
local started = false

-- * Thread Class

---@class Thread
---@field __id integer
---@field __thread thread
---@field __attached_threads table
---@field __parent_thread Thread
local Thread = {}
Thread.__index = Thread

function Thread:kill()
    thread_pool[self.__id] = nil
    for _, thread in ipairs(self.__attached_threads) do
        thread:kill()
    end
end

function Thread:suspend()
    suspended_threads[self.__id] = true
    for _, thread in ipairs(self.__attached_threads) do
        thread:suspend()
    end
end

function Thread:resume()
    suspended_threads[self.__id] = nil
    for _, thread in ipairs(self.__attached_threads) do
        thread:resume()
    end
end

function Thread:status()
    if not thread_pool[self.__id] then
        return "dead"
    end
    if suspended_threads[self.__id] then
        return "suspended"
    end
    return "running"
end

---@param thread Thread
function Thread:attach(thread)
    thread:detach()
    self.__attached_threads[thread.__id] = thread
    thread.__parent_thread = self
end

function Thread:detach()
    self.__parent_thread.__attached_threads[self.__id] = nil
    self.__parent_thread = nil
end

--* Package

local Threading = {}

---@param func function
---@return Thread
function Threading.new(func)
    local id = #thread_pool + 1
    local thread = coroutine.create(func)

    local o = {
        __id = id,
        __thread = thread,
        __attached_threads = {},
        __parent_thread = nil
    }
    setmetatable(o, Thread)

    thread_pool[id] = o
    return o
end

---@return Thread
function Threading.current()
    return thread_pool[current_thread_id]
end

--- Starts the threading system, running the given main thread function.
---@param main_thread function
---@throws if threading has already been started
function Threading.start(main_thread)
    if type(main_thread) ~= "function" then
        error("Expected function, got " .. type(main_thread), 2)
    end
    if started then
        error("Threading has already been started", 2)
    end

    local event_filters = {}
    local event_data = { nil }

    while true do
        if #thread_pool == 0 then
            return
        end

        local event_type = event_data[1]

        for id, thread in pairs(thread_pool) do
            current_thread_id = id
            if (not suspended_threads[id] and (not event_filters[id] or event_filters[id] == event_type)) or event_type == "terminate" then
                local ok, param = coroutine.resume(thread.__thread, table.unpack(event_data))
                if ok then
                    if type(param) == "string" then
                        event_filters[id] = param
                    end
                else
                    error(param, 0)
                end
                if coroutine.status(thread.__thread) == "dead" then
                    thread_pool[id] = nil
                end
            end
        end

        for id, thread in pairs(thread_pool) do
            if coroutine.status(thread.__thread) == "dead" then
                thread_pool[id] = nil
            end
        end

        event_data = { os.pullEventRaw() }
    end
end

return Threading
