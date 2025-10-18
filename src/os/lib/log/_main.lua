local System = require("system")

local Package = {}

--* Constants

local LOG_FOLDER = "/logs/"
local LOG_FILE_EXTENSION = ".log"
local CONSOLE_HISTORY_FILE = "/sys/data/console_history"

--* Variables

local active_log     -- Initialized in setup function
local active_log_path -- Initialized in setup function
local console_history = {}

--* Main Functionality

---@param id string
local function log_path(id)
    return LOG_FOLDER .. id .. LOG_FILE_EXTENSION
end

---@param color number
---@param text string
local function save_console_history(color, text)
    table.insert(console_history, { color, text })
end

---@param color number
---@param text string
local function log_to_console(color, text)
    if (System.get_console_lock()) then
        return
    end

    term.setTextColor(color)
    term.write(text)

    local _, y = term.getCursorPos()
    term.setCursorPos(1, y + 1)

    save_console_history(color, text)
end

---@param prefix string
---@param text string
local function log_to_file(prefix, text)
    local active_package = System.get_active_package()

    local f = fs.open(active_log_path, "a")
    f.write(prefix .. " (" .. active_package .. ") " .. text .. "\n")
    f.close()
end

---@param prefix string
---@param color number
---@param args any[]
local function log(prefix, color, args)
    local text = ""
    for _, v in ipairs(args) do
        text = text .. tostring(v) .. " "
    end
    text = text:sub(1, -2)

    log_to_console(color, text)
    log_to_file(prefix, text)
end

---@param ... any
function Package.debug(...)
    log("[DEBUG]", colors.lightGray, {...})
end

---@param ... any
function Package.info(...)
    log("[INFO]", colors.white, {...})
end

---@param ... any
function Package.warn(...)
    log("[WARN]", colors.yellow, {...})
end

---Used by the error library
---@param ... string
function Package.__error(...)
    log("[ERROR]", colors.red, {...})
end

---Used for system crashes
---@param ... any
function Package.__fatal(...)
    log("[FATAL]", colors.red, {...})
end

---Returns a part of console history
---For the parameters is `1` the newest console entry and `-1` the oldest
---@param first integer default = `1`
---@param last integer default = the same as `first`
function Package.get_console_history(first, last)
    first = first or 1
    last = last or first

    if first == 0 or last == 0 then
        error("first and last can't be 0", 2)
    end
    if last < first then
        error("last has to be greater or equals to first", 2)
    end

    if first < 0 then
        first = #console_history + first + 1
    end
    if last < 0 then
        last = #console_history + last + 1
    end

    -- invert values
    first = #console_history - first + 1
    last = #console_history - last + 1

    local history = {}
    for i = first, last do
        table.insert(history, console_history[i])
    end

    return history
end

--* Setup

local function setup()
    active_log = tostring(os.epoch("utc"))
    active_log_path = log_path(active_log)

    local f = fs.open(active_log_path, "w")
    f.close()

    f = fs.open(CONSOLE_HISTORY_FILE, "w")
    f.write("")
    f.close()
end

setup()

--* Finishing Touches

print = Package.debug
return Package
