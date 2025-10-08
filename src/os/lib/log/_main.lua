local System = require("system")

local Package = {}

--* Constants

local LOG_FOLDER = "/logs/"
local LOG_FILE_EXTENSION = ".log"
local CONSOLE_HISTORY_FILE = "/sys/data/console_history"

--* Variables

local activeLog     -- Initialized in setup function
local activeLogPath -- Initialized in setup function
local consoleHistory = {}

--* Main Functionality

---@param id string
local function logPath(id)
	return LOG_FOLDER .. id .. LOG_FILE_EXTENSION
end

---@param color number
---@param text string
local function saveConsoleHistory(color, text)
	table.insert(consoleHistory, { color, text })
end

---@param color number
---@param text string
local function logToConsole(color, text)
	if (System.getConsoleLock()) then
		return
	end

	term.setTextColor(color)
	term.write(text)

	local _, y = term.getCursorPos()
	term.setCursorPos(1, y + 1)

	saveConsoleHistory(color, text)
end

---@param prefix string
---@param text string
local function logToFile(prefix, text)
	local activePackage = System.getActivePackage()

	local f = fs.open(activeLogPath, "a")
	f.write(prefix .. " (" .. activePackage .. ") " .. text .. "\n")
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

	logToConsole(color, text)
	logToFile(prefix, text)
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
function Package.getConsoleHistory(first, last)
	first = first or 1
	last = last or first

	if first == 0 or last == 0 then
		error("first and last can't be 0", 2)
	end
	if last < first then
		error("last has to be greater or equals to first", 2)
	end

	if first < 0 then
		first = #consoleHistory + first + 1
	end
	if last < 0 then
		last = #consoleHistory + last + 1
	end

	-- invert values
	first = #consoleHistory - first + 1
	last = #consoleHistory - last + 1

	local history = {}
	for i = first, last do
		table.insert(history, consoleHistory[i])
	end

	return history
end

--* Setup

local function setup()
	activeLog = tostring(os.epoch("utc"))
	activeLogPath = logPath(activeLog)

	local f = fs.open(activeLogPath, "w")
	f.close()

	f = fs.open(CONSOLE_HISTORY_FILE, "w")
	f.write("")
	f.close()
end

setup()

--* Finishing Touches

print = Package.debug
return Package
