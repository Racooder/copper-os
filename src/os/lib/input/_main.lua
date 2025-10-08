local Threading = require("threading")
local ErrorUtils = require("error_utils")

local Package = {}

--* Variables

local VALID_MOUSE_BUTTONS = { "left", "middle", "right" }

local listenerCounter = 0 -- Used for key generation

local charListeners = {}
local keyListeners = {}
local hotkeyListeners = {}
local eventListeners = {
	["key"] = {},
	["key_up"] = {},
	["mouse_click"] = {
		[1] = {},
		[2] = {},
		[3] = {}
	},
	["mouse_up"] = {
		[1] = {},
		[2] = {},
		[3] = {}
	},
	["mouse_drag"] = {
		[1] = {},
		[2] = {},
		[3] = {}
	},
	["mouse_scroll"] = {}
}

local isPressed = {} -- Maps currently pressed keys to true

--* Main Functionality

---@return string
local function newListenerKey()
	listenerCounter = listenerCounter + 1
	return tostring(listenerCounter)
end

---@param type "char"|"key"|"hotkey"|"event"
---@param key string
---@param ... any Additional data for the listener
---@return table listener A table representing the listener
local function newListener(type, key, ...)
	return { type, key, table.unpack({...}) }
end

---@param listener table
---@return boolean
local function isValidListener(listener)
	if type(listener) ~= "table" then
		return false
	end
	if listener[1] ~= "char" and listener[1] ~= "key" and listener[1] ~= "hotkey" and listener[1] ~= "event" then
		return false
	end
	if type(listener[2]) ~= "string" then
		return false
	end
	if tonumber(listener[2]) == nil then
		return false
	end
	if listener[1] == "hotkey" and type(listener[3]) ~= "string" then
		return false
	end
	if listener[1] == "event" then
		if listener[3] == "key" or listener[3] == "key_up" then
			if type(listener[4]) ~= "string" then
				return false
			end
			if tonumber(listener[4]) == nil then
				return false
			end
		elseif listener[3] == "mouse_click" or listener[3] == "mouse_up" or listener[3] == "mouse_drag" then
			if listener[4] ~= 1 and listener[4] ~= 2 and listener[4] ~= 3 then
				return false
			end
		else
			return false
		end
	end
	return true
end

---@return integer[]
local function getPressedKeyCodes()
	local keyCodes = {}
	for keyCode, pressed in pairs(isPressed) do
		if pressed then
			table.insert(keyCodes, keyCode)
		end
	end
	return keyCodes
end

---@return integer buttonNumber 1 = left, 2 = right, 3 = middle
local function getMouseButtonNumber(name)
	if name == "left" then
		return 1
	elseif name == "right" then
		return 2
	elseif name == "middle" then
		return 3
	else
		error("Invalid mouse button name: " .. tostring(name), 2)
	end
end

local function callCallbacks(listeners, ...)
	if listeners ~= nil then
		for _, callback in pairs(listeners) do
			if callback ~= nil then
				callback(...)
			end
		end
	end
end

local eventHandlers = {
	---Called when a character is typed
	---@param char string The character that was typed
	["char"] = function(char)
		for _, callback in pairs(charListeners) do
			callback(char)
		end
	end,
	---Called when a key is pressed
	---@param keyCode integer The key code of the pressed key
	---@param isHeld boolean Whether the key is held down (true) or just pressed (false)
	["key"] = function(keyCode, isHeld) -- Called when a key is pressed
		isPressed[keyCode] = true

		callCallbacks(keyListeners, keyCode, isHeld) -- Call listeners that listen for any key press

		-- Trigger hotkey listeners if the key combination matches
		local pressedHotkey = Package.newHotkey(table.unpack(getPressedKeyCodes()))
		local pressedHotkeyListeners = hotkeyListeners[pressedHotkey]
		if pressedHotkeyListeners ~= nil then
			callCallbacks(pressedHotkeyListeners)
		end

		-- Call specific key listeners
		local keyCodeListeners = eventListeners["key"][tostring(keyCode)]
		if keyCodeListeners ~= nil then
			callCallbacks(keyCodeListeners, isHeld)
		end
	end,
	---Called when a key is released
	---@param keyCode integer The key code of the released key
	["key_up"] = function(keyCode)
		isPressed[keyCode] = nil

		local keyCodeListeners = eventListeners["key_up"][tostring(keyCode)]
		if keyCodeListeners ~= nil then
			callCallbacks(keyCodeListeners)
		end
	end,
	---Called when a mouse button is clicked
	---@param button integer The mouse button that was clicked (1 = left, 2 = right, 3 = middle)
	---@param x integer The x coordinate of the mouse
	---@param y integer The y coordinate of the mouse
	["mouse_click"] = function(button, x, y)
		local buttonListeners = eventListeners["mouse_click"][button]
		callCallbacks(buttonListeners, x, y)
	end,
	---Called when a mouse button is released
	---@param button integer The mouse button that was released (1 = left, 2 = right, 3 = middle)
	---@param x integer The x coordinate of the mouse
	---@param y integer The y coordinate of the mouse
	["mouse_up"] = function(button, x, y)
		local buttonListeners = eventListeners["mouse_up"][button]
		callCallbacks(buttonListeners, x, y)
	end,
	---Called when a mouse button is dragged
	---@param button integer The mouse button that was dragged (1 = left, 2 = right, 3 = middle)
	---@param x integer The x coordinate of the mouse
	---@param y integer The y coordinate of the mouse
	["mouse_drag"] = function(button, x, y)
		local buttonListeners = eventListeners["mouse_drag"][button]
		callCallbacks(buttonListeners, x, y)
	end,
	---Called when the mouse is scrolled
	---@param direction integer The scroll direction (-1 for up, 1 for down)
	---@param x integer The x coordinate of the mouse
	---@param y integer The y coordinate of the mouse
	["mouse_scroll"] = function(direction, x, y)
		local scrollListeners = eventListeners["mouse_scroll"]
		callCallbacks(scrollListeners, direction, x, y)
	end
}

local function eventListener()
	while true do
		local eventData = { os.pullEvent() }
		local event = table.remove(eventData, 1)
		local eventHandler = eventHandlers[event]
		if eventHandler ~= nil then
			eventHandler(table.unpack(eventData))
		end
		local listeners = eventListeners[event]
		if type(listeners) == "table" then
			listeners = listeners[eventData[1]]
		end
		if listeners ~= nil then
			for _, callback in pairs(listeners) do
				if callback ~= nil then
					callback(table.unpack(eventData))
				end
			end
		end
	end
end

---Generates a hotkey string from keycodes
---@param ... integer The keycodes
function Package.newHotkey(...)
	local keys = {...}
	if keys[1] == nil then
		error("A hotkey must contain at least one key", 2)
	end

	for i, v in pairs(keys) do
		ErrorUtils.mustBeOfType(v, "integer", "Each key")
	end

	table.sort(keys)

	local hotkey = ""
	for i, v in ipairs(keys) do
		hotkey = hotkey .. tostring(v) .. "+"
	end

	return hotkey:sub(1, -2)
end

---@param callback function
function Package.listenChars(callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	charListeners[listenerKey] = callback
	return newListener("char", listenerKey)
end

---@param callback function
function Package.listenKeyCodes(callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	keyListeners[listenerKey] = callback
	return newListener("key", listenerKey)
end

---@param hotkey string
---@param callback function
function Package.listenHotkey(hotkey, callback)
	ErrorUtils.mustBeOfType(hotkey, "string", "hotkey")
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	if hotkeyListeners[hotkey] == nil then
		hotkeyListeners[hotkey] = {}
	end
	hotkeyListeners[hotkey][listenerKey] = callback
	return newListener("hotkey", listenerKey, hotkey)
end

---@param key integer
---@param callback function
function Package.listenKey(key, callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	local keyString = tostring(key)
	if eventListeners["key"][keyString] == nil then
		eventListeners["key"][keyString] = {}
	end
	eventListeners["key"][keyString][listenerKey] = callback
	return newListener("event", listenerKey, "key", keyString)
end

---@param key integer
---@param callback function
function Package.listenKeyRelease(key, callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	local keyString = tostring(key)
	if eventListeners["key_up"][keyString] == nil then
		eventListeners["key_up"][keyString] = {}
	end
	eventListeners["key_up"][keyString][listenerKey] = callback
	return newListener("event", listenerKey, "key_up", keyString)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listenMouseClick(button, callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")
	ErrorUtils.mustBeOneOf(button, VALID_MOUSE_BUTTONS, "button")
	local buttonNumber = getMouseButtonNumber(button)

	local listenerKey = newListenerKey()
	eventListeners["mouse_click"][buttonNumber][listenerKey] = callback
	return newListener("event", listenerKey, "mouse_click", buttonNumber)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listenMouseRelease(button, callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")
	ErrorUtils.mustBeOneOf(button, VALID_MOUSE_BUTTONS, "button")
	local buttonNumber = getMouseButtonNumber(button)

	local listenerKey = newListenerKey()
	eventListeners["mouse_up"][buttonNumber][listenerKey] = callback
	return newListener("event", listenerKey, "mouse_up", buttonNumber)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listenMouseDrag(button, callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")
	ErrorUtils.mustBeOneOf(button, VALID_MOUSE_BUTTONS, "button")
	local buttonNumber = getMouseButtonNumber(button)

	local listenerKey = newListenerKey()
	eventListeners["mouse_drag"][buttonNumber][listenerKey] = callback
	return newListener("event", listenerKey, "mouse_drag", buttonNumber)
end

---@param callback function
function Package.listenMouseScroll(callback)
	ErrorUtils.mustBeOfType(callback, "function", "callback")

	local listenerKey = newListenerKey()
	eventListeners["mouse_scroll"][listenerKey] = callback
	return newListener("event", listenerKey, "mouse_scroll")
end

---Stop a event listener from listening
---@param listener table
function Package.stopListening(listener)
	if not isValidListener(listener) then
		error("listener must be a valid listener")
	end

	if listener[1] == "char" then
		charListeners[listener[2]] = nil
	elseif listener[1] == "key" then
		keyListeners[listener[2]] = nil
	elseif listener[1] == "hotkey" then
		hotkeyListeners[listener[3]][listener[2]] = nil
	elseif listener[1] == "event" then
		if listener[3] == "mouse_scroll" then
			eventListeners[listener[3]][listener[2]] = nil
		elseif listener[3] == "key" or listener[3] == "key_up" or listener[3] == "mouse_click" or listener[3] == "mouse_up" or listener[3] == "mouse_drag" then
			eventListeners[listener[3]][listener[4]][listener[2]] = nil
		end
	end
end

--* Setup

local function setup()
	Threading.new(eventListener)
end

setup()

--* Finshing Touches

return Package
