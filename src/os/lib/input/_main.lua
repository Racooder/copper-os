local Threading = require("threading")
local Error = require("error")

local Package = {}

--* Variables

local VALID_MOUSE_BUTTONS = { "left", "middle", "right" }

local listener_counter = 0 -- Used for key generation

local char_listeners = {}
local key_listeners = {}
local hotkey_listeners = {}
local event_listeners = {
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

local is_pressed = {} -- Maps currently pressed keys to true

--* Main Functionality

---@return string
local function new_listener_key()
    listener_counter = listener_counter + 1
    return tostring(listener_counter)
end

---@param type "char"|"key"|"hotkey"|"event"
---@param key string
---@param ... any Additional data for the listener
---@return table listener A table representing the listener
local function new_listener(type, key, ...)
    return { type, key, table.unpack({...}) }
end

---@param listener table
---@return boolean
local function is_valid_listener(listener)
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
local function get_pressed_key_codes()
    local key_codes = {}
    for key_code, pressed in pairs(is_pressed) do
        if pressed then
            table.insert(key_codes, key_code)
        end
    end
    return key_codes
end

---@return integer button_number 1 = left, 2 = right, 3 = middle
local function get_mouse_button_number(name)
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

local function call_callbacks(listeners, ...)
    if listeners ~= nil then
        for _, callback in pairs(listeners) do
            if callback ~= nil then
                callback(...)
            end
        end
    end
end

local event_handlers = {
    ---Called when a character is typed
    ---@param char string The character that was typed
    ["char"] = function(char)
        for _, callback in pairs(char_listeners) do
            callback(char)
        end
    end,
    ---Called when a key is pressed
    ---@param key_code integer The key code of the pressed key
    ---@param is_held boolean Whether the key is held down (true) or just pressed (false)
    ["key"] = function(key_code, is_held) -- Called when a key is pressed
        is_pressed[key_code] = true

        call_callbacks(key_listeners, key_code, is_held) -- Call listeners that listen for any key press

        -- Trigger hotkey listeners if the key combination matches
        local pressed_hotkey = Package.new_hotkey(table.unpack(get_pressed_key_codes()))
        local pressed_hotkey_listeners = hotkey_listeners[pressed_hotkey]
        if pressed_hotkey_listeners ~= nil then
            call_callbacks(pressed_hotkey_listeners)
        end

        -- Call specific key listeners
        local key_code_listeners = event_listeners["key"][tostring(key_code)]
        if key_code_listeners ~= nil then
            call_callbacks(key_code_listeners, is_held)
        end
    end,
    ---Called when a key is released
    ---@param key_code integer The key code of the released key
    ["key_up"] = function(key_code)
        is_pressed[key_code] = nil

        local key_code_listeners = event_listeners["key_up"][tostring(key_code)]
        if key_code_listeners ~= nil then
            call_callbacks(key_code_listeners)
        end
    end,
    ---Called when a mouse button is clicked
    ---@param button integer The mouse button that was clicked (1 = left, 2 = right, 3 = middle)
    ---@param x integer The x coordinate of the mouse
    ---@param y integer The y coordinate of the mouse
    ["mouse_click"] = function(button, x, y)
        local button_listeners = event_listeners["mouse_click"][button]
        call_callbacks(button_listeners, x, y)
    end,
    ---Called when a mouse button is released
    ---@param button integer The mouse button that was released (1 = left, 2 = right, 3 = middle)
    ---@param x integer The x coordinate of the mouse
    ---@param y integer The y coordinate of the mouse
    ["mouse_up"] = function(button, x, y)
        local button_listeners = event_listeners["mouse_up"][button]
        call_callbacks(button_listeners, x, y)
    end,
    ---Called when a mouse button is dragged
    ---@param button integer The mouse button that was dragged (1 = left, 2 = right, 3 = middle)
    ---@param x integer The x coordinate of the mouse
    ---@param y integer The y coordinate of the mouse
    ["mouse_drag"] = function(button, x, y)
        local button_listeners = event_listeners["mouse_drag"][button]
        call_callbacks(button_listeners, x, y)
    end,
    ---Called when the mouse is scrolled
    ---@param direction integer The scroll direction (-1 for up, 1 for down)
    ---@param x integer The x coordinate of the mouse
    ---@param y integer The y coordinate of the mouse
    ["mouse_scroll"] = function(direction, x, y)
        local scroll_listeners = event_listeners["mouse_scroll"]
        call_callbacks(scroll_listeners, direction, x, y)
    end
}

local function event_listener()
    while true do
        local event_data = { os.pullEvent() }
        local event = table.remove(event_data, 1)
        local event_handler = event_handlers[event]
        if event_handler ~= nil then
            event_handler(table.unpack(event_data))
        end
        local listeners = event_listeners[event]
        if type(listeners) == "table" then
            listeners = listeners[event_data[1]]
        end
        if listeners ~= nil then
            for _, callback in pairs(listeners) do
                if callback ~= nil then
                    callback(table.unpack(event_data))
                end
            end
        end
    end
end

---Generates a hotkey string from keycodes
---@param ... integer The keycodes
function Package.new_hotkey(...)
    local keys = {...}
    if keys[1] == nil then
        error("A hotkey must contain at least one key", 2)
    end

    for i, v in pairs(keys) do
        Error.must_be_of_type(v, "integer", "Each key")
    end

    table.sort(keys)

    local hotkey = ""
    for i, v in ipairs(keys) do
        hotkey = hotkey .. tostring(v) .. "+"
    end

    return hotkey:sub(1, -2)
end

---@param callback function
function Package.listen_chars(callback)
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    char_listeners[listener_key] = callback
    return new_listener("char", listener_key)
end

---@param callback function
function Package.listen_key_codes(callback)
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    key_listeners[listener_key] = callback
    return new_listener("key", listener_key)
end

---@param hotkey string
---@param callback function
function Package.listen_hotkey(hotkey, callback)
    Error.must_be_of_type(hotkey, "string", "hotkey")
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    if hotkey_listeners[hotkey] == nil then
        hotkey_listeners[hotkey] = {}
    end
    hotkey_listeners[hotkey][listener_key] = callback
    return new_listener("hotkey", listener_key, hotkey)
end

---@param key integer
---@param callback function
function Package.listen_key(key, callback)
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    local key_string = tostring(key)
    if event_listeners["key"][key_string] == nil then
        event_listeners["key"][key_string] = {}
    end
    event_listeners["key"][key_string][listener_key] = callback
    return new_listener("event", listener_key, "key", key_string)
end

---@param key integer
---@param callback function
function Package.listen_key_release(key, callback)
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    local key_string = tostring(key)
    if event_listeners["key_up"][key_string] == nil then
        event_listeners["key_up"][key_string] = {}
    end
    event_listeners["key_up"][key_string][listener_key] = callback
    return new_listener("event", listener_key, "key_up", key_string)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listen_mouse_click(button, callback)
    Error.must_be_of_type(callback, "function", "callback")
    Error.must_be_one_of(button, VALID_MOUSE_BUTTONS, "button")
    local button_number = get_mouse_button_number(button)

    local listener_key = new_listener_key()
    event_listeners["mouse_click"][button_number][listener_key] = callback
    return new_listener("event", listener_key, "mouse_click", button_number)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listen_mouse_release(button, callback)
    Error.must_be_of_type(callback, "function", "callback")
    Error.must_be_one_of(button, VALID_MOUSE_BUTTONS, "button")
    local button_number = get_mouse_button_number(button)

    local listener_key = new_listener_key()
    event_listeners["mouse_up"][button_number][listener_key] = callback
    return new_listener("event", listener_key, "mouse_up", button_number)
end

---@param button "left"|"middle"|"right"
---@param callback function
function Package.listen_mouse_drag(button, callback)
    Error.must_be_of_type(callback, "function", "callback")
    Error.must_be_one_of(button, VALID_MOUSE_BUTTONS, "button")
    local button_number = get_mouse_button_number(button)

    local listener_key = new_listener_key()
    event_listeners["mouse_drag"][button_number][listener_key] = callback
    return new_listener("event", listener_key, "mouse_drag", button_number)
end

---@param callback function
function Package.listen_mouse_scroll(callback)
    Error.must_be_of_type(callback, "function", "callback")

    local listener_key = new_listener_key()
    event_listeners["mouse_scroll"][listener_key] = callback
    return new_listener("event", listener_key, "mouse_scroll")
end

---Stop a event listener from listening
---@param listener table
function Package.stop_listening(listener)
    if not is_valid_listener(listener) then
        error("listener must be a valid listener")
    end

    if listener[1] == "char" then
        char_listeners[listener[2]] = nil
    elseif listener[1] == "key" then
        key_listeners[listener[2]] = nil
    elseif listener[1] == "hotkey" then
        hotkey_listeners[listener[3]][listener[2]] = nil
    elseif listener[1] == "event" then
        if listener[3] == "mouse_scroll" then
            event_listeners[listener[3]][listener[2]] = nil
        elseif listener[3] == "key" or listener[3] == "key_up" or listener[3] == "mouse_click" or listener[3] == "mouse_up" or listener[3] == "mouse_drag" then
            event_listeners[listener[3]][listener[4]][listener[2]] = nil
        end
    end
end

--* Setup

local function setup()
    Threading.new(event_listener)
end

setup()

--* Finishing Touches

return Package
