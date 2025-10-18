local Package = {
    __internal = {}
}

local active_package
local console_lock

--* Internal Functions

---@param package string
function Package.__internal.set_active_package(package)
    active_package = package
end

---@param enabled boolean
function Package.__internal.set_console_lock(enabled)
    console_lock = enabled
end

--* Api Functions

---Get the currently active/foreground package
function Package.get_active_package()
    return active_package
end

---Check if gui mode is enabled
function Package.get_console_lock()
    return console_lock == true
end

function Package.get_home_path()
    return "/home"
end

return Package
