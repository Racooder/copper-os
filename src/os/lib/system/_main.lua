local Package = {
	__internal = {}
}

local activePackage
local consoleLock

--* Internal Functions

---@param package string
function Package.__internal.setActivePackage(package)
	activePackage = package
end

---@param enabled boolean
function Package.__internal.setConsoleLock(enabled)
	consoleLock = enabled
end

--* Api Functions

---Get the currently active/foreground package
function Package.getActivePackage()
	return activePackage
end

---Check if gui mode is enabled
function Package.getConsoleLock()
	return consoleLock == true
end

return Package
