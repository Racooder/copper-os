local utility = require "copperUtility"

local loggerPrefix = "[Copper] "

local copperLogger = {}

function copperLogger.logToMonitor(scale, monitorQuery)
    scale = scale or 1
    local monitor
    if monitorQuery == nil then
        monitor = peripheral.find("monitor")
    else
        monitor = peripheral.wrap(monitorQuery)
    end
    monitor.setTextScale(scale)
    term.redirect(monitor)
    term.clear()
end

function copperLogger.setPrefix(prefix)
    loggerPrefix = prefix
end

function copperLogger.log(text)
    print(loggerPrefix .. text)
end

function copperLogger.logInColumns(text)
    local w, h = term.getSize()
    local lines = utility.splitByChunk(text, w - #loggerPrefix)
    local spacing = string.rep(" ", #loggerPrefix)
    for i, line in ipairs(lines) do
        if i == 1 then
            print(loggerPrefix .. line)
        else
            print(spacing .. line)
        end
    end
end

function copperLogger.debug(serializable)
    print("[DEBUG] " .. textutils.serialise(serializable))
end

return copperLogger
