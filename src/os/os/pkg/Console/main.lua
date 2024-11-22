local Console = {}

function Console.clear()
    term.clear()
    term.setCursorPos(1, 1)
end

--- @param message string
function Console.write(message)
    term.write(message) -- TODO: Prevent logging while in gui
end

--- @param message string
--- @param color? string
function Console.print(message, color)
    term.setTextColor(color or colors.white)
    term.write(message) -- TODO: Prevent logging while in gui
    local _, y = term.getCursorPos()
    term.setCursorPos(1, y + 1)
end

--- @param prefix? string
--- @param replaceChar? string
--- @param history? table
--- @param completeFn? function
--- @param default? string
--- @return string
function Console.read(prefix, replaceChar, history, completeFn, default)
    term.write(prefix or "")
    return read(replaceChar, history, completeFn, default)
end

local function log(message, prefix, color, package)
    local packagePrefix = package and "[" .. package .. "]" or ""
    Console.print("[" .. prefix .. "]" .. packagePrefix .. " " .. message, color)
    -- TODO: Log to file
end

--- @param message string
--- @param package? string
function Console.info(message, package)
    log(message, "INFO", colors.white, package)
end

--- @param message string
--- @param package? string
function Console.success(message, package)
    log(message, "SUCCESS", colors.green, package)
end

--- @param message string
--- @param package? string
function Console.warning(message, package)
    log(message, "WARNING", colors.orange, package)
end

--- @param message string
--- @param package? string
function Console.error(message, package)
    log(message, "ERROR", colors.red, package)
end

--- Prints a list of elements, recursively if they are tables
--- @param list table
--- @param index? boolean If true, prints the index of the element
--- @param prefix? string
function Console.printList(list, index, prefix)
    prefix = prefix or ""
    for i, element in ipairs(list) do
        if (type(element) == "table") then
            Console.printList(element, index, "  " .. prefix)
        else
            Console.print((index and i .. ". " or "") .. prefix .. element)
        end
    end
end

return Console
