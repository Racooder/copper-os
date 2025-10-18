local ErrorUtil = require("error")

local Package = {}

--- Reverses the order of elements in a table.
--- @param tbl table The string to split.
function Package.reverse(tbl)
    ErrorUtil.must_be_of_type(tbl, "table", "tbl")

    local reversed = {}
    for i = #tbl, 1, -1 do
        table.insert(reversed, tbl[i])
    end
    return reversed
end

--- Returns a part of a table from the specified start index to the stop index.
--- @param tbl table The table to slice.
--- @param start number The starting index.
--- @param stop number The ending index. If negative, it counts from the end of the table.
function Package.slice(tbl, start, stop)
    ErrorUtil.must_be_of_type(tbl, "table", "tbl")
    ErrorUtil.must_be_of_type(start, "number", "start")
    ErrorUtil.must_be_of_type(stop, "number", "stop")

    if stop < 0 then
        stop = #tbl - stop + 1
    end

    local sliced = {}
    for i = start, stop do
        table.insert(sliced, tbl[i])
    end
    return sliced
end

return Package
