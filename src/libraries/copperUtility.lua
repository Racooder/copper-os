---A collection of utility functions for copper os.
---@module copperUtility
local copperUtility = {}

---Splits a string into a table of strings based on a separator.
---@param inputstr string
---@param sep string
---@src https://stackoverflow.com/a/7615129
function copperUtility.splitString(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end
    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

---Trims a string.
---@param inputstr string
---@return string
function copperUtility.trimString(inputstr)
    return (string.gsub(inputstr, "^%s*(.-)%s*$", "%1"))
end

---Split a string into chunks of a given size.
---@param text string
---@param chunkSize integer
---@return table
function copperUtility.splitByChunk(text, chunkSize)
    local s = {}
    for i=1, #text, chunkSize do
        s[#s+1] = text:sub(i,i+chunkSize - 1)
    end
    return s
end

---Concatenates two tables. The first table is modified.
---@param t1 table
---@param t2 table
---@return table - The concatenated table
function copperUtility.concatTables(t1, t2)
    for i=1,#t2 do
        t1[#t1+1] = t2[i]
    end
    return t1
end

--* List

---@class List
---@field first number
---@field last number
copperUtility.List = {
    first = 0,
    last = -1
}
function copperUtility.List:new()
    local o = {}
    setmetatable(o, self)
    return o
end

---Adds a value to the beginning of the list.
---@param value any
function copperUtility.List:pushLeft(value)
    local first = self.first - 1
    self.first = first
    self[first] = value
end

---Adds a value to the end of the list.
---@param value any
function copperUtility.List:pushRight(value)
    local last = self.last + 1
    self.last = last
    self[last] = value
end

---Removes and returns the first value of the list.
---@return any
function copperUtility.List:popLeft()
    local first = self.first
    if first > self.last then
        error("list is empty")
    end
    local value = self[first]
    self[first] = nil
    self.first = first + 1
    return value
end

---Removes and returns the last value of the list.
---@return any
function copperUtility.List:popRight()
    local last = self.last
    if self.first > last then
        error("list is empty")
    end
    local value = self[last]
    self[last] = nil
    self.last = last - 1
    return value
end

--* Export

return copperUtility
