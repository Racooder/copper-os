local PacMan = require "main"

local api = {
    ["exists"] = function (args)
        print(PacMan.exists(args[1]))
    end,
    ["list"] = function ()
        local pkgList = PacMan.list()
        for i, pkg in ipairs(pkgList) do
            local type = PacMan.getType(pkg)
            print(i .. ". " .. pkg .. " (" .. type .. ")")
        end
    end,
    ["getMeta"] = function (args)
        local meta = PacMan.getMeta(args[1])
    end,
    ["getType"] = function (args)
        print(PacMan.getType(args[1]))
    end,
    ["install"] = function (args)
        PacMan.install(args[1])
    end,
    ["delete"] = function (args)
        PacMan.delete(args[1])
    end
}

---@param args string[]
local function main(args)
    print("App Store Debug")
end

return main
