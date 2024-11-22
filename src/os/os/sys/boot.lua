package.path = "?.lua;/os/sys/?.lua;/os/pkg/?/main.lua"

local main = require "main"
local ThreadApi = require "ThreadApi"
local UserManager = require "UserManager"

local function login()
    if #UserManager.list() == 0 then
        while not UserManager.setupUserInterface() do end
    else
        while not UserManager.loginInterface() do end
    end
end

local function boot()
    print("Booting up...")

    login()

    package.path = "?.lua;os/pkg/?/main.lua"

    ThreadApi.startThreading(main)
end

boot()
