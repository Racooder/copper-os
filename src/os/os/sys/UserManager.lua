local sha256 = require "sha256"
local Console = require "Console"

local UserManager = {}

local activeUser = nil

function UserManager.exists(username)
    return fs.exists("/os/usr/" .. username)
end

function UserManager.list()
    return fs.list("/os/usr/")
end

local function hashPassword(username, password)
    return tostring(sha256.digest(username .. password))
end

function UserManager.add(username, password)
    if UserManager.exists(username) then
        return false
    end

    fs.makeDir("/os/usr/" .. username)
    local file = fs.open("/os/usr/" .. username .. "/.password", "w")
    file.write(hashPassword(username, password))
    file.close()
    return true
end

function UserManager.login(username, password)
    if not UserManager.exists(username) then
        return false
    end

    local file = fs.open("/os/usr/" .. username .. "/.password", "r")
    local storedPassword = file.readAll()
    file.close()

    if hashPassword(username, password) == storedPassword then
        activeUser = username
        return true
    end

    return false
end

function UserManager.getActiveUser()
    return activeUser
end

function UserManager.setupUserInterface()
    Console.clear()
    Console.print("Set up a new user account")
    local username = Console.read("Username: ")
    if UserManager.exists(username) then
        Console.print("User already exists")
        return false
    end
    local password = Console.read("Password: ", "*")
    local passwordConfirm = Console.read("Confirm password: ", "*")
    if password ~= passwordConfirm then
        Console.print("Passwords do not match")
        return false
    end
    UserManager.add(username, password)
    UserManager.login(username, password)
    return true
end

function UserManager.loginInterface()
    Console.clear()
    Console.printList(UserManager.list(), true)
    Console.print("Login")
    local username = Console.read("Username: ")
    local password = Console.read("Password: ", "*")
    if not UserManager.exists(username) then
        Console.print("User does not exist")
        return false
    end
    return UserManager.login(username, password)
end

return UserManager
