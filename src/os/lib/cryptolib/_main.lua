local Aes = require("aes")
local Isaac = require("isaac")
local RsaCrypt = require("rsaCrypt")
local RsaKeygen = require("rsaKeygen")
local Sha256 = require("sha256")

local Cryptolib = {
    Aes = Aes,
    Isaac = Isaac,
    RsaCrypt = RsaCrypt,
    RsaKeygen = RsaKeygen,
    Sha256 = Sha256,
}

return Cryptolib
