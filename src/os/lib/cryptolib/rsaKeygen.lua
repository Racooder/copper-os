local RsaCrypt = require("rsaCrypt")

--
-- RSA Key Generator
-- By 1lann
--
-- Refer to license: http://pastebin.com/9gWSyqQt
--

local RsaKeygen = {}

--
-- Start of my (1lann's) code
--

RsaKeygen.bigZero = RsaCrypt.bigint(0)
RsaKeygen.bigOne = RsaCrypt.bigint(1)

RsaKeygen.gcd = function(a, b)
    if b ~= RsaKeygen.bigZero then
        return RsaKeygen.gcd(b, a % b)
    else
        return a
    end
end

RsaKeygen.modexp = function(base, exponent, modulus)
    local r = 1

    while true do
        if exponent % 2 == RsaKeygen.bigOne then
            r = r * base % modulus
        end
        exponent = exponent / 2

        if exponent == RsaKeygen.bigZero then
            break
        end
        base = base * base % modulus
    end

    return r
end

RsaKeygen.bigRandomWithLength = function(length, cap)
    if not cap then
        cap = 999999999
    end

    local randomString = tostring(math.random(100000000, cap))

    while true do
        randomString = randomString ..
            tostring(math.random(100000000, cap))
        if #randomString >= length then
            local finalRandom = randomString:sub(1, length)
            if finalRandom:sub(-1, -1) == "2" then
                return RsaCrypt.bigint(finalRandom:sub(1, -2) .. "3")
            elseif finalRandom:sub(-1, -1) == "4" then
                return RsaCrypt.bigint(finalRandom:sub(1, -2) .. "5")
            elseif finalRandom:sub(-1, -1) == "6" then
                return RsaCrypt.bigint(finalRandom:sub(1, -2) .. "7")
            elseif finalRandom:sub(-1, -1) == "8" then
                return RsaCrypt.bigint(finalRandom:sub(1, -2) .. "9")
            elseif finalRandom:sub(-1, -1) == "0" then
                return RsaCrypt.bigint(finalRandom:sub(1, -2) .. "1")
            else
                return RsaCrypt.bigint(finalRandom)
            end
        end
    end
end

RsaKeygen.bigRandom = function(minNum, maxNum)
    if maxNum < RsaCrypt.bigint(1000000000) then
        return RsaCrypt.bigint(math.random(RsaCrypt.biginttonumber(minNum),
            RsaCrypt.biginttonumber(maxNum)))
    end

    local maxString = tostring(maxNum)
    local cap = tonumber(tostring(maxNum):sub(1, 9))
    local range = #maxString - #tostring(minNum)

    if range == 0 then
        return RsaKeygen.bigRandomWithLength(#maxString, cap)
    end

    if #maxString > 30 then
        return RsaKeygen.bigRandomWithLength(#maxString - 1)
    end

    local randomLength = math.random(1, 2 ^ (#maxString - 1))
    for i = 1, #maxString - 1 do
        if randomLength <= (2 ^ i) then
            return RsaKeygen.bigRandomWithLength(i)
        end
    end
end

RsaKeygen.isPrime = function(n)
    if type(n) == "number" then
        n = RsaCrypt.bigint(n)
    end

    if n % 2 == RsaKeygen.bigZero then
        return false
    end

    local s, d = 0, n - RsaKeygen.bigOne
    while d % 2 == RsaKeygen.bigZero do
        s, d = s + 1, d / 2
    end

    for i = 1, 3 do
        local a = RsaKeygen.bigRandom(RsaCrypt.bigint(2), n - 2)
        local x = RsaKeygen.modexp(a, d, n)
        if x ~= RsaKeygen.bigOne and x + 1 ~= n then
            for j = 1, s do
                x = RsaKeygen.modexp(x, RsaCrypt.bigint(2), n)
                if x == RsaKeygen.bigOne then
                    return false
                elseif x == n - 1 then
                    a = RsaKeygen.bigZero
                    break
                end
            end
            if a ~= RsaKeygen.bigZero then
                return false
            end
        end
    end

    return true
end

RsaKeygen.generateLargePrime = function()
    local i = 0
    while true do
        write(".")
        os.sleep(0.1)
        local randomNumber = RsaKeygen.bigRandomWithLength(39)

        if RsaKeygen.isPrime(randomNumber) then
            return randomNumber
        end
    end
end

RsaKeygen.generatePQ = function(e)
    local randomPrime
    while true do
        randomPrime = RsaKeygen.generateLargePrime()
        if RsaKeygen.gcd(e, randomPrime - 1) == RsaKeygen.bigOne then
            return randomPrime
        end
    end
end

RsaKeygen.euclidean = function(a, b)
    local x, y, u, v = RsaKeygen.bigZero, RsaKeygen.bigOne, RsaKeygen.bigOne, RsaKeygen.bigZero
    while a ~= RsaKeygen.bigZero do
        local q, r = b / a, b % a
        local m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    end
    return b, x, y
end

RsaKeygen.modinv = function(a, m)
    local gcdnum, x, y = RsaKeygen.euclidean(a, m)
    if gcdnum ~= RsaKeygen.bigOne then
        return nil
    else
        return x % m
    end
end

RsaKeygen.generateKeyPair = function()
    while true do
        local e = RsaKeygen.generateLargePrime()
        write("-")
        sleep(0.1)
        local p = RsaKeygen.generatePQ(e)
        write("-")
        sleep(0.1)
        local q = RsaKeygen.generatePQ(e)
        write("-")
        sleep(0.1)

        local n = p * q
        local phi = (p - 1) * (q - 1)
        local d = RsaKeygen.modinv(e, phi)

        -- 104328 is just a magic number (can be any semi-unique number)
        local encrypted = RsaKeygen.modexp(RsaCrypt.bigint(104328), e, n)
        local decrypted = RsaKeygen.modexp(encrypted, d, n)

        write("+")
        sleep(0.1)
        local counter = 0

        if decrypted == RsaCrypt.bigint(104328) then
            counter = 0
            return {
                shared = tostring(n),
                public = tostring(e),
            }, {
                shared = tostring(n),
                private = tostring(d),
            }
        end
    end
end

return RsaKeygen
