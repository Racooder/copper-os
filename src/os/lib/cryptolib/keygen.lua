local Rsa = require("rsa")

--
-- RSA Key Generator
-- By 1lann
--
-- Refer to license: http://pastebin.com/9gWSyqQt
--

local Package = {}

--
-- Start of my (1lann's) code
--

Package.big_zero = Rsa.bigint(0)
Package.big_one = Rsa.bigint(1)

Package.gcd = function(a, b)
    if b ~= Package.big_zero then
        return Package.gcd(b, a % b)
    else
        return a
    end
end

Package.modexp = function(base, exponent, modulus)
    local r = 1

    while true do
        if exponent % 2 == Package.big_one then
            r = r * base % modulus
        end
        exponent = exponent / 2

        if exponent == Package.big_zero then
            break
        end
        base = base * base % modulus
    end

    return r
end

Package.big_random_with_length = function(length, cap)
    if not cap then
        cap = 999999999
    end

    local random_string = tostring(math.random(100000000, cap))

    while true do
        random_string = random_string ..
            tostring(math.random(100000000, cap))
        if #random_string >= length then
            local final_random = random_string:sub(1, length)
            if final_random:sub(-1, -1) == "2" then
                return Rsa.bigint(final_random:sub(1, -2) .. "3")
            elseif final_random:sub(-1, -1) == "4" then
                return Rsa.bigint(final_random:sub(1, -2) .. "5")
            elseif final_random:sub(-1, -1) == "6" then
                return Rsa.bigint(final_random:sub(1, -2) .. "7")
            elseif final_random:sub(-1, -1) == "8" then
                return Rsa.bigint(final_random:sub(1, -2) .. "9")
            elseif final_random:sub(-1, -1) == "0" then
                return Rsa.bigint(final_random:sub(1, -2) .. "1")
            else
                return Rsa.bigint(final_random)
            end
        end
    end
end

Package.big_random = function(minNum, maxNum)
    if maxNum < Rsa.bigint(1000000000) then
        return Rsa.bigint(math.random(Rsa.biginttonumber(minNum),
            Rsa.biginttonumber(maxNum)))
    end

    local maxString = tostring(maxNum)
    local cap = tonumber(tostring(maxNum):sub(1, 9))
    local range = #maxString - #tostring(minNum)

    if range == 0 then
        return Package.big_random_with_length(#maxString, cap)
    end

    if #maxString > 30 then
        return Package.big_random_with_length(#maxString - 1)
    end

    local random_length = math.random(1, 2 ^ (#maxString - 1))
    for i = 1, #maxString - 1 do
        if random_length <= (2 ^ i) then
            return Package.big_random_with_length(i)
        end
    end
end

Package.is_prime = function(n)
    if type(n) == "number" then
        n = Rsa.bigint(n)
    end

    if n % 2 == Package.big_zero then
        return false
    end

    local s, d = 0, n - Package.big_one
    while d % 2 == Package.big_zero do
        s, d = s + 1, d / 2
    end

    for i = 1, 3 do
        local a = Package.big_random(Rsa.bigint(2), n - 2)
        local x = Package.modexp(a, d, n)
        if x ~= Package.big_one and x + 1 ~= n then
            for j = 1, s do
                x = Package.modexp(x, Rsa.bigint(2), n)
                if x == Package.big_one then
                    return false
                elseif x == n - 1 then
                    a = Package.big_zero
                    break
                end
            end
            if a ~= Package.big_zero then
                return false
            end
        end
    end

    return true
end

Package.generate_large_prime = function()
    local i = 0
    while true do
        write(".")
        os.sleep(0.1)
        local random_number = Package.big_random_with_length(39)

        if Package.is_prime(random_number) then
            return random_number
        end
    end
end

Package.generate_pq = function(e)
    local random_prime
    while true do
        random_prime = Package.generate_large_prime()
        if Package.gcd(e, random_prime - 1) == Package.big_one then
            return random_prime
        end
    end
end

Package.euclidean = function(a, b)
    local x, y, u, v = Package.big_zero, Package.big_one, Package.big_one, Package.big_zero
    while a ~= Package.big_zero do
        local q, r = b / a, b % a
        local m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    end
    return b, x, y
end

Package.modinv = function(a, m)
    local gcdnum, x, y = Package.euclidean(a, m)
    if gcdnum ~= Package.big_one then
        return nil
    else
        return x % m
    end
end

Package.generate_key_pair = function()
    while true do
        local e = Package.generate_large_prime()
        write("-")
        sleep(0.1)
        local p = Package.generate_pq(e)
        write("-")
        sleep(0.1)
        local q = Package.generate_pq(e)
        write("-")
        sleep(0.1)

        local n = p * q
        local phi = (p - 1) * (q - 1)
        local d = Package.modinv(e, phi)

        -- 104328 is just a magic number (can be any semi-unique number)
        local encrypted = Package.modexp(Rsa.bigint(104328), e, n)
        local decrypted = Package.modexp(encrypted, d, n)

        write("+")
        sleep(0.1)
        local counter = 0

        if decrypted == Rsa.bigint(104328) then
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

return Package
