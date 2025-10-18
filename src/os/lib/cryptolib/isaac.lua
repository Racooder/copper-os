-- KillaVanilla's RNG('s), composed of the Mersenne Twister RNG and the ISAAC algorithm.

-- Exposed functions:
-- initalize_mt_generator(seed) - Seed the Mersenne Twister RNG.
-- extract_mt() - Get a number from the Mersenne Twister RNG.
-- seed_from_mt(seed) - Seed the ISAAC RNG, optionally seeding the Mersenne Twister RNG beforehand.
-- generate_isaac() - Force a reseed.
-- random(min, max) - Get a random number between min and max.

local Package = {}

-- Helper functions:
Package.to_binary = function(a)  -- Convert from an integer to an arbitrary-length table of bits
    local b = {}
    local copy = a
    while true do
        table.insert(b, copy % 2)
        copy = math.floor(copy / 2)
        if copy == 0 then
            break
        end
    end
    return b
end

Package.from_binary = function(a)  -- Convert from an arbitrary-length table of bits (from toBinary) to an integer
    local dec = 0
    for i = #a, 1, -1 do
        dec = dec * 2 + a[i]
    end
    return dec
end

-- ISAAC internal state:
Package.aa = 0
Package.bb = 0
Package.cc = 0
Package.randrsl = {} -- Acts as entropy/seed-in. Fill to randrsl[256].
Package.mm = {}      -- Fill to mm[256]. Acts as output.

-- Mersenne Twister State:
Package.MT = {} -- Twister state
Package.index = 0

-- Other variables for the seeding mechanism
Package.mt_seeded = false
Package.mt_seed = math.random(1, 2 ^ 31 - 1)

-- The Mersenne Twister can be used as an RNG for non-cryptographic purposes.
-- Here, we're using it to seed the ISAAC algorithm, which *can* be used for cryptographic purposes.

Package.initalize_mt_generator = function(seed)
    Package.index = 0
    Package.MT[0] = seed
    for i = 1, 623 do
        local full = ((1812433253 * bit.bxor(Package.MT[i - 1], bit.brshift(Package.MT[i - 1], 30))) + i)
        local b = Package.to_binary(full)
        while #b > 32 do
            table.remove(b, 1)
        end
        Package.MT[i] = Package.from_binary(b)
    end
end

Package.generate_mt = function()  -- Restock the MT with new random numbers.
    for i = 0, 623 do
        local y = bit.band(Package.MT[i], 0x80000000)
        y = y + bit.band(Package.MT[(i + 1) % 624], 0x7FFFFFFF)
        Package.MT[i] = bit.bxor(Package.MT[(i + 397) % 624], bit.brshift(y, 1))
        if y % 2 == 1 then
            Package.MT[i] = bit.bxor(Package.MT[i], 0x9908B0DF)
        end
    end
end

Package.extract_mt = function(min, max)  -- Get one number from the Mersenne Twister.
    if Package.index == 0 then
        Package.generate_mt()
    end
    local y = Package.MT[Package.index]
    min = min or 0
    max = max or 2 ^ 32 - 1
    --print("Accessing: isaac.MT["..isaac.index.."]...")
    y = bit.bxor(y, bit.brshift(y, 11))
    y = bit.bxor(y, bit.band(bit.blshift(y, 7), 0x9D2C5680))
    y = bit.bxor(y, bit.band(bit.blshift(y, 15), 0xEFC60000))
    y = bit.bxor(y, bit.brshift(y, 18))
    Package.index = (Package.index + 1) % 624
    return (y % max) + min
end

Package.seed_from_mt = function(seed)  -- seed ISAAC with numbers from the MT:
    if seed then
        Package.mt_seeded = false
        Package.mt_seed = seed
    end
    if not Package.mt_seeded or (math.random(1, 100) == 50) then -- Always seed the first time around. Otherwise, seed approximately once per 100 times.
        Package.initalize_mt_generator(Package.mt_seed)
        Package.mt_seeded = true
        Package.mt_seed = Package.extract_mt()
    end
    for i = 1, 256 do
        Package.randrsl[i] = Package.extract_mt()
    end
end

Package.mix = function(a, b, c, d, e, f, g, h)
    a = a % (2 ^ 32 - 1)
    b = b % (2 ^ 32 - 1)
    c = c % (2 ^ 32 - 1)
    d = d % (2 ^ 32 - 1)
    e = e % (2 ^ 32 - 1)
    f = f % (2 ^ 32 - 1)
    g = g % (2 ^ 32 - 1)
    h = h % (2 ^ 32 - 1)
    a = bit.bxor(a, bit.blshift(b, 11))
    d = (d + a) % (2 ^ 32 - 1)
    b = (b + c) % (2 ^ 32 - 1)
    b = bit.bxor(b, bit.brshift(c, 2))
    e = (e + b) % (2 ^ 32 - 1)
    c = (c + d) % (2 ^ 32 - 1)
    c = bit.bxor(c, bit.blshift(d, 8))
    f = (f + c) % (2 ^ 32 - 1)
    d = (d + e) % (2 ^ 32 - 1)
    d = bit.bxor(d, bit.brshift(e, 16))
    g = (g + d) % (2 ^ 32 - 1)
    e = (e + f) % (2 ^ 32 - 1)
    e = bit.bxor(e, bit.blshift(f, 10))
    h = (h + e) % (2 ^ 32 - 1)
    f = (f + g) % (2 ^ 32 - 1)
    f = bit.bxor(f, bit.brshift(g, 4))
    a = (a + f) % (2 ^ 32 - 1)
    g = (g + h) % (2 ^ 32 - 1)
    g = bit.bxor(g, bit.blshift(h, 8))
    b = (b + g) % (2 ^ 32 - 1)
    h = (h + a) % (2 ^ 32 - 1)
    h = bit.bxor(h, bit.brshift(a, 9))
    c = (c + h) % (2 ^ 32 - 1)
    a = (a + b) % (2 ^ 32 - 1)
    return a, b, c, d, e, f, g, h
end

Package.isaac = function()
    local x, y = 0, 0
    for i = 1, 256 do
        x = Package.mm[i]
        if (i % 4) == 0 then
            Package.aa = bit.bxor(Package.aa, bit.blshift(Package.aa, 13))
        elseif (i % 4) == 1 then
            Package.aa = bit.bxor(Package.aa, bit.brshift(Package.aa, 6))
        elseif (i % 4) == 2 then
            Package.aa = bit.bxor(Package.aa, bit.blshift(Package.aa, 2))
        elseif (i % 4) == 3 then
            Package.aa = bit.bxor(Package.aa, bit.brshift(Package.aa, 16))
        end
        Package.aa = (Package.mm[((i + 128) % 256) + 1] + Package.aa) % (2 ^ 32 - 1)
        y = (Package.mm[(bit.brshift(x, 2) % 256) + 1] + Package.aa + Package.bb) % (2 ^ 32 - 1)
        Package.mm[i] = y
        Package.bb = (Package.mm[(bit.brshift(y, 10) % 256) + 1] + x) % (2 ^ 32 - 1)
        Package.randrsl[i] = Package.bb
    end
end

Package.randinit = function(flag)
    local a, b, c, d, e, f, g, h = 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9,
        0x9e3779b9                                                                                               -- 0x9e3779b9 is the golden ratio
    Package.aa = 0
    Package.bb = 0
    Package.cc = 0
    for i = 1, 4 do
        a, b, c, d, e, f, g, h = Package.mix(a, b, c, d, e, f, g, h)
    end
    for i = 1, 256, 8 do
        if flag then
            a = (a + Package.randrsl[i]) % (2 ^ 32 - 1)
            b = (b + Package.randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + Package.randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + Package.randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + Package.randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + Package.randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + Package.randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + Package.randrsl[i + 7]) % (2 ^ 32 - 1)
        end
        a, b, c, d, e, f, g, h = Package.mix(a, b, c, d, e, f, g, h)
        Package.mm[i] = a
        Package.mm[i + 1] = b
        Package.mm[i + 2] = c
        Package.mm[i + 3] = d
        Package.mm[i + 4] = e
        Package.mm[i + 5] = f
        Package.mm[i + 6] = g
        Package.mm[i + 7] = h
    end

    if flag then
        for i = 1, 256, 8 do
            a = (a + Package.randrsl[i]) % (2 ^ 32 - 1)
            b = (b + Package.randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + Package.randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + Package.randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + Package.randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + Package.randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + Package.randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + Package.randrsl[i + 7]) % (2 ^ 32 - 1)
            a, b, c, d, e, f, g, h = Package.mix(a, b, c, d, e, f, g, h)
            Package.mm[i] = a
            Package.mm[i + 1] = b
            Package.mm[i + 2] = c
            Package.mm[i + 3] = d
            Package.mm[i + 4] = e
            Package.mm[i + 5] = f
            Package.mm[i + 6] = g
            Package.mm[i + 7] = h
        end
    end
    Package.isaac()
    local randcnt = 256
end

Package.generate_isaac = function(entropy)
    Package.aa = 0
    Package.bb = 0
    Package.cc = 0
    if entropy and #entropy >= 256 then
        for i = 1, 256 do
            Package.randrsl[i] = entropy[i]
        end
    else
        Package.seed_from_mt()
    end
    for i = 1, 256 do
        Package.mm[i] = 0
    end
    Package.randinit(true)
    Package.isaac()
    Package.isaac() -- run isaac twice
end

Package.get_random = function()
    if #Package.mm > 0 then
        return table.remove(Package.mm, 1)
    else
        Package.generate_isaac()
        return table.remove(Package.mm, 1)
    end
end

Package.random = function(min, max)
    if not max then
        max = 2 ^ 32 - 1
    end
    if not min then
        min = 0
    end
    return (Package.get_random() % max) + min
end

return Package
