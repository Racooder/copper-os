-- KillaVanilla's RNG('s), composed of the Mersenne Twister RNG and the ISAAC algorithm.

-- Exposed functions:
-- initalize_mt_generator(seed) - Seed the Mersenne Twister RNG.
-- extract_mt() - Get a number from the Mersenne Twister RNG.
-- seed_from_mt(seed) - Seed the ISAAC RNG, optionally seeding the Mersenne Twister RNG beforehand.
-- generate_isaac() - Force a reseed.
-- random(min, max) - Get a random number between min and max.

local Isaac = {}

-- Helper functions:
Isaac.toBinary = function(a)  -- Convert from an integer to an arbitrary-length table of bits
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

Isaac.fromBinary = function(a)  -- Convert from an arbitrary-length table of bits (from toBinary) to an integer
    local dec = 0
    for i = #a, 1, -1 do
        dec = dec * 2 + a[i]
    end
    return dec
end

-- ISAAC internal state:
Isaac.aa = 0
Isaac.bb = 0
Isaac.cc = 0
Isaac.randrsl = {} -- Acts as entropy/seed-in. Fill to randrsl[256].
Isaac.mm = {}      -- Fill to mm[256]. Acts as output.

-- Mersenne Twister State:
Isaac.MT = {} -- Twister state
Isaac.index = 0

-- Other variables for the seeding mechanism
Isaac.mtSeeded = false
Isaac.mtSeed = math.random(1, 2 ^ 31 - 1)

-- The Mersenne Twister can be used as an RNG for non-cryptographic purposes.
-- Here, we're using it to seed the ISAAC algorithm, which *can* be used for cryptographic purposes.

Isaac.initalize_mt_generator = function(seed)
    Isaac.index = 0
    Isaac.MT[0] = seed
    for i = 1, 623 do
        local full = ((1812433253 * bit.bxor(Isaac.MT[i - 1], bit.brshift(Isaac.MT[i - 1], 30))) + i)
        local b = Isaac.toBinary(full)
        while #b > 32 do
            table.remove(b, 1)
        end
        Isaac.MT[i] = Isaac.fromBinary(b)
    end
end

Isaac.generate_mt = function()  -- Restock the MT with new random numbers.
    for i = 0, 623 do
        local y = bit.band(Isaac.MT[i], 0x80000000)
        y = y + bit.band(Isaac.MT[(i + 1) % 624], 0x7FFFFFFF)
        Isaac.MT[i] = bit.bxor(Isaac.MT[(i + 397) % 624], bit.brshift(y, 1))
        if y % 2 == 1 then
            Isaac.MT[i] = bit.bxor(Isaac.MT[i], 0x9908B0DF)
        end
    end
end

Isaac.extract_mt = function(min, max)  -- Get one number from the Mersenne Twister.
    if Isaac.index == 0 then
        Isaac.generate_mt()
    end
    local y = Isaac.MT[Isaac.index]
    min = min or 0
    max = max or 2 ^ 32 - 1
    --print("Accessing: isaac.MT["..isaac.index.."]...")
    y = bit.bxor(y, bit.brshift(y, 11))
    y = bit.bxor(y, bit.band(bit.blshift(y, 7), 0x9D2C5680))
    y = bit.bxor(y, bit.band(bit.blshift(y, 15), 0xEFC60000))
    y = bit.bxor(y, bit.brshift(y, 18))
    Isaac.index = (Isaac.index + 1) % 624
    return (y % max) + min
end

Isaac.seed_from_mt = function(seed)  -- seed ISAAC with numbers from the MT:
    if seed then
        Isaac.mtSeeded = false
        Isaac.mtSeed = seed
    end
    if not Isaac.mtSeeded or (math.random(1, 100) == 50) then -- Always seed the first time around. Otherwise, seed approximately once per 100 times.
        Isaac.initalize_mt_generator(Isaac.mtSeed)
        Isaac.mtSeeded = true
        Isaac.mtSeed = Isaac.extract_mt()
    end
    for i = 1, 256 do
        Isaac.randrsl[i] = Isaac.extract_mt()
    end
end

Isaac.mix = function(a, b, c, d, e, f, g, h)
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

Isaac.isaac = function()
    local x, y = 0, 0
    for i = 1, 256 do
        x = Isaac.mm[i]
        if (i % 4) == 0 then
            Isaac.aa = bit.bxor(Isaac.aa, bit.blshift(Isaac.aa, 13))
        elseif (i % 4) == 1 then
            Isaac.aa = bit.bxor(Isaac.aa, bit.brshift(Isaac.aa, 6))
        elseif (i % 4) == 2 then
            Isaac.aa = bit.bxor(Isaac.aa, bit.blshift(Isaac.aa, 2))
        elseif (i % 4) == 3 then
            Isaac.aa = bit.bxor(Isaac.aa, bit.brshift(Isaac.aa, 16))
        end
        Isaac.aa = (Isaac.mm[((i + 128) % 256) + 1] + Isaac.aa) % (2 ^ 32 - 1)
        y = (Isaac.mm[(bit.brshift(x, 2) % 256) + 1] + Isaac.aa + Isaac.bb) % (2 ^ 32 - 1)
        Isaac.mm[i] = y
        Isaac.bb = (Isaac.mm[(bit.brshift(y, 10) % 256) + 1] + x) % (2 ^ 32 - 1)
        Isaac.randrsl[i] = Isaac.bb
    end
end

Isaac.randinit = function(flag)
    local a, b, c, d, e, f, g, h = 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9, 0x9e3779b9,
        0x9e3779b9                                                                                               -- 0x9e3779b9 is the golden ratio
    Isaac.aa = 0
    Isaac.bb = 0
    Isaac.cc = 0
    for i = 1, 4 do
        a, b, c, d, e, f, g, h = Isaac.mix(a, b, c, d, e, f, g, h)
    end
    for i = 1, 256, 8 do
        if flag then
            a = (a + Isaac.randrsl[i]) % (2 ^ 32 - 1)
            b = (b + Isaac.randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + Isaac.randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + Isaac.randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + Isaac.randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + Isaac.randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + Isaac.randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + Isaac.randrsl[i + 7]) % (2 ^ 32 - 1)
        end
        a, b, c, d, e, f, g, h = Isaac.mix(a, b, c, d, e, f, g, h)
        Isaac.mm[i] = a
        Isaac.mm[i + 1] = b
        Isaac.mm[i + 2] = c
        Isaac.mm[i + 3] = d
        Isaac.mm[i + 4] = e
        Isaac.mm[i + 5] = f
        Isaac.mm[i + 6] = g
        Isaac.mm[i + 7] = h
    end

    if flag then
        for i = 1, 256, 8 do
            a = (a + Isaac.randrsl[i]) % (2 ^ 32 - 1)
            b = (b + Isaac.randrsl[i + 1]) % (2 ^ 32 - 1)
            c = (c + Isaac.randrsl[i + 2]) % (2 ^ 32 - 1)
            d = (b + Isaac.randrsl[i + 3]) % (2 ^ 32 - 1)
            e = (e + Isaac.randrsl[i + 4]) % (2 ^ 32 - 1)
            f = (f + Isaac.randrsl[i + 5]) % (2 ^ 32 - 1)
            g = (g + Isaac.randrsl[i + 6]) % (2 ^ 32 - 1)
            h = (h + Isaac.randrsl[i + 7]) % (2 ^ 32 - 1)
            a, b, c, d, e, f, g, h = Isaac.mix(a, b, c, d, e, f, g, h)
            Isaac.mm[i] = a
            Isaac.mm[i + 1] = b
            Isaac.mm[i + 2] = c
            Isaac.mm[i + 3] = d
            Isaac.mm[i + 4] = e
            Isaac.mm[i + 5] = f
            Isaac.mm[i + 6] = g
            Isaac.mm[i + 7] = h
        end
    end
    Isaac.isaac()
    local randcnt = 256
end

Isaac.generate_isaac = function(entropy)
    Isaac.aa = 0
    Isaac.bb = 0
    Isaac.cc = 0
    if entropy and #entropy >= 256 then
        for i = 1, 256 do
            Isaac.randrsl[i] = entropy[i]
        end
    else
        Isaac.seed_from_mt()
    end
    for i = 1, 256 do
        Isaac.mm[i] = 0
    end
    Isaac.randinit(true)
    Isaac.isaac()
    Isaac.isaac() -- run isaac twice
end

Isaac.getRandom = function()
    if #Isaac.mm > 0 then
        return table.remove(Isaac.mm, 1)
    else
        Isaac.generate_isaac()
        return table.remove(Isaac.mm, 1)
    end
end

Isaac.random = function(min, max)
    if not max then
        max = 2 ^ 32 - 1
    end
    if not min then
        min = 0
    end
    return (Isaac.getRandom() % max) + min
end

return Isaac
