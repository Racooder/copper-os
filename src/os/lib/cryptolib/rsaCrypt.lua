--
-- Licenses for Simple RSA Library by 1lann
--
-- This RSA library should not be used for real-life purposes.
-- It is here to demonstrate a pure Lua implementation of RSA
-- for educational purposes. This RSA library is in no way
-- secure and does not endorse use of this library for any
-- actual security purposes.
--
-- Copyright (c) 2015 Jason Chu (1lann)
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

--
-- Big Integer Library, copyright as follows.
--
-- Copyright (c) 2010 Ted Unangst <ted.unangst@gmail.com>
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

--
-- Lua version ported/copied from the C version of the Big Integer Library, copyright as follows.
--
-- Copyright (c) 2000 by Jef Poskanzer <jef@mail.acme.com>.
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--


--
-- RSA Encryption/Decryption Library
-- By 1lann
--
-- Refer to license: http://pastebin.com/9gWSyqQt
--

local RsaCrypt = {}

--
-- Start of third-party libraries/helpers
--

-- two functions to help make Lua act more like C
RsaCrypt.fl = function(x)
    if x < 0 then
        return math.ceil(x) + 0 -- make -0 go away
    else
        return math.floor(x)
    end
end

RsaCrypt.cmod = function(a, b)
    local x = a % b
    if a < 0 and x > 0 then
        x = x - b
    end
    return x
end


RsaCrypt.radix = 2 ^ 24 -- maybe up to 2^26 is safe?
RsaCrypt.radix_sqrt = RsaCrypt.fl(math.sqrt(RsaCrypt.radix))

RsaCrypt.alloc = function()
    local bi = {}
    setmetatable(bi, RsaCrypt.bigintmt)
    bi.comps = {}
    bi.sign = 1;
    return bi
end

RsaCrypt.clone = function(a)
    local bi = RsaCrypt.alloc()
    bi.sign = a.sign
    local c = bi.comps
    local ac = a.comps
    for i = 1, #ac do
        c[i] = ac[i]
    end
    return bi
end

RsaCrypt.normalize = function(bi, notrunc)
    local c = bi.comps
    local v
    -- borrow for negative components
    for i = 1, #c - 1 do
        v = c[i]
        if v < 0 then
            c[i + 1] = c[i + 1] + RsaCrypt.fl(v / RsaCrypt.radix) - 1
            v = RsaCrypt.cmod(v, RsaCrypt.radix)
            if v ~= 0 then
                c[i] = v + RsaCrypt.radix
            else
                c[i] = v
                c[i + 1] = c[i + 1] + 1
            end
        end
    end
    -- is top component negative?
    if c[#c] < 0 then
        -- switch the sign and fix components
        bi.sign = -bi.sign
        for i = 1, #c - 1 do
            v = c[i]
            c[i] = RsaCrypt.radix - v
            c[i + 1] = c[i + 1] + 1
        end
        c[#c] = -c[#c]
    end
    -- carry for components larger than radix
    for i = 1, #c do
        v = c[i]
        if v > RsaCrypt.radix then
            c[i + 1] = (c[i + 1] or 0) + RsaCrypt.fl(v / RsaCrypt.radix)
            c[i] = RsaCrypt.cmod(v, RsaCrypt.radix)
        end
    end
    -- trim off leading zeros
    if not notrunc then
        for i = #c, 2, -1 do
            if c[i] == 0 then
                c[i] = nil
            else
                break
            end
        end
    end
    -- check for -0
    if #c == 1 and c[1] == 0 and bi.sign == -1 then
        bi.sign = 1
    end
end

RsaCrypt.negate = function(a)
    local bi = RsaCrypt.clone(a)
    bi.sign = -bi.sign
    return bi
end

RsaCrypt.compare = function(a, b)
    local ac, bc = a.comps, b.comps
    local as, bs = a.sign, b.sign
    if ac == bc then
        return 0
    elseif as > bs then
        return 1
    elseif as < bs then
        return -1
    elseif #ac > #bc then
        return as
    elseif #ac < #bc then
        return -as
    end
    for i = #ac, 1, -1 do
        if ac[i] > bc[i] then
            return as
        elseif ac[i] < bc[i] then
            return -as
        end
    end
    return 0
end

RsaCrypt.lt = function(a, b)
    return RsaCrypt.compare(a, b) < 0
end

RsaCrypt.eq = function(a, b)
    return RsaCrypt.compare(a, b) == 0
end

RsaCrypt.le = function(a, b)
    return RsaCrypt.compare(a, b) <= 0
end

RsaCrypt.addint = function(a, n)
    local bi = RsaCrypt.clone(a)
    if bi.sign == 1 then
        bi.comps[1] = bi.comps[1] + n
    else
        bi.comps[1] = bi.comps[1] - n
    end
    RsaCrypt.normalize(bi)
    return bi
end

RsaCrypt.add = function(a, b)
    if type(a) == "number" then
        return RsaCrypt.addint(b, a)
    elseif type(b) == "number" then
        return RsaCrypt.addint(a, b)
    end
    local bi = RsaCrypt.clone(a)
    local sign = bi.sign == b.sign
    local c = bi.comps
    for i = #c + 1, #b.comps do
        c[i] = 0
    end
    local bc = b.comps
    for i = 1, #bc do
        local v = bc[i]
        if sign then
            c[i] = c[i] + v
        else
            c[i] = c[i] - v
        end
    end
    RsaCrypt.normalize(bi)
    return bi
end

RsaCrypt.sub = function(a, b)
    if type(b) == "number" then
        return RsaCrypt.addint(a, -b)
    elseif type(a) == "number" then
        a = RsaCrypt.bigint(a)
    end
    return RsaCrypt.add(a, RsaCrypt.negate(b))
end

RsaCrypt.mulint = function(a, b)
    local bi = RsaCrypt.clone(a)
    if b < 0 then
        b = -b
        bi.sign = -bi.sign
    end
    local bc = bi.comps
    for i = 1, #bc do
        bc[i] = bc[i] * b
    end
    RsaCrypt.normalize(bi)
    return bi
end

RsaCrypt.multiply = function(a, b)
    local bi = RsaCrypt.alloc()
    local c = bi.comps
    local ac, bc = a.comps, b.comps
    for i = 1, #ac + #bc do
        c[i] = 0
    end
    for i = 1, #ac do
        for j = 1, #bc do
            c[i + j - 1] = c[i + j - 1] + ac[i] * bc[j]
        end
        -- keep the zeroes
        RsaCrypt.normalize(bi, true)
    end
    RsaCrypt.normalize(bi)
    if bi ~= RsaCrypt.bigint(0) then
        bi.sign = a.sign * b.sign
    end
    return bi
end

RsaCrypt.kmul = function(a, b)
    local ac, bc = a.comps, b.comps
    local an, bn = #a.comps, #b.comps
    local bi, bj, bk, bl = RsaCrypt.alloc(), RsaCrypt.alloc(), RsaCrypt.alloc(), RsaCrypt.alloc()
    local ic, jc, kc, lc = bi.comps, bj.comps, bk.comps, bl.comps

    local n = RsaCrypt.fl((math.max(an, bn) + 1) / 2)
    for i = 1, n do
        ic[i] = (i + n <= an) and ac[i + n] or 0
        jc[i] = (i <= an) and ac[i] or 0
        kc[i] = (i + n <= bn) and bc[i + n] or 0
        lc[i] = (i <= bn) and bc[i] or 0
    end
    RsaCrypt.normalize(bi)
    RsaCrypt.normalize(bj)
    RsaCrypt.normalize(bk)
    RsaCrypt.normalize(bl)
    local ik = bi * bk
    local jl = bj * bl
    local mid = (bi + bj) * (bk + bl) - ik - jl
    local mc = mid.comps
    local ikc = ik.comps
    local jlc = jl.comps
    for i = 1, #ikc + n * 2 do -- fill it up
        jlc[i] = jlc[i] or 0
    end
    for i = 1, #mc do
        jlc[i + n] = jlc[i + n] + mc[i]
    end
    for i = 1, #ikc do
        jlc[i + n * 2] = jlc[i + n * 2] + ikc[i]
    end
    jl.sign = a.sign * b.sign
    RsaCrypt.normalize(jl)
    return jl
end

RsaCrypt.kthresh = 12

RsaCrypt.mul = function(a, b)
    if type(a) == "number" then
        return RsaCrypt.mulint(b, a)
    elseif type(b) == "number" then
        return RsaCrypt.mulint(a, b)
    end
    if #a.comps < RsaCrypt.kthresh or #b.comps < RsaCrypt.kthresh then
        return RsaCrypt.multiply(a, b)
    end
    return RsaCrypt.kmul(a, b)
end

RsaCrypt.divint = function(numer, denom)
    local bi = RsaCrypt.clone(numer)
    if denom < 0 then
        denom = -denom
        bi.sign = -bi.sign
    end
    local r = 0
    local c = bi.comps
    for i = #c, 1, -1 do
        r = r * RsaCrypt.radix + c[i]
        c[i] = RsaCrypt.fl(r / denom)
        r = RsaCrypt.cmod(r, denom)
    end
    RsaCrypt.normalize(bi)
    return bi
end

RsaCrypt.multi_divide = function(numer, denom)
    local n = #denom.comps
    local approx = RsaCrypt.divint(numer, denom.comps[n])
    for i = n, #approx.comps do
        approx.comps[i - n + 1] = approx.comps[i]
    end
    for i = #approx.comps, #approx.comps - n + 2, -1 do
        approx.comps[i] = nil
    end
    local rem = approx * denom - numer
    local quotient
    if rem < denom then
        quotient = approx
    else
        quotient = approx - RsaCrypt.multi_divide(rem, denom)
    end
    return quotient
end

RsaCrypt.multi_divide_wrap = function(numer, denom)
    -- we use a successive approximation method, but it doesn't work
    -- if the high order component is too small.  adjust if needed.
    if denom.comps[#denom.comps] < RsaCrypt.radix_sqrt then
        numer = RsaCrypt.mulint(numer, RsaCrypt.radix_sqrt)
        denom = RsaCrypt.mulint(denom, RsaCrypt.radix_sqrt)
    end
    return RsaCrypt.multi_divide(numer, denom)
end

RsaCrypt.div = function(numer, denom)
    if type(denom) == "number" then
        if denom == 0 then
            error("divide by 0", 2)
        end
        return RsaCrypt.divint(numer, denom)
    elseif type(numer) == "number" then
        numer = RsaCrypt.bigint(numer)
    end
    -- check signs and trivial cases
    local sign = 1
    local cmp = RsaCrypt.compare(denom, RsaCrypt.bigint(0))
    if cmp == 0 then
        error("divide by 0", 2)
    elseif cmp == -1 then
        sign = -sign
        denom = RsaCrypt.negate(denom)
    end
    cmp = RsaCrypt.compare(numer, RsaCrypt.bigint(0))
    if cmp == 0 then
        return RsaCrypt.bigint(0)
    elseif cmp == -1 then
        sign = -sign
        numer = RsaCrypt.negate(numer)
    end
    cmp = RsaCrypt.compare(numer, denom)
    if cmp == -1 then
        return RsaCrypt.bigint(0)
    elseif cmp == 0 then
        return RsaCrypt.bigint(sign)
    end
    local bi
    -- if small enough, do it the easy way
    if #denom.comps == 1 then
        bi = RsaCrypt.divint(numer, denom.comps[1])
    else
        bi = RsaCrypt.multi_divide_wrap(numer, denom)
    end
    if sign == -1 then
        bi = RsaCrypt.negate(bi)
    end
    return bi
end

RsaCrypt.intrem = function(bi, m)
    if m < 0 then
        m = -m
    end
    local rad_r = 1
    local r = 0
    local bc = bi.comps
    for i = 1, #bc do
        local v = bc[i]
        r = RsaCrypt.cmod(r + v * rad_r, m)
        rad_r = RsaCrypt.cmod(rad_r * RsaCrypt.radix, m)
    end
    if bi.sign < 1 then
        r = -r
    end
    return r
end

RsaCrypt.intmod = function(bi, m)
    local r = RsaCrypt.intrem(bi, m)
    if r < 0 then
        r = r + m
    end
    return r
end

RsaCrypt.rem = function(bi, m)
    if type(m) == "number" then
        return RsaCrypt.bigint(RsaCrypt.intrem(bi, m))
    elseif type(bi) == "number" then
        bi = RsaCrypt.bigint(bi)
    end

    return bi - ((bi / m) * m)
end

RsaCrypt.mod = function(a, m)
    local bi = RsaCrypt.rem(a, m)
    if bi.sign == -1 then
        bi = bi + m
    end
    return bi
end

RsaCrypt.printscale = 10000000
RsaCrypt.printscalefmt = string.format("%%.%dd", math.log(RsaCrypt.printscale, 10))
RsaCrypt.makestr = function(bi, s)
    if bi >= RsaCrypt.bigint(RsaCrypt.printscale) then
        RsaCrypt.makestr(RsaCrypt.divint(bi, RsaCrypt.printscale), s)
    end
    table.insert(s, string.format(RsaCrypt.printscalefmt, RsaCrypt.intmod(bi, RsaCrypt.printscale)))
end

RsaCrypt.biginttostring = function(bi)
    local s = {}
    if bi < RsaCrypt.bigint(0) then
        bi = RsaCrypt.negate(bi)
        table.insert(s, "-")
    end
    RsaCrypt.makestr(bi, s)
    s = table.concat(s):gsub("^0*", "")
    if s == "" then s = "0" end
    return s
end

RsaCrypt.biginttonumber = function(bi)
    return tonumber(RsaCrypt.biginttostring(bi))
end

RsaCrypt.bigintmt = {
    __add = RsaCrypt.add,
    __sub = RsaCrypt.sub,
    __mul = RsaCrypt.mul,
    __div = RsaCrypt.div,
    __mod = RsaCrypt.mod,
    __unm = RsaCrypt.negate,
    __eq = RsaCrypt.eq,
    __lt = RsaCrypt.lt,
    __le = RsaCrypt.le,
    __tostring = RsaCrypt.biginttostring,
}

RsaCrypt.cache = {}
RsaCrypt.ncache = 0

RsaCrypt.bigint = function(n)
    if RsaCrypt.cache[n] then
        return RsaCrypt.cache[n]
    end
    local bi
    if type(n) == "string" then
        local digits = { n:byte(1, -1) }
        for i = 1, #digits do
            digits[i] = string.char(digits[i])
        end
        local start = 1
        local sign = 1
        if digits[i] == '-' then
            sign = -1
            start = 2
        end
        bi = RsaCrypt.bigint(0)
        for i = start, #digits do
            bi = RsaCrypt.addint(RsaCrypt.mulint(bi, 10), tonumber(digits[i]))
        end
        bi = RsaCrypt.mulint(bi, sign)
    else
        bi = RsaCrypt.alloc()
        bi.comps[1] = n
        RsaCrypt.normalize(bi)
    end
    if RsaCrypt.ncache > 100 then
        RsaCrypt.cache = {}
        RsaCrypt.ncache = 0
    end
    RsaCrypt.cache[n] = bi
    RsaCrypt.ncache = RsaCrypt.ncache + 1
    return bi
end

--
-- Start of my code
--

RsaCrypt.powersTwo = {
    RsaCrypt.bigint("2"),
    RsaCrypt.bigint("4"),
    RsaCrypt.bigint("8"),
    RsaCrypt.bigint("16"),
    RsaCrypt.bigint("32"),
    RsaCrypt.bigint("64"),
    RsaCrypt.bigint("128"),
    RsaCrypt.bigint("256"),
    RsaCrypt.bigint("512"),
    RsaCrypt.bigint("1024"),
    RsaCrypt.bigint("2048"),
    RsaCrypt.bigint("4096"),
    RsaCrypt.bigint("8192"),
    RsaCrypt.bigint("16384"),
    RsaCrypt.bigint("32768"),
    RsaCrypt.bigint("65536"),
    RsaCrypt.bigint("131072"),
    RsaCrypt.bigint("262144"),
    RsaCrypt.bigint("524288"),
    RsaCrypt.bigint("1048576"),
    RsaCrypt.bigint("2097152"),
    RsaCrypt.bigint("4194304"),
    RsaCrypt.bigint("8388608"),
    RsaCrypt.bigint("16777216"),
    RsaCrypt.bigint("33554432"),
    RsaCrypt.bigint("67108864"),
    RsaCrypt.bigint("134217728"),
    RsaCrypt.bigint("268435456"),
    RsaCrypt.bigint("536870912"),
    RsaCrypt.bigint("1073741824"),
    RsaCrypt.bigint("2147483648"),
    RsaCrypt.bigint("4294967296"),
    RsaCrypt.bigint("8589934592"),
    RsaCrypt.bigint("17179869184"),
    RsaCrypt.bigint("34359738368"),
    RsaCrypt.bigint("68719476736"),
    RsaCrypt.bigint("137438953472"),
    RsaCrypt.bigint("274877906944"),
    RsaCrypt.bigint("549755813888"),
    RsaCrypt.bigint("1099511627776"),
    RsaCrypt.bigint("2199023255552"),
    RsaCrypt.bigint("4398046511104"),
    RsaCrypt.bigint("8796093022208"),
    RsaCrypt.bigint("17592186044416"),
    RsaCrypt.bigint("35184372088832"),
    RsaCrypt.bigint("70368744177664"),
    RsaCrypt.bigint("140737488355328"),
    RsaCrypt.bigint("281474976710656"),
    RsaCrypt.bigint("562949953421312"),
    RsaCrypt.bigint("1125899906842624"),
    RsaCrypt.bigint("2251799813685248"),
    RsaCrypt.bigint("4503599627370496"),
    RsaCrypt.bigint("9007199254740992"),
    RsaCrypt.bigint("18014398509481984"),
    RsaCrypt.bigint("36028797018963968"),
    RsaCrypt.bigint("72057594037927936"),
    RsaCrypt.bigint("144115188075855872"),
    RsaCrypt.bigint("288230376151711744"),
    RsaCrypt.bigint("576460752303423488"),
    RsaCrypt.bigint("1152921504606846976"),
    RsaCrypt.bigint("2305843009213693952"),
    RsaCrypt.bigint("4611686018427387904"),
    RsaCrypt.bigint("9223372036854775808"),
    RsaCrypt.bigint("18446744073709551616"),
    RsaCrypt.bigint("36893488147419103232"),
    RsaCrypt.bigint("73786976294838206464"),
    RsaCrypt.bigint("147573952589676412928"),
    RsaCrypt.bigint("295147905179352825856"),
    RsaCrypt.bigint("590295810358705651712"),
    RsaCrypt.bigint("1180591620717411303424"),
    RsaCrypt.bigint("2361183241434822606848"),
    RsaCrypt.bigint("4722366482869645213696"),
    RsaCrypt.bigint("9444732965739290427392"),
    RsaCrypt.bigint("18889465931478580854784"),
    RsaCrypt.bigint("37778931862957161709568"),
    RsaCrypt.bigint("75557863725914323419136"),
    RsaCrypt.bigint("151115727451828646838272"),
    RsaCrypt.bigint("302231454903657293676544"),
    RsaCrypt.bigint("604462909807314587353088"),
    RsaCrypt.bigint("1208925819614629174706176"),
    RsaCrypt.bigint("2417851639229258349412352"),
    RsaCrypt.bigint("4835703278458516698824704"),
    RsaCrypt.bigint("9671406556917033397649408"),
    RsaCrypt.bigint("19342813113834066795298816"),
    RsaCrypt.bigint("38685626227668133590597632"),
    RsaCrypt.bigint("77371252455336267181195264"),
    RsaCrypt.bigint("154742504910672534362390528"),
    RsaCrypt.bigint("309485009821345068724781056"),
    RsaCrypt.bigint("618970019642690137449562112"),
    RsaCrypt.bigint("1237940039285380274899124224"),
    RsaCrypt.bigint("2475880078570760549798248448"),
    RsaCrypt.bigint("4951760157141521099596496896"),
    RsaCrypt.bigint("9903520314283042199192993792"),
    RsaCrypt.bigint("19807040628566084398385987584"),
    RsaCrypt.bigint("39614081257132168796771975168"),
    RsaCrypt.bigint("79228162514264337593543950336"),
    RsaCrypt.bigint("158456325028528675187087900672"),
    RsaCrypt.bigint("316912650057057350374175801344"),
    RsaCrypt.bigint("633825300114114700748351602688"),
    RsaCrypt.bigint("1267650600228229401496703205376"),
    RsaCrypt.bigint("2535301200456458802993406410752"),
    RsaCrypt.bigint("5070602400912917605986812821504"),
    RsaCrypt.bigint("10141204801825835211973625643008"),
    RsaCrypt.bigint("20282409603651670423947251286016"),
    RsaCrypt.bigint("40564819207303340847894502572032"),
    RsaCrypt.bigint("81129638414606681695789005144064"),
    RsaCrypt.bigint("162259276829213363391578010288128"),
    RsaCrypt.bigint("324518553658426726783156020576256"),
    RsaCrypt.bigint("649037107316853453566312041152512"),
    RsaCrypt.bigint("1298074214633706907132624082305024"),
    RsaCrypt.bigint("2596148429267413814265248164610048"),
    RsaCrypt.bigint("5192296858534827628530496329220096"),
    RsaCrypt.bigint("10384593717069655257060992658440192"),
    RsaCrypt.bigint("20769187434139310514121985316880384"),
    RsaCrypt.bigint("41538374868278621028243970633760768"),
    RsaCrypt.bigint("83076749736557242056487941267521536"),
    RsaCrypt.bigint("166153499473114484112975882535043072"),
    RsaCrypt.bigint("332306998946228968225951765070086144"),
    RsaCrypt.bigint("664613997892457936451903530140172288"),
    RsaCrypt.bigint("1329227995784915872903807060280344576"),
    RsaCrypt.bigint("2658455991569831745807614120560689152"),
    RsaCrypt.bigint("5316911983139663491615228241121378304"),
    RsaCrypt.bigint("10633823966279326983230456482242756608"),
    RsaCrypt.bigint("21267647932558653966460912964485513216"),
    RsaCrypt.bigint("42535295865117307932921825928971026432"),
    RsaCrypt.bigint("85070591730234615865843651857942052864"),
    RsaCrypt.bigint("170141183460469231731687303715884105728"),
    RsaCrypt.bigint("340282366920938463463374607431768211456"),
    RsaCrypt.bigint("680564733841876926926749214863536422912"),
    RsaCrypt.bigint("1361129467683753853853498429727072845824"),
    RsaCrypt.bigint("2722258935367507707706996859454145691648"),
    RsaCrypt.bigint("5444517870735015415413993718908291383296"),
    RsaCrypt.bigint("10889035741470030830827987437816582766592"),
    RsaCrypt.bigint("21778071482940061661655974875633165533184"),
    RsaCrypt.bigint("43556142965880123323311949751266331066368"),
    RsaCrypt.bigint("87112285931760246646623899502532662132736"),
    RsaCrypt.bigint("174224571863520493293247799005065324265472"),
    RsaCrypt.bigint("348449143727040986586495598010130648530944"),
    RsaCrypt.bigint("696898287454081973172991196020261297061888"),
    RsaCrypt.bigint("1393796574908163946345982392040522594123776"),
    RsaCrypt.bigint("2787593149816327892691964784081045188247552"),
    RsaCrypt.bigint("5575186299632655785383929568162090376495104"),
    RsaCrypt.bigint("11150372599265311570767859136324180752990208"),
    RsaCrypt.bigint("22300745198530623141535718272648361505980416"),
    RsaCrypt.bigint("44601490397061246283071436545296723011960832"),
    RsaCrypt.bigint("89202980794122492566142873090593446023921664"),
    RsaCrypt.bigint("178405961588244985132285746181186892047843328"),
    RsaCrypt.bigint("356811923176489970264571492362373784095686656"),
    RsaCrypt.bigint("713623846352979940529142984724747568191373312"),
    RsaCrypt.bigint("1427247692705959881058285969449495136382746624"),
    RsaCrypt.bigint("2854495385411919762116571938898990272765493248"),
    RsaCrypt.bigint("5708990770823839524233143877797980545530986496"),
    RsaCrypt.bigint("11417981541647679048466287755595961091061972992"),
    RsaCrypt.bigint("22835963083295358096932575511191922182123945984"),
    RsaCrypt.bigint("45671926166590716193865151022383844364247891968"),
    RsaCrypt.bigint("91343852333181432387730302044767688728495783936"),
    RsaCrypt.bigint("182687704666362864775460604089535377456991567872"),
    RsaCrypt.bigint("365375409332725729550921208179070754913983135744"),
    RsaCrypt.bigint("730750818665451459101842416358141509827966271488"),
    RsaCrypt.bigint("1461501637330902918203684832716283019655932542976"),
    RsaCrypt.bigint("2923003274661805836407369665432566039311865085952"),
    RsaCrypt.bigint("5846006549323611672814739330865132078623730171904"),
    RsaCrypt.bigint("11692013098647223345629478661730264157247460343808"),
    RsaCrypt.bigint("23384026197294446691258957323460528314494920687616"),
    RsaCrypt.bigint("46768052394588893382517914646921056628989841375232"),
    RsaCrypt.bigint("93536104789177786765035829293842113257979682750464"),
    RsaCrypt.bigint("187072209578355573530071658587684226515959365500928"),
    RsaCrypt.bigint("374144419156711147060143317175368453031918731001856"),
    RsaCrypt.bigint("748288838313422294120286634350736906063837462003712"),
    RsaCrypt.bigint("1496577676626844588240573268701473812127674924007424"),
    RsaCrypt.bigint("2993155353253689176481146537402947624255349848014848"),
    RsaCrypt.bigint("5986310706507378352962293074805895248510699696029696"),
    RsaCrypt.bigint("11972621413014756705924586149611790497021399392059392"),
    RsaCrypt.bigint("23945242826029513411849172299223580994042798784118784"),
    RsaCrypt.bigint("47890485652059026823698344598447161988085597568237568"),
    RsaCrypt.bigint("95780971304118053647396689196894323976171195136475136"),
    RsaCrypt.bigint("191561942608236107294793378393788647952342390272950272"),
    RsaCrypt.bigint("383123885216472214589586756787577295904684780545900544"),
    RsaCrypt.bigint("766247770432944429179173513575154591809369561091801088"),
    RsaCrypt.bigint("1532495540865888858358347027150309183618739122183602176"),
    RsaCrypt.bigint("3064991081731777716716694054300618367237478244367204352"),
    RsaCrypt.bigint("6129982163463555433433388108601236734474956488734408704"),
    RsaCrypt.bigint("12259964326927110866866776217202473468949912977468817408"),
    RsaCrypt.bigint("24519928653854221733733552434404946937899825954937634816"),
    RsaCrypt.bigint("49039857307708443467467104868809893875799651909875269632"),
    RsaCrypt.bigint("98079714615416886934934209737619787751599303819750539264"),
    RsaCrypt.bigint("196159429230833773869868419475239575503198607639501078528"),
    RsaCrypt.bigint("392318858461667547739736838950479151006397215279002157056"),
    RsaCrypt.bigint("784637716923335095479473677900958302012794430558004314112"),
    RsaCrypt.bigint("1569275433846670190958947355801916604025588861116008628224"),
    RsaCrypt.bigint("3138550867693340381917894711603833208051177722232017256448"),
    RsaCrypt.bigint("6277101735386680763835789423207666416102355444464034512896"),
    RsaCrypt.bigint("12554203470773361527671578846415332832204710888928069025792"),
    RsaCrypt.bigint("25108406941546723055343157692830665664409421777856138051584"),
    RsaCrypt.bigint("50216813883093446110686315385661331328818843555712276103168"),
    RsaCrypt.bigint("100433627766186892221372630771322662657637687111424552206336"),
    RsaCrypt.bigint("200867255532373784442745261542645325315275374222849104412672"),
    RsaCrypt.bigint("401734511064747568885490523085290650630550748445698208825344"),
    RsaCrypt.bigint("803469022129495137770981046170581301261101496891396417650688"),
    RsaCrypt.bigint("1606938044258990275541962092341162602522202993782792835301376"),
    RsaCrypt.bigint("3213876088517980551083924184682325205044405987565585670602752"),
    RsaCrypt.bigint("6427752177035961102167848369364650410088811975131171341205504"),
    RsaCrypt.bigint("12855504354071922204335696738729300820177623950262342682411008"),
    RsaCrypt.bigint("25711008708143844408671393477458601640355247900524685364822016"),
    RsaCrypt.bigint("51422017416287688817342786954917203280710495801049370729644032"),
    RsaCrypt.bigint("102844034832575377634685573909834406561420991602098741459288064"),
    RsaCrypt.bigint("205688069665150755269371147819668813122841983204197482918576128"),
    RsaCrypt.bigint("411376139330301510538742295639337626245683966408394965837152256"),
    RsaCrypt.bigint("822752278660603021077484591278675252491367932816789931674304512"),
    RsaCrypt.bigint("1645504557321206042154969182557350504982735865633579863348609024"),
    RsaCrypt.bigint("3291009114642412084309938365114701009965471731267159726697218048"),
    RsaCrypt.bigint("6582018229284824168619876730229402019930943462534319453394436096"),
    RsaCrypt.bigint("13164036458569648337239753460458804039861886925068638906788872192"),
    RsaCrypt.bigint("26328072917139296674479506920917608079723773850137277813577744384"),
    RsaCrypt.bigint("52656145834278593348959013841835216159447547700274555627155488768"),
    RsaCrypt.bigint("105312291668557186697918027683670432318895095400549111254310977536"),
    RsaCrypt.bigint("210624583337114373395836055367340864637790190801098222508621955072"),
    RsaCrypt.bigint("421249166674228746791672110734681729275580381602196445017243910144"),
    RsaCrypt.bigint("842498333348457493583344221469363458551160763204392890034487820288"),
    RsaCrypt.bigint("1684996666696914987166688442938726917102321526408785780068975640576"),
    RsaCrypt.bigint("3369993333393829974333376885877453834204643052817571560137951281152"),
    RsaCrypt.bigint("6739986666787659948666753771754907668409286105635143120275902562304"),
    RsaCrypt.bigint("13479973333575319897333507543509815336818572211270286240551805124608"),
    RsaCrypt.bigint("26959946667150639794667015087019630673637144422540572481103610249216"),
    RsaCrypt.bigint("53919893334301279589334030174039261347274288845081144962207220498432"),
    RsaCrypt.bigint("107839786668602559178668060348078522694548577690162289924414440996864"),
    RsaCrypt.bigint("215679573337205118357336120696157045389097155380324579848828881993728"),
    RsaCrypt.bigint("431359146674410236714672241392314090778194310760649159697657763987456"),
    RsaCrypt.bigint("862718293348820473429344482784628181556388621521298319395315527974912"),
    RsaCrypt.bigint("1725436586697640946858688965569256363112777243042596638790631055949824"),
    RsaCrypt.bigint("3450873173395281893717377931138512726225554486085193277581262111899648"),
    RsaCrypt.bigint("6901746346790563787434755862277025452451108972170386555162524223799296"),
    RsaCrypt.bigint("13803492693581127574869511724554050904902217944340773110325048447598592"),
    RsaCrypt.bigint("27606985387162255149739023449108101809804435888681546220650096895197184"),
    RsaCrypt.bigint("55213970774324510299478046898216203619608871777363092441300193790394368"),
    RsaCrypt.bigint("110427941548649020598956093796432407239217743554726184882600387580788736"),
    RsaCrypt.bigint("220855883097298041197912187592864814478435487109452369765200775161577472"),
    RsaCrypt.bigint("441711766194596082395824375185729628956870974218904739530401550323154944"),
    RsaCrypt.bigint("883423532389192164791648750371459257913741948437809479060803100646309888"),
    RsaCrypt.bigint("1766847064778384329583297500742918515827483896875618958121606201292619776"),
    RsaCrypt.bigint("3533694129556768659166595001485837031654967793751237916243212402585239552"),
    RsaCrypt.bigint("7067388259113537318333190002971674063309935587502475832486424805170479104"),
    RsaCrypt.bigint("14134776518227074636666380005943348126619871175004951664972849610340958208"),
    RsaCrypt.bigint("28269553036454149273332760011886696253239742350009903329945699220681916416"),
    RsaCrypt.bigint("56539106072908298546665520023773392506479484700019806659891398441363832832"),
    RsaCrypt.bigint("113078212145816597093331040047546785012958969400039613319782796882727665664"),
    RsaCrypt.bigint("226156424291633194186662080095093570025917938800079226639565593765455331328"),
    RsaCrypt.bigint("452312848583266388373324160190187140051835877600158453279131187530910662656"),
    RsaCrypt.bigint("904625697166532776746648320380374280103671755200316906558262375061821325312"),
    RsaCrypt.bigint("1809251394333065553493296640760748560207343510400633813116524750123642650624"),
    RsaCrypt.bigint("3618502788666131106986593281521497120414687020801267626233049500247285301248"),
    RsaCrypt.bigint("7237005577332262213973186563042994240829374041602535252466099000494570602496"),
    RsaCrypt.bigint("14474011154664524427946373126085988481658748083205070504932198000989141204992"),
    RsaCrypt.bigint("28948022309329048855892746252171976963317496166410141009864396001978282409984"),
    RsaCrypt.bigint("57896044618658097711785492504343953926634992332820282019728792003956564819968"),
    RsaCrypt.bigint("115792089237316195423570985008687907853269984665640564039457584007913129639936"),
}

RsaCrypt.powersTwo[0] = RsaCrypt.bigint("1")

RsaCrypt.bigZero = RsaCrypt.bigint(0)
RsaCrypt.bigOne = RsaCrypt.bigint(1)

RsaCrypt.numberToBytes = function(num, bits, byteSize)
    if bits > #RsaCrypt.powersTwo then
        error("Too many bits. Must be <= " .. #RsaCrypt.powersTwo .. ".")
    end

    num = RsaCrypt.bigint(num)

    local resultBits = {}
    resultBits[1] = {}
    for i = bits - 1, 0, -1 do
        local expVal = RsaCrypt.powersTwo[i]
        local resultant = num - expVal
        if expVal <= resultant then
            -- Invalid data!
            return nil
        end

        if resultant < RsaCrypt.bigZero then
            -- A zero bit
            if #(resultBits[#resultBits]) >= byteSize then
                table.insert(resultBits, { 0 })
            else
                table.insert(resultBits[#resultBits], 0)
            end
        else
            -- A one bit
            num = resultant
            if #(resultBits[#resultBits]) >= byteSize then
                table.insert(resultBits, { 1 })
            else
                table.insert(resultBits[#resultBits], 1)
            end
        end

        if num == RsaCrypt.bigint(0) then
            break
        end
    end

    local results = {}
    for _, binarySeq in pairs(resultBits) do
        local thisResult = 0
        for k, bin in pairs(binarySeq) do
            if bin == 1 then
                thisResult = thisResult + 2 ^ (byteSize - k)
            end
        end
        table.insert(results, thisResult)
    end

    return results
end

RsaCrypt.bytesToNumber = function(bytes, bits, byteSize)
    if bits > #RsaCrypt.powersTwo then
        error("Too many bits. Must be <= " .. #RsaCrypt.powersTwo .. ".")
    end

    if #bytes > bits / byteSize then
        error("Too many bytes to store into the number of bits available. Must be <= " ..
            bits / byteSize .. ".")
    end

    local binary = {}
    for _, byte in pairs(bytes) do
        for i = byteSize - 1, 0, -1 do
            if byte - (2 ^ i) < 0 then
                table.insert(binary, 0)
            else
                table.insert(binary, 1)
                byte = byte - (2 ^ i)
            end
        end
    end

    local num = RsaCrypt.bigint(0)
    for i = 1, #binary do
        if binary[i] == 1 then
            num = num + RsaCrypt.powersTwo[bits - i]
        end
    end

    return tostring(num)
end

RsaCrypt.encodeBigNumbers = function(numbers)
    for k, v in pairs(numbers) do
        numbers[k] = tostring(v)
    end
    return numbers
end

RsaCrypt.stringToBytes = function(str)
    local result = {}
    for i = 1, #str do
        table.insert(result, string.byte(str, i))
    end
    return result
end

RsaCrypt.bytesToString = function(bytes)
    local str = ""
    for _, v in pairs(bytes) do
        str = str .. string.char(v)
    end
    return str
end

RsaCrypt.modexp = function(base, exponent, modulus)
    local r = 1

    while true do
        if exponent % 2 == RsaCrypt.bigOne then
            r = r * base % modulus
        end
        exponent = exponent / 2

        if exponent == RsaCrypt.bigZero then
            break
        end
        base = base * base % modulus
    end

    return r
end

RsaCrypt.crypt = function(key, number)
    local exp
    if key.public then
        exp = RsaCrypt.bigint(key.public)
    else
        exp = RsaCrypt.bigint(key.private)
    end

    return tostring(RsaCrypt.modexp(RsaCrypt.bigint(number), exp, RsaCrypt.bigint(key.shared)))
end

return RsaCrypt
