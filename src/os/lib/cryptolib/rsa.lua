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

local Package = {}

--
-- Start of third-party libraries/helpers
--

-- two functions to help make Lua act more like C
Package.fl = function(x)
    if x < 0 then
        return math.ceil(x) + 0 -- make -0 go away
    else
        return math.floor(x)
    end
end

Package.cmod = function(a, b)
    local x = a % b
    if a < 0 and x > 0 then
        x = x - b
    end
    return x
end


Package.radix = 2 ^ 24 -- maybe up to 2^26 is safe?
Package.radix_sqrt = Package.fl(math.sqrt(Package.radix))

Package.alloc = function()
    local bi = {}
    setmetatable(bi, Package.bigintmt)
    bi.comps = {}
    bi.sign = 1;
    return bi
end

Package.clone = function(a)
    local bi = Package.alloc()
    bi.sign = a.sign
    local c = bi.comps
    local ac = a.comps
    for i = 1, #ac do
        c[i] = ac[i]
    end
    return bi
end

Package.normalize = function(bi, notrunc)
    local c = bi.comps
    local v
    -- borrow for negative components
    for i = 1, #c - 1 do
        v = c[i]
        if v < 0 then
            c[i + 1] = c[i + 1] + Package.fl(v / Package.radix) - 1
            v = Package.cmod(v, Package.radix)
            if v ~= 0 then
                c[i] = v + Package.radix
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
            c[i] = Package.radix - v
            c[i + 1] = c[i + 1] + 1
        end
        c[#c] = -c[#c]
    end
    -- carry for components larger than radix
    for i = 1, #c do
        v = c[i]
        if v > Package.radix then
            c[i + 1] = (c[i + 1] or 0) + Package.fl(v / Package.radix)
            c[i] = Package.cmod(v, Package.radix)
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

Package.negate = function(a)
    local bi = Package.clone(a)
    bi.sign = -bi.sign
    return bi
end

Package.compare = function(a, b)
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

Package.lt = function(a, b)
    return Package.compare(a, b) < 0
end

Package.eq = function(a, b)
    return Package.compare(a, b) == 0
end

Package.le = function(a, b)
    return Package.compare(a, b) <= 0
end

Package.addint = function(a, n)
    local bi = Package.clone(a)
    if bi.sign == 1 then
        bi.comps[1] = bi.comps[1] + n
    else
        bi.comps[1] = bi.comps[1] - n
    end
    Package.normalize(bi)
    return bi
end

Package.add = function(a, b)
    if type(a) == "number" then
        return Package.addint(b, a)
    elseif type(b) == "number" then
        return Package.addint(a, b)
    end
    local bi = Package.clone(a)
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
    Package.normalize(bi)
    return bi
end

Package.sub = function(a, b)
    if type(b) == "number" then
        return Package.addint(a, -b)
    elseif type(a) == "number" then
        a = Package.bigint(a)
    end
    return Package.add(a, Package.negate(b))
end

Package.mulint = function(a, b)
    local bi = Package.clone(a)
    if b < 0 then
        b = -b
        bi.sign = -bi.sign
    end
    local bc = bi.comps
    for i = 1, #bc do
        bc[i] = bc[i] * b
    end
    Package.normalize(bi)
    return bi
end

Package.multiply = function(a, b)
    local bi = Package.alloc()
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
        Package.normalize(bi, true)
    end
    Package.normalize(bi)
    if bi ~= Package.bigint(0) then
        bi.sign = a.sign * b.sign
    end
    return bi
end

Package.kmul = function(a, b)
    local ac, bc = a.comps, b.comps
    local an, bn = #a.comps, #b.comps
    local bi, bj, bk, bl = Package.alloc(), Package.alloc(), Package.alloc(), Package.alloc()
    local ic, jc, kc, lc = bi.comps, bj.comps, bk.comps, bl.comps

    local n = Package.fl((math.max(an, bn) + 1) / 2)
    for i = 1, n do
        ic[i] = (i + n <= an) and ac[i + n] or 0
        jc[i] = (i <= an) and ac[i] or 0
        kc[i] = (i + n <= bn) and bc[i + n] or 0
        lc[i] = (i <= bn) and bc[i] or 0
    end
    Package.normalize(bi)
    Package.normalize(bj)
    Package.normalize(bk)
    Package.normalize(bl)
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
    Package.normalize(jl)
    return jl
end

Package.kthresh = 12

Package.mul = function(a, b)
    if type(a) == "number" then
        return Package.mulint(b, a)
    elseif type(b) == "number" then
        return Package.mulint(a, b)
    end
    if #a.comps < Package.kthresh or #b.comps < Package.kthresh then
        return Package.multiply(a, b)
    end
    return Package.kmul(a, b)
end

Package.divint = function(numer, denom)
    local bi = Package.clone(numer)
    if denom < 0 then
        denom = -denom
        bi.sign = -bi.sign
    end
    local r = 0
    local c = bi.comps
    for i = #c, 1, -1 do
        r = r * Package.radix + c[i]
        c[i] = Package.fl(r / denom)
        r = Package.cmod(r, denom)
    end
    Package.normalize(bi)
    return bi
end

Package.multi_divide = function(numer, denom)
    local n = #denom.comps
    local approx = Package.divint(numer, denom.comps[n])
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
        quotient = approx - Package.multi_divide(rem, denom)
    end
    return quotient
end

Package.multi_divide_wrap = function(numer, denom)
    -- we use a successive approximation method, but it doesn't work
    -- if the high order component is too small.  adjust if needed.
    if denom.comps[#denom.comps] < Package.radix_sqrt then
        numer = Package.mulint(numer, Package.radix_sqrt)
        denom = Package.mulint(denom, Package.radix_sqrt)
    end
    return Package.multi_divide(numer, denom)
end

Package.div = function(numer, denom)
    if type(denom) == "number" then
        if denom == 0 then
            error("divide by 0", 2)
        end
        return Package.divint(numer, denom)
    elseif type(numer) == "number" then
        numer = Package.bigint(numer)
    end
    -- check signs and trivial cases
    local sign = 1
    local cmp = Package.compare(denom, Package.bigint(0))
    if cmp == 0 then
        error("divide by 0", 2)
    elseif cmp == -1 then
        sign = -sign
        denom = Package.negate(denom)
    end
    cmp = Package.compare(numer, Package.bigint(0))
    if cmp == 0 then
        return Package.bigint(0)
    elseif cmp == -1 then
        sign = -sign
        numer = Package.negate(numer)
    end
    cmp = Package.compare(numer, denom)
    if cmp == -1 then
        return Package.bigint(0)
    elseif cmp == 0 then
        return Package.bigint(sign)
    end
    local bi
    -- if small enough, do it the easy way
    if #denom.comps == 1 then
        bi = Package.divint(numer, denom.comps[1])
    else
        bi = Package.multi_divide_wrap(numer, denom)
    end
    if sign == -1 then
        bi = Package.negate(bi)
    end
    return bi
end

Package.intrem = function(bi, m)
    if m < 0 then
        m = -m
    end
    local rad_r = 1
    local r = 0
    local bc = bi.comps
    for i = 1, #bc do
        local v = bc[i]
        r = Package.cmod(r + v * rad_r, m)
        rad_r = Package.cmod(rad_r * Package.radix, m)
    end
    if bi.sign < 1 then
        r = -r
    end
    return r
end

Package.intmod = function(bi, m)
    local r = Package.intrem(bi, m)
    if r < 0 then
        r = r + m
    end
    return r
end

Package.rem = function(bi, m)
    if type(m) == "number" then
        return Package.bigint(Package.intrem(bi, m))
    elseif type(bi) == "number" then
        bi = Package.bigint(bi)
    end

    return bi - ((bi / m) * m)
end

Package.mod = function(a, m)
    local bi = Package.rem(a, m)
    if bi.sign == -1 then
        bi = bi + m
    end
    return bi
end

Package.printscale = 10000000
Package.printscalefmt = string.format("%%.%dd", math.log(Package.printscale, 10))
Package.makestr = function(bi, s)
    if bi >= Package.bigint(Package.printscale) then
        Package.makestr(Package.divint(bi, Package.printscale), s)
    end
    table.insert(s, string.format(Package.printscalefmt, Package.intmod(bi, Package.printscale)))
end

Package.biginttostring = function(bi)
    local s = {}
    if bi < Package.bigint(0) then
        bi = Package.negate(bi)
        table.insert(s, "-")
    end
    Package.makestr(bi, s)
    s = table.concat(s):gsub("^0*", "")
    if s == "" then s = "0" end
    return s
end

Package.biginttonumber = function(bi)
    return tonumber(Package.biginttostring(bi))
end

Package.bigintmt = {
    __add = Package.add,
    __sub = Package.sub,
    __mul = Package.mul,
    __div = Package.div,
    __mod = Package.mod,
    __unm = Package.negate,
    __eq = Package.eq,
    __lt = Package.lt,
    __le = Package.le,
    __tostring = Package.biginttostring,
}

Package.cache = {}
Package.ncache = 0

Package.bigint = function(n)
    if Package.cache[n] then
        return Package.cache[n]
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
        bi = Package.bigint(0)
        for i = start, #digits do
            bi = Package.addint(Package.mulint(bi, 10), tonumber(digits[i]))
        end
        bi = Package.mulint(bi, sign)
    else
        bi = Package.alloc()
        bi.comps[1] = n
        Package.normalize(bi)
    end
    if Package.ncache > 100 then
        Package.cache = {}
        Package.ncache = 0
    end
    Package.cache[n] = bi
    Package.ncache = Package.ncache + 1
    return bi
end

--
-- Start of my code
--

Package.powers_two = {
    Package.bigint("2"),
    Package.bigint("4"),
    Package.bigint("8"),
    Package.bigint("16"),
    Package.bigint("32"),
    Package.bigint("64"),
    Package.bigint("128"),
    Package.bigint("256"),
    Package.bigint("512"),
    Package.bigint("1024"),
    Package.bigint("2048"),
    Package.bigint("4096"),
    Package.bigint("8192"),
    Package.bigint("16384"),
    Package.bigint("32768"),
    Package.bigint("65536"),
    Package.bigint("131072"),
    Package.bigint("262144"),
    Package.bigint("524288"),
    Package.bigint("1048576"),
    Package.bigint("2097152"),
    Package.bigint("4194304"),
    Package.bigint("8388608"),
    Package.bigint("16777216"),
    Package.bigint("33554432"),
    Package.bigint("67108864"),
    Package.bigint("134217728"),
    Package.bigint("268435456"),
    Package.bigint("536870912"),
    Package.bigint("1073741824"),
    Package.bigint("2147483648"),
    Package.bigint("4294967296"),
    Package.bigint("8589934592"),
    Package.bigint("17179869184"),
    Package.bigint("34359738368"),
    Package.bigint("68719476736"),
    Package.bigint("137438953472"),
    Package.bigint("274877906944"),
    Package.bigint("549755813888"),
    Package.bigint("1099511627776"),
    Package.bigint("2199023255552"),
    Package.bigint("4398046511104"),
    Package.bigint("8796093022208"),
    Package.bigint("17592186044416"),
    Package.bigint("35184372088832"),
    Package.bigint("70368744177664"),
    Package.bigint("140737488355328"),
    Package.bigint("281474976710656"),
    Package.bigint("562949953421312"),
    Package.bigint("1125899906842624"),
    Package.bigint("2251799813685248"),
    Package.bigint("4503599627370496"),
    Package.bigint("9007199254740992"),
    Package.bigint("18014398509481984"),
    Package.bigint("36028797018963968"),
    Package.bigint("72057594037927936"),
    Package.bigint("144115188075855872"),
    Package.bigint("288230376151711744"),
    Package.bigint("576460752303423488"),
    Package.bigint("1152921504606846976"),
    Package.bigint("2305843009213693952"),
    Package.bigint("4611686018427387904"),
    Package.bigint("9223372036854775808"),
    Package.bigint("18446744073709551616"),
    Package.bigint("36893488147419103232"),
    Package.bigint("73786976294838206464"),
    Package.bigint("147573952589676412928"),
    Package.bigint("295147905179352825856"),
    Package.bigint("590295810358705651712"),
    Package.bigint("1180591620717411303424"),
    Package.bigint("2361183241434822606848"),
    Package.bigint("4722366482869645213696"),
    Package.bigint("9444732965739290427392"),
    Package.bigint("18889465931478580854784"),
    Package.bigint("37778931862957161709568"),
    Package.bigint("75557863725914323419136"),
    Package.bigint("151115727451828646838272"),
    Package.bigint("302231454903657293676544"),
    Package.bigint("604462909807314587353088"),
    Package.bigint("1208925819614629174706176"),
    Package.bigint("2417851639229258349412352"),
    Package.bigint("4835703278458516698824704"),
    Package.bigint("9671406556917033397649408"),
    Package.bigint("19342813113834066795298816"),
    Package.bigint("38685626227668133590597632"),
    Package.bigint("77371252455336267181195264"),
    Package.bigint("154742504910672534362390528"),
    Package.bigint("309485009821345068724781056"),
    Package.bigint("618970019642690137449562112"),
    Package.bigint("1237940039285380274899124224"),
    Package.bigint("2475880078570760549798248448"),
    Package.bigint("4951760157141521099596496896"),
    Package.bigint("9903520314283042199192993792"),
    Package.bigint("19807040628566084398385987584"),
    Package.bigint("39614081257132168796771975168"),
    Package.bigint("79228162514264337593543950336"),
    Package.bigint("158456325028528675187087900672"),
    Package.bigint("316912650057057350374175801344"),
    Package.bigint("633825300114114700748351602688"),
    Package.bigint("1267650600228229401496703205376"),
    Package.bigint("2535301200456458802993406410752"),
    Package.bigint("5070602400912917605986812821504"),
    Package.bigint("10141204801825835211973625643008"),
    Package.bigint("20282409603651670423947251286016"),
    Package.bigint("40564819207303340847894502572032"),
    Package.bigint("81129638414606681695789005144064"),
    Package.bigint("162259276829213363391578010288128"),
    Package.bigint("324518553658426726783156020576256"),
    Package.bigint("649037107316853453566312041152512"),
    Package.bigint("1298074214633706907132624082305024"),
    Package.bigint("2596148429267413814265248164610048"),
    Package.bigint("5192296858534827628530496329220096"),
    Package.bigint("10384593717069655257060992658440192"),
    Package.bigint("20769187434139310514121985316880384"),
    Package.bigint("41538374868278621028243970633760768"),
    Package.bigint("83076749736557242056487941267521536"),
    Package.bigint("166153499473114484112975882535043072"),
    Package.bigint("332306998946228968225951765070086144"),
    Package.bigint("664613997892457936451903530140172288"),
    Package.bigint("1329227995784915872903807060280344576"),
    Package.bigint("2658455991569831745807614120560689152"),
    Package.bigint("5316911983139663491615228241121378304"),
    Package.bigint("10633823966279326983230456482242756608"),
    Package.bigint("21267647932558653966460912964485513216"),
    Package.bigint("42535295865117307932921825928971026432"),
    Package.bigint("85070591730234615865843651857942052864"),
    Package.bigint("170141183460469231731687303715884105728"),
    Package.bigint("340282366920938463463374607431768211456"),
    Package.bigint("680564733841876926926749214863536422912"),
    Package.bigint("1361129467683753853853498429727072845824"),
    Package.bigint("2722258935367507707706996859454145691648"),
    Package.bigint("5444517870735015415413993718908291383296"),
    Package.bigint("10889035741470030830827987437816582766592"),
    Package.bigint("21778071482940061661655974875633165533184"),
    Package.bigint("43556142965880123323311949751266331066368"),
    Package.bigint("87112285931760246646623899502532662132736"),
    Package.bigint("174224571863520493293247799005065324265472"),
    Package.bigint("348449143727040986586495598010130648530944"),
    Package.bigint("696898287454081973172991196020261297061888"),
    Package.bigint("1393796574908163946345982392040522594123776"),
    Package.bigint("2787593149816327892691964784081045188247552"),
    Package.bigint("5575186299632655785383929568162090376495104"),
    Package.bigint("11150372599265311570767859136324180752990208"),
    Package.bigint("22300745198530623141535718272648361505980416"),
    Package.bigint("44601490397061246283071436545296723011960832"),
    Package.bigint("89202980794122492566142873090593446023921664"),
    Package.bigint("178405961588244985132285746181186892047843328"),
    Package.bigint("356811923176489970264571492362373784095686656"),
    Package.bigint("713623846352979940529142984724747568191373312"),
    Package.bigint("1427247692705959881058285969449495136382746624"),
    Package.bigint("2854495385411919762116571938898990272765493248"),
    Package.bigint("5708990770823839524233143877797980545530986496"),
    Package.bigint("11417981541647679048466287755595961091061972992"),
    Package.bigint("22835963083295358096932575511191922182123945984"),
    Package.bigint("45671926166590716193865151022383844364247891968"),
    Package.bigint("91343852333181432387730302044767688728495783936"),
    Package.bigint("182687704666362864775460604089535377456991567872"),
    Package.bigint("365375409332725729550921208179070754913983135744"),
    Package.bigint("730750818665451459101842416358141509827966271488"),
    Package.bigint("1461501637330902918203684832716283019655932542976"),
    Package.bigint("2923003274661805836407369665432566039311865085952"),
    Package.bigint("5846006549323611672814739330865132078623730171904"),
    Package.bigint("11692013098647223345629478661730264157247460343808"),
    Package.bigint("23384026197294446691258957323460528314494920687616"),
    Package.bigint("46768052394588893382517914646921056628989841375232"),
    Package.bigint("93536104789177786765035829293842113257979682750464"),
    Package.bigint("187072209578355573530071658587684226515959365500928"),
    Package.bigint("374144419156711147060143317175368453031918731001856"),
    Package.bigint("748288838313422294120286634350736906063837462003712"),
    Package.bigint("1496577676626844588240573268701473812127674924007424"),
    Package.bigint("2993155353253689176481146537402947624255349848014848"),
    Package.bigint("5986310706507378352962293074805895248510699696029696"),
    Package.bigint("11972621413014756705924586149611790497021399392059392"),
    Package.bigint("23945242826029513411849172299223580994042798784118784"),
    Package.bigint("47890485652059026823698344598447161988085597568237568"),
    Package.bigint("95780971304118053647396689196894323976171195136475136"),
    Package.bigint("191561942608236107294793378393788647952342390272950272"),
    Package.bigint("383123885216472214589586756787577295904684780545900544"),
    Package.bigint("766247770432944429179173513575154591809369561091801088"),
    Package.bigint("1532495540865888858358347027150309183618739122183602176"),
    Package.bigint("3064991081731777716716694054300618367237478244367204352"),
    Package.bigint("6129982163463555433433388108601236734474956488734408704"),
    Package.bigint("12259964326927110866866776217202473468949912977468817408"),
    Package.bigint("24519928653854221733733552434404946937899825954937634816"),
    Package.bigint("49039857307708443467467104868809893875799651909875269632"),
    Package.bigint("98079714615416886934934209737619787751599303819750539264"),
    Package.bigint("196159429230833773869868419475239575503198607639501078528"),
    Package.bigint("392318858461667547739736838950479151006397215279002157056"),
    Package.bigint("784637716923335095479473677900958302012794430558004314112"),
    Package.bigint("1569275433846670190958947355801916604025588861116008628224"),
    Package.bigint("3138550867693340381917894711603833208051177722232017256448"),
    Package.bigint("6277101735386680763835789423207666416102355444464034512896"),
    Package.bigint("12554203470773361527671578846415332832204710888928069025792"),
    Package.bigint("25108406941546723055343157692830665664409421777856138051584"),
    Package.bigint("50216813883093446110686315385661331328818843555712276103168"),
    Package.bigint("100433627766186892221372630771322662657637687111424552206336"),
    Package.bigint("200867255532373784442745261542645325315275374222849104412672"),
    Package.bigint("401734511064747568885490523085290650630550748445698208825344"),
    Package.bigint("803469022129495137770981046170581301261101496891396417650688"),
    Package.bigint("1606938044258990275541962092341162602522202993782792835301376"),
    Package.bigint("3213876088517980551083924184682325205044405987565585670602752"),
    Package.bigint("6427752177035961102167848369364650410088811975131171341205504"),
    Package.bigint("12855504354071922204335696738729300820177623950262342682411008"),
    Package.bigint("25711008708143844408671393477458601640355247900524685364822016"),
    Package.bigint("51422017416287688817342786954917203280710495801049370729644032"),
    Package.bigint("102844034832575377634685573909834406561420991602098741459288064"),
    Package.bigint("205688069665150755269371147819668813122841983204197482918576128"),
    Package.bigint("411376139330301510538742295639337626245683966408394965837152256"),
    Package.bigint("822752278660603021077484591278675252491367932816789931674304512"),
    Package.bigint("1645504557321206042154969182557350504982735865633579863348609024"),
    Package.bigint("3291009114642412084309938365114701009965471731267159726697218048"),
    Package.bigint("6582018229284824168619876730229402019930943462534319453394436096"),
    Package.bigint("13164036458569648337239753460458804039861886925068638906788872192"),
    Package.bigint("26328072917139296674479506920917608079723773850137277813577744384"),
    Package.bigint("52656145834278593348959013841835216159447547700274555627155488768"),
    Package.bigint("105312291668557186697918027683670432318895095400549111254310977536"),
    Package.bigint("210624583337114373395836055367340864637790190801098222508621955072"),
    Package.bigint("421249166674228746791672110734681729275580381602196445017243910144"),
    Package.bigint("842498333348457493583344221469363458551160763204392890034487820288"),
    Package.bigint("1684996666696914987166688442938726917102321526408785780068975640576"),
    Package.bigint("3369993333393829974333376885877453834204643052817571560137951281152"),
    Package.bigint("6739986666787659948666753771754907668409286105635143120275902562304"),
    Package.bigint("13479973333575319897333507543509815336818572211270286240551805124608"),
    Package.bigint("26959946667150639794667015087019630673637144422540572481103610249216"),
    Package.bigint("53919893334301279589334030174039261347274288845081144962207220498432"),
    Package.bigint("107839786668602559178668060348078522694548577690162289924414440996864"),
    Package.bigint("215679573337205118357336120696157045389097155380324579848828881993728"),
    Package.bigint("431359146674410236714672241392314090778194310760649159697657763987456"),
    Package.bigint("862718293348820473429344482784628181556388621521298319395315527974912"),
    Package.bigint("1725436586697640946858688965569256363112777243042596638790631055949824"),
    Package.bigint("3450873173395281893717377931138512726225554486085193277581262111899648"),
    Package.bigint("6901746346790563787434755862277025452451108972170386555162524223799296"),
    Package.bigint("13803492693581127574869511724554050904902217944340773110325048447598592"),
    Package.bigint("27606985387162255149739023449108101809804435888681546220650096895197184"),
    Package.bigint("55213970774324510299478046898216203619608871777363092441300193790394368"),
    Package.bigint("110427941548649020598956093796432407239217743554726184882600387580788736"),
    Package.bigint("220855883097298041197912187592864814478435487109452369765200775161577472"),
    Package.bigint("441711766194596082395824375185729628956870974218904739530401550323154944"),
    Package.bigint("883423532389192164791648750371459257913741948437809479060803100646309888"),
    Package.bigint("1766847064778384329583297500742918515827483896875618958121606201292619776"),
    Package.bigint("3533694129556768659166595001485837031654967793751237916243212402585239552"),
    Package.bigint("7067388259113537318333190002971674063309935587502475832486424805170479104"),
    Package.bigint("14134776518227074636666380005943348126619871175004951664972849610340958208"),
    Package.bigint("28269553036454149273332760011886696253239742350009903329945699220681916416"),
    Package.bigint("56539106072908298546665520023773392506479484700019806659891398441363832832"),
    Package.bigint("113078212145816597093331040047546785012958969400039613319782796882727665664"),
    Package.bigint("226156424291633194186662080095093570025917938800079226639565593765455331328"),
    Package.bigint("452312848583266388373324160190187140051835877600158453279131187530910662656"),
    Package.bigint("904625697166532776746648320380374280103671755200316906558262375061821325312"),
    Package.bigint("1809251394333065553493296640760748560207343510400633813116524750123642650624"),
    Package.bigint("3618502788666131106986593281521497120414687020801267626233049500247285301248"),
    Package.bigint("7237005577332262213973186563042994240829374041602535252466099000494570602496"),
    Package.bigint("14474011154664524427946373126085988481658748083205070504932198000989141204992"),
    Package.bigint("28948022309329048855892746252171976963317496166410141009864396001978282409984"),
    Package.bigint("57896044618658097711785492504343953926634992332820282019728792003956564819968"),
    Package.bigint("115792089237316195423570985008687907853269984665640564039457584007913129639936"),
}

Package.powers_two[0] = Package.bigint("1")

Package.big_zero = Package.bigint(0)
Package.big_one = Package.bigint(1)

Package.number_to_bytes = function(num, bits, byte_size)
    if bits > #Package.powers_two then
        error("Too many bits. Must be <= " .. #Package.powers_two .. ".")
    end

    num = Package.bigint(num)

    local result_bits = {}
    result_bits[1] = {}
    for i = bits - 1, 0, -1 do
        local exp_val = Package.powers_two[i]
        local resultant = num - exp_val
        if exp_val <= resultant then
            -- Invalid data!
            return nil
        end

        if resultant < Package.big_zero then
            -- A zero bit
            if #(result_bits[#result_bits]) >= byte_size then
                table.insert(result_bits, { 0 })
            else
                table.insert(result_bits[#result_bits], 0)
            end
        else
            -- A one bit
            num = resultant
            if #(result_bits[#result_bits]) >= byte_size then
                table.insert(result_bits, { 1 })
            else
                table.insert(result_bits[#result_bits], 1)
            end
        end

        if num == Package.bigint(0) then
            break
        end
    end

    local results = {}
    for _, binary_seq in pairs(result_bits) do
        local this_result = 0
        for k, bin in pairs(binary_seq) do
            if bin == 1 then
                this_result = this_result + 2 ^ (byte_size - k)
            end
        end
        table.insert(results, this_result)
    end

    return results
end

Package.bytes_to_number = function(bytes, bits, byte_size)
    if bits > #Package.powers_two then
        error("Too many bits. Must be <= " .. #Package.powers_two .. ".")
    end

    if #bytes > bits / byte_size then
        error("Too many bytes to store into the number of bits available. Must be <= " ..
            bits / byte_size .. ".")
    end

    local binary = {}
    for _, byte in pairs(bytes) do
        for i = byte_size - 1, 0, -1 do
            if byte - (2 ^ i) < 0 then
                table.insert(binary, 0)
            else
                table.insert(binary, 1)
                byte = byte - (2 ^ i)
            end
        end
    end

    local num = Package.bigint(0)
    for i = 1, #binary do
        if binary[i] == 1 then
            num = num + Package.powers_two[bits - i]
        end
    end

    return tostring(num)
end

Package.encode_big_numbers = function(numbers)
    for k, v in pairs(numbers) do
        numbers[k] = tostring(v)
    end
    return numbers
end

Package.string_to_bytes = function(str)
    local result = {}
    for i = 1, #str do
        table.insert(result, string.byte(str, i))
    end
    return result
end

Package.bytes_to_string = function(bytes)
    local str = ""
    for _, v in pairs(bytes) do
        str = str .. string.char(v)
    end
    return str
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

Package.crypt = function(key, number)
    local exp
    if key.public then
        exp = Package.bigint(key.public)
    else
        exp = Package.bigint(key.private)
    end

    return tostring(Package.modexp(Package.bigint(number), exp, Package.bigint(key.shared)))
end

return Package
