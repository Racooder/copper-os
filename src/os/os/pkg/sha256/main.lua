-- SHA-256, HMAC and PBKDF2 functions in ComputerCraft
-- By Anavrins
-- For help and details, you can PM me on the CC forums
-- You may use this code in your projects without asking me, as long as credit is given and this header is kept intact
-- http://www.computercraft.info/forums2/index.php?/user/12870-anavrins
-- http://pastebin.com/6UV4qfNF
-- Last update: October 10, 2017

-- Usage
---- Data format
------ Almost all arguments passed in these functions can take both a string or a special table containing a byte array.
------ This byte array format is simply a table containing a list of each character's byte values.
------ The phrase "hello world" will become {104,101,108,108,111, 32,119,111,114,108,100}.
------ Any strings can be converted into it with {str:byte(1,-1)}, and back into string with string.char(unpack(arr))
------
------ The data returned by all functions are also in this byte array format.
------ They are paired with a metatable containing metamethods like
------ :toHex() to convert into the traditional hexadecimal representation.
------ :isEqual(arr) to compare the hash with another byte array "arr" in constant time.
------ __tostring to convert into a raw string (Might crash window api on old CC versions).
------ This output can also be fed into my base64 function (TEtna4tX) to get a shorter hash representation.

---- digest(data)
------ The digest function is the core of this API, it simply hashes your data with the SHA256 algorithm, period.
------ It's the function everybody is familiar with, and most likely what you're looking for.
------ This function is mainly used for file integrity, however it is not suited for password storage by itself, use PBKDF2 instead.

---- hmac(data, key)
------ The HMAC function is used for message authentication, it's primary use is in networking apis
------ to authenticate an encrypted message and ensuring that the data was not tempered with.
------ The key may be a string or a byte array, with a size between 0 and 32 bytes (256-bits), having a key larger than 32 bytes will not increase security.
------ This function *may* be used for password storage, if you choose to do so, you must pass the password as the key argument, and the salt as the data argument.

---- PBKDF2(pass, salt, iter, dklen)
------ Password-based key derivation function, returns a "dklen" bytes long array for use in various networking protocol to generate secure cryptographic keys.
------ This is the preferred choice for password storage, it uses individual argument for password and salt, do not concatenate beforehand.
------ This algorithm is designed to inherently slow down hashing by repeating the process many times to slow down cracking attempts.
------ You can adjust the number of "iter" to control the speed of the algorithm, higher "iter" means slower hashing, as well as slower to crack.
------ DO NOT TOUCH "dklen" if you're using it for passwords, simply pass nil or nothing at all (defaults to 32).
------ Passing a dklen higher than 32 will multiply the number of iterations with no additional security whatsoever.

local sha256       = {}

sha256.mod32       = 2 ^ 32
sha256.band        = bit32 and bit32.band or bit.band
sha256.bnot        = bit32 and bit32.bnot or bit.bnot
sha256.bxor        = bit32 and bit32.bxor or bit.bxor
sha256.blshift     = bit32 and bit32.lshift or bit.blshift
sha256.upack       = table.unpack

sha256.rrotate     = function(n, b)
	local s = n / (2 ^ b)
	local f = s % 1
	return (s - f) + f * sha256.mod32
end
sha256.brshift     = function(int, by) -- Thanks bit32 for bad rshift
	local s = int / (2 ^ by)
	return s - s % 1
end

sha256.H           = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

sha256.K           = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

sha256.counter     = function(incr)
	local t1, t2 = 0, 0
	if 0xFFFFFFFF - t1 < incr then
		t2 = t2 + 1
		t1 = incr - (0xFFFFFFFF - t1) - 1
	else
		t1 = t1 + incr
	end
	return t2, t1
end

sha256.BE_toInt    = function(bs, i)
	return sha256.blshift((bs[i] or 0), 24) + sha256.blshift((bs[i + 1] or 0), 16) + sha256.blshift((bs[i + 2] or 0), 8) +
	(bs[i + 3] or 0)
end

sha256.preprocess  = function(data)
	local len = #data
	local proc = {}
	data[#data + 1] = 0x80
	while #data % 64 ~= 56 do data[#data + 1] = 0 end
	local blocks = math.ceil(#data / 64)
	for i = 1, blocks do
		proc[i] = {}
		for j = 1, 16 do
			proc[i][j] = sha256.BE_toInt(data, 1 + ((i - 1) * 64) + ((j - 1) * 4))
		end
	end
	proc[blocks][15], proc[blocks][16] = sha256.counter(len * 8)
	return proc
end

sha256.digestblock = function(w, C)
	for j = 17, 64 do
		local v = w[j - 15]
		local s0 = sha256.bxor(sha256.bxor(sha256.rrotate(w[j - 15], 7), sha256.rrotate(w[j - 15], 18)),
			sha256.brshift(w[j - 15], 3))
		local s1 = sha256.bxor(sha256.bxor(sha256.rrotate(w[j - 2], 17), sha256.rrotate(w[j - 2], 19)),
			sha256.brshift(w[j - 2], 10))
		w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % sha256.mod32
	end
	local a, b, c, d, e, f, g, h = sha256.upack(C)
	for j = 1, 64 do
		local S1 = sha256.bxor(sha256.bxor(sha256.rrotate(e, 6), sha256.rrotate(e, 11)), sha256.rrotate(e, 25))
		local ch = sha256.bxor(sha256.band(e, f), sha256.band(sha256.bnot(e), g))
		local temp1 = (h + S1 + ch + sha256.K[j] + w[j]) % sha256.mod32
		local S0 = sha256.bxor(sha256.bxor(sha256.rrotate(a, 2), sha256.rrotate(a, 13)), sha256.rrotate(a, 22))
		local maj = sha256.bxor(sha256.bxor(sha256.band(a, b), sha256.band(a, c)), sha256.band(b, c))
		local temp2 = (S0 + maj) % sha256.mod32
		h, g, f, e, d, c, b, a = g, f, e, (d + temp1) % sha256.mod32, c, b, a, (temp1 + temp2) % sha256.mod32
	end
	C[1] = (C[1] + a) % sha256.mod32
	C[2] = (C[2] + b) % sha256.mod32
	C[3] = (C[3] + c) % sha256.mod32
	C[4] = (C[4] + d) % sha256.mod32
	C[5] = (C[5] + e) % sha256.mod32
	C[6] = (C[6] + f) % sha256.mod32
	C[7] = (C[7] + g) % sha256.mod32
	C[8] = (C[8] + h) % sha256.mod32
	return C
end

sha256.mt          = {
	__tostring = function(a) return string.char(table.unpack(a)) end,
	__index = {
		toHex = function(self, s) return ("%02x"):rep(#self):format(table.unpack(self)) end,
		isEqual = function(self, t)
			if type(t) ~= "table" then return false end
			if #self ~= #t then return false end
			local ret = 0
			for i = 1, #self do
				ret = bit32.bor(ret, sha256.bxor(self[i], t[i]))
			end
			return ret == 0
		end
	}
}

sha256.toBytes     = function(t, n)
	local b = {}
	for i = 1, n do
		b[(i - 1) * 4 + 1] = sha256.band(sha256.brshift(t[i], 24), 0xFF)
		b[(i - 1) * 4 + 2] = sha256.band(sha256.brshift(t[i], 16), 0xFF)
		b[(i - 1) * 4 + 3] = sha256.band(sha256.brshift(t[i], 8), 0xFF)
		b[(i - 1) * 4 + 4] = sha256.band(t[i], 0xFF)
	end
	return setmetatable(b, sha256.mt)
end

sha256.digest      = function(data)
	data = data or ""
	data = type(data) == "string" and { data:byte(1, -1) } or data

	data = sha256.preprocess(data)
	local C = { sha256.upack(sha256.H) }
	for i = 1, #data do C = sha256.digestblock(data[i], C) end
	return sha256.toBytes(C, 8)
end

sha256.hmac        = function(data, key)
	local data = type(data) == "table" and { sha256.upack(data) } or { tostring(data):byte(1, -1) }
	local key = type(key) == "table" and { sha256.upack(key) } or { tostring(key):byte(1, -1) }

	local blocksize = 64

	key = #key > blocksize and sha256.digest(key) or key

	local ipad = {}
	local opad = {}
	local padded_key = {}

	for i = 1, blocksize do
		ipad[i] = sha256.bxor(0x36, key[i] or 0)
		opad[i] = sha256.bxor(0x5C, key[i] or 0)
	end

	for i = 1, #data do
		ipad[blocksize + i] = data[i]
	end

	ipad = sha256.digest(ipad)

	for i = 1, blocksize do
		padded_key[i] = opad[i]
		padded_key[blocksize + i] = ipad[i]
	end

	return sha256.digest(padded_key)
end

sha256.pbkdf2      = function(pass, salt, iter, dklen)
	local salt = type(salt) == "table" and salt or { tostring(salt):byte(1, -1) }
	local hashlen = 32
	local dklen = dklen or 32
	local block = 1
	local out = {}

	while dklen > 0 do
		local ikey = {}
		local isalt = { sha256.upack(salt) }
		local clen = dklen > hashlen and hashlen or dklen

		isalt[#isalt + 1] = sha256.band(sha256.brshift(block, 24), 0xFF)
		isalt[#isalt + 1] = sha256.band(sha256.brshift(block, 16), 0xFF)
		isalt[#isalt + 1] = sha256.band(sha256.brshift(block, 8), 0xFF)
		isalt[#isalt + 1] = sha256.band(block, 0xFF)

		for j = 1, iter do
			isalt = sha256.hmac(isalt, pass)
			for k = 1, clen do ikey[k] = sha256.bxor(isalt[k], ikey[k] or 0) end
			if j % 200 == 0 then
				os.queueEvent("PBKDF2", j)
				coroutine.yield("PBKDF2")
			end
		end
		dklen = dklen - clen
		block = block + 1
		for k = 1, clen do out[#out + 1] = ikey[k] end
	end

	return setmetatable(out, sha256.mt)
end

return sha256
