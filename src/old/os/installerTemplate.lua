

local _fix_block_literal_huffman_bitlen_count
local _fix_block_literal_huffman_to_deflate_code
local _fix_block_dist_huffman_bitlen_count
local _fix_block_dist_huffman_to_deflate_code
local _byte_to_char = {}
local _literal_deflate_code_to_base_len = {
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}
local _literal_deflate_code_to_extra_bitlen = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
}
local _dist_deflate_code_to_base_dist = {
	[0] = 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
	8193, 12289, 16385, 24577,
}
local _dist_deflate_code_to_extra_bitlen = {
	[0] = 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
}
local _rle_codes_huffman_bitlen_order = {16, 17, 18,
	0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
}
local _reverse_bits_tbl = {}
local _pow2 = {}
local function CreateReader(input_string)
	local input = input_string
	local input_strlen = #input_string
	local input_next_byte_pos = 1
	local cache_bitlen = 0
	local cache = 0
	local function ReadBits(bitlen)
		local rshift_mask = _pow2[bitlen]
		local code
		if bitlen <= cache_bitlen then
			code = cache % rshift_mask
			cache = (cache - code) / rshift_mask
			cache_bitlen = cache_bitlen - bitlen
			local lshift_mask = _pow2[cache_bitlen]
			local byte1, byte2, byte3, byte4 = string.byte(input
				, input_next_byte_pos, input_next_byte_pos+3)
			cache = cache + ((byte1 or 0)+(byte2 or 0)*256
				+ (byte3 or 0)*65536+(byte4 or 0)*16777216)*lshift_mask
			input_next_byte_pos = input_next_byte_pos + 4
			cache_bitlen = cache_bitlen + 32 - bitlen
			code = cache % rshift_mask
			cache = (cache - code) / rshift_mask
		end
		return code
	end
	local function ReadBytes(bytelen, buffer, buffer_size)
		assert(cache_bitlen % 8 == 0)
		local byte_from_cache = (cache_bitlen/8 < bytelen)
			and (cache_bitlen/8) or bytelen
		for _=1, byte_from_cache do
			local byte = cache % 256
			buffer_size = buffer_size + 1
			buffer[buffer_size] = string.char(byte)
			cache = (cache - byte) / 256
		end
		cache_bitlen = cache_bitlen - byte_from_cache*8
		bytelen = bytelen - byte_from_cache
		if (input_strlen - input_next_byte_pos - bytelen + 1) * 8
			+ cache_bitlen < 0 then
			return -1
		end
		for i=input_next_byte_pos, input_next_byte_pos+bytelen-1 do
			buffer_size = buffer_size + 1
			buffer[buffer_size] = string.sub(input, i, i)
		end
		input_next_byte_pos = input_next_byte_pos + bytelen
		return buffer_size
	end
	local function Decode(huffman_bitlen_counts, huffman_symbols, min_bitlen)
		local code = 0
		local first = 0
		local index = 0
		local count
		if min_bitlen > 0 then
			if cache_bitlen < 15 and input then
				local lshift_mask = _pow2[cache_bitlen]
				local byte1, byte2, byte3, byte4 =
					string.byte(input, input_next_byte_pos
					, input_next_byte_pos+3)
				cache = cache + ((byte1 or 0)+(byte2 or 0)*256
					+(byte3 or 0)*65536+(byte4 or 0)*16777216)*lshift_mask
				input_next_byte_pos = input_next_byte_pos + 4
				cache_bitlen = cache_bitlen + 32
			end
			local rshift_mask = _pow2[min_bitlen]
			cache_bitlen = cache_bitlen - min_bitlen
			code = cache % rshift_mask
			cache = (cache - code) / rshift_mask
			code = _reverse_bits_tbl[min_bitlen][code]
			count = huffman_bitlen_counts[min_bitlen]
			if code < count then
				return huffman_symbols[code]
			end
			index = count
			first = count * 2
			code = code * 2
		end
		for bitlen = min_bitlen+1, 15 do
			local bit
			bit = cache % 2
			cache = (cache - bit) / 2
			cache_bitlen = cache_bitlen - 1
			code = (bit==1) and (code + 1 - code % 2) or code
			count = huffman_bitlen_counts[bitlen] or 0
			local diff = code - first
			if diff < count then
				return huffman_symbols[index + diff]
			end
			index = index + count
			first = first + count
			first = first * 2
			code = code * 2
		end
		return -10
	end
	local function ReaderBitlenLeft()
		return (input_strlen - input_next_byte_pos + 1) * 8 + cache_bitlen
	end
	local function SkipToByteBoundary()
		local skipped_bitlen = cache_bitlen%8
		local rshift_mask = _pow2[skipped_bitlen]
		cache_bitlen = cache_bitlen - skipped_bitlen
		cache = (cache - cache % rshift_mask) / rshift_mask
	end
	return ReadBits, ReadBytes, Decode, ReaderBitlenLeft, SkipToByteBoundary
end
local function CreateDecompressState(str, dictionary)
	local ReadBits, ReadBytes, Decode, ReaderBitlenLeft
		, SkipToByteBoundary = CreateReader(str)
	local state =
	{
		ReadBits = ReadBits,
		ReadBytes = ReadBytes,
		Decode = Decode,
		ReaderBitlenLeft = ReaderBitlenLeft,
		SkipToByteBoundary = SkipToByteBoundary,
		buffer_size = 0,
		buffer = {},
		result_buffer = {},
		dictionary = dictionary,
	}
	return state
end
local function DecodeUntilEndOfBlock(state, lcodes_huffman_bitlens
	, lcodes_huffman_symbols, lcodes_huffman_min_bitlen
	, dcodes_huffman_bitlens, dcodes_huffman_symbols
	, dcodes_huffman_min_bitlen)
	local buffer, buffer_size, ReadBits, Decode, ReaderBitlenLeft
		, result_buffer =
		state.buffer, state.buffer_size, state.ReadBits, state.Decode
		, state.ReaderBitlenLeft, state.result_buffer
	local dictionary = state.dictionary
	local dict_string_table
	local dict_strlen
	local buffer_end = 1
	if dictionary and not buffer[0] then
		dict_string_table = dictionary.string_table
		dict_strlen = dictionary.strlen
		buffer_end = -dict_strlen + 1
		for i=0, (-dict_strlen+1)<-257 and -257 or (-dict_strlen+1), -1 do
			buffer[i] = _byte_to_char[dict_string_table[dict_strlen+i]]
		end
	end
	repeat
		local symbol = Decode(lcodes_huffman_bitlens
			, lcodes_huffman_symbols, lcodes_huffman_min_bitlen)
		if symbol < 0 or symbol > 285 then
			return -10
		elseif symbol < 256 then
			buffer_size = buffer_size + 1
			buffer[buffer_size] = _byte_to_char[symbol]
		elseif symbol > 256 then
			symbol = symbol - 256
			local bitlen = _literal_deflate_code_to_base_len[symbol]
			bitlen = (symbol >= 8)
				 and (bitlen
				 + ReadBits(_literal_deflate_code_to_extra_bitlen[symbol]))
					or bitlen
			symbol = Decode(dcodes_huffman_bitlens, dcodes_huffman_symbols
				, dcodes_huffman_min_bitlen)
			if symbol < 0 or symbol > 29 then
				return -10
			end
			local dist = _dist_deflate_code_to_base_dist[symbol]
			dist = (dist > 4) and (dist
				+ ReadBits(_dist_deflate_code_to_extra_bitlen[symbol])) or dist
			local char_buffer_index = buffer_size-dist+1
			if char_buffer_index < buffer_end then
				return -11
			end
			if char_buffer_index >= -257 then
				for _=1, bitlen do
					buffer_size = buffer_size + 1
					buffer[buffer_size] = buffer[char_buffer_index]
					char_buffer_index = char_buffer_index + 1
				end
			else
				char_buffer_index = dict_strlen + char_buffer_index
				for _=1, bitlen do
					buffer_size = buffer_size + 1
					buffer[buffer_size] =
					_byte_to_char[dict_string_table[char_buffer_index]]
					char_buffer_index = char_buffer_index + 1
				end
			end
		end
		if ReaderBitlenLeft() < 0 then
			return 2
		end
		if buffer_size >= 65536 then
			result_buffer[#result_buffer+1] =
				table.concat(buffer, "", 1, 32768)
			for i=32769, buffer_size do
				buffer[i-32768] = buffer[i]
			end
			buffer_size = buffer_size - 32768
			buffer[buffer_size+1] = nil
		end
	until symbol == 256
	state.buffer_size = buffer_size
	return 0
end
local function DecompressFixBlock(state)
	return DecodeUntilEndOfBlock(state
		, _fix_block_literal_huffman_bitlen_count
		, _fix_block_literal_huffman_to_deflate_code, 7
		, _fix_block_dist_huffman_bitlen_count
		, _fix_block_dist_huffman_to_deflate_code, 5)
end
local function DecompressStoreBlock(state)
	local buffer, buffer_size, ReadBits, ReadBytes, ReaderBitlenLeft
		, SkipToByteBoundary, result_buffer =
		state.buffer, state.buffer_size, state.ReadBits, state.ReadBytes
		, state.ReaderBitlenLeft, state.SkipToByteBoundary, state.result_buffer
	SkipToByteBoundary()
	local bytelen = ReadBits(16)
	if ReaderBitlenLeft() < 0 then
		return 2
	end
	local bytelenComp = ReadBits(16)
	if ReaderBitlenLeft() < 0 then
		return 2
	end
	if bytelen % 256 + bytelenComp % 256 ~= 255 then
		return -2
	end
	if (bytelen-bytelen % 256)/256
		+ (bytelenComp-bytelenComp % 256)/256 ~= 255 then
		return -2
	end
	buffer_size = ReadBytes(bytelen, buffer, buffer_size)
	if buffer_size < 0 then
		return 2
	end
	if buffer_size >= 65536 then
		result_buffer[#result_buffer+1] = table.concat(buffer, "", 1, 32768)
		for i=32769, buffer_size do
			buffer[i-32768] = buffer[i]
		end
		buffer_size = buffer_size - 32768
		buffer[buffer_size+1] = nil
	end
	state.buffer_size = buffer_size
	return 0
end
local function GetHuffmanForDecode(huffman_bitlens, max_symbol, max_bitlen)
	local huffman_bitlen_counts = {}
	local min_bitlen = max_bitlen
	for symbol = 0, max_symbol do
		local bitlen = huffman_bitlens[symbol] or 0
		min_bitlen = (bitlen > 0 and bitlen < min_bitlen)
			and bitlen or min_bitlen
		huffman_bitlen_counts[bitlen] = (huffman_bitlen_counts[bitlen] or 0)+1
	end
	if huffman_bitlen_counts[0] == max_symbol+1 then
		return 0, huffman_bitlen_counts, {}, 0
	end
	local left = 1
	for len = 1, max_bitlen do
		left = left * 2
		left = left - (huffman_bitlen_counts[len] or 0)
		if left < 0 then
			return left
		end
	end
	local offsets = {}
	offsets[1] = 0
	for len = 1, max_bitlen-1 do
		offsets[len + 1] = offsets[len] + (huffman_bitlen_counts[len] or 0)
	end
	local huffman_symbols = {}
	for symbol = 0, max_symbol do
		local bitlen = huffman_bitlens[symbol] or 0
		if bitlen ~= 0 then
			local offset = offsets[bitlen]
			huffman_symbols[offset] = symbol
			offsets[bitlen] = offsets[bitlen] + 1
		end
	end
	return left, huffman_bitlen_counts, huffman_symbols, min_bitlen
end
local function DecompressDynamicBlock(state)
	local ReadBits, Decode = state.ReadBits, state.Decode
	local nlen = ReadBits(5) + 257
	local ndist = ReadBits(5) + 1
	local ncode = ReadBits(4) + 4
	if nlen > 286 or ndist > 30 then
		return -3
	end
	local rle_codes_huffman_bitlens = {}
	for i = 1, ncode do
		rle_codes_huffman_bitlens[_rle_codes_huffman_bitlen_order[i]] =
			ReadBits(3)
	end
	local rle_codes_err, rle_codes_huffman_bitlen_counts,
		rle_codes_huffman_symbols, rle_codes_huffman_min_bitlen =
		GetHuffmanForDecode(rle_codes_huffman_bitlens, 18, 7)
	if rle_codes_err ~= 0 then
		return -4
	end
	local lcodes_huffman_bitlens = {}
	local dcodes_huffman_bitlens = {}
	local index = 0
	while index < nlen + ndist do
		local symbol
		local bitlen
		symbol = Decode(rle_codes_huffman_bitlen_counts
			, rle_codes_huffman_symbols, rle_codes_huffman_min_bitlen)
		if symbol < 0 then
			return symbol
		elseif symbol < 16 then
			if index < nlen then
				lcodes_huffman_bitlens[index] = symbol
			else
				dcodes_huffman_bitlens[index-nlen] = symbol
			end
			index = index + 1
		else
			bitlen = 0
			if symbol == 16 then
				if index == 0 then
					return -5
				end
				if index-1 < nlen then
					bitlen = lcodes_huffman_bitlens[index-1]
				else
					bitlen = dcodes_huffman_bitlens[index-nlen-1]
				end
				symbol = 3 + ReadBits(2)
			elseif symbol == 17 then
				symbol = 3 + ReadBits(3)
			else
				symbol = 11 + ReadBits(7)
			end
			if index + symbol > nlen + ndist then
				return -6
			end
			while symbol > 0 do
				symbol = symbol - 1
				if index < nlen then
					lcodes_huffman_bitlens[index] = bitlen
				else
					dcodes_huffman_bitlens[index-nlen] = bitlen
				end
				index = index + 1
			end
		end
	end
	if (lcodes_huffman_bitlens[256] or 0) == 0 then
		return -9
	end
	local lcodes_err, lcodes_huffman_bitlen_counts
		, lcodes_huffman_symbols, lcodes_huffman_min_bitlen =
		GetHuffmanForDecode(lcodes_huffman_bitlens, nlen-1, 15)
	if (lcodes_err ~=0 and (lcodes_err < 0
		or nlen ~= (lcodes_huffman_bitlen_counts[0] or 0)
			+(lcodes_huffman_bitlen_counts[1] or 0))) then
		return -7
	end
	local dcodes_err, dcodes_huffman_bitlen_counts
		, dcodes_huffman_symbols, dcodes_huffman_min_bitlen =
		GetHuffmanForDecode(dcodes_huffman_bitlens, ndist-1, 15)
	if (dcodes_err ~=0 and (dcodes_err < 0
		or ndist ~= (dcodes_huffman_bitlen_counts[0] or 0)
			+ (dcodes_huffman_bitlen_counts[1] or 0))) then
		return -8
	end
	return DecodeUntilEndOfBlock(state, lcodes_huffman_bitlen_counts
		, lcodes_huffman_symbols, lcodes_huffman_min_bitlen
		, dcodes_huffman_bitlen_counts, dcodes_huffman_symbols
		, dcodes_huffman_min_bitlen)
end
local function Inflate(state)
	local ReadBits = state.ReadBits
	local is_last_block
	while not is_last_block do
		is_last_block = (ReadBits(1) == 1)
		local block_type = ReadBits(2)
		local status
		if block_type == 0 then
			status = DecompressStoreBlock(state)
		elseif block_type == 1 then
			status = DecompressFixBlock(state)
		elseif block_type == 2 then
			status = DecompressDynamicBlock(state)
		else
			return nil, -1
		end
		if status ~= 0 then
			return nil, status
        end
        if os and os.pullEvent then
            os.queueEvent("nosleep")
            os.pullEvent()
        end
	end
	state.result_buffer[#state.result_buffer+1] =
		table.concat(state.buffer, "", 1, state.buffer_size)
	local result = table.concat(state.result_buffer)
	return result
end
local function decompressDeflateInternal(str, dictionary)
    local state = CreateDecompressState(str, dictionary)
    local result, status = Inflate(state)
    if not result then
        return nil, status
    end
    local bitlen_left = state.ReaderBitlenLeft()
    local bytelen_left = (bitlen_left - bitlen_left % 8) / 8
    return result, bytelen_left
end
local function memoize(f)
    local mt = {}
    local t = setmetatable({}, mt)
    function mt:__index(k)
        local v = f(k); t[k] = v
        return v
    end
    return t
end
local crc_table = memoize(function(i)
    local crc = i
    for _ = 1, 8 do
        local b = bit32.band(crc, 1)
        crc = bit32.rshift(crc, 1)
        if b == 1 then crc = bit32.xor(crc, 0xEDB88320) end
    end
    return crc
end)
local function crc32_byte(byte, crc)
    crc = bit32.bnot(crc or 0)
    local v1 = bit32.rshift(crc, 8)
    local v2 = crc_table[bit32.xor(crc % 256, byte)]
    return bit32.bnot(bit32.xor(v1, v2))
end
local function crc32_string(s, crc)
    crc = crc or 0
    for i = 1, #s do
        crc = crc32_byte(s:byte(i), crc)
    end
    return crc
end
local function crc32(s, crc)
    if type(s) == 'string' then
        return crc32_string(s, crc)
    else
        return crc32_byte(s, crc)
    end
end
local function decompressGzip(str)
    local offset = 10
    if bit32.band(string.byte(string.sub(str, 4, 4)), 4) == 4 then
        offset = offset + string.byte(string.sub(str, 11, 11)) * 256 + string.byte(string.sub(str, 12, 12))
    end
    if bit32.band(string.byte(string.sub(str, 4, 4)), 8) == 8 then
        while string.byte(string.sub(str, offset, offset)) ~= 0 do offset = offset + 1 end
    end
    if bit32.band(string.byte(string.sub(str, 4, 4)), 16) == 16 then
        while string.byte(string.sub(str, offset, offset)) ~= 0 do offset = offset + 1 end
    end
    if bit32.band(string.byte(string.sub(str, 4, 4)), 2) == 2 then
        local src_checksum = string.byte(string.sub(str, offset + 1, offset + 1)) * 256 +
            string.byte(string.sub(str, offset, offset))
        local target_checksum = bit32.band(crc32(string.sub(str, 1, offset - 1)), 0xFFFF)
        if bit32.xor(src_checksum, target_checksum) ~= 0xFFFF then return nil, -5 end
        offset = offset + 2
    end
    local res, err = decompressDeflateInternal(string.sub(str, offset + 1, -8))
    if res == nil then return res, err end
    local src_checksum = string.byte(string.sub(str, -5, -5)) * 0x1000000 +
        string.byte(string.sub(str, -6, -6)) * 0x10000 + string.byte(string.sub(str, -7, -7)) * 256 +
        string.byte(string.sub(str, -8, -8))
    src_checksum = bit32.bnot(src_checksum)
    local target_checksum = crc32(res)
    if bit32.xor(src_checksum, target_checksum) ~= 0xFFFFFFFF then return nil, -2 end
    return res
end

local function decompressTable(compressedTable)
    local decompressedTable = decompressGzip(compressedTable)
    return textutils.unserialise(decompressedTable)
end

local function createSystemFiles(systemTable, path)
    for key, value in pairs(systemTable) do
        if type(value) == "table" then
            fs.makeDir(path .. key)
            createSystemFiles(value, path .. key .. "/")
        else
            local file = fs.open(path .. key, "w")
            file.write(value)
            file.close()
        end
    end
end

createSystemFiles(decompressTable(compressedSystem), "/")
