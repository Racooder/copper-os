-- Simple thread API by immibis

local threadAPI = {}

threadAPI.threads = {}
threadAPI.starting = {}
threadAPI.eventFilter = nil

rawset(os, "startThread", function(fn, blockTerminate)
	table.insert(threadAPI.starting, {
		cr = coroutine.create(fn),
		blockTerminate = blockTerminate or false,
		error = nil,
		dead = false,
		filter = nil
	})
end)

threadAPI.tick = function(t, evt, ...)
	if t.dead then return end
	if t.filter ~= nil and evt ~= t.filter then return end
	if evt == "terminate" and t.blockTerminate then return end

	coroutine.resume(t.cr, evt, ...)
	t.dead = (coroutine.status(t.cr) == "dead")
end

threadAPI.tickAll = function()
	if #threadAPI.starting > 0 then
		local clone = threadAPI.starting
		threadAPI.starting = {}
		for _, v in ipairs(clone) do
			threadAPI.tick(v)
			table.insert(threadAPI.threads, v)
		end
	end
	local e
	if threadAPI.eventFilter then
		e = { threadAPI.eventFilter(coroutine.yield()) }
	else
		e = { coroutine.yield() }
	end
	local dead = nil
	for k, v in ipairs(threadAPI.threads) do
		threadAPI.tick(v, table.unpack(e))
		if v.dead then
			if dead == nil then dead = {} end
			table.insert(dead, k - #dead)
		end
	end
	if dead ~= nil then
		for _, v in ipairs(dead) do
			table.remove(threadAPI.threads, v)
		end
	end
end

-- rawset(os, "setGlobalEventFilter", function(fn)
-- 	if threadAPI.eventFilter ~= nil then error("This can only be set once!") end
-- 	threadAPI.eventFilter = fn
-- 	rawset(os, "setGlobalEventFilter", nil)
-- end)

threadAPI.startThreading = function(mainThread)
	if type(mainThread) == "function" then
		os.startThread(mainThread)
	else
		os.startThread(function() shell.run("shell") end)
	end

	while #threadAPI.threads > 0 or #threadAPI.starting > 0 do
		threadAPI.tickAll()
	end

	print("All threads terminated!")
	print("Exiting thread manager")
end

return threadAPI
