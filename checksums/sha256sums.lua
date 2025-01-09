--[[
Summay:
    computes the SHA256 hash from a file

Usage:
    lua sha256sums.lua "path/to/my/file"
]]

local filepath = arg[1]
local file = assert(io.open(filepath, "rb"), "provide the file path as a parameter to this script to compute a SHA256 checksum")

local hash = require("lua-hash")
local algorithm = hash.algorithm
local context = hash.context
local digest = hash.digest

local algo = algorithm.open("SHA256")
local ctx = context.new(algo)
local message = digest.new(ctx)

local kb = 1024
local size = 16 * kb
local valid = true

while (valid) do
    local chunk = file:read(size)
    if (chunk == nil) then
        valid = false
    else
        message:update(chunk)
    end
end

file:close()

local hashed = message:finalize()
print(("%s  %s"):format(hashed, filepath))

ctx:close()
algo:close()

