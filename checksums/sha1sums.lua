--[[
The MIT License (MIT)

Copyright (c) 2025 luau-project [https://github.com/luau-project/lua-hash](https://github.com/luau-project/lua-hash)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
]]

--[[
Summary:
    computes the SHA1 hash from a file

Usage:
    lua sha1sums.lua "path/to/my/file"
]]

local filepath = arg[1]
local file = assert(io.open(filepath, "rb"), "provide the file path as a parameter to this script to compute a SHA1 checksum")

local hash = require("lua-hash")
local algorithm = hash.algorithm
local context = hash.context
local digest = hash.digest

local algo = algorithm.open("SHA1")
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

