-- the text to be hashed
local text = "lua-hash is a cool hashing library"

-- load the library
local hash = require("lua-hash")

-- cache the classes
local algorithm = hash.algorithm
local context = hash.context
local digest = hash.digest

-- loop through all the
-- algorithms available
for _, name in ipairs({ "MD5", "SHA1", "SHA256", "SHA384", "SHA512" }) do

    -- open the algorithm
    local algo = algorithm.open(name)

    -- create a context
    local ctx = context.new(algo)

    -- create a message digest
    local message = digest.new(ctx)
    
    -- hash the text into the context
    message:update(text)

    -- get the output as a table of bytes
    local hashed = message:finalize({ type = 'table' })

    -- convert the table of bytes to a table of hex strings
    local hex_bytes = {}
    for i, byte in ipairs(hashed) do
        table.insert(hex_bytes, ("%02x"):format(byte))
    end

    -- the hex output
    local hex_hashed = table.concat(hex_bytes)

    -- print the hex output
    print(name, "is", hex_hashed)

    -- free the context resources
    ctx:close()

    -- free the algorithm resources
    algo:close()
end