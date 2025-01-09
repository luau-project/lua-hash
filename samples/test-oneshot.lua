-- the text to be hashed
local text = "lua-hash is a cool hashing library"

-- load the library
local hash = require("lua-hash")

-- loop through all the
-- algorithms available
for _, name in ipairs({ "MD5", "SHA1", "SHA256", "SHA384", "SHA512" }) do

    -- get the output as a hex-string
    local hashed = hash.oneshot(name, text)

    -- print the output
    print(name, "is", hashed)
end