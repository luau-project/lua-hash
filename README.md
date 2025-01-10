# lua-hash

[![CI](https://github.com/luau-project/lua-hash/actions/workflows/ci.yml/badge.svg)](./.github/workflows/ci.yml) [![LuaRocks](https://img.shields.io/luarocks/v/luau-project/lua-hash?label=LuaRocks&color=2c3e67)](https://luarocks.org/modules/luau-project/lua-hash)

## Overview

**lua-hash** is a lightweight, native library providing hash algorithms for Lua.

* On Unix-like distributions, it uses the ```OpenSSL``` library;
* On Windows, it uses the WINAPI ```bcrypt``` library;
* On macOS / iOS, it uses the ```CommonCrypto``` framework.

> [!NOTE]
> 
> ```lua-hash``` is implemented in C, and also compiles as C++.

## Supported Algorithms

| Algorithm | Description |
| --- | --- |
| MD5 | An implementation of MD5 hashing with a 128-bit digest |
| SHA1 | An implementation of SHA1 hashing with a 160-bit digest |
| SHA256 | An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a 256-bit digest |
| SHA384 | An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a 384-bit digest |
| SHA512 | An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a 512-bit digest |

> [!WARNING]
> 
> According to Apple (see [[1]](https://developer.apple.com/documentation/cryptokit/insecure/md5) and [[2]](https://developer.apple.com/documentation/cryptokit/insecure/sha1)), MD5 and SHA1 are considered insecure algorithms, but they are provided for backward compatibility with older services that require it. For new services, prefer SHA512.

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Methods](#methods)
    * [oneshot](#oneshot)
* [Classes](#classes)
    * [algorithm](#algorithm)
        * [open](#open)
        * [close](#close)
    * [context](#context)
        * [new](#context)
        * [close](#context)
    * [digest](#digest)
        * [new](#digest)
        * [update](#update)
        * [finalize](#finalize)
* [Change log](#change-log)
* [Future works](#future-works)

## Installation

> [!IMPORTANT]
> 
> On Unix-like operating systems (e.g.: Linux, BSD),  ```lua-hash``` depends on the ```OpenSSL``` library:
>  * On Debian-based (e.g.: Ubuntu) distributions:
> 
>      ```bash
>      sudo apt install -y libssl-dev
>      ```
> 
>  * On RedHat-based (e.g.: Fedora) distributions:
> 
>      ```bash
>      sudo dnf install openssl-devel
>      ```
> 
>  * On BSD-based (e.g.: FreeBSD) distributions:
> 
>      ```bash
>      pkg install openssl-devel
>      ```

Assuming that [LuaRocks](https://luarocks.org) is properly installed and configured on your system, execute the following command:

```bash
luarocks install lua-hash
```

## Usage

### Compute hash of a text on memory

This manner is suitable for (*small*) text that fits well in the memory.

```lua
-- load the library
local hash = require("lua-hash")

-- the text to be hashed
local text = "lua-hash is a cool hashing library"

-- hash 'text' by different algorithms
local MD5_hash = hash.oneshot("MD5", text)
local SHA1_hash = hash.oneshot("SHA1", text)
local SHA256_hash = hash.oneshot("SHA256", text)
local SHA384_hash = hash.oneshot("SHA384", text)
local SHA512_hash = hash.oneshot("SHA512", text)

-- print the hash of 'text' computed by different algorithms
print("MD5 hash is", MD5_hash)
print("SHA1 hash is", SHA1_hash)
print("SHA256 hash is", SHA256_hash)
print("SHA384 hash is", SHA384_hash)
print("SHA512 hash is", SHA512_hash)
```

### Compute a SHA512 hash of a file

By the use of the core API, you can compute a hash of a file of any size (even the huge ones).

```lua
-- the file path to compute a SHA512 hash
local filepath = "path/to/some/file"

local file = assert(io.open(filepath, "rb"), "provide the file path as a parameter to this script to compute a SHA512 checksum")

-- load the library
local hash = require("lua-hash")

-- cache the classes
local algorithm = hash.algorithm
local context = hash.context
local digest = hash.digest

-- open the SHA512 algorithm
local algo = algorithm.open("SHA512")

-- create a context for the hash operation
local ctx = context.new(algo)

-- create a message digest
local message = digest.new(ctx)

-- define a size in bytes
-- to read a chunk from
-- disk
local kb = 1024
local size = 16 * kb

local valid = true

-- keep reading the file while
-- it is not finished
while (valid) do
    local chunk = file:read(size)
    if (chunk == nil) then
        valid = false
    else
        -- hash the chunk read from disk
        -- into the context
        message:update(chunk)
    end
end

-- close the file
file:close()

local output = message:finalize()
print(("%s  %s"):format(output, filepath))

-- close the context to free resources
--
-- tip: the context is closed
-- automatically at garbage collection
ctx:close()

-- close the algorithm to free resources
--
-- tip: the algorithm is closed
-- automatically at garbage collection
algo:close()
```

> [!TIP]
> 
> In the [checksums](./checksums/README.md#computing-file-checksums) folder, you can find scripts for each available hashing algorithm on this library.

## Methods

### oneshot

* *Description*: The oneshot function provides a quick manner to compute the hash of a text held in memory.
* *Signature*: ```oneshot(name, text)```
* *Parameters*:
    * *name* (```string```): the name of the algorithm. See [Supported Algorithms](#supported-algorithms) for a list containing the possible values for this parameter.  
    * *text* (```string```): the text to compute a hash.
* *Return* (```string```): A hex string containing the hash of the text.

## Classes

In order to compute the hash of content that is not suitable to hold in memory, we have to use a verbose approach through in-depth methods. Such specialized methods, split into three classes, were mirrored directly from the C API of the underlying libraries:

* algorithm;
* context;
* digest.

### algorithm

Implementation of a hash algorithm provided by the underlying library.

#### open

* *Description*: Opens the implementation of a given hash algorithm and initializes resources.
* *Signature*: ```open(name)```
* *Parameters*:
    * *name* (```string```): the name of the algorithm. See [Supported Algorithms](#supported-algorithms) for a list of all the possible algorithms.

* *Return* (```userdata```): A handle to the hash algorithm.
* *Remark*: In case of failure, this function throws an error. It might happen if the underlying library does not support the hash algorithm identified by the```name``` parameter.

#### close

* *Description*: Closes the algorithm and free resources.
* *Signature*: ```algorithm:close()```
* *Return* (```void```)

### context

A manager to process a digest associated to a given hash algorithm

#### new

* *Description*: Creates a new context to the provided algorithm, and initializes resources.
* *Signature*: ```new(algorithm)```
* *Parameters*:
    * *algorithm* (```userdata```): an instance to an algorithm previously opened.
* *Return* (```userdata```): A handle to the newly created context.
* *Remark*: In case of failure, this function throws an error. It might happen if the provided hashing algorithm is closed.

#### close

* *Description*: Closes the context and free resources.
* *Signature*: ```context:close()```
* *Return* (```void```)

### digest

Allows a message, even the long ones, to be streamed in chunks to the underlying algorithm for the hash computation.

#### new

* *Description*: Creates a new digest bound to a context, and initializes resources. 
* *Signature*: ```new(ctx)```
* *Parameters*:
    * *ctx* (```userdata```): an instance of a ```context```.
* *Return* (```userdata```): A handle to the newly created digest.
* *Remark*: In case of failure, this function throws an error. It might happen if the provided context, or algorithm bound to the context, was closed.

#### update

* *Description*: Hashes the data into the context.
* *Signature*: ```digest:update(data)```
* *Parameters*:
    * *data* (```string | table```): the data to be hashed into the context. If ```data``` is a string, the only requirement is that it cannot be an empty string. Otherwise, when ```data``` is a table, it is expected to be an array of bytes, i.e., elements are integers in 0 - 255 range.
* *Return* (```void```)
* *Remark*: In case of failure, this function throws an error. It might happen if the provided context, or algorithm bound to the context, was closed.

#### finalize

* *Description*: Hashes the data into the context.
* *Signature*: ```digest:finalize(options)```
* *Parameters*:
    * *options* (```nil | string | table```): the data to be hashed into the context. If ```data``` is a string, the only requirement is that it cannot be an empty string. Otherwise, when ```data``` is a table, it is mandatory to have a field ```type``` describing the desired return type (with possible values of 'string' or 'table'). Moreover, ```type``` is ```"string"```, an optional boolean field ```hex``` can be assigned to signal whether the resulting hash should be formatted as hex string or not.
        * *examples*:
            * output a hex string:
                ```lua
                -- output is a hex string
                local output = digest:finalize()
                ```
            * output a hex string:
                ```lua
                -- output is a hex string
                local output = digest:finalize(nil)
                ```
            * (alternative) output a hex string:
                ```lua
                -- output is a hex string
                local output = digest:finalize({ type = 'string', hex = true })
                ```
            * output a string (*not hex-formatted*):
                ```lua
                -- output is a raw string,
                -- but not in hex format.
                -- Usually, this output string
                -- contains characters that cannot
                -- be rendered nicely on the screen.
                local output = digest:finalize({ type = 'string', hex = false })
                ```
            * output a table of bytes:
                ```lua
                -- output is a table (array) such that
                -- each element falls in the 0 - 255 range
                local output = digest:finalize({ type = 'table' })
                ```
* *Return* (```string | table```): the resulting hash of the whole set of bytes pushed into the context.
* *Remark*:
    * After calling this function, no additional usage of both the context and digest can be made, except for closing them and freeing resources.
    * In case of failure, this function throws an error. It might happen if the provided context, or algorithm bound to the context, was closed.

## Change log

v0.0.1: Initial release.

## Future works

* Add CMake as a build system.