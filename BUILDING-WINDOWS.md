# Build lua-hash on Windows

This page details how to build `lua-hash` directly from the source code on Windows using `cmake`.

## Table of Contents

* [Prerequisites](#prerequisites)
* [Build and Install](#build-and-install)

## Prerequisites

* Lua (&ge; 5.1) or LuaJIT must be installed in the system;

* The same compiler used to build Lua or LuaJIT must be available on `PATH` environment variable.

* CMake: since `v0.1.0`, it is possible to employ `cmake` to build `lua-hash` directly from the source code, out of `LuaRocks`. From now on, we are going to assume that `cmake` is installed in the system.

> [!NOTE]
> 
> **Install CMake**: In order to use this method, the `cmake` tool is required. Visit the website [https://cmake.org/](https://cmake.org/), download and install it.

## Build and Install

1. Download the latest source code of `lua-hash`, extract it and launch the same command prompt used to build Lua;

2. Then, change directory to `lua-hash` directory:

    ```batch
    cd lua-hash
    ```

3. Set an environment variable (`LUA_DIR`) to hold the directory of Lua (*assumed to be at `C:\Program Files\Lua`*):

    ```batch
    set "LUA_DIR=C:\Program Files\Lua"
    ```

4. Configure `lua-hash` for the Lua version installed:

    * Microsoft Visual C/C++ build tools (MSVC):

        ```batch
        cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release --install-prefix "C:\lua-hash" -B build
        ```

    * MinGW / MinGW-w64

        ```batch
        cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release --install-prefix "C:\lua-hash" -B build
        ```

> [!TIP]
> 
> * Change `C:\lua-hash` above to the destination directory;
> * In case multiple Lua versions are installed in the system, use `-DLUA_VERSION=5.1`, ..., `-DLUA_VERSION=5.5` to select the appropriate version for PUC-Lua or `-DLUA_VERSION=luajit` for LuaJIT.

5. Build `lua-hash`:

    ```batch
    cmake --build build --config Release
    ```

6. Test `lua-hash`:

    ```batch
    ctest --test-dir build -C Release
    ```

7. Install `lua-hash`:

    ```batch
    cmake --install build --config Release
    ```

    ```lua
    -- run this script
    -- to find suitable locations
    -- to install `lua-hash.dll`
    local pkg = "lua-hash"
    local dirsep = package.config:sub(1, 1)
    local pattern = (dirsep == "\\") and
        "([^\\/]+)$" or
        "([^" .. dirsep .. "]+)$"

    for p in package.cpath:gmatch("[^;]+") do
        local path = ((p:gsub("%?", pkg)))
        local basename = path:match(pattern)
        if (basename and basename:sub(1, #pkg) == pkg) then
            print(path)
        end
    end
    ```

> [!NOTE]
> 
> Find the file `lua-hash.dll` within `C:\lua-hash` and copy it to any directory covered by `LUA_CPATH`. For instance, the previous script tells suitable paths to store `lua-hash.dll`.
