package = "lua-hash"
version = "0.0.1-1"

source = {
   url = "git+https://github.com/luau-project/lua-hash",
   tag = "v0.0.1"
}

description = {
   homepage = "https://github.com/luau-project/lua-hash",
   summary = [[Hash algorithms for Lua]],
   detailed = [=[
lua-hash is a lightweight, native library providing hash algorithms for Lua.

Visit the repository for more information.]=],
   license = "MIT"
}

dependencies = {
    "lua >= 5.1"
}

local function external_dependencies_plat()
    return {
        ["CRYPTO"] = {
            header = "openssl/evp.h"
        }
    }
end

external_dependencies = {
    platforms = {
        linux = external_dependencies_plat(),
        freebsd = external_dependencies_plat(),
        openbsd = external_dependencies_plat(),
        netbsd = external_dependencies_plat(),
        dragonfly = external_dependencies_plat()
    }
}

local function build_plat(plat)
    if (plat == "macosx" or plat == "macos") then
        return {
            type = "make",
            makefile = "Makefile.macosx",
            build_variables = {                                                                               
                CFLAGS = "$(CFLAGS)",                                                                         
                LIBFLAG = "$(LIBFLAG)",
                CFLAGS_EXTRA = "-DLUA_HASH_BUILD_SHARED -DLUA_HASH_USE_APPLE",
                LIBFLAG_EXTRA = "",
                LUA_INCDIR = "$(LUA_INCDIR)",
                OBJ_EXTENSION = "$(OBJ_EXTENSION)",
                LIB_EXTENSION = "$(LIB_EXTENSION)"
            },
            install_variables = {
                INSTALL_PREFIX = "$(PREFIX)",
                INSTALL_LIBDIR = "$(LIBDIR)",
                LUA_VERSION = "$(LUA_VERSION)",
                LIB_EXTENSION = "$(LIB_EXTENSION)"
            }
        }
    elseif (plat == "windows" or plat == "cygwin") then
        return {
            type = "builtin",
            modules = {
                ["lua-hash"] = {
                    sources = { "src/lua-hash.c" },
                    libraries = { "bcrypt" },
                    defines = { "LUA_HASH_BUILD_SHARED", "LUA_HASH_USE_WIN32" },
                    incdirs = { "src" },
                    libdirs = { }
                }
            }
        }
    elseif (plat == "linux" or plat == "bsd") then
        return {
            type = "builtin",
            modules = {
                ["lua-hash"] = {
                    sources = { "src/lua-hash.c" },
                    libraries = { "crypto" },
                    defines = { "LUA_HASH_BUILD_SHARED", "LUA_HASH_USE_OPENSSL" },
                    incdirs = { "src", "$(CRYPTO_INCDIR)" },
                    libdirs = { "$(CRYPTO_LIBDIR)" }
                }
            }
        }
    else
        error("Unknown platform", 2)
    end
end

build = {
    platforms = {
        macosx = build_plat("macosx"),
        macos = build_plat("macos"),
        windows = build_plat("windows"),
        cygwin = build_plat("cygwin"),
        linux = build_plat("linux"),
        freebsd = build_plat("bsd"),
        openbsd = build_plat("bsd"),
        netbsd = build_plat("bsd"),
        dragonfly = build_plat("bsd")
    }
}
