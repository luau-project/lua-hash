/*
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
*/

#include "lua-hash.h"

#if defined(LUA_HASH_USE_WIN32)
#include <ntstatus.h>
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <windows.h>
#ifdef WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#endif
#include <bcrypt.h>
#elif defined(LUA_HASH_USE_APPLE)
#include <CommonCrypto/CommonCrypto.h>
#elif defined(LUA_HASH_USE_OPENSSL)
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <luaconf.h>
#include <lauxlib.h>
#include <lualib.h>

#define LUA_HASH_METATABLE "lua_hash_metatable"

/* Start of LuaHashAlgorithm */

#define LUA_HASH_ALGORITHM_METATABLE "lua_hash_algorithm_metatable"

typedef enum tagLuaHashAlgorithmId {
    LUA_HASH_ALGORITHM_NONE,/*
    LUA_HASH_ALGORITHM_MD2,
    LUA_HASH_ALGORITHM_MD4,*/
    LUA_HASH_ALGORITHM_MD5,
    LUA_HASH_ALGORITHM_SHA1,
    LUA_HASH_ALGORITHM_SHA256,
    LUA_HASH_ALGORITHM_SHA384,
    LUA_HASH_ALGORITHM_SHA512,
    LUA_HASH_ALGORITHM_LAST
} LuaHashAlgorithmId;

#if defined(LUA_HASH_USE_APPLE)
/* prototypes for LuaDigest */
typedef int (*LuaDigestInit)(void *ctx_handle);
typedef int (*LuaDigestUpdate)(void *ctx_handle, const void *data, CC_LONG len);
typedef int (*LuaDigestFinal)(unsigned char *md, void *ctx_handle);

/* MD2 functions */
/*
static int LuaDigestInit_MD2(void *ctx_handle) { return CC_MD2_Init((CC_MD2_CTX *)ctx_handle); }
static int LuaDigestUpdate_MD2(void *ctx_handle, const void *data, CC_LONG len) { return CC_MD2_Update((CC_MD2_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_MD2(unsigned char *md, void *ctx_handle) { return CC_MD2_Final(md, (CC_MD2_CTX *)ctx_handle); }
*/
/* MD4 functions */

/*
static int LuaDigestInit_MD4(void *ctx_handle) { return CC_MD4_Init((CC_MD4_CTX *)ctx_handle); }
static int LuaDigestUpdate_MD4(void *ctx_handle, const void *data, CC_LONG len) { return CC_MD4_Update((CC_MD4_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_MD4(unsigned char *md, void *ctx_handle) { return CC_MD4_Final(md, (CC_MD4_CTX *)ctx_handle); }
*/
/* MD5 functions */

static int LuaDigestInit_MD5(void *ctx_handle) { return CC_MD5_Init((CC_MD5_CTX *)ctx_handle); }
static int LuaDigestUpdate_MD5(void *ctx_handle, const void *data, CC_LONG len) { return CC_MD5_Update((CC_MD5_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_MD5(unsigned char *md, void *ctx_handle) { return CC_MD5_Final(md, (CC_MD5_CTX *)ctx_handle); }

/* SHA1 functions */

static int LuaDigestInit_SHA1(void *ctx_handle) { return CC_SHA1_Init((CC_SHA1_CTX *)ctx_handle); }
static int LuaDigestUpdate_SHA1(void *ctx_handle, const void *data, CC_LONG len) { return CC_SHA1_Update((CC_SHA1_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_SHA1(unsigned char *md, void *ctx_handle) { return CC_SHA1_Final(md, (CC_SHA1_CTX *)ctx_handle); }

/* SHA256 functions */

static int LuaDigestInit_SHA256(void *ctx_handle) { return CC_SHA256_Init((CC_SHA256_CTX *)ctx_handle); }
static int LuaDigestUpdate_SHA256(void *ctx_handle, const void *data, CC_LONG len) { return CC_SHA256_Update((CC_SHA256_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_SHA256(unsigned char *md, void *ctx_handle) { return CC_SHA256_Final(md, (CC_SHA256_CTX *)ctx_handle); }

/* SHA384 functions */

static int LuaDigestInit_SHA384(void *ctx_handle) { return CC_SHA384_Init((CC_SHA512_CTX *)ctx_handle); }
static int LuaDigestUpdate_SHA384(void *ctx_handle, const void *data, CC_LONG len) { return CC_SHA384_Update((CC_SHA512_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_SHA384(unsigned char *md, void *ctx_handle) { return CC_SHA384_Final(md, (CC_SHA512_CTX *)ctx_handle); }

/* SHA512 functions */

static int LuaDigestInit_SHA512(void *ctx_handle) { return CC_SHA512_Init((CC_SHA512_CTX *)ctx_handle); }
static int LuaDigestUpdate_SHA512(void *ctx_handle, const void *data, CC_LONG len) { return CC_SHA512_Update((CC_SHA512_CTX *)ctx_handle, data, len); }
static int LuaDigestFinal_SHA512(unsigned char *md, void *ctx_handle) { return CC_SHA512_Final(md, (CC_SHA512_CTX *)ctx_handle); }


#endif

typedef struct tagLuaHashAlgorithmEntry
{
    const char *name;
    LuaHashAlgorithmId id;

#if defined(LUA_HASH_USE_WIN32)
    /* properties to be used at LuaHashAlgorithm creation */
    LPCWSTR implementation;
#elif defined(LUA_HASH_USE_APPLE)
    /* properties to forward to LuaDigestContext and LuaDigest */
    size_t ctx_size;
    LuaDigestInit init_fn;
    LuaDigestUpdate update_fn;
    LuaDigestFinal final_fn;

    /* digest length in bytes */
    size_t digest_length;

#elif defined(LUA_HASH_USE_OPENSSL)
    /* nothing */
#endif
    
} LuaHashAlgorithmEntry;

typedef struct tagLuaHashAlgorithm
{
    int is_open;
    LuaHashAlgorithmId id;

    /* digest length in bytes */
    size_t digest_length;

#if defined(LUA_HASH_USE_WIN32)
    /* algorithm handle */
    BCRYPT_ALG_HANDLE algorithm_handle;
#elif defined(LUA_HASH_USE_APPLE)
    /* properties to forward to LuaDigestContext and LuaDigest */
    size_t ctx_size;
    LuaDigestInit init_fn;
    LuaDigestUpdate update_fn;
    LuaDigestFinal final_fn;

#elif defined(LUA_HASH_USE_OPENSSL)
    /* algorithm handle */
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
    EVP_MD *algorithm_handle;
#else
    const EVP_MD *algorithm_handle;
#endif
#endif

} LuaHashAlgorithm;

static const LuaHashAlgorithmEntry lua_hash_algorithms[] = {
#if defined(LUA_HASH_USE_WIN32)
    /*
    {"MD2", LUA_HASH_ALGORITHM_MD2, BCRYPT_MD2_ALGORITHM},
    {"MD4", LUA_HASH_ALGORITHM_MD4, BCRYPT_MD4_ALGORITHM},*/
    {"MD5", LUA_HASH_ALGORITHM_MD5, BCRYPT_MD5_ALGORITHM},
    {"SHA1", LUA_HASH_ALGORITHM_SHA1, BCRYPT_SHA1_ALGORITHM},
    {"SHA256", LUA_HASH_ALGORITHM_SHA256, BCRYPT_SHA256_ALGORITHM},
    {"SHA384", LUA_HASH_ALGORITHM_SHA384, BCRYPT_SHA384_ALGORITHM},
    {"SHA512", LUA_HASH_ALGORITHM_SHA512, BCRYPT_SHA512_ALGORITHM},
    {NULL, LUA_HASH_ALGORITHM_LAST, NULL}
#elif defined(LUA_HASH_USE_APPLE)
    /*
    {"MD2", LUA_HASH_ALGORITHM_MD2, sizeof(CC_MD2_CTX), LuaDigestInit_MD2, LuaDigestUpdate_MD2, LuaDigestFinal_MD2, CC_MD2_DIGEST_LENGTH},
    {"MD4", LUA_HASH_ALGORITHM_MD4, sizeof(CC_MD4_CTX), LuaDigestInit_MD4, LuaDigestUpdate_MD4, LuaDigestFinal_MD4, CC_MD4_DIGEST_LENGTH},*/
    {"MD5", LUA_HASH_ALGORITHM_MD5, sizeof(CC_MD5_CTX), LuaDigestInit_MD5, LuaDigestUpdate_MD5, LuaDigestFinal_MD5, CC_MD5_DIGEST_LENGTH},
    {"SHA1", LUA_HASH_ALGORITHM_SHA1, sizeof(CC_SHA1_CTX), LuaDigestInit_SHA1, LuaDigestUpdate_SHA1, LuaDigestFinal_SHA1, CC_SHA1_DIGEST_LENGTH},
    {"SHA256", LUA_HASH_ALGORITHM_SHA256, sizeof(CC_SHA256_CTX), LuaDigestInit_SHA256, LuaDigestUpdate_SHA256, LuaDigestFinal_SHA256, CC_SHA256_DIGEST_LENGTH},
    {"SHA384", LUA_HASH_ALGORITHM_SHA384, sizeof(CC_SHA512_CTX), LuaDigestInit_SHA384, LuaDigestUpdate_SHA384, LuaDigestFinal_SHA384, CC_SHA384_DIGEST_LENGTH},
    {"SHA512", LUA_HASH_ALGORITHM_SHA512, sizeof(CC_SHA512_CTX), LuaDigestInit_SHA512, LuaDigestUpdate_SHA512, LuaDigestFinal_SHA512, CC_SHA512_DIGEST_LENGTH},
    {NULL, LUA_HASH_ALGORITHM_LAST, 0, NULL, NULL, NULL, 0}
#else
    /*
    {"MD2", LUA_HASH_ALGORITHM_MD2},
    {"MD4", LUA_HASH_ALGORITHM_MD4},*/
    {"MD5", LUA_HASH_ALGORITHM_MD5},
    {"SHA1", LUA_HASH_ALGORITHM_SHA1},
    {"SHA256", LUA_HASH_ALGORITHM_SHA256},
    {"SHA384", LUA_HASH_ALGORITHM_SHA384},
    {"SHA512", LUA_HASH_ALGORITHM_SHA512},
    {NULL, LUA_HASH_ALGORITHM_LAST}
#endif
};

static int lua_hash_algorithm_find_index(const char *name)
{
    LuaHashAlgorithmId id = LUA_HASH_ALGORITHM_NONE;
    int i = 0;
    int count = ((sizeof(lua_hash_algorithms)) / (sizeof(lua_hash_algorithms[0]))) - 1;
    while (id == LUA_HASH_ALGORITHM_NONE && i < count)
    {
        if (strcmp(name, lua_hash_algorithms[i].name) == 0)
        {
            id = lua_hash_algorithms[i].id;
        }
        else
        {
            i++;
        }
    }
    return id == LUA_HASH_ALGORITHM_NONE ? (-1) : i;
}

static LuaHashAlgorithm *lua_hash_algorithm_check(lua_State *L, int index)
{
    void *ud = luaL_checkudata(L, index, LUA_HASH_ALGORITHM_METATABLE);
    luaL_argcheck(L, ud != NULL, index, "hash algorithm expected");
    return (LuaHashAlgorithm *)ud;
}

static int lua_hash_algorithm_open(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    int entry_index = lua_hash_algorithm_find_index(name);

    if (entry_index == -1)
    {
        luaL_error(L, "hash algorithm not found");
    }

    void *ud = lua_newuserdata(L, sizeof(LuaHashAlgorithm));
    if (ud == NULL)
    {
        luaL_error(L, "Failed to create hash algorithm userdata");
    }

    luaL_getmetatable(L, LUA_HASH_ALGORITHM_METATABLE);
    lua_setmetatable(L, -2);

    LuaHashAlgorithm *algo = (LuaHashAlgorithm *)ud;

    algo->is_open = 0;

#if defined(LUA_HASH_USE_WIN32)
    NTSTATUS status;
    
    status = BCryptOpenAlgorithmProvider(
        &(algo->algorithm_handle),
        lua_hash_algorithms[entry_index].implementation,
        NULL,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        luaL_error(L, "Error opening algorithm provider through BCryptOpenAlgorithmProvider. Most likely, it is unsupported by the underlying bcrypt library.");
    }

    ULONG hashSize = 0;
    ULONG copiedCount = 0;

    status = BCryptGetProperty(
        algo->algorithm_handle,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)(&hashSize),
        sizeof(ULONG),
        &copiedCount,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        BCryptCloseAlgorithmProvider(algo->algorithm_handle, 0);
        luaL_error(L, "Failed to get the digest length in bytes through BCryptGetProperty.");
    }

    algo->digest_length = (size_t)hashSize;

#elif defined(LUA_HASH_USE_APPLE)
    
    algo->ctx_size = lua_hash_algorithms[entry_index].ctx_size;
    algo->init_fn = lua_hash_algorithms[entry_index].init_fn;
    algo->update_fn = lua_hash_algorithms[entry_index].update_fn;
    algo->final_fn = lua_hash_algorithms[entry_index].final_fn;
    algo->digest_length = (size_t)(lua_hash_algorithms[entry_index].digest_length);

#elif defined(LUA_HASH_USE_OPENSSL)

#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
    algo->algorithm_handle = EVP_MD_fetch(NULL, name, NULL);

    if (algo->algorithm_handle == NULL)
    {
        luaL_error(L, "Error opening algorithm provider through EVP_MD_fetch. Most likely, it is unsupported by the underlying OPENSSL library.");
    }
#else
    algo->algorithm_handle = EVP_get_digestbyname(name);

    if (algo->algorithm_handle == NULL)
    {
        luaL_error(L, "Error opening algorithm provider through EVP_get_digestbyname. Most likely, it is unsupported by the underlying OPENSSL library.");
    }
#endif

    algo->digest_length = (size_t)(EVP_MD_size(algo->algorithm_handle));
#endif
    
    algo->is_open = 1;
    algo->id = lua_hash_algorithms[entry_index].id;

    return 1;
}

static int lua_hash_algorithm_close(lua_State *L)
{
    LuaHashAlgorithm *algo = lua_hash_algorithm_check(L, 1);

    if (algo->is_open)
    {

#if defined(LUA_HASH_USE_WIN32)
        NTSTATUS status = BCryptCloseAlgorithmProvider(algo->algorithm_handle, 0);
        if (status != STATUS_SUCCESS)
        {
            luaL_error(L, "Error closing algorithm provider");
        }

#elif defined(LUA_HASH_USE_APPLE)
        /* do nothing */
#elif defined(LUA_HASH_USE_OPENSSL)
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
        EVP_MD_free(algo->algorithm_handle);
#else
        /* do nothing */
#endif
#endif

        algo->is_open = 0;
    }

    return 0;
}

static int lua_hash_algorithm_new_index(lua_State *L)
{
    luaL_error(L, "Read-only object");
    return 0;
}

static const luaL_Reg lua_hash_algorithm_functions[] = {
    {"open", lua_hash_algorithm_open},
    {"close", lua_hash_algorithm_close},
    {"__gc", lua_hash_algorithm_close},
    {NULL, NULL}
};

/* End of LuaHashAlgorithm */


/* Start of LuaDigestContext */

#define LUA_HASH_DIGEST_CONTEXT_METATABLE "lua_hash_digest_context_metatable"

typedef struct tagLuaDigestContext
{
    int is_open;
    int algo_ref;
    int finalized_by_digest;

#if defined(LUA_HASH_USE_WIN32)
    /* digest handle */
    BCRYPT_HASH_HANDLE ctx_handle;
#elif defined(LUA_HASH_USE_APPLE)
    /* digest handle */
    void *ctx_handle;
#elif defined(LUA_HASH_USE_OPENSSL)
    /* digest handle */
    EVP_MD_CTX *ctx_handle;
#endif

} LuaDigestContext;

static LuaDigestContext *lua_hash_digest_context_check(lua_State *L, int index)
{
    void *ud = luaL_checkudata(L, index, LUA_HASH_DIGEST_CONTEXT_METATABLE);
    luaL_argcheck(L, ud != NULL, index, "digest context expected");
    return (LuaDigestContext *)ud;
}

static int lua_hash_digest_context_new(lua_State *L)
{
    LuaHashAlgorithm *algo = lua_hash_algorithm_check(L, 1);
    luaL_argcheck(L, algo->is_open, 1, "algorithm cannot be closed");

    void *ud = lua_newuserdata(L, sizeof(LuaDigestContext));
    if (ud == NULL)
    {
        luaL_error(L, "Userdata creation for the digest context failed");
    }

    luaL_getmetatable(L, LUA_HASH_DIGEST_CONTEXT_METATABLE);
    lua_setmetatable(L, -2);

    LuaDigestContext *ctx = (LuaDigestContext *)ud;
    
#if defined(LUA_HASH_USE_WIN32)
    NTSTATUS status = BCryptCreateHash(
        algo->algorithm_handle,
        &(ctx->ctx_handle),
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        luaL_error(L, "Error creating context through BCryptCreateHash");
    }

#elif defined(LUA_HASH_USE_APPLE)
    ctx->ctx_handle = malloc(algo->ctx_size);
    if (ctx->ctx_handle == NULL)
    {
        luaL_error(L, "Memory allocation for the digest context failed");
    }
#elif defined(LUA_HASH_USE_OPENSSL)
    ctx->ctx_handle = EVP_MD_CTX_create();
    if (ctx->ctx_handle == NULL)
    {
        luaL_error(L, "Memory allocation for the digest context failed");
    }
#endif

    lua_pushvalue(L, 1);
    ctx->algo_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->is_open = 1;
    ctx->finalized_by_digest = 0;

    return 1;
}

static int lua_hash_digest_context_close(lua_State *L)
{
    LuaDigestContext *ctx = lua_hash_digest_context_check(L, 1);
    
    if (ctx->is_open)
    {

#if defined(LUA_HASH_USE_WIN32)
        NTSTATUS status = BCryptDestroyHash(ctx->ctx_handle);
        if (status != STATUS_SUCCESS)
        {
            luaL_error(L, "Error closing context through BCryptDestroyHash");
        }

#elif defined(LUA_HASH_USE_APPLE)
        free(ctx->ctx_handle);
#elif defined(LUA_HASH_USE_OPENSSL)
        EVP_MD_CTX_destroy(ctx->ctx_handle);
#endif

        luaL_unref(L, LUA_REGISTRYINDEX, ctx->algo_ref);

        ctx->is_open = 0;
    }

    return 0;
}

static int lua_hash_digest_context_new_index(lua_State *L)
{
    luaL_error(L, "Read-only object");
    return 0;
}

static const luaL_Reg lua_hash_digest_context_functions[] = {
    {"new", lua_hash_digest_context_new},
    {"close", lua_hash_digest_context_close},
    {"__gc", lua_hash_digest_context_close},
    {NULL, NULL}
};

/* End of LuaDigestContext */

/* Start of LuaDigest */

#define LUA_HASH_DIGEST_METATABLE "lua_hash_digest_metatable"

typedef struct tagLuaDigest
{
    int ctx_ref;

} LuaDigest;

static LuaDigest *lua_hash_digest_check(lua_State *L, int index)
{
    void *ud = luaL_checkudata(L, index, LUA_HASH_DIGEST_METATABLE);
    luaL_argcheck(L, ud != NULL, index, "digest expected");
    return (LuaDigest *)ud;
}

static int lua_hash_digest_new(lua_State *L)
{
    LuaDigestContext *ctx = lua_hash_digest_context_check(L, 1);
    luaL_argcheck(L, ctx->is_open, 1, "digest context cannot be closed");

    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->algo_ref);
    void *ud_algo = luaL_checkudata(L, -1, LUA_HASH_ALGORITHM_METATABLE);
    if (ud_algo == NULL)
    {
        lua_pop(L, 1);
        luaL_error(L, "algorithm cannot be closed");
    }

    LuaHashAlgorithm *algo = (LuaHashAlgorithm *)ud_algo;
    if (!algo->is_open)
    {
        lua_pop(L, 1);
        luaL_error(L, "the algorithm bound to the context was closed");
    }

#if defined(LUA_HASH_USE_WIN32)
    /* nothing */

#elif defined(LUA_HASH_USE_APPLE)
    if (!algo->init_fn(ctx->ctx_handle))
    {
        lua_pop(L, 1);
        luaL_error(L, "Error intializing digest through init");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
    if (!EVP_DigestInit(ctx->ctx_handle, algo->algorithm_handle))
    {
        lua_pop(L, 1);
        luaL_error(L, "Error intializing digest through EVP_DigestInit");
    }

#endif

    /* pop the algorithm from the stack*/
    lua_pop(L, 1);

    void *ud = lua_newuserdata(L, sizeof(LuaDigest));
    if (ud == NULL)
    {
        luaL_error(L, "Userdata creation for the digest context failed");
    }

    luaL_getmetatable(L, LUA_HASH_DIGEST_METATABLE);
    lua_setmetatable(L, -2);

    LuaDigest *digest = (LuaDigest *)ud;

    lua_pushvalue(L, 1);
    digest->ctx_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 1;
}

typedef struct tagLuaDigestInfo
{
    LuaHashAlgorithm *algo;
    LuaDigestContext *ctx;
    LuaDigest *digest;
    
} LuaDigestInfo;

static void lua_hash_digest_validate(lua_State *L, LuaDigestInfo *info)
{
    if (info == NULL)
    {
        luaL_error(L, "Internal error: LuaDigestInfo is null");
    }

    LuaDigest *digest = lua_hash_digest_check(L, 1);

    lua_rawgeti(L, LUA_REGISTRYINDEX, digest->ctx_ref);
    void *ud_ctx = luaL_checkudata(L, -1, LUA_HASH_DIGEST_CONTEXT_METATABLE);
    if (ud_ctx == NULL)
    {
        lua_pop(L, 1);
        luaL_error(L, "context cannot be closed");
    }

    LuaDigestContext *ctx = (LuaDigestContext *)ud_ctx;
    if (!ctx->is_open)
    {
        lua_pop(L, 1);
        luaL_error(L, "the context bound to the digest was closed");
    }

    if (ctx->finalized_by_digest)
    {
        lua_pop(L, 1);
        luaL_error(L, "the digest already finalized the context");
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->algo_ref);
    void *ud_algo = luaL_checkudata(L, -1, LUA_HASH_ALGORITHM_METATABLE);
    if (ud_algo == NULL)
    {
        lua_pop(L, 2);
        luaL_error(L, "algorithm cannot be closed");
    }

    LuaHashAlgorithm *algo = (LuaHashAlgorithm *)ud_algo;
    if (!algo->is_open)
    {
        lua_pop(L, 2);
        luaL_error(L, "the algorithm bound to the context was closed");
    }

    info->algo = algo;
    info->ctx = ctx;
    info->digest = digest;

    lua_pop(L, 2);
}

static void lua_hash_digest_update_core(lua_State *L, unsigned char *buffer, size_t size, LuaDigestInfo *info, int free_buffer)
{
#if defined(LUA_HASH_USE_WIN32)
    NTSTATUS status = BCryptHashData(
        info->ctx->ctx_handle,
        buffer,
        (ULONG)size,
        0
    );
    if (status != STATUS_SUCCESS)
    {
        if (free_buffer)
        {
            free((void *)buffer);
        }
        luaL_error(L, "Error hashing data through BCryptHashData");
    }

#elif defined(LUA_HASH_USE_APPLE)
    if (!info->algo->update_fn(info->ctx->ctx_handle, (const void *)buffer, (CC_LONG)size))
    {
        if (free_buffer)
        {
            free((void *)buffer);
        }
        luaL_error(L, "Error hashing data through update");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
    if (!EVP_DigestUpdate(info->ctx->ctx_handle, (const void *)buffer, size))
    {
        if (free_buffer)
        {
            free((void *)buffer);
        }
        luaL_error(L, "Error hashing data through EVP_DigestUpdate");
    }
#endif

    if (free_buffer)
    {
        free((void *)buffer);
    }
}

static int lua_hash_digest_update(lua_State *L)
{
    LuaDigestInfo info;
    lua_hash_digest_validate(L, &info);

    if (lua_istable(L, 2))
    {

#if LUA_VERSION_NUM == 501
        lua_Integer table_size = lua_objlen(L, 2);
#else
        lua_Integer table_size = luaL_len(L, 2);
#endif
        if (table_size == 0)
        {
            luaL_error(L, "table is empty");
        }

        if (table_size >= UINT_MAX)
        {
            luaL_error(L, "table is too long");
        }

        unsigned int size = (unsigned int)table_size;
        unsigned char *buffer = (unsigned char *)malloc(size * sizeof(unsigned char));

        if (buffer == NULL)
        {
            luaL_error(L, "Memory allocation for the update buffer failed");
        }

        lua_Integer i = 1;
        while (i <= table_size)
        {
            lua_pushinteger(L, i);
            lua_gettable(L, 2);
            lua_Integer value = luaL_checkinteger(L, -1);
            lua_pop(L, 1);

            if (0 <= value && value <= 0xFF)
            {
                buffer[i - 1] = (unsigned char)value;
            }
            else
            {
                free((void *)buffer);
                char errMsg[100];
                sprintf(errMsg, "value at table index %u is out of 0 - 255 range", (unsigned int)i);
                luaL_error(L, errMsg);
            }

            i++;
        }
        
        /* #5 argument == 1 allows the buffer to be freed */
        lua_hash_digest_update_core(L, buffer, (size_t)size, &info, 1);
    }
    else if (lua_isstring(L, 2))
    {
        size_t size;
        const char *data = luaL_checklstring(L, 2, &size);

        luaL_argcheck(L, size > 0, 2, "string cannot be empty");

        /* #5 argument == 1 allows the buffer to be freed */
        lua_hash_digest_update_core(L, (unsigned char *)data, size, &info, 0);
    }
    else
    {
        luaL_error(L, "#2 argument must be a table or string");
    }

    return 0;
}

static void lua_hash_digest_finalize_core(lua_State *L, void *buffer, LuaDigestInfo *info, int free_buffer)
{
#if defined(LUA_HASH_USE_WIN32)
    
    NTSTATUS status = BCryptFinishHash(
        info->ctx->ctx_handle,
        (PUCHAR)buffer,
        info->algo->digest_length,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        if (free_buffer)
        {
            free(buffer);
        }
        luaL_error(L, "Failed to finalize hash through BCryptFinishHash");
    }

#elif defined(LUA_HASH_USE_APPLE)
            
    if (!info->algo->final_fn((unsigned char *)buffer, info->ctx->ctx_handle))
    {
        if (free_buffer)
        {
            free(buffer);
        }
        luaL_error(L, "Failed to finalize hash through final");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
            
    unsigned int len = 0;
    if (!EVP_DigestFinal(info->ctx->ctx_handle, (unsigned char *)buffer, &len))
    {
        if (free_buffer)
        {
            free(buffer);
        }
        luaL_error(L, "Failed to finalize hash through EVP_DigestFinal_ex");
    }

#endif
}

static void lua_hash_digest_finalize_string_core(lua_State *L, LuaDigestInfo *info, int return_hex)
{
    void *buffer = malloc(info->algo->digest_length * sizeof(unsigned char));
    if (buffer == NULL)
    {
        luaL_error(L, "Failed to allocate memory for the digest output");
    }
    
    /* #4 argument == 1 allows the buffer to be freed */
    lua_hash_digest_finalize_core(L, buffer, info, 1);

    if (return_hex)
    {
        size_t hex_string_len = 2 * info->algo->digest_length;
        char *hex_string = (char *)(malloc((hex_string_len + 1) * sizeof(char)));
        if (hex_string == NULL)
        {
            luaL_error(L, "Failed to allocate memory for the digest");
        }

        unsigned char *buffer_cast = (unsigned char *)buffer;

        for (size_t i = 0, hex_offset = 0; i < info->algo->digest_length; i++, hex_offset += 2)
        {
            sprintf(hex_string + hex_offset, "%02x", buffer_cast[i]);
        }

        lua_pushlstring(L, (const char *)hex_string, hex_string_len);

        free(hex_string);
    }
    else
    {
        lua_pushlstring(L, (const char *)buffer, info->algo->digest_length);
    }

    free(buffer);
}

static int lua_hash_digest_finalize(lua_State *L)
{
    LuaDigestInfo info;
    lua_hash_digest_validate(L, &info);

    if (lua_isnoneornil(L, 2))
    {
        lua_hash_digest_finalize_string_core(L, &info, 1);
    }
    else if (lua_istable(L, 2))
    {
        lua_pushstring(L, "type");
        lua_gettable(L, 2);
        
        if (lua_isstring(L, -1))
        {
            const char *return_type = lua_tostring(L, -1);

            if (strcmp(return_type, "string") == 0)
            {
                lua_pushstring(L, "hex");
                lua_gettable(L, 2);
                int return_hex = lua_toboolean(L, -1);
                
                /* remove both return_type and return_hex from stack */
                lua_pop(L, 2);

                lua_hash_digest_finalize_string_core(L, &info, return_hex);
            }
            else if (strcmp(return_type, "table") == 0)
            {
                /* remove return_type from stack */
                lua_pop(L, 1);

                void *buffer = malloc(info.algo->digest_length * sizeof(unsigned char));
                if (buffer == NULL)
                {
                    luaL_error(L, "Failed to allocate memory for the digest output");
                }
                
                /* #4 argument == 1 allows the buffer to be freed */
                lua_hash_digest_finalize_core(L, buffer, &info, 1);

                lua_createtable(L, info.algo->digest_length, 0);

                unsigned char *buffer_cast = (unsigned char *)buffer;

                for (int i = 1; i <= info.algo->digest_length; i++)
                {
                    lua_pushinteger(L, i);
                    lua_pushinteger(L, 0xFF & (buffer_cast[i - 1]));
                    lua_settable(L, -3);
                }

                free(buffer);
            }
            else
            {
                /* remove return_type from the stack */
                lua_pop(L, 1);
                luaL_error(L, "type field must be 'string' or 'table'");
            }
        }
        else
        {
            /* remove return_type from the stack */
            lua_pop(L, 1);
            luaL_error(L, "the 'type' field must be have a type of 'string' or 'table'");
        }
    }
    else
    {
        luaL_error(L, "#2 argument must be of type 'nil' or 'table'");
    }

    /* prevent further usage of the digest */
    info.ctx->finalized_by_digest = 1;

    return 1;
}

static int lua_hash_digest_new_index(lua_State *L)
{
    luaL_error(L, "Read-only object");
    return 0;
}

static const luaL_Reg lua_hash_digest_functions[] = {
    {"new", lua_hash_digest_new},
    {"update", lua_hash_digest_update},
    {"finalize", lua_hash_digest_finalize},
    {NULL, NULL}
};

/* End of LuaDigest */

/* Start of LuaOneShot */

static int lua_hash_oneshot(lua_State *L)
{
    /* start of algorithm open */
    const char *name = luaL_checkstring(L, 1);

    int entry_index = lua_hash_algorithm_find_index(name);

    if (entry_index == -1)
    {
        luaL_error(L, "hash algorithm not found");
    }

    size_t size;
    const char *data = luaL_checklstring(L, 2, &size);

    luaL_argcheck(L, size > 0, 2, "string cannot be empty");

    size_t digest_length;

#if defined(LUA_HASH_USE_WIN32)
    BCRYPT_ALG_HANDLE algorithm_handle;
    NTSTATUS status;
    
    status = BCryptOpenAlgorithmProvider(
        &algorithm_handle,
        lua_hash_algorithms[entry_index].implementation,
        NULL,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        luaL_error(L, "Error opening algorithm provider through BCryptOpenAlgorithmProvider. Most likely, it is unsupported by the underlying bcrypt library.");
    }

    ULONG hashSize = 0;
    ULONG copiedCount = 0;

    status = BCryptGetProperty(
        algorithm_handle,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)(&hashSize),
        sizeof(ULONG),
        &copiedCount,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        BCryptCloseAlgorithmProvider(algorithm_handle, 0);
        luaL_error(L, "Failed to get the digest length in bytes through BCryptGetProperty.");
    }

    digest_length = (size_t)hashSize;

#elif defined(LUA_HASH_USE_APPLE)
    size_t ctx_size;
    LuaDigestInit init_fn;
    LuaDigestUpdate update_fn;
    LuaDigestFinal final_fn;
    
    ctx_size = lua_hash_algorithms[entry_index].ctx_size;
    init_fn = lua_hash_algorithms[entry_index].init_fn;
    update_fn = lua_hash_algorithms[entry_index].update_fn;
    final_fn = lua_hash_algorithms[entry_index].final_fn;
    digest_length = (size_t)(lua_hash_algorithms[entry_index].digest_length);

#elif defined(LUA_HASH_USE_OPENSSL)
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
    EVP_MD *algorithm_handle;
    algorithm_handle = EVP_MD_fetch(NULL, name, NULL);

    if (algorithm_handle == NULL)
    {
        luaL_error(L, "Error opening algorithm provider through EVP_MD_fetch. Most likely, it is unsupported by the underlying OPENSSL library.");
    }
#else
    const EVP_MD *algorithm_handle;
    algorithm_handle = EVP_get_digestbyname(name);

    if (algorithm_handle == NULL)
    {
        luaL_error(L, "Error opening algorithm provider through EVP_get_digestbyname. Most likely, it is unsupported by the underlying OPENSSL library.");
    }
#endif

    digest_length = (size_t)(EVP_MD_size(algorithm_handle));
#endif
    /* end of algorithm open */

    /* begin of context new */
#if defined(LUA_HASH_USE_WIN32)
    /* digest handle */
    BCRYPT_HASH_HANDLE ctx_handle;
    
    status = BCryptCreateHash(
        algorithm_handle,
        &ctx_handle,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        BCryptCloseAlgorithmProvider(algorithm_handle, 0);
        luaL_error(L, "Error creating context through BCryptCreateHash");
    }
#elif defined(LUA_HASH_USE_APPLE)
    /* digest handle */
    void *ctx_handle;
    ctx_handle = malloc(ctx_size);
    if (ctx_handle == NULL)
    {
        luaL_error(L, "Memory allocation for the digest context failed");
    }
#elif defined(LUA_HASH_USE_OPENSSL)
    /* digest handle */
    EVP_MD_CTX *ctx_handle;
    ctx_handle = EVP_MD_CTX_create();
    if (ctx_handle == NULL)
    {
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
        EVP_MD_free(algorithm_handle);
#else
        /* do nothing */
#endif
        luaL_error(L, "Memory allocation for the digest context failed");
    }
#endif
    /* end of context new */

    /* begin of digest new */
#if defined(LUA_HASH_USE_WIN32)
    /* nothing */

#elif defined(LUA_HASH_USE_APPLE)
    if (!init_fn(ctx_handle))
    {
        free(ctx_handle);
        luaL_error(L, "Error intializing digest through init");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
    if (!EVP_DigestInit(ctx_handle, algorithm_handle))
    {
        EVP_MD_CTX_destroy(ctx_handle);
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
        EVP_MD_free(algorithm_handle);
#else
        /* do nothing */
#endif
        luaL_error(L, "Error intializing digest through EVP_DigestInit");
    }

#endif
    /* end of digest new */

    /* begin of digest update */
#if defined(LUA_HASH_USE_WIN32)
    status = BCryptHashData(
        ctx_handle,
        (unsigned char *)data,
        (ULONG)size,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        BCryptDestroyHash(ctx_handle);
        BCryptCloseAlgorithmProvider(algorithm_handle, 0);
        luaL_error(L, "Error hashing data through BCryptHashData");
    }

#elif defined(LUA_HASH_USE_APPLE)
    if (!update_fn(ctx_handle, (const void *)data, (CC_LONG)size))
    {
        free(ctx_handle);
        luaL_error(L, "Error hashing data through update");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
    if (!EVP_DigestUpdate(ctx_handle, (const void *)data, size))
    {
        EVP_MD_CTX_destroy(ctx_handle);
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
        EVP_MD_free(algorithm_handle);
#else
        /* do nothing */
#endif
        luaL_error(L, "Error hashing data through EVP_DigestUpdate");
    }
#endif
    /* end of digest update */

    /* begin of digest finalize */
    void *output_buffer = malloc(digest_length * sizeof(unsigned char));
    if (output_buffer == NULL)
    {
        luaL_error(L, "Failed to allocate memory for the digest output");
    }

#if defined(LUA_HASH_USE_WIN32)
    
    status = BCryptFinishHash(
        ctx_handle,
        (PUCHAR)output_buffer,
        digest_length,
        0
    );

    if (status != STATUS_SUCCESS)
    {
        free(output_buffer);
        BCryptDestroyHash(ctx_handle);
        BCryptCloseAlgorithmProvider(algorithm_handle, 0);
        luaL_error(L, "Failed to finalize hash through BCryptFinishHash");
    }

#elif defined(LUA_HASH_USE_APPLE)

    if (!final_fn((unsigned char *)output_buffer, ctx_handle))
    {
        free(output_buffer);
        free(ctx_handle);
        luaL_error(L, "Failed to finalize hash through final");
    }

#elif defined(LUA_HASH_USE_OPENSSL)
            
    unsigned int len = 0;
    if (!EVP_DigestFinal(ctx_handle, (unsigned char *)output_buffer, &len))
    {
        free(output_buffer);
        EVP_MD_CTX_destroy(ctx_handle);
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
        EVP_MD_free(algorithm_handle);
#else
        /* do nothing */
#endif
        luaL_error(L, "Failed to finalize hash through EVP_DigestFinal_ex");
    }

#endif
    /* end of digest finalize */

    /* start of native resources cleanup */
#if defined(LUA_HASH_USE_WIN32)
    BCryptDestroyHash(ctx_handle);
    BCryptCloseAlgorithmProvider(algorithm_handle, 0);
#elif defined(LUA_HASH_USE_APPLE)
    free(ctx_handle);
#elif defined(LUA_HASH_USE_OPENSSL)
    EVP_MD_CTX_destroy(ctx_handle);
#if defined(OPENSSL_VERSION_PREREQ) && OPENSSL_VERSION_PREREQ(3,0)
    EVP_MD_free(algorithm_handle);
#else
        /* do nothing */
#endif
#endif
    /* end of native resources cleanup */

    /*
    ** converting the output
    ** to a hex-string
    */
    size_t hex_string_len = 2 * digest_length;
    char *hex_string = (char *)(malloc((hex_string_len + 1) * sizeof(char)));
    if (hex_string == NULL)
    {
        luaL_error(L, "Failed to allocate memory for the digest");
    }

    unsigned char *output_buffer_cast = (unsigned char *)output_buffer;

    for (size_t i = 0, hex_offset = 0; i < digest_length; i++, hex_offset += 2)
    {
        sprintf(hex_string + hex_offset, "%02x", output_buffer_cast[i]);
    }

    lua_pushlstring(L, (const char *)hex_string, hex_string_len);

    free(hex_string);

    free(output_buffer);

    return 1;
}

/* End of LuaOneShot */

static int lua_hash_new_index(lua_State *L)
{
    luaL_error(L, "Read-only object");
    return 0;
}

LUA_HASH_EXPORT int luaopen_hash(lua_State *L)
{
    lua_createtable(L, 0, 0);

    luaL_newmetatable(L, LUA_HASH_METATABLE);

    /* algorithm */
    lua_pushstring(L, "algorithm");
    lua_createtable(L, 0, 0);
    luaL_newmetatable(L, LUA_HASH_ALGORITHM_METATABLE);

#if LUA_VERSION_NUM == 501
    luaL_register(L, NULL, lua_hash_algorithm_functions);
#else
    luaL_setfuncs(L, lua_hash_algorithm_functions, 0);
#endif

    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    lua_pushstring(L, "__metatable");
    lua_pushboolean(L, 0);
    lua_settable(L, -3);

    lua_pushstring(L, "__newindex");
    lua_pushcfunction(L, lua_hash_algorithm_new_index);
    lua_settable(L, -3);

    lua_setmetatable(L, -2);
    lua_settable(L, -3);

    /* context */
    lua_pushstring(L, "context");
    lua_createtable(L, 0, 0);
    luaL_newmetatable(L, LUA_HASH_DIGEST_CONTEXT_METATABLE);

#if LUA_VERSION_NUM == 501
    luaL_register(L, NULL, lua_hash_digest_context_functions);
#else
    luaL_setfuncs(L, lua_hash_digest_context_functions, 0);
#endif

    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    lua_pushstring(L, "__metatable");
    lua_pushboolean(L, 0);
    lua_settable(L, -3);

    lua_pushstring(L, "__newindex");
    lua_pushcfunction(L, lua_hash_digest_context_new_index);
    lua_settable(L, -3);

    lua_setmetatable(L, -2);
    lua_settable(L, -3);

    /* digest */
    lua_pushstring(L, "digest");

    lua_createtable(L, 0, 0);
    luaL_newmetatable(L, LUA_HASH_DIGEST_METATABLE);

#if LUA_VERSION_NUM == 501
    luaL_register(L, NULL, lua_hash_digest_functions);
#else
    luaL_setfuncs(L, lua_hash_digest_functions, 0);
#endif

    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    lua_pushstring(L, "__metatable");
    lua_pushboolean(L, 0);
    lua_settable(L, -3);

    lua_pushstring(L, "__newindex");
    lua_pushcfunction(L, lua_hash_digest_new_index);
    lua_settable(L, -3);

    lua_setmetatable(L, -2);
    lua_settable(L, -3);

    /* hash lib */
    lua_pushstring(L, "oneshot");
    lua_pushcfunction(L, lua_hash_oneshot);
    lua_settable(L, -3);

    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    lua_pushstring(L, "__metatable");
    lua_pushboolean(L, 0);
    lua_settable(L, -3);

    lua_pushstring(L, "__newindex");
    lua_pushcfunction(L, lua_hash_new_index);
    lua_settable(L, -3);

    lua_setmetatable(L, -2);

    return 1;
}
