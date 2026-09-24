# lua-hash v0.0.3

* Fixed an invalid error message, which would crash on Lua 5.1 and Lua 5.2, when a table of bytes was provided with numbers out of 0 - 255 range. In-depth explanation: `%I%` flag on `luaL_error` is only allowed on Lua 5.3 or newer;
* Updated malloc calls to account for `sizeof(char)` and `sizeof(unsigned char)`;
* Through CI, the library is also verified to work correctly on ARM64;
* GitHub actions were pinned by commit id to avoid supply-chain attacks;
* Rockspec upload now lives on its own [publish.yml](./.github/workflows/publish.yml) workflow. This has the goal to avoid manual upload in case of intermitent failures (e.g.: connection issues or unavailable services). In the new publish behavior, the repository owner must trigger upload manually on GitHub for the rockspec to be published on LuaRocks website.

# lua-hash v0.0.2

* Added the possibility for all Unix-like distributions to build and install `lua-hash` using the binding for `OpenSSL`;
* Added a CI job to build and test `lua-hash` on [Cygwin](https://www.cygwin.com/);
* Now, as a Unix-like distribution, Cygwin builds as a Unix distro. Thus, in order to build on Cygwin, you need to install the package `libssl-devel`.

# lua-hash v0.0.1

* Initial release.
