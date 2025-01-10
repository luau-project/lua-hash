## Computing file checksums

In the Lua scripts provided here, you can compute a hash of files, even the big ones, efficiently by the provided algorithms.

## Usage

* Compute the MD5 checksum of a file using [md5sums.lua](./md5sums.lua) on this folder:
    ```lua
    lua md5sums.lua "path/to/my/file"
    ```

* Compute the SHA1 checksum of a file using [sha1sums.lua](./sha1sums.lua) on this folder:
    ```lua
    lua sha1sums.lua "path/to/my/file"
    ```

* Compute the SHA256 checksum of a file using [sha256sums.lua](./sha256sums.lua) on this folder:
    ```lua
    lua sha256sums.lua "path/to/my/file"
    ```

* Compute the SHA384 checksum of a file using [sha384sums.lua](./sha384sums.lua) on this folder:
    ```lua
    lua sha384sums.lua "path/to/my/file"
    ```

* Compute the SHA512 checksum of a file using [sha512sums.lua](./sha512sums.lua) on this folder:
    ```lua
    lua sha512sums.lua "path/to/my/file"
    ```
