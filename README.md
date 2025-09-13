# veeam-backoops
A Veeam credential password decrypter/recovery tool for PostgreSQL databases

This tool attempts to load the libpq (PostgreSQL) library from the default installed location (packaged with Veeam), overwrites the pg_hba.conf file to allow trusted access, then extracts and decrypts the credentials from the Veeam credential store.

Paths can be configured from the `veeam-backoops.h` file at the top to set the PostgreSQL root path location, along with the database name and registry key locations for encryption data.

# Build

This tool relies on `mingw-w64` to build, so do so via your respected package manager.
##### Debian
`$ sudo apt install mingw-w64`
##### Arch
`$ sudo pacman -S mingw-w64`
or
`$ yay -S mingw-w64`


Then, you can compile with the following:
`x86_64-w64-mingw32-gcc veeam-backoops.c -o veeam-backoops -lcrypt32`

If successful, `veeam-backoops.exe` should now be in the current working directory.

Copy this to the server and run it! Either double click, or through cmd:

