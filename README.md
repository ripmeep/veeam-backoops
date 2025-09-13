# veeam-backoops
A Veeam credential password decrypter/recovery tool for PostgreSQL databases

This tool attempts to load the libpq (PostgreSQL) library from the default installed location (packaged with Veeam), overwrites the pg_hba.conf file to allow trusted access, then extracts and decrypts the credentials from the Veeam credential store.

Restoration of the original pg_hba.conf will be attempted, and some fallbacks are in place if this fails.

Paths can be configured from the `veeam-backoops.h` file at the top to set the PostgreSQL root path location, along with the database name and registry key locations for encryption data:

```c
/* Change these if needed */
#define PG_ROOT_PATH      "C:\\Program Files\\PostgreSQL\\15" /* Path to PostgreSQL install */
#define PG_USERNAME       "postgres"                          /* Username to connect to the Veeam database as */
#define PG_HOST           "localhost"                         /* Host of the PostgreSQL database (rarely needs changing) */
#define PG_DATABASE       "VeeamBackup"                       /* Database name of the Veeam Credential store */

#define VEEAM_SALT_ROOT   HKEY_LOCAL_MACHINE
#define VEEAM_SALT_SUBKEY "SOFTWARE\\Veeam\\Veeam Backup and Replication\\Data" /* Registry key path of the EncryptionSalt key */
#define VEEAM_SALT_KEY    "EncryptionSalt"
```

# Build

This tool relies on `mingw-w64` to build, so do so via your respected package manager.
##### Debian
`$ sudo apt install mingw-w64`
##### Arch
`$ sudo pacman -S mingw-w64`
or
`$ yay -S mingw-w64`
##### MacOS (brew)
`$ brew install mingw-w64`

Then, you can compile with the following:
`x86_64-w64-mingw32-gcc veeam-backoops.c -o veeam-backoops -lcrypt32`

If successful, `veeam-backoops.exe` should now be in the current working directory.

A pre-compiled release can be found in the releases section for x86_64 Windows :)

DISCLAIMER: I ain't responsible for yo mischief.

Copy this to the server and run it! Either double click, or through cmd:

![veeam-backoops.exe running](https://github.com/ripmeep/veeam-backoops/blob/main/images/veeam-backoops.png?raw=true)
![veeam-backoops.exe over netexec](https://github.com/ripmeep/veeam-backoops/blob/main/images/nxc.png?raw=true)
