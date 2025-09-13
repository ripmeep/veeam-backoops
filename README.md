# veeam-backoops
A Veeam credential password decrypter/recovery tool for PostgreSQL databases

# Build
`x86_64-w64-mingw32-gcc veeam-backoops.c -o veeam-backoops -lcrypt32`

If successful, `veeam-backoops.exe` should now be in the current working directory.
Copy this to the server and run it! Either double click, or through cmd.
