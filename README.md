# Rusty Port Scanner

A port scanner written in Rust as a personal project.

I plan to add more useful features to the tool, such as:
- UDP port scanning
- Service discovery
- Multiple-host scanning (subnets)

## Notes on features

Below are some notes on the current state of program features. These will be updated as the program is worked on and improved.

### TCP Scanning

- Limited to single target host only
- Conducted using full TCP Connect

### UDP Scanning

- Limited to single target host only
- Only remote ports that provide a response before timeout is reached are registered as OPEN.

## Compilation for Windows (on Linux dev box)

1. Add the Rust toolchain "x86_64-pc-windows-gnu"
   1. `rustup target add x86_64-pc-windows-gnu`
2. Install "mingw-w64" linker
   1. `sudo apt install mingw-w64`
3. Compile program targeting Windows:
   1. `cargo build --target x86_64-pc-windows-gnu --release`
4. Locate Windows x86_64 binary in project directory at "target/x86_64-pc-windows-gnu/release/rusty-port-scanner.exe"
5. Run tool on Windows and enjoy!

## Testing UDP - Linux remote

To test the ability of the program to check UDP port scanning, you can use `ncat` on the remote host to echo back whatever is received on a set UDP port:

```
ncat -e /bin/cat -k -u -l <listen_port>
```
