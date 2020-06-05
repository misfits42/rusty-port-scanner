# Rusty Port Scanner

A port scanner written in Rust as a personal project.

I plan to add more useful features to the tool, such as:
- UDP port scanning
- Service discovery
- Multiple-host scanning (subnets)

## Compilation for Windows (on Linux dev box)

1. Add the Rust toolchain "x86_64-pc-windows-gnu"
   1. `rustup add target x86_64-pc-windows-gnu`
2. Install "mingw-w64" linker
   1. `sudo apt install mingw-w64`
3. Compile program targeting Windows:
   1. `cargo build --target x86_64-pc-windows-gnu --release`
4. Locate Windows x86_64 binary in project directory at "target/x86_64-pc-windows-gnu/release/rusty-port-scanner.exe"
5. Run tool on Windows and enjoy!
