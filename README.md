# Radar

Radar is a small but efficient network scanner written in Rust heavily inspired 
by `masscan`.

These are the main features:
- Userspace TCP, UDP, DHCP and ARP implementations, thanks to `pnet`
- Being asynchronous
- Randomized IP/ports scanning with no pre-allocation/shuffling
- Rate limiting
- Monitor mode that notifies about different kind of network events
- JSON output

As `masscan`, it aims to be as fast as possible. On my 1Gbit network it achieves 
circa 300k packets per second.


## Build

### Rustup
```sh
rustup default stable
rustup target add x86_64-unknown-linux-musl
rustup component add rustfmt rust-analyzer rust-src clippy
export CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

cargo build
```

### Nix
```sh
nix build
```

### Nix shell
```sh
nixedevelop
```

## Run

**Console mode**
```sh
sudo ./target/x86_64-unknown-linux-musl/debug/radar -i default console
```
This opens the scanner in console mode, where you can issue various commands.  
To see all of them, just type `help`. The console mode is based on
[Hackshell](https://github.com/deade1e/hackshell).

**CLI mode**
```sh
sudo ./target/x86_64-unknown-linux-musl/debug/radar -i default scan -h
```
This shows you the same help shown in the console mode if the `scan` command is 
issued.

## Purpose
The project aims to be an extended and more pluggable/hackable version of 
`masscan`. It both works in local networks and non RFC1918 ones, so yes, you can 
theoretically scan the whole internet with it.
