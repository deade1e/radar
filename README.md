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

## Usage

Either download the github release binaries (only available for x86_64) or build
the project yourself. `nix shell github:deade1e/radar` helps.

First of all open a radar console:
```sh
user@machine> $ sudo radar -i default console
```
`sudo` or the equivalent permission is required to use the raw sockets.

Show the help with all commands and brief description:
```sh
radar> help
```

Show the internal ARP table:
```sh
radar> arp
```

Perform an ARP scan on all the interface's subnets:
```sh
radar> arpscan -a
```

View the `scan` command help:
```sh
radar> scan --help
Error: Scan the network

Usage: scan [OPTIONS] -p <PORTS> <SUBNET>

Arguments:
  <SUBNET>  The subnet to scan

Options:
  -p <PORTS>                     The ports to scan
  -u, --udp                      Use UDP instead of TCP
  -a, --arp-mode                 Enables ARP mode for scanning only the local network. When this option is enabled the packets are sent directly to the target MAC address instead of the router MAC address. An ARP 
scan will be performed before the actual port scan while using this option
  -r, --max-rate <MAX_RATE>      The maximum rate of packets to send per second. Default = 1000
  -j, --json                     JSON output
      --json-content             Include response packet content in the JSON output
  -b, --blacklist <BLACKLIST>    Blacklist file of subnets not to be scanned or ever contacted in any way. Mandatory when a /0 (global IPv4) scan is performed
  -m, --router-mac <ROUTER_MAC>  Router MAC address. Used when the router cannot be detected automatically or for benchmarking purposes
  -c, --content <CONTENT>        The content of the packet to send. Must be a base64 encoded string. Only used in UDP mode
  -h, --help                     Print help
```


Perform a basic scan of an internal subnet:
```sh
radar> scan -p 1-1000 192.168.1.0/24
```
This mode uses the default gateway to route packets, as `masscan` does.

By adding `-a` the ARP mode is enabled and therefore individual mac addresses
get resolved before sending the ethernet frames.


Perform a UDP scan in search of DNS servers:
```sh
radar> scan -p 53 192.168.1.0/24 -u -c kOQBAAABAAAAAAABBmdvb2dsZQNjb20AAAEAAQAAKQSwAAAAAAAA
```
This base64 content is a DNS request for google.com.

Monitor for DHCP requests on your interface:
```sh
radar> monitor -f dhcp-req
```

View the current ongoing tasks:
```sh
radar> task

Task                     Started at              
----                     ----------              

monitor                  2026-01-07 00:09:34     
```

Terminate a task:
```sh
radar> task -t monitor
```

Script the console to execute a list of commands on start:
```sh
user@machine> $ sudo radar -i default console -r script.txt
```

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
nix develop
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
