# Packet Counter

A network packet analyzer that captures and counts packets by protocol type. 

## Build

```sh
make
```

## Run

```sh
sudo ./packet_counter -i <interface> [-f <filter>] [-t <seconds>]
```

## Examples

```sh
sudo ./packet_counter -i eth0
sudo ./packet_counter -i wlan0 -f "tcp port 80" -t 1
```

## Options

- `-i <interface>`: Network interface (required)
    
- `-f <filter>`: Protocol filter (e.g., "tcp", "udp", "icmp")
    
- `-t <seconds>`: Update interval (default: 5)

## Protocols

- TCP
- UDP
- ICMP
- Other

## Requirements

- Build dependences.
```sh
# Install build dependencies first
sudo apt update
sudo apt install build-essential flex bison
```

- libpcap
```sh
# Compile libpcap
wget http://www.tcpdump.org/release/libpcap-1.10.1.tar.gz
tar xzf libpcap-1.10.1.tar.gz
cd libpcap-1.10.1
./configure
make
sudo make install
```

- Root privileges
