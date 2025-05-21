# SSNIFF - Advanced Python Packet Sniffer and Injector

SSNIFF is a versatile network tool written in Python that provides packet capturing and injection capabilities with a user-friendly interface and rich features. It's designed to work seamlessly across Linux (including Kali, ParrotOS, etc.), and macOS.

```
███████╗███████╗███╗   ██╗██╗███████╗███████╗
██╔════╝██╔════╝████╗  ██║██║██╔════╝██╔════╝
███████╗███████╗██╔██╗ ██║██║█████╗  █████╗  
╚════██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
███████║███████║██║ ╚████║██║██║     ██║     
╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     
```

## Features

- **Packet Capturing**
  - Capture packets from any network interface
  - Filter by protocol (TCP, UDP, ICMP, IP)
  - Limit number of packets to capture
  - Rate limiting to control capture speed
  - Real-time packet display
  - Native support for Linux packet capture interfaces

- **Packet Injection**
  - Inject custom packets into the network
  - Support for TCP, UDP, and ICMP protocols
  - Customizable packet data
  - Safe testing capabilities

- **Output Options**
  - Colorized output for better readability
  - Summary view for compact display
  - Logging to file for later analysis
  - Packet numbering and statistics

## Platform-Specific Requirements

### Linux (Including Kali, ParrotOS, etc.)
```bash
# Debian/Ubuntu/Kali
sudo apt-get install python3-pip python3-venv libpcap-dev

# Fedora/RHEL
sudo dnf install python3-pip python3-venv libpcap-devel

# Arch/BlackArch
sudo pacman -S python-pip python-virtualenv libpcap
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install libpcap
brew install libpcap
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/pakagronglb/ssniff.git
cd ssniff
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Unix/macOS
# or
.\venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Common Interface Names

### Linux
- `eth0`, `eth1`: Ethernet interfaces
- `wlan0`, `wlan1`: Wireless interfaces
- `enp0s3`, `enp0s8`: Modern naming scheme for network interfaces
- `wlp2s0`: Modern naming scheme for wireless interfaces

### macOS
- `en0`: Usually the built-in Ethernet
- `en1`: Usually the built-in WiFi
- `bridge0`: Bridge interface
- `lo0`: Loopback interface

## Usage

### Basic Commands

1. List available network interfaces:
```bash
# Show all interfaces with their status
sudo python3 ssniff.py -l
```

2. Capture packets:
```bash
# Linux examples (replace with your interface name)
sudo python3 ssniff.py -i eth0     # Ethernet
sudo python3 ssniff.py -i wlan0    # Wireless

# macOS examples
sudo python3 ssniff.py -i en0      # Ethernet
sudo python3 ssniff.py -i en1      # Wireless
```

### Advanced Features

1. Protocol Filtering:
```bash
# Capture only TCP packets
sudo python3 ssniff.py -i eth0 -p tcp

# Capture only UDP packets
sudo python3 ssniff.py -i eth0 -p udp

# Capture only ICMP packets
sudo python3 ssniff.py -i eth0 -p icmp
```

2. Rate Limiting:
```bash
# Limit to 10 packets per second
sudo python3 ssniff.py -i eth0 --rate-limit 10
```

3. Output Options:
```bash
# Log to file
sudo python3 ssniff.py -i eth0 --log-file packets.log

# Show summary only
sudo python3 ssniff.py -i eth0 --summary

# Disable color output
sudo python3 ssniff.py -i eth0 --no-color
```

4. Packet Injection:
```bash
# Inject TCP packet
sudo python3 ssniff.py -i eth0 --inject --target-ip 127.0.0.1 --target-port 8080 --inject-data "TEST"

# Inject UDP packet
sudo python3 ssniff.py -i eth0 --inject --target-ip 127.0.0.1 --target-port 8080 --inject-data "TEST" --inject-protocol udp

# Inject ICMP packet
sudo python3 ssniff.py -i eth0 --inject --target-ip 127.0.0.1 --inject-data "TEST" --inject-protocol icmp
```

## Command Line Options

```
usage: ssniff.py [-h] (-i INTERFACE | -l) [-c COUNT] [-p {tcp,udp,icmp,ip}]
                 [--rate-limit RATE_LIMIT] [--summary] [--no-color]
                 [--log-file LOG_FILE] [--inject] [--target-ip TARGET_IP]
                 [--target-port TARGET_PORT] [--inject-data INJECT_DATA]
                 [--inject-protocol {tcp,udp,icmp}]
```

### Main Options
- `-i, --interface`: Network interface to sniff on
- `-l, --list-interfaces`: List available network interfaces
- `-h, --help`: Show help message

### Capture Options
- `-c, --count`: Number of packets to capture (default: 100, 0 for unlimited)
- `-p, --protocol`: Protocol filter (tcp, udp, icmp, ip)
- `--rate-limit`: Maximum number of packets to process per second

### Output Options
- `--summary`: Print packet summaries only
- `--no-color`: Disable color output
- `--log-file`: Log file to save packet information

### Packet Injection Options
- `--inject`: Enable packet injection mode
- `--target-ip`: Target IP address for packet injection
- `--target-port`: Target port for packet injection
- `--inject-data`: Data to inject in the packet
- `--inject-protocol`: Protocol to use for injection (tcp, udp, icmp)

## Troubleshooting

### Linux-Specific Issues
1. **Permission Denied**: 
   - Run with sudo
   - Or add your user to the pcap group: `sudo usermod -a -G pcap $USER`

2. **Interface Not Found**: 
   - Check interface name: `ip link show`
   - Modern Linux systems use predictable interface names (like `enp0s3`)

3. **Capture Issues on Kali/ParrotOS**:
   - The tool automatically detects security distributions and adjusts settings
   - Try different capture methods if issues persist

### macOS-Specific Issues
1. **Permission Issues**:
   - Run with sudo
   - Check System Preferences → Security & Privacy for allowed kernel extensions

2. **Interface Names**:
   - Use `ifconfig` to list correct interface names
   - Names might change after system updates

## Security Considerations

1. Always run packet injection tests in a controlled environment
2. Be cautious when capturing packets on production networks
3. Use rate limiting to prevent network overload
4. Review captured data for sensitive information before sharing logs
5. On Linux systems, consider using network namespaces for isolation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scapy project for the packet manipulation library
- Rich library for the beautiful terminal output 