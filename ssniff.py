#!/usr/bin/env python3
import argparse
from scapy.all import sniff, send, IP, TCP, UDP, ICMP, Raw, get_if_list, conf, L2Socket
from scapy.arch.bpf.supersocket import L2bpfListenSocket
from rich.console import Console
from rich.text import Text
from termcolor import colored
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
import platform
import os
import subprocess
import re

console = Console()
packet_count = 0

# Setup logging
def setup_logging(log_file):
    if log_file:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )

class RateLimiter:
    def __init__(self, max_packets_per_second):
        self.max_packets = max_packets_per_second
        self.last_check = time.time()
        self.packet_count = 0
    
    def can_process(self):
        current_time = time.time()
        if current_time - self.last_check >= 1:
            self.last_check = current_time
            self.packet_count = 0
        
        if self.packet_count < self.max_packets:
            self.packet_count += 1
            return True
        return False

def create_injection_packet(target_ip, target_port, data, protocol='tcp'):
    if protocol.lower() == 'tcp':
        packet = IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=data)
    elif protocol.lower() == 'udp':
        packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=data)
    elif protocol.lower() == 'icmp':
        packet = IP(dst=target_ip)/ICMP()/Raw(load=data)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")
    return packet

def print_ascii_banner():
    banner = Text()
    title = "SSNIFF"
    colors = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    banner.append("\n")
    ascii_lines = [
        "███████╗███████╗███╗   ██╗██╗███████╗███████╗",
        "██╔════╝██╔════╝████╗  ██║██║██╔════╝██╔════╝",
        "███████╗███████╗██╔██╗ ██║██║█████╗  █████╗  ",
        "╚════██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ",
        "███████║███████║██║ ╚████║██║██║     ██║     ",
        "╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     "
    ]
    for line in ascii_lines:
        for i, char in enumerate(line):
            banner.append(char, style=colors[i % len(colors)])
        banner.append("\n")
    console.print(banner)

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

def get_default_interface():
    """Get the default interface based on the operating system."""
    system = platform.system().lower()
    if system == "linux":
        return "eth0"
    elif system == "darwin":  # macOS
        return "en0"
    elif system == "windows":
        return "Ethernet"
    return None

def get_linux_interfaces():
    """Get detailed information about network interfaces on Linux."""
    try:
        # Try using ip command first (modern Linux)
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and '@' in line:
                    iface = line.split(':')[1].split('@')[0].strip()
                    if iface != 'lo':  # Skip loopback
                        interfaces.append(iface)
            return interfaces
    except:
        pass

    try:
        # Fallback to ifconfig (older Linux distributions)
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.split('\n'):
                if line and not line.startswith(' '):
                    iface = line.split(':')[0].split()[0]
                    if iface != 'lo':  # Skip loopback
                        interfaces.append(iface)
            return interfaces
    except:
        pass

    # If both fail, use Scapy's get_if_list
    return [iface for iface in get_if_list() if iface != 'lo']

def get_interface_status(interface):
    """Get the status of a network interface."""
    system = platform.system().lower()
    
    if system == "linux":
        try:
            # Try using ip command
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
            if result.returncode == 0:
                return "UP" in result.stdout and "LOWER_UP" in result.stdout
        except:
            try:
                # Fallback to ifconfig
                result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
                return result.returncode == 0 and "UP" in result.stdout
            except:
                pass
    elif system == "darwin":
        try:
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            return result.returncode == 0 and "status: active" in result.stdout
        except:
            pass
    
    return True  # Default to True if we can't determine status

def get_available_interfaces():
    """Get a list of available network interfaces with their status."""
    system = platform.system().lower()
    interfaces = []
    
    if system == "linux":
        ifaces = get_linux_interfaces()
    else:
        ifaces = [iface for iface in get_if_list() if iface != 'lo' and iface != 'lo0']
    
    for iface in ifaces:
        status = "active" if get_interface_status(iface) else "inactive"
        if system == "linux":
            # Try to get additional info for Linux
            try:
                result = subprocess.run(['ip', 'addr', 'show', iface], capture_output=True, text=True)
                if result.returncode == 0:
                    # Extract IP address if available
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if ip_match:
                        interfaces.append(f"  - {iface} ({status}) - {ip_match.group(1)}")
                        continue
            except:
                pass
        interfaces.append(f"  - {iface} ({status})")
    
    return interfaces

def setup_scapy():
    """Configure Scapy based on the operating system."""
    system = platform.system().lower()
    if system == "linux":
        # Linux-specific configuration
        conf.use_pcap = True
        
        # Check if we're running on Kali or similar
        try:
            with open('/etc/os-release') as f:
                os_info = f.read().lower()
                if 'kali' in os_info or 'parrot' in os_info or 'blackarch' in os_info:
                    # These distros typically have better packet capture support
                    conf.use_pcap = False
        except:
            pass
    elif system == "darwin":
        # macOS-specific configuration
        conf.use_bpf = True

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="""SSNIFF: Advanced Python Packet Sniffer and Injector

A versatile network tool for packet capture and injection with features including:
- Packet capturing with customizable count and protocol filtering
- Rate limiting to control capture speed
- Packet injection capabilities
- Logging to file
- Colorized output""",
        epilog="""Examples:
  List interfaces:
    %(prog)s -l
  
  Capture packets:
    %(prog)s -i en1 -c 100                    # Capture 100 packets
    %(prog)s -i en1 -c 0                      # Capture unlimited packets
    %(prog)s -i en1 -p tcp --rate-limit 10    # Capture TCP packets with rate limit
    %(prog)s -i en1 --log-file packets.log    # Log packets to file
  
  Packet injection:
    %(prog)s -i en1 --inject --target-ip 127.0.0.1 --target-port 8080 --inject-data "TEST"
    """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Create argument groups for better organization
    main_group = parser.add_mutually_exclusive_group(required=True)
    capture_group = parser.add_argument_group('Capture options')
    output_group = parser.add_argument_group('Output options')
    injection_group = parser.add_argument_group('Packet injection options')

    # Main arguments
    main_group.add_argument("-i", "--interface",
                          help="Network interface to sniff on")
    main_group.add_argument("-l", "--list-interfaces",
                          help="List available network interfaces",
                          action="store_true")

    # Capture options
    capture_group.add_argument("-c", "--count",
                             help="Number of packets to capture (default: 100, 0 for unlimited)",
                             type=int, default=100)
    capture_group.add_argument("-p", "--protocol",
                             help="Protocol filter: tcp, udp, icmp, ip",
                             choices=["tcp", "udp", "icmp", "ip"],
                             default="ip")
    capture_group.add_argument("--rate-limit",
                             help="Maximum number of packets to process per second",
                             type=int)

    # Output options
    output_group.add_argument("--summary",
                            help="Print packet summaries only",
                            action="store_true")
    output_group.add_argument("--no-color",
                            help="Disable color output",
                            action="store_true")
    output_group.add_argument("--log-file",
                            help="Log file to save packet information",
                            type=str)

    # Packet injection options
    injection_group.add_argument("--inject",
                               help="Enable packet injection mode",
                               action="store_true")
    injection_group.add_argument("--target-ip",
                               help="Target IP address for packet injection")
    injection_group.add_argument("--target-port",
                               help="Target port for packet injection",
                               type=int)
    injection_group.add_argument("--inject-data",
                               help="Data to inject in the packet")
    injection_group.add_argument("--inject-protocol",
                               help="Protocol to use for injection (default: tcp)",
                               choices=["tcp", "udp", "icmp"],
                               default="tcp")

    return parser.parse_args()

def process_packet(packet, no_color=False, summary=False, rate_limiter=None):
    global packet_count
    
    if rate_limiter and not rate_limiter.can_process():
        return

    packet_count += 1
    
    if summary:
        text = packet.summary()
        if no_color:
            logging.info(text)
        else:
            console.print(f"[cyan]{text}[/cyan]")
        return

    if IP in packet:
        proto = packet[IP].proto
        src = packet[IP].src
        dst = packet[IP].dst
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
        out = f"Packet #{packet_count}: {src} -> {dst} ({proto_name})"
        
        if no_color:
            logging.info(out)
        else:
            console.print(f"[bold]Packet #{packet_count}:[/bold] [bold green]{src}[/bold green] -> [bold red]{dst}[/bold red] [yellow]({proto_name})[/yellow]")

def start_sniffing(interface, count, proto_filter, summary, no_color, rate_limit=None):
    global packet_count
    packet_count = 0
    
    console.print(f"[bold]Starting packet capture on [green]{interface}[/green]...[/bold]")
    if count > 0:
        console.print(f"[bold]Will capture [cyan]{count}[/cyan] packets[/bold]")
    else:
        console.print("[bold yellow]Unlimited packet capture mode. Press Ctrl+C to stop.[/bold yellow]")
    
    if rate_limit:
        console.print(f"[bold]Rate limit: [cyan]{rate_limit}[/cyan] packets/second[/bold]")
    
    if proto_filter == "ip":
        filter_str = ""
        console.print("[bold]Capturing all IP protocols[/bold]")
    else:
        filter_str = proto_filter
        console.print(f"[bold]Capturing only [cyan]{proto_filter.upper()}[/cyan] packets[/bold]")

    rate_limiter = RateLimiter(rate_limit) if rate_limit else None
    
    try:
        system = platform.system().lower()
        if system == "darwin":
            # macOS-specific socket handling
            socket = L2bpfListenSocket(iface=interface)
            sniff(
                opened_socket=socket,
                prn=lambda pkt: process_packet(pkt, no_color, summary, rate_limiter),
                count=count if count > 0 else None,
                filter=filter_str,
                store=False
            )
        elif system == "linux":
            # Linux-specific handling
            try:
                # Try using L2Socket first (better for some Linux distributions)
                socket = L2Socket(iface=interface)
                sniff(
                    opened_socket=socket,
                    prn=lambda pkt: process_packet(pkt, no_color, summary, rate_limiter),
                    count=count if count > 0 else None,
                    filter=filter_str,
                    store=False
                )
            except Exception as e:
                # Fallback to regular sniffing
                sniff(
                    iface=interface,
                    prn=lambda pkt: process_packet(pkt, no_color, summary, rate_limiter),
                    count=count if count > 0 else None,
                    filter=filter_str,
                    store=False
                )
        console.print(f"\n[bold green]Packet capture completed! Captured {packet_count} packets.[/bold green]")
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Packet capture stopped by user. Captured {packet_count} packets.[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error during packet capture: {str(e)}[/bold red]")
    finally:
        if 'socket' in locals():
            try:
                socket.close()
            except:
                pass

def inject_packet(target_ip, target_port, data, protocol):
    try:
        packet = create_injection_packet(target_ip, target_port, data, protocol)
        console.print(f"[bold yellow]Injecting packet to {target_ip}:{target_port} using {protocol}[/bold yellow]")
        send(packet, verbose=False)
        console.print("[bold green]Packet injected successfully[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to inject packet: {str(e)}[/bold red]")

def main():
    if not is_admin():
        console.print("[bold red]Error: This script requires administrator/root privileges.[/bold red]")
        console.print("\nPlease run with:")
        if platform.system() == "Windows":
            console.print("  - Right-click and select 'Run as administrator'")
            console.print("  - Or use 'runas /user:Administrator' from command line")
        else:
            console.print("  sudo python3 ssniff.py [options]")
        sys.exit(1)

    setup_scapy()
    print_ascii_banner()
    args = parse_arguments()
    
    # List interfaces if requested
    if args.list_interfaces:
        console.print("[bold]Available Network Interfaces:[/bold]")
        for iface in get_available_interfaces():
            console.print(iface)
        sys.exit(0)
    
    # Validate interface
    available_interfaces = get_if_list()
    if args.interface not in available_interfaces:
        console.print("[bold red]Error: Invalid interface specified[/bold red]")
        console.print("\n[bold]Available Network Interfaces:[/bold]")
        for iface in get_available_interfaces():
            console.print(iface)
        sys.exit(1)
    
    # Setup logging
    setup_logging(args.log_file)
    
    try:
        if args.inject:
            if not all([args.target_ip, args.target_port, args.inject_data]):
                console.print("[bold red]Error: --target-ip, --target-port, and --inject-data are required for packet injection[/bold red]")
                sys.exit(1)
            inject_packet(args.target_ip, args.target_port, args.inject_data, args.inject_protocol)
        else:
            start_sniffing(args.interface, args.count, args.protocol, args.summary, args.no_color, args.rate_limit)
    except KeyboardInterrupt:
        console.print("\n[red]Sniffing stopped by user[/red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
