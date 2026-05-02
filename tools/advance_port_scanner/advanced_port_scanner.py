#!/usr/bin/env python3
"""
Advanced Port Scanner with Service Detection
A comprehensive network reconnaissance tool for cybersecurity professionals
"""

import socket
import threading
import queue
import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple, Set
import signal


class ColorCodes:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'


class ServiceMapper:
    """Maps ports to common services"""
    
    SERVICES = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
    }
    
    @staticmethod
    def get_service(port: int) -> str:
        """Get service name for a port"""
        return ServiceMapper.SERVICES.get(port, 'Unknown')
    
    @staticmethod
    def is_web_port(port: int) -> bool:
        """Check if port is web-related"""
        web_ports = {80, 443, 8080, 8443}
        return port in web_ports
    
    @staticmethod
    def is_database_port(port: int) -> bool:
        """Check if port is database-related"""
        db_ports = {3306, 5432, 27017, 6379}
        return port in db_ports
    
    @staticmethod
    def is_remote_access_port(port: int) -> bool:
        """Check if port is for remote access"""
        remote_ports = {22, 23, 3389, 5900}
        return port in remote_ports


class BannerGrabber:
    """Attempts to grab service banners from open ports"""
    
    @staticmethod
    def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
        """
        Attempt to grab banner from an open port
        Returns the banner string or empty string if unsuccessful
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try to receive banner data
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # For HTTP-like services, send a probe
            if ServiceMapper.is_web_port(port):
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0]
                if response:
                    banner = response.strip()
            
            sock.close()
            return banner[:100] if banner else "Service detected"
            
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return ""
        except Exception:
            return ""


class SecurityAdvisor:
    """Provides security recommendations based on open ports"""
    
    RECOMMENDATIONS = {
        22: "⚠️  Port 22 open (SSH). Ensure strong authentication, disable root login, and use key-based auth.",
        23: "🚨 Port 23 open (Telnet). CRITICAL: Telnet is insecure. Use SSH instead.",
        25: "ℹ️  Port 25 open (SMTP). Ensure proper mail server configuration and authentication.",
        53: "ℹ️  Port 53 open (DNS). Ensure DNS server is properly secured and configured.",
        80: "ℹ️  Port 80 open (HTTP). Unencrypted web traffic. Use HTTPS and keep services updated.",
        110: "ℹ️  Port 110 open (POP3). Consider using encrypted alternatives (POP3S).",
        135: "⚠️  Port 135 open (RPC). Consider restricting access to trusted networks only.",
        139: "⚠️  Port 139 open (NetBIOS). Can expose system information. Disable if not needed.",
        143: "ℹ️  Port 143 open (IMAP). Consider using encrypted alternatives (IMAPS).",
        443: "✅ Port 443 open (HTTPS). Good: Encrypted web traffic. Keep certificates updated.",
        445: "⚠️  Port 445 open (SMB). High risk for lateral movement. Restrict access and patch regularly.",
        3306: "⚠️  Port 3306 open (MySQL). Database exposed. Use firewall rules, strong passwords, and bind to localhost.",
        3389: "⚠️  Port 3389 open (RDP). Remote access exposed. Use VPN, strong credentials, and fail2ban.",
        5432: "⚠️  Port 5432 open (PostgreSQL). Database exposed. Use firewall rules and strong authentication.",
        5900: "⚠️  Port 5900 open (VNC). Remote access exposed. Use encryption and strong authentication.",
        6379: "🚨 Port 6379 open (Redis). CRITICAL: Redis typically has no authentication. Restrict access immediately.",
        8080: "ℹ️  Port 8080 open (HTTP-Alt). Alternate web port. Ensure services are properly secured.",
        8443: "ℹ️  Port 8443 open (HTTPS-Alt). Alternate HTTPS port. Ensure certificates are valid.",
        27017: "🚨 Port 27017 open (MongoDB). CRITICAL: MongoDB should not be exposed. Use firewall rules immediately.",
    }
    
    @staticmethod
    def get_recommendation(port: int) -> str:
        """Get security recommendation for a port"""
        return SecurityAdvisor.RECOMMENDATIONS.get(port, "")
    
    @staticmethod
    def generate_recommendations(open_ports: List[int]) -> List[str]:
        """Generate recommendations based on all open ports"""
        recommendations = []
        for port in sorted(open_ports):
            rec = SecurityAdvisor.get_recommendation(port)
            if rec:
                recommendations.append(rec)
        return recommendations


class PortScanner:
    """Main port scanning engine"""
    
    def __init__(self, target: str, threads: int = 50, timeout: float = 3.0, 
                 verbose: bool = False, banner_grab: bool = True):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.banner_grab = banner_grab
        
        # Results storage
        self.open_ports = {}  # {port: banner}
        self.closed_ports = set()
        self.results_lock = threading.Lock()
        
        # Statistics
        self.start_time = None
        self.end_time = None
        self.total_ports_scanned = 0
        
        # Graceful shutdown
        self.stop_scanning = False
    
    def resolve_target(self) -> str:
        """Resolve hostname to IP address"""
        try:
            resolved_ip = socket.gethostbyname(self.target)
            if self.verbose:
                print(f"{ColorCodes.DIM}Resolved {self.target} to {resolved_ip}{ColorCodes.RESET}")
            return resolved_ip
        except socket.gaierror:
            print(f"{ColorCodes.RED}Error: Could not resolve hostname '{self.target}'{ColorCodes.RESET}")
            sys.exit(1)
    
    def scan_port(self, host: str, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single port
        Returns: (port, is_open, banner)
        """
        if self.stop_scanning:
            return port, False, ""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Port is open
                banner = ""
                if self.banner_grab:
                    banner = BannerGrabber.grab_banner(host, port, self.timeout - 0.5)
                
                if self.verbose:
                    print(f"{ColorCodes.GREEN}✓ Port {port} OPEN{ColorCodes.RESET}")
                
                return port, True, banner
            else:
                if self.verbose:
                    print(f"{ColorCodes.DIM}✗ Port {port} closed{ColorCodes.RESET}")
                return port, False, ""
                
        except socket.timeout:
            if self.verbose:
                print(f"{ColorCodes.DIM}✗ Port {port} timeout{ColorCodes.RESET}")
            return port, False, ""
        except Exception as e:
            if self.verbose:
                print(f"{ColorCodes.RED}✗ Port {port} error: {str(e)[:30]}{ColorCodes.RESET}")
            return port, False, ""
    
    def worker_thread(self, host: str, port_queue: queue.Queue):
        """Worker thread that processes ports from the queue"""
        while not self.stop_scanning:
            try:
                port = port_queue.get(timeout=0.1)
            except queue.Empty:
                break
            
            port_num, is_open, banner = self.scan_port(host, port)
            
            with self.results_lock:
                self.total_ports_scanned += 1
                if is_open:
                    self.open_ports[port_num] = banner
                else:
                    self.closed_ports.add(port_num)
            
            port_queue.task_done()
    
    def scan(self, ports: List[int]) -> Dict:
        """
        Execute the port scan
        Returns results dictionary
        """
        self.start_time = time.time()
        
        # Resolve target
        host = self.resolve_target()
        
        # Create port queue
        port_queue = queue.Queue()
        for port in ports:
            port_queue.put(port)
        
        # Start worker threads
        threads = []
        actual_thread_count = min(self.threads, len(ports))
        
        print(f"\n{ColorCodes.BOLD}{ColorCodes.CYAN}Starting scan...{ColorCodes.RESET}\n")
        
        for _ in range(actual_thread_count):
            t = threading.Thread(target=self.worker_thread, args=(host, port_queue))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        try:
            port_queue.join()
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print(f"\n{ColorCodes.YELLOW}Scan interrupted by user{ColorCodes.RESET}")
            self.stop_scanning = True
            port_queue.join()
        
        self.end_time = time.time()
        
        return self.compile_results(host, len(ports))
    
    def compile_results(self, host: str, total_ports: int) -> Dict:
        """Compile scan results into a dictionary"""
        return {
            'target': self.target,
            'ip_address': host,
            'scan_time': datetime.now().isoformat(),
            'duration_seconds': round(self.end_time - self.start_time, 2),
            'total_ports_scanned': total_ports,
            'open_ports_count': len(self.open_ports),
            'closed_ports_count': len(self.closed_ports),
            'open_ports_details': [
                {
                    'port': port,
                    'service': ServiceMapper.get_service(port),
                    'banner': banner
                }
                for port, banner in sorted(self.open_ports.items())
            ],
            'recommendations': SecurityAdvisor.generate_recommendations(list(self.open_ports.keys()))
        }


class PortRangeParser:
    """Parses port specifications into lists of ports"""
    
    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        """
        Parse port specification
        Examples:
        - "22" -> [22]
        - "22,80,443" -> [22, 80, 443]
        - "20-25" -> [20, 21, 22, 23, 24, 25]
        - "common" -> common ports
        """
        if port_spec.lower() == 'common':
            return list(sorted(ServiceMapper.SERVICES.keys()))
        
        ports = set()
        parts = port_spec.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range
                try:
                    start, end = part.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        raise ValueError(f"Invalid port range: {part}")
                    
                    ports.update(range(start_port, end_port + 1))
                except ValueError as e:
                    print(f"{ColorCodes.RED}Error parsing port range '{part}': {e}{ColorCodes.RESET}")
                    sys.exit(1)
            else:
                # Single port
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port must be between 1 and 65535")
                    ports.add(port)
                except ValueError as e:
                    print(f"{ColorCodes.RED}Error parsing port '{part}': {e}{ColorCodes.RESET}")
                    sys.exit(1)
        
        return sorted(list(ports))


class OutputFormatter:
    """Formats and displays scan results"""
    
    @staticmethod
    def print_header(target: str, thread_count: int, banner_grabbing: bool):
        """Print scan header"""
        print(f"\n{ColorCodes.BOLD}{ColorCodes.BG_BLUE}{ColorCodes.WHITE}")
        print("╔════════════════════════════════════════════════════╗")
        print("║       🔎 ADVANCED PORT SCANNER v2.0              ║")
        print("║       Cybersecurity Portfolio Tool                ║")
        print("╚════════════════════════════════════════════════════╝")
        print(ColorCodes.RESET)
        
        print(f"{ColorCodes.CYAN}🎯 Target: {target}{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}🔧 Threads: {thread_count}{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}🎯 Banner Grabbing: {'Enabled' if banner_grabbing else 'Disabled'}{ColorCodes.RESET}")
    
    @staticmethod
    def print_results(results: Dict):
        """Print formatted scan results"""
        print(f"\n{ColorCodes.BOLD}{ColorCodes.GREEN}")
        print("=" * 60)
        print("📡 SCAN COMPLETE")
        print("=" * 60)
        print(ColorCodes.RESET)
        
        print(f"{ColorCodes.CYAN}🎯 Target: {results['target']}{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}📍 IP Address: {results['ip_address']}{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}📊 Total Ports Scanned: {results['total_ports_scanned']}{ColorCodes.RESET}")
        print(f"{ColorCodes.GREEN}🔓 Open Ports: {results['open_ports_count']}{ColorCodes.RESET}")
        print(f"{ColorCodes.DIM}🔒 Closed Ports: {results['closed_ports_count']}{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}⏰ Duration: {results['duration_seconds']} seconds{ColorCodes.RESET}")
        print(f"{ColorCodes.CYAN}📅 Scan Time: {results['scan_time']}{ColorCodes.RESET}")
        
        # Open ports details
        if results['open_ports_details']:
            print(f"\n{ColorCodes.BOLD}{ColorCodes.CYAN}")
            print("-" * 60)
            print("📋 OPEN PORTS DETAILS:")
            print("-" * 60)
            print(ColorCodes.RESET)
            
            print(f"{ColorCodes.BOLD}PORT{ColorCodes.RESET:<8} {ColorCodes.BOLD}SERVICE{ColorCodes.RESET:<20} {ColorCodes.BOLD}BANNER/VERSION{ColorCodes.RESET}")
            print("-" * 60)
            
            for port_info in results['open_ports_details']:
                port = port_info['port']
                service = port_info['service']
                banner = port_info['banner'] or "Service detected"
                
                print(f"{ColorCodes.GREEN}{port:<7}{ColorCodes.RESET} {service:<20} {banner[:35]}")
        else:
            print(f"\n{ColorCodes.YELLOW}No open ports found.{ColorCodes.RESET}")
        
        # Security recommendations
        if results['recommendations']:
            print(f"\n{ColorCodes.BOLD}{ColorCodes.CYAN}")
            print("-" * 60)
            print("🛡️  SECURITY RECOMMENDATIONS:")
            print("-" * 60)
            print(ColorCodes.RESET)
            
            for rec in results['recommendations']:
                print(f"{rec}")
        
        print(f"\n{ColorCodes.BOLD}{ColorCodes.GREEN}✅ Scan finished successfully!{ColorCodes.RESET}\n")
    
    @staticmethod
    def print_json_export(results: Dict, filename: str):
        """Export results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{ColorCodes.GREEN}✅ Results saved to: {filename}{ColorCodes.RESET}")
        except IOError as e:
            print(f"{ColorCodes.RED}Error saving to file: {e}{ColorCodes.RESET}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner with Service Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                          # Scan common ports
  %(prog)s 192.168.1.1 -p 20-100               # Scan port range
  %(prog)s 192.168.1.1 -p 22,80,443            # Scan specific ports
  %(prog)s 192.168.1.1 --full                  # Full scan (1-65535)
  %(prog)s 192.168.1.1 -o results.json         # Save results to JSON
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common',
                        help='Port(s) to scan (default: common ports). Examples: "22", "22,80,443", "20-100"')
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=3.0,
                        help='Socket timeout in seconds (default: 3.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--no-banner', action='store_true',
                        help='Disable banner grabbing (faster scan)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('--full', action='store_true',
                        help='Scan all ports (1-65535)')
    
    args = parser.parse_args()
    
    # Determine ports to scan
    if args.full:
        ports = list(range(1, 65536))
        port_spec_display = "all 65535 ports"
    else:
        ports = PortRangeParser.parse_ports(args.ports)
        port_spec_display = f"{len(ports)} ports"
    
    # Create scanner
    scanner = PortScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        banner_grab=not args.no_banner
    )
    
    # Print header
    OutputFormatter.print_header(args.target, args.threads, not args.no_banner)
    print(f"{ColorCodes.CYAN}📊 Ports to scan: {port_spec_display}{ColorCodes.RESET}\n")
    
    # Run scan
    results = scanner.scan(ports)
    
    # Display results
    OutputFormatter.print_results(results)
    
    # Export to JSON if requested
    if args.output:
        OutputFormatter.print_json_export(results, args.output)


if __name__ == '__main__':
    main()
