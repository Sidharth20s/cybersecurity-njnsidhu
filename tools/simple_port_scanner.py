#!/usr/bin/env python3
"""
Simple Port Scanner - Educational purpose only
Usage: python3 simple_port_scanner.py <target_ip>
"""

import socket
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 simple_port_scanner.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\n🔍 Scanning {target}")
    print(f"⏰ Started: {datetime.now()}\n")
    
    open_ports = []
    for port in range(1, 1025):
        if scan_port(target, port):
            open_ports.append(port)
            print(f"✅ Port {port} - OPEN")
    
    print(f"\n📊 Scan complete. Found {len(open_ports)} open ports.")

if __name__ == "__main__":
    main()
