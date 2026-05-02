# Advanced Port Scanner with Service Detection

A professional Python-based network reconnaissance tool for cybersecurity professionals. Performs TCP port scanning, service detection, banner grabbing, and provides automated security recommendations.

## ✨ Features

- **Multi-threaded Scanning**: 50+ concurrent threads for fast scanning
- **Service Detection**: Maps 25+ common ports to their services
- **Banner Grabbing**: Retrieves service banners for version identification
- **Flexible Port Selection**: Single ports, ranges, comma-separated lists, or full scan
- **Color-coded Output**: Terminal output with colors for easy distinction
- **Security Recommendations**: Automated advice based on open ports
- **JSON Export**: Save results for documentation and reporting
- **Professional CLI**: Full command-line interface with argparse
- **Error Handling**: Graceful handling of errors and user interrupts
- **No Dependencies**: Uses only Python standard library

## 🛠️ Installation

### Requirements
- Python 3.8 or higher
- No external packages required (uses only standard library)

### Setup
```bash
# Clone or download the tool
git clone https://github.com/yourusername/cybersecurity-portfolio.git
cd cybersecurity-portfolio/tools/advanced_port_scanner/

# Make executable (optional)
chmod +x advanced_port_scanner.py
```

## 🚀 Quick Start

```bash
# Scan common ports (25 most common services)
python3 advanced_port_scanner.py 192.168.1.1

# Scan specific port range
python3 advanced_port_scanner.py 192.168.1.1 -p 20-100

# Scan specific ports
python3 advanced_port_scanner.py 192.168.1.1 -p 22,80,443,3306

# Full port scan (1-65535) - takes longer
python3 advanced_port_scanner.py 192.168.1.1 --full

# Save results to JSON
python3 advanced_port_scanner.py 192.168.1.1 -o scan_results.json

# Control thread count (for slower networks)
python3 advanced_port_scanner.py 192.168.1.1 -t 25

# Disable banner grabbing (faster scan)
python3 advanced_port_scanner.py 192.168.1.1 --no-banner

# Verbose output (see each port being tested)
python3 advanced_port_scanner.py 192.168.1.1 -v
```

## 📋 Command-line Arguments

| Argument | Short | Type | Default | Description |
|----------|-------|------|---------|-------------|
| `target` | - | string | required | Target IP address or hostname |
| `--ports` | `-p` | string | "common" | Port specification (e.g., "22", "22,80,443", "20-100") |
| `--threads` | `-t` | int | 50 | Number of concurrent threads |
| `--timeout` | - | float | 3.0 | Socket timeout in seconds |
| `--verbose` | `-v` | flag | False | Enable verbose output |
| `--no-banner` | - | flag | False | Disable banner grabbing |
| `--output` | `-o` | string | None | Save results to JSON file |
| `--full` | - | flag | False | Scan all 65535 ports |

## 🔍 Supported Services

The scanner detects and recommends actions for:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 20 | FTP-Data | 443 | HTTPS |
| 21 | FTP | 445 | SMB |
| 22 | SSH | 993 | IMAPS |
| 23 | Telnet | 995 | POP3S |
| 25 | SMTP | 1723 | PPTP |
| 53 | DNS | 3306 | MySQL |
| 80 | HTTP | 3389 | RDP |
| 110 | POP3 | 5432 | PostgreSQL |
| 111 | RPC | 5900 | VNC |
| 135 | RPC | 6379 | Redis |
| 139 | NetBIOS | 8080 | HTTP-Alt |
| 143 | IMAP | 8443 | HTTPS-Alt |
| 27017 | MongoDB | - | - |

## 📊 Example Output

```
╔════════════════════════════════════════════════════╗
║       🔎 ADVANCED PORT SCANNER v2.0              ║
║       Cybersecurity Portfolio Tool                ║
╚════════════════════════════════════════════════════╝

🎯 Target: scanme.nmap.org
🔧 Threads: 50
🎯 Banner Grabbing: Enabled
📊 Ports to scan: 25 ports

Starting scan...

============================================================
📡 SCAN COMPLETE
============================================================
🎯 Target: scanme.nmap.org
📍 IP Address: 45.33.32.156
📊 Total Ports Scanned: 25
🔓 Open Ports: 3
🔒 Closed Ports: 22
⏰ Duration: 2.34 seconds
📅 Scan Time: 2026-05-02T14:23:45.123456

────────────────────────────────────────────────────────────
📋 OPEN PORTS DETAILS:
────────────────────────────────────────────────────────────
PORT    SERVICE              BANNER/VERSION
22      SSH                  SSH-2.0-OpenSSH_8.9p1
80      HTTP                 HTTP/1.1 200 OK
443     HTTPS                HTTP/1.1 200 OK

────────────────────────────────────────────────────────────
🛡️  SECURITY RECOMMENDATIONS:
────────────────────────────────────────────────────────────
⚠️  Port 22 open (SSH). Ensure strong authentication, disable root login, and use key-based auth.
ℹ️  Port 80 open (HTTP). Unencrypted web traffic. Use HTTPS and keep services updated.
✅ Port 443 open (HTTPS). Good: Encrypted web traffic. Keep certificates updated.

✅ Scan finished successfully!
```

## 💾 JSON Export Format

When using the `-o` option, results are saved in the following JSON format:

```json
{
  "target": "192.168.1.1",
  "ip_address": "192.168.1.1",
  "scan_time": "2026-05-02T14:23:45.123456",
  "duration_seconds": 2.34,
  "total_ports_scanned": 25,
  "open_ports_count": 3,
  "closed_ports_count": 22,
  "open_ports_details": [
    {
      "port": 22,
      "service": "SSH",
      "banner": "SSH-2.0-OpenSSH_8.9p1"
    },
    {
      "port": 80,
      "service": "HTTP",
      "banner": "HTTP/1.1 200 OK"
    }
  ],
  "recommendations": [
    "⚠️  Port 22 open (SSH). Ensure strong authentication...",
    "ℹ️  Port 80 open (HTTP). Unencrypted web traffic..."
  ]
}
```

## 🏗️ Architecture & Components

### Core Classes

**PortScanner**
- Main scanning engine
- Manages multi-threading and port queue
- Handles scan execution and result compilation

**ServiceMapper**
- Maps ports to service names
- Identifies port categories (web, database, remote access)
- 25+ service definitions built-in

**BannerGrabber**
- Connects to open ports and retrieves banners
- Handles HTTP-specific banner grabbing
- Timeout and error handling

**SecurityAdvisor**
- Provides contextual security recommendations
- Maps ports to security best practices
- Categorizes severity levels (info, warning, critical)

**OutputFormatter**
- Formats terminal output with colors
- Handles JSON export
- Professional report generation

**PortRangeParser**
- Parses command-line port specifications
- Supports multiple formats (single, range, list)
- Input validation

### Color System

- 🟢 Green: Open ports, successful operations
- 🔴 Red: Errors, critical issues
- 🟡 Yellow: Warnings, interruptions
- 🔵 Blue: Information, headers
- ⚪ Gray: Verbose/detailed info

## 🔐 Security Considerations

### Legal & Ethical Usage

⚠️ **IMPORTANT**: This tool is for authorized security testing only.

- **DO NOT** scan systems without explicit written permission
- **DO NOT** perform unauthorized penetration testing
- Unauthorized port scanning may violate:
  - Computer Fraud and Abuse Act (CFAA) in the US
  - Similar laws in other jurisdictions
  - ISP and hosting provider terms of service

### Best Practices

- Always get written authorization before scanning
- Start with common ports (default) before full scans
- Use appropriate thread counts based on network conditions
- Document all scanning activities
- Follow responsible disclosure if vulnerabilities are found

## ⚙️ Technical Details

### Multi-threading Strategy
- Uses Python's `threading` module with `queue.Queue`
- Default 50 concurrent threads (configurable)
- Thread-safe result storage with locks
- Graceful shutdown on Ctrl+C

### Socket Programming
- Pure Python socket library (no external dependencies)
- TCP connect scanning (full three-way handshake)
- Configurable timeouts per port
- Handles all socket exceptions

### Banner Grabbing
- Up to 1024 bytes per port
- HTTP-specific probe detection
- Service-aware timeout handling
- UTF-8 decoding with error tolerance

## 📈 Performance Tips

1. **Thread Count**: Increase threads for fast networks, decrease for slow/throttled networks
   ```bash
   python3 advanced_port_scanner.py 192.168.1.1 -t 100  # Faster
   python3 advanced_port_scanner.py 192.168.1.1 -t 25   # Slower but gentler
   ```

2. **Banner Grabbing**: Disable for significantly faster scans
   ```bash
   python3 advanced_port_scanner.py 192.168.1.1 --no-banner
   ```

3. **Timeout**: Adjust for network conditions
   ```bash
   python3 advanced_port_scanner.py 192.168.1.1 --timeout 5.0  # Longer timeout
   ```

4. **Port Selection**: Start with common ports, expand if needed
   ```bash
   python3 advanced_port_scanner.py 192.168.1.1              # Common only
   python3 advanced_port_scanner.py 192.168.1.1 -p 1-5000   # Larger range
   ```

## 🐛 Troubleshooting

### "Cannot resolve hostname"
```bash
# Use IP address instead of hostname
python3 advanced_port_scanner.py 192.168.1.1
```

### Slow scanning
```bash
# Disable banner grabbing for speed
python3 advanced_port_scanner.py 192.168.1.1 --no-banner

# Reduce thread count if network is throttling
python3 advanced_port_scanner.py 192.168.1.1 -t 25
```

### Permission denied on port scan
```bash
# Most ports > 1024 don't require root
# For ports < 1024, you may need elevated privileges
sudo python3 advanced_port_scanner.py 192.168.1.1 -p 1-1024
```

### Firewall blocking scans
- Network firewall may block outbound connections
- Check firewall rules and policies
- Try scanning from a different network

## 📝 Limitations & Future Roadmap

### Current Limitations
- TCP scanning only (UDP support coming)
- No SYN stealth scanning (uses full TCP connect)
- Banner grabbing limited to common services
- IPv4 only (IPv6 coming)

### Planned Features
- [ ] TCP SYN stealth scanning using scapy
- [ ] UDP port scanning
- [ ] OS fingerprinting
- [ ] PDF report export
- [ ] Live progress bar with ETA
- [ ] GUI interface (Tkinter)
- [ ] Service version deep detection
- [ ] IPv6 support
- [ ] Nmap XML import/export compatibility

## 📚 Learning Resources

This project demonstrates:
- **Networking**: TCP/IP, socket programming, network protocols
- **Python**: Threading, queues, exception handling, argparse
- **Security**: Port scanning, service identification, vulnerability assessment
- **Software Design**: Object-oriented programming, design patterns, modular code

## 🤝 Contributing

Found a bug or have a feature request? Contributions welcome!

1. Test your changes thoroughly
2. Follow PEP 8 style guidelines
3. Add comments for complex logic
4. Update documentation

## 📄 License

MIT License - See LICENSE file for details

## 👤 Author

Created as part of a cybersecurity portfolio project.

**Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring their usage complies with all applicable laws and regulations.

---

**Last Updated**: May 2026

For more information or questions, please refer to the project documentation or reach out through GitHub.
