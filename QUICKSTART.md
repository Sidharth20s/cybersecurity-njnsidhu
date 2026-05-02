# Advanced Port Scanner - Quick Start Guide

## Installation (30 seconds)

```bash
# 1. Download the file
# Already have: advanced_port_scanner.py

# 2. Make it executable (optional)
chmod +x advanced_port_scanner.py

# 3. Done! No additional installations needed
```

## Your First Scan (1 minute)

### Scan your localhost (safe test)
```bash
python3 advanced_port_scanner.py localhost
```

### Scan a test server (scanme.nmap.org)
```bash
python3 advanced_port_scanner.py scanme.nmap.org
```

### Scan your local network
```bash
python3 advanced_port_scanner.py 192.168.1.1
```

## Common Commands

### 1. Scan specific ports
```bash
# Single port
python3 advanced_port_scanner.py 192.168.1.1 -p 22

# Multiple ports
python3 advanced_port_scanner.py 192.168.1.1 -p 22,80,443,3306

# Port range
python3 advanced_port_scanner.py 192.168.1.1 -p 1-1000
```

### 2. Faster scanning
```bash
# Disable banner grabbing (significantly faster)
python3 advanced_port_scanner.py 192.168.1.1 --no-banner

# Reduce thread count (for slower networks)
python3 advanced_port_scanner.py 192.168.1.1 -t 25
```

### 3. Save results
```bash
# Export to JSON for documentation
python3 advanced_port_scanner.py 192.168.1.1 -o scan_results.json

# View the results
cat scan_results.json
```

### 4. Verbose output
```bash
# See each port as it's tested
python3 advanced_port_scanner.py 192.168.1.1 -v
```

### 5. Full network scan
```bash
# Warning: This takes a while!
python3 advanced_port_scanner.py 192.168.1.1 --full
```

## Understanding the Output

```
🎯 Target: 192.168.1.1              # What you're scanning
🔧 Threads: 50                      # How many ports simultaneously
📊 Ports to scan: 25                # How many total ports
```

```
🔓 Open Ports: 3                    # Ports that responded
🔒 Closed Ports: 22                 # Ports that were blocked
⏰ Duration: 2.34 seconds           # How long it took
```

```
PORT    SERVICE    BANNER/VERSION
22      SSH        SSH-2.0-OpenSSH_8.9p1
80      HTTP       HTTP/1.1 200 OK
443     HTTPS      HTTP/1.1 200 OK
```

```
🛡️ SECURITY RECOMMENDATIONS:
⚠️  Port 22 open (SSH). Ensure strong authentication...
ℹ️  Port 80 open (HTTP). Unencrypted web traffic...
```

## Parameters Explained

| Parameter | What it does | Example |
|-----------|------------|---------|
| `target` | What to scan | `192.168.1.1` or `google.com` |
| `-p` | Which ports | `-p 22,80,443` or `-p 20-100` |
| `-t` | Thread count | `-t 50` (default) |
| `--no-banner` | Skip service detection | Makes scan 2-3x faster |
| `-o` | Save to file | `-o results.json` |
| `-v` | Verbose mode | See each port tested |
| `--full` | All 65535 ports | ⚠️ Takes 5-15 minutes |

## Troubleshooting

### Port scan shows all closed?
- Normal! Most public systems block scans
- Try scanme.nmap.org (test server): `python3 advanced_port_scanner.py scanme.nmap.org`
- Or scan your own machine: `python3 advanced_port_scanner.py localhost`

### Scan is too slow?
```bash
# Disable banner grabbing
python3 advanced_port_scanner.py 192.168.1.1 --no-banner

# Reduce thread count
python3 advanced_port_scanner.py 192.168.1.1 -t 100
```

### "Cannot resolve hostname"
```bash
# Use IP address instead
python3 advanced_port_scanner.py 8.8.8.8  # Instead of google.com
```

### Permission denied for ports < 1024?
```bash
# Use sudo for system ports
sudo python3 advanced_port_scanner.py 192.168.1.1 -p 1-1024
```

## Legal Reminder ⚠️

**Only scan systems you own or have written permission to test!**

Unauthorized scanning is illegal in most jurisdictions.

## Example: Full Workflow

```bash
# 1. Scan common ports
python3 advanced_port_scanner.py 192.168.1.100

# 2. Found some open ports? Scan more specific range
python3 advanced_port_scanner.py 192.168.1.100 -p 1-10000

# 3. Save detailed results
python3 advanced_port_scanner.py 192.168.1.100 -p 1-10000 -o full_scan.json

# 4. Review the JSON output
cat full_scan.json | python3 -m json.tool  # Pretty print
```

## Next Steps

1. Read **README.md** for comprehensive documentation
2. Explore command options: `python3 advanced_port_scanner.py --help`
3. Try different targets and port ranges
4. Integrate results into your security reports

---

**Happy scanning! Remember: always get permission first.** 🔍
