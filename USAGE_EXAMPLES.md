#!/usr/bin/env python3
"""
Advanced Port Scanner - Usage Examples & Recipes
Run these examples to understand the tool's capabilities
"""

import subprocess
import sys

# Color codes for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_section(title):
    """Print a section header"""
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{title}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")


def print_example(num, title, command, description):
    """Print an example"""
    print(f"{YELLOW}Example {num}: {title}{RESET}")
    print(f"Description: {description}")
    print(f"\n{GREEN}Command:{RESET}")
    print(f"  {command}")
    print()


def main():
    """Display usage examples"""
    
    print(f"\n{BOLD}{BLUE}Advanced Port Scanner - Usage Examples & Recipes{RESET}\n")
    print("These examples show various ways to use the scanner.")
    print("To run an example, copy the command and paste it in your terminal.\n")
    
    # Section 1: Basic Scanning
    print_section("1. BASIC SCANNING")
    
    print_example(
        1.1,
        "Scan Default Common Ports",
        "python3 advanced_port_scanner.py 192.168.1.1",
        "Scans the 25 most common service ports on a target"
    )
    
    print_example(
        1.2,
        "Scan with Hostname",
        "python3 advanced_port_scanner.py scanme.nmap.org",
        "Resolve hostname to IP and scan it"
    )
    
    print_example(
        1.3,
        "Scan Localhost (Safe Test)",
        "python3 advanced_port_scanner.py localhost",
        "Test on your own machine (safest option)"
    )
    
    # Section 2: Port Selection
    print_section("2. PORT SELECTION METHODS")
    
    print_example(
        2.1,
        "Single Port",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 22",
        "Scan only SSH port (22)"
    )
    
    print_example(
        2.2,
        "Multiple Specific Ports",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 22,80,443,3306",
        "Scan SSH, HTTP, HTTPS, and MySQL"
    )
    
    print_example(
        2.3,
        "Port Range",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 20-100",
        "Scan ports 20 through 100"
    )
    
    print_example(
        2.4,
        "Large Port Range",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 1-10000",
        "Scan first 10,000 ports (comprehensive scan)"
    )
    
    print_example(
        2.5,
        "Full Port Scan",
        "python3 advanced_port_scanner.py 192.168.1.1 --full",
        "Scan all 65,535 ports (slow, 10+ minutes)"
    )
    
    # Section 3: Performance Tuning
    print_section("3. PERFORMANCE OPTIMIZATION")
    
    print_example(
        3.1,
        "Fast Scan (No Banner Grabbing)",
        "python3 advanced_port_scanner.py 192.168.1.1 --no-banner",
        "2-3x faster by skipping service banner detection"
    )
    
    print_example(
        3.2,
        "Fast Scan (Fewer Threads)",
        "python3 advanced_port_scanner.py 192.168.1.1 -t 25",
        "Reduce load on target network (25 threads vs 50 default)"
    )
    
    print_example(
        3.3,
        "Super Fast Scan",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 22,80,443 --no-banner -t 10",
        "Minimal ports + no banner + fewer threads = ultra fast"
    )
    
    print_example(
        3.4,
        "More Threads (Faster)",
        "python3 advanced_port_scanner.py 192.168.1.1 -t 100",
        "More aggressive scanning (100 threads)"
    )
    
    print_example(
        3.5,
        "Longer Timeout (Thorough)",
        "python3 advanced_port_scanner.py 192.168.1.1 --timeout 5.0",
        "Wait longer for slow services (default is 3.0 seconds)"
    )
    
    print_example(
        3.6,
        "Shorter Timeout (Faster)",
        "python3 advanced_port_scanner.py 192.168.1.1 --timeout 1.0",
        "Assume unresponsive ports are closed (quick scan)"
    )
    
    # Section 4: Output & Reporting
    print_section("4. OUTPUT & REPORTING")
    
    print_example(
        4.1,
        "Save Results to JSON",
        "python3 advanced_port_scanner.py 192.168.1.1 -o scan_results.json",
        "Export results for documentation and further analysis"
    )
    
    print_example(
        4.2,
        "View JSON Results (Pretty Print)",
        "cat scan_results.json | python3 -m json.tool",
        "Display JSON in readable format"
    )
    
    print_example(
        4.3,
        "Extract Open Ports from JSON",
        "python3 -c \"import json; data=json.load(open('scan_results.json')); print([p['port'] for p in data['open_ports_details']])\"",
        "Extract just the open port numbers"
    )
    
    print_example(
        4.4,
        "Verbose Output",
        "python3 advanced_port_scanner.py 192.168.1.1 -v",
        "See detailed output for each port being tested"
    )
    
    # Section 5: Security Scenarios
    print_section("5. SECURITY ASSESSMENT SCENARIOS")
    
    print_example(
        5.1,
        "Quick Security Audit",
        "python3 advanced_port_scanner.py 192.168.1.100 -p 22,80,443,3306,5432,6379",
        "Check common dangerous ports (SSH, HTTP, HTTPS, databases)"
    )
    
    print_example(
        5.2,
        "Web Server Assessment",
        "python3 advanced_port_scanner.py webserver.example.com -p 80,443,8080,8443",
        "Focus on web-related ports"
    )
    
    print_example(
        5.3,
        "Database Server Scan",
        "python3 advanced_port_scanner.py dbserver.internal -p 3306,5432,27017,6379",
        "Check database-related ports"
    )
    
    print_example(
        5.4,
        "Windows Server Assessment",
        "python3 advanced_port_scanner.py 192.168.1.10 -p 135,139,445,3389",
        "Scan Windows-specific services (RPC, NetBIOS, SMB, RDP)"
    )
    
    print_example(
        5.5,
        "Network Inventory Scan",
        "python3 advanced_port_scanner.py 192.168.1.1 --full -o inventory_scan.json",
        "Full network discovery (save for documentation)"
    )
    
    # Section 6: Automation Recipes
    print_section("6. AUTOMATION & SCRIPTING")
    
    print_example(
        6.1,
        "Scan Multiple Targets",
        "for ip in 192.168.1.{1..10}; do python3 advanced_port_scanner.py $ip -o scan_$ip.json; done",
        "Scan a range of IPs and save results for each"
    )
    
    print_example(
        6.2,
        "Scan with Timestamp",
        "python3 advanced_port_scanner.py 192.168.1.1 -o scan_$(date +%Y%m%d_%H%M%S).json",
        "Save results with timestamp for versioning"
    )
    
    print_example(
        6.3,
        "Run Scheduled Scan",
        "0 2 * * * cd /path/to/scanner && python3 advanced_port_scanner.py 192.168.1.1 -o daily_scan.json",
        "Add to crontab for automated daily scans"
    )
    
    print_example(
        6.4,
        "Email Results",
        "python3 advanced_port_scanner.py 192.168.1.1 -o results.json && mail -s 'Scan Results' admin@example.com < results.json",
        "Scan and email results (requires mail configured)"
    )
    
    # Section 7: Troubleshooting
    print_section("7. TROUBLESHOOTING")
    
    print_example(
        7.1,
        "Verbose Mode for Debugging",
        "python3 advanced_port_scanner.py 192.168.1.1 -v",
        "See detailed output for debugging issues"
    )
    
    print_example(
        7.2,
        "Test Connection to Target",
        "ping 192.168.1.1",
        "Verify target is reachable before scanning"
    )
    
    print_example(
        7.3,
        "Quick Connectivity Test",
        "python3 advanced_port_scanner.py 192.168.1.1 -p 22 -t 1",
        "Fast test with single port and thread"
    )
    
    print_example(
        7.4,
        "Check Python Version",
        "python3 --version",
        "Ensure Python 3.8+ is installed"
    )
    
    # Section 8: Real-World Scenarios
    print_section("8. REAL-WORLD SCENARIOS")
    
    print_example(
        8.1,
        "First Time Assessment",
        "python3 advanced_port_scanner.py 192.168.1.1 -o baseline.json",
        "Create baseline scan of your network"
    )
    
    print_example(
        8.2,
        "After Patch Management",
        "python3 advanced_port_scanner.py 192.168.1.1 -o post_patch.json",
        "Verify patches didn't open unexpected ports"
    )
    
    print_example(
        8.3,
        "Firewall Verification",
        "python3 advanced_port_scanner.py 10.0.0.1 -p 22,25,123",
        "Test if firewall rules are working"
    )
    
    print_example(
        8.4,
        "Penetration Test Recon",
        "python3 advanced_port_scanner.py target.example.com -p 1-65535 -o recon.json",
        "Full reconnaissance for authorized pen test"
    )
    
    print_example(
        8.5,
        "Compliance Verification",
        "python3 advanced_port_scanner.py 192.168.1.50 -p 445,139,22 -o compliance_check.json",
        "Check compliance with security policies"
    )
    
    # Section 9: Integration Examples
    print_section("9. INTEGRATION WITH OTHER TOOLS")
    
    print_example(
        9.1,
        "Use Results with Nmap",
        "python3 advanced_port_scanner.py target.com -o ports.json && nmap -p $(python3 -c 'import json; print(\",\".join(map(str, [p[\"port\"] for p in json.load(open(\"ports.json\"))[\"open_ports_details\"]]))') target.com",
        "Find ports with this tool, then do detailed nmap scan"
    )
    
    print_example(
        9.2,
        "CSV Export for Spreadsheet",
        "python3 advanced_port_scanner.py 192.168.1.1 -o results.json && python3 -c 'import json; data=json.load(open(\"results.json\")); print(\"port,service,banner\"); [print(f\"{p[\\\"port\\\"]},{p[\\\"service\\\"]},{p[\\\"banner\\\"]}\") for p in data[\"open_ports_details\"]]' > results.csv",
        "Export results to CSV for Excel"
    )
    
    print_example(
        9.3,
        "Check Against Expected Ports",
        "python3 advanced_port_scanner.py target.com -o current.json && diff expected_ports.json current.json",
        "Compare current scan with baseline (using diff)"
    )
    
    # Tips
    print_section("💡 TIPS & BEST PRACTICES")
    
    print("""
1. ALWAYS GET PERMISSION
   - Never scan systems without authorization
   - Keep written consent for audits
   - Document all scanning activities

2. START SMALL
   - Begin with common ports (default)
   - Expand to larger ranges if needed
   - Full scans take 10+ minutes

3. RESPECT TARGET
   - Use appropriate thread counts
   - Don't overwhelm small networks
   - Reduce threads if target is slow

4. DOCUMENT RESULTS
   - Save all scans with -o option
   - Include timestamps
   - Keep baseline for comparison

5. COMBINE WITH OTHER TOOLS
   - Use results to focus nmap
   - Import into vulnerability scanners
   - Integrate with security platforms

6. AUTOMATE REGULAR SCANS
   - Schedule with cron (Linux)
   - Use Task Scheduler (Windows)
   - Email results automatically

7. ANALYZE RECOMMENDATIONS
   - Read security suggestions carefully
   - Verify findings before action
   - Escalate critical issues

8. KEEP BASELINE
   - Initial scan = baseline
   - Compare future scans
   - Track changes over time
    """)
    
    print(f"\n{GREEN}Need help? Read the documentation:{RESET}")
    print("  - Quick start: See QUICKSTART.md")
    print("  - Full guide: See README.md")
    print("  - Deep dive: See TECHNICAL_DOCUMENTATION.md")
    print()


if __name__ == '__main__':
    main()
