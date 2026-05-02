# Advanced Port Scanner - Technical Documentation

## 📚 Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Class Reference](#class-reference)
3. [Code Flow](#code-flow)
4. [Key Algorithms](#key-algorithms)
5. [Data Structures](#data-structures)
6. [Error Handling](#error-handling)
7. [Performance Considerations](#performance-considerations)

---

## Architecture Overview

The Advanced Port Scanner follows an **object-oriented, modular design** with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│         Main Entry (main.py)                    │
│  - Argument parsing with argparse               │
│  - User interface orchestration                 │
└────────────────┬────────────────────────────────┘
                 │
     ┌───────────┼───────────┐
     │           │           │
     ▼           ▼           ▼
┌─────────┐  ┌─────────┐  ┌─────────┐
│ Port    │  │ Service │  │ Security│
│ Scanner │  │ Mapper  │  │ Advisor │
└────┬────┘  └─────────┘  └─────────┘
     │
┌────▼──────────────┐
│ Multi-threading  │
│ + Queue System   │
└───────┬──────────┘
        │
┌───────▼────────────┐
│ Banner Grabber     │
│ + Socket I/O       │
└────────────────────┘
```

### Design Principles

1. **Modularity**: Each class has a single responsibility
2. **Reusability**: Classes can be used independently
3. **Extensibility**: Easy to add new services or features
4. **Error Resilience**: Graceful failure handling
5. **Performance**: Multi-threaded concurrent scanning
6. **User Experience**: Professional output and feedback

---

## Class Reference

### 1. ColorCodes
**Purpose**: ANSI color codes for terminal output

```python
class ColorCodes:
    RED = '\033[91m'        # Error messages
    GREEN = '\033[92m'      # Success, open ports
    YELLOW = '\033[93m'     # Warnings
    BLUE = '\033[94m'       # Information
    BOLD = '\033[1m'        # Bold text
    RESET = '\033[0m'       # Reset formatting
```

**Usage**:
```python
print(f"{ColorCodes.GREEN}Success!{ColorCodes.RESET}")
```

**Key Features**:
- Terminal-portable ANSI escape sequences
- Consistent color scheme throughout app
- Easy to disable on non-ANSI terminals

---

### 2. ServiceMapper
**Purpose**: Maps port numbers to service names and categories

```python
class ServiceMapper:
    SERVICES = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        # ... 22+ more services
    }
```

**Key Methods**:
- `get_service(port)` - Returns service name for a port
- `is_web_port(port)` - Identifies web-related ports
- `is_database_port(port)` - Identifies database ports
- `is_remote_access_port(port)` - Identifies remote access ports

**Example**:
```python
service = ServiceMapper.get_service(3306)  # Returns 'MySQL'
if ServiceMapper.is_database_port(3306):
    # Handle database port
```

**Design Rationale**:
- Static methods allow use without instantiation
- Dictionary-based lookup is O(1) performance
- Easy to extend with new services

---

### 3. BannerGrabber
**Purpose**: Retrieves service banners from open ports

```python
class BannerGrabber:
    @staticmethod
    def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
        # Connects to port and retrieves banner
```

**How It Works**:
1. Creates TCP socket
2. Connects to host:port with timeout
3. For HTTP ports: sends HTTP probe
4. For other ports: receives initial response
5. Returns banner (first 100 chars)

**Example**:
```python
banner = BannerGrabber.grab_banner('192.168.1.1', 22, timeout=2.0)
# Returns: "SSH-2.0-OpenSSH_8.9p1"
```

**Error Handling**:
- Socket timeout → Returns empty string
- Connection refused → Returns empty string
- Decode errors → Stripped with 'ignore' mode
- Any exception → Returns empty string

**Performance**:
- Timeout per port prevents hanging
- Parallel execution via threading
- Optional disabling for speed

---

### 4. SecurityAdvisor
**Purpose**: Provides security recommendations based on open ports

```python
class SecurityAdvisor:
    RECOMMENDATIONS = {
        22: "Port 22 open (SSH). Ensure...",
        6379: "CRITICAL: Redis typically...",
        # ... 20+ recommendations
    }
```

**Key Methods**:
- `get_recommendation(port)` - Single port advice
- `generate_recommendations(open_ports)` - Full report

**Recommendation Levels**:
- 🔴 **Critical** (🚨): Immediate action needed
- 🟠 **Warning** (⚠️): Address soon
- 🟡 **Info** (ℹ️): Good to know
- 🟢 **Good** (✅): Secure configuration

**Example**:
```python
ports = [22, 80, 6379]
recs = SecurityAdvisor.generate_recommendations(ports)
# Returns: [SSH warning, HTTP info, Redis CRITICAL]
```

---

### 5. PortScanner (Main Engine)
**Purpose**: Core scanning logic with multi-threading

```python
class PortScanner:
    def __init__(self, target, threads=50, timeout=3.0):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.open_ports = {}      # {port: banner}
        self.closed_ports = set()
        self.results_lock = threading.Lock()
```

#### Key Methods

**`resolve_target()`**
- Converts hostname to IP
- Uses `socket.gethostbyname()`
- Exits on failure

**`scan_port(host, port)`**
- Scans single port
- Returns: (port, is_open, banner)
- Handles all exceptions

```python
def scan_port(self, host: str, port: int) -> Tuple:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(self.timeout)
    result = sock.connect_ex((host, port))
    
    if result == 0:
        # Port is open
        banner = BannerGrabber.grab_banner(...) if self.banner_grab else ""
        return port, True, banner
    else:
        # Port is closed
        return port, False, ""
```

**`worker_thread(host, port_queue)`**
- Worker for thread pool
- Gets ports from queue
- Calls `scan_port()`
- Stores results thread-safely

```python
def worker_thread(self, host: str, port_queue: queue.Queue):
    while not self.stop_scanning:
        try:
            port = port_queue.get(timeout=0.1)
        except queue.Empty:
            break
        
        # Scan port and store result
        port_num, is_open, banner = self.scan_port(host, port)
        
        with self.results_lock:  # Thread-safe
            if is_open:
                self.open_ports[port_num] = banner
            else:
                self.closed_ports.add(port_num)
```

**`scan(ports)`**
- Main orchestration method
- Resolves target
- Creates thread pool
- Manages queue
- Handles Ctrl+C gracefully

```python
def scan(self, ports: List[int]) -> Dict:
    host = self.resolve_target()
    port_queue = queue.Queue()
    
    # Add all ports to queue
    for port in ports:
        port_queue.put(port)
    
    # Start worker threads
    threads = []
    for _ in range(min(self.threads, len(ports))):
        t = threading.Thread(target=self.worker_thread, 
                            args=(host, port_queue))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for completion
    try:
        port_queue.join()
    except KeyboardInterrupt:
        self.stop_scanning = True
```

#### Thread Safety

The scanner uses thread synchronization to prevent race conditions:

```python
self.results_lock = threading.Lock()

# Thread-safe result storage
with self.results_lock:
    self.open_ports[port] = banner  # Safe from race conditions
    self.closed_ports.add(port)
```

---

### 6. PortRangeParser
**Purpose**: Parses various port specification formats

```python
class PortRangeParser:
    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        # Handles: "22", "22,80,443", "20-100", "common"
```

**Supported Formats**:
1. Single port: `"22"` → `[22]`
2. Multiple ports: `"22,80,443"` → `[22, 80, 443]`
3. Range: `"20-100"` → `[20, 21, ..., 100]`
4. Keyword: `"common"` → all common ports

**Implementation**:
```python
def parse_ports(port_spec: str) -> List[int]:
    ports = set()  # Use set to avoid duplicates
    
    for part in port_spec.split(','):
        if '-' in part:
            # Parse range
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            # Single port
            ports.add(int(part))
    
    return sorted(list(ports))
```

**Error Handling**:
- Validates port ranges (1-65535)
- Validates format
- Exits with error message on invalid input

---

### 7. OutputFormatter
**Purpose**: Formats and displays results

```python
class OutputFormatter:
    @staticmethod
    def print_header(target, threads, banner_grabbing)
    @staticmethod
    def print_results(results: Dict)
    @staticmethod
    def print_json_export(results: Dict, filename: str)
```

**Output Components**:
- Header with scanner info
- Scan statistics
- Open ports details table
- Security recommendations
- JSON export option

---

## Code Flow

### High-Level Flow Diagram

```
1. main()
   ├─ Parse arguments
   ├─ Parse ports (PortRangeParser)
   ├─ Create PortScanner instance
   ├─ Print header (OutputFormatter)
   └─ scan()
       ├─ Resolve target (gethostbyname)
       ├─ Create queue with ports
       ├─ Start 50 worker threads
       ├─ Each thread:
       │  ├─ Gets port from queue
       │  ├─ scan_port()
       │  │  ├─ Create socket
       │  │  ├─ Try connect_ex()
       │  │  ├─ If open: grab_banner()
       │  │  └─ Return (port, open, banner)
       │  └─ Store result (thread-safe)
       ├─ Wait for all ports complete
       └─ Compile results
   ├─ Print results (OutputFormatter)
   └─ Optionally export JSON
```

### Sequence Diagram (Single Port)

```
Thread          Scanner      Socket      Target
  │               │            │           │
  ├─ get port ────>            │           │
  │               │            │           │
  ├──────────────────> socket()│           │
  │               │            │           │
  ├──────────────────────> connect_ex()──>│
  │               │            │       (waiting)
  │<──────────────────────────────────────┤
  │  (port open)  │            │           │
  │               │            │           │
  ├──────────────────> grab_banner()      │
  │               │            │           │
  ├──────────────────────────> recv()─────>│
  │               │            │       (data)
  │<──────────────────────────────────────┤
  │  (banner)     │            │           │
  │               │            │           │
  ├─ store result──>            │           │
  │               │            │           │
```

---

## Key Algorithms

### 1. Multi-threaded Port Scanning

**Algorithm**: Producer-Consumer with Thread Pool

```
1. Main thread creates Queue with all ports
2. Main thread starts N worker threads
3. Each worker thread:
   - Gets next port from queue (blocking)
   - Scans port (with timeout)
   - Stores result (thread-safe)
   - Gets next port
4. Main thread waits for queue to empty
5. All workers exit when queue is empty
```

**Advantages**:
- Constant memory usage (queue size)
- Natural work distribution
- Easy shutdown handling
- Scales to any thread count

### 2. Graceful Shutdown

```python
self.stop_scanning = False  # Flag

def worker_thread(...):
    while not self.stop_scanning:  # Check flag
        try:
            port = port_queue.get(timeout=0.1)
        except queue.Empty:
            break

# In main:
try:
    port_queue.join()
except KeyboardInterrupt:
    self.stop_scanning = True  # Signal stop
```

**Features**:
- No forced thread termination
- Waits for queue to empty
- Allows cleanup
- Safe Ctrl+C handling

### 3. Thread-Safe Result Storage

```python
results_lock = threading.Lock()

# Critical section
with results_lock:
    self.open_ports[port] = banner  # Atomic operation
    self.total_ports_scanned += 1
```

**Benefits**:
- Prevents race conditions
- Atomic updates
- No data corruption
- Simple and efficient

---

## Data Structures

### 1. Results Dictionary (Output)

```python
results = {
    'target': '192.168.1.1',
    'ip_address': '192.168.1.1',
    'scan_time': '2026-05-02T14:23:45',
    'duration_seconds': 2.34,
    'total_ports_scanned': 25,
    'open_ports_count': 3,
    'closed_ports_count': 22,
    'open_ports_details': [
        {
            'port': 22,
            'service': 'SSH',
            'banner': 'SSH-2.0-OpenSSH_8.9p1'
        },
        # ... more ports
    ],
    'recommendations': [
        'Port 22 open (SSH). Ensure...',
        # ... more recommendations
    ]
}
```

### 2. Internal Scanner State

```python
class PortScanner:
    self.open_ports = {}        # {port: banner}
    self.closed_ports = set()   # {port, port, ...}
    self.results_lock = Lock()  # Thread synchronization
    self.total_ports_scanned = 0
    self.start_time = float
    self.end_time = float
    self.stop_scanning = bool   # Shutdown flag
```

---

## Error Handling

### 1. Hostname Resolution
```python
try:
    resolved_ip = socket.gethostbyname(self.target)
except socket.gaierror:
    print(f"Error: Could not resolve hostname '{self.target}'")
    sys.exit(1)
```

### 2. Port Scanning
```python
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(self.timeout)
    result = sock.connect_ex((host, port))
except socket.timeout:
    return port, False, ""  # Timeout = closed
except socket.error:
    return port, False, ""  # Error = closed
except Exception:
    return port, False, ""  # Unknown = closed
finally:
    sock.close()
```

### 3. Banner Grabbing
```python
try:
    banner = sock.recv(1024).decode('utf-8', errors='ignore')
except socket.timeout:
    return ""
except socket.error:
    return ""
except Exception:
    return ""
finally:
    sock.close()
```

### 4. File I/O
```python
try:
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
except IOError as e:
    print(f"Error saving to file: {e}")
```

### 5. User Interruption
```python
try:
    port_queue.join()
except KeyboardInterrupt:
    print(f"Scan interrupted by user")
    self.stop_scanning = True
    port_queue.join()
```

---

## Performance Considerations

### 1. Threading Overhead
- Default 50 threads balances speed vs. overhead
- More threads = faster but more memory/CPU
- Fewer threads = slower but lighter
- Optimal: network-dependent (test both)

### 2. Socket Timeout
- Default 3.0 seconds
- Shorter = faster but misses slow services
- Longer = slower but catches everything
- Adjust based on network quality

### 3. Banner Grabbing
- Adds ~0.5-1.0 second per port
- `--no-banner` can make scanning 2-3x faster
- Useful for reconnaissance vs. enumeration

### 4. Port Selection
- 25 common ports: ~2-5 seconds
- 1000 ports: ~20-40 seconds
- Full scan (65535): ~5-15 minutes
- Start with common, expand as needed

### 5. Memory Usage
- Queue holds all ports (minimal)
- Results hold open port data only
- Thread stack: ~8MB per thread
- Total: 50 threads × 8MB = ~400MB

### 6. Network Impact
- 50 concurrent TCP connections
- Throttled by port timeout
- Minimal traffic per port (1-3 packets)
- Total data: <100KB per full scan

---

## Extending the Code

### Adding a New Service

```python
# In ServiceMapper.SERVICES:
{
    9200: 'Elasticsearch',  # Add new port
    # ...
}
```

### Adding Security Recommendation

```python
# In SecurityAdvisor.RECOMMENDATIONS:
{
    9200: "🚨 Port 9200 open (Elasticsearch). Disable if exposed...",
    # ...
}
```

### Custom Banner Probe

```python
def grab_banner(host, port, timeout=2.0):
    # Custom probe for specific service
    if port == 9200:  # Elasticsearch
        sock.send(b'GET / HTTP/1.0\r\n\r\n')
```

### Filter Results

```python
# Only return database ports
db_results = {
    port: banner for port, banner in open_ports.items()
    if ServiceMapper.is_database_port(port)
}
```

---

## Testing & Validation

### Unit Test Examples

```python
# Test port parser
assert PortRangeParser.parse_ports("22") == [22]
assert PortRangeParser.parse_ports("20-25") == [20,21,22,23,24,25]
assert PortRangeParser.parse_ports("22,80,443") == [22, 80, 443]

# Test service mapper
assert ServiceMapper.get_service(22) == "SSH"
assert ServiceMapper.is_web_port(80) == True
assert ServiceMapper.is_database_port(3306) == True

# Test color codes
assert ColorCodes.GREEN in ['\033[92m']
```

### Integration Test

```python
# Scan localhost
scanner = PortScanner('localhost', threads=5, timeout=2.0)
results = scanner.scan([22, 80, 443])

# Verify results structure
assert 'open_ports_details' in results
assert 'recommendations' in results
assert isinstance(results['duration_seconds'], float)
```

---

## Conclusion

The Advanced Port Scanner demonstrates:
- **Modular design** with separated concerns
- **Thread-safe** concurrent execution
- **Robust error** handling
- **Professional** code quality
- **Extensible** architecture

Perfect for a cybersecurity portfolio!
