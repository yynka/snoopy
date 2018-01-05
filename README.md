<a id="top"></a>
```
     ███████╗███╗   ██╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗  ⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
     ██╔════╝████╗  ██║██╔═══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝  ⠀⠀⠀⠀⠀⡠⠔⢊⣩⣭⡐⠳⣤⣤⣤⡀⠀⠀⠀⠀⠀
     ███████╗██╔██╗ ██║██║   ██║██║   ██║██████╔╝ ╚████╔╝   ⠀⠀⠀⢠⠊⠀⢠⣿⣿⣿⣿⣶⣿⣿⣿⣿⠍⠒⢄⠀⠀
     ╚════██║██║╚██╗██║██║   ██║██║   ██║██╔═══╝   ╚██╔╝    ⠀⠀⢀⠇⠀⣠⡼⢿⣿⣿⡿⠉⠻⣿⣿⠟⠀⠀⠀⠱⡄
     ███████║██║ ╚████║╚██████╔╝╚██████╔╝██║        ██║     ⠀⢀⢎⣶⣎⡇⠀⠀⠉⠁⠀⠀⠀⠀⣴⣶⣦⠀⠀⠀⠃
     ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝        ╚═╝     ⢠⣾⢸⣿⣿⣞⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡆
                                                           ⠻⢹⣸⣿⣿⣿⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠞⠀
                                                           ⠀⠈⢻⣿⣿⡿⣸⠤⢀⡀⠀⠀⠀⡠⠔⠒⠉⠁⠀⠀⠀
                                                           ⡠⢔⠒⡯⣓⣚⣁⣀⣀⣈⣷⣤⣴⣷⠀⠀⠀⠀⠀⠀⠀
                                                           ⠧⡈⠀⡟⠁⠀⠀⠀⠀⠈⠛⠛⠛⠻⢿⡄⠀⠀⠀⠀⠀
                                                           ⠰⣇⣰⠛⠦⠤⠤⠤⢤⠀⢀⣺⣿⣿⣿⣧⠀⠀⠀⠀⠀
                                                           ⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⢸⣿⣿⢿⠿⣾⣱⠀⠀⠀⠀
                                                           ⠀⠀⠀⠀⠀⠀⡠⠤⢼⡿⠿⠿⠿⠛⠛⠋⠀⡇⠀⠀⠀
                                                           ⠀⠀⠀⠀⠀⠀⠈⠉⠀⠈⠦⡀⠀⢀⣠⠂⢀⡇⠀⠀⠀
                                                           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⠒⠛⠀⠈⢅⠠⡈⠑⡀⠀
                                                           ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠈⠀⠁⠈⠀⠀
```

**Real-Time Network Intrusion Detection & Active Response System**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

## Enhanced Security Features

▸ **Real-Time Traffic Analysis** - Live packet inspection with intelligent attack pattern recognition  
▸ **Automatic Port Blocking** - Instant firewall response when attacks are detected  
▸ **Cross-Platform Support** - Native integration with Windows Firewall, iptables, and pfctl  
▸ **Intelligent Thresholds** - Service-specific attack detection (SSH: 3-5 attempts, Database: 2 attempts)  
▸ **Service Management** - Automatic service shutdown and restart during attacks  
▸ **Comprehensive Logging** - JSON-formatted attack logs with timestamps and attacker details  
▸ **System Integration** - Native notifications, syslog integration, and event logging  
▸ **Attack Classification** - Recognizes SSH brute force, database attacks, port scans, and more  
▸ **Reverse DNS Lookup** - Identifies attacking hosts with hostname resolution  
▸ **Fail2ban Integration** - Works alongside existing security tools (Linux only)  

## Attack Detection Profiles

### ■ **High Security Servers** (Aggressive Protection)
- [+] SSH: 3 attempts trigger block (Linux), 4 attempts (macOS), 5 attempts (Windows)
- [+] Database ports: 2 attempts (MySQL, PostgreSQL, Redis, MongoDB)
- [+] VNC/RDP: 2-3 attempts for remote desktop services
- [+] Automatic service shutdown during active attacks
- [+] Complete IP blocking in addition to port blocking

### ▲ **Balanced Workstations** (Standard Protection)
- [+] Moderate thresholds for daily use compatibility
- [+] Web services: Higher thresholds for legitimate traffic
- [+] Development ports: Balanced protection for local testing
- [+] Service management with longer grace periods

### ▪ **Development Systems** (Permissive Protection)
- [+] Higher thresholds to prevent blocking legitimate testing
- [+] Logging-focused with minimal automatic blocking
- [+] Configurable timeout periods for development workflows

---

## ◆ Windows <a id="windows"></a>[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#top)

### Prerequisites
▪ Windows 10/11 or Windows Server 2016+  
▪ Python 3.8+ with Administrator privileges  
▪ Windows Firewall service enabled  

### Installation
```cmd
# Clone repository
git clone https://github.com/yynka/snoopy.git
cd snoopy

# Install dependencies
pip install -r requirements.txt

# Or download directly
curl https://raw.githubusercontent.com/yynka/snoopy/main/windows.py -o windows.py
curl https://raw.githubusercontent.com/yynka/snoopy/main/requirements.txt -o requirements.txt
pip install -r requirements.txt
```

### Usage
```cmd
# Start monitoring with default settings
python windows.py

# Custom configuration
python windows.py --threshold 7 --block-duration 600 --debug

# Monitor specific network interface
python windows.py --interface "Ethernet 2"
```

### Advanced Windows Features
```cmd
# Enterprise Windows deployment
python windows.py --threshold 3 --block-duration 300
# Integrates with: Windows Event Log, Windows Firewall Advanced Security
# Monitors: SSH, RDP, WinRM, MSSQL, MySQL, HTTP/HTTPS, FTP, Telnet
# Blocks: Creates netsh firewall rules with automatic cleanup
# Logs: %SCRIPT_DIR%\logs\ with Windows Event Log integration
```

※ **Note:** Requires running Command Prompt or PowerShell as Administrator

---

## ◆ macOS <a id="macos"></a>[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#top)

### Prerequisites
▪ macOS 10.14+ (Mojave or later)  
▪ Python 3.8+ with `sudo` privileges  
▪ pfctl (Packet Filter) firewall support  

### Installation
```bash
# Clone repository
git clone https://github.com/yynka/snoopy.git
cd snoopy

# Install dependencies
pip3 install -r requirements.txt

# Or download directly
curl https://raw.githubusercontent.com/yynka/snoopy/main/macos.py -o macos.py
curl https://raw.githubusercontent.com/yynka/snoopy/main/requirements.txt -o requirements.txt
pip3 install -r requirements.txt
```

### Usage
```bash
# Start monitoring with elevated privileges
sudo python3 macos.py

# Custom configuration for Mac servers
sudo python3 macos.py --threshold 4 --block-duration 450 --debug

# Monitor specific network interface
sudo python3 macos.py --interface en1
```

### Advanced macOS Features
```bash
# Native macOS integration
sudo python3 macos.py --threshold 4 --block-duration 300
# Integrates with: macOS Unified Logging, pfctl firewall, launchctl services
# Monitors: SSH, AFP, VNC, CUPS, AirPlay, HTTP/HTTPS, MySQL, PostgreSQL
# Blocks: Creates pfctl anchor rules with automatic cleanup
# Notifications: Native AppleScript alerts with sound and Notification Center
# Logs: /var/log/intrusion-detector/ with proper macOS permissions
```

※ **Note:** Requires running commands with `sudo` for pfctl firewall access

---

## ◆ Linux <a id="linux"></a>[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#top)

### Prerequisites
▪ Linux distribution with iptables support  
▪ Python 3.8+ with `sudo` privileges  
▪ iptables and ip6tables utilities  

### Installation
```bash
# Clone repository
git clone https://github.com/yynka/snoopy.git
cd snoopy

# Install dependencies
pip3 install -r requirements.txt

# Or download directly
curl https://raw.githubusercontent.com/yynka/snoopy/main/linux.py -o linux.py
curl https://raw.githubusercontent.com/yynka/snoopy/main/requirements.txt -o requirements.txt
pip3 install -r requirements.txt
```

### Usage
```bash
# Start monitoring with default settings
sudo python3 linux.py

# High-security server configuration
sudo python3 linux.py --threshold 3 --block-duration 600 --debug

# Disable fail2ban integration if not available
sudo python3 linux.py --no-fail2ban
```

### Advanced Linux Features
```bash
# Enterprise Linux deployment
sudo python3 linux.py --threshold 3 --block-duration 300
# Integrates with: iptables/ip6tables, systemd, syslog, fail2ban
# Monitors: SSH, HTTP/HTTPS, FTP, MySQL, PostgreSQL, Redis, MongoDB, NFS, Docker
# Blocks: Custom iptables chain with IP and port blocking
# Services: Automatic systemd service management during attacks
# Logs: /var/log/intrusion-detector/ with syslog integration
# Fail2ban: Automatic IP addition to appropriate jails
```

※ **Note:** Requires running commands with `sudo` for iptables and service management

---

## ※ Command Reference & Configuration

### Universal Command Options
All platforms support the same core command structure:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--interface` | Network interface to monitor | Auto-detect | `--interface eth0` |
| `--threshold` | Suspicious attempts before blocking | 10 (8 Linux/macOS) | `--threshold 5` |
| `--block-duration` | Auto-unblock time in seconds | 300 | `--block-duration 600` |
| `--debug` | Enable verbose debug logging | False | `--debug` |

### Platform-Specific Options
| Platform | Option | Description | Example |
|----------|--------|-------------|---------|
| **Linux** | `--no-fail2ban` | Disable fail2ban integration | `--no-fail2ban` |
| **Windows** | N/A | Windows-specific options | N/A |
| **macOS** | N/A | macOS-specific options | N/A |

### Monitored Services & Thresholds
| Service | Port | Linux Threshold | macOS Threshold | Windows Threshold | Attack Type |
|---------|------|----------------|-----------------|-------------------|-------------|
| **SSH** | 22 | 3 attempts | 4 attempts | 5 attempts | SSH_BRUTE_FORCE |
| **FTP** | 21 | 5 attempts | 4 attempts | 8 attempts | FTP_BRUTE_FORCE |
| **Telnet** | 23 | 5 attempts | 4 attempts | 8 attempts | TELNET_ATTACK |
| **MySQL** | 3306 | 2 attempts | 3 attempts | 3 attempts | DATABASE_ATTACK |
| **PostgreSQL** | 5432 | 2 attempts | 3 attempts | 3 attempts | DATABASE_ATTACK |
| **Redis** | 6379 | 2 attempts | 4 attempts | 10 attempts | NOSQL_ATTACK |
| **RDP** | 3389 | N/A | 2 attempts | 3 attempts | RDP_BRUTE_FORCE |
| **VNC** | 5900 | N/A | 2 attempts | 10 attempts | VNC_ATTACK |
| **WinRM** | 5985 | N/A | N/A | 3 attempts | WINRM_ATTACK |

## Real-Time Attack Response

### Automatic Response Actions
```bash
# When attack detected:
# 1. Log attack details with timestamp and attacker info
# 2. Block attacking IP completely (all traffic)
# 3. Block target port (prevent further service access)
# 4. Send system notification
# 5. Optionally stop target service temporarily
# 6. Integrate with system security tools (fail2ban, Event Log, syslog)

# When attack stops:
# 1. Wait for cool-down period (60+ seconds)
# 2. Either auto-unblock after configured duration
# 3. Or provide manual unblock command with exact syntax
# 4. Log attack duration and effectiveness
# 5. Restart stopped services automatically
```

### Attack Log Format
```json
{
  "attacker_ip": "203.0.113.45",
  "target_port": 22,
  "attack_type": "SSH_BRUTE_FORCE",
  "timestamp": "2024-01-15T14:32:15.123456",
  "packet_count": 12,
  "duration": 67.2,
  "reverse_dns": "scanner.badguys.com",
  "attack_details": {
    "service": "SSH",
    "first_seen": "2024-01-15T14:31:08.456789",
    "interface": "eth0",
    "platform_info": "Linux Ubuntu 22.04"
  }
}
```

## Usage Examples

### Basic Monitoring
```bash
# Start with default settings (all platforms)
# Windows
python windows.py

# macOS
sudo python3 macos.py

# Linux
sudo python3 linux.py
```

### High-Security Server Deployment
```bash
# Aggressive protection for internet-facing servers
# Windows
python windows.py --threshold 3 --block-duration 900

# macOS
sudo python3 macos.py --threshold 3 --block-duration 900

# Linux (with fail2ban integration)
sudo python3 linux.py --threshold 2 --block-duration 1200
```

### Development Environment
```bash
# Permissive settings for development work
# Windows
python windows.py --threshold 15 --block-duration 120

# macOS
sudo python3 macos.py --threshold 12 --block-duration 120

# Linux (without fail2ban conflicts)
sudo python3 linux.py --threshold 15 --block-duration 120 --no-fail2ban
```

### Network Monitoring
```bash
# Monitor specific interfaces
# Windows
python windows.py --interface "Wi-Fi"

# macOS (Wi-Fi interface)
sudo python3 macos.py --interface en0

# Linux (Ethernet interface)
sudo python3 linux.py --interface enp0s3
```

## Technical Implementation

### Windows (Python + Windows Firewall)
▪ **Technology:** Windows Firewall with Advanced Security via `netsh` commands  
▪ **Method:** Creates named firewall rules with automatic cleanup on exit  
▪ **Rules:** `SecurityMonitor_Block_*` series with timestamps for tracking  
▪ **Integration:** Windows Event Log, native notifications, service management  
▪ **Features:** Real-time packet analysis, comprehensive attack logging  

### macOS (Python + pfctl)
▪ **Technology:** pfctl (Packet Filter) firewall with custom anchor system  
▪ **Method:** Creates rules files loaded into `intrusion_blocker` anchor  
▪ **Rules:** Block rules for both IPs and ports with automatic cleanup  
▪ **Integration:** Unified Logging, AppleScript notifications, launchctl services  
▪ **Features:** Thermal monitoring, native macOS service integration  

### Linux (Python + iptables)
▪ **Technology:** iptables and ip6tables with custom chain management  
▪ **Method:** Creates `INTRUSION_BLOCK` chain with commented rules  
▪ **Rules:** IP blocking and port blocking with connection tracking  
▪ **Integration:** syslog, systemd, fail2ban, desktop notifications  
▪ **Features:** System resource monitoring, comprehensive service management  

## Enhanced Security Benefits

▪ **Zero-Delay Response** - Attacks blocked within milliseconds of detection  
▪ **Intelligent Classification** - Recognizes 10+ different attack patterns  
▪ **Service-Aware Protection** - Tailored thresholds for different services and platforms  
▪ **System Integration** - Native integration with platform security tools  
▪ **Comprehensive Logging** - Enterprise-grade attack logging with JSON format  
▪ **Automatic Recovery** - Self-healing with automatic service restart and rule cleanup  
▪ **Cross-Platform Consistency** - Same protection logic across Windows, macOS, and Linux  
▪ **Real-Time Monitoring** - Live attack detection with instant response capabilities  
▪ **Forensic Analysis** - Detailed attack logs with timestamps, duration, and attacker details  
▪ **Production Ready** - Designed for 24/7 operation on critical systems  

## Output Examples

### Attack Detection in Progress
```
2024-01-15 14:32:15 - WARNING - ATTACK DETECTED: SSH_BRUTE_FORCE from 203.0.113.45 (scanner.badguys.com) targeting port 22
2024-01-15 14:32:15 - WARNING - BLOCKED PORT 22 (SSH) due to attacks from 1 IPs
2024-01-15 14:32:15 - WARNING - NOTIFICATION: PORT 22 (SSH) BLOCKED - Attack from 203.0.113.45
2024-01-15 14:32:15 - INFO - temporarily stopping ssh service due to attack
2024-01-15 14:32:15 - INFO - added 203.0.113.45 to fail2ban jail sshd
2024-01-15 14:32:15 - INFO - saved attack log to /var/log/intrusion-detector/attacks_2024-01-15.json
```

### Attack Resolution
```
2024-01-15 14:37:22 - INFO - attack from 203.0.113.45 on port 22 appears to have stopped
2024-01-15 14:37:45 - INFO - UNBLOCKED PORT 22 (SSH) - attack appears to have stopped
2024-01-15 14:37:45 - WARNING - NOTIFICATION: PORT 22 (SSH) UNBLOCKED - Safe to resume service
2024-01-15 14:37:45 - INFO - automatically restarted ssh service
2024-01-15 14:37:45 - INFO - saved block history to /var/log/intrusion-detector/blocked_ports_2024-01-15.json
```

### System Status
```
2024-01-15 14:35:10 - INFO - starting linux network intrusion monitoring...
2024-01-15 14:35:10 - INFO - monitoring ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 2049, 3306, 3389, 5432, 5985, 6379, 8080, 9200, 27017]
2024-01-15 14:35:10 - INFO - suspicious threshold: 8 attempts
2024-01-15 14:35:10 - INFO - fail2ban integration: enabled
2024-01-15 14:35:10 - INFO - starting packet capture with filter: tcp and (dst port 21 or dst port 22 or dst port 23...)
```

## Dependencies

| Platform | Core Requirements | System Integration | Optional Components |
|----------|-------------------|-------------------|-------------------|
| **Windows** | Python 3.8+, psutil, scapy, Administrator privileges | Windows Firewall, Event Log | Windows Defender integration |
| **macOS** | Python 3.8+, psutil, scapy, `sudo` privileges | pfctl, launchctl, Unified Logging | terminal-notifier, AppleScript |
| **Linux** | Python 3.8+, psutil, scapy, `sudo` privileges | iptables, systemd, syslog | fail2ban, desktop notifications |

### Python Dependencies
```txt
psutil>=5.9.0
scapy>=2.5.0
```

## File Structure

```
snoopy/
├── windows.py              # Windows intrusion detector
├── linux.py                # Linux intrusion detector  
├── macos.py                # macOS intrusion detector
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
└── logs/                  # Attack logs and monitoring data (created at runtime)
    ├── attacks_2024-01-15.json
    ├── blocked_ports_2024-01-15.json
    └── intrusion_monitor.log
```

---

## License

[MIT License](LICENSE) - Feel free to use and modify as needed.

**※ Security Note:** This tool provides enterprise-grade real-time intrusion detection and response capabilities. Requires administrative privileges on all platforms. Designed for production deployment on critical systems. Use responsibly and in compliance with your organization's security policies. Test thoroughly in non-production environments before deployment. 