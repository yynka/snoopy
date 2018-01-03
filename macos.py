#!/usr/bin/env python3

"""
macos network intrusion detection and response system

monitors network traffic for attacks, blocks with pfctl, integrates with macos system logs,
and handles automatic port reopening when attacks stop
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import logging
import signal
import pwd
import grp
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

# macos-specific log locations
SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / "logs"
SYSTEM_LOG_DIR = Path("/var/log/intrusion-detector") if os.geteuid() == 0 else LOGS_DIR
SYSTEM_LOG_DIR.mkdir(exist_ok=True, mode=0o755)

# setup logging with macos system integration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(SYSTEM_LOG_DIR / 'intrusion_monitor.log'))
    ]
)

# integrate with unified logging system
logger = logging.getLogger(__name__)

def log_to_macos_system(message, level="info"):
    """log to macos unified logging system"""
    try:
        subprocess.run(['log', level, f'intrusion-detector: {message}'], 
                      capture_output=True, check=False, timeout=2)
    except:
        pass

@dataclass
class AttackAttempt:
    attacker_ip: str
    target_port: int
    attack_type: str
    timestamp: datetime
    packet_count: int = 1
    duration: float = 0.0
    attack_details: Dict = None
    geo_location: str = None
    reverse_dns: str = None
    
    def __post_init__(self):
        if self.attack_details is None:
            self.attack_details = {}
    
    def to_dict(self):
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass
class BlockedPort:
    port: int
    blocked_at: datetime
    attacker_ips: Set[str]
    attack_count: int
    pfctl_rule_id: str
    service_name: str
    
    def to_dict(self):
        data = asdict(self)
        data['blocked_at'] = self.blocked_at.isoformat()
        data['attacker_ips'] = list(self.attacker_ips)
        return data

class MacOSIntrusionDetector:
    def __init__(self, interface=None, suspicious_threshold=10, block_duration=300):
        self.interface = interface or self.find_default_network_interface()
        self.suspicious_threshold = suspicious_threshold
        self.block_duration = block_duration
        self.monitoring_active = False
        
        # track connection attempts per IP per port
        self.connection_attempts_by_ip_and_port = defaultdict(lambda: defaultdict(deque))
        self.currently_blocked_ports = {}
        self.active_attacks_by_ip_and_port = {}
        self.completed_attack_history = []
        self.blocked_ips_with_pfctl = set()
        
        # macos-specific monitored services
        self.monitored_ports_with_services = {
            22: "SSH",
            23: "Telnet",
            21: "FTP", 
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            548: "AFP",
            631: "CUPS",
            2049: "NFS",
            5900: "VNC",
            3389: "RDP",
            8080: "HTTP-Alt",
            5000: "AirPlay"
        }
        
        # pfctl anchor for our rules
        self.pfctl_anchor_name = "intrusion_blocker"
        self.setup_pfctl_anchor()
        
        logger.info(f"initialized macos intrusion detector on interface {self.interface}")
        logger.info(f"logging to {SYSTEM_LOG_DIR}")
        log_to_macos_system(f"intrusion detector initialized on {self.interface}")
    
    def find_default_network_interface(self):
        try:
            # get default route interface on macos
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    interface_name = line.split(':')[1].strip()
                    logger.info(f"using network interface: {interface_name}")
                    return interface_name
            
            # fallback to common macos interfaces
            network_interfaces = psutil.net_if_addrs()
            for interface_name in ['en0', 'en1', 'en2']:
                if interface_name in network_interfaces:
                    for addr in network_interfaces[interface_name]:
                        if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                            logger.info(f"using fallback interface: {interface_name}")
                            return interface_name
                            
        except Exception as e:
            logger.error(f"couldnt determine default interface: {e}")
            return None
    
    def setup_pfctl_anchor(self):
        try:
            # create anchor in pfctl if it doesnt exist
            anchor_rule = f"anchor \"{self.pfctl_anchor_name}\""
            
            # check if anchor already exists
            result = subprocess.run(['pfctl', '-s', 'Anchors'], 
                                  capture_output=True, text=True, check=False)
            
            if self.pfctl_anchor_name not in result.stdout:
                # add anchor to pf config
                with open('/etc/pf.conf', 'r') as f:
                    pf_config = f.read()
                
                if anchor_rule not in pf_config:
                    # backup original config
                    subprocess.run(['cp', '/etc/pf.conf', '/etc/pf.conf.backup'], check=False)
                    
                    # add our anchor
                    with open('/etc/pf.conf', 'a') as f:
                        f.write(f"\n# intrusion detector anchor\n{anchor_rule}\n")
                    
                    # reload pfctl
                    subprocess.run(['pfctl', '-f', '/etc/pf.conf'], check=False)
            
            # enable pf if not already enabled
            subprocess.run(['pfctl', '-e'], capture_output=True, check=False)
            
            logger.info(f"pfctl anchor {self.pfctl_anchor_name} ready")
            
        except Exception as e:
            logger.error(f"failed to setup pfctl anchor: {e}")
    
    def connection_attempt_looks_like_attack(self, src_ip, dst_port, packet_flags=""):
        now = datetime.now()
        
        # clean old attempts (older than 60 seconds)
        cutoff_time = now - timedelta(seconds=60)
        recent_attempts_from_this_ip = self.connection_attempts_by_ip_and_port[src_ip][dst_port]
        while recent_attempts_from_this_ip and recent_attempts_from_this_ip[0] < cutoff_time:
            recent_attempts_from_this_ip.popleft()
        
        recent_attempts_from_this_ip.append(now)
        attempt_count = len(recent_attempts_from_this_ip)
        
        # macos-specific attack patterns
        if dst_port == 22:  # ssh on macos
            return attempt_count >= 4
        elif dst_port == 548:  # afp file sharing
            return attempt_count >= 3
        elif dst_port == 5900:  # vnc screen sharing
            return attempt_count >= 2
        elif dst_port == 631:  # cups printing
            return attempt_count >= 5
        elif dst_port in [3306, 5432]:  # databases
            return attempt_count >= 3
        elif dst_port == 5000:  # airplay
            return attempt_count >= 4
        else:
            return attempt_count >= self.suspicious_threshold
    
    def block_port_using_pfctl(self, port, attacker_ips):
        try:
            service_name = self.monitored_ports_with_services.get(port, f"port-{port}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # create pfctl rules file for this block
            rules_file = SYSTEM_LOG_DIR / f"pfctl_rules_{timestamp}.conf"
            
            with open(rules_file, 'w') as f:
                # block the port
                f.write(f"block in proto tcp from any to any port {port}\n")
                f.write(f"block out proto tcp from any to any port {port}\n")
                
                # block attacking IPs completely
                for ip in attacker_ips:
                    f.write(f"block in from {ip} to any\n")
                    f.write(f"block out from any to {ip}\n")
                    self.blocked_ips_with_pfctl.add(ip)
            
            # load rules into our anchor
            cmd = ['pfctl', '-a', self.pfctl_anchor_name, '-f', str(rules_file)]
            subprocess.run(cmd, check=True)
            
            blocked_port_info = BlockedPort(
                port=port,
                blocked_at=datetime.now(),
                attacker_ips=set(attacker_ips),
                attack_count=len(attacker_ips),
                pfctl_rule_id=str(rules_file),
                service_name=service_name
            )
            
            self.currently_blocked_ports[port] = blocked_port_info
            
            # try to stop the service if its running
            self.try_stopping_service_temporarily(service_name)
            
            logger.warning(f"BLOCKED PORT {port} ({service_name}) due to attacks from {len(attacker_ips)} IPs")
            log_to_macos_system(f"blocked port {port} ({service_name}) - attack from {', '.join(attacker_ips)}", "error")
            self.send_macos_notification(f"Security Alert", f"Blocked port {port} ({service_name}) due to attack")
            
            return str(rules_file)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"failed to block port {port} with pfctl: {e}")
            return None
    
    def try_stopping_service_temporarily(self, service_name):
        # map service names to macos launchd service names
        launchd_services = {
            "SSH": "com.openssh.sshd",
            "FTP": "com.apple.ftpd", 
            "AFP": "com.apple.AppleFileServer",
            "VNC": "com.apple.screensharing",
            "CUPS": "org.cups.cupsd",
            "MySQL": "homebrew.mxcl.mysql",
            "PostgreSQL": "homebrew.mxcl.postgresql",
            "Redis": "homebrew.mxcl.redis"
        }
        
        service_id = launchd_services.get(service_name)
        if not service_id:
            return
        
        try:
            # check if service is loaded
            result = subprocess.run(['launchctl', 'list', service_id], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"temporarily stopping {service_id} due to attack")
                subprocess.run(['launchctl', 'unload', '-w', f'/System/Library/LaunchDaemons/{service_id}.plist'], 
                             check=False)
                
                # schedule restart after block duration
                def restart_service_later():
                    time.sleep(self.block_duration + 60)
                    try:
                        subprocess.run(['launchctl', 'load', '-w', f'/System/Library/LaunchDaemons/{service_id}.plist'], 
                                     check=True)
                        logger.info(f"automatically restarted {service_id}")
                    except Exception as e:
                        logger.error(f"failed to restart {service_id}: {e}")
                
                restart_thread = threading.Thread(target=restart_service_later, daemon=True)
                restart_thread.start()
                
        except Exception as e:
            logger.debug(f"couldnt stop service {service_id}: {e}")
    
    def unblock_port_using_pfctl(self, port):
        if port not in self.currently_blocked_ports:
            return
        
        blocked_info = self.currently_blocked_ports[port]
        
        try:
            # flush our anchor to remove all rules
            subprocess.run(['pfctl', '-a', self.pfctl_anchor_name, '-F', 'all'], 
                         capture_output=True, check=True)
            
            # clean up rules file
            rules_file = Path(blocked_info.pfctl_rule_id)
            if rules_file.exists():
                rules_file.unlink()
            
            logger.info(f"UNBLOCKED PORT {port} ({blocked_info.service_name}) - attack stopped")
            log_to_macos_system(f"unblocked port {port} ({blocked_info.service_name})")
            self.send_macos_notification("Security Alert", f"Port {port} ({blocked_info.service_name}) unblocked - Safe to resume")
            
            block_history_entry = {
                'unblocked_at': datetime.now().isoformat(),
                'total_block_duration': (datetime.now() - blocked_info.blocked_at).total_seconds(),
                **blocked_info.to_dict()
            }
            
            self.save_port_blocking_history(block_history_entry)
            del self.currently_blocked_ports[port]
            
        except subprocess.CalledProcessError as e:
            logger.error(f"failed to unblock port {port}: {e}")
    
    def handle_detected_attack_attempt(self, src_ip, dst_port):
        attack_key = (src_ip, dst_port)
        
        if attack_key in self.active_attacks_by_ip_and_port:
            self.active_attacks_by_ip_and_port[attack_key].packet_count += 1
            self.active_attacks_by_ip_and_port[attack_key].timestamp = datetime.now()
        else:
            attack_type = self.determine_attack_type_from_patterns(dst_port, src_ip)
            
            # try to get reverse dns
            reverse_dns = self.get_reverse_dns_safely(src_ip)
            
            attack = AttackAttempt(
                attacker_ip=src_ip,
                target_port=dst_port,
                attack_type=attack_type,
                timestamp=datetime.now(),
                reverse_dns=reverse_dns,
                attack_details={
                    'service': self.monitored_ports_with_services.get(dst_port, 'Unknown'),
                    'first_seen': datetime.now().isoformat(),
                    'interface': self.interface,
                    'macos_version': self.get_macos_version()
                }
            )
            
            self.active_attacks_by_ip_and_port[attack_key] = attack
            logger.warning(f"ATTACK DETECTED: {attack_type} from {src_ip} ({reverse_dns}) targeting port {dst_port}")
            log_to_macos_system(f"attack detected: {attack_type} from {src_ip} targeting port {dst_port}", "error")
        
        # check if we should block the port
        all_attackers_targeting_this_port = [ip for (ip, port) in self.active_attacks_by_ip_and_port.keys() if port == dst_port]
        
        if len(all_attackers_targeting_this_port) >= 2 or len(self.connection_attempts_by_ip_and_port[src_ip][dst_port]) >= self.suspicious_threshold:
            if dst_port not in self.currently_blocked_ports:
                self.block_port_using_pfctl(dst_port, all_attackers_targeting_this_port)
    
    def get_macos_version(self):
        try:
            result = subprocess.run(['sw_vers'], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except:
            return "unknown macos version"
    
    def get_reverse_dns_safely(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "unknown"
    
    def determine_attack_type_from_patterns(self, port, src_ip):
        attempt_count = len(self.connection_attempts_by_ip_and_port[src_ip][port])
        
        if port == 22:
            return "SSH_BRUTE_FORCE"
        elif port == 548:
            return "AFP_FILE_SHARING_ATTACK"
        elif port == 5900:
            return "VNC_SCREEN_SHARING_ATTACK"
        elif port == 631:
            return "CUPS_PRINTER_ATTACK"
        elif port in [3306, 5432]:
            return "DATABASE_ATTACK"
        elif port in [80, 443, 8080]:
            return "WEB_APPLICATION_ATTACK"
        elif port == 5000:
            return "AIRPLAY_ATTACK"
        elif port == 2049:
            return "NFS_ATTACK"
        else:
            return "PORT_SCAN_OR_BRUTE_FORCE"
    
    def analyze_packet_for_suspicious_activity(self, packet):
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        if not packet.haslayer(TCP):
            return
        
        tcp_layer = packet[TCP]
        dst_port = tcp_layer.dport
        
        if dst_port not in self.monitored_ports_with_services:
            return
        
        if self.ip_address_is_from_local_network(src_ip) or self.ip_address_is_from_local_network(dst_ip):
            return
        
        if self.connection_attempt_looks_like_attack(src_ip, dst_port, str(tcp_layer.flags)):
            self.handle_detected_attack_attempt(src_ip, dst_port)
    
    def ip_address_is_from_local_network(self, ip):
        try:
            # check common private networks
            if (ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.') or
                ip.startswith('127.') or 
                ip.startswith('169.254.')):
                return True
            
            # check against actual interface IPs
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET and ip == addr.address:
                        return True
            return False
        except:
            return False
    
    def cleanup_attacks_that_have_stopped(self):
        now = datetime.now()
        expired_attacks = []
        
        for attack_key, attack in self.active_attacks_by_ip_and_port.items():
            # macos systems typically less targeted, longer timeout
            if (now - attack.timestamp).total_seconds() > 120:
                attack.duration = (now - attack.timestamp).total_seconds()
                self.completed_attack_history.append(attack)
                expired_attacks.append(attack_key)
                
                self.save_attack_details_to_log_file(attack)
        
        for key in expired_attacks:
            src_ip, dst_port = key
            logger.info(f"attack from {src_ip} on port {dst_port} appears to have stopped")
            del self.active_attacks_by_ip_and_port[key]
        
        self.check_if_blocked_ports_can_be_reopened()
    
    def check_if_blocked_ports_can_be_reopened(self):
        now = datetime.now()
        
        for port in list(self.currently_blocked_ports.keys()):
            blocked_info = self.currently_blocked_ports[port]
            
            attacks_still_active_on_this_port = [
                attack for (ip, p), attack in self.active_attacks_by_ip_and_port.items() 
                if p == port
            ]
            
            block_duration_so_far = (now - blocked_info.blocked_at).total_seconds()
            
            if not attacks_still_active_on_this_port and block_duration_so_far > 60:
                if block_duration_so_far > self.block_duration:
                    self.unblock_port_using_pfctl(port)
                else:
                    unblock_cmd = self.get_command_to_manually_unblock_port(port)
                    logger.info(f"port {port} ({blocked_info.service_name}) can be safely reopened")
                    self.send_macos_notification("Security Alert", 
                        f"Port {port} ({blocked_info.service_name}) safe to reopen")
    
    def get_command_to_manually_unblock_port(self, port):
        if port not in self.currently_blocked_ports:
            return "Port not currently blocked"
        
        return f'pfctl -a {self.pfctl_anchor_name} -F all'
    
    def send_macos_notification(self, title, message):
        logger.warning(f"NOTIFICATION: {title} - {message}")
        
        try:
            # use applescript for native macos notifications
            applescript = f'''
            display notification "{message}" with title "{title}" sound name "Basso"
            '''
            subprocess.run(['osascript', '-e', applescript], 
                         capture_output=True, check=False, timeout=5)
        except:
            try:
                # fallback to terminal-notifier if available
                subprocess.run(['terminal-notifier', '-title', title, '-message', message], 
                             capture_output=True, check=False, timeout=5)
            except:
                pass
    
    def save_attack_details_to_log_file(self, attack):
        try:
            log_date = attack.timestamp.strftime("%Y-%m-%d")
            log_file = SYSTEM_LOG_DIR / f"attacks_{log_date}.json"
            
            if log_file.exists():
                with open(log_file, 'r') as f:
                    attacks = json.load(f)
            else:
                attacks = []
            
            attacks.append(attack.to_dict())
            
            with open(log_file, 'w') as f:
                json.dump(attacks, f, indent=2)
            
            # set appropriate permissions for macos
            try:
                if os.geteuid() == 0:
                    os.chown(log_file, 0, 80)  # wheel group on macos
                    os.chmod(log_file, 0o640)
            except:
                pass
            
            logger.info(f"saved attack log to {log_file}")
            
        except Exception as e:
            logger.error(f"failed to save attack log: {e}")
    
    def save_port_blocking_history(self, block_info):
        try:
            log_date = datetime.now().strftime("%Y-%m-%d")
            log_file = SYSTEM_LOG_DIR / f"blocked_ports_{log_date}.json"
            
            if log_file.exists():
                with open(log_file, 'r') as f:
                    blocks = json.load(f)
            else:
                blocks = []
            
            blocks.append(block_info)
            
            with open(log_file, 'w') as f:
                json.dump(blocks, f, indent=2)
            
            try:
                if os.geteuid() == 0:
                    os.chown(log_file, 0, 80)  # wheel group
                    os.chmod(log_file, 0o640)
            except:
                pass
            
            logger.info(f"saved block history to {log_file}")
            
        except Exception as e:
            logger.error(f"failed to save block history: {e}")
    
    def start_monitoring_network_traffic(self):
        logger.info("starting macos network intrusion monitoring...")
        logger.info(f"monitoring ports: {list(self.monitored_ports_with_services.keys())}")
        logger.info(f"suspicious threshold: {self.suspicious_threshold} attempts")
        log_to_macos_system("network intrusion monitoring started")
        
        self.monitoring_active = True
        
        cleanup_thread = threading.Thread(target=self.run_background_cleanup_worker, daemon=True)
        cleanup_thread.start()
        
        # monitor system resources and thermal state
        resource_thread = threading.Thread(target=self.monitor_system_resources, daemon=True)
        resource_thread.start()
        
        try:
            filter_ports = " or ".join([f"dst port {port}" for port in self.monitored_ports_with_services.keys()])
            packet_filter = f"tcp and ({filter_ports})"
            
            logger.info(f"starting packet capture with filter: {packet_filter}")
            
            scapy.sniff(
                iface=self.interface,
                filter=packet_filter,
                prn=self.analyze_packet_for_suspicious_activity,
                stop_filter=lambda x: not self.monitoring_active
            )
            
        except KeyboardInterrupt:
            logger.info("monitoring stopped by user")
            log_to_macos_system("monitoring stopped by user")
        except Exception as e:
            logger.error(f"monitoring error: {e}")
            log_to_macos_system(f"monitoring error: {e}", "error")
        finally:
            self.stop_monitoring_and_cleanup()
    
    def monitor_system_resources(self):
        while self.monitoring_active:
            try:
                # check system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                # check thermal state on macos
                try:
                    result = subprocess.run(['pmset', '-g', 'therm'], 
                                          capture_output=True, text=True, check=False)
                    if "CPU_Slow_Mode" in result.stdout and "1" in result.stdout:
                        logger.warning("system in thermal throttling mode")
                except:
                    pass
                
                if cpu_percent > 85 or memory_percent > 90:
                    logger.warning(f"system under load - CPU: {cpu_percent}%, Memory: {memory_percent}%")
                
                time.sleep(45)  # longer interval on macos
            except Exception as e:
                logger.debug(f"resource monitoring error: {e}")
    
    def run_background_cleanup_worker(self):
        while self.monitoring_active:
            try:
                self.cleanup_attacks_that_have_stopped()
                time.sleep(30)  # moderate cleanup frequency
            except Exception as e:
                logger.error(f"cleanup worker error: {e}")
    
    def cleanup_pfctl_on_exit(self):
        try:
            # flush our anchor
            subprocess.run(['pfctl', '-a', self.pfctl_anchor_name, '-F', 'all'], 
                         capture_output=True, check=False)
            
            # clean up rules files
            for rules_file in SYSTEM_LOG_DIR.glob("pfctl_rules_*.conf"):
                rules_file.unlink()
            
            logger.info("cleaned up pfctl rules")
            log_to_macos_system("cleaned up firewall rules")
        except Exception as e:
            logger.error(f"failed to cleanup pfctl: {e}")
    
    def stop_monitoring_and_cleanup(self):
        logger.info("stopping macos intrusion monitoring...")
        log_to_macos_system("intrusion monitoring stopped")
        self.monitoring_active = False
        
        summary = {
            'stop_time': datetime.now().isoformat(),
            'total_attacks_detected': len(self.completed_attack_history),
            'currently_blocked_ports': {
                port: info.to_dict() for port, info in self.currently_blocked_ports.items()
            },
            'active_attacks': len(self.active_attacks_by_ip_and_port),
            'blocked_ips_count': len(self.blocked_ips_with_pfctl),
            'macos_version': self.get_macos_version()
        }
        
        summary_file = SYSTEM_LOG_DIR / f"monitoring_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"monitoring summary saved to {summary_file}")
        
        for port in list(self.currently_blocked_ports.keys()):
            logger.info(f"port {port} still blocked - unblock: {self.get_command_to_manually_unblock_port(port)}")
        
        # cleanup pfctl rules
        self.cleanup_pfctl_on_exit()

def handle_ctrl_c_gracefully(signum, frame):
    logger.info("received interrupt signal, shutting down...")
    log_to_macos_system("received shutdown signal")
    sys.exit(0)

def check_macos_capabilities():
    # check if we have necessary capabilities
    missing_capabilities = []
    
    if os.geteuid() != 0:
        missing_capabilities.append("root privileges (needed for pfctl and raw sockets)")
    
    # check for required tools
    required_tools = ['pfctl', 'launchctl', 'route']
    for tool in required_tools:
        if not subprocess.run(['which', tool], capture_output=True).returncode == 0:
            missing_capabilities.append(f"{tool} command")
    
    # check if we can access pfctl
    try:
        subprocess.run(['pfctl', '-s', 'info'], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        missing_capabilities.append("pfctl access (try running with sudo)")
    
    if missing_capabilities:
        logger.error(f"missing requirements: {', '.join(missing_capabilities)}")
        return False
    return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='macOS Network Intrusion Detection and Response')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold', type=int, default=8, help='Suspicious attempt threshold')
    parser.add_argument('--block-duration', type=int, default=300, help='Auto-unblock duration in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not check_macos_capabilities():
        sys.exit(1)
    
    signal.signal(signal.SIGINT, handle_ctrl_c_gracefully)
    signal.signal(signal.SIGTERM, handle_ctrl_c_gracefully)
    
    try:
        detector = MacOSIntrusionDetector(
            interface=args.interface,
            suspicious_threshold=args.threshold,
            block_duration=args.block_duration
        )
        
        detector.start_monitoring_network_traffic()
        
    except Exception as e:
        logger.error(f"critical error: {e}")
        log_to_macos_system(f"critical error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
