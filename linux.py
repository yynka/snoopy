#!/usr/bin/env python3

"""
linux network intrusion detection and response system

monitors network traffic for attacks, blocks with iptables, integrates with system logs,
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

# linux-specific log locations
SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / "logs"
SYSTEM_LOG_DIR = Path("/var/log/intrusion-detector") if os.geteuid() == 0 else LOGS_DIR
SYSTEM_LOG_DIR.mkdir(exist_ok=True, mode=0o755)

# setup logging with syslog integration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(SYSTEM_LOG_DIR / 'intrusion_monitor.log'))
    ]
)

# also log to syslog if available
try:
    from logging.handlers import SysLogHandler
    syslog_handler = SysLogHandler(address='/dev/log')
    syslog_handler.setFormatter(logging.Formatter('intrusion-detector: %(message)s'))
    logging.getLogger().addHandler(syslog_handler)
except:
    pass

logger = logging.getLogger(__name__)

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
    iptables_rule_id: str
    service_name: str
    
    def to_dict(self):
        data = asdict(self)
        data['blocked_at'] = self.blocked_at.isoformat()
        data['attacker_ips'] = list(self.attacker_ips)
        return data

class LinuxIntrusionDetector:
    def __init__(self, interface=None, suspicious_threshold=10, block_duration=300, enable_fail2ban_integration=True):
        self.interface = interface or self.find_default_network_interface()
        self.suspicious_threshold = suspicious_threshold
        self.block_duration = block_duration
        self.enable_fail2ban_integration = enable_fail2ban_integration
        self.monitoring_active = False
        
        # track connection attempts per IP per port
        self.connection_attempts_by_ip_and_port = defaultdict(lambda: defaultdict(deque))
        self.currently_blocked_ports = {}
        self.active_attacks_by_ip_and_port = {}
        self.completed_attack_history = []
        self.blocked_ips_with_iptables = set()
        
        # linux-specific monitored services
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
            2049: "NFS",
            111: "Portmapper",
            2375: "Docker",
            8080: "HTTP-Alt",
            9200: "Elasticsearch"
        }
        
        # create custom iptables chain for our rules
        self.iptables_chain_name = "INTRUSION_BLOCK"
        self.setup_iptables_chain()
        
        logger.info(f"initialized linux intrusion detector on interface {self.interface}")
        logger.info(f"logging to {SYSTEM_LOG_DIR}")
    
    def find_default_network_interface(self):
        try:
            # get interface with default gateway
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[1] == '00000000':  # default route
                        interface_name = fields[0]
                        logger.info(f"using network interface: {interface_name}")
                        return interface_name
            
            # fallback to first non-loopback interface
            network_interfaces = psutil.net_if_addrs()
            for interface_name, addresses in network_interfaces.items():
                if interface_name.startswith(('eth', 'ens', 'wlan', 'wlp')):
                    for addr in addresses:
                        if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                            logger.info(f"using fallback interface: {interface_name}")
                            return interface_name
        except Exception as e:
            logger.error(f"couldnt determine default interface: {e}")
            return None
    
    def setup_iptables_chain(self):
        try:
            # create our custom chain if it doesnt exist
            subprocess.run(['iptables', '-N', self.iptables_chain_name], 
                         capture_output=True, check=False)
            
            # insert jump rule to our chain at the beginning of INPUT
            subprocess.run(['iptables', '-I', 'INPUT', '1', '-j', self.iptables_chain_name], 
                         capture_output=True, check=False)
            
            logger.info(f"iptables chain {self.iptables_chain_name} ready")
        except Exception as e:
            logger.error(f"failed to setup iptables chain: {e}")
    
    def connection_attempt_looks_like_attack(self, src_ip, dst_port, packet_flags=""):
        now = datetime.now()
        
        # clean old attempts (older than 60 seconds)
        cutoff_time = now - timedelta(seconds=60)
        recent_attempts_from_this_ip = self.connection_attempts_by_ip_and_port[src_ip][dst_port]
        while recent_attempts_from_this_ip and recent_attempts_from_this_ip[0] < cutoff_time:
            recent_attempts_from_this_ip.popleft()
        
        recent_attempts_from_this_ip.append(now)
        attempt_count = len(recent_attempts_from_this_ip)
        
        # linux-specific attack patterns
        if dst_port == 22:  # ssh brute force is super common on linux
            return attempt_count >= 3
        elif dst_port in [21, 23]:  # ftp/telnet
            return attempt_count >= 5
        elif dst_port in [3306, 5432]:  # database ports
            return attempt_count >= 2
        elif dst_port in [2049, 111]:  # nfs/portmapper
            return attempt_count >= 3
        elif dst_port in [6379, 27017]:  # redis/mongo
            return attempt_count >= 2
        else:
            return attempt_count >= self.suspicious_threshold
    
    def block_port_using_iptables(self, port, attacker_ips):
        try:
            service_name = self.monitored_ports_with_services.get(port, f"port-{port}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_comment = f"intrusion-block-{service_name}-{timestamp}"
            
            # block the port in our custom chain
            cmd = [
                'iptables', '-A', self.iptables_chain_name,
                '-p', 'tcp', '--dport', str(port),
                '-j', 'DROP',
                '-m', 'comment', '--comment', rule_comment
            ]
            
            result = subprocess.run(cmd, capture_output=True, check=True)
            
            # also block the attacking IPs completely
            for ip in attacker_ips:
                if ip not in self.blocked_ips_with_iptables:
                    ip_cmd = [
                        'iptables', '-A', self.iptables_chain_name,
                        '-s', ip,
                        '-j', 'DROP',
                        '-m', 'comment', '--comment', f'attacker-{ip}-{timestamp}'
                    ]
                    subprocess.run(ip_cmd, capture_output=True, check=False)
                    self.blocked_ips_with_iptables.add(ip)
            
            blocked_port_info = BlockedPort(
                port=port,
                blocked_at=datetime.now(),
                attacker_ips=set(attacker_ips),
                attack_count=len(attacker_ips),
                iptables_rule_id=rule_comment,
                service_name=service_name
            )
            
            self.currently_blocked_ports[port] = blocked_port_info
            
            # try to stop the service if its running
            self.try_stopping_service_temporarily(service_name)
            
            logger.warning(f"BLOCKED PORT {port} ({service_name}) due to attacks from {len(attacker_ips)} IPs")
            self.send_notification_about_security_event(f"PORT {port} ({service_name}) BLOCKED - Attack from {', '.join(attacker_ips)}")
            
            # integrate with fail2ban if available
            if self.enable_fail2ban_integration:
                self.add_ips_to_fail2ban(attacker_ips, service_name)
            
            return rule_comment
            
        except subprocess.CalledProcessError as e:
            logger.error(f"failed to block port {port} with iptables: {e}")
            return None
    
    def try_stopping_service_temporarily(self, service_name):
        # map service names to systemd service names
        systemd_services = {
            "SSH": "ssh",
            "FTP": "vsftpd",
            "MySQL": "mysql",
            "PostgreSQL": "postgresql",
            "Redis": "redis-server",
            "MongoDB": "mongod",
            "NFS": "nfs-server"
        }
        
        systemd_name = systemd_services.get(service_name)
        if not systemd_name:
            return
        
        try:
            # check if service is running
            result = subprocess.run(['systemctl', 'is-active', systemd_name], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'active':
                logger.info(f"temporarily stopping {systemd_name} service due to attack")
                subprocess.run(['systemctl', 'stop', systemd_name], check=True)
                
                # schedule restart after block duration
                def restart_service_later():
                    time.sleep(self.block_duration + 60)  # extra minute buffer
                    try:
                        subprocess.run(['systemctl', 'start', systemd_name], check=True)
                        logger.info(f"automatically restarted {systemd_name} service")
                    except Exception as e:
                        logger.error(f"failed to restart {systemd_name}: {e}")
                
                restart_thread = threading.Thread(target=restart_service_later, daemon=True)
                restart_thread.start()
                
        except Exception as e:
            logger.debug(f"couldnt stop service {systemd_name}: {e}")
    
    def add_ips_to_fail2ban(self, attacker_ips, service_name):
        try:
            # map to fail2ban jail names
            fail2ban_jails = {
                "SSH": "sshd",
                "FTP": "vsftpd",
                "HTTP": "apache",
                "HTTPS": "apache-ssl"
            }
            
            jail_name = fail2ban_jails.get(service_name)
            if not jail_name:
                return
            
            for ip in attacker_ips:
                cmd = ['fail2ban-client', 'set', jail_name, 'banip', ip]
                result = subprocess.run(cmd, capture_output=True, check=False)
                if result.returncode == 0:
                    logger.info(f"added {ip} to fail2ban jail {jail_name}")
                    
        except Exception as e:
            logger.debug(f"fail2ban integration failed: {e}")
    
    def unblock_port_using_iptables(self, port):
        if port not in self.currently_blocked_ports:
            return
        
        blocked_info = self.currently_blocked_ports[port]
        rule_comment = blocked_info.iptables_rule_id
        
        try:
            # remove the port block rule
            cmd = [
                'iptables', '-D', self.iptables_chain_name,
                '-p', 'tcp', '--dport', str(port),
                '-j', 'DROP',
                '-m', 'comment', '--comment', rule_comment
            ]
            subprocess.run(cmd, capture_output=True, check=True)
            
            logger.info(f"UNBLOCKED PORT {port} ({blocked_info.service_name}) - attack stopped")
            self.send_notification_about_security_event(f"PORT {port} ({blocked_info.service_name}) UNBLOCKED - Safe to resume")
            
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
            
            # try to get reverse dns and geo info
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
                    'interface': self.interface
                }
            )
            
            self.active_attacks_by_ip_and_port[attack_key] = attack
            logger.warning(f"ATTACK DETECTED: {attack_type} from {src_ip} ({reverse_dns}) targeting port {dst_port}")
        
        # check if we should block the port
        all_attackers_targeting_this_port = [ip for (ip, port) in self.active_attacks_by_ip_and_port.keys() if port == dst_port]
        
        if len(all_attackers_targeting_this_port) >= 2 or len(self.connection_attempts_by_ip_and_port[src_ip][dst_port]) >= self.suspicious_threshold:
            if dst_port not in self.currently_blocked_ports:
                self.block_port_using_iptables(dst_port, all_attackers_targeting_this_port)
    
    def get_reverse_dns_safely(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "unknown"
    
    def determine_attack_type_from_patterns(self, port, src_ip):
        attempt_count = len(self.connection_attempts_by_ip_and_port[src_ip][port])
        
        if port == 22:
            return "SSH_BRUTE_FORCE"
        elif port == 21:
            return "FTP_BRUTE_FORCE"
        elif port in [3306, 5432]:
            return "DATABASE_ATTACK"
        elif port in [80, 443, 8080]:
            return "WEB_APPLICATION_ATTACK"
        elif port in [6379, 27017]:
            return "NOSQL_DATABASE_ATTACK"
        elif port in [2049, 111]:
            return "NFS_ATTACK"
        elif port == 2375:
            return "DOCKER_API_ATTACK"
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
            # linux systems get hit more frequently, shorter timeout
            if (now - attack.timestamp).total_seconds() > 90:
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
            
            if not attacks_still_active_on_this_port and block_duration_so_far > 45:
                if block_duration_so_far > self.block_duration:
                    self.unblock_port_using_iptables(port)
                else:
                    unblock_cmd = self.get_command_to_manually_unblock_port(port)
                    logger.info(f"port {port} ({blocked_info.service_name}) can be safely reopened")
                    self.send_notification_about_security_event(
                        f"Port {port} ({blocked_info.service_name}) safe to reopen.\n"
                        f"Command: {unblock_cmd}"
                    )
    
    def get_command_to_manually_unblock_port(self, port):
        if port not in self.currently_blocked_ports:
            return "Port not currently blocked"
        
        blocked_info = self.currently_blocked_ports[port]
        rule_comment = blocked_info.iptables_rule_id
        
        return (f'iptables -D {self.iptables_chain_name} -p tcp --dport {port} -j DROP '
                f'-m comment --comment {rule_comment}')
    
    def send_notification_about_security_event(self, message):
        logger.warning(f"NOTIFICATION: {message}")
        
        # try to send to desktop notification if display available
        try:
            if os.environ.get('DISPLAY'):
                subprocess.run(['notify-send', 'Security Alert', message], 
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
            
            # make readable by security group if we have permissions
            try:
                if os.geteuid() == 0:
                    os.chown(log_file, 0, grp.getgrnam('adm').gr_gid)
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
                    os.chown(log_file, 0, grp.getgrnam('adm').gr_gid)
                    os.chmod(log_file, 0o640)
            except:
                pass
            
            logger.info(f"saved block history to {log_file}")
            
        except Exception as e:
            logger.error(f"failed to save block history: {e}")
    
    def start_monitoring_network_traffic(self):
        logger.info("starting linux network intrusion monitoring...")
        logger.info(f"monitoring ports: {list(self.monitored_ports_with_services.keys())}")
        logger.info(f"suspicious threshold: {self.suspicious_threshold} attempts")
        logger.info(f"fail2ban integration: {'enabled' if self.enable_fail2ban_integration else 'disabled'}")
        
        self.monitoring_active = True
        
        cleanup_thread = threading.Thread(target=self.run_background_cleanup_worker, daemon=True)
        cleanup_thread.start()
        
        # also start a thread to monitor system resources
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
        except Exception as e:
            logger.error(f"monitoring error: {e}")
        finally:
            self.stop_monitoring_and_cleanup()
    
    def monitor_system_resources(self):
        while self.monitoring_active:
            try:
                # check if system is under load (might indicate DDoS)
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                if cpu_percent > 90 or memory_percent > 95:
                    logger.warning(f"system under heavy load - CPU: {cpu_percent}%, Memory: {memory_percent}%")
                    # could implement emergency measures here
                
                time.sleep(30)
            except Exception as e:
                logger.debug(f"resource monitoring error: {e}")
    
    def run_background_cleanup_worker(self):
        while self.monitoring_active:
            try:
                self.cleanup_attacks_that_have_stopped()
                time.sleep(20)  # faster cleanup on linux
            except Exception as e:
                logger.error(f"cleanup worker error: {e}")
    
    def cleanup_iptables_on_exit(self):
        try:
            # flush our custom chain
            subprocess.run(['iptables', '-F', self.iptables_chain_name], 
                         capture_output=True, check=False)
            
            # remove jump rule
            subprocess.run(['iptables', '-D', 'INPUT', '-j', self.iptables_chain_name], 
                         capture_output=True, check=False)
            
            # delete chain
            subprocess.run(['iptables', '-X', self.iptables_chain_name], 
                         capture_output=True, check=False)
            
            logger.info("cleaned up iptables rules")
        except Exception as e:
            logger.error(f"failed to cleanup iptables: {e}")
    
    def stop_monitoring_and_cleanup(self):
        logger.info("stopping linux intrusion monitoring...")
        self.monitoring_active = False
        
        summary = {
            'stop_time': datetime.now().isoformat(),
            'total_attacks_detected': len(self.completed_attack_history),
            'currently_blocked_ports': {
                port: info.to_dict() for port, info in self.currently_blocked_ports.items()
            },
            'active_attacks': len(self.active_attacks_by_ip_and_port),
            'blocked_ips_count': len(self.blocked_ips_with_iptables)
        }
        
        summary_file = SYSTEM_LOG_DIR / f"monitoring_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"monitoring summary saved to {summary_file}")
        
        for port in list(self.currently_blocked_ports.keys()):
            logger.info(f"port {port} still blocked - unblock: {self.get_command_to_manually_unblock_port(port)}")
        
        # cleanup iptables rules
        self.cleanup_iptables_on_exit()

def handle_ctrl_c_gracefully(signum, frame):
    logger.info("received interrupt signal, shutting down...")
    sys.exit(0)

def check_linux_capabilities():
    # check if we have necessary capabilities
    missing_capabilities = []
    
    if os.geteuid() != 0:
        missing_capabilities.append("root privileges (needed for iptables and raw sockets)")
    
    # check for required tools
    required_tools = ['iptables', 'systemctl']
    for tool in required_tools:
        if not subprocess.run(['which', tool], capture_output=True).returncode == 0:
            missing_capabilities.append(f"{tool} command")
    
    if missing_capabilities:
        logger.error(f"missing requirements: {', '.join(missing_capabilities)}")
        return False
    return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Linux Network Intrusion Detection and Response')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold', type=int, default=8, help='Suspicious attempt threshold')
    parser.add_argument('--block-duration', type=int, default=300, help='Auto-unblock duration in seconds')
    parser.add_argument('--no-fail2ban', action='store_true', help='Disable fail2ban integration')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not check_linux_capabilities():
        sys.exit(1)
    
    signal.signal(signal.SIGINT, handle_ctrl_c_gracefully)
    signal.signal(signal.SIGTERM, handle_ctrl_c_gracefully)
    
    try:
        detector = LinuxIntrusionDetector(
            interface=args.interface,
            suspicious_threshold=args.threshold,
            block_duration=args.block_duration,
            enable_fail2ban_integration=not args.no_fail2ban
        )
        
        detector.start_monitoring_network_traffic()
        
    except Exception as e:
        logger.error(f"critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
