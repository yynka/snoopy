#!/usr/bin/env python3

"""
watches network traffic for attack attempts, blocks ports when attacks detected,
logs everything, and handles port reopening when attacks stop
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
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

# make sure we can write to logs
SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# setup logging so we dont go crazy
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(LOGS_DIR / 'intrusion_monitor.log'))
    ]
)
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
    firewall_rule_name: str
    
    def to_dict(self):
        data = asdict(self)
        data['blocked_at'] = self.blocked_at.isoformat()
        data['attacker_ips'] = list(self.attacker_ips)
        return data

class IntrusionDetector:
    def __init__(self, interface=None, suspicious_threshold=10, block_duration=300, active_mode=False):
        self.interface = interface or self.find_default_network_interface()
        self.suspicious_threshold = suspicious_threshold
        self.block_duration = block_duration
        self.active_mode = active_mode
        self.monitoring_active = False
        
        # track connection attempts per IP per port
        self.connection_attempts_by_ip_and_port = defaultdict(lambda: defaultdict(deque))
        self.currently_blocked_ports = {}
        self.active_attacks_by_ip_and_port = {}
        self.completed_attack_history = []
        
        # ports we actually care about monitoring
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
            3389: "RDP",
            5985: "WinRM",
            1433: "MSSQL",
            3306: "MySQL"
        }
        
        logger.info(f"initialized intrusion detector on interface {self.interface}")
        logger.info(f"mode: {'ACTIVE' if self.active_mode else 'PASSIVE'} response")
        
        # active mode initialization
        if self.active_mode:
            self.initialize_active_mode()
    
    def initialize_active_mode(self):
        """initialize active response capabilities for Windows"""
        logger.info("ACTIVE MODE: initializing automated defensive responses")
        
        # adjust thresholds for more aggressive protection
        original_threshold = self.suspicious_threshold
        self.suspicious_threshold = max(2, self.suspicious_threshold // 2)
        logger.info(f"ACTIVE MODE: reduced threshold from {original_threshold} to {self.suspicious_threshold}")
        
        # start background analysis and response threads
        self.start_active_response_threads()
        
        # perform initial security audit
        self.perform_immediate_security_audit()
    
    def start_active_response_threads(self):
        """start background threads for active responses"""
        # periodic top attacker blocking
        attacker_thread = threading.Thread(target=self.active_attacker_blocking_worker, daemon=True)
        attacker_thread.start()
        
        # service security monitoring
        service_thread = threading.Thread(target=self.active_service_security_worker, daemon=True)
        service_thread.start()
        
        # adaptive threshold adjustment
        adaptive_thread = threading.Thread(target=self.active_adaptive_threshold_worker, daemon=True)
        adaptive_thread.start()
    
    def perform_immediate_security_audit(self):
        """immediate security assessment and response"""
        logger.info("ACTIVE MODE: performing immediate security audit")
        
        # check for running vulnerable services
        self.audit_and_secure_services()
        
        # analyze recent attack patterns
        self.analyze_and_block_persistent_attackers()
        
        # enhance firewall rules
        self.enhance_windows_firewall_protection()
    
    def active_attacker_blocking_worker(self):
        """background worker to block persistent attackers"""
        while self.monitoring_active:
            try:
                if len(self.completed_attack_history) >= 5:
                    self.block_top_persistent_attackers()
                time.sleep(120)  # check every 2 minutes
            except Exception as e:
                logger.error(f"active attacker blocking error: {e}")
    
    def active_service_security_worker(self):
        """background worker to secure services under attack"""
        while self.monitoring_active:
            try:
                self.secure_services_under_attack()
                time.sleep(300)  # check every 5 minutes
            except Exception as e:
                logger.error(f"active service security error: {e}")
    
    def active_adaptive_threshold_worker(self):
        """background worker to adapt thresholds based on attack patterns"""
        while self.monitoring_active:
            try:
                self.adapt_thresholds_to_attack_patterns()
                time.sleep(600)  # check every 10 minutes
            except Exception as e:
                logger.error(f"adaptive threshold error: {e}")
    
    def analyze_and_block_persistent_attackers(self):
        """analyze attack history and block persistent attackers"""
        if not self.active_mode:
            return
            
        try:
            from collections import Counter
            recent_attacks = []
            
            # get attacks from last 3 days
            attack_files = list(LOGS_DIR.glob("attacks_*.json"))[-3:]
            for attack_file in attack_files:
                try:
                    with open(attack_file, 'r') as f:
                        daily_attacks = json.load(f)
                        recent_attacks.extend(daily_attacks)
                except:
                    continue
            
            if recent_attacks:
                ip_counts = Counter(attack['attacker_ip'] for attack in recent_attacks)
                top_attackers = ip_counts.most_common(5)
                
                for ip, count in top_attackers:
                    if count >= 3:
                        logger.warning(f"ACTIVE MODE: blocking persistent attacker {ip} ({count} attacks)")
                        self.block_ip_permanently(ip)
                        
        except Exception as e:
            logger.error(f"persistent attacker analysis failed: {e}")
    
    def block_ip_permanently(self, ip):
        """permanently block an IP address using Windows Firewall"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_name = f"SnoopyBlock_{ip.replace('.', '_')}_{timestamp}"
            
            # create inbound and outbound blocking rules
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip}'
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip}'
            
            subprocess.run(cmd_in, shell=True, check=True)
            subprocess.run(cmd_out, shell=True, check=True)
            
            logger.info(f"ACTIVE MODE: permanently blocked {ip}")
            self.send_notification_about_security_event(f"Permanently blocked persistent attacker {ip}")
            
        except Exception as e:
            logger.error(f"failed to permanently block {ip}: {e}")
    
    def audit_and_secure_services(self):
        """audit running services and secure them"""
        if not self.active_mode:
            return
            
        try:
            vulnerable_services = []
            
            for port, service_name in self.monitored_ports_with_services.items():
                if self.is_port_listening(port):
                    if self.is_service_under_attack(port):
                        vulnerable_services.append((port, service_name))
            
            for port, service_name in vulnerable_services:
                logger.warning(f"ACTIVE MODE: securing {service_name} (port {port}) - under attack")
                self.secure_specific_service(port, service_name)
                
        except Exception as e:
            logger.error(f"service audit failed: {e}")
    
    def is_port_listening(self, port):
        """check if a port is listening on Windows"""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, check=False)
            return f":{port} " in result.stdout
        except:
            return False
    
    def is_service_under_attack(self, port):
        """check if a service is currently under attack"""
        active_attacks_on_port = [
            attack for (ip, p), attack in self.active_attacks_by_ip_and_port.items() 
            if p == port
        ]
        return len(active_attacks_on_port) > 0
    
    def secure_specific_service(self, port, service_name):
        """apply specific security measures to a service"""
        try:
            # create enhanced blocking rules for the service
            self.add_enhanced_port_protection(port, service_name)
            
            # disable service if critical and under attack
            if service_name in ["SSH", "RDP", "WinRM"] and self.is_service_under_attack(port):
                logger.info(f"ACTIVE MODE: considering security measures for {service_name}")
                self.add_enhanced_port_protection(port, service_name)
            
        except Exception as e:
            logger.error(f"failed to secure {service_name}: {e}")
    
    def add_enhanced_port_protection(self, port, service_name):
        """add enhanced firewall protection for a specific port"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_name = f"SnoopyEnhanced_{service_name}_{timestamp}"
            
            # create restrictive rule for the port
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol=TCP localport={port} profile=any'
            subprocess.run(cmd, shell=True, check=False)
            
            logger.info(f"ACTIVE MODE: enhanced protection for {service_name} port {port}")
            
        except Exception as e:
            logger.debug(f"enhanced protection setup failed for port {port}: {e}")
    
    def block_top_persistent_attackers(self):
        """block the most persistent current attackers"""
        if not self.active_mode:
            return
            
        try:
            attacker_counts = {}
            for (ip, port), attack in self.active_attacks_by_ip_and_port.items():
                if ip not in attacker_counts:
                    attacker_counts[ip] = 0
                attacker_counts[ip] += attack.packet_count
            
            for ip, count in attacker_counts.items():
                if count >= 15:  # Windows threshold
                    logger.warning(f"ACTIVE MODE: blocking aggressive attacker {ip} ({count} packets)")
                    self.block_ip_permanently(ip)
                    
        except Exception as e:
            logger.error(f"top attacker blocking failed: {e}")
    
    def secure_services_under_attack(self):
        """secure services that are currently under attack"""
        if not self.active_mode:
            return
            
        try:
            attacked_ports = set()
            for (ip, port), attack in self.active_attacks_by_ip_and_port.items():
                attacked_ports.add(port)
            
            for port in attacked_ports:
                if port not in self.currently_blocked_ports:
                    service_name = self.monitored_ports_with_services.get(port, f"port-{port}")
                    logger.info(f"ACTIVE MODE: preemptively securing {service_name} under attack")
                    self.secure_specific_service(port, service_name)
                    
        except Exception as e:
            logger.error(f"service security update failed: {e}")
    
    def adapt_thresholds_to_attack_patterns(self):
        """adapt detection thresholds based on current attack patterns"""
        if not self.active_mode:
            return
            
        try:
            if len(self.active_attacks_by_ip_and_port) > 10:  # high attack volume
                if self.suspicious_threshold > 2:
                    self.suspicious_threshold -= 1
                    logger.info(f"ACTIVE MODE: reduced threshold to {self.suspicious_threshold} due to high attack volume")
            elif len(self.active_attacks_by_ip_and_port) == 0:  # quiet period
                original_threshold = 10  # default for windows
                if self.suspicious_threshold < original_threshold:
                    self.suspicious_threshold = min(self.suspicious_threshold + 1, original_threshold)
                    logger.info(f"ACTIVE MODE: increased threshold to {self.suspicious_threshold} during quiet period")
                    
        except Exception as e:
            logger.error(f"threshold adaptation failed: {e}")
    
    def enhance_windows_firewall_protection(self):
        """enhance overall Windows Firewall protection"""
        try:
            # create enhanced blocking rules for common attack patterns
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # block common scanning patterns
            rules = [
                f'netsh advfirewall firewall add rule name="SnoopyEnhanced_PortScan_{timestamp}" dir=in action=block protocol=TCP localport=1-1024',
                f'netsh advfirewall firewall add rule name="SnoopyEnhanced_HighPorts_{timestamp}" dir=in action=block protocol=TCP localport=8000-9999'
            ]
            
            for rule in rules:
                subprocess.run(rule, shell=True, check=False)
            
            logger.info("ACTIVE MODE: enhanced Windows Firewall protection enabled")
            
        except Exception as e:
            logger.debug(f"enhanced firewall setup failed: {e}")
    
    def find_default_network_interface(self):
        try:
            network_interfaces = psutil.net_if_addrs()
            for interface_name, addresses in network_interfaces.items():
                for addr in addresses:
                    if addr.family == socket.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                        logger.info(f"using network interface: {interface_name}")
                        return interface_name
        except Exception as e:
            logger.error(f"couldnt determine default interface: {e}")
            return None
    
    def connection_attempt_looks_like_attack(self, src_ip, dst_port, packet_flags=""):
        now = datetime.now()
        
        # clean old attempts (older than 60 seconds)
        cutoff_time = now - timedelta(seconds=60)
        recent_attempts_from_this_ip = self.connection_attempts_by_ip_and_port[src_ip][dst_port]
        while recent_attempts_from_this_ip and recent_attempts_from_this_ip[0] < cutoff_time:
            recent_attempts_from_this_ip.popleft()
        
        # add this attempt
        recent_attempts_from_this_ip.append(now)
        
        attempt_count = len(recent_attempts_from_this_ip)
        
        # different thresholds for different attack patterns
        if dst_port == 22:
            return attempt_count >= 5
        elif dst_port in [21, 23]:
            return attempt_count >= 8
        elif dst_port in [3389, 5985]:
            return attempt_count >= 3
        else:
            return attempt_count >= self.suspicious_threshold
    
    def block_port_using_system_firewall(self, port, attacker_ips):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_name = f"IntrusionBlock_Port{port}_{timestamp}"
            
            if sys.platform.startswith('win'):
                cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block protocol=TCP localport={port}'
                cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block protocol=TCP localport={port}'
                
                subprocess.run(cmd_in, shell=True, check=True)
                subprocess.run(cmd_out, shell=True, check=True)
                
            else:
                cmd = f'iptables -A INPUT -p tcp --dport {port} -j DROP'
                subprocess.run(['sudo'] + cmd.split(), check=True)
            
            blocked_port_info = BlockedPort(
                port=port,
                blocked_at=datetime.now(),
                attacker_ips=set(attacker_ips),
                attack_count=len(attacker_ips),
                firewall_rule_name=rule_name
            )
            
            self.currently_blocked_ports[port] = blocked_port_info
            
            logger.warning(f"BLOCKED PORT {port} due to attacks from {len(attacker_ips)} IPs")
            self.send_notification_about_security_event(f"PORT {port} BLOCKED - Attack detected from {', '.join(attacker_ips)}")
            
            return rule_name
            
        except subprocess.CalledProcessError as e:
            logger.error(f"failed to block port {port}: {e}")
            return None
    
    def unblock_port_using_system_firewall(self, port):
        if port not in self.currently_blocked_ports:
            return
        
        blocked_info = self.currently_blocked_ports[port]
        rule_name = blocked_info.firewall_rule_name
        
        try:
            if sys.platform.startswith('win'):
                cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
                cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
                
                subprocess.run(cmd_in, shell=True, check=True)
                subprocess.run(cmd_out, shell=True, check=True)
            else:
                cmd = f'iptables -D INPUT -p tcp --dport {port} -j DROP'
                subprocess.run(['sudo'] + cmd.split(), check=True)
            
            logger.info(f"UNBLOCKED PORT {port} - attack appears to have stopped")
            self.send_notification_about_security_event(f"PORT {port} UNBLOCKED - Safe to resume service")
            
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
        else:
            attack_type = self.determine_attack_type_from_patterns(dst_port, src_ip)
            
            attack = AttackAttempt(
                attacker_ip=src_ip,
                target_port=dst_port,
                attack_type=attack_type,
                timestamp=datetime.now(),
                attack_details={
                    'service': self.monitored_ports_with_services.get(dst_port, 'Unknown'),
                    'first_seen': datetime.now().isoformat()
                }
            )
            
            self.active_attacks_by_ip_and_port[attack_key] = attack
            logger.warning(f"ATTACK DETECTED: {attack_type} from {src_ip} targeting port {dst_port}")
        
        # check if we should block the port
        all_attackers_targeting_this_port = [ip for (ip, port) in self.active_attacks_by_ip_and_port.keys() if port == dst_port]
        
        if len(all_attackers_targeting_this_port) >= 2 or len(self.connection_attempts_by_ip_and_port[src_ip][dst_port]) >= self.suspicious_threshold:
            if dst_port not in self.currently_blocked_ports:
                self.block_port_using_system_firewall(dst_port, all_attackers_targeting_this_port)
    
    def determine_attack_type_from_patterns(self, port, src_ip):
        attempt_count = len(self.connection_attempts_by_ip_and_port[src_ip][port])
        
        if port == 22 and attempt_count >= 5:
            return "SSH_BRUTE_FORCE"
        elif port == 21 and attempt_count >= 8:
            return "FTP_BRUTE_FORCE"
        elif port == 3389:
            return "RDP_BRUTE_FORCE"
        elif port in [80, 443]:
            return "WEB_ATTACK"
        elif port == 25:
            return "SMTP_SPAM_ATTEMPT"
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
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        if ip == addr.address or ip.startswith('127.') or ip.startswith('169.254.'):
                            return True
            return False
        except:
            return False
    
    def cleanup_attacks_that_have_stopped(self):
        now = datetime.now()
        expired_attacks = []
        
        for attack_key, attack in self.active_attacks_by_ip_and_port.items():
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
                    self.unblock_port_using_system_firewall(port)
                else:
                    service_name = self.monitored_ports_with_services.get(port, f"port {port}")
                    unblock_cmd = self.get_command_to_manually_unblock_port(port)
                    logger.info(f"port {port} ({service_name}) can be safely reopened")
                    self.send_notification_about_security_event(
                        f"Port {port} ({service_name}) safe to reopen.\n"
                        f"Command: {unblock_cmd}"
                    )
    
    def get_command_to_manually_unblock_port(self, port):
        if port not in self.currently_blocked_ports:
            return "Port not currently blocked"
        
        rule_name = self.currently_blocked_ports[port].firewall_rule_name
        
        if sys.platform.startswith('win'):
            return f'netsh advfirewall firewall delete rule name="{rule_name}_IN" & netsh advfirewall firewall delete rule name="{rule_name}_OUT"'
        else:
            return f'sudo iptables -D INPUT -p tcp --dport {port} -j DROP'
    
    def send_notification_about_security_event(self, message):
        logger.warning(f"NOTIFICATION: {message}")
        # could add email/slack/desktop notifications here later
    
    def save_attack_details_to_log_file(self, attack):
        try:
            log_date = attack.timestamp.strftime("%Y-%m-%d")
            log_file = LOGS_DIR / f"attacks_{log_date}.json"
            
            if log_file.exists():
                with open(log_file, 'r') as f:
                    attacks = json.load(f)
            else:
                attacks = []
            
            attacks.append(attack.to_dict())
            
            with open(log_file, 'w') as f:
                json.dump(attacks, f, indent=2)
            
            logger.info(f"saved attack log to {log_file}")
            
        except Exception as e:
            logger.error(f"failed to save attack log: {e}")
    
    def save_port_blocking_history(self, block_info):
        try:
            log_date = datetime.now().strftime("%Y-%m-%d")
            log_file = LOGS_DIR / f"blocked_ports_{log_date}.json"
            
            if log_file.exists():
                with open(log_file, 'r') as f:
                    blocks = json.load(f)
            else:
                blocks = []
            
            blocks.append(block_info)
            
            with open(log_file, 'w') as f:
                json.dump(blocks, f, indent=2)
            
            logger.info(f"saved block history to {log_file}")
            
        except Exception as e:
            logger.error(f"failed to save block history: {e}")
    
    def start_monitoring_network_traffic(self):
        logger.info("starting network intrusion monitoring...")
        logger.info(f"monitoring ports: {list(self.monitored_ports_with_services.keys())}")
        logger.info(f"suspicious threshold: {self.suspicious_threshold} attempts")
        
        self.monitoring_active = True
        
        cleanup_thread = threading.Thread(target=self.run_background_cleanup_worker, daemon=True)
        cleanup_thread.start()
        
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
    
    def run_background_cleanup_worker(self):
        while self.monitoring_active:
            try:
                self.cleanup_attacks_that_have_stopped()
                time.sleep(30)
            except Exception as e:
                logger.error(f"cleanup worker error: {e}")
    
    def stop_monitoring_and_cleanup(self):
        logger.info("stopping intrusion monitoring...")
        self.monitoring_active = False
        
        summary = {
            'stop_time': datetime.now().isoformat(),
            'total_attacks_detected': len(self.completed_attack_history),
            'currently_blocked_ports': {
                port: info.to_dict() for port, info in self.currently_blocked_ports.items()
            },
            'active_attacks': len(self.active_attacks_by_ip_and_port)
        }
        
        summary_file = LOGS_DIR / f"monitoring_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"monitoring summary saved to {summary_file}")
        
        for port in list(self.currently_blocked_ports.keys()):
            logger.info(f"port {port} is still blocked - unblock command: {self.get_command_to_manually_unblock_port(port)}")

def handle_ctrl_c_gracefully(signum, frame):
    logger.info("received interrupt signal, shutting down...")
    sys.exit(0)

class SnoopyAnalyzer:
    """integrated attack analysis for windows intrusion detector"""
    
    def __init__(self, logs_directory=None):
        if logs_directory is None:
            logs_directory = LOGS_DIR
        self.logs_dir = Path(logs_directory)
        self.attacks = []
        self.blocked_ports = []
        
    def load_attack_data(self):
        """load all available attack logs"""
        print(f"[*] loading attack data from {self.logs_dir}")
        
        # load attack logs
        attack_files = list(self.logs_dir.glob("attacks_*.json"))
        for attack_file in attack_files:
            try:
                with open(attack_file, 'r') as f:
                    daily_attacks = json.load(f)
                    self.attacks.extend(daily_attacks)
                    print(f"  [+] loaded {len(daily_attacks)} attacks from {attack_file.name}")
            except Exception as e:
                print(f"  [-] failed to load {attack_file}: {e}")
        
        # load blocked port history
        block_files = list(self.logs_dir.glob("blocked_ports_*.json"))
        for block_file in block_files:
            try:
                with open(block_file, 'r') as f:
                    daily_blocks = json.load(f)
                    self.blocked_ports.extend(daily_blocks)
                    print(f"  [+] loaded {len(daily_blocks)} blocks from {block_file.name}")
            except Exception as e:
                print(f"  [-] failed to load {block_file}: {e}")
        
        print(f"[*] total loaded: {len(self.attacks)} attacks, {len(self.blocked_ports)} blocks\n")
    
    def analyze_attack_patterns(self):
        """analyze attack timing and patterns"""
        print("** ATTACK TIMING ANALYSIS **")
        
        if not self.attacks:
            print("  no attack data available\n")
            return
        
        # analyze by hour
        from collections import Counter
        attack_times = []
        for attack in self.attacks:
            try:
                timestamp = datetime.fromisoformat(attack['timestamp'])
                attack_times.append(timestamp)
            except:
                continue
        
        if attack_times:
            hour_counts = Counter(t.hour for t in attack_times)
            print("  attacks by hour of day:")
            for hour in sorted(hour_counts.keys()):
                bar = "#" * min(hour_counts[hour], 20)
                print(f"    {hour:02d}:00  {bar} ({hour_counts[hour]} attacks)")
        
        print()
    
    def analyze_top_attackers(self):
        """analyze top attacking IPs"""
        print("** TOP ATTACKERS **")
        
        if not self.attacks:
            print("  no attack data available\n")
            return
        
        from collections import Counter
        ip_counts = Counter(attack['attacker_ip'] for attack in self.attacks)
        
        print(f"  top attacking ips ({len(ip_counts)} unique):")
        for ip, count in ip_counts.most_common(10):
            print(f"    {ip:15} -> {count:3} attacks")
        
        print()
    
    def analyze_targeted_services(self):
        """analyze most targeted services"""
        print("** TARGETED SERVICES **")
        
        if not self.attacks:
            print("  no attack data available\n")
            return
        
        from collections import Counter
        port_counts = Counter(attack['target_port'] for attack in self.attacks)
        service_names = {
            22: "SSH", 21: "FTP", 80: "HTTP", 443: "HTTPS",
            3389: "RDP", 5985: "WinRM", 1433: "MSSQL", 3306: "MySQL"
        }
        
        print("  most targeted services:")
        for port, count in port_counts.most_common(8):
            service = service_names.get(port, f"Port-{port}")
            bar = "#" * min(count, 20)
            print(f"    {service:12} (:{port}) -> {bar} {count} attacks")
        
        print()
    
    def show_windows_firewall_status(self):
        """show windows firewall status"""
        print("** WINDOWS FIREWALL STATUS **")
        
        try:
            # check firewall status
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'State' in line and ('ON' in line or 'OFF' in line):
                        print(f"  {line.strip()}")
            
            # check our rules
            result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], 
                                  capture_output=True, text=True, check=False)
            if result.returncode == 0:
                rule_count = result.stdout.count('IntrusionBlock_')
                if rule_count > 0:
                    print(f"  Active Snoopy blocking rules: {rule_count}")
                else:
                    print("  [+] No active Snoopy blocking rules")
        except Exception as e:
            print(f"  [-] firewall status check failed: {e}")
        
        print()

class SnoopyDashboard:
    """integrated real-time dashboard for windows"""
    
    def __init__(self, logs_directory=None, refresh_interval=5):
        if logs_directory is None:
            logs_directory = LOGS_DIR
        self.logs_dir = Path(logs_directory)
        self.refresh_interval = refresh_interval
        self.start_time = datetime.now()
    
    def clear_screen(self):
        """clear terminal screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def load_recent_attacks(self, hours_back=24):
        """load recent attacks"""
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        recent_attacks = []
        
        attack_files = list(self.logs_dir.glob("attacks_*.json"))
        for attack_file in attack_files:
            try:
                with open(attack_file, 'r') as f:
                    daily_attacks = json.load(f)
                    for attack in daily_attacks:
                        try:
                            attack_time = datetime.fromisoformat(attack['timestamp'])
                            if attack_time >= cutoff_time:
                                recent_attacks.append(attack)
                        except:
                            continue
            except:
                continue
        
        return recent_attacks
    
    def display_header(self):
        """display dashboard header"""
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]
        
        print("=" * 80)
        print("SNOOPY WINDOWS SECURITY DASHBOARD")
        print("=" * 80)
        print(f"Dashboard Uptime: {uptime_str}")
        print(f"Log Directory: {self.logs_dir}")
        print(f"Refresh Rate: {self.refresh_interval} seconds")
        print(f"Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
    
    def display_recent_activity(self, attacks):
        """display recent attack activity"""
        recent_cutoff = datetime.now() - timedelta(hours=1)
        recent_attacks = []
        
        for attack in attacks:
            try:
                attack_time = datetime.fromisoformat(attack['timestamp'])
                if attack_time >= recent_cutoff:
                    recent_attacks.append(attack)
            except:
                continue
        
        print(f"** RECENT ACTIVITY (Last 1 hour) **")
        print(f"Total Attacks: {len(recent_attacks)}")
        
        if recent_attacks:
            recent_sorted = sorted(recent_attacks, key=lambda x: x['timestamp'], reverse=True)[:5]
            print("Latest Attacks:")
            for attack in recent_sorted:
                timestamp = attack['timestamp'][:19]
                ip = attack['attacker_ip']
                port = attack['target_port']
                attack_type = attack['attack_type']
                print(f"  [!] {timestamp} | {ip:15} -> Port {port:4} ({attack_type})")
        else:
            print("  [+] No recent attacks detected")
        
        print()
    
    def display_system_status(self):
        """display windows system status"""
        print("** SYSTEM STATUS **")
        
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            print(f"  CPU Usage: {cpu_percent:.1f}%")
            print(f"  Memory Usage: {memory.percent:.1f}% ({memory.used//1024//1024}MB used)")
            
            # check if running as administrator
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("  [+] Running with Administrator privileges")
            else:
                print("  [!] Not running as Administrator")
                
        except Exception as e:
            print(f"  [-] system status check failed: {e}")
        
        print()
    
    def run_dashboard(self):
        """run the live dashboard"""
        print("Starting Windows Snoopy Dashboard...")
        time.sleep(2)
        
        try:
            while True:
                self.clear_screen()
                attacks = self.load_recent_attacks(24)
                
                self.display_header()
                self.display_recent_activity(attacks)
                self.display_system_status()
                
                from collections import Counter
                if attacks:
                    ip_counts = Counter(attack['attacker_ip'] for attack in attacks)
                    print("** TOP ATTACKERS (24h) **")
                    for ip, count in ip_counts.most_common(5):
                        print(f"  {ip:15} -> {count:3} attacks")
                    print()
                
                print("=" * 80)
                print(f"Total Attacks (24h): {len(attacks)}")
                print(f"Next update in {self.refresh_interval}s... (Ctrl+C to exit)")
                print("=" * 80)
                
                time.sleep(self.refresh_interval)
                
        except KeyboardInterrupt:
            self.clear_screen()
            print("\nWindows Snoopy Dashboard stopped")

def geolocate_attackers():
    """analyze geographic distribution of attacks"""
    print("** GEOGRAPHIC ATTACK ANALYSIS **")
    
    # load attack data
    attacks = []
    attack_files = list(LOGS_DIR.glob("attacks_*.json"))
    for attack_file in attack_files:
        try:
            with open(attack_file, 'r') as f:
                daily_attacks = json.load(f)
                attacks.extend(daily_attacks)
        except:
            continue
    
    if not attacks:
        print("[-] no attack data found")
        return
    
    # get unique IPs
    unique_ips = list(set(attack['attacker_ip'] for attack in attacks))
    print(f"[*] found {len(unique_ips)} unique attacking ips")
    
    # basic geolocation (simplified for integration)
    print("\n** BASIC IP ANALYSIS **")
    for ip in unique_ips[:10]:
        ip_attacks = [a for a in attacks if a['attacker_ip'] == ip]
        print(f"  {ip:15} -> {len(ip_attacks):3} attacks")
    
    print(f"\n[*] analysis complete - {len(attacks)} total attacks analyzed")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Windows Network Intrusion Detection and Response')
    
    # operation modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--monitor', action='store_true', default=True, help='Start network monitoring (default)')
    group.add_argument('--analyze', action='store_true', help='Analyze captured attack data')
    group.add_argument('--dashboard', action='store_true', help='Start real-time monitoring dashboard')
    group.add_argument('--geolocate', action='store_true', help='Analyze geographic distribution of attacks')
    
    # response modes
    response_group = parser.add_mutually_exclusive_group()
    response_group.add_argument('--passive', action='store_true', default=True, help='Passive monitoring - log attacks only (default)')
    response_group.add_argument('--active', action='store_true', help='Active response - automatically block attackers and secure services')
    
    # monitoring options
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold', type=int, default=10, help='Suspicious attempt threshold')
    parser.add_argument('--block-duration', type=int, default=300, help='Auto-unblock duration in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    # dashboard options
    parser.add_argument('--refresh', type=int, default=5, help='Dashboard refresh interval in seconds')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # handle analysis modes
    if args.analyze:
        print("** SNOOPY WINDOWS ATTACK ANALYZER **\n")
        analyzer = SnoopyAnalyzer()
        analyzer.load_attack_data()
        
        if not analyzer.attacks:
            print("[-] no attack data found. run with --monitor first to capture attacks")
            return
        
        analyzer.analyze_attack_patterns()
        analyzer.analyze_top_attackers()
        analyzer.analyze_targeted_services()
        analyzer.show_windows_firewall_status()
        print("** ANALYSIS COMPLETE **")
        return
    
    elif args.dashboard:
        dashboard = SnoopyDashboard(refresh_interval=args.refresh)
        dashboard.run_dashboard()
        return
    
    elif args.geolocate:
        geolocate_attackers()
        return
    
    # default monitoring mode - check admin privileges
    if sys.platform.startswith('win'):
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("this script needs to run as administrator to modify firewall rules")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            logger.error("this script needs to run as root to modify iptables")
            sys.exit(1)
    
    signal.signal(signal.SIGINT, handle_ctrl_c_gracefully)
    signal.signal(signal.SIGTERM, handle_ctrl_c_gracefully)
    
    try:
        detector = IntrusionDetector(
            interface=args.interface,
            suspicious_threshold=args.threshold,
            block_duration=args.block_duration,
            active_mode=args.active
        )
        
        detector.start_monitoring_network_traffic()
        
    except Exception as e:
        logger.error(f"critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 