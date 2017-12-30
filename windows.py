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
        
        if len(all_attackers_targeting_this_port) >= 3 or len(self.connection_attempts_by_ip_and_port[src_ip][dst_port]) >= self.suspicious_threshold:
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

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Intrusion Detection and Response')
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold', type=int, default=10, help='Suspicious attempt threshold')
    parser.add_argument('--block-duration', type=int, default=300, help='Auto-unblock duration in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
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
            block_duration=args.block_duration
        )
        
        detector.start_monitoring_network_traffic()
        
    except Exception as e:
        logger.error(f"critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 