#!/usr/bin/env python3
"""
Accurate Cyber Defense Advanced Cyber Security Training Bot
Author: Ian Carter Kulani

"""

import os
import sys
import socket
import threading
import time
import json
import logging
import subprocess
import requests
import ipaddress
import datetime
from collections import deque
from typing import Dict, List, Optional
import readline  # For command history

class CyberSecurityMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitored_ips = set()
        self.command_history = deque(maxlen=100)
        self.current_color = "white"
        self.colors = {
            "white": "\033[97m",
            "blue": "\033[94m",
            "red": "\033[91m",
            "green": "\033[92m"
        }
        self.reset_color = "\033[0m"
        self.telegram_token = None
        self.telegram_chat_id = None
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cyber_security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{self.colors[self.current_color]}
╔══════════════════════════════════════════════════════════════╗
║                   Accurate Cyber Defense Training Bot       ║
║                     Community:                              ║
╚══════════════════════════════════════════════════════════════╝
{self.reset_color}
        """
        print(banner)

    def change_color(self, color_name: str):
        """Change terminal color theme"""
        if color_name in self.colors:
            self.current_color = color_name
            print(f"{self.colors[self.current_color]}Color theme changed to {color_name}{self.reset_color}")
        else:
            print("Invalid color. Available: white, blue, red, green")

    def help_command(self):
        """Display help information"""
        help_text = f"""
{self.colors[self.current_color]}
╔══════════════════════════════════════════════════════════════╗
║                         COMMAND HELP                         ║
╚══════════════════════════════════════════════════════════════╝

Basic Commands:
[1] help                    - Show this help message
[2] ping IP                 - Ping an IP address
[3] start monitoring IP     - Start monitoring specific IP
[4] stop                    - Stop all monitoring
[5] exit                    - Exit the program
[6] clear                   - Clear the screen
[7] add IP                  - Add IP to monitoring list
[8] remove IP               - Remove IP from monitoring list
[9] history                 - View command history
[10] scan IP                - Basic port scan
[11] deep scan IP           - Comprehensive port scan (1-65535)
[12] location IP            - Get IP geolocation
[13] analyze IP             - Analyze IP for threats
[14] config telegram token  - Set Telegram bot token
[15] config telegram chat_id - Set Telegram chat ID
[16] test telegram          - Test Telegram connection
[17] generate daily report  - Generate daily security report
[18] generate weekly report - Generate weekly security report
[19] export telegram        - Export data to Telegram
[20] monthly report         - Generate monthly report
[21] kill IP                - Send traffic to IP (USE WITH CAUTION)
[22] curl domain            - Execute curl command
[23] nmap IP                - Perform nmap scan
[24] brute ssh IP           - SSH brute force (ETHICAL USE ONLY)
[25] color [color_name]     - Change interface color

Telegram Commands Available via Bot Interface
{self.reset_color}
        """
        print(help_text)

    def ping_ip(self, ip: str):
        """Ping an IP address"""
        try:
            # Validate IP
            ipaddress.ip_address(ip)
            
            # Platform-specific ping command
            param = "-n" if sys.platform.lower() == "win32" else "-c"
            command = ["ping", param, "4", ip]
            
            result = subprocess.run(command, capture_output=True, text=True)
            print(f"Ping results for {ip}:\n{result.stdout}")
            
            self.logger.info(f"Ping executed for {ip}")
            
        except Exception as e:
            print(f"Error pinging {ip}: {e}")

    def port_scan(self, ip: str, start_port=1, end_port=1000):
        """Perform basic port scanning"""
        print(f"Scanning {ip} from port {start_port} to {end_port}...")
        
        open_ports = []
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                        print(f"Port {port}: Open")
            except:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
            
        print(f"Scan completed. Found {len(open_ports)} open ports.")
        return open_ports

    def deep_scan(self, ip: str):
        """Deep port scan from 1 to 65535"""
        return self.port_scan(ip, 1, 65535)

    def start_monitoring(self, ip: str):
        """Start monitoring specific IP for threats"""
        if ip in self.monitored_ips:
            print(f"Already monitoring {ip}")
            return
            
        self.monitored_ips.add(ip)
        print(f"Started monitoring {ip}")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_ip, args=(ip,))
        monitor_thread.daemon = True
        monitor_thread.start()

    def monitor_ip(self, ip: str):
        """Monitor IP for suspicious activities"""
        suspicious_events = 0
        
        while ip in self.monitored_ips and self.monitoring:
            try:
                # Simulate monitoring checks
                time.sleep(5)
                
                # Check for port scanning patterns
                # Check for flood attempts
                # Analyze traffic patterns
                
                # Example: Random alert for demonstration
                if suspicious_events < 3 and int(time.time()) % 30 == 0:
                    alert_msg = f"Suspicious activity detected from {ip}"
                    print(f"{self.colors['red']}ALERT: {alert_msg}{self.reset_color}")
                    self.logger.warning(alert_msg)
                    suspicious_events += 1
                    
            except Exception as e:
                self.logger.error(f"Monitoring error for {ip}: {e}")

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        self.monitoring = False
        self.monitored_ips.clear()
        print("All monitoring stopped")

    def get_ip_location(self, ip: str):
        """Get geolocation information for IP"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            
            if data['status'] == 'success':
                location_info = f"""
Location Information for {ip}:
Country: {data.get('country', 'N/A')}
Region: {data.get('regionName', 'N/A')}
City: {data.get('city', 'N/A')}
ISP: {data.get('isp', 'N/A')}
Latitude: {data.get('lat', 'N/A')}
Longitude: {data.get('lon', 'N/A')}
                """
                print(location_info)
            else:
                print("Could not retrieve location information")
                
        except Exception as e:
            print(f"Error getting location: {e}")

    def analyze_ip(self, ip: str):
        """Analyze IP for potential threats"""
        print(f"Analyzing {ip} for threats...")
        
        # Basic threat analysis
        threats_detected = []
        
        try:
            # Check if IP is private
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                threats_detected.append("Private IP address")
                
            # Check for common malicious patterns
            if ip.startswith('10.') or ip.startswith('192.168.'):
                threats_detected.append("Internal network IP")
                
            # Add more analysis logic here
            
            if threats_detected:
                print(f"Potential threats detected for {ip}:")
                for threat in threats_detected:
                    print(f"  - {threat}")
            else:
                print(f"No obvious threats detected for {ip}")
                
        except Exception as e:
            print(f"Error analyzing IP: {e}")

    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        self.telegram_token = token
        print("Telegram token configured")
        self.logger.info("Telegram token updated")

    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        self.telegram_chat_id = chat_id
        print("Telegram chat ID configured")
        self.logger.info("Telegram chat ID updated")

    def test_telegram_connection(self):
        """Test Telegram bot connection"""
        if not self.telegram_token or not self.telegram_chat_id:
            print("Telegram token or chat ID not configured")
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            response = requests.get(url)
            
            if response.status_code == 200:
                print("Telegram connection successful")
            else:
                print("Telegram connection failed")
                
        except Exception as e:
            print(f"Telegram test error: {e}")

    def generate_report(self, report_type: str):
        """Generate security reports"""
        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
Security Report - {report_type.upper()}
Generated: {report_date}
Monitored IPs: {len(self.monitored_ips)}
Status: {'Active' if self.monitoring else 'Inactive'}

Summary:
- Total monitored targets: {len(self.monitored_ips)}
- Monitoring status: {'ACTIVE' if self.monitoring else 'INACTIVE'}
- Recent activities: Logged in cyber_security.log
        """
        
        print(report)
        
        # Save report to file
        filename = f"{report_type}_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
            
        print(f"Report saved as {filename}")

    def execute_curl(self, domain: str):
        """Execute curl command"""
        try:
            result = subprocess.run(['curl', '-I', domain], capture_output=True, text=True)
            print(f"Curl results for {domain}:\n{result.stdout}")
        except Exception as e:
            print(f"Error executing curl: {e}")

    def execute_nmap(self, ip: str):
        """Execute nmap scan"""
        try:
            print(f"Running nmap scan on {ip}...")
            result = subprocess.run(['nmap', '-sV', ip], capture_output=True, text=True)
            print(f"Nmap results for {ip}:\n{result.stdout}")
        except Exception as e:
            print(f"Error executing nmap: {e}")

    def show_history(self):
        """Display command history"""
        print("Command History:")
        for i, cmd in enumerate(self.command_history, 1):
            print(f"{i}: {cmd}")

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def run_command(self, command: str):
        """Execute user commands"""
        self.command_history.append(command)
        parts = command.strip().split()
        
        if not parts:
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                self.help_command()
                
            elif cmd == "ping" and args:
                self.ping_ip(args[0])
                
            elif cmd == "start" and len(args) >= 2 and args[0] == "monitoring":
                self.start_monitoring(args[1])
                
            elif cmd == "stop":
                self.stop_monitoring()
                
            elif cmd == "exit":
                print("Exiting Accurate Cyber Defense Training Bot...")
                sys.exit(0)
                
            elif cmd == "clear":
                self.clear_screen()
                
            elif cmd == "add" and args:
                self.monitored_ips.add(args[0])
                print(f"Added {args[0]} to monitoring list")
                
            elif cmd == "remove" and args:
                if args[0] in self.monitored_ips:
                    self.monitored_ips.remove(args[0])
                    print(f"Removed {args[0]} from monitoring list")
                else:
                    print(f"{args[0]} not in monitoring list")
                    
            elif cmd == "history":
                self.show_history()
                
            elif cmd == "scan" and args:
                self.port_scan(args[0])
                
            elif cmd == "deep" and len(args) >= 2 and args[0] == "scan":
                self.deep_scan(args[1])
                
            elif cmd == "location" and args:
                self.get_ip_location(args[0])
                
            elif cmd == "analyze" and args:
                self.analyze_ip(args[0])
                
            elif cmd == "config" and len(args) >= 3 and args[0] == "telegram":
                if args[1] == "token":
                    self.config_telegram_token(args[2])
                elif args[1] == "chat_id":
                    self.config_telegram_chat_id(args[2])
                    
            elif cmd == "test" and args and args[0] == "telegram":
                self.test_telegram_connection()
                
            elif cmd == "generate" and len(args) >= 2:
                if args[0] == "daily" and args[1] == "report":
                    self.generate_report("daily")
                elif args[0] == "weekly" and args[1] == "report":
                    self.generate_report("weekly")
                elif args[0] == "monthly" and args[1] == "report":
                    self.generate_report("monthly")
                    
            elif cmd == "export" and args and args[0] == "telegram":
                print("Exporting data to Telegram...")
                # Implementation for Telegram export
                
            elif cmd == "curl" and args:
                self.execute_curl(args[0])
                
            elif cmd == "nmap" and args:
                self.execute_nmap(args[0])
                
            elif cmd == "color" and args:
                self.change_color(args[0])
                
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
                
        except Exception as e:
            print(f"Error executing command: {e}")
            self.logger.error(f"Command execution error: {e}")

    def main_loop(self):
        """Main command loop"""
        self.print_banner()
        print("Type 'help' for available commands")
        
        self.monitoring = True
        
        while True:
            try:
                prompt = f"{self.colors[self.current_color]}accurate-Cyber-defense#>{self.reset_color} "
                command = input(prompt).strip()
                
                if command:
                    self.run_command(command)
                    
            except KeyboardInterrupt:
                print("\n\nUse 'exit' to quit the program")
            except EOFError:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")

def main():
    """Main entry point"""
    # Check for root privileges on Unix systems
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: Some features may require root privileges")
    
    monitor = CyberSecurityMonitor()
    monitor.main_loop()

if __name__ == "__main__":
    main()