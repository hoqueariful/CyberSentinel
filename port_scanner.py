#!/usr/bin/env python3
"""
CyberSentinel - Network Port Scanner
Author: Md Ariful Hoque
Email: george.ariful@gmail.com
GitHub: https://github.com/yourusername/CyberSentinel

Description: Multi-threaded port scanner for security assessments and network reconnaissance.
             Identifies open ports, services, and potential vulnerabilities.
Usage: python port_scanner.py <target> [--ports 1-1000] [--threads 100]

WARNING: Only scan networks you have permission to test. Unauthorized scanning is illegal.
"""

import socket
import argparse
import threading
import sys
import getpass
import platform
from datetime import datetime
from queue import Queue
import ipaddress

class PortScanner:
    def __init__(self, target, ports, threads=100, timeout=1):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()
        
        # System information
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.os_info = platform.system() + " " + platform.release()
        
        # Common service signatures
        self.services = {
            20: 'FTP-Data',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
            6379: 'Redis',
        }
        
        # Vulnerable service warnings
        self.vulnerable_services = {
            21: 'FTP - Often unencrypted, consider SFTP/FTPS',
            23: 'Telnet - Unencrypted protocol, use SSH instead',
            445: 'SMB - Check for EternalBlue vulnerability (MS17-010)',
            3389: 'RDP - Ensure strong passwords and NLA enabled',
            5900: 'VNC - Often uses weak authentication',
        }
    
    def display_system_info(self):
        """Display system information"""
        print("=" * 80)
        print("CYBERSENTINEL - NETWORK PORT SCANNER")
        print("=" * 80)
        print(f"Computer Name:    {self.hostname}")
        print(f"User Account:     {self.username}")
        print(f"Operating System: {self.os_info}")
        print(f"Python Version:   {platform.python_version()}")
        print(f"Scan Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
        
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[*] Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Unable to resolve hostname: {self.target}")
            sys.exit(1)
            
    def validate_target(self, ip):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def scan_port(self, port):
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = self.grab_banner(sock, port)
                service = self.services.get(port, 'Unknown')
                
                with self.lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'warning': self.vulnerable_services.get(port, None)
                    })
                    print(f"[+] Port {port:<6} OPEN    {service:<15} {banner if banner else ''}")
                    
            sock.close()
        except socket.error:
            pass
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            sys.exit(0)
            
    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2)
            # Send HTTP request for web servers
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            # Send generic newline for other services
            else:
                sock.send(b'\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else None
        except:
            return None
            
    def worker(self):
        """Worker thread for scanning ports"""
        while True:
            port = self.queue.get()
            if port is None:
                break
            self.scan_port(port)
            self.queue.task_done()
            
    def scan(self):
        """Main scanning function"""
        # Display system info
        self.display_system_info()
        
        # Resolve target
        self.target_ip = self.resolve_target()
        
        if not self.validate_target(self.target_ip):
            print(f"[!] Invalid IP address: {self.target_ip}")
            sys.exit(1)
            
        print("=" * 80)
        print(f"TARGET SCAN CONFIGURATION")
        print(f"Target: {self.target} ({self.target_ip})")
        print(f"Ports: {self.ports[0]}-{self.ports[-1]} ({len(self.ports)} ports)")
        print(f"Threads: {self.threads}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
        
        # Add ports to queue
        for port in self.ports:
            self.queue.put(port)
            
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Wait for all tasks to complete
        self.queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()
            
        print()
        self.generate_report()
        
    def generate_report(self):
        """Generate scan report"""
        print("=" * 80)
        print("CYBERSENTINEL - SCAN RESULTS")
        print("=" * 80)
        print(f"Author: Md Ariful Hoque | george.ariful@gmail.com")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Computer: {self.hostname} | User: {self.username}")
        print(f"Total ports scanned: {len(self.ports)}")
        print(f"Open ports found: {len(self.open_ports)}")
        print()
        
        if self.open_ports:
            print("OPEN PORTS SUMMARY")
            print("-" * 80)
            print(f"{'Port':<8} {'Service':<15} {'Banner':<40}")
            print("-" * 80)
            
            for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                banner = (port_info['banner'][:37] + '...') if port_info['banner'] and len(port_info['banner']) > 40 else port_info['banner'] or ''
                print(f"{port_info['port']:<8} {port_info['service']:<15} {banner:<40}")
            print()
            
            # Security warnings
            warnings = [p for p in self.open_ports if p['warning']]
            if warnings:
                print("SECURITY WARNINGS")
                print("-" * 80)
                for port_info in warnings:
                    print(f"⚠ Port {port_info['port']} ({port_info['service']})")
                    print(f"  {port_info['warning']}")
                    print()
                    
            # Recommendations
            print("RECOMMENDATIONS")
            print("-" * 80)
            
            if any(p['port'] in [21, 23] for p in self.open_ports):
                print("• Disable insecure protocols (FTP, Telnet) and use encrypted alternatives")
                
            if any(p['port'] == 3389 for p in self.open_ports):
                print("• Secure RDP with strong passwords, NLA, and firewall restrictions")
                
            if any(p['port'] == 445 for p in self.open_ports):
                print("• Ensure SMB is patched against EternalBlue (MS17-010)")
                
            if len(self.open_ports) > 20:
                print("• Large attack surface detected - review necessity of each open port")
                print("• Implement firewall rules to restrict unnecessary services")
                
            print("• Run vulnerability scanner (Nessus, OpenVAS) for detailed assessment")
            print("• Ensure all services are updated to latest versions")
            
        else:
            print("No open ports found in the scanned range.")
            
        print()
        print("=" * 80)
        print("CyberSentinel - Network Security Assessment Tool")
        print("=" * 80)

def parse_port_range(port_string):
    """Parse port range string (e.g., '1-1000' or '80,443,8080')"""
    ports = []
    
    if ',' in port_string:
        # Individual ports: 80,443,8080
        for port in port_string.split(','):
            try:
                ports.append(int(port.strip()))
            except ValueError:
                print(f"[!] Invalid port: {port}")
                sys.exit(1)
    elif '-' in port_string:
        # Port range: 1-1000
        try:
            start, end = port_string.split('-')
            start, end = int(start.strip()), int(end.strip())
            if start > end or start < 1 or end > 65535:
                raise ValueError
            ports = list(range(start, end + 1))
        except ValueError:
            print(f"[!] Invalid port range: {port_string}")
            print("    Use format: 1-1000 or 80,443,8080")
            sys.exit(1)
    else:
        # Single port
        try:
            ports.append(int(port_string))
        except ValueError:
            print(f"[!] Invalid port: {port_string}")
            sys.exit(1)
            
    return ports

def main():
    parser = argparse.ArgumentParser(
        description='CyberSentinel Port Scanner - Network Security Assessment',
        epilog='Author: Md Ariful Hoque | george.ariful@gmail.com | WARNING: Only scan authorized systems!'
    )
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', 
                       help='Port range (e.g., 1-1000, 80,443,8080) [default: 1-1000]')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads [default: 100]')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds [default: 1.0]')
    parser.add_argument('--common', action='store_true',
                       help='Scan only common ports (fast scan)')
    
    args = parser.parse_args()
    
    # Common ports for quick scan
    if args.common:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]
        print("[*] Quick scan mode: scanning common ports only")
    else:
        ports = parse_port_range(args.ports)
        
    # Validate thread count
    if args.threads < 1 or args.threads > 1000:
        print("[!] Thread count must be between 1 and 1000")
        sys.exit(1)
        
    # Create scanner and run
    scanner = PortScanner(args.target, ports, threads=args.threads, timeout=args.timeout)
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()
