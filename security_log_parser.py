#!/usr/bin/env python3
"""
CyberSentinel - Security Log Parser
Author: Md Ariful Hoque
Email: george.ariful@gmail.com
GitHub: https://github.com/yourusername/CyberSentinel

Description: Automated security log analysis tool for detecting suspicious activities,
             failed login attempts, port scans, and security anomalies.
Usage: python security_log_parser.py <logfile> [--output report.html]
"""

import re
import sys
import argparse
import socket
import getpass
import platform
from datetime import datetime
from collections import defaultdict, Counter
import json

class SecurityLogParser:
    def __init__(self, logfile):
        self.logfile = logfile
        self.failed_logins = []
        self.successful_logins = []
        self.port_scans = defaultdict(list)
        self.suspicious_ips = Counter()
        self.errors = []
        self.warnings = []
        
        # System information
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.os_info = platform.system() + " " + platform.release()
        
        # Common attack patterns
        self.attack_patterns = {
            'sql_injection': r'(union.*select|insert.*into|drop.*table|script.*alert)',
            'xss': r'(<script|javascript:|onerror=|onload=)',
            'path_traversal': r'(\.\./|\.\.\\)',
            'command_injection': r'(;.*ls|;.*cat|;.*wget|&.*cmd)',
        }
        
    def display_system_info(self):
        """Display system information"""
        print("=" * 80)
        print("CYBERSENTINEL - SECURITY LOG PARSER")
        print("=" * 80)
        print(f"Computer Name:    {self.hostname}")
        print(f"User Account:     {self.username}")
        print(f"Operating System: {self.os_info}")
        print(f"Python Version:   {platform.python_version()}")
        print(f"Analysis Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
        
    def parse_log(self):
        """Parse log file and extract security events"""
        self.display_system_info()
        print(f"[*] Parsing log file: {self.logfile}")
        
        try:
            with open(self.logfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    self._analyze_line(line, line_num)
        except FileNotFoundError:
            print(f"[!] Error: Log file '{self.logfile}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading log file: {e}")
            sys.exit(1)
            
        print(f"[+] Log parsing completed. Analyzed {line_num} lines")
        
    def _analyze_line(self, line, line_num):
        """Analyze individual log line for security events"""
        
        # Detect failed login attempts
        if re.search(r'(failed|invalid|authentication failure|login incorrect)', line, re.I):
            ip = self._extract_ip(line)
            user = self._extract_username(line)
            self.failed_logins.append({
                'line': line_num,
                'ip': ip,
                'user': user,
                'timestamp': self._extract_timestamp(line),
                'message': line.strip()
            })
            if ip:
                self.suspicious_ips[ip] += 1
                
        # Detect successful logins
        elif re.search(r'(accepted|successful|authenticated|logged in)', line, re.I):
            ip = self._extract_ip(line)
            user = self._extract_username(line)
            self.successful_logins.append({
                'line': line_num,
                'ip': ip,
                'user': user,
                'timestamp': self._extract_timestamp(line)
            })
            
        # Detect port scanning activity
        if re.search(r'(port scan|connection refused|connection timeout)', line, re.I):
            ip = self._extract_ip(line)
            if ip:
                self.port_scans[ip].append({
                    'line': line_num,
                    'timestamp': self._extract_timestamp(line)
                })
                self.suspicious_ips[ip] += 3  # Port scans are more suspicious
                
        # Detect attack patterns
        for attack_type, pattern in self.attack_patterns.items():
            if re.search(pattern, line, re.I):
                self.warnings.append({
                    'type': attack_type,
                    'line': line_num,
                    'message': line.strip()
                })
                
        # Detect errors
        if re.search(r'(error|critical|alert|emergency)', line, re.I):
            self.errors.append({
                'line': line_num,
                'message': line.strip()
            })
            
    def _extract_ip(self, line):
        """Extract IPv4 address from log line"""
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
        return match.group(0) if match else None
        
    def _extract_username(self, line):
        """Extract username from log line"""
        patterns = [
            r'user[:\s]+([a-zA-Z0-9_\-\.]+)',
            r'username[:\s]+([a-zA-Z0-9_\-\.]+)',
            r'for\s+([a-zA-Z0-9_\-\.]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, line, re.I)
            if match:
                return match.group(1)
        return None
        
    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
            r'\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}',
        ]
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None
        
    def generate_report(self):
        """Generate security analysis report"""
        report = []
        report.append("=" * 80)
        report.append("CYBERSENTINEL - SECURITY LOG ANALYSIS REPORT")
        report.append(f"Author: Md Ariful Hoque | george.ariful@gmail.com")
        report.append("=" * 80)
        report.append(f"Generated:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Computer Name:   {self.hostname}")
        report.append(f"User Account:    {self.username}")
        report.append(f"Operating System: {self.os_info}")
        report.append(f"Log File:        {self.logfile}")
        report.append("=" * 80)
        report.append("")
        
        # Summary statistics
        report.append("SUMMARY STATISTICS")
        report.append("-" * 80)
        report.append(f"Failed Login Attempts:    {len(self.failed_logins)}")
        report.append(f"Successful Logins:        {len(self.successful_logins)}")
        report.append(f"Port Scan Detections:     {len(self.port_scans)}")
        report.append(f"Security Warnings:        {len(self.warnings)}")
        report.append(f"Errors Detected:          {len(self.errors)}")
        report.append("")
        
        # Top suspicious IPs
        if self.suspicious_ips:
            report.append("TOP 10 SUSPICIOUS IP ADDRESSES")
            report.append("-" * 80)
            for ip, count in self.suspicious_ips.most_common(10):
                report.append(f"{ip:<20} Events: {count}")
            report.append("")
            
        # Failed login details
        if self.failed_logins:
            report.append("FAILED LOGIN ATTEMPTS (Recent 20)")
            report.append("-" * 80)
            for login in self.failed_logins[-20:]:
                report.append(f"[{login['timestamp']}] IP: {login['ip']:<15} User: {login['user']}")
            report.append("")
            
        # Port scan activity
        if self.port_scans:
            report.append("PORT SCAN ACTIVITY")
            report.append("-" * 80)
            for ip, scans in list(self.port_scans.items())[:10]:
                report.append(f"IP: {ip:<15} Scan events: {len(scans)}")
            report.append("")
            
        # Attack pattern warnings
        if self.warnings:
            report.append("SECURITY WARNINGS (Attack Patterns Detected)")
            report.append("-" * 80)
            attack_summary = Counter([w['type'] for w in self.warnings])
            for attack_type, count in attack_summary.items():
                report.append(f"{attack_type:<20} {count} occurrences")
            report.append("")
            
        # Recommendations
        report.append("SECURITY RECOMMENDATIONS")
        report.append("-" * 80)
        
        if len(self.failed_logins) > 10:
            report.append("⚠ HIGH: Excessive failed login attempts detected")
            report.append("  → Consider implementing account lockout policies")
            report.append("  → Review and potentially block suspicious IPs")
            
        if self.port_scans:
            report.append("⚠ HIGH: Port scanning activity detected")
            report.append("  → Enable rate limiting on firewall")
            report.append("  → Consider implementing IDS/IPS")
            
        if self.warnings:
            report.append("⚠ CRITICAL: Potential attack patterns detected")
            report.append("  → Review application logs for exploitation attempts")
            report.append("  → Update WAF rules to block detected patterns")
            
        report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT - CyberSentinel by Md Ariful Hoque")
        report.append("=" * 80)
        
        return "\n".join(report)
        
    def export_json(self):
        """Export findings as JSON"""
        return json.dumps({
            'generated': datetime.now().isoformat(),
            'system': {
                'hostname': self.hostname,
                'username': self.username,
                'os': self.os_info,
            },
            'logfile': self.logfile,
            'summary': {
                'failed_logins': len(self.failed_logins),
                'successful_logins': len(self.successful_logins),
                'port_scans': len(self.port_scans),
                'warnings': len(self.warnings),
                'errors': len(self.errors),
            },
            'suspicious_ips': dict(self.suspicious_ips.most_common(20)),
            'failed_logins': self.failed_logins[-50:],
            'warnings': self.warnings[-50:],
        }, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description='CyberSentinel Log Parser - Automated security log analysis',
        epilog='Author: Md Ariful Hoque | george.ariful@gmail.com'
    )
    parser.add_argument('logfile', help='Path to log file')
    parser.add_argument('-o', '--output', help='Output report file (default: stdout)')
    parser.add_argument('-j', '--json', help='Export as JSON file')
    
    args = parser.parse_args()
    
    # Parse logs
    log_parser = SecurityLogParser(args.logfile)
    log_parser.parse_log()
    
    # Generate report
    report = log_parser.generate_report()
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to: {args.output}")
    else:
        print("\n" + report)
        
    # Export JSON if requested
    if args.json:
        with open(args.json, 'w') as f:
            f.write(log_parser.export_json())
        print(f"[+] JSON data exported to: {args.json}")

if __name__ == "__main__":
    main()
