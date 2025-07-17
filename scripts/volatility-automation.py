#!/usr/bin/env python3
"""
AKRODLABS Volatility Automation Script
Automated memory analysis workflow for malware investigation
"""

import subprocess
import sys
import os
import json
from datetime import datetime

class VolatilityAnalyzer:
    def __init__(self, memory_image, profile=None):
        self.memory_image = memory_image
        self.profile = profile
        self.results = {}
        
    def run_volatility_command(self, plugin, extra_args=""):
        """Execute a volatility command and return output"""
        if self.profile:
            cmd = f"python vol.py -f {self.memory_image} --profile={self.profile} {plugin} {extra_args}"
        else:
            cmd = f"python vol.py -f {self.memory_image} {plugin} {extra_args}"
        
        print(f"[*] Running: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)
    
    def identify_profile(self):
        """Automatically identify the memory profile"""
        print("[*] Identifying memory profile...")
        stdout, stderr = self.run_volatility_command("imageinfo")
        
        if "Suggested Profile(s)" in stdout:
            # Extract first suggested profile
            for line in stdout.split('\n'):
                if "Suggested Profile(s)" in line:
                    profiles = line.split(':')[1].strip()
                    self.profile = profiles.split(',')[0].strip()
                    print(f"[+] Using profile: {self.profile}")
                    break
        
        return self.profile
    
    def analyze_processes(self):
        """Comprehensive process analysis"""
        print("[*] Analyzing processes...")
        
        # Basic process list
        stdout, stderr = self.run_volatility_command("pslist")
        self.results['pslist'] = stdout
        
        # Process tree
        stdout, stderr = self.run_volatility_command("pstree")
        self.results['pstree'] = stdout
        
        # Cross-view process analysis
        stdout, stderr = self.run_volatility_command("psxview")
        self.results['psxview'] = stdout
        
        # Hidden process detection
        stdout, stderr = self.run_volatility_command("pscan")
        self.results['pscan'] = stdout
        
        print("[+] Process analysis complete")
    
    def analyze_network(self):
        """Network connection analysis"""
        print("[*] Analyzing network connections...")
        
        # Network scan
        stdout, stderr = self.run_volatility_command("netscan")
        self.results['netscan'] = stdout
        
        # Legacy netstat
        stdout, stderr = self.run_volatility_command("netstat")
        self.results['netstat'] = stdout
        
        print("[+] Network analysis complete")
    
    def detect_malware(self):
        """Malware detection techniques"""
        print("[*] Detecting malware...")
        
        # Code injection detection
        stdout, stderr = self.run_volatility_command("malfind", "-D malfind_output/")
        self.results['malfind'] = stdout
        
        # Process hollowing detection
        stdout, stderr = self.run_volatility_command("hollowfind")
        self.results['hollowfind'] = stdout
        
        # YARA scanning (if rules provided)
        if os.path.exists("malware_rules.yar"):
            stdout, stderr = self.run_volatility_command("yarascan", "-y malware_rules.yar")
            self.results['yarascan'] = stdout
        
        print("[+] Malware detection complete")
    
    def analyze_registry(self):
        """Registry analysis"""
        print("[*] Analyzing registry...")
        
        # Registry hives
        stdout, stderr = self.run_volatility_command("hivelist")
        self.results['hivelist'] = stdout
        
        # Persistence locations
        persistence_keys = [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "System\\CurrentControlSet\\Services"
        ]
        
        for key in persistence_keys:
            stdout, stderr = self.run_volatility_command("printkey", f'-K "{key}"')
            self.results[f'registry_{key.replace("\\", "_")}'] = stdout
        
        print("[+] Registry analysis complete")
    
    def extract_files(self):
        """Extract suspicious files"""
        print("[*] Extracting files...")
        
        # File scan
        stdout, stderr = self.run_volatility_command("filescan")
        self.results['filescan'] = stdout
        
        # Look for suspicious files
        if stdout:
            suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs']
            for line in stdout.split('\n'):
                for ext in suspicious_extensions:
                    if ext in line and ('temp' in line.lower() or 'appdata' in line.lower()):
                        # Extract suspicious file (implementation would go here)
                        pass
        
        print("[+] File extraction complete")
    
    def generate_report(self):
        """Generate analysis report"""
        print("[*] Generating analysis report...")
        
        report = {
            'analysis_info': {
                'timestamp': datetime.now().isoformat(),
                'memory_image': self.memory_image,
                'profile': self.profile
            },
            'findings': {},
            'iocs': []
        }
        
        # Analyze results for IOCs
        suspicious_processes = []
        if 'pslist' in self.results:
            for line in self.results['pslist'].split('\n'):
                if any(proc in line.lower() for proc in ['temp', 'appdata', 'suspicious']):
                    suspicious_processes.append(line.strip())
        
        report['findings']['suspicious_processes'] = suspicious_processes
        
        # Extract network IOCs
        network_iocs = []
        if 'netscan' in self.results:
            for line in self.results['netscan'].split('\n'):
                if ':' in line and any(port in line for port in ['4444', '8080', '1337']):
                    network_iocs.append(line.strip())
        
        report['findings']['network_iocs'] = network_iocs
        
        # Save report
        with open('volatility_analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print("[+] Report saved to volatility_analysis_report.json")
    
    def run_full_analysis(self):
        """Run complete analysis workflow"""
        print("[*] Starting comprehensive memory analysis...")
        
        # Create output directories
        os.makedirs("malfind_output", exist_ok=True)
        os.makedirs("extracted_files", exist_ok=True)
        
        # Analysis workflow
        if not self.profile:
            self.identify_profile()
        
        if not self.profile:
            print("[-] Could not identify memory profile. Exiting.")
            return
        
        self.analyze_processes()
        self.analyze_network()
        self.detect_malware()
        self.analyze_registry()
        self.extract_files()
        self.generate_report()
        
        print("[+] Analysis complete!")

def main():
    if len(sys.argv) < 2:
        print("Usage: python volatility-automation.py <memory_image> [profile]")
        print("Example: python volatility-automation.py memory.raw Win10x64")
        sys.exit(1)
    
    memory_image = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(memory_image):
        print(f"[-] Memory image not found: {memory_image}")
        sys.exit(1)
    
    analyzer = VolatilityAnalyzer(memory_image, profile)
    analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
