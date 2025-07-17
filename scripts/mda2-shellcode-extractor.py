#!/usr/bin/env python3
"""
MDA-2 Shellcode Extractor
AKRODLABS Malware Analysis Course - Day 4

Extracts shellcode from MDA-2 sample's VBA array.
Sample: 070281b8c1a72893182928c21bf7241a0ad8c95879969d5f58e28d08f1a73b55

Usage:
    python mda2-shellcode-extractor.py vba_macro.txt
    python mda2-shellcode-extractor.py --interactive
"""

import sys
import struct
import re
import hashlib
import subprocess
from pathlib import Path

class MDA2ShellcodeExtractor:
    """Extract shellcode from MDA-2 VBA macro"""
    
    def __init__(self):
        self.verbose = True
    
    def print_banner(self):
        """Print extraction banner"""
        print("=" * 60)
        print("AKRODLABS - MDA-2 Shellcode Extractor")
        print("Malicious Document Analysis - Sample 2")
        print("=" * 60)
        print()
    
    def extract_vba_array(self, vba_content):
        """Extract array from VBA macro content"""
        if self.verbose:
            print("[+] Extracting VBA array...")
        
        # Look for array declaration patterns
        array_patterns = [
            r'myArray\s*=\s*Array\s*\((.*?)\)',
            r'shellcode\s*=\s*Array\s*\((.*?)\)',
            r'myList\s*=\s*\[(.*?)\]',
            r'Array\s*\((.*?)\)'
        ]
        
        for pattern in array_patterns:
            match = re.search(pattern, vba_content, re.DOTALL | re.IGNORECASE)
            if match:
                array_content = match.group(1)
                if self.verbose:
                    print(f"[+] Found array pattern: {pattern}")
                return self.parse_array_content(array_content)
        
        # If no pattern found, try to extract numbers directly
        if self.verbose:
            print("[+] No array pattern found, extracting numbers directly...")
        
        # Extract all negative and positive numbers
        numbers = re.findall(r'-?\d+', vba_content)
        if numbers:
            try:
                return [int(n) for n in numbers if -128 <= int(n) <= 255]
            except ValueError:
                pass
        
        return []
    
    def parse_array_content(self, array_content):
        """Parse array content and extract integers"""
        if self.verbose:
            print("[+] Parsing array content...")
        
        # Split by comma and extract integers
        parts = array_content.split(',')
        values = []
        
        for part in parts:
            part = part.strip()
            # Remove any VBA-specific syntax
            part = re.sub(r'[&H]', '', part)  # Remove hex prefixes
            part = re.sub(r'[^\d\-]', '', part)  # Keep only digits and minus
            
            if part and part.lstrip('-').isdigit():
                try:
                    value = int(part)
                    if -128 <= value <= 255:
                        values.append(value)
                except ValueError:
                    continue
        
        if self.verbose:
            print(f"[+] Extracted {len(values)} values from array")
        
        return values
    
    def analyze_api_calls(self, vba_content):
        """Analyze API calls in VBA code"""
        if self.verbose:
            print("\n[+] Analyzing API calls...")
        
        # Process injection APIs
        injection_apis = [
            'CreateRemoteThread', 'CreateStuff',
            'VirtualAllocEx', 'AllocStuff', 
            'WriteProcessMemory', 'WriteStuff',
            'CreateProcessA', 'RunStuff'
        ]
        
        found_apis = []
        for api in injection_apis:
            if re.search(api, vba_content, re.IGNORECASE):
                found_apis.append(api)
        
        if found_apis:
            print("[+] Process injection APIs detected:")
            for api in found_apis:
                print(f"    - {api}")
        
        # Look for target process
        process_patterns = [
            r'windir.*?\\.*?\\([^"]+\.exe)',
            r'SystemW64\\([^"]+\.exe)',
            r'System32\\([^"]+\.exe)'
        ]
        
        for pattern in process_patterns:
            match = re.search(pattern, vba_content, re.IGNORECASE)
            if match:
                process = match.group(1)
                print(f"[+] Target process: {process}")
    
    def convert_to_shellcode(self, values, output_file="mda2_shellcode.bin"):
        """Convert values to binary shellcode"""
        if self.verbose:
            print(f"\n[+] Converting to shellcode: {output_file}")
        
        try:
            with open(output_file, 'wb') as f:
                for value in values:
                    f.write(struct.pack('b', value))
            
            if self.verbose:
                print(f"[+] Successfully wrote {len(values)} bytes")
            
            return True
            
        except Exception as e:
            print(f"[-] Error writing shellcode file: {e}")
            return False
    
    def analyze_shellcode(self, shellcode_file):
        """Analyze extracted shellcode"""
        if not Path(shellcode_file).exists():
            print(f"[-] Shellcode file not found: {shellcode_file}")
            return
        
        print(f"\n[+] Analyzing shellcode: {shellcode_file}")
        
        with open(shellcode_file, 'rb') as f:
            data = f.read()
        
        # File size
        print(f"[+] Shellcode size: {len(data)} bytes")
        
        # Calculate hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        
        print(f"[+] MD5: {md5_hash}")
        print(f"[+] SHA256: {sha256_hash}")
        
        # Check for common shellcode patterns
        self.detect_shellcode_patterns(data)
        
        # Extract strings
        self.extract_shellcode_strings(data)
        
        # Try to emulate with scdbg if available
        self.emulate_shellcode(shellcode_file)
    
    def detect_shellcode_patterns(self, data):
        """Detect common shellcode patterns"""
        print("\n[+] Detecting shellcode patterns...")
        
        patterns = {
            'API hashing': [b'\x64\x8b\x52\x30', b'\x8b\x52\x0c'],  # PEB walking
            'GetProcAddress': [b'\x68\x6e\x65\x74\x00'],  # "net\0"
            'LoadLibrary': [b'\x68\x77\x69\x6e\x69'],     # "wini"
            'CreateProcess': [b'\x68\x72\x6f\x63\x41'],   # "rocA"
            'WinInet': [b'\x68\x6e\x65\x74\x00'],         # Internet functions
        }
        
        for pattern_name, signatures in patterns.items():
            for sig in signatures:
                if sig in data:
                    print(f"[+] {pattern_name} pattern detected")
                    break
    
    def extract_shellcode_strings(self, data):
        """Extract strings from shellcode"""
        print("\n[+] Extracting strings from shellcode:")
        
        # ASCII strings
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= 4:
            strings.append(current_string)
        
        # Show interesting strings
        interesting_strings = []
        for s in strings:
            if any(keyword in s.lower() for keyword in ['http', 'user-agent', 'mozilla', '.exe', '.dll']):
                interesting_strings.append(s)
        
        if interesting_strings:
            for s in interesting_strings:
                print(f"    {s}")
        else:
            # Show first few strings
            for s in strings[:5]:
                print(f"    {s}")
            if len(strings) > 5:
                print(f"    ... and {len(strings) - 5} more")
    
    def emulate_shellcode(self, shellcode_file):
        """Try to emulate shellcode with scdbg"""
        print("\n[+] Attempting shellcode emulation...")
        
        # Check if scdbg is available
        scdbg_paths = [
            '/usr/bin/scdbg',
            '/usr/local/bin/scdbg', 
            'scdbg.exe',
            'wine scdbg.exe'
        ]
        
        scdbg_cmd = None
        for path in scdbg_paths:
            try:
                result = subprocess.run(path.split() + ['--help'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0 or 'scdbg' in result.stderr.decode().lower():
                    scdbg_cmd = path
                    break
            except:
                continue
        
        if scdbg_cmd:
            try:
                print(f"[+] Using: {scdbg_cmd}")
                result = subprocess.run(
                    scdbg_cmd.split() + ['-f', shellcode_file],
                    capture_output=True, timeout=30, text=True
                )
                
                if result.stdout:
                    print("[+] Emulation results:")
                    print(result.stdout)
                elif result.stderr:
                    print("[+] Emulation output:")
                    print(result.stderr)
            
            except subprocess.TimeoutExpired:
                print("[-] Emulation timed out")
            except Exception as e:
                print(f"[-] Emulation error: {e}")
        else:
            print("[-] scdbg not found, skipping emulation")
            print("    Install scdbg for dynamic shellcode analysis")
    
    def process_file(self, input_file, output_file="mda2_shellcode.bin"):
        """Process VBA file and extract shellcode"""
        if not Path(input_file).exists():
            print(f"[-] Input file not found: {input_file}")
            return False
        
        print(f"[+] Processing VBA file: {input_file}")
        
        # Read VBA content
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                vba_content = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            return False
        
        # Analyze API calls
        self.analyze_api_calls(vba_content)
        
        # Extract array
        values = self.extract_vba_array(vba_content)
        
        if not values:
            print("[-] No valid array values found")
            return False
        
        print(f"[+] Extracted {len(values)} array values")
        if self.verbose and values:
            print(f"[+] First 10 values: {values[:10]}")
            print(f"[+] Last 10 values: {values[-10:]}")
        
        # Convert to shellcode
        if self.convert_to_shellcode(values, output_file):
            self.analyze_shellcode(output_file)
            return True
        
        return False
    
    def interactive_mode(self):
        """Interactive shellcode extraction"""
        self.print_banner()
        print("Interactive MDA-2 Shellcode Extraction")
        print("This tool extracts shellcode from VBA process injection code")
        print()
        
        while True:
            print("Options:")
            print("1. Extract from VBA file")
            print("2. Paste VBA code directly") 
            print("3. Show example workflow")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                input_file = input("Enter VBA file path: ").strip()
                output_file = input("Enter output file (or press Enter for 'mda2_shellcode.bin'): ").strip()
                if not output_file:
                    output_file = "mda2_shellcode.bin"
                
                if self.process_file(input_file, output_file):
                    print(f"\n[+] Extraction completed successfully!")
                    print(f"[+] Shellcode saved to: {output_file}")
                else:
                    print("\n[-] Extraction failed!")
            
            elif choice == '2':
                print("\nPaste VBA code (end with empty line):")
                lines = []
                while True:
                    line = input()
                    if not line:
                        break
                    lines.append(line)
                
                vba_content = '\n'.join(lines)
                
                output_file = input("Enter output file (or press Enter for 'mda2_shellcode.bin'): ").strip()
                if not output_file:
                    output_file = "mda2_shellcode.bin"
                
                self.analyze_api_calls(vba_content)
                values = self.extract_vba_array(vba_content)
                
                if values and self.convert_to_shellcode(values, output_file):
                    self.analyze_shellcode(output_file)
                    print(f"\n[+] Extraction completed successfully!")
                else:
                    print("\n[-] Extraction failed!")
            
            elif choice == '3':
                self.show_workflow_example()
            
            elif choice == '4':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice. Please enter 1-4.")
    
    def show_workflow_example(self):
        """Show example MDA-2 workflow"""
        print("\n" + "=" * 60)
        print("MDA-2 ANALYSIS WORKFLOW EXAMPLE")
        print("=" * 60)
        
        print("""
1. DOWNLOAD SAMPLE:
   malwoverview.py -b 5 -B 070281b8c1a72893182928c21bf7241a0ad8c95879969d5f58e28d08f1a73b55
   7z e sample.zip

2. ANALYZE DOCUMENT STRUCTURE:
   zipdump.py sample.docx
   zipdump.py sample.docx -s 5 -d | oledump.py

3. EXTRACT VBA MACRO:
   zipdump.py sample.docx -s 5 -d | oledump.py -s 3 -v > vba_macro.txt

4. EXTRACT SHELLCODE:
   python mda2-shellcode-extractor.py vba_macro.txt

5. ANALYZE SHELLCODE:
   file mda2_shellcode.bin
   strings mda2_shellcode.bin
   wine scdbg.exe -f mda2_shellcode.bin

Expected Results:
- Process injection APIs detected
- Shellcode size: ~797 bytes
- C2 server: 47.93.63.179:7498
- User-Agent string detected
        """)

def main():
    """Main function"""
    extractor = MDA2ShellcodeExtractor()
    
    if len(sys.argv) == 1 or '--interactive' in sys.argv:
        # Interactive mode
        extractor.interactive_mode()
    
    elif len(sys.argv) == 2:
        # Single file processing
        input_file = sys.argv[1]
        extractor.print_banner()
        
        if extractor.process_file(input_file):
            print("\n[+] Extraction completed successfully!")
            print("[+] Check mda2_shellcode.bin for the shellcode")
        else:
            print("\n[-] Extraction failed!")
            sys.exit(1)
    
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} <vba_file>")
        print(f"  {sys.argv[0]} --interactive")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} vba_macro.txt")
        sys.exit(1)

if __name__ == "__main__":
    main()
