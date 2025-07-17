#!/usr/bin/env python3
"""
MDA-1 Payload Extractor
AKRODLABS Malware Analysis Course - Day 4

Extracts embedded payload from MDA-1 sample's decimal array format.
Sample: 59ed41388826fed419cc3b18d28707491a4fa51309935c4fa016e53c6f2f94bc

Usage:
    python mda1-payload-extractor.py decimal_dump.txt
    python mda1-payload-extractor.py --interactive
"""

import sys
import struct
import re
import hashlib
from pathlib import Path

class MDA1PayloadExtractor:
    """Extract payload from MDA-1 document analysis"""
    
    def __init__(self):
        self.verbose = True
    
    def print_banner(self):
        """Print extraction banner"""
        print("=" * 60)
        print("AKRODLABS - MDA-1 Payload Extractor")
        print("Malicious Document Analysis - Sample 1")
        print("=" * 60)
        print()
    
    def clean_decimal_data(self, raw_data):
        """Clean and prepare decimal data for conversion"""
        if self.verbose:
            print("[+] Cleaning decimal data...")
        
        # Remove common garbage strings
        garbage_patterns = [
            'Tahoma', 'tahoma', 'TAHOMA',
            'UserForm1', 'TextBox1', 'TextBox2', 'TextBox3', 'TextBox4',
            'Microsoft', 'Form', 'Control'
        ]
        
        cleaned = raw_data
        for pattern in garbage_patterns:
            cleaned = cleaned.replace(pattern, '')
        
        # Replace exclamation marks with commas
        cleaned = cleaned.replace('!', ',')
        
        # Remove extra whitespace and newlines
        cleaned = re.sub(r'\s+', ' ', cleaned)
        cleaned = cleaned.strip()
        
        if self.verbose:
            print(f"[+] Cleaned data length: {len(cleaned)} characters")
        
        return cleaned
    
    def extract_decimal_values(self, cleaned_data):
        """Extract decimal values from cleaned data"""
        if self.verbose:
            print("[+] Extracting decimal values...")
        
        # Split by comma and extract valid integers
        parts = cleaned_data.split(',')
        decimal_values = []
        
        for part in parts:
            part = part.strip()
            if part and part.lstrip('-').isdigit():
                try:
                    value = int(part)
                    # Validate range for byte values
                    if -128 <= value <= 255:
                        decimal_values.append(value)
                except ValueError:
                    continue
        
        if self.verbose:
            print(f"[+] Extracted {len(decimal_values)} decimal values")
            if decimal_values:
                print(f"[+] First 10 values: {decimal_values[:10]}")
                print(f"[+] Last 10 values: {decimal_values[-10:]}")
        
        return decimal_values
    
    def convert_to_binary(self, decimal_values, output_file="extracted_payload.bin"):
        """Convert decimal values to binary payload"""
        if self.verbose:
            print(f"[+] Converting to binary: {output_file}")
        
        try:
            with open(output_file, 'wb') as f:
                for value in decimal_values:
                    # Convert to signed byte
                    f.write(struct.pack('b', value))
            
            if self.verbose:
                print(f"[+] Successfully wrote {len(decimal_values)} bytes")
            
            return True
            
        except Exception as e:
            print(f"[-] Error writing binary file: {e}")
            return False
    
    def analyze_payload(self, binary_file):
        """Analyze extracted payload"""
        if not Path(binary_file).exists():
            print(f"[-] Binary file not found: {binary_file}")
            return
        
        print(f"\n[+] Analyzing extracted payload: {binary_file}")
        
        with open(binary_file, 'rb') as f:
            data = f.read()
        
        # File size
        print(f"[+] File size: {len(data)} bytes")
        
        # Calculate hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        
        print(f"[+] MD5: {md5_hash}")
        print(f"[+] SHA256: {sha256_hash}")
        
        # Check for PE header
        if len(data) >= 2:
            if data[:2] == b'MZ':
                print("[+] PE executable detected (MZ header)")
                
                # Look for PE signature
                if len(data) >= 64:
                    pe_offset = struct.unpack('<I', data[60:64])[0]
                    if pe_offset < len(data) - 4:
                        pe_sig = data[pe_offset:pe_offset+4]
                        if pe_sig == b'PE\x00\x00':
                            print("[+] Valid PE signature found")
                        else:
                            print("[-] PE signature not found at expected offset")
            else:
                print("[-] No PE header detected")
        
        # Look for .NET assembly
        if b'Mono' in data or b'.NET' in data:
            print("[+] Possible .NET assembly detected")
        
        # Extract strings
        print("\n[+] Extracting strings (length >= 5):")
        strings = self.extract_strings(data, min_length=5)
        for i, string in enumerate(strings[:10]):  # Show first 10
            print(f"    {string}")
        if len(strings) > 10:
            print(f"    ... and {len(strings) - 10} more strings")
    
    def extract_strings(self, data, min_length=4):
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def process_file(self, input_file, output_file="extracted_payload.bin"):
        """Process input file and extract payload"""
        if not Path(input_file).exists():
            print(f"[-] Input file not found: {input_file}")
            return False
        
        print(f"[+] Processing file: {input_file}")
        
        # Read input file
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                raw_data = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            return False
        
        # Process data
        cleaned_data = self.clean_decimal_data(raw_data)
        decimal_values = self.extract_decimal_values(cleaned_data)
        
        if not decimal_values:
            print("[-] No valid decimal values found")
            return False
        
        # Convert to binary
        if self.convert_to_binary(decimal_values, output_file):
            self.analyze_payload(output_file)
            return True
        
        return False
    
    def interactive_mode(self):
        """Interactive extraction mode"""
        self.print_banner()
        print("Interactive MDA-1 Payload Extraction")
        print("This tool helps extract payloads from decimal array dumps")
        print()
        
        while True:
            print("Options:")
            print("1. Extract from file")
            print("2. Paste decimal data directly")
            print("3. Show example workflow")
            print("4. Exit")
            
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                input_file = input("Enter input file path: ").strip()
                output_file = input("Enter output file (or press Enter for 'extracted_payload.bin'): ").strip()
                if not output_file:
                    output_file = "extracted_payload.bin"
                
                if self.process_file(input_file, output_file):
                    print(f"\n[+] Extraction completed successfully!")
                    print(f"[+] Output saved to: {output_file}")
                else:
                    print("\n[-] Extraction failed!")
            
            elif choice == '2':
                print("\nPaste decimal data (end with empty line):")
                lines = []
                while True:
                    line = input()
                    if not line:
                        break
                    lines.append(line)
                
                raw_data = '\n'.join(lines)
                
                output_file = input("Enter output file (or press Enter for 'extracted_payload.bin'): ").strip()
                if not output_file:
                    output_file = "extracted_payload.bin"
                
                cleaned_data = self.clean_decimal_data(raw_data)
                decimal_values = self.extract_decimal_values(cleaned_data)
                
                if decimal_values and self.convert_to_binary(decimal_values, output_file):
                    self.analyze_payload(output_file)
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
        """Show example MDA-1 workflow"""
        print("\n" + "=" * 60)
        print("MDA-1 ANALYSIS WORKFLOW EXAMPLE")
        print("=" * 60)
        
        print("""
1. DOWNLOAD SAMPLE:
   malwoverview.py -b 5 -B 59ed41388826fed419cc3b18d28707491a4fa51309935c4fa016e53c6f2f94bc
   7z e sample.zip

2. ANALYZE DOCUMENT STRUCTURE:
   zipdump.py sample.docx
   zipdump.py sample.docx -s 5 -d | oledump.py

3. EXTRACT USERFORM DATA:
   zipdump.py sample.docx -s 5 -d | oledump.py -s 11 -d > payload_dump.txt

4. CLEAN AND EXTRACT PAYLOAD:
   python mda1-payload-extractor.py payload_dump.txt

5. ANALYZE EXTRACTED PAYLOAD:
   file extracted_payload.bin
   strings extracted_payload.bin
   
Expected Result: PE32 executable (GUI) Intel 80386 Mono/.Net assembly
        """)

def main():
    """Main function"""
    extractor = MDA1PayloadExtractor()
    
    if len(sys.argv) == 1 or '--interactive' in sys.argv:
        # Interactive mode
        extractor.interactive_mode()
    
    elif len(sys.argv) == 2:
        # Single file processing
        input_file = sys.argv[1]
        extractor.print_banner()
        
        if extractor.process_file(input_file):
            print("\n[+] Extraction completed successfully!")
            print("[+] Check extracted_payload.bin for the payload")
        else:
            print("\n[-] Extraction failed!")
            sys.exit(1)
    
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} <input_file>")
        print(f"  {sys.argv[0]} --interactive")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} payload_dump.txt")
        sys.exit(1)

if __name__ == "__main__":
    main()
