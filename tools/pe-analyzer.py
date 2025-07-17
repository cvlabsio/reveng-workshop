#!/usr/bin/env python3
"""
AKRODLABS PE File Analysis Tool
Comprehensive PE analysis for malware investigation
"""

import pefile
import hashlib
import sys
import os
import json
from datetime import datetime
import math
from collections import Counter

class PEAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.analysis_results = {}
        
    def load_pe(self):
        """Load PE file for analysis"""
        try:
            self.pe = pefile.PE(self.filepath)
            return True
        except Exception as e:
            print(f"Error loading PE file: {e}")
            return False
    
    def calculate_hashes(self):
        """Calculate file hashes"""
        hash_algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        with open(self.filepath, 'rb') as f:
            data = f.read()
            
        hashes = {}
        for name, hasher in hash_algorithms.items():
            hasher.update(data)
            hashes[name] = hasher.hexdigest()
        
        self.analysis_results['hashes'] = hashes
        return hashes
    
    def analyze_basic_info(self):
        """Analyze basic PE information"""
        info = {
            'file_size': os.path.getsize(self.filepath),
            'machine_type': hex(self.pe.FILE_HEADER.Machine),
            'timestamp': datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp).isoformat(),
            'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase)
        }
        
        # Determine architecture
        if self.pe.FILE_HEADER.Machine == 0x14c:
            info['architecture'] = 'x86'
        elif self.pe.FILE_HEADER.Machine == 0x8664:
            info['architecture'] = 'x64'
        else:
            info['architecture'] = 'Unknown'
        
        self.analysis_results['basic_info'] = info
        return info
    
    def analyze_sections(self):
        """Analyze PE sections"""
        sections = []
        
        for section in self.pe.sections:
            section_info = {
                'name': section.Name.decode('utf-8').rstrip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics),
                'entropy': self.calculate_entropy(section.get_data())
            }
            
            # Determine section type
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                section_info['type'] = 'executable'
            elif section.Characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                section_info['type'] = 'writable'
            else:
                section_info['type'] = 'readonly'
            
            # Flag suspicious sections
            if section_info['entropy'] > 7.0:
                section_info['suspicious'] = 'High entropy (possibly packed/encrypted)'
            elif section_info['virtual_size'] > section_info['raw_size'] * 2:
                section_info['suspicious'] = 'Large virtual size (possible unpacking space)'
            
            sections.append(section_info)
        
        self.analysis_results['sections'] = sections
        return sections
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0
        
        frequencies = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_imports(self):
        """Analyze imported functions"""
        imports = {}
        suspicious_apis = [
            'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetWindowsHookEx', 'CreateProcess',
            'WinExec', 'ShellExecute', 'URLDownloadToFile',
            'CryptEncrypt', 'CryptDecrypt', 'RegSetValue',
            'FindFirstFile', 'FindNextFile', 'CreateFile'
        ]
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                imports[dll_name] = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                        imports[dll_name].append(func_name)
                        
                        # Flag suspicious APIs
                        if func_name in suspicious_apis:
                            if 'suspicious_imports' not in self.analysis_results:
                                self.analysis_results['suspicious_imports'] = []
                            self.analysis_results['suspicious_imports'].append(f"{dll_name}!{func_name}")
        
        self.analysis_results['imports'] = imports
        return imports
    
    def analyze_exports(self):
        """Analyze exported functions"""
        exports = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'ordinal': exp.ordinal,
                    'address': hex(exp.address),
                    'name': exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}"
                }
                exports.append(export_info)
        
        self.analysis_results['exports'] = exports
        return exports
    
    def analyze_resources(self):
        """Analyze PE resources"""
        resources = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, f"Type_{resource_type.struct.Id}")
                
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                
                                resource_info = {
                                    'type': type_name,
                                    'id': resource_id.struct.Id,
                                    'language': resource_lang.struct.Id,
                                    'rva': hex(data_rva),
                                    'size': size
                                }
                                
                                # Check for suspicious resources
                                if size > 100000:  # Large resource
                                    resource_info['suspicious'] = 'Large resource (possible embedded PE)'
                                
                                resources.append(resource_info)
        
        self.analysis_results['resources'] = resources
        return resources
    
    def detect_packers(self):
        """Detect common packers"""
        packer_signatures = {
            'UPX': [b'UPX0', b'UPX1', b'UPX!'],
            'VMProtect': [b'VMProtect'],
            'Themida': [b'.themida'],
            'ASPack': [b'.aspack', b'.adata'],
            'PEtite': [b'petite'],
            'FSG': [b'.FSG'],
            'MEW': [b'MEW'],
            'NSPack': [b'.nsp']
        }
        
        detected_packers = []
        
        # Check section names
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00').lower()
            for packer, signatures in packer_signatures.items():
                for sig in signatures:
                    if sig.decode('utf-8').lower() in section_name:
                        detected_packers.append(packer)
        
        # Check entry point section
        ep_section = None
        for section in self.pe.sections:
            if (section.VirtualAddress <= self.pe.OPTIONAL_HEADER.AddressOfEntryPoint < 
                section.VirtualAddress + section.Misc_VirtualSize):
                ep_section = section
                break
        
        if ep_section:
            # Check if entry point is in last section (common packer indicator)
            if ep_section == self.pe.sections[-1]:
                detected_packers.append("Possible_Packer_EP_Last_Section")
        
        self.analysis_results['detected_packers'] = detected_packers
        return detected_packers
    
    def analyze_strings(self, min_length=4):
        """Extract and analyze strings"""
        with open(self.filepath, 'rb') as f:
            data = f.read()
        
        # Extract ASCII strings
        ascii_strings = []
        unicode_strings = []
        
        # ASCII strings
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append(current_string)
                current_string = ""
        
        # Unicode strings (simple UTF-16 LE detection)
        for i in range(0, len(data) - 1, 2):
            if data[i+1] == 0 and 32 <= data[i] <= 126:
                current_string += chr(data[i])
            else:
                if len(current_string) >= min_length:
                    unicode_strings.append(current_string)
                current_string = ""
        
        # Analyze for suspicious patterns
        suspicious_strings = []
        suspicious_patterns = [
            'http://', 'https://', 'ftp://',
            'cmd.exe', 'powershell', 'regsvr32',
            'temp', 'appdata', 'startup',
            'password', 'token', 'key',
            'encrypt', 'decrypt', 'crypto'
        ]
        
        all_strings = ascii_strings + unicode_strings
        for string in all_strings:
            for pattern in suspicious_patterns:
                if pattern.lower() in string.lower():
                    suspicious_strings.append(string)
                    break
        
        self.analysis_results['strings'] = {
            'ascii_count': len(ascii_strings),
            'unicode_count': len(unicode_strings),
            'suspicious_strings': suspicious_strings[:50]  # Limit output
        }
        
        return ascii_strings, unicode_strings
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        report = {
            'file_path': self.filepath,
            'analysis_timestamp': datetime.now().isoformat(),
            'analysis_results': self.analysis_results
        }
        
        # Calculate overall suspicion score
        suspicion_score = 0
        
        # Check for suspicious indicators
        if 'suspicious_imports' in self.analysis_results:
            suspicion_score += len(self.analysis_results['suspicious_imports']) * 2
        
        if 'detected_packers' in self.analysis_results:
            suspicion_score += len(self.analysis_results['detected_packers']) * 3
        
        # High entropy sections
        for section in self.analysis_results.get('sections', []):
            if section.get('entropy', 0) > 7.0:
                suspicion_score += 2
        
        # Suspicious strings
        if 'strings' in self.analysis_results:
            suspicion_score += len(self.analysis_results['strings']['suspicious_strings'])
        
        report['suspicion_score'] = suspicion_score
        
        if suspicion_score > 10:
            report['risk_level'] = 'HIGH'
        elif suspicion_score > 5:
            report['risk_level'] = 'MEDIUM'
        else:
            report['risk_level'] = 'LOW'
        
        return report
    
    def run_full_analysis(self):
        """Run complete PE analysis"""
        print(f"[*] Analyzing PE file: {self.filepath}")
        
        if not self.load_pe():
            return None
        
        # Run all analysis modules
        self.calculate_hashes()
        self.analyze_basic_info()
        self.analyze_sections()
        self.analyze_imports()
        self.analyze_exports()
        self.analyze_resources()
        self.detect_packers()
        self.analyze_strings()
        
        # Generate final report
        report = self.generate_report()
        
        print(f"[+] Analysis complete. Risk level: {report['risk_level']}")
        print(f"[+] Suspicion score: {report['suspicion_score']}")
        
        return report

def main():
    if len(sys.argv) != 2:
        print("Usage: python pe-analyzer.py <pe_file>")
        sys.exit(1)
    
    pe_file = sys.argv[1]
    
    if not os.path.exists(pe_file):
        print(f"File not found: {pe_file}")
        sys.exit(1)
    
    analyzer = PEAnalyzer(pe_file)
    report = analyzer.run_full_analysis()
    
    if report:
        # Save report to JSON file
        output_file = f"pe_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Detailed report saved to: {output_file}")
        
        # Print summary
        print("\n=== ANALYSIS SUMMARY ===")
        print(f"File: {pe_file}")
        print(f"SHA256: {report['analysis_results']['hashes']['sha256']}")
        print(f"Architecture: {report['analysis_results']['basic_info']['architecture']}")
        print(f"Sections: {report['analysis_results']['basic_info']['number_of_sections']}")
        
        if report['analysis_results'].get('detected_packers'):
            print(f"Detected Packers: {', '.join(report['analysis_results']['detected_packers'])}")
        
        if report['analysis_results'].get('suspicious_imports'):
            print(f"Suspicious APIs: {len(report['analysis_results']['suspicious_imports'])}")
        
        print(f"Risk Level: {report['risk_level']}")

if __name__ == "__main__":
    main()
