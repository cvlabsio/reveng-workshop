#!/usr/bin/env python3
"""
AKRODLABS PE Entropy Analysis Script
Calculates entropy for PE sections to identify packed/encrypted content
"""

import pefile
import math
import sys
from collections import Counter

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if len(data) == 0:
        return 0
    
    # Count frequency of each byte
    frequencies = Counter(data)
    
    # Calculate entropy
    entropy = 0
    data_len = len(data)
    
    for count in frequencies.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_pe_entropy(filepath):
    """Analyze entropy of PE sections"""
    try:
        pe = pefile.PE(filepath)
        
        print(f"PE Entropy Analysis: {filepath}")
        print("=" * 50)
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            
            print(f"Section: {section_name:12} | Size: {len(section_data):8} | Entropy: {entropy:.2f}")
            
            # Flag suspicious sections
            if entropy > 7.0:
                print(f"  ⚠️  HIGH ENTROPY - Possibly packed/encrypted")
            elif entropy < 1.0:
                print(f"  ℹ️  LOW ENTROPY - Mostly zeros or repeated data")
        
        # Overall file entropy
        file_data = open(filepath, 'rb').read()
        file_entropy = calculate_entropy(file_data)
        print(f"\nOverall file entropy: {file_entropy:.2f}")
        
    except Exception as e:
        print(f"Error analyzing {filepath}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pe-entropy.py <pe_file>")
        sys.exit(1)
    
    analyze_pe_entropy(sys.argv[1])
