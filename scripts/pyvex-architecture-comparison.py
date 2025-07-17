#!/usr/bin/env python3
"""
Cross-Architecture Assembly Comparison using PyVEX
AKRODLABS Malware Analysis Course - Day 1

This script demonstrates how different CPU architectures can be analyzed
using a common intermediate representation (VEX IR) for universal malware analysis.
"""

import pyvex
import archinfo
import sys
from typing import Dict, Tuple, List

def print_banner():
    """Print course banner"""
    print("=" * 70)
    print("AKRODLABS - Cross-Architecture Assembly Comparison")
    print("Using PyVEX for Universal Malware Analysis")
    print("=" * 70)
    print()

def get_architectures() -> Dict[str, archinfo.Arch]:
    """Get supported architectures for comparison"""
    return {
        'x86_32': archinfo.ArchX86(),
        'x86_64': archinfo.ArchAMD64(),
        'arm32': archinfo.ArchARM(),
        'arm64': archinfo.ArchAArch64(),
        'mips32': archinfo.ArchMIPS32(),
        'ppc32': archinfo.ArchPPC32()
    }

def get_assembly_examples() -> Dict[str, Dict[str, bytes]]:
    """Get assembly examples for different architectures"""
    return {
        'x86_32': {
            'mov_immediate': b'\xb8\x78\x56\x34\x12',  # mov eax, 0x12345678
            'add_registers': b'\x01\xd8',              # add eax, ebx
            'conditional_jump': b'\x3d\x0a\x00\x00\x00\x74\x02', # cmp eax, 10; je +2
            'call_function': b'\xe8\x10\x00\x00\x00',  # call +0x10
            'xor_operation': b'\x31\xdb',              # xor ebx, ebx
        },
        'x86_64': {
            'mov_immediate': b'\x48\xb8\x78\x56\x34\x12\x78\x56\x34\x12', # mov rax, 0x1234567812345678
            'add_registers': b'\x48\x01\xd8',          # add rax, rbx
            'conditional_jump': b'\x48\x3d\x0a\x00\x00\x00\x74\x02', # cmp rax, 10; je +2
        },
        'arm32': {
            'mov_immediate': b'\x78\x56\x34\xe3',      # mov r0, #0x12345678 (simplified)
            'add_registers': b'\x01\x00\x80\xe0',      # add r0, r0, r1
            'conditional_jump': b'\x0a\x00\x50\xe3\x00\x00\x00\x0a', # cmp r0, #10; beq
        },
        'mips32': {
            'mov_immediate': b'\x78\x56\x08\x34',      # li $t0, 0x5678 (simplified)
            'add_registers': b'\x20\x48\x08\x01',      # add $t1, $t0, $t0
        },
    }

def analyze_instruction(machine_code: bytes, arch: archinfo.Arch, arch_name: str, operation: str) -> bool:
    """Analyze a single instruction and show VEX IR translation"""
    try:
        # Lift machine code to VEX IR
        irsb = pyvex.lift(machine_code, 0x1000, arch)
        
        print(f"--- {arch_name.upper()} - {operation.replace('_', ' ').title()} ---")
        print(f"Machine Code: {machine_code.hex().upper()}")
        print(f"Architecture: {arch.name}")
        print("VEX IR Translation:")
        
        for i, stmt in enumerate(irsb.statements):
            print(f"  {i:2d}: {stmt}")
        
        if irsb.exit:
            print(f"Exit: {irsb.exit}")
        
        print("-" * 50)
        return True
        
    except Exception as e:
        print(f"Error analyzing {arch_name} {operation}: {e}")
        return False

def compare_architectures():
    """Compare the same logical operations across different architectures"""
    print_banner()
    
    architectures = get_architectures()
    examples = get_assembly_examples()
    
    print("Comparing common operations across CPU architectures:\n")
    
    # Track which operations are available for each architecture
    available_operations = set()
    for arch_examples in examples.values():
        available_operations.update(arch_examples.keys())
    
    for operation in sorted(available_operations):
        print(f"\n{'='*20} {operation.replace('_', ' ').upper()} {'='*20}")
        print("Same logical operation implemented differently per architecture")
        print("All translate to similar VEX IR for universal analysis\n")
        
        for arch_name, arch in architectures.items():
            if arch_name in examples and operation in examples[arch_name]:
                machine_code = examples[arch_name][operation]
                analyze_instruction(machine_code, arch, arch_name, operation)
            else:
                print(f"--- {arch_name.upper()} - {operation.replace('_', ' ').title()} ---")
                print("Not available for this architecture")
                print("-" * 50)
        
        print()

def demonstrate_vex_benefits():
    """Show practical benefits of VEX IR for malware analysis"""
    print("\n" + "=" * 70)
    print("VEX IR BENEFITS FOR MALWARE ANALYSIS")
    print("=" * 70)
    
    print("""
Key Benefits:

1. ARCHITECTURE INDEPENDENCE
   - Write analysis tools once, work on all architectures
   - Same malware families across x86, ARM, MIPS platforms
   - Universal pattern detection algorithms

2. SIMPLIFIED INSTRUCTION SET
   - Complex x86 instructions broken into simple operations
   - Easier to write analysis algorithms
   - Consistent representation across architectures

3. STANDARDIZED SEMANTICS
   - All memory operations explicit
   - Register operations normalized
   - Control flow clearly represented

4. ANALYSIS TOOL DEVELOPMENT
   - Symbolic execution engines (angr)
   - Automated vulnerability discovery
   - Cross-platform code similarity detection
""")

def detect_suspicious_patterns(binary_data: bytes, arch: archinfo.Arch) -> List[str]:
    """Demonstrate pattern detection using VEX IR"""
    try:
        irsb = pyvex.lift(binary_data, 0x1000, arch)
        patterns = []
        
        for stmt in irsb.statements:
            stmt_str = str(stmt)
            
            # Look for XOR operations (common in obfuscation)
            if 'Xor' in stmt_str:
                patterns.append("XOR operation detected (possible obfuscation)")
            
            # Look for memory operations
            if 'Load' in stmt_str or 'Store' in stmt_str:
                patterns.append("Memory operation")
            
            # Look for arithmetic operations
            if any(op in stmt_str for op in ['Add', 'Sub', 'Mul', 'Div']):
                patterns.append("Arithmetic operation")
        
        return patterns
        
    except Exception as e:
        return [f"Analysis error: {e}"]

def interactive_demo():
    """Interactive demonstration of architecture comparison"""
    print("\n" + "=" * 70)
    print("INTERACTIVE DEMO")
    print("=" * 70)
    
    architectures = get_architectures()
    
    print("\nAvailable architectures:")
    for i, arch_name in enumerate(architectures.keys(), 1):
        print(f"  {i}. {arch_name}")
    
    print("\nExample: Try entering some hex bytes to analyze:")
    print("x86_32 mov eax, 0x12345678: b8 78 56 34 12")
    print("ARM32 mov r0, #0x1234:      78 56 34 e3")
    
    while True:
        try:
            print("\nOptions:")
            print("1. Analyze hex bytes")
            print("2. Run full comparison")
            print("3. Quit")
            
            choice = input("\nEnter choice (1-3): ").strip()
            
            if choice == '1':
                arch_choice = input("Enter architecture (x86_32, arm32, etc.): ").strip()
                if arch_choice not in architectures:
                    print(f"Unknown architecture: {arch_choice}")
                    continue
                
                hex_input = input("Enter hex bytes (e.g., 'b8 78 56 34 12'): ").strip()
                try:
                    # Convert hex string to bytes
                    hex_bytes = bytes.fromhex(hex_input.replace(' ', ''))
                    arch = architectures[arch_choice]
                    
                    print(f"\nAnalyzing {len(hex_bytes)} bytes on {arch_choice}:")
                    analyze_instruction(hex_bytes, arch, arch_choice, "custom")
                    
                    # Show pattern detection
                    patterns = detect_suspicious_patterns(hex_bytes, arch)
                    if patterns:
                        print("Detected patterns:")
                        for pattern in patterns:
                            print(f"  - {pattern}")
                    
                except ValueError:
                    print("Invalid hex format. Use format like 'b8 78 56 34 12'")
                except Exception as e:
                    print(f"Analysis error: {e}")
            
            elif choice == '2':
                compare_architectures()
                demonstrate_vex_benefits()
            
            elif choice == '3':
                break
            
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
                
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        interactive_demo()
    else:
        compare_architectures()
        demonstrate_vex_benefits()
        print("\nTip: Run with --interactive for hands-on exploration")

if __name__ == "__main__":
    main()
