#!/usr/bin/env python3
"""
Interactive Instruction Decoder using PyVEX
AKRODLABS Malware Analysis Course - Day 1

Interactive tool for understanding how assembly instructions from different
architectures translate to VEX intermediate representation.
"""

import pyvex
import archinfo
import sys
import re
from typing import Dict, Optional, List, Tuple

class InstructionDecoder:
    """Interactive instruction decoder using PyVEX"""
    
    def __init__(self):
        self.architectures = {
            'x86_32': archinfo.ArchX86(),
            'x86_64': archinfo.ArchAMD64(),
            'arm32': archinfo.ArchARM(),
            'arm64': archinfo.ArchAArch64(),
            'mips32': archinfo.ArchMIPS32(),
            'ppc32': archinfo.ArchPPC32()
        }
        
        # Common instruction examples for each architecture
        self.examples = {
            'x86_32': {
                'mov eax, 0x12345678': 'b8 78 56 34 12',
                'add eax, ebx': '01 d8',
                'xor eax, eax': '31 c0',
                'push eax': '50',
                'pop eax': '58',
                'call 0x401000': 'e8 fb ef 00 00',
                'ret': 'c3',
                'int 0x80': 'cd 80',
            },
            'x86_64': {
                'mov rax, 0x12345678': '48 b8 78 56 34 12 00 00 00 00',
                'add rax, rbx': '48 01 d8',
                'xor rax, rax': '48 31 c0',
                'push rax': '50',
                'pop rax': '58',
                'syscall': '0f 05',
            },
            'arm32': {
                'mov r0, #0x1234': '34 02 a0 e3',
                'add r0, r0, r1': '01 00 80 e0',
                'ldr r0, [r1]': '00 00 91 e5',
                'str r0, [r1]': '00 00 81 e5',
                'bx lr': '1e ff 2f e1',
            },
            'mips32': {
                'li $t0, 0x1234': '34 12 08 34',
                'add $t1, $t0, $t0': '20 48 08 01',
                'lw $t0, 0($t1)': '00 00 28 8d',
                'sw $t0, 0($t1)': '00 00 28 ad',
                'jr $ra': '08 00 e0 03',
            }
        }
    
    def print_banner(self):
        """Print application banner"""
        print("=" * 70)
        print("AKRODLABS - Interactive Instruction Decoder")
        print("PyVEX-based Cross-Architecture Analysis Tool")
        print("=" * 70)
        print()
    
    def print_help(self):
        """Print help information"""
        print("Commands:")
        print("  decode <arch> <hex_bytes>  - Decode hex bytes for architecture")
        print("  example <arch>             - Show examples for architecture")
        print("  list                       - List available architectures")
        print("  help                       - Show this help")
        print("  quit                       - Exit program")
        print()
        print("Example usage:")
        print("  decode x86_32 b8 78 56 34 12")
        print("  example arm32")
        print()
    
    def list_architectures(self):
        """List available architectures"""
        print("Available architectures:")
        for arch_name in sorted(self.architectures.keys()):
            print(f"  - {arch_name}")
        print()
    
    def show_examples(self, arch_name: str):
        """Show instruction examples for an architecture"""
        if arch_name not in self.examples:
            print(f"No examples available for {arch_name}")
            return
        
        print(f"\nInstruction examples for {arch_name}:")
        print("-" * 50)
        
        for instruction, hex_bytes in self.examples[arch_name].items():
            print(f"Assembly:     {instruction}")
            print(f"Hex bytes:    {hex_bytes}")
            
            # Try to decode the example
            try:
                bytes_data = bytes.fromhex(hex_bytes.replace(' ', ''))
                arch = self.architectures[arch_name]
                self.decode_instruction(bytes_data, arch, arch_name, show_header=False)
            except Exception as e:
                print(f"Error decoding: {e}")
            
            print("-" * 30)
        print()
    
    def decode_instruction(self, machine_code: bytes, arch: archinfo.Arch, 
                          arch_name: str, show_header: bool = True) -> bool:
        """Decode instruction and show VEX IR"""
        try:
            if show_header:
                print(f"\nDecoding {len(machine_code)} bytes for {arch_name}:")
                print(f"Hex: {machine_code.hex().upper()}")
                print("-" * 40)
            
            # Lift to VEX IR
            irsb = pyvex.lift(machine_code, 0x1000, arch)
            
            print("VEX IR Statements:")
            if not irsb.statements:
                print("  (No statements generated)")
            else:
                for i, stmt in enumerate(irsb.statements):
                    print(f"  {i:2d}: {stmt}")
            
            if irsb.exit:
                print(f"Exit: {irsb.exit}")
            
            # Analyze instruction properties
            self.analyze_instruction_properties(irsb)
            
            return True
            
        except Exception as e:
            print(f"Error decoding instruction: {e}")
            return False
    
    def analyze_instruction_properties(self, irsb):
        """Analyze and report instruction properties"""
        properties = []
        
        for stmt in irsb.statements:
            stmt_str = str(stmt)
            
            # Check for different operation types
            if 'PUT' in stmt_str:
                properties.append("Register write")
            if 'GET' in stmt_str:
                properties.append("Register read")
            if 'Load' in stmt_str:
                properties.append("Memory load")
            if 'Store' in stmt_str:
                properties.append("Memory store")
            if any(op in stmt_str for op in ['Add', 'Sub', 'Mul', 'Div']):
                properties.append("Arithmetic operation")
            if any(op in stmt_str for op in ['And', 'Or', 'Xor', 'Not']):
                properties.append("Logical operation")
            if 'CCall' in stmt_str:
                properties.append("Function call")
        
        if properties:
            print("Properties:")
            for prop in sorted(set(properties)):
                print(f"  - {prop}")
        
        print()
    
    def parse_hex_input(self, hex_string: str) -> Optional[bytes]:
        """Parse hex string input and return bytes"""
        try:
            # Remove spaces and common separators
            hex_clean = re.sub(r'[^0-9a-fA-F]', '', hex_string)
            
            # Ensure even number of characters
            if len(hex_clean) % 2 != 0:
                print("Error: Hex string must have even number of characters")
                return None
            
            return bytes.fromhex(hex_clean)
            
        except ValueError:
            print("Error: Invalid hex characters in input")
            return None
    
    def interactive_mode(self):
        """Run interactive decoder"""
        self.print_banner()
        print("Interactive Instruction Decoder")
        print("Type 'help' for commands or 'quit' to exit")
        print()
        
        while True:
            try:
                user_input = input("decoder> ").strip()
                
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                
                if command == 'quit' or command == 'exit':
                    print("Goodbye!")
                    break
                
                elif command == 'help':
                    self.print_help()
                
                elif command == 'list':
                    self.list_architectures()
                
                elif command == 'example':
                    if len(parts) < 2:
                        print("Usage: example <architecture>")
                        continue
                    
                    arch_name = parts[1]
                    if arch_name not in self.architectures:
                        print(f"Unknown architecture: {arch_name}")
                        print("Use 'list' to see available architectures")
                        continue
                    
                    self.show_examples(arch_name)
                
                elif command == 'decode':
                    if len(parts) < 3:
                        print("Usage: decode <architecture> <hex_bytes>")
                        continue
                    
                    arch_name = parts[1]
                    if arch_name not in self.architectures:
                        print(f"Unknown architecture: {arch_name}")
                        print("Use 'list' to see available architectures")
                        continue
                    
                    hex_string = ' '.join(parts[2:])
                    machine_code = self.parse_hex_input(hex_string)
                    
                    if machine_code is not None:
                        arch = self.architectures[arch_name]
                        self.decode_instruction(machine_code, arch, arch_name)
                
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n\nUse 'quit' to exit")
                continue
            except EOFError:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def batch_mode(self, arch_name: str, hex_bytes: str):
        """Run in batch mode with provided arguments"""
        if arch_name not in self.architectures:
            print(f"Error: Unknown architecture '{arch_name}'")
            print("Available architectures:", ', '.join(self.architectures.keys()))
            return False
        
        machine_code = self.parse_hex_input(hex_bytes)
        if machine_code is None:
            return False
        
        arch = self.architectures[arch_name]
        return self.decode_instruction(machine_code, arch, arch_name)

def main():
    """Main function"""
    decoder = InstructionDecoder()
    
    if len(sys.argv) == 1 or '--interactive' in sys.argv:
        # Interactive mode
        decoder.interactive_mode()
    
    elif len(sys.argv) == 3:
        # Batch mode: script.py <arch> <hex_bytes>
        arch_name = sys.argv[1]
        hex_bytes = sys.argv[2]
        
        if not decoder.batch_mode(arch_name, hex_bytes):
            sys.exit(1)
    
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} --interactive")
        print(f"  {sys.argv[0]} <architecture> <hex_bytes>")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} --interactive")
        print(f"  {sys.argv[0]} x86_32 'b8 78 56 34 12'")
        print(f"  {sys.argv[0]} arm32 '34 02 a0 e3'")
        sys.exit(1)

if __name__ == "__main__":
    main()
