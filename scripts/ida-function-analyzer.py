#!/usr/bin/env python3
"""
AKRODLABS IDA Pro Function Analysis Script
IDAPython script for automated function analysis and documentation
"""

import ida_funcs
import ida_name
import ida_bytes
import ida_xref
import ida_strlist

def enumerate_functions():
    """Enumerate all functions with basic information"""
    print("Function Analysis Report")
    print("=" * 50)
    
    for func_ea in ida_funcs.Functions():
        func_name = ida_name.get_ea_name(func_ea)
        func_obj = ida_funcs.get_func(func_ea)
        func_size = func_obj.end_ea - func_obj.start_ea
        
        print(f"Function: {func_name}")
        print(f"  Address: {hex(func_ea)}")
        print(f"  Size: {func_size} bytes")
        print(f"  End: {hex(func_obj.end_ea)}")
        
        # Count cross-references
        xref_count = len(list(ida_xref.XrefsTo(func_ea)))
        print(f"  Cross-references: {xref_count}")
        print()

def find_api_usage(api_names):
    """Find usage of specific APIs"""
    print("API Usage Analysis")
    print("=" * 50)
    
    for api_name in api_names:
        api_ea = ida_name.get_name_ea(0, api_name)
        if api_ea != ida_bytes.BADADDR:
            print(f"\nAPI: {api_name} (at {hex(api_ea)})")
            for xref in ida_xref.XrefsTo(api_ea):
                func_name = ida_name.get_ea_name(xref.frm)
                print(f"  Called from: {func_name} at {hex(xref.frm)}")
        else:
            print(f"API not found: {api_name}")

def analyze_strings():
    """Analyze strings in the binary"""
    print("String Analysis")
    print("=" * 50)
    
    suspicious_patterns = [
        "http://", "https://", "ftp://",
        "cmd.exe", "powershell", "regsvr32",
        "temp", "appdata", "startup",
        "password", "token", "key"
    ]
    
    strings = ida_strlist.Strings()
    for i in range(strings.size()):
        string_item = strings[i]
        string_content = ida_bytes.get_strlit_contents(string_item.ea)
        if string_content:
            string_str = string_content.decode('utf-8', errors='ignore')
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if pattern.lower() in string_str.lower():
                    print(f"Suspicious string at {hex(string_item.ea)}: {string_str}")
                    break

def main():
    """Main analysis function"""
    print("AKRODLABS IDA Pro Analysis Script")
    print("=" * 60)
    
    # Enumerate functions
    enumerate_functions()
    
    # Analyze specific APIs
    suspicious_apis = [
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "SetWindowsHookEx", "CreateProcess",
        "WinExec", "ShellExecute", "URLDownloadToFile",
        "CryptEncrypt", "CryptDecrypt", "RegSetValue"
    ]
    find_api_usage(suspicious_apis)
    
    # Analyze strings
    analyze_strings()
    
    print("\nAnalysis complete. Review findings above.")

if __name__ == "__main__":
    main()
