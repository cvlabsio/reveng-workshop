#!/usr/bin/env python3
"""
AKRODLABS IDA Pro Function Analysis Script
IDAPython script for automated function analysis and documentation

Features:
- Function enumeration with classification (User/System/Compiler)
- Priority analysis to identify key functions for reverse engineering
- API usage analysis with cross-reference tracking
- String analysis for suspicious patterns
- Comprehensive reporting with analysis recommendations

Usage: Run this script from within IDA Pro using File -> Script file
or use Alt+F7 and select this script.

The script will automatically:
1. Classify all functions by type
2. Identify high-priority user functions for analysis
3. Find suspicious API usage patterns
4. Analyze strings for indicators
5. Provide actionable recommendations for further analysis

Focus on USER functions with high priority scores for maximum efficiency.
"""

try:
    import ida_funcs
    import ida_name
    import ida_bytes
    import ida_xref
    import ida_strlist
    import idautils
    import ida_kernwin
    import idc
    import idaapi
except ImportError as e:
    print(f"Error: This script must be run from within IDA Pro. Missing: {e}")
    exit(1)

def classify_function(func_name, func_ea, func_size, xref_count):
    """Classify function as compiler, system, or user-created"""
    
    # Compiler-generated function patterns
    compiler_patterns = [
        # Runtime startup/shutdown
        "_start", "_mainCRTStartup", "_DllMainCRTStartup", "_WinMainCRTStartup",
        "mainCRTStartup", "DllMainCRTStartup", "WinMainCRTStartup",
        # Exception handling
        "__CxxFrameHandler", "_except_handler", "__security_check_cookie",
        "__GSHandlerCheck", "__security_init_cookie", "_chkstk", "__chkstk",
        # C++ runtime
        "_GLOBAL__sub_I_", "_GLOBAL__sub_D_", "??_E", "??_G", "??_C",
        # Stack and security
        "__stack_chk_fail", "__stack_chk_guard", "_RTC_CheckEsp",
        # Memory management helpers
        "__malloc_base", "__free_base", "_heap_alloc", "_calloc_base"
    ]
    
    # System/Library function patterns  
    system_patterns = [
        # Windows API patterns
        "CreateFile", "GetProcAddress", "LoadLibrary", "VirtualAlloc",
        "WriteFile", "ReadFile", "CloseHandle", "GetModuleHandle",
        "SetWindowsHook", "CreateProcess", "TerminateProcess",
        # C Runtime patterns
        "printf", "malloc", "free", "strcpy", "memcpy", "strlen",
        "_printf", "_malloc", "_free", "_strcpy", "_memcpy", "_strlen",
        # POSIX patterns
        "open", "read", "write", "close", "socket", "bind", "listen"
    ]
    
    # Check for compiler functions
    for pattern in compiler_patterns:
        if pattern in func_name:
            return "compiler"
    
    # Additional compiler heuristics
    if (func_size < 50 and xref_count > 10) or func_name.startswith("__"):
        return "compiler"
    
    # Check for system/library functions
    for pattern in system_patterns:
        if pattern in func_name:
            return "system"
    
    # Check if it's an import (IAT entry)
    if func_size == 0 or func_size == 6:  # Typical import stub size
        return "system"
    
    # Check for mangled C++ names (likely system/library)
    if func_name.startswith("?") or "@@" in func_name:
        return "system"
    
    # Check for standard library naming patterns
    if func_name.startswith("_") and func_size < 100:
        return "system"
    
    # Default to user-created
    return "user"

def enumerate_functions():
    """Enumerate all functions with basic information and classification"""
    print("Function Analysis Report")
    print("=" * 50)
    
    try:
        function_count = 0
        total_size = 0
        interesting_functions = []
        
        # Classification counters
        function_types = {"compiler": 0, "system": 0, "user": 0}
        classified_functions = {"compiler": [], "system": [], "user": []}
        
        for func_ea in idautils.Functions():
            function_count += 1
            func_name = ida_name.get_ea_name(func_ea)
            func_obj = ida_funcs.get_func(func_ea)
            
            if func_obj is None:
                print(f"Warning: Could not get function object for {hex(func_ea)}")
                continue
                
            func_size = func_obj.end_ea - func_obj.start_ea
            total_size += func_size
            
            # Count cross-references
            xref_count = len(list(idautils.XrefsTo(func_ea)))
            
            # Classify function
            func_type = classify_function(func_name, func_ea, func_size, xref_count)
            function_types[func_type] += 1
            classified_functions[func_type].append((func_name, func_size, xref_count))
            
            print(f"Function: {func_name}")
            print(f"  Address: {hex(func_ea)}")
            print(f"  Size: {func_size} bytes")
            print(f"  End: {hex(func_obj.end_ea)}")
            print(f"  Cross-references: {xref_count}")
            print(f"  Type: {func_type.upper()}")
            
            # Mark functions with many cross-references as interesting
            if xref_count > 5:
                interesting_functions.append((func_name, xref_count, func_type))
            
            print()
        
        # Print summary
        print(f"SUMMARY:")
        print(f"  Total functions: {function_count}")
        print(f"  Total code size: {total_size} bytes")
        if function_count > 0:
            print(f"  Average function size: {total_size // function_count} bytes")
        
        # Function type breakdown
        print(f"  Function Types:")
        print(f"    User-created: {function_types['user']} ({function_types['user']/function_count*100:.1f}%)")
        print(f"    System/Library: {function_types['system']} ({function_types['system']/function_count*100:.1f}%)")
        print(f"    Compiler-generated: {function_types['compiler']} ({function_types['compiler']/function_count*100:.1f}%)")
        
        if interesting_functions:
            print(f"  Functions with many references (>5):")
            for func_name, xref_count, func_type in sorted(interesting_functions, key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {func_name}: {xref_count} refs [{func_type.upper()}]")
        
        # Show top user functions (most likely to be interesting for analysis)
        user_functions = classified_functions["user"]
        if user_functions:
            print(f"  Top User Functions (by size):")
            sorted_user_funcs = sorted(user_functions, key=lambda x: x[1], reverse=True)[:5]
            for func_name, func_size, xref_count in sorted_user_funcs:
                print(f"    {func_name}: {func_size} bytes, {xref_count} refs")
        
        # Analysis recommendations
        print(f"  Analysis Recommendations:")
        if function_types['user'] > 0:
            print(f"    - Focus on {function_types['user']} user-created functions")
            print(f"    - Prioritize large user functions (>200 bytes)")
            print(f"    - Examine user functions with high cross-references")
        if function_types['system'] > function_types['user'] * 2:
            print(f"    - High system function ratio suggests statically linked binary")
        if function_types['compiler'] > function_count * 0.3:
            print(f"    - Many compiler functions suggest debug build or specific compiler")
        
    except Exception as e:
        print(f"Error enumerating functions: {e}")

def find_api_usage(api_names):
    """Find usage of specific APIs"""
    print("API Usage Analysis")
    print("=" * 50)
    
    try:
        found_apis = []
        
        for api_name in api_names:
            api_ea = ida_name.get_name_ea(0, api_name)
            # Check if API was found (BADADDR means not found)
            if api_ea != idaapi.BADADDR and api_ea != 0:
                print(f"\nAPI: {api_name} (at {hex(api_ea)})")
                xref_count = 0
                for xref in idautils.XrefsTo(api_ea):
                    func_name = ida_name.get_ea_name(xref.frm)
                    if not func_name:
                        func_name = f"sub_{xref.frm:X}"
                    print(f"  Called from: {func_name} at {hex(xref.frm)}")
                    xref_count += 1
                
                if xref_count == 0:
                    print(f"  No cross-references found for {api_name}")
                else:
                    found_apis.append((api_name, xref_count))
            # Uncomment the line below if you want to see APIs that are not found
            # else:
            #     print(f"API not found: {api_name}")
        
        # Summary of found APIs
        if found_apis:
            print(f"\nAPI SUMMARY:")
            print(f"  Found {len(found_apis)} APIs with cross-references:")
            for api_name, xref_count in sorted(found_apis, key=lambda x: x[1], reverse=True):
                print(f"    {api_name}: {xref_count} calls")
        else:
            print(f"\nNo interesting APIs found with cross-references.")
            
    except Exception as e:
        print(f"Error analyzing API usage: {e}")

def analyze_strings():
    """Analyze strings in the binary"""
    print("String Analysis")
    print("=" * 50)
    
    suspicious_patterns = [
        "http://", "https://", "ftp://",
        "cmd.exe", "powershell", "regsvr32",
        "temp", "appdata", "startup",
        "password", "token", "key", "registry",
        "malware", "virus", "trojan", "backdoor"
    ]
    
    try:
        found_suspicious = False
        
        # Iterate through strings using idautils
        for s in idautils.Strings():
            try:
                string_content = ida_bytes.get_strlit_contents(s.ea)
                if string_content:
                    string_str = string_content.decode('utf-8', errors='ignore')
                    
                    # Skip very short strings
                    if len(string_str) < 3:
                        continue
                    
                    # Check for suspicious patterns
                    for pattern in suspicious_patterns:
                        if pattern.lower() in string_str.lower():
                            print(f"Suspicious string at {hex(s.ea)}: {string_str[:100]}{'...' if len(string_str) > 100 else ''}")
                            found_suspicious = True
                            break
            except Exception as e:
                # Skip problematic strings
                continue
        
        if not found_suspicious:
            print("No suspicious strings found with current patterns.")
            
    except Exception as e:
        print(f"Error analyzing strings: {e}")

def analyze_priority_functions():
    """Quick analysis focusing on high-priority user functions"""
    print("Priority Function Analysis")
    print("=" * 50)
    print("Focusing on functions most likely to contain core application logic...")
    print()
    
    try:
        priority_functions = []
        
        for func_ea in idautils.Functions():
            func_name = ida_name.get_ea_name(func_ea)
            func_obj = ida_funcs.get_func(func_ea)
            
            if func_obj is None:
                continue
                
            func_size = func_obj.end_ea - func_obj.start_ea
            xref_count = len(list(idautils.XrefsTo(func_ea)))
            func_type = classify_function(func_name, func_ea, func_size, xref_count)
            
            # Priority scoring for user functions
            if func_type == "user":
                priority_score = 0
                
                # Size factor (larger functions often more important)
                if func_size > 200:
                    priority_score += 3
                elif func_size > 100:
                    priority_score += 2
                elif func_size > 50:
                    priority_score += 1
                
                # Cross-reference factor
                if xref_count > 10:
                    priority_score += 3
                elif xref_count > 5:
                    priority_score += 2
                elif xref_count > 2:
                    priority_score += 1
                
                # Name analysis (meaningful names suggest important functions)
                if not func_name.startswith("sub_"):
                    priority_score += 2
                
                # Check for main-like names
                main_patterns = ["main", "Main", "WinMain", "DllMain", "start", "entry"]
                if any(pattern in func_name for pattern in main_patterns):
                    priority_score += 4
                
                # Check for interesting keywords in function names
                interesting_keywords = ["process", "handle", "execute", "run", "init", "setup", 
                                      "config", "decrypt", "encode", "parse", "validate"]
                if any(keyword in func_name.lower() for keyword in interesting_keywords):
                    priority_score += 2
                
                if priority_score > 0:
                    priority_functions.append((func_name, func_ea, func_size, xref_count, priority_score))
        
        # Sort by priority score
        priority_functions.sort(key=lambda x: x[4], reverse=True)
        
        if priority_functions:
            print(f"Found {len(priority_functions)} high-priority user functions:")
            print()
            
            for i, (func_name, func_ea, func_size, xref_count, score) in enumerate(priority_functions[:10]):
                print(f"{i+1:2d}. {func_name}")
                print(f"     Address: {hex(func_ea)}")
                print(f"     Size: {func_size} bytes")
                print(f"     Cross-refs: {xref_count}")
                print(f"     Priority Score: {score}/10")
                print()
            
            if len(priority_functions) > 10:
                print(f"... and {len(priority_functions) - 10} more functions")
                print()
            
            print("ANALYSIS RECOMMENDATIONS:")
            print("1. Start with functions that have high priority scores")
            print("2. Focus on large functions (>200 bytes) first")
            print("3. Examine functions with many cross-references")
            print("4. Look for main/entry point functions")
            print("5. Pay attention to functions with meaningful names")
            
        else:
            print("No high-priority user functions identified.")
            print("This might indicate:")
            print("- Heavily obfuscated binary")
            print("- Statically linked binary with mostly library code")
            print("- Very simple program")
        
    except Exception as e:
        print(f"Error analyzing priority functions: {e}")

def main():
    """Main analysis function"""
    print("AKRODLABS IDA Pro Analysis Script")
    print("=" * 60)
    print("Starting automated analysis of the loaded binary...")
    print()
    
    try:
        # Check if we have a valid database
        import ida_loader
        if not idaapi.get_input_file_path():
            print("Warning: No file seems to be loaded in IDA.")
            return
        
        # Get basic file info
        input_file = idaapi.get_input_file_path()
        print(f"Analyzing file: {input_file}")
        print(f"Database: {idc.get_idb_path()}")
        print()
        
        # Enumerate functions
        enumerate_functions()
        print()
        
        # Analyze specific APIs
        print("Searching for potentially interesting APIs...")
        suspicious_apis = [
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "SetWindowsHookEx", "CreateProcess",
            "WinExec", "ShellExecute", "URLDownloadToFile",
            "CryptEncrypt", "CryptDecrypt", "RegSetValue",
            "GetProcAddress", "LoadLibrary", "CreateFile",
            "InternetOpen", "HttpSendRequest", "Socket"
        ]
        find_api_usage(suspicious_apis)
        print()
        
        # Analyze strings
        print("Analyzing strings for suspicious patterns...")
        analyze_strings()
        print()
        
        # Priority function analysis
        print("Running priority analysis to identify key functions...")
        analyze_priority_functions()
        print()
        
        print("=" * 60)
        print("Analysis complete! Review the findings above.")
        print("TIP: Focus on high-priority USER functions first, then")
        print("     examine functions with suspicious API usage patterns.")
        print("     Avoid spending time on compiler/system functions unless necessary.")
        print("=" * 60)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        print("Make sure you're running this script from within IDA Pro.")

if __name__ == "__main__":
    main()
