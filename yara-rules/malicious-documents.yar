/*
Malicious Document Analysis YARA Rules
AKRODLABS Malware Analysis Course - Day 4

Detection rules for common malicious document patterns
Used in MDA-1 and MDA-2 exercises
*/

rule MDA1_VBA_Decimal_Array_Dropper
{
    meta:
        description = "Detects MDA-1 style VBA macro with decimal array payload"
        author = "AKRODLABS"
        reference = "MDA-1 Sample: 59ed41388826fed419cc3b18d28707491a4fa51309935c4fa016e53c6f2f94bc"
        date = "2024-01-15"
        
    strings:
        // VBA macro indicators
        $vba1 = "Auto_Open" nocase
        $vba2 = "UserForm1" nocase
        $vba3 = "TextBox" nocase
        $vba4 = "Split(" nocase
        
        // Decimal array patterns
        $decimal1 = /\d+!\d+!\d+/
        $decimal2 = /Array\([^)]*\d+[^)]*\)/
        
        // File operation indicators
        $file1 = "SaveBinaryData" nocase
        $file2 = "MoveFile" nocase
        $file3 = "winword.con" nocase
        $file4 = "winword.exe" nocase
        
        // WMI/Process creation
        $wmi1 = "winmgmts:" nocase
        $wmi2 = "Win32_Process" nocase
        $wmi3 = "impersonationLevel=impersonate" nocase
        
        // Stream objects
        $stream1 = "ADODB.Stream" nocase
        $stream2 = "Scripting.FileSystemObject" nocase
        
    condition:
        // Must be Office document
        uint16(0) == 0x5A4D or  // PE header (OLE compound)
        uint32(0) == 0x04034b50 or  // ZIP header (OOXML)
        
        // VBA macro presence
        (2 of ($vba*)) and
        
        // Decimal array encoding
        (1 of ($decimal*)) and
        
        // File operations
        (2 of ($file*)) and
        
        // WMI or Stream usage
        (1 of ($wmi*) or 1 of ($stream*))
}

rule MDA2_VBA_Process_Injection_Shellcode
{
    meta:
        description = "Detects MDA-2 style VBA macro with process injection"
        author = "AKRODLABS"
        reference = "MDA-2 Sample: 070281b8c1a72893182928c21bf7241a0ad8c95879969d5f58e28d08f1a73b55"
        family = "Metasploit"
        date = "2024-01-15"
        
    strings:
        // Process injection APIs
        $api1 = "CreateRemoteThread" nocase
        $api2 = "VirtualAllocEx" nocase
        $api3 = "WriteProcessMemory" nocase
        $api4 = "CreateProcessA" nocase
        
        // API aliases (obfuscation)
        $alias1 = "CreateStuff" nocase
        $alias2 = "AllocStuff" nocase
        $alias3 = "WriteStuff" nocase
        $alias4 = "RunStuff" nocase
        
        // VBA structures
        $struct1 = "PROCESS_INFORMATION" nocase
        $struct2 = "STARTUPINFO" nocase
        
        // Array patterns
        $array1 = "myArray" nocase
        $array2 = "Array(" nocase
        $array3 = /[-]?\d+,\s*[-]?\d+,\s*[-]?\d+/
        
        // Process targeting
        $proc1 = "windll32.exe" nocase
        $proc2 = "SystemW64" nocase
        $proc3 = "windir" nocase
        
    condition:
        // Office document
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        
        // Process injection APIs (direct or aliased)
        (2 of ($api*) or 2 of ($alias*)) and
        
        // VBA structures
        (1 of ($struct*)) and
        
        // Array with numeric data
        (1 of ($array*)) and
        
        // Process targeting
        (1 of ($proc*))
}

rule Generic_VBA_Macro_Suspicious
{
    meta:
        description = "Generic detection for suspicious VBA macros"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        // Auto-execution
        $auto1 = "Auto_Open" nocase
        $auto2 = "AutoOpen" nocase
        $auto3 = "Document_Open" nocase
        $auto4 = "Workbook_Open" nocase
        
        // Suspicious APIs
        $api1 = "CreateObject" nocase
        $api2 = "Shell" nocase
        $api3 = "WScript.Shell" nocase
        $api4 = "Environ" nocase
        
        // Network activity
        $net1 = "WinHttp" nocase
        $net2 = "XMLHttpRequest" nocase
        $net3 = "InternetExplorer" nocase
        $net4 = "http://" nocase
        $net5 = "https://" nocase
        
        // File operations
        $file1 = "CreateTextFile" nocase
        $file2 = "SaveToFile" nocase
        $file3 = "Open" nocase
        $file4 = "Binary" nocase
        
        // Obfuscation indicators
        $obf1 = "Chr(" nocase
        $obf2 = "Asc(" nocase
        $obf3 = "Replace(" nocase
        $obf4 = "Split(" nocase
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        (1 of ($auto*)) and
        (3 of ($api*, $net*, $file*, $obf*))
}

rule Office_Embedded_PE_Executable
{
    meta:
        description = "Detects PE executable embedded in Office document"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        // PE headers
        $pe1 = { 4D 5A }  // MZ header
        $pe2 = "PE\x00\x00"
        
        // Common PE sections
        $sec1 = ".text" 
        $sec2 = ".data"
        $sec3 = ".rsrc"
        
        // Office document signatures
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE signature
        $zip = { 50 4B 03 04 }  // ZIP signature (OOXML)
        
    condition:
        // Office document
        ($ole at 0 or $zip at 0) and
        
        // Contains PE
        $pe1 and $pe2 and
        (1 of ($sec*))
}

rule VBA_UserForm_Data_Hiding
{
    meta:
        description = "Detects data hiding in VBA UserForm objects"
        author = "AKRODLABS"
        reference = "Common technique in MDA samples"
        date = "2024-01-15"
        
    strings:
        $userform = "UserForm" nocase
        $textbox = "TextBox" nocase
        $caption = "Caption" nocase
        $text = ".Text" nocase
        
        // Concatenation patterns
        $concat1 = "&" 
        $concat2 = "+"
        
        // Array/data patterns
        $data1 = "Split(" nocase
        $data2 = "Join(" nocase
        $data3 = "Array(" nocase
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        $userform and $textbox and
        (2 of ($caption, $text, $concat*, $data*))
}

rule Document_Password_Protected_VBA
{
    meta:
        description = "Detects password-protected VBA projects"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        $vba_pass1 = "DPB=" // VBA project password indicator
        $vba_pass2 = "CMG=" 
        $vba_pass3 = "VBA Password"
        
        $protect1 = "VisibilityState"
        $protect2 = "Protection"
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        (1 of ($vba_pass*)) and
        (1 of ($protect*))
}

rule Shellcode_Pattern_Detection
{
    meta:
        description = "Detects common shellcode patterns in documents"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        // Common shellcode opcodes
        $sc1 = { FC E8 ?? ?? ?? ?? 60 }  // Common shellcode prologue
        $sc2 = { 64 8B ?? 30 }  // PEB access
        $sc3 = { 8B ?? 0C }     // InMemoryOrderModuleList
        
        // API hashing patterns
        $hash1 = { C1 CF 0D }   // Common hash rotation
        $hash2 = { 01 C7 }      // Add to hash
        
        // WinInet indicators
        $wininet1 = "wininet" nocase
        $wininet2 = { 77 69 6E 69 6E 65 74 00 }  // "wininet\0"
        
        // User-Agent patterns
        $ua1 = "User-Agent:" nocase
        $ua2 = "Mozilla" nocase
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        (
            (2 of ($sc*)) or
            (1 of ($hash*) and 1 of ($wininet*)) or
            (1 of ($ua*))
        )
}

rule Document_Macro_Downloader
{
    meta:
        description = "Detects document macros that download additional payloads"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        // Download methods
        $dl1 = "URLDownloadToFile" nocase
        $dl2 = "WinHttp.WinHttpRequest" nocase
        $dl3 = "MSXML2.XMLHTTP" nocase
        $dl4 = "InternetExplorer.Application" nocase
        
        // File writing
        $write1 = "CreateTextFile" nocase
        $write2 = "SaveToFile" nocase
        $write3 = "Open" nocase
        $write4 = "Binary" nocase
        
        // Execution
        $exec1 = "Shell" nocase
        $exec2 = "CreateObject" nocase
        $exec3 = "Run" nocase
        
        // URLs
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $url3 = "ftp://" nocase
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        (1 of ($dl*)) and
        (1 of ($write*)) and
        (1 of ($exec*)) and
        (1 of ($url*))
}

rule MDA_Course_Samples
{
    meta:
        description = "Specific detection for MDA course samples"
        author = "AKRODLABS"
        date = "2024-01-15"
        
    strings:
        // MDA-1 specific
        $mda1_hash = "59ed41388826fed419cc3b18d28707491a4fa51309935c4fa016e53c6f2f94bc"
        $mda1_path1 = "C:\\Users\\Public\\Pictures\\winword.con" nocase
        $mda1_path2 = "C:\\Users\\Public\\Pictures\\winword.exe" nocase
        
        // MDA-2 specific  
        $mda2_hash = "070281b8c1a72893182928c21bf7241a0ad8c95879969d5f58e28d08f1a73b55"
        $mda2_c2 = "47.93.63.179"
        $mda2_port = "7498"
        $mda2_ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
        
    condition:
        uint16(0) == 0x5A4D or uint32(0) == 0x04034b50 and
        (
            // MDA-1 patterns
            (1 of ($mda1_*)) or
            
            // MDA-2 patterns  
            (1 of ($mda2_*))
        )
}
