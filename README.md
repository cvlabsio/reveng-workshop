# AKRODLABS Course Materials
## 6-Day Malware Analysis Training - Code and Scripts

This directory contains all the code snippets, scripts, and configuration files referenced in the AKRODLABS Workshop Manual.

---

## Directory Structure

### 📁 `/scripts/`
Python scripts for automated malware analysis:
- **`pe-entropy-analysis.py`** - Calculate entropy for PE sections to identify packed/encrypted content
- **`ida-function-analyzer.py`** - IDAPython script for automated function analysis and documentation
- **`volatility-automation.py`** - Automated memory analysis workflow for malware investigation

### 📁 `/yara-rules/`
YARA detection rules for various malware families:
- **`malware-detection.yar`** - Comprehensive rule set including:
  - Cobalt Strike beacon detection
  - Banking trojan indicators
  - Cryptocurrency miners
  - Process hollowing techniques
  - Ransomware indicators
  - Android/iOS malware patterns

### 📁 `/frida-scripts/`
Dynamic instrumentation scripts for mobile analysis:
- **`android-hooks.js`** - Comprehensive Android malware analysis hooks
- **`ios-hooks.js`** - iOS malware analysis and privacy monitoring hooks

### 📁 `/android-scripts/`
Android-specific analysis tools:
- **`apk-analyzer.sh`** - Comprehensive APK analysis workflow script

### 📁 `/ios-scripts/`
iOS-specific analysis tools:
- **`ipa-analyzer.sh`** - Comprehensive IPA analysis workflow script

### 📁 `/configs/`
Configuration files for analysis tools:
- **`scyllahide-config.ini`** - ScyllaHide anti-debugging protection settings

### 📁 `/tools/`
Standalone analysis utilities:
- **`pe-analyzer.py`** - Comprehensive PE file analysis tool

---

## Usage Instructions

### Python Scripts
All Python scripts require Python 3.6+ and specific dependencies:

```bash
# Install required packages
pip install pefile yara-python volatility3

# Run PE entropy analysis
python scripts/pe-entropy-analysis.py malware.exe

# Run comprehensive PE analysis
python tools/pe-analyzer.py malware.exe

# Run automated Volatility analysis
python scripts/volatility-automation.py memory.raw Win10x64
```

### Bash Scripts
Make scripts executable and run:

```bash
# Make executable
chmod +x android-scripts/apk-analyzer.sh
chmod +x ios-scripts/ipa-analyzer.sh

# Run APK analysis
./android-scripts/apk-analyzer.sh malware.apk

# Run IPA analysis
./ios-scripts/ipa-analyzer.sh malware.ipa
```

### Frida Scripts
Use with Frida for runtime instrumentation:

```bash
# Android analysis
frida -U -l frida-scripts/android-hooks.js com.malware.package

# iOS analysis
frida -U -l frida-scripts/ios-hooks.js com.malware.ios
```

### YARA Rules
Scan files or memory with YARA:

```bash
# Scan file
yara yara-rules/malware-detection.yar malware.exe

# Scan with Volatility
python vol.py -f memory.raw --profile=Win10x64 yarascan -y yara-rules/malware-detection.yar
```

---

## Workshop Exercise Mapping

### Day 1 Exercises
- **PE Analysis**: Use `pe-analyzer.py` and `pe-entropy-analysis.py`
- **Static Analysis**: Apply YARA rules from `malware-detection.yar`

### Day 2 Exercises
- **Anti-Debug Setup**: Configure with `scyllahide-config.ini`
- **Dynamic Analysis**: Use Volatility automation scripts

### Day 3 Exercises
- **IDA Pro Analysis**: Use `ida-function-analyzer.py` scripts
- **Cross-Platform**: Analyze with platform-specific tools

### Day 4 Exercises
- **Advanced Techniques**: Combine multiple scripts for comprehensive analysis

### Day 5 Exercises
- **Memory Forensics**: Use `volatility-automation.py` for systematic analysis

### Day 6 Exercises
- **Mobile Analysis**: Use `apk-analyzer.sh`, `ipa-analyzer.sh`, and Frida scripts

---

## Integration with Workshop Manual

Each script corresponds to specific exercises in the **AKRODLABS-Workshop-Manual.md**:

1. **Exercise 1A-1C (Day 1)**: Use PE analysis tools and YARA rules
2. **Exercise 2A-2B (Day 2)**: Apply anti-debug configs and dynamic analysis
3. **Exercise 3 (Day 3)**: Leverage IDA Pro automation scripts
4. **Exercise 4A-4C (Day 4)**: Combine tools for advanced analysis
5. **Exercise 5A-5E (Day 5)**: Use memory forensics automation
6. **Exercise 6A-6C (Day 6)**: Apply mobile analysis workflows

---

## Security Notes

⚠️ **WARNING**: These tools are designed for malware analysis in isolated environments only.

- Run all scripts in isolated virtual machines
- Do not execute on production systems
- Use proper network isolation during dynamic analysis
- Follow your organization's malware handling procedures

---

## Prerequisites

### Required Software
- **Python 3.6+** with pip
- **YARA 4.x**
- **Volatility Framework** (2.6 and 3.x)
- **Frida** (latest version)
- **Android SDK** (for Android analysis)
- **macOS development tools** (for iOS analysis)

### Required Python Packages
```bash
pip install pefile yara-python volatility3 frida-tools
```

### Platform-Specific Tools
- **Windows**: IDA Pro, x64dbg, PE analysis tools
- **Linux**: radare2, binutils, file analysis tools
- **macOS**: Xcode, class-dump, otool, security tools

---

## Contributing

When adding new scripts or rules:

1. **Documentation**: Include comprehensive comments
2. **Error Handling**: Implement proper exception handling
3. **Testing**: Test with known malware samples
4. **Integration**: Ensure compatibility with workshop exercises

---

## Support

For questions about these materials:
- **Workshop Manual**: Reference corresponding exercise sections
- **Script Issues**: Check Python dependencies and permissions
- **Platform Compatibility**: Verify tool availability for your OS

---

**AKRODLABS Training Team**  
*Advanced Malware Analysis Education*

*This collection supports the 6-Day Malware Analysis Course and should be used in conjunction with the Workshop Manual for complete learning experience.*
