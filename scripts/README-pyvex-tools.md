# AKRODLABS PyVEX Analysis Tools
## Cross-Architecture Malware Analysis Scripts

This directory contains PyVEX-based tools for analyzing malware across different processor architectures. These tools demonstrate how to use VEX Intermediate Representation for architecture-independent analysis.

## 🔧 Tools Overview

### 1. `pyvex-architecture-comparison.py`
**Purpose**: Compare the same operations across different processor architectures  
**Use Cases**: 
- Understanding how similar operations are implemented across platforms
- Cross-architecture malware family analysis
- Educational demonstrations of architecture differences

**Key Features**:
- Basic operation comparison (MOV, ADD, memory operations)
- Function call mechanism analysis
- Conditional branch comparison
- Comprehensive architecture analysis with statistics

**Usage**:
```bash
python pyvex-architecture-comparison.py
```

**Example Output**:
```
=== Basic Move Operation Comparison ===

1. x86-64: mov rax, rbx
   Bytes: 4889d8
   VEX IR:
   t0 = GET:I64(rbx)
   PUT(rax) = t0

2. ARM64: mov x0, x1
   Bytes: e00301aa
   VEX IR:
   t0 = GET:I64(x1)
   PUT(x0) = t0
```

### 2. `pyvex-malware-analysis.py`
**Purpose**: Advanced malware analysis using PyVEX for pattern detection  
**Use Cases**:
- XOR decryption routine analysis
- Control flow obfuscation detection
- Shellcode pattern identification
- Malware family comparison

**Key Features**:
- Automated malware pattern detection
- Cross-architecture shellcode analysis
- Cryptographic implementation comparison
- Malware family clustering based on VEX IR patterns

**Usage**:
```bash
python pyvex-malware-analysis.py
```

**Example Analysis**:
```python
# Detect XOR operations in malware
patterns = analyzer.detect_malware_patterns(vex_ir)
# Output: ['XOR_OPERATION', 'MEMORY_MANIPULATION', 'CONTROL_FLOW_TRANSFER']
```

### 3. `pyvex-instruction-decoder.py`
**Purpose**: Interactive instruction decoder and analyzer  
**Use Cases**:
- Real-time instruction analysis during reverse engineering
- Batch processing of instruction sequences
- Cross-architecture instruction comparison
- Educational tool for learning assembly

**Key Features**:
- Interactive command-line interface
- Batch processing from files
- Cross-architecture comparison mode
- Detailed VEX IR analysis

**Usage Examples**:

**Interactive Mode**:
```bash
python pyvex-instruction-decoder.py
PyVEX> x64:4889d8
# Decodes "mov rax, rbx" and shows VEX IR
```

**Direct Decode**:
```bash
python pyvex-instruction-decoder.py -d x64 4889d8
```

**Batch Processing**:
```bash
python pyvex-instruction-decoder.py -i instructions.txt -o results.json
```

**Compare Across Architectures**:
```bash
python pyvex-instruction-decoder.py -c x64:4889d8
```

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- Build tools (gcc/clang on Linux/macOS, Visual Studio on Windows)
- At least 4GB RAM for complex analysis

### Installation

1. **Install system dependencies**:

   **Ubuntu/Debian**:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential python3-dev libffi-dev
   ```

   **macOS**:
   ```bash
   xcode-select --install
   brew install libffi
   ```

   **Windows**:
   - Install Visual Studio Build Tools
   - Install Python 3.8+ from python.org

2. **Install Python dependencies**:
   ```bash
   pip install -r course-materials/configs/pyvex-requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python -c "import pyvex; print('PyVEX installed successfully')"
   ```

## 🎯 Educational Objectives

### Day 1 Integration
These tools complement the Assembly Architecture Crash Course by providing:
- **Practical Examples**: Real code demonstrating architecture differences
- **Interactive Learning**: Hands-on exploration of assembly concepts
- **Cross-Platform Understanding**: See how the same logic appears across architectures

### Skills Developed
- **Architecture Awareness**: Understanding x86, ARM, MIPS, PowerPC differences
- **Pattern Recognition**: Identifying malware techniques across platforms
- **Tool Usage**: Professional-grade analysis tool experience
- **IR Understanding**: Intermediate representation concepts

## 📚 Input File Formats

### Batch Processing Format (`instructions.txt`)
```
# Architecture comparison examples
x64:4889d8
arm64:e00301aa
mips32:25182000
x86:89d8

# Malware patterns
x64:4831d8
arm64:200001ca
```

### Expected Output Format
```json
{
  "line_number": 1,
  "input_line": "x64:4889d8",
  "success": true,
  "architecture": "x64",
  "input_bytes": "4889d8",
  "instruction_count": 1,
  "vex_statements": 2,
  "analysis": {
    "register_operations": ["PUT_REG: PUT(rax) = t0"],
    "memory_operations": [],
    "arithmetic_operations": []
  }
}
```

## 🔍 Analysis Capabilities

### Pattern Detection
The tools automatically detect:
- **XOR Operations**: Common in encryption/obfuscation
- **Memory Manipulation**: Potential code injection
- **Control Flow Transfer**: Jump/call patterns
- **Arithmetic Operations**: Mathematical computations
- **Shift Operations**: Bit manipulation (crypto indicators)

### Architecture Support
- **x86/x64**: Intel/AMD processors
- **ARM32/ARM64**: Mobile and embedded devices
- **MIPS32/MIPS64**: Network equipment and embedded systems
- **PowerPC32/PowerPC64**: Legacy gaming and industrial systems

### Output Analysis
Each instruction analysis provides:
- **VEX IR Representation**: Architecture-independent intermediate code
- **Operation Classification**: Memory, register, arithmetic, logical operations
- **Pattern Detection**: Malware-relevant behavior identification
- **Complexity Metrics**: Statement count, operation distribution

## 🚀 Advanced Usage

### Custom Pattern Detection
```python
def detect_custom_patterns(vex_ir):
    patterns = []
    
    # Detect specific malware families
    if 'Xor' in vex_ir and 'STORE' in vex_ir:
        patterns.append('ENCRYPTION_ROUTINE')
    
    # Detect API hashing
    if 'Add' in vex_ir and 'Shl' in vex_ir:
        patterns.append('HASH_COMPUTATION')
    
    return patterns
```

### Cross-Architecture Analysis
```python
def compare_malware_samples(samples):
    analyzer = MalwareAnalyzer()
    
    for sample in samples:
        analysis = analyzer.analyze_instruction_sequence(
            sample['bytes'], 
            sample['arch']
        )
        
        # Compare VEX IR patterns
        patterns = analysis['patterns']
        complexity = analysis['operations']
```

## 🎓 Training Exercises

### Exercise 1: Basic Architecture Comparison
1. Run `pyvex-architecture-comparison.py`
2. Observe how the same operation appears in different architectures
3. Identify common VEX IR patterns across platforms

### Exercise 2: Malware Pattern Detection
1. Use `pyvex-malware-analysis.py` to analyze XOR routines
2. Compare shellcode patterns across architectures
3. Identify crypto implementation differences

### Exercise 3: Interactive Analysis
1. Use `pyvex-instruction-decoder.py` in interactive mode
2. Decode various instruction sequences
3. Compare results across different architectures

### Exercise 4: Batch Processing
1. Create an input file with various instruction sequences
2. Process with batch mode
3. Analyze patterns in the JSON output

## 🔧 Troubleshooting

### Common Issues

**Import Error: No module named 'pyvex'**
```bash
pip install pyvex archinfo
```

**Build Error on Windows**
- Install Visual Studio Build Tools
- Use pre-compiled wheels: `pip install --only-binary=all pyvex`

**Memory Issues**
- Reduce batch size for large files
- Use 64-bit Python for large analyses

**Architecture Not Supported**
- Check `archinfo.py` for supported architectures
- Verify architecture name spelling

### Performance Tips
- Use specific architectures instead of auto-detection
- Limit VEX IR output for large instruction sequences
- Process files in smaller batches for better memory usage

## 📖 Further Reading

- [PyVEX Documentation](https://github.com/angr/pyvex)
- [VEX IR Specification](https://github.com/angr/vex)
- [AKRODLABS Assembly Architecture Guide](../Day1-Malware-Analysis-Training.md#assembly-architecture-crash-course)
- [Cross-Architecture Malware Analysis Techniques](../research/cross-arch-analysis.md)

## 🤝 Contributing

To contribute additional analysis patterns or architecture support:
1. Fork the AKRODLABS training repository
2. Add new detection patterns to the analyzer classes
3. Update documentation with examples
4. Submit pull request with test cases

---

*These tools are part of the AKRODLABS comprehensive malware analysis training program, designed to provide hands-on experience with modern reverse engineering techniques.*
