#!/bin/bash
# AKRODLABS APK Analysis Script
# Comprehensive Android malware analysis workflow

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if APK file is provided
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <apk_file>"
    exit 1
fi

APK_FILE=$1
APK_NAME=$(basename "$APK_FILE" .apk)
ANALYSIS_DIR="analysis_${APK_NAME}_$(date +%Y%m%d_%H%M%S)"

# Check if APK file exists
if [ ! -f "$APK_FILE" ]; then
    print_error "APK file not found: $APK_FILE"
    exit 1
fi

# Create analysis directory
mkdir -p "$ANALYSIS_DIR"
cd "$ANALYSIS_DIR"

print_status "Starting APK analysis for: $APK_FILE"
print_status "Analysis directory: $ANALYSIS_DIR"

# Phase 1: Basic Information
print_status "Phase 1: Basic APK Information"
echo "APK Analysis Report" > report.txt
echo "===================" >> report.txt
echo "File: $APK_FILE" >> report.txt
echo "Analysis Date: $(date)" >> report.txt
echo "" >> report.txt

# File information
print_status "Gathering file information..."
file "$APK_FILE" >> report.txt
echo "" >> report.txt

# APK structure
print_status "Analyzing APK structure..."
echo "APK Contents:" >> report.txt
unzip -l "$APK_FILE" >> report.txt
echo "" >> report.txt

# Phase 2: Manifest Analysis
print_status "Phase 2: Manifest Analysis"
print_status "Extracting and analyzing AndroidManifest.xml..."

# Extract manifest using aapt
if command -v aapt >/dev/null 2>&1; then
    echo "Manifest Analysis (aapt):" >> report.txt
    aapt dump badging "$APK_FILE" >> report.txt 2>&1
    echo "" >> report.txt
    
    echo "Permissions:" >> report.txt
    aapt dump permissions "$APK_FILE" >> report.txt 2>&1
    echo "" >> report.txt
else
    print_warning "aapt not found, skipping manifest analysis"
fi

# Phase 3: APKTool Decompilation
print_status "Phase 3: APKTool Decompilation"
if command -v apktool >/dev/null 2>&1; then
    print_status "Decompiling APK with apktool..."
    apktool d "$APK_FILE" -o apktool_output
    
    if [ -d "apktool_output" ]; then
        print_success "APKTool decompilation successful"
        
        # Analyze manifest
        if [ -f "apktool_output/AndroidManifest.xml" ]; then
            echo "Detailed Manifest Analysis:" >> report.txt
            cat apktool_output/AndroidManifest.xml >> report.txt
            echo "" >> report.txt
        fi
        
        # Search for suspicious patterns
        print_status "Searching for suspicious patterns..."
        echo "Suspicious Patterns Found:" >> report.txt
        
        # Search for URLs
        grep -r "http" apktool_output/ 2>/dev/null | head -20 >> report.txt
        
        # Search for suspicious permissions
        grep -i "SMS\|CALL\|LOCATION\|CAMERA\|MICROPHONE" apktool_output/AndroidManifest.xml >> report.txt
        
        # Search for suspicious services
        grep -i "service\|receiver\|provider" apktool_output/AndroidManifest.xml >> report.txt
        echo "" >> report.txt
    else
        print_error "APKTool decompilation failed"
    fi
else
    print_warning "apktool not found, skipping decompilation"
fi

# Phase 4: JADX Decompilation
print_status "Phase 4: JADX Decompilation"
if command -v jadx >/dev/null 2>&1; then
    print_status "Decompiling APK with JADX..."
    jadx -d jadx_output "$APK_FILE"
    
    if [ -d "jadx_output" ]; then
        print_success "JADX decompilation successful"
        
        # Search for malicious patterns in Java code
        print_status "Analyzing Java code for malicious patterns..."
        echo "Java Code Analysis:" >> report.txt
        
        # Search for reflection usage
        grep -r "Class.forName\|getClass\|getDeclaredMethod" jadx_output/ 2>/dev/null | head -10 >> report.txt
        
        # Search for network operations
        grep -r "HttpURLConnection\|HttpClient\|Socket" jadx_output/ 2>/dev/null | head -10 >> report.txt
        
        # Search for file operations
        grep -r "FileOutputStream\|FileInputStream" jadx_output/ 2>/dev/null | head -10 >> report.txt
        
        # Search for encryption
        grep -r "encrypt\|decrypt\|AES\|DES" jadx_output/ 2>/dev/null | head -10 >> report.txt
        echo "" >> report.txt
    else
        print_error "JADX decompilation failed"
    fi
else
    print_warning "jadx not found, skipping JADX analysis"
fi

# Phase 5: DEX Analysis
print_status "Phase 5: DEX Analysis"
# Extract classes.dex
unzip "$APK_FILE" classes.dex 2>/dev/null

if [ -f "classes.dex" ]; then
    print_status "Analyzing DEX file..."
    
    # Use dexdump if available
    if command -v dexdump >/dev/null 2>&1; then
        echo "DEX Structure Analysis:" >> report.txt
        dexdump -f classes.dex >> report.txt 2>&1
        echo "" >> report.txt
    fi
    
    # Extract strings from DEX
    strings classes.dex > dex_strings.txt
    echo "Interesting strings from DEX:" >> report.txt
    grep -E "(http|ftp|smtp|pop|imap)" dex_strings.txt | head -20 >> report.txt
    grep -E "(password|token|key|secret)" dex_strings.txt | head -20 >> report.txt
    echo "" >> report.txt
else
    print_warning "Could not extract classes.dex"
fi

# Phase 6: Certificate Analysis
print_status "Phase 6: Certificate Analysis"
# Extract META-INF for certificate analysis
unzip "$APK_FILE" -d cert_analysis META-INF/* 2>/dev/null

if [ -d "cert_analysis/META-INF" ]; then
    print_status "Analyzing certificates..."
    echo "Certificate Analysis:" >> report.txt
    
    # Find certificate files
    find cert_analysis/META-INF -name "*.RSA" -o -name "*.DSA" -o -name "*.EC" | while read cert_file; do
        echo "Certificate: $cert_file" >> report.txt
        if command -v openssl >/dev/null 2>&1; then
            openssl pkcs7 -inform DER -in "$cert_file" -noout -print_certs -text >> report.txt 2>&1
        fi
        echo "" >> report.txt
    done
fi

# Phase 7: Generate Summary
print_status "Phase 7: Generating Summary"
echo "Analysis Summary:" >> report.txt
echo "=================" >> report.txt

# Count suspicious indicators
SUSPICIOUS_COUNT=0

# Check for dangerous permissions
if grep -q "SEND_SMS\|RECEIVE_SMS\|READ_SMS" report.txt; then
    echo "⚠️  SMS permissions detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

if grep -q "ACCESS_FINE_LOCATION\|ACCESS_COARSE_LOCATION" report.txt; then
    echo "⚠️  Location permissions detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

if grep -q "RECORD_AUDIO\|CAMERA" report.txt; then
    echo "⚠️  Audio/Camera permissions detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

if grep -q "DEVICE_ADMIN\|SYSTEM_ALERT_WINDOW" report.txt; then
    echo "🚨 Administrative permissions detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

# Check for suspicious code patterns
if grep -q "encrypt\|decrypt" report.txt; then
    echo "⚠️  Encryption code detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

if grep -q "reflection" report.txt; then
    echo "⚠️  Reflection usage detected" >> report.txt
    ((SUSPICIOUS_COUNT++))
fi

echo "" >> report.txt
echo "Total suspicious indicators: $SUSPICIOUS_COUNT" >> report.txt

if [ $SUSPICIOUS_COUNT -gt 3 ]; then
    echo "🚨 HIGH RISK: Multiple suspicious indicators found" >> report.txt
    print_error "HIGH RISK APK detected!"
elif [ $SUSPICIOUS_COUNT -gt 1 ]; then
    echo "⚠️  MEDIUM RISK: Some suspicious indicators found" >> report.txt
    print_warning "MEDIUM RISK APK detected"
else
    echo "✅ LOW RISK: Few suspicious indicators found" >> report.txt
    print_success "LOW RISK APK"
fi

# Clean up
rm -f classes.dex
rm -rf cert_analysis

print_success "Analysis complete! Report saved to: $ANALYSIS_DIR/report.txt"
print_status "Decompiled code available in: $ANALYSIS_DIR/jadx_output"
print_status "APKTool output available in: $ANALYSIS_DIR/apktool_output"

# Display summary
echo ""
echo "=== ANALYSIS SUMMARY ==="
tail -n 10 report.txt
