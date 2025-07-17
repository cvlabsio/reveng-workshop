#!/bin/bash
# AKRODLABS IPA Analysis Script
# Comprehensive iOS malware analysis workflow

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

# Check if IPA file is provided
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <ipa_file>"
    exit 1
fi

IPA_FILE=$1
IPA_NAME=$(basename "$IPA_FILE" .ipa)
ANALYSIS_DIR="analysis_${IPA_NAME}_$(date +%Y%m%d_%H%M%S)"

# Check if IPA file exists
if [ ! -f "$IPA_FILE" ]; then
    print_error "IPA file not found: $IPA_FILE"
    exit 1
fi

# Create analysis directory
mkdir -p "$ANALYSIS_DIR"
cd "$ANALYSIS_DIR"

print_status "Starting IPA analysis for: $IPA_FILE"
print_status "Analysis directory: $ANALYSIS_DIR"

# Phase 1: Extract IPA
print_status "Phase 1: Extracting IPA contents"
echo "IPA Analysis Report" > report.txt
echo "===================" >> report.txt
echo "File: $IPA_FILE" >> report.txt
echo "Analysis Date: $(date)" >> report.txt
echo "" >> report.txt

# Extract IPA
unzip -q "$IPA_FILE" -d ipa_contents
if [ $? -eq 0 ]; then
    print_success "IPA extraction successful"
else
    print_error "Failed to extract IPA"
    exit 1
fi

# Find the app bundle
APP_BUNDLE=$(find ipa_contents/Payload -name "*.app" -type d | head -1)
if [ -z "$APP_BUNDLE" ]; then
    print_error "Could not find app bundle in IPA"
    exit 1
fi

APP_NAME=$(basename "$APP_BUNDLE" .app)
EXECUTABLE_PATH="$APP_BUNDLE/$APP_NAME"

print_status "Found app bundle: $APP_BUNDLE"
print_status "Main executable: $EXECUTABLE_PATH"

# Phase 2: Basic File Analysis
print_status "Phase 2: Basic File Analysis"
echo "File Information:" >> report.txt
file "$EXECUTABLE_PATH" >> report.txt 2>&1
echo "" >> report.txt

# Check if Mach-O binary exists
if [ ! -f "$EXECUTABLE_PATH" ]; then
    print_error "Main executable not found: $EXECUTABLE_PATH"
    exit 1
fi

# Phase 3: Info.plist Analysis
print_status "Phase 3: Info.plist Analysis"
INFO_PLIST="$APP_BUNDLE/Info.plist"

if [ -f "$INFO_PLIST" ]; then
    print_status "Analyzing Info.plist..."
    echo "Info.plist Analysis:" >> report.txt
    
    if command -v plutil >/dev/null 2>&1; then
        plutil -p "$INFO_PLIST" >> report.txt 2>&1
    else
        cat "$INFO_PLIST" >> report.txt
    fi
    echo "" >> report.txt
    
    # Extract key information
    if command -v plutil >/dev/null 2>&1; then
        BUNDLE_ID=$(plutil -extract CFBundleIdentifier raw "$INFO_PLIST" 2>/dev/null)
        VERSION=$(plutil -extract CFBundleVersion raw "$INFO_PLIST" 2>/dev/null)
        DISPLAY_NAME=$(plutil -extract CFBundleDisplayName raw "$INFO_PLIST" 2>/dev/null)
        
        echo "Key App Information:" >> report.txt
        echo "Bundle ID: $BUNDLE_ID" >> report.txt
        echo "Version: $VERSION" >> report.txt
        echo "Display Name: $DISPLAY_NAME" >> report.txt
        echo "" >> report.txt
    fi
else
    print_warning "Info.plist not found"
fi

# Phase 4: Provisioning Profile Analysis
print_status "Phase 4: Provisioning Profile Analysis"
PROVISION_PROFILE="$APP_BUNDLE/embedded.mobileprovision"

if [ -f "$PROVISION_PROFILE" ]; then
    print_status "Analyzing provisioning profile..."
    echo "Provisioning Profile Analysis:" >> report.txt
    
    if command -v security >/dev/null 2>&1; then
        security cms -D -i "$PROVISION_PROFILE" >> report.txt 2>&1
    else
        print_warning "security command not available for provisioning profile analysis"
    fi
    echo "" >> report.txt
else
    print_warning "Provisioning profile not found"
fi

# Phase 5: Mach-O Binary Analysis
print_status "Phase 5: Mach-O Binary Analysis"
echo "Mach-O Binary Analysis:" >> report.txt

# Basic header analysis
if command -v otool >/dev/null 2>&1; then
    print_status "Analyzing Mach-O header..."
    echo "Mach-O Header:" >> report.txt
    otool -h "$EXECUTABLE_PATH" >> report.txt 2>&1
    echo "" >> report.txt
    
    # Architecture analysis
    echo "Architecture Information:" >> report.txt
    if command -v lipo >/dev/null 2>&1; then
        lipo -detailed_info "$EXECUTABLE_PATH" >> report.txt 2>&1
    fi
    echo "" >> report.txt
    
    # Load commands analysis
    echo "Load Commands:" >> report.txt
    otool -l "$EXECUTABLE_PATH" | head -50 >> report.txt
    echo "" >> report.txt
    
    # Dynamic libraries
    echo "Dynamic Libraries:" >> report.txt
    otool -L "$EXECUTABLE_PATH" >> report.txt 2>&1
    echo "" >> report.txt
    
    # Check for suspicious libraries
    echo "Suspicious Library Analysis:" >> report.txt
    otool -L "$EXECUTABLE_PATH" | grep -v "/System/" | grep -v "/usr/lib/" >> report.txt
    echo "" >> report.txt
else
    print_warning "otool not available for Mach-O analysis"
fi

# Phase 6: Symbol Analysis
print_status "Phase 6: Symbol Analysis"
if command -v nm >/dev/null 2>&1; then
    print_status "Analyzing symbols..."
    echo "Symbol Analysis:" >> report.txt
    
    # Look for interesting symbols
    nm -a "$EXECUTABLE_PATH" 2>/dev/null | grep -i "crypt\|encrypt\|decrypt\|password\|token" >> report.txt
    nm -a "$EXECUTABLE_PATH" 2>/dev/null | grep -i "network\|http\|url\|socket" >> report.txt
    nm -a "$EXECUTABLE_PATH" 2>/dev/null | grep -i "location\|gps\|coordinate" >> report.txt
    nm -a "$EXECUTABLE_PATH" 2>/dev/null | grep -i "keychain\|secure\|auth" >> report.txt
    echo "" >> report.txt
fi

# Phase 7: String Analysis
print_status "Phase 7: String Analysis"
print_status "Extracting strings from binary..."
echo "String Analysis:" >> report.txt

strings "$EXECUTABLE_PATH" > all_strings.txt

# Analyze interesting strings
echo "URLs and Network Indicators:" >> report.txt
grep -E "(https?|ftp)://[^\s]+" all_strings.txt | head -20 >> report.txt
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" all_strings.txt | head -10 >> report.txt
echo "" >> report.txt

echo "Suspicious Strings:" >> report.txt
grep -i "password\|token\|secret\|key\|credential" all_strings.txt | head -20 >> report.txt
echo "" >> report.txt

echo "File Paths:" >> report.txt
grep "/" all_strings.txt | grep -E "\.(plist|db|sqlite|log|txt)" | head -20 >> report.txt
echo "" >> report.txt

# Phase 8: Objective-C Class Analysis
print_status "Phase 8: Objective-C Class Analysis"
if command -v class-dump >/dev/null 2>&1; then
    print_status "Extracting Objective-C class information..."
    mkdir -p class_headers
    class-dump -H "$EXECUTABLE_PATH" -o class_headers/ 2>/dev/null
    
    if [ -d "class_headers" ] && [ "$(ls -A class_headers)" ]; then
        print_success "Class-dump successful"
        echo "Objective-C Classes Found:" >> report.txt
        ls class_headers/ | head -20 >> report.txt
        echo "" >> report.txt
        
        # Search for privacy-sensitive classes
        echo "Privacy-Sensitive Classes:" >> report.txt
        grep -r "location\|contact\|photo\|camera\|microphone" class_headers/ | head -10 >> report.txt
        grep -r "keychain\|password\|encrypt" class_headers/ | head -10 >> report.txt
        echo "" >> report.txt
    else
        print_warning "No Objective-C classes found or class-dump failed"
    fi
else
    print_warning "class-dump not available"
fi

# Phase 9: Code Signature Analysis
print_status "Phase 9: Code Signature Analysis"
if command -v codesign >/dev/null 2>&1; then
    print_status "Analyzing code signature..."
    echo "Code Signature Analysis:" >> report.txt
    
    codesign -dv "$APP_BUNDLE" >> report.txt 2>&1
    echo "" >> report.txt
    
    # Check signature validity
    echo "Signature Verification:" >> report.txt
    codesign -v "$APP_BUNDLE" >> report.txt 2>&1
    echo "" >> report.txt
    
    # Extract entitlements
    echo "Entitlements:" >> report.txt
    codesign -d --entitlements - "$APP_BUNDLE" >> report.txt 2>&1
    echo "" >> report.txt
fi

# Phase 10: Generate Risk Assessment
print_status "Phase 10: Generating Risk Assessment"
echo "Risk Assessment:" >> report.txt
echo "================" >> report.txt

RISK_SCORE=0

# Check for suspicious permissions/entitlements
if grep -q "location" report.txt; then
    echo "⚠️  Location access detected" >> report.txt
    ((RISK_SCORE++))
fi

if grep -q "contacts\|addressbook" report.txt; then
    echo "⚠️  Contacts access detected" >> report.txt
    ((RISK_SCORE++))
fi

if grep -q "camera\|photo" report.txt; then
    echo "⚠️  Camera/Photo access detected" >> report.txt
    ((RISK_SCORE++))
fi

if grep -q "microphone\|audio" report.txt; then
    echo "⚠️  Microphone access detected" >> report.txt
    ((RISK_SCORE++))
fi

if grep -q "keychain" report.txt; then
    echo "⚠️  Keychain access detected" >> report.txt
    ((RISK_SCORE++))
fi

# Check for suspicious libraries
if otool -L "$EXECUTABLE_PATH" 2>/dev/null | grep -q "/private/"; then
    echo "🚨 Private framework usage detected" >> report.txt
    ((RISK_SCORE+=2))
fi

# Check for enterprise distribution
if grep -q "enterprise" report.txt; then
    echo "🚨 Enterprise distribution detected" >> report.txt
    ((RISK_SCORE+=2))
fi

echo "" >> report.txt
echo "Total risk score: $RISK_SCORE" >> report.txt

if [ $RISK_SCORE -gt 5 ]; then
    echo "🚨 HIGH RISK: Multiple privacy/security concerns" >> report.txt
    print_error "HIGH RISK IPA detected!"
elif [ $RISK_SCORE -gt 2 ]; then
    echo "⚠️  MEDIUM RISK: Some privacy concerns" >> report.txt
    print_warning "MEDIUM RISK IPA detected"
else
    echo "✅ LOW RISK: Minimal privacy concerns" >> report.txt
    print_success "LOW RISK IPA"
fi

# Clean up
rm -f all_strings.txt

print_success "Analysis complete! Report saved to: $ANALYSIS_DIR/report.txt"
if [ -d "class_headers" ]; then
    print_status "Objective-C headers available in: $ANALYSIS_DIR/class_headers"
fi
print_status "Extracted IPA contents available in: $ANALYSIS_DIR/ipa_contents"

# Display summary
echo ""
echo "=== ANALYSIS SUMMARY ==="
tail -n 10 report.txt
