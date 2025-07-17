#!/usr/bin/env python3
"""
AKRODLABS AI Analysis Orchestrator
Comprehensive AI-assisted malware analysis workflow

This script demonstrates the integration of multiple AI tools for 
automated malware analysis, including Gepetto and Blackfyre.
"""

import os
import json
import hashlib
from typing import Dict, List, Optional
from pathlib import Path
import argparse

try:
    from blackfyre import BinaryContext
    BLACKFYRE_AVAILABLE = True
except ImportError:
    BLACKFYRE_AVAILABLE = False
    print("Warning: Blackfyre not available. Install with: pip install blackfyre")

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: OpenAI not available. Install with: pip install openai")

class AIAnalysisOrchestrator:
    """
    Orchestrates AI-powered malware analysis using multiple tools and models
    """
    
    def __init__(self, config_file: str = None):
        self.config = self.load_config(config_file)
        self.results = {}
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration for AI tools"""
        default_config = {
            'openai': {
                'api_key': os.getenv('OPENAI_API_KEY'),
                'model': 'gpt-4o-mini',
                'max_tokens': 2048
            },
            'analysis': {
                'include_function_analysis': True,
                'include_string_analysis': True,
                'include_ml_classification': True,
                'generate_yara_rules': True
            },
            'output': {
                'save_intermediate': True,
                'output_dir': './ai_analysis_results',
                'format': 'json'
            }
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def analyze_binary_with_blackfyre(self, bcc_file: str) -> Dict:
        """
        Analyze binary using Blackfyre ML platform
        """
        if not BLACKFYRE_AVAILABLE:
            return {"error": "Blackfyre not available"}
        
        try:
            bc = BinaryContext(bcc_file)
            
            analysis_result = {
                'binary_info': {
                    'filename': bc.filename,
                    'architecture': bc.architecture,
                    'function_count': len(bc.get_functions()),
                    'string_count': len(bc.get_strings()),
                    'import_count': len(bc.get_imports())
                },
                'ml_features': self.extract_ml_features(bc),
                'function_analysis': self.analyze_functions(bc),
                'behavioral_indicators': self.extract_behavioral_indicators(bc)
            }
            
            return analysis_result
            
        except Exception as e:
            return {"error": f"Blackfyre analysis failed: {str(e)}"}
    
    def extract_ml_features(self, bc) -> Dict:
        """Extract machine learning features from binary"""
        features = {}
        
        try:
            functions = bc.get_functions()
            
            # Statistical features
            features['function_stats'] = {
                'count': len(functions),
                'avg_size': sum(f.size for f in functions) / len(functions) if functions else 0,
                'max_size': max(f.size for f in functions) if functions else 0,
                'min_size': min(f.size for f in functions) if functions else 0
            }
            
            # String analysis features
            strings = bc.get_strings()
            features['string_stats'] = {
                'count': len(strings),
                'avg_length': sum(len(s) for s in strings) / len(strings) if strings else 0,
                'suspicious_count': self.count_suspicious_strings(strings)
            }
            
            # Import analysis features
            imports = bc.get_imports()
            features['import_stats'] = {
                'count': len(imports),
                'unique_dlls': len(set(imp.dll for imp in imports if hasattr(imp, 'dll'))),
                'suspicious_apis': self.count_suspicious_apis(imports)
            }
            
        except Exception as e:
            features['error'] = f"Feature extraction failed: {str(e)}"
        
        return features
    
    def analyze_functions(self, bc) -> List[Dict]:
        """Analyze individual functions for behavioral patterns"""
        function_analysis = []
        
        try:
            for func in bc.get_functions()[:10]:  # Limit to first 10 for demo
                analysis = {
                    'name': func.name,
                    'size': func.size,
                    'basic_block_count': len(func.basic_blocks) if hasattr(func, 'basic_blocks') else 0,
                    'complexity_score': self.calculate_complexity_score(func),
                    'suspicious_indicators': self.identify_suspicious_patterns(func)
                }
                function_analysis.append(analysis)
                
        except Exception as e:
            function_analysis.append({"error": f"Function analysis failed: {str(e)}"})
        
        return function_analysis
    
    def extract_behavioral_indicators(self, bc) -> Dict:
        """Extract behavioral indicators from binary"""
        indicators = {
            'file_operations': False,
            'network_operations': False,
            'registry_operations': False,
            'process_operations': False,
            'crypto_operations': False
        }
        
        try:
            imports = bc.get_imports()
            import_names = [imp.name for imp in imports if hasattr(imp, 'name')]
            
            # Check for various operation types
            file_ops = ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile']
            network_ops = ['WSAStartup', 'connect', 'send', 'recv', 'InternetOpen']
            registry_ops = ['RegOpenKey', 'RegSetValue', 'RegQueryValue']
            process_ops = ['CreateProcess', 'OpenProcess', 'WriteProcessMemory']
            crypto_ops = ['CryptAcquireContext', 'CryptCreateHash', 'CryptEncrypt']
            
            indicators['file_operations'] = any(op in import_names for op in file_ops)
            indicators['network_operations'] = any(op in import_names for op in network_ops)
            indicators['registry_operations'] = any(op in import_names for op in registry_ops)
            indicators['process_operations'] = any(op in import_names for op in process_ops)
            indicators['crypto_operations'] = any(op in import_names for op in crypto_ops)
            
        except Exception as e:
            indicators['error'] = f"Behavioral analysis failed: {str(e)}"
        
        return indicators
    
    def count_suspicious_strings(self, strings: List) -> int:
        """Count potentially suspicious strings"""
        suspicious_patterns = [
            'cmd.exe', 'powershell', 'rundll32', 'regsvr32',
            'http://', 'https://', 'ftp://',
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_', 'CreateProcess', 'WriteProcessMemory'
        ]
        
        count = 0
        for string in strings:
            if any(pattern.lower() in str(string).lower() for pattern in suspicious_patterns):
                count += 1
        
        return count
    
    def count_suspicious_apis(self, imports: List) -> int:
        """Count potentially suspicious API calls"""
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'SetWindowsHookEx', 'FindWindow',
            'GetProcAddress', 'LoadLibrary', 'CreateProcess'
        ]
        
        count = 0
        for imp in imports:
            if hasattr(imp, 'name') and imp.name in suspicious_apis:
                count += 1
        
        return count
    
    def calculate_complexity_score(self, func) -> float:
        """Calculate complexity score for a function"""
        # Simple complexity scoring based on available attributes
        score = 0.0
        
        if hasattr(func, 'size'):
            score += min(func.size / 100, 5.0)  # Size component (max 5 points)
        
        if hasattr(func, 'basic_blocks'):
            score += min(len(func.basic_blocks) / 10, 3.0)  # Complexity component (max 3 points)
        
        return round(score, 2)
    
    def identify_suspicious_patterns(self, func) -> List[str]:
        """Identify suspicious patterns in function"""
        patterns = []
        
        # This would be enhanced with actual pattern detection
        if hasattr(func, 'size') and func.size > 1000:
            patterns.append('large_function')
        
        if hasattr(func, 'name') and any(keyword in func.name.lower() for keyword in ['crypt', 'encode', 'decode', 'xor']):
            patterns.append('crypto_related')
        
        return patterns
    
    def generate_llm_analysis(self, analysis_data: Dict) -> Dict:
        """Generate LLM-powered analysis summary"""
        if not OPENAI_AVAILABLE or not self.config['openai']['api_key']:
            return {"error": "OpenAI not configured"}
        
        try:
            openai.api_key = self.config['openai']['api_key']
            
            prompt = self.create_analysis_prompt(analysis_data)
            
            response = openai.ChatCompletion.create(
                model=self.config['openai']['model'],
                messages=[
                    {"role": "system", "content": "You are an expert malware analyst. Provide concise, technical analysis."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.config['openai']['max_tokens'],
                temperature=0.1
            )
            
            return {
                'llm_summary': response.choices[0].message.content,
                'model_used': self.config['openai']['model'],
                'tokens_used': response.usage.total_tokens
            }
            
        except Exception as e:
            return {"error": f"LLM analysis failed: {str(e)}"}
    
    def create_analysis_prompt(self, analysis_data: Dict) -> str:
        """Create prompt for LLM analysis"""
        prompt = f"""
        Analyze this malware sample based on the following technical data:
        
        Binary Information:
        - Functions: {analysis_data.get('binary_info', {}).get('function_count', 'Unknown')}
        - Imports: {analysis_data.get('binary_info', {}).get('import_count', 'Unknown')}
        - Architecture: {analysis_data.get('binary_info', {}).get('architecture', 'Unknown')}
        
        Behavioral Indicators:
        {json.dumps(analysis_data.get('behavioral_indicators', {}), indent=2)}
        
        ML Features:
        {json.dumps(analysis_data.get('ml_features', {}), indent=2)}
        
        Provide:
        1. Threat assessment (High/Medium/Low)
        2. Likely malware family or type
        3. Key behavioral characteristics
        4. Recommended analysis steps
        5. Potential IOCs
        
        Keep response under 500 words and focus on actionable intelligence.
        """
        
        return prompt
    
    def generate_yara_rule(self, analysis_data: Dict) -> str:
        """Generate YARA rule based on analysis"""
        if not OPENAI_AVAILABLE or not self.config['openai']['api_key']:
            return "// YARA rule generation requires OpenAI configuration"
        
        try:
            prompt = f"""
            Generate a YARA rule for malware detection based on this analysis:
            
            {json.dumps(analysis_data, indent=2)}
            
            Include:
            - Appropriate rule name
            - Metadata section with description, author, date
            - String patterns (if available)
            - Condition logic
            - Comments explaining detection logic
            
            Make the rule specific enough to avoid false positives but general enough to catch variants.
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a YARA rule expert. Generate precise, well-commented rules."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"// YARA rule generation failed: {str(e)}"
    
    def save_results(self, results: Dict, output_file: str):
        """Save analysis results to file"""
        output_dir = Path(self.config['output']['output_dir'])
        output_dir.mkdir(exist_ok=True)
        
        output_path = output_dir / output_file
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"Results saved to: {output_path}")
    
    def run_comprehensive_analysis(self, sample_path: str) -> Dict:
        """Run comprehensive AI-assisted analysis"""
        print(f"Starting AI-assisted analysis of: {sample_path}")
        
        # Generate sample hash for tracking
        sample_hash = self.calculate_file_hash(sample_path)
        
        comprehensive_results = {
            'sample_info': {
                'path': sample_path,
                'hash': sample_hash,
                'analysis_timestamp': str(Path().cwd())
            }
        }
        
        # Step 1: Blackfyre analysis (if BCC file provided)
        if sample_path.endswith('.bcc') and BLACKFYRE_AVAILABLE:
            print("Running Blackfyre ML analysis...")
            blackfyre_results = self.analyze_binary_with_blackfyre(sample_path)
            comprehensive_results['blackfyre_analysis'] = blackfyre_results
            
            # Step 2: LLM analysis
            if self.config['analysis']['include_function_analysis']:
                print("Generating LLM analysis...")
                llm_results = self.generate_llm_analysis(blackfyre_results)
                comprehensive_results['llm_analysis'] = llm_results
            
            # Step 3: YARA rule generation
            if self.config['analysis']['generate_yara_rules']:
                print("Generating YARA rules...")
                yara_rule = self.generate_yara_rule(blackfyre_results)
                comprehensive_results['yara_rule'] = yara_rule
        
        else:
            comprehensive_results['error'] = "Requires .bcc file for Blackfyre analysis"
        
        # Save results
        if self.config['output']['save_intermediate']:
            output_filename = f"ai_analysis_{sample_hash[:8]}.json"
            self.save_results(comprehensive_results, output_filename)
        
        return comprehensive_results
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        if not os.path.exists(file_path):
            return "file_not_found"
        
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="AKRODLABS AI Analysis Orchestrator")
    parser.add_argument("sample", help="Path to sample file (.bcc for Blackfyre analysis)")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output directory for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = AIAnalysisOrchestrator(args.config)
    
    if args.output:
        orchestrator.config['output']['output_dir'] = args.output
    
    # Run analysis
    try:
        results = orchestrator.run_comprehensive_analysis(args.sample)
        
        if args.verbose:
            print(json.dumps(results, indent=2, default=str))
        else:
            print("Analysis completed successfully!")
            if 'llm_analysis' in results:
                print("\nLLM Summary:")
                print(results['llm_analysis'].get('llm_summary', 'No summary available'))
            
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
