#!/usr/bin/env python3
"""
Interactive Credential Scanner - Standalone Version
User-friendly interface for desktop usage with guided setup
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Import the main scanner
try:
    from credential_scanner import CredentialScanner
    import pandas as pd
    import tqdm
except ImportError as e:
    print(f"Error: Required modules not found: {e}")
    print("Please ensure all dependencies are installed.")
    sys.exit(1)

class InteractiveScanner:
    """Interactive wrapper for the credential scanner"""
    
    def __init__(self):
        self.config = {
            "scanning": {
                "max_file_size_mb": 10,
                "supported_extensions": [
                    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
                    ".cs", ".php", ".rb", ".go", ".rs", ".swift", ".kt", ".scala",
                    ".sh", ".bash", ".yaml", ".yml", ".json", ".xml", ".properties",
                    ".ini", ".cfg", ".conf", ".env", ".sql", ".tf", ".dockerfile"
                ],
                "excluded_files": [
                    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"
                ],
                "excluded_directories": [
                    ".git", "node_modules", "__pycache__", "venv", "env", "build", "dist"
                ]
            },
            "detection": {
                "min_entropy": 4.5,
                "min_length_for_entropy_check": 20,
                "context_lines": 2
            },
            "whitelist": {
                "files": [],
                "patterns": ["test_.*", "example_.*", "mock_.*", "dummy_.*"],
                "file_patterns": [".*test.*", ".*spec.*", ".*example.*"],
                "line_hashes": []
            },
            "false_positive_reduction": {
                "test_indicators": ["test", "example", "dummy", "fake", "mock"],
                "confidence_reduction_factor": 0.5
            }
        }
    
    def print_banner(self):
        """Print welcome banner"""
        print("\n" + "="*60)
        print("🔍 CREDENTIAL SCANNER - Interactive Mode")
        print("="*60)
        print("Professional security scanning tool for developers")
        print("Detects hardcoded credentials in source code")
        print("Version 2.0.0 | Enhanced Edition")
        print("="*60 + "\n")
    
    def get_input(self, prompt, default=None, choices=None):
        """Get user input with validation"""
        while True:
            if default:
                user_input = input(f"{prompt} [{default}]: ").strip()
                if not user_input:
                    return default
            else:
                user_input = input(f"{prompt}: ").strip()
            
            if not user_input and not default:
                print("❌ This field is required. Please enter a value.")
                continue
            
            if choices and user_input.lower() not in [c.lower() for c in choices]:
                print(f"❌ Please choose from: {', '.join(choices)}")
                continue
            
            return user_input
    
    def get_yes_no(self, prompt, default="y"):
        """Get yes/no input"""
        result = self.get_input(f"{prompt} (y/n)", default.lower(), ["y", "n", "yes", "no"])
        return result.lower() in ["y", "yes"]
    
    def select_directory(self):
        """Select directory to scan"""
        print("📂 STEP 1: Select Directory to Scan")
        print("-" * 40)
        
        while True:
            current_dir = os.getcwd()
            print(f"Current directory: {current_dir}")
            
            directory = self.get_input("Enter path to scan", current_dir)
            directory = os.path.expanduser(directory)
            
            if not os.path.exists(directory):
                print(f"❌ Directory '{directory}' does not exist.")
                continue
            
            if not os.path.isdir(directory):
                print(f"❌ '{directory}' is not a directory.")
                continue
            
            # Show directory contents preview
            try:
                files = list(Path(directory).rglob("*"))[:10]
                print(f"\n📁 Directory preview (showing first 10 items):")
                for f in files:
                    if f.is_file():
                        print(f"  📄 {f.relative_to(Path(directory))}")
                    else:
                        print(f"  📁 {f.relative_to(Path(directory))}/")
                
                if len(files) == 10:
                    print("  ... and more")
                
                confirm = self.get_yes_no(f"\nScan directory '{directory}'?", "y")
                if confirm:
                    return directory
            
            except Exception as e:
                print(f"❌ Error reading directory: {e}")
    
    def select_output_format(self):
        """Select output format"""
        print("\n📊 STEP 2: Choose Output Format")
        print("-" * 40)
        
        formats = {
            "1": ("excel", "Excel Report (.xlsx) - Recommended for review"),
            "2": ("json", "JSON Data (.json) - For automation/CI-CD"),
            "3": ("html", "Interactive HTML (.html) - Web-based report"),
            "4": ("csv", "CSV Data (.csv) - For analysis/spreadsheets"),
            "5": ("all", "All Formats - Generate everything")
        }
        
        for key, (format_name, description) in formats.items():
            print(f"  {key}) {description}")
        
        while True:
            choice = self.get_input("\nSelect format (1-5)", "1")
            if choice in formats:
                selected_format, description = formats[choice]
                print(f"✅ Selected: {description}")
                return selected_format
            print("❌ Please enter a number between 1-5")
    
    def configure_advanced_options(self):
        """Configure advanced scanning options"""
        print("\n⚙️  STEP 3: Advanced Options")
        print("-" * 40)
        
        # File size limit
        size_limit = self.get_input("Maximum file size to scan (MB)", "10")
        try:
            self.config["scanning"]["max_file_size_mb"] = int(size_limit)
        except ValueError:
            print("❌ Invalid size, using default: 10MB")
        
        # Include test files
        include_test = self.get_yes_no("Include test/example files in scan?", "n")
        if not include_test:
            self.config["whitelist"]["patterns"].extend([
                "TEST_.*", "EXAMPLE_.*", "DEMO_.*", "SAMPLE_.*"
            ])
            self.config["whitelist"]["file_patterns"].extend([
                ".*demo.*", ".*sample.*", ".*template.*"
            ])
        
        # Progress bar
        show_progress = self.get_yes_no("Show progress bar during scan?", "y")
        
        # Console report
        console_report = self.get_yes_no("Display summary report in console?", "y")
        
        # Exit code behavior
        exit_on_high = self.get_yes_no("Exit with error code if high-severity findings?", "n")
        
        return show_progress, console_report, exit_on_high
    
    def select_output_location(self, base_name="credential_scan_results"):
        """Select output file location"""
        print("\n💾 STEP 4: Output Location")
        print("-" * 40)
        
        default_name = f"{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_name = self.get_input("Output file name (without extension)", default_name)
        
        # Suggest current directory or desktop
        suggested_dir = os.path.expanduser("~/Desktop") if os.path.exists(os.path.expanduser("~/Desktop")) else os.getcwd()
        
        output_dir = self.get_input("Output directory", suggested_dir)
        output_dir = os.path.expanduser(output_dir)
        
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, output_name)
        print(f"✅ Results will be saved to: {output_path}.*")
        
        return output_path
    
    def run_scan(self, target_dir, output_path, output_format, show_progress, console_report, exit_on_high):
        """Execute the credential scan"""
        print("\n🔍 STEP 5: Running Scan")
        print("-" * 40)
        
        # Save temporary config
        config_path = "temp_interactive_config.json"
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        try:
            print(f"🎯 Target: {target_dir}")
            print(f"📊 Format: {output_format}")
            print(f"💾 Output: {output_path}")
            print("\n⏳ Initializing scanner...")
            
            # Create scanner instance
            scanner = CredentialScanner(target_dir, output_path, config_path)
            
            # Run scan
            print("🔍 Scanning files...")
            scanner.scan_directory(show_progress=show_progress)
            
            if not scanner.findings:
                print("\n✅ SCAN COMPLETE - No credentials found!")
                print("🛡️  Your code appears to be secure.")
                return 0
            
            # Generate reports
            print(f"\n📊 Found {len(scanner.findings)} potential credentials")
            print("📝 Generating reports...")
            
            # Export results
            if output_format == "all":
                scanner.export_to_excel()
                scanner.export_to_json()
                scanner.export_to_csv()
                scanner.export_to_html()
                print("✅ All report formats generated")
            elif output_format == "excel":
                scanner.export_to_excel()
            elif output_format == "json":
                scanner.export_to_json()
            elif output_format == "csv":
                scanner.export_to_csv()
            elif output_format == "html":
                scanner.export_to_html()
            
            # Show summary
            if console_report:
                print("\n" + "="*60)
                print("📋 SCAN SUMMARY")
                print("="*60)
                print(scanner.generate_report())
            
            # Display key findings
            high_severity = [f for f in scanner.findings if f.severity == 'High']
            medium_severity = [f for f in scanner.findings if f.severity == 'Medium']
            low_severity = [f for f in scanner.findings if f.severity == 'Low']
            
            print(f"\n🚨 SEVERITY BREAKDOWN:")
            print(f"   🔴 High:   {len(high_severity)} (immediate attention required)")
            print(f"   🟡 Medium: {len(medium_severity)} (should be reviewed)")
            print(f"   🟢 Low:    {len(low_severity)} (possible false positives)")
            
            if high_severity:
                print(f"\n🚨 HIGH PRIORITY FINDINGS:")
                for i, finding in enumerate(high_severity[:5], 1):
                    print(f"   {i}. {finding.credential_type} in {finding.relative_path}:{finding.line_number}")
                if len(high_severity) > 5:
                    print(f"   ... and {len(high_severity) - 5} more")
            
            # Show recommended actions
            self.show_recommendations(scanner.findings)
            
            # Exit code handling
            if exit_on_high and high_severity:
                print(f"\n❌ Exiting with error code due to {len(high_severity)} high-severity findings")
                return 1
            
            return 0
        
        except Exception as e:
            print(f"\n❌ Scan failed: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        finally:
            # Clean up temp config
            if os.path.exists(config_path):
                os.remove(config_path)
    
    def show_recommendations(self, findings):
        """Show security recommendations"""
        print(f"\n💡 SECURITY RECOMMENDATIONS:")
        print("="*60)
        
        if any(f.severity == 'High' for f in findings):
            print("🚨 IMMEDIATE ACTIONS REQUIRED:")
            print("   1. Rotate all high-severity credentials immediately")
            print("   2. Remove credentials from code history if needed")
            print("   3. Update affected systems and services")
            print("   4. Implement environment variables for secrets")
        
        print("\n🛡️  PREVENTION MEASURES:")
        print("   • Use environment variables for all secrets")
        print("   • Implement a secrets management system")
        print("   • Add credential scanning to your CI/CD pipeline")
        print("   • Use pre-commit hooks to prevent credential commits")
        print("   • Regular security training for development team")
        
        print("\n📚 NEXT STEPS:")
        print("   • Review detailed reports for context")
        print("   • Update whitelist for confirmed false positives")
        print("   • Schedule regular security scans")
        print("   • Document remediation actions taken")
    
    def show_results_summary(self, output_path, output_format):
        """Show final results and how to access them"""
        print("\n" + "="*60)
        print("✅ SCAN COMPLETED SUCCESSFULLY!")
        print("="*60)
        
        print("\n📁 Generated Files:")
        
        extensions = {
            "excel": ".xlsx",
            "json": ".json", 
            "csv": ".csv",
            "html": ".html",
            "all": [".xlsx", ".json", ".csv", ".html"]
        }
        
        if output_format == "all":
            for ext in extensions["all"]:
                file_path = output_path + ext
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path) / 1024  # KB
                    print(f"   📄 {file_path} ({size:.1f} KB)")
        else:
            ext = extensions.get(output_format, ".xlsx")
            file_path = output_path + ext
            if os.path.exists(file_path):
                size = os.path.getsize(file_path) / 1024  # KB
                print(f"   📄 {file_path} ({size:.1f} KB)")
        
        print("\n🌐 To view reports:")
        if output_format in ["html", "all"]:
            html_file = output_path + ".html"
            if os.path.exists(html_file):
                print(f"   • Open {html_file} in your web browser for interactive report")
        
        if output_format in ["excel", "all"]:
            excel_file = output_path + ".xlsx"
            if os.path.exists(excel_file):
                print(f"   • Open {excel_file} in Excel/LibreOffice for detailed analysis")
        
        print("\n📋 For automation/CI-CD:")
        if output_format in ["json", "all"]:
            json_file = output_path + ".json"
            if os.path.exists(json_file):
                print(f"   • Use {json_file} for programmatic processing")
    
    def run(self):
        """Main interactive flow"""
        try:
            self.print_banner()
            
            # Step 1: Select directory
            target_dir = self.select_directory()
            
            # Step 2: Choose output format
            output_format = self.select_output_format()
            
            # Step 3: Advanced options
            show_progress, console_report, exit_on_high = self.configure_advanced_options()
            
            # Step 4: Output location
            output_path = self.select_output_location()
            
            # Step 5: Run scan
            exit_code = self.run_scan(target_dir, output_path, output_format, 
                                    show_progress, console_report, exit_on_high)
            
            # Show results
            self.show_results_summary(output_path, output_format)
            
            print("\n🎉 Thank you for using Credential Scanner!")
            print("Stay secure! 🔒")
            
            return exit_code
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Scan cancelled by user")
            return 130
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return 1

def main():
    """Entry point for interactive scanner"""
    scanner = InteractiveScanner()
    exit_code = scanner.run()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
