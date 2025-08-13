# Credential Scanner

A comprehensive Python script to detect hardcoded credentials in source code and export findings to Excel.

## Features

- **Comprehensive Detection**: Scans for various types of credentials including:
  - AWS Access Keys and Secret Keys
  - GitHub Tokens
  - Google API Keys
  - Slack Tokens
  - JWT Tokens
  - Database Passwords
  - Private Keys and Certificates
  - Connection Strings
  - And many more...

- **In-depth Analysis**: 
  - Entropy analysis for detecting random strings
  - Context analysis to reduce false positives
  - Confidence scoring for each finding
  - Severity classification (High/Medium/Low)
  - File metadata tracking (size, permissions, modification time)

- **Comprehensive File Support**: Supports 40+ file extensions including Python, JavaScript, Java, C/C++, and configuration files

- **Multiple Output Formats**: 
  - **Excel**: Detailed reports with formatting and charts
  - **JSON**: Structured data for CI/CD integration
  - **CSV**: Simple tabular format for data analysis
  - **HTML**: Interactive reports with filtering and search

- **Advanced Configuration**:
  - Fully configurable via JSON config file
  - Custom credential patterns
  - Whitelist support for false positive management
  - Configurable file size limits and exclusions

- **Developer Experience**:
  - Progress bars for large scans
  - Verbose and quiet modes
  - Exit codes for CI/CD integration
  - Comprehensive logging

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

The scanner now requires these additional packages:
- `pandas` >= 1.3.0
- `openpyxl` >= 3.0.0  
- `tqdm` >= 4.60.0 (for progress bars)

## Building Standalone Executables

The credential scanner can be built into standalone executables that don't require Python to be installed on the target system.

### Quick Build (Recommended)
```bash
# Install build dependencies
pip install pyinstaller

# Build executables for current platform
python3 build_simple.py
```

This creates:
- `dist/credential_scanner` - Command line version
- `dist/credential_scanner_interactive` - Interactive version

### Advanced Multi-Platform Build
```bash
# Build with comprehensive options
python3 build_all_executables.py
```

### Manual Build
```bash
# Command line version
pyinstaller --onefile --name credential_scanner --add-data "config.json:." credential_scanner.py

# Interactive version  
pyinstaller --onefile --name credential_scanner_interactive --add-data "config.json:." credential_scanner_interactive.py
```

### Build Requirements
- Python 3.8+
- PyInstaller (`pip install pyinstaller`)
- All project dependencies installed (`pip install -r requirements.txt`)

### Platform-Specific Notes

**macOS:**
```bash
# For Apple Silicon (M1/M2)
python3 build_simple.py
# Creates ARM64 executables

# For Intel Macs
arch -x86_64 python3 build_simple.py
# Creates x64 executables
```

**Windows:**
```bash
# On Windows with Python installed
python build_simple.py
# Creates .exe files in dist/ folder
```

**Linux:**
```bash
# On Linux
python3 build_simple.py
# Creates Linux executables
```

### Docker Build
```bash
# Build in Docker container for consistent results
docker build -t credential-scanner .
docker run -v /path/to/scan:/scan credential-scanner /scan
```

**For detailed build instructions and troubleshooting, see [BUILD.md](BUILD.md)**

## Usage

### Basic Usage
```bash
python credential_scanner.py /path/to/source/code
```

### Advanced Usage
```bash
# Multiple output formats
python credential_scanner.py /path/to/source/code -f json -o security_report.json

# Export to all formats
python credential_scanner.py /path/to/source/code -f all -o security_audit_2024

# Custom configuration with whitelist
python credential_scanner.py /path/to/source/code -c custom_config.json

# CI/CD integration with exit codes
python credential_scanner.py /path/to/source/code -f json --exit-code

# Disable progress bar for automated scans
python credential_scanner.py /path/to/source/code --no-progress

# Full example with all options
python credential_scanner.py ./my_project -o security_audit_2024.xlsx -c config.json -f all -r --exit-code
```

### Command Line Options

- `directory`: Path to the directory to scan (required)
- `-o, --output`: Output file name (default: credential_findings.xlsx)
- `-c, --config`: Configuration file path (default: config.json)
- `-f, --format`: Output format: excel, json, csv, html, or all (default: excel)
- `-r, --report`: Print summary report to console
- `--exit-code`: Exit with non-zero code if high severity findings are found
- `--no-progress`: Disable progress bar display

## Output

The scanner now supports multiple output formats:

### Excel Format (.xlsx)
- **Summary Sheet**: Overview statistics and charts
- **Detailed Findings Sheet**: Complete findings with color-coding
- Includes file metadata (size, permissions, modification time)
- Sortable and filterable columns

### JSON Format (.json)
- Structured data perfect for CI/CD integration
- Includes scan metadata and timestamp
- Summary statistics and complete findings array
- Easy to parse programmatically

### CSV Format (.csv)
- Simple tabular format for data analysis
- Compatible with spreadsheet applications
- Single-line context for easy processing

### HTML Format (.html)
- Interactive web report with modern UI
- Real-time filtering by severity and type
- Search functionality across all findings
- Responsive design for mobile viewing
- Color-coded severity indicators

### Report Contents
All formats include:
- File path and line number
- Credential type and matched pattern
- Confidence score and severity level
- Code context around the finding
- File metadata (size, permissions, last modified)
- Scan timestamp and configuration details

## Configuration

The scanner is now fully configurable via `config.json`:

### Scanning Configuration
```json
{
  "scanning": {
    "max_file_size_mb": 10,
    "supported_extensions": [".py", ".js", ".ts", "..."],
    "excluded_files": ["package-lock.json", "..."],
    "excluded_directories": [".git", "node_modules", "..."]
  }
}
```

### Detection Settings
```json
{
  "detection": {
    "min_entropy": 4.5,
    "min_length_for_entropy_check": 20,
    "context_lines": 2
  }
}
```

### Custom Patterns
```json
{
  "custom_patterns": {
    "My Custom Token": [
      "CUSTOM_[A-Za-z0-9]{32}",
      "my_secret\\s*[:=]\\s*[\"'][A-Za-z0-9]{20,}[\"']"
    ]
  }
}
```

### Whitelist Configuration
```json
{
  "whitelist": {
    "files": ["test_file.py"],
    "patterns": ["test_key_.*", "example_secret"],
    "file_patterns": [".*test.*", ".*mock.*"],
    "line_hashes": ["sha256_hash_of_specific_line"]
  }
}
```

### False Positive Reduction
```json
{
  "false_positive_reduction": {
    "test_indicators": ["test", "example", "dummy", "fake"],
    "confidence_reduction_factor": 0.5
  }
}
```

## Credential Types Detected

- **AWS**: Access Keys, Secret Keys
- **GitHub**: Personal Access Tokens, OAuth tokens
- **Google**: API Keys
- **Slack**: Bot tokens, User tokens
- **JWT**: JSON Web Tokens
- **Database**: Password fields, Connection strings
- **Certificates**: Private keys, Public certificates
- **Payment**: Stripe keys, PayPal credentials
- **Email**: SendGrid, MailGun API keys
- **Cloud**: Azure credentials, Twilio keys
- **Generic**: API keys, Secret keys, Auth headers

## False Positive Reduction

The scanner includes several mechanisms to reduce false positives:
- Detection of test/example code patterns
- Entropy analysis for random strings
- Context analysis around findings
- Configurable confidence scoring

## Security Best Practices

After running the scan:

1. **Immediate Actions**:
   - Rotate any confirmed credentials found
   - Remove credentials from code history if needed
   - Update affected systems

2. **Prevention**:
   - Use environment variables for credentials
   - Implement proper secrets management
   - Add credential scanning to CI/CD pipelines
   - Use tools like git-secrets or pre-commit hooks

3. **Regular Monitoring**:
   - Run scans regularly during development
   - Monitor for new credential patterns
   - Keep the scanner patterns updated

## CI/CD Integration

The scanner now provides excellent CI/CD integration capabilities:

### GitHub Actions Example
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.8'
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run credential scan
      run: |
        python credential_scanner.py . -f json --exit-code --no-progress
    - name: Upload scan results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: credential_findings.json
```

### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'python credential_scanner.py . -f json --exit-code --no-progress'
                archiveArtifacts artifacts: 'credential_findings.json'
            }
        }
    }
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'credential_findings.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

### Exit Codes
- `0`: No high-severity findings (build can proceed)
- `1`: High-severity findings detected (build should fail)

## Limitations

- Some patterns may generate false positives (use whitelist to manage)
- Cannot detect heavily obfuscated or encoded credentials
- Limited to text-based files
- Large files are skipped based on configurable size limit
- Binary files are automatically excluded

## Contributing

To add new credential patterns:
1. Edit the `patterns` dictionary in `credential_scanner.py`
2. Or add custom patterns to `config.json`
3. Test with known samples to verify detection

## License

MIT License - Feel free to modify and distribute.