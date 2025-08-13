# Building Credential Scanner Executables

This guide provides comprehensive instructions for building standalone executables of the Credential Scanner for different platforms.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Build](#quick-build)
3. [Advanced Build Options](#advanced-build-options)
4. [Platform-Specific Instructions](#platform-specific-instructions)
5. [Docker Builds](#docker-builds)
6. [Troubleshooting](#troubleshooting)
7. [Distribution](#distribution)

## Prerequisites

### System Requirements
- Python 3.8 or higher
- 2GB+ available disk space for build process
- 4GB+ RAM recommended for large builds

### Required Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install build tools
pip install pyinstaller

# Optional: For advanced builds
pip install cx_Freeze auto-py-to-exe
```

### Verify Installation
```bash
# Check Python version
python3 --version

# Check PyInstaller
pyinstaller --version

# Test scanner functionality
python3 credential_scanner.py --help
```

## Quick Build

### Using build_simple.py (Recommended)
This is the easiest way to build executables for your current platform:

```bash
# Navigate to project directory
cd credential-scanner

# Run the build script
python3 build_simple.py
```

**Output:**
- `dist/credential_scanner` - Command line version
- `dist/credential_scanner_interactive` - Interactive GUI version

### Build Process Details
The `build_simple.py` script:
1. Checks for required dependencies
2. Cleans previous builds
3. Creates PyInstaller spec files
4. Builds both CLI and interactive versions
5. Reports file sizes and locations

## Advanced Build Options

### Using build_all_executables.py
For comprehensive builds with additional features:

```bash
python3 build_all_executables.py
```

**Features:**
- Multi-platform support detection
- Advanced packaging options
- Checksum generation
- Release package creation
- Build verification

### Manual PyInstaller Commands

#### Basic Build
```bash
# CLI version
pyinstaller --onefile \
    --name credential_scanner \
    --add-data "config.json:." \
    credential_scanner.py

# Interactive version
pyinstaller --onefile \
    --name credential_scanner_interactive \
    --add-data "config.json:." \
    credential_scanner_interactive.py
```

#### Advanced Build with Options
```bash
pyinstaller --onefile \
    --name credential_scanner \
    --add-data "config.json:." \
    --hidden-import pandas._libs.tslibs.timedeltas \
    --hidden-import openpyxl.xml.functions \
    --exclude-module matplotlib \
    --exclude-module PIL \
    --console \
    credential_scanner.py
```

#### Optimized Build (Smaller Size)
```bash
pyinstaller --onefile \
    --name credential_scanner \
    --add-data "config.json:." \
    --exclude-module tkinter \
    --exclude-module PyQt5 \
    --exclude-module matplotlib \
    --exclude-module scipy \
    --strip \
    --upx-dir /path/to/upx \
    credential_scanner.py
```

## Platform-Specific Instructions

### macOS

#### Apple Silicon (M1/M2/M3)
```bash
# Build native ARM64 executables
python3 build_simple.py

# Verify architecture
file dist/credential_scanner
# Should show: Mach-O 64-bit executable arm64
```

#### Intel Macs
```bash
# Build x86_64 executables
arch -x86_64 python3 build_simple.py

# Or set environment variable
export ARCHFLAGS="-arch x86_64"
python3 build_simple.py
```

#### Universal Binaries (Both Architectures)
```bash
# Build for both architectures
python3 build_all_executables.py --universal
```

#### Code Signing (Optional)
```bash
# Sign the executables
codesign --force --deep --sign "Developer ID Application: Your Name" dist/credential_scanner
codesign --force --deep --sign "Developer ID Application: Your Name" dist/credential_scanner_interactive

# Verify signature
codesign --verify --deep --strict dist/credential_scanner
```

### Windows

#### Prerequisites
```bash
# Install Visual C++ Build Tools if needed
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Install dependencies
pip install pywin32
```

#### Build Process
```bash
# Standard build
python build_simple.py

# Build with console hidden (for GUI version)
pyinstaller --onefile --noconsole \
    --name credential_scanner_gui \
    --add-data "config.json;." \
    credential_scanner_interactive.py
```

#### Creating MSI Installer
```bash
# Install cx_Freeze
pip install cx_Freeze

# Create installer
python setup.py bdist_msi
```

### Linux

#### Ubuntu/Debian
```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install python3-dev build-essential

# Build executables
python3 build_simple.py
```

#### CentOS/RHEL/Fedora
```bash
# Install dependencies
sudo yum install python3-devel gcc gcc-c++
# or for newer versions:
sudo dnf install python3-devel gcc gcc-c++

# Build executables
python3 build_simple.py
```

#### Alpine Linux
```bash
# Install dependencies
apk add python3-dev gcc musl-dev

# Build executables
python3 build_simple.py
```

#### Static Linking (Portable)
```bash
# Build statically linked executable
pyinstaller --onefile \
    --name credential_scanner_static \
    --add-data "config.json:." \
    --runtime-tmpdir . \
    credential_scanner.py
```

## Docker Builds

### Multi-Stage Docker Build
```dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /build
COPY requirements.txt .
RUN pip install -r requirements.txt pyinstaller

COPY . .
RUN python3 build_simple.py

# Runtime stage
FROM ubuntu:22.04
COPY --from=builder /build/dist/credential_scanner /usr/local/bin/
COPY --from=builder /build/dist/credential_scanner_interactive /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/credential_scanner"]
```

### Build Commands
```bash
# Build container
docker build -t credential-scanner-builder .

# Extract executables
docker run --rm -v $(pwd)/dist:/output credential-scanner-builder cp /usr/local/bin/credential_scanner* /output/
```

### Cross-Platform Docker Builds
```bash
# Build for multiple architectures
docker buildx create --name mybuilder --use
docker buildx build --platform linux/amd64,linux/arm64 -t credential-scanner:latest .
```

## Troubleshooting

### Common Issues

#### "ModuleNotFoundError" During Runtime
**Problem:** Missing hidden imports
```bash
# Solution: Add hidden imports
pyinstaller --onefile \
    --hidden-import pandas._libs.tslibs.timedeltas \
    --hidden-import openpyxl.xml.functions \
    --hidden-import tqdm.std \
    credential_scanner.py
```

#### Large Executable Size
**Problem:** Executable is too large (>100MB)
```bash
# Solution: Exclude unnecessary modules
pyinstaller --onefile \
    --exclude-module matplotlib \
    --exclude-module scipy \
    --exclude-module PIL \
    --exclude-module tkinter \
    credential_scanner.py
```

#### "Permission Denied" on Linux/macOS
**Problem:** Executable not marked as executable
```bash
# Solution: Set execute permissions
chmod +x dist/credential_scanner
chmod +x dist/credential_scanner_interactive
```

#### Import Errors with pandas/openpyxl
**Problem:** Missing data files or libraries
```bash
# Solution: Include data directories
pyinstaller --onefile \
    --add-data "$(python -c 'import pandas; print(pandas.__path__[0])')/io/formats/templates:pandas/io/formats/templates" \
    credential_scanner.py
```

### Advanced Troubleshooting

#### Debug Build
```bash
# Create debug build for troubleshooting
pyinstaller --onefile \
    --debug all \
    --log-level DEBUG \
    credential_scanner.py
```

#### Analyze Dependencies
```bash
# Check what modules are being included
pyinstaller --onefile --debug imports credential_scanner.py
```

#### Test Build
```bash
# Quick test of built executable
./dist/credential_scanner --help
./dist/credential_scanner_interactive --version
```

### Performance Optimization

#### Optimize for Speed
```bash
# Build with optimization flags
pyinstaller --onefile \
    --optimize 2 \
    --strip \
    credential_scanner.py
```

#### Optimize for Size
```bash
# Use UPX compression (if available)
pyinstaller --onefile \
    --upx-dir /usr/bin \
    --strip \
    credential_scanner.py
```

## Distribution

### Creating Release Packages

#### For macOS
```bash
# Create DMG file
hdiutil create -volname "Credential Scanner" \
    -srcfolder dist/ \
    -ov -format UDZO \
    credential-scanner-macos.dmg
```

#### For Windows
```bash
# Create ZIP archive
powershell Compress-Archive -Path dist\* -DestinationPath credential-scanner-windows.zip

# Or create installer with NSIS/Inno Setup
```

#### For Linux
```bash
# Create tarball
tar -czf credential-scanner-linux.tar.gz -C dist/ .

# Create DEB package (Ubuntu/Debian)
fpm -s dir -t deb -n credential-scanner -v 2.0.0 \
    --description "Professional credential scanner" \
    dist/credential_scanner=/usr/local/bin/credential_scanner \
    dist/credential_scanner_interactive=/usr/local/bin/credential_scanner_interactive
```

### Checksums and Verification
```bash
# Generate checksums
sha256sum dist/credential_scanner > dist/credential_scanner.sha256
md5sum dist/credential_scanner > dist/credential_scanner.md5

# For all files
find dist/ -type f -exec sha256sum {} \; > checksums.sha256
```

### Testing Distribution
```bash
# Test on clean system
docker run --rm -v $(pwd)/dist:/scanner ubuntu:22.04 /scanner/credential_scanner --help

# Test with sample data
./dist/credential_scanner /path/to/test/code
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Build Executables

on: [push, release]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    
    runs-on: ${{ matrix.os }}
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pyinstaller
    
    - name: Build executables
      run: python3 build_simple.py
    
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: credential-scanner-${{ matrix.os }}
        path: dist/
```

## Best Practices

1. **Version Control:** Tag builds with version numbers
2. **Testing:** Always test executables on target platforms
3. **Security:** Sign executables for distribution
4. **Documentation:** Include build date and version in executables
5. **Automation:** Use CI/CD for consistent builds
6. **Backup:** Keep build environments reproducible

## Support

For build issues:
1. Check this troubleshooting guide
2. Verify all dependencies are installed
3. Test with a minimal example
4. Check PyInstaller documentation
5. Report issues with build environment details

---

**Last Updated:** January 2025  
**Build System Version:** 2.0.0
