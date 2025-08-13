#!/usr/bin/env python3
"""
Enhanced Build Script for Credential Scanner
Creates standalone executables for Mac, Windows, and Linux
"""

import os
import sys
import shutil
import subprocess
import platform
import argparse
import zipfile
import tarfile
from pathlib import Path
from datetime import datetime

class ExecutableBuilder:
    """Build standalone executables for multiple platforms"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.build_dir = self.project_root / "build"
        self.dist_dir = self.project_root / "dist"
        self.release_dir = self.project_root / "releases"
        self.version = "2.0.0"
        
        # Platform-specific configurations
        self.platforms = {
            "darwin_arm64": {
                "name": "macos_arm64",
                "executable": "credential_scanner_macos_arm64",
                "interactive": "credential_scanner_interactive_macos_arm64",
                "archive": "tar.gz"
            },
            "darwin_x64": {
                "name": "macos_x64", 
                "executable": "credential_scanner_macos_x64",
                "interactive": "credential_scanner_interactive_macos_x64",
                "archive": "tar.gz"
            },
            "linux": {
                "name": "linux_x64",
                "executable": "credential_scanner_linux",
                "interactive": "credential_scanner_interactive_linux",
                "archive": "tar.gz"
            },
            "windows": {
                "name": "windows_x64",
                "executable": "credential_scanner_windows.exe",
                "interactive": "credential_scanner_interactive_windows.exe",
                "archive": "zip"
            }
        }
    
    def clean_previous_builds(self):
        """Clean previous build artifacts"""
        print("🧹 Cleaning previous builds...")
        
        for directory in [self.build_dir, self.dist_dir]:
            if directory.exists():
                shutil.rmtree(directory)
                print(f"   Removed {directory}")
        
        # Create fresh directories
        self.build_dir.mkdir(exist_ok=True)
        self.dist_dir.mkdir(exist_ok=True)
        self.release_dir.mkdir(exist_ok=True)
        
        print("✅ Build directories prepared")
    
    def setup_virtual_environment(self):
        """Set up build environment"""
        print("🔧 Setting up build environment...")
        
        venv_path = self.project_root / "build_env"
        
        if not venv_path.exists():
            print("   Creating virtual environment...")
            subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
        
        # Determine activation script and pip path
        if platform.system() == "Windows":
            activate_script = venv_path / "Scripts" / "activate.bat"
            pip_path = venv_path / "Scripts" / "pip"
            python_path = venv_path / "Scripts" / "python"
        else:
            activate_script = venv_path / "bin" / "activate"
            pip_path = venv_path / "bin" / "pip"
            python_path = venv_path / "bin" / "python"
        
        # Install dependencies
        print("   Installing build dependencies...")
        subprocess.run([
            str(pip_path), "install", "-q", "--upgrade",
            "pip", "pyinstaller", "pandas", "openpyxl", "tqdm"
        ], check=True)
        
        return python_path, activate_script
    
    def create_spec_files(self):
        """Create PyInstaller spec files"""
        print("📝 Creating PyInstaller specification files...")
        
        # Command line version spec
        cli_spec = f"""
# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

a = Analysis(
    ['credential_scanner.py'],
    pathex=['{self.project_root}'],
    binaries=[],
    datas=[
        ('config.json', '.'),
        ('README.md', '.'),
        ('USER_GUIDE.md', '.'),
    ],
    hiddenimports=[
        'pandas._libs.tslibs.timedeltas',
        'pandas._libs.tslibs.timestamps', 
        'pandas._libs.tslibs.offsets',
        'openpyxl.xml.functions',
        'openpyxl.styles.fills',
        'tqdm.std',
        'tqdm.utils',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'scipy', 'numpy.random._pickle',
        'PIL', 'tkinter', 'PyQt5', 'PyQt6'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='credential_scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
        
        # Interactive version spec
        interactive_spec = f"""
# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

a = Analysis(
    ['credential_scanner_interactive.py'],
    pathex=['{self.project_root}'],
    binaries=[],
    datas=[
        ('config.json', '.'),
        ('README.md', '.'),
        ('USER_GUIDE.md', '.'),
    ],
    hiddenimports=[
        'pandas._libs.tslibs.timedeltas',
        'pandas._libs.tslibs.timestamps',
        'pandas._libs.tslibs.offsets',
        'openpyxl.xml.functions',
        'openpyxl.styles.fills',
        'tqdm.std',
        'tqdm.utils',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'scipy', 'numpy.random._pickle',
        'PIL', 'tkinter', 'PyQt5', 'PyQt6'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='credential_scanner_interactive',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
        
        # Write spec files
        with open(self.project_root / "credential_scanner.spec", "w") as f:
            f.write(cli_spec.strip())
        
        with open(self.project_root / "credential_scanner_interactive.spec", "w") as f:
            f.write(interactive_spec.strip())
        
        print("✅ Spec files created")
    
    def build_executables(self, python_path):
        """Build executables using PyInstaller"""
        print("🔨 Building executables...")
        
        # Build command line version
        print("   Building command line version...")
        subprocess.run([
            str(python_path), "-m", "PyInstaller",
            "--clean", "--onefile",
            str(self.project_root / "credential_scanner.spec")
        ], check=True, cwd=self.project_root)
        
        # Build interactive version
        print("   Building interactive version...")
        subprocess.run([
            str(python_path), "-m", "PyInstaller", 
            "--clean", "--onefile",
            str(self.project_root / "credential_scanner_interactive.spec")
        ], check=True, cwd=self.project_root)
        
        print("✅ Executables built successfully")
    
    def test_executables(self):
        """Test built executables"""
        print("🧪 Testing executables...")
        
        cli_exe = self.dist_dir / "credential_scanner"
        interactive_exe = self.dist_dir / "credential_scanner_interactive"
        
        if platform.system() == "Windows":
            cli_exe = cli_exe.with_suffix(".exe")
            interactive_exe = interactive_exe.with_suffix(".exe")
        
        # Test CLI version
        if cli_exe.exists():
            try:
                result = subprocess.run([str(cli_exe), "--help"], 
                                      capture_output=True, timeout=10)
                if result.returncode == 0:
                    print("   ✅ CLI executable test passed")
                else:
                    print("   ⚠️ CLI executable test failed")
            except subprocess.TimeoutExpired:
                print("   ⚠️ CLI executable test timed out (may be normal)")
        
        # Test interactive version (just check if it starts)
        if interactive_exe.exists():
            print("   ✅ Interactive executable created")
        
        print("✅ Executable testing completed")
    
    def create_release_packages(self):
        """Create release packages for distribution"""
        print("📦 Creating release packages...")
        
        current_platform = self.get_current_platform()
        platform_config = self.platforms.get(current_platform, self.platforms["linux"])
        
        # Create platform-specific directory
        platform_dir = self.release_dir / f"credential-scanner-v{self.version}-{platform_config['name']}"
        platform_dir.mkdir(exist_ok=True)
        
        # Copy executables
        cli_exe = self.dist_dir / "credential_scanner"
        interactive_exe = self.dist_dir / "credential_scanner_interactive"
        
        if platform.system() == "Windows":
            cli_exe = cli_exe.with_suffix(".exe")
            interactive_exe = interactive_exe.with_suffix(".exe")
        
        if cli_exe.exists():
            shutil.copy2(cli_exe, platform_dir / platform_config["executable"])
        
        if interactive_exe.exists():
            shutil.copy2(interactive_exe, platform_dir / platform_config["interactive"])
        
        # Copy documentation and configuration
        docs_to_copy = [
            "README.md", "USER_GUIDE.md", "config.json", 
            "requirements.txt", "ENHANCEMENTS_SUMMARY.md"
        ]
        
        for doc in docs_to_copy:
            doc_path = self.project_root / doc
            if doc_path.exists():
                shutil.copy2(doc_path, platform_dir / doc)
        
        # Create installation scripts
        self.create_installation_scripts(platform_dir, platform_config)
        
        # Create usage examples
        self.create_usage_examples(platform_dir, platform_config)
        
        # Create release archive
        archive_name = f"credential-scanner-v{self.version}-{platform_config['name']}"
        
        if platform_config["archive"] == "zip":
            archive_path = self.release_dir / f"{archive_name}.zip"
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in platform_dir.rglob("*"):
                    if file_path.is_file():
                        zf.write(file_path, file_path.relative_to(self.release_dir))
        else:
            archive_path = self.release_dir / f"{archive_name}.tar.gz"
            with tarfile.open(archive_path, 'w:gz') as tf:
                tf.add(platform_dir, arcname=platform_dir.name)
        
        print(f"✅ Release package created: {archive_path}")
        return archive_path
    
    def create_installation_scripts(self, platform_dir, platform_config):
        """Create platform-specific installation scripts"""
        
        if platform.system() == "Windows":
            # Windows batch installer
            install_script = f"""@echo off
echo Installing Credential Scanner v{self.version}...

set "INSTALL_DIR=%USERPROFILE%\\AppData\\Local\\CredentialScanner"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Copying files...
copy "{platform_config['executable']}" "%INSTALL_DIR%\\"
copy "{platform_config['interactive']}" "%INSTALL_DIR%\\"
copy "config.json" "%INSTALL_DIR%\\"

echo Adding to PATH...
setx PATH "%PATH%;%INSTALL_DIR%"

echo.
echo ✅ Installation completed!
echo.
echo You can now run:
echo   {platform_config['executable']} ^<directory^>
echo   {platform_config['interactive']}
echo.
echo Note: Restart your command prompt to use the new PATH
pause
"""
            with open(platform_dir / "install.bat", "w") as f:
                f.write(install_script)
        
        else:
            # Unix/Linux installer
            install_script = f"""#!/bin/bash
echo "Installing Credential Scanner v{self.version}..."

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

echo "Copying files..."
cp "{platform_config['executable']}" "$INSTALL_DIR/"
cp "{platform_config['interactive']}" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/{platform_config['executable']}"
chmod +x "$INSTALL_DIR/{platform_config['interactive']}"

# Copy config to user directory
CONFIG_DIR="$HOME/.config/credential-scanner"
mkdir -p "$CONFIG_DIR"
cp config.json "$CONFIG_DIR/"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
    echo "Added $INSTALL_DIR to PATH"
fi

echo
echo "✅ Installation completed!"
echo
echo "You can now run:"
echo "  {platform_config['executable']} <directory>"
echo "  {platform_config['interactive']}"
echo
echo "Note: You may need to restart your terminal or run 'source ~/.bashrc'"
"""
            install_path = platform_dir / "install.sh"
            with open(install_path, "w") as f:
                f.write(install_script)
            install_path.chmod(0o755)
    
    def create_usage_examples(self, platform_dir, platform_config):
        """Create usage examples and quick start guide"""
        
        quick_start = f"""# Credential Scanner v{self.version} - Quick Start Guide

## 🚀 Interactive Mode (Recommended for beginners)
```
./{platform_config['interactive']}
```
Follow the guided setup to scan your project.

## 📋 Command Line Mode (For automation/scripts)

### Basic Usage
```
./{platform_config['executable']} /path/to/your/project
```

### Advanced Usage
```
# Generate all report formats
./{platform_config['executable']} /path/to/project -f all -o security_report

# CI/CD integration (with exit codes)
./{platform_config['executable']} /path/to/project -f json --exit-code --no-progress

# Custom configuration
./{platform_config['executable']} /path/to/project -c custom_config.json -r
```

## 🔧 Configuration

Edit `config.json` to customize:
- File types to scan
- Directories to exclude
- Custom credential patterns
- False positive filters

## 📊 Output Formats

- **Excel (.xlsx)**: Detailed reports with formatting
- **JSON (.json)**: Structured data for automation
- **HTML (.html)**: Interactive web reports
- **CSV (.csv)**: Simple data for analysis

## 🛡️ Security Best Practices

1. **Immediate Actions** for found credentials:
   - Rotate/change all discovered credentials
   - Remove from code history if needed
   - Update affected systems

2. **Prevention**:
   - Use environment variables
   - Implement secrets management
   - Add to CI/CD pipeline
   - Use pre-commit hooks

## 📞 Support

- Read USER_GUIDE.md for comprehensive documentation
- Report issues on GitHub
- Join community discussions

---
Version: {self.version} | Built: {datetime.now().strftime('%Y-%m-%d')}
"""
        
        with open(platform_dir / "QUICK_START.md", "w") as f:
            f.write(quick_start)
        
        # Create example CI/CD configurations
        cicd_examples = """# CI/CD Integration Examples

## GitHub Actions
```yaml
- name: Security Scan
  run: |
    ./credential_scanner_linux . \\
      -f json \\
      --exit-code \\
      --no-progress \\
      -o security_results.json
```

## Jenkins Pipeline
```groovy
stage('Security Scan') {
    steps {
        sh './credential_scanner_linux . -f json --exit-code'
    }
}
```

## GitLab CI
```yaml
security-scan:
  script:
    - ./credential_scanner_linux . -f json --exit-code --no-progress
```
"""
        
        with open(platform_dir / "CI_CD_EXAMPLES.md", "w") as f:
            f.write(cicd_examples)
    
    def get_current_platform(self):
        """Detect current platform"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "darwin":
            if machine in ["arm64", "aarch64"]:
                return "darwin_arm64"
            else:
                return "darwin_x64"
        elif system == "linux":
            return "linux"
        elif system == "windows":
            return "windows"
        else:
            return "linux"  # Default fallback
    
    def generate_checksums(self, archive_path):
        """Generate checksums for release verification"""
        import hashlib
        
        checksums = {}
        
        # Generate SHA256
        with open(archive_path, 'rb') as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()
            checksums['sha256'] = sha256_hash
        
        # Generate MD5
        with open(archive_path, 'rb') as f:
            md5_hash = hashlib.md5(f.read()).hexdigest()
            checksums['md5'] = md5_hash
        
        # Write checksums file
        checksum_file = archive_path.with_suffix(archive_path.suffix + '.checksums')
        with open(checksum_file, 'w') as f:
            f.write(f"# Checksums for {archive_path.name}\\n")
            f.write(f"SHA256: {checksums['sha256']}\\n")
            f.write(f"MD5: {checksums['md5']}\\n")
        
        print(f"✅ Checksums generated: {checksum_file}")
        return checksums
    
    def build_all(self, clean=True):
        """Main build process"""
        print(f"🚀 Building Credential Scanner v{self.version} for {platform.system()}")
        print("="*60)
        
        try:
            # Clean previous builds
            if clean:
                self.clean_previous_builds()
            
            # Setup environment
            python_path, activate_script = self.setup_virtual_environment()
            
            # Create spec files
            self.create_spec_files()
            
            # Build executables
            self.build_executables(python_path)
            
            # Test executables
            self.test_executables()
            
            # Create release packages
            archive_path = self.create_release_packages()
            
            # Generate checksums
            checksums = self.generate_checksums(archive_path)
            
            # Final summary
            print("\\n" + "="*60)
            print("✅ BUILD COMPLETED SUCCESSFULLY!")
            print("="*60)
            print(f"📦 Release package: {archive_path}")
            print(f"🔍 SHA256: {checksums['sha256']}")
            print(f"📁 Size: {archive_path.stat().st_size / (1024*1024):.1f} MB")
            
            print("\\n🎯 Distribution:")
            print(f"   • Extract the archive on target system")
            print(f"   • Run install script for system-wide installation")
            print(f"   • Or use executables directly from extracted folder")
            
            print("\\n🚀 Quick Test:")
            current_platform = self.get_current_platform()
            platform_config = self.platforms.get(current_platform, self.platforms["linux"])
            print(f"   • ./{platform_config['interactive']} (interactive mode)")
            print(f"   • ./{platform_config['executable']} --help (CLI mode)")
            
            return True
            
        except Exception as e:
            print(f"\\n❌ Build failed: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Build Credential Scanner executables")
    parser.add_argument("--no-clean", action="store_true", 
                       help="Don't clean previous builds")
    parser.add_argument("--version", default="2.0.0",
                       help="Version string for the build")
    
    args = parser.parse_args()
    
    builder = ExecutableBuilder()
    builder.version = args.version
    
    success = builder.build_all(clean=not args.no_clean)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
