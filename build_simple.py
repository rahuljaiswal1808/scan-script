#!/usr/bin/env python3
"""
Simple Build Script for Credential Scanner
Creates executables for the current platform only
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def main():
    """Simple build process"""
    print("🔨 Building Credential Scanner Executables")
    print("="*50)
    
    # Check if we have dependencies
    try:
        import pandas
        import openpyxl
        import tqdm
        print("✅ Dependencies found")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Installing dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pandas", "openpyxl", "tqdm", "pyinstaller"], check=True)
    
    # Clean previous builds
    build_dir = Path("build")
    dist_dir = Path("dist")
    
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    
    print("🧹 Cleaned previous builds")
    
    # Build CLI version
    print("🔨 Building CLI version...")
    subprocess.run([
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "credential_scanner",
        "--add-data", "config.json:.",
        "credential_scanner.py"
    ], check=True)
    
    # Build interactive version
    print("🔨 Building interactive version...")
    subprocess.run([
        sys.executable, "-m", "PyInstaller", 
        "--onefile",
        "--name", "credential_scanner_interactive",
        "--add-data", "config.json:.",
        "credential_scanner_interactive.py"
    ], check=True)
    
    print("✅ Build completed!")
    print(f"📁 Executables in: {Path('dist').absolute()}")
    
    # List built files
    dist_files = list(Path("dist").glob("*"))
    for file in dist_files:
        size_mb = file.stat().st_size / (1024 * 1024)
        print(f"   📄 {file.name} ({size_mb:.1f} MB)")

if __name__ == "__main__":
    main()
