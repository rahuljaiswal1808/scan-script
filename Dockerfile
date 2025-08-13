# Multi-stage Dockerfile for Credential Scanner
# Builds standalone executables in containers

# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source files
COPY requirements.txt ./
COPY *.py ./
COPY *.json ./
COPY *.md ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller

# Build executables
RUN python build_all_executables.py

# Runtime stage
FROM ubuntu:22.04 as runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create scanner user
RUN useradd -m -s /bin/bash scanner

# Copy built executables and documentation
COPY --from=builder /build/releases/ /opt/credential-scanner/
COPY --from=builder /build/*.md /opt/credential-scanner/

# Set permissions
RUN chown -R scanner:scanner /opt/credential-scanner
RUN find /opt/credential-scanner -name "credential_scanner*" -type f -exec chmod +x {} \;

# Create symlinks for easy access
RUN ln -s /opt/credential-scanner/*/credential_scanner_linux /usr/local/bin/credential-scanner
RUN ln -s /opt/credential-scanner/*/credential_scanner_interactive_linux /usr/local/bin/credential-scanner-interactive

# Switch to scanner user
USER scanner
WORKDIR /scan

# Default command
CMD ["/usr/local/bin/credential-scanner-interactive"]

# Labels
LABEL org.opencontainers.image.title="Credential Scanner"
LABEL org.opencontainers.image.description="Professional security scanning tool for detecting hardcoded credentials"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Security Team"
