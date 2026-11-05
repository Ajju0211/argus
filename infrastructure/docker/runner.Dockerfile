# Sandboxed Tool Runner for ARGUS Autonomous Pentesting Platform (X-05)
# Runs unprivileged tools (Nmap, Nuclei, ZAP CLI) inside hardened container with least privilege

FROM debian:bookworm-slim

# Install pinned, official security packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei pinned binary (v3.3.0)
ARG TARGETARCH=arm64
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_${TARGETARCH}.zip" -o nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin \
    && rm nuclei.zip \
    && chmod 755 /usr/local/bin/nuclei

# Create unprivileged runner user 'argus' (UID 1000, GID 1000)
RUN groupadd -g 1000 argus \
    && useradd -m -u 1000 -g argus -s /bin/bash argus

# Pinned template directory for Nuclei - read-only to runner user
RUN mkdir -p /templates/pinned \
    && chown -R root:root /templates \
    && chmod -R 555 /templates

# Dedicated /tmp configuration with sticky bit
RUN chmod 1777 /tmp

# Security metadata labels
LABEL org.opencontainers.image.title="ARGUS Sandboxed Tool Runner" \
      security.sandbox="hardened" \
      security.user="argus" \
      security.capabilities="none" \
      security.read_only="true"

USER argus
WORKDIR /home/argus

# Default unprivileged entrypoint
ENTRYPOINT ["/bin/bash"]

