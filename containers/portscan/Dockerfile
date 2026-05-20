FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    netcat-openbsd \
    curl \
    wget \
    iputils-ping \
    traceroute \
    iproute2 \
    ca-certificates \
    golang-go \
    hydra \
    onesixtyone \
    snmp \
    smbclient \
    python3 \
    python3-pip \
    python3-venv \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Go-based tools
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

# naabu (fast port scanner by ProjectDiscovery) — install prebuilt binary
RUN curl -sL "https://github.com/projectdiscovery/naabu/releases/download/v2.3.0/naabu_2.3.0_linux_amd64.zip" \
    -o /tmp/naabu.zip && \
    unzip -q /tmp/naabu.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/naabu && \
    rm /tmp/naabu.zip

# rustscan (install prebuilt binary)
RUN curl -sL "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" \
    -o /tmp/rustscan.deb && \
    dpkg -i /tmp/rustscan.deb 2>/dev/null || apt-get install -f -y && \
    rm /tmp/rustscan.deb

# enum4linux-ng — SMB/RPC/LDAP enumeration (successor to enum4linux)
RUN pip3 install --no-cache-dir --break-system-packages impacket ldap3 pycryptodome && \
    pip3 install --no-cache-dir --break-system-packages git+https://github.com/cddmp/enum4linux-ng.git@master

WORKDIR /results

CMD ["bash"]
