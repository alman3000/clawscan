FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    whois \
    dnsutils \
    dnsenum \
    dnsrecon \
    netcat-openbsd \
    jq \
    unzip \
    ca-certificates \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Go-based tools
ENV GOPATH=/go
ENV PATH=$PATH:/go/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# Install amass from source
RUN git clone https://github.com/owasp-amass/amass.git /tmp/amass && \
    cd /tmp/amass && \
    go build -o /usr/local/bin/amass ./cmd/amass && \
    rm -rf /tmp/amass

# Python OSINT tools
RUN pip install --no-cache-dir \
    theHarvester \
    sherlock-project \
    shodan \
    censys \
    dnspython \
    requests && \
    git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng && \
    ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng

WORKDIR /results

CMD ["bash"]
