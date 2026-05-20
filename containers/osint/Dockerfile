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

# Install amass
RUN curl -sL "https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip" \
    -o /tmp/amass.zip && \
    unzip /tmp/amass.zip -d /tmp/amass && \
    mv /tmp/amass/amass_linux_amd64/amass /usr/local/bin/amass && \
    rm -rf /tmp/amass /tmp/amass.zip

# Python OSINT tools
RUN pip install --no-cache-dir \
    theHarvester \
    recon-ng \
    sherlock-project \
    shodan \
    censys \
    dnspython \
    requests

WORKDIR /results

CMD ["bash"]
