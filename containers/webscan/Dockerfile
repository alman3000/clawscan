FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin

RUN go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# feroxbuster (prebuilt binary)
RUN curl -sL "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" \
    -o /tmp/ferox.zip && \
    unzip /tmp/ferox.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm /tmp/ferox.zip

# kiterunner — REST API endpoint discovery (assetnote) - prebuilt binary (optional)
# NOTE: Latest releases may be unavailable; skip if build fails
RUN curl -fL "https://github.com/assetnote/kiterunner/releases/download/v1.0.7/kiterunner_linux_amd64" \
    -o /usr/local/bin/kr 2>/dev/null && chmod +x /usr/local/bin/kr || echo "Warning: kiterunner not available"

# SecLists subset (common wordlists)
RUN git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists.git /opt/seclists && \
    cd /opt/seclists && \
    git sparse-checkout set \
        Discovery/Web-Content \
        Discovery/DNS \
        Passwords/Common-Credentials \
        Fuzzing

WORKDIR /results

CMD ["bash"]
