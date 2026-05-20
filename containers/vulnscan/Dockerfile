FROM python:3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://deb.debian.org/debian bookworm main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian bookworm-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    perl \
    libssl-dev \
    libnet-ssleay-perl \
    nikto \
    sqlmap \
    wapiti \
    whatweb \
    wafw00f \
    ca-certificates \
    ruby \
    ruby-dev \
    build-essential \
    openssl \
    bash \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin

# nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# dalfox (XSS scanner)
RUN go install github.com/hahwul/dalfox/v2@latest

# commix (command injection)
RUN pip install --no-cache-dir commix

# xsstrike
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike && \
    pip install --no-cache-dir -r /opt/xsstrike/requirements.txt && \
    ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike

# testssl.sh — comprehensive TLS/SSL scanner
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /results

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
