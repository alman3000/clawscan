FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ruby \
    ruby-dev \
    rubygems \
    build-essential \
    zlib1g-dev \
    libffi-dev \
    libssl-dev \
    perl \
    libwww-perl \
    libnet-ssleay-perl \
    libcrypt-ssleay-perl \
    python3 \
    python3-pip \
    python3-venv \
    php-cli \
    php-curl \
    php-json \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# WPScan — WordPress vuln scanner (plugins, themes, users, passwords)
RUN gem install wpscan --no-document

# JoomScan — OWASP Joomla scanner (Perl)
RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/joomscan && \
    chmod +x /opt/joomscan/joomscan.pl && \
    ln -s /opt/joomscan/joomscan.pl /usr/local/bin/joomscan

# droopescan — Drupal, WordPress, Silverstripe, Typo3, Joomla (Python)
RUN pip3 install --no-cache-dir --break-system-packages droopescan

# CMSmap — multi-CMS: WordPress, Joomla, Drupal (Python)
RUN git clone --depth 1 https://github.com/dionach/CMSmap.git /opt/cmsmap && \
    chmod +x /opt/cmsmap/cmsmap.py && \
    ln -s /opt/cmsmap/cmsmap.py /usr/local/bin/cmsmap

# Typo3Scan — TYPO3 scanner (Python)
RUN git clone --depth 1 https://github.com/whoot/Typo3Scan.git /opt/typo3scan && \
    pip3 install --no-cache-dir --break-system-packages -r /opt/typo3scan/requirements.txt && \
    chmod +x /opt/typo3scan/typo3scan.py && \
    ln -s /opt/typo3scan/typo3scan.py /usr/local/bin/typo3scan

# magescan — Magento scanner (PHP PHAR)
RUN curl -sL "https://github.com/steverobbins/magescan/releases/latest/download/magescan.phar" \
    -o /usr/local/bin/magescan && \
    chmod +x /usr/local/bin/magescan

WORKDIR /results

CMD ["bash"]
