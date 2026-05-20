#!/bin/bash
set -e

# Update nuclei templates on first run if not already present
if [ ! -d "/root/nuclei-templates" ] || [ -z "$(ls -A /root/nuclei-templates 2>/dev/null)" ]; then
    echo "[*] Pulling nuclei templates..."
    nuclei -update-templates -update-template-dir /root/nuclei-templates 2>/dev/null || true
fi

exec "$@"
