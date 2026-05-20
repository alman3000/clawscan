#!/usr/bin/env bash
# Usage: ./scripts/scan.sh <target> [passive|active]
set -euo pipefail

TARGET="${1:-}"
MODE="${2:-active}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target> [passive|active]"
  echo "Examples:"
  echo "  $0 example.com"
  echo "  $0 192.168.1.1 active"
  echo "  $0 example.com passive"
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results/$TARGET/$TIMESTAMP"

mkdir -p "$RESULTS_DIR"

# Write env file for agent/docker exec reference
cat > "$RESULTS_DIR/.env" <<EOF
TARGET=$TARGET
MODE=$MODE
TIMESTAMP=$TIMESTAMP
RESULTS_DIR=$RESULTS_DIR
EOF

# Containers mount ./results as /results — compute the inner path
INNER_RESULTS="/results/$TARGET/$TIMESTAMP"

export TARGET MODE TIMESTAMP RESULTS_DIR INNER_RESULTS

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  clawscan"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Target    : $TARGET"
echo "  Mode      : $MODE"
echo "  Results   : $RESULTS_DIR"
echo "  Container : $INNER_RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verify containers are running
CONTAINERS=(clawscan-osint clawscan-portscan clawscan-vulnscan clawscan-webscan clawscan-cmsscan)
for c in "${CONTAINERS[@]}"; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
    echo "[!] Container not running: $c"
    echo "    Run: docker compose up -d"
    exit 1
  fi
done

echo "[*] All containers up — starting scan"
echo ""

# ── Phase 1: OSINT ──────────────────────────────────────────────
echo "[Phase 1] OSINT"

docker exec clawscan-osint \
  subfinder -d "$TARGET" -o "$INNER_RESULTS/subdomains.txt"

docker exec clawscan-osint \
  amass enum -passive -d "$TARGET" -o "$INNER_RESULTS/amass.txt"

docker exec clawscan-osint \
  bash -c "theHarvester -d $TARGET -b all -f $INNER_RESULTS/harvest.json"

docker exec clawscan-osint \
  bash -c "waybackurls $TARGET > $INNER_RESULTS/wayback.txt"

docker exec clawscan-osint \
  bash -c "gau $TARGET > $INNER_RESULTS/gau.txt"

docker exec clawscan-osint \
  bash -c "whois $TARGET > $INNER_RESULTS/whois.txt"

docker exec clawscan-osint \
  bash -c "dig any $TARGET > $INNER_RESULTS/dns.txt"

echo "[Phase 1] Done"

if [[ "$MODE" == "passive" ]]; then
  echo ""
  echo "[*] Passive mode — stopping after OSINT."
  echo "[*] Results: $RESULTS_DIR"
  python3 "$SCRIPT_DIR/report.py" "$RESULTS_DIR" "$TARGET"
  exit 0
fi

# ── Phase 2: Port Scan ───────────────────────────────────────────
echo ""
echo "[Phase 2] Port & Service Discovery"

docker exec clawscan-portscan \
  nmap -p- --min-rate 5000 -T4 \
  -oN "$INNER_RESULTS/portscan-fast.txt" "$TARGET"

# Extract open ports for deep scan
OPEN_PORTS=$(grep ^[0-9] "$RESULTS_DIR/portscan-fast.txt" \
  | awk -F/ '{print $1}' | paste -sd, -)

if [[ -n "$OPEN_PORTS" ]]; then
  docker exec clawscan-portscan \
    nmap -p "$OPEN_PORTS" -sV -sC -O \
    -oA "$INNER_RESULTS/portscan-deep" "$TARGET"
fi

echo "[Phase 2] Done — open ports: $OPEN_PORTS"
echo ""
echo "[*] Phases 3–5 are driven by the OpenFang agent based on findings in:"
echo "    $RESULTS_DIR"
echo "[*] Pass RESULTS_DIR=$INNER_RESULTS and TARGET=$TARGET to the agent."
