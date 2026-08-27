#!/usr/bin/bash

# ========================================
# Smart Recon & Report Script — Micro-SOC Edition
# v2: เพิ่มโหมด non-interactive (สำหรับ cron), Delta Reporting,
#     Smart Alerting ผ่าน SQLite (ตาราง recon_assets, recon_scans)
# Creator: Khawtommat
# ========================================

# ==========================================================
# วิธีใช้ (โหมดเดิม - ถามทีละขั้น):
#   ./Smart_Recon.sh TARGET
#
# วิธีใช้ (โหมด cron / non-interactive):
#   ./Smart_Recon.sh TARGET --non-interactive [--deep] [--web=gobuster|nikto|both|skip]
#
# ตัวอย่างตั้ง cron ทุกเที่ยงคืน (ไม่ deep scan, ข้าม web scan, เก็บ delta ลง DB):
#   0 0 * * *  /path/Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip
# ==========================================================

set -uo pipefail

TARGET="${1:-}"
DATE=$(date +"%Y-%m-%d-%H-%M")
DB_FILE="microsoc.db"
NON_INTERACTIVE=0
DEEP_SCAN_FLAG=0
WEB_CHOICE_ARG=""

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# ----------------------------------------------------------
# แยก argument: TARGET ตัวแรกเสมอ ตามด้วยแฟล็กเสริม
# ----------------------------------------------------------
shift || true
for arg in "$@"; do
    case "$arg" in
        --non-interactive) NON_INTERACTIVE=1 ;;
        --deep) DEEP_SCAN_FLAG=1 ;;
        --web=*) WEB_CHOICE_ARG="${arg#--web=}" ;;
        --db=*) DB_FILE="${arg#--db=}" ;;
        -h|--help)
            cat <<EOF
วิธีใช้:
  โหมด interactive (ถามทีละขั้น):
    ./Smart_Recon.sh TARGET

  โหมด cron / non-interactive:
    ./Smart_Recon.sh TARGET --non-interactive [--deep] [--web=gobuster|nikto|both|skip] [--db=path]

ตัวอย่าง cron ทุกเที่ยงคืน:
  0 0 * * *  /path/Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip

EOF
            exit 0
            ;;
        *) echo -e "${YELLOW}[!] ไม่รู้จัก flag: $arg (ข้ามไป)${NC}" ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "[!] ERROR: PLEASE ENTER IP OR DOMAIN OF TARGET"
    echo "    HOW TO USE: ./Smart_Recon.sh {IP OR DOMAIN OF TARGET}"
    exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo -e "${RED}[!] ERROR:${NC} ไม่พบ sqlite3 กรุณาติดตั้งก่อน (เช่น apt install sqlite3)"
    exit 1
fi

OUTPUT_DIR="smart_report_${TARGET}_${DATE}"
echo "[*] Target: $TARGET"
echo "[*] Creating Directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ----------------------------------------------------------
# เตรียม DB (สร้าง schema อัตโนมัติถ้ายังไม่มี — inline ให้รันเดี่ยวๆ ได้)
# ----------------------------------------------------------

init_db() {
    sqlite3 "$DB_FILE" <<'SQL'
CREATE TABLE IF NOT EXISTS recon_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL DEFAULT 'tcp',
    service         TEXT,
    version_info    TEXT,
    state           TEXT    NOT NULL DEFAULT 'open',
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    is_new          INTEGER NOT NULL DEFAULT 1,
    UNIQUE(target, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_recon_assets_target ON recon_assets(target);

CREATE TABLE IF NOT EXISTS recon_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    scan_type       TEXT    NOT NULL DEFAULT 'fast',
    new_ports_count INTEGER NOT NULL DEFAULT 0,
    total_ports     INTEGER NOT NULL DEFAULT 0,
    scanned_at      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_recon_scans_target ON recon_scans(target);
SQL
}
init_db

sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }

echo "[*] Step 1: Checking target & running Nmap fast scan..."
echo ""
ping -c 4 "$TARGET" 2>/dev/null
nmap -F --top-ports 1000 -T4 "$TARGET" -oN "$OUTPUT_DIR/NMAP_FAST.log" 2>/dev/null

RUN_DEEP=0
if [ "$NON_INTERACTIVE" -eq 1 ]; then
    RUN_DEEP=$DEEP_SCAN_FLAG
else
    echo ""
    read -p "[?] Do you want to run Nmap Deep Scan (-sC -sV -Pn) (y/n): " DEEP_SCAN
    [[ "$DEEP_SCAN" =~ ^[Yy]$ ]] && RUN_DEEP=1
fi

if [ "$RUN_DEEP" -eq 1 ]; then
    echo "Running Deep Scan (IT MIGHT TAKE A MOMENT)..."
    nmap -sC -sV -Pn "$TARGET" -oN "$OUTPUT_DIR/NMAP_DEEP.log" 2>/dev/null
    NMAP_FILE="$OUTPUT_DIR/NMAP_DEEP.log"
    SCAN_TYPE="deep"
else
    NMAP_FILE="$OUTPUT_DIR/NMAP_FAST.log"
    SCAN_TYPE="fast"
fi

# ----------------------------------------------------------
# ตัดสินใจว่าจะรัน Web Recon Tool ไหน: ถามผู้ใช้ (interactive) หรือใช้ --web= (cron)
# ----------------------------------------------------------

if grep -E "^80/tcp.*open|^443/tcp.*open" "$NMAP_FILE" >/dev/null 2>&1; then
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        WEB_CHOICE="${WEB_CHOICE_ARG:-skip}"
    else
    echo ""
    echo "======================================="
    echo "[!] Web server (Port 80/443 open)"
    echo "Select a Web Reconnaissance Tool (Web Enumeration):"
    echo "1) Gobuster (Scan For Hidden Directory)"
    echo "2) Nikto (Web Server Scan)"
    echo "3) Run Both Gobuster and Nikto"
    echo "4) Skip this Step"
    echo "======================================="
    read -p "เลือกเมนู [1-4]: " WEB_CHOICE_NUM
    case "$WEB_CHOICE_NUM" in
            1) WEB_CHOICE="gobuster" ;;
            2) WEB_CHOICE="nikto" ;;
            3) WEB_CHOICE="both" ;;
            *) WEB_CHOICE="skip" ;;
        esac
    fi

    case $WEB_CHOICE in

        gobuster)
            echo  "[*] Running Gobuster..."
        gobuster dir -u  "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/GOBUSTER.log" -q 2>/dev/null
        ;;

      nikto)  echo "[*] Running Nikto..."
      nikto -h "http://$TARGET" -o "$OUTPUT_DIR/NIKTO.txt" 2>/dev/null 2>&1
      ;;

      both) echo "[*] Running Gobuster & Nikto..."
      gobuster dir -u  "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/GOBUSTER.log" -q 2>/dev/null
      nikto -h "http://$TARGET" -o "$OUTPUT_DIR/NIKTO.txt" 2>/dev/null 2>&1
      ;;

      *) echo "[-] Skip"
      ;;
  esac
fi

# ----------------------------------------------------------
# Delta Reporting: เทียบพอร์ตที่เจอวันนี้กับที่เคยเจอใน DB (recon_assets)
# ใช้ INSERT ... ON CONFLICT เพื่ออัปเดต last_seen และตั้ง is_new ให้ถูกต้อง
# ----------------------------------------------------------

NEW_PORTS_COUNT=0
TOTAL_PORTS_COUNT=0
declare -a NEW_PORT_LINES=()

# mark ทุกพอร์ตของ target นี้เป็น "ไม่ใหม่" ก่อน แล้วค่อยอัปเดตทีละรายการที่เจอจริง
sqlite3 "$DB_FILE" "UPDATE recon_assets SET is_new = 0 WHERE target = '$(sql_escape "$TARGET")';"

while read -r line; do
    [ -z "$line" ] && continue
    PORT_PROTO=$(echo "$line" | awk '{print $1}')
    PORT=$(echo "$PORT_PROTO" | cut -d'/' -f1)
    PROTO=$(echo "$PORT_PROTO" | cut -d'/' -f2)
    STATE=$(echo "$line" | awk '{print $2}')
    SERVICE=$(echo "$line" | awk '{print $3}')
    VERSION=$(echo "$line" | cut -d ' ' -f4-)

    [[ "$PORT" =~ ^[0-9]+$ ]] || continue
    TOTAL_PORTS_COUNT=$((TOTAL_PORTS_COUNT + 1))

    T_ESC=$(sql_escape "$TARGET")
    SV_ESC=$(sql_escape "$SERVICE")
    VER_ESC=$(sql_escape "$VERSION")
    ST_ESC=$(sql_escape "$STATE")
    PR_ESC=$(sql_escape "$PROTO")

    # เช็คว่าเคยเห็น port นี้ของ target นี้มาก่อนไหม
    EXISTS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM recon_assets WHERE target='$T_ESC' AND port=$PORT AND protocol='$PR_ESC';")

    if [ "$EXISTS" -eq 0 ]; then
        NEW_PORTS_COUNT=$((NEW_PORTS_COUNT + 1))
        NEW_PORT_LINES+=("$PORT/$PROTO ($SERVICE)")
        sqlite3 "$DB_FILE" "INSERT INTO recon_assets (target, port, protocol, service, version_info, state, is_new)
            VALUES ('$T_ESC', $PORT, '$PR_ESC', '$SV_ESC', '$VER_ESC', '$ST_ESC', 1);"
    else
        sqlite3 "$DB_FILE" "UPDATE recon_assets
            SET service='$SV_ESC', version_info='$VER_ESC', state='$ST_ESC',
                last_seen=datetime('now','localtime'), is_new=0
            WHERE target='$T_ESC' AND port=$PORT AND protocol='$PR_ESC';"
    fi
done < <(grep -E "^[0-9]+/(tcp|udp)" "$NMAP_FILE")

sqlite3 "$DB_FILE" "INSERT INTO recon_scans (target, scan_type, new_ports_count, total_ports)
    VALUES ('$(sql_escape "$TARGET")', '$SCAN_TYPE', $NEW_PORTS_COUNT, $TOTAL_PORTS_COUNT);"

# ----------------------------------------------------------
# Smart Alerting: แจ้งเตือนเฉพาะเมื่อมีพอร์ตใหม่ (ลด Alert Fatigue)
# ----------------------------------------------------------

echo ""
echo "-------------------------------------------"
if [ "$NEW_PORTS_COUNT" -gt 0 ]; then
    echo -e "${RED}[SMART ALERT] พบพอร์ตใหม่ที่ไม่เคยเห็นมาก่อน $NEW_PORTS_COUNT พอร์ต บน $TARGET:${NC}"
    for p in "${NEW_PORT_LINES[@]}"; do
        echo -e "${RED}  -> $p${NC}"
    done
else
    echo -e "${GREEN}[OK] ไม่พบพอร์ตใหม่ผิดปกติ (เทียบกับประวัติสแกนก่อนหน้า) — งดแจ้งเตือน${NC}"
fi
echo "-------------------------------------------"

echo ""
echo "[+] Generating Smart HTML Report..."
REPORT_FILE="$OUTPUT_DIR/report.html"

cat <<EOF> "$REPORT_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Smart Recon Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f7f6; color: #333; }
        .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #2c3e50; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr.new-port { background-color: #fdecea !important; }
        .badge { background: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        .badge-new { background: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .delta-box { padding: 12px 16px; border-radius: 6px; margin-top: 15px; }
        .delta-alert { background: #fdecea; border-left: 5px solid #e74c3c; }
        .delta-ok { background: #eafaf1; border-left: 5px solid #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Smart Security Recon Report</h1>
        <p><strong>Target:</strong> $TARGET &vert; <strong>Scan Date:</strong> $DATE &vert; <strong>Scan Type:</strong> $SCAN_TYPE</p>
EOF

if [ "$NEW_PORTS_COUNT" -gt 0 ]; then
    cat <<EOF >> "$REPORT_FILE"
        <div class="delta-box delta-alert">
            <strong>[SMART ALERT]</strong> พบพอร์ตใหม่ที่ไม่เคยเห็นมาก่อน $NEW_PORTS_COUNT พอร์ต (เทียบกับประวัติสแกนก่อนหน้า)
        </div>
EOF
else
    cat <<EOF >> "$REPORT_FILE"
        <div class="delta-box delta-ok">
            <strong>[OK]</strong> ไม่พบพอร์ตใหม่ผิดปกติ เทียบกับประวัติสแกนก่อนหน้า
        </div>
EOF
fi

cat <<EOF >> "$REPORT_FILE"
        <h2>Open Ports & Services (Nmap Results)</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Version Info</th>
                <th>Status</th>
            </tr>
EOF

grep -E "^[0-9]+/(tcp|udp)" "$NMAP_FILE" | while read -r line; do
    PORT_PROTO=$(echo "$line" | awk '{print $1}')
    STATE=$(echo "$line" | awk '{print $2}')
    SERVICE=$(echo "$line" | awk '{print $3}')
    VERSION=$(echo "$line" | cut -d ' ' -f4-)

    IS_NEW_ROW=""
    STATUS_BADGE="<span class=\"badge\">SEEN BEFORE</span>"
    for p in "${NEW_PORT_LINES[@]}"; do
        if [[ "$p" == "$PORT_PROTO"* ]]; then
            IS_NEW_ROW=" class=\"new-port\""
            STATUS_BADGE="<span class=\"badge-new\">NEW</span>"
            break
        fi
    done

cat <<EOF >> "$REPORT_FILE"
            <tr$IS_NEW_ROW>
                <td>$PORT_PROTO</td>
                <td><span class="badge">$STATE</span></td>
                <td>$SERVICE</td>
                <td>$VERSION</td>
                <td>$STATUS_BADGE</td>
            </tr>
EOF
done

cat <<EOF >> "$REPORT_FILE"
        </table>
EOF

if [ -f "$OUTPUT_DIR/GOBUSTER.log" ]; then
    cat <<EOF >> "$REPORT_FILE"
        <h2>Web Directory Enumeration (Gobuster)</h2>
        <pre>$(cat "$OUTPUT_DIR/GOBUSTER.log" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</pre>
EOF
fi

if [ -f "$OUTPUT_DIR/NIKTO.txt" ]; then
    cat <<EOF >> "$REPORT_FILE"
        <h2>Web Server Vulnerability Scan (Nikto)</h2>
        <pre>$(cat "$OUTPUT_DIR/NIKTO.txt" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</pre>
EOF
fi

cat <<EOF>> "$REPORT_FILE"
    </div>
</body>
</html>
EOF

echo "[✔] Done! Report Generated at: $REPORT_FILE"
echo -e "${CYAN}บันทึกผลลง database: $DB_FILE (ตาราง recon_assets, recon_scans)${NC}"
