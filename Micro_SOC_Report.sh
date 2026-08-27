#!/bin/bash
# 
# ==========================================================
# micro_soc_report.sh — ศูนย์บัญชาการ (Central Hub / Dashboard)
# ดึงข้อมูลจาก microsoc.db (ips_logs + recon_assets + recon_scans)
# สร้าง Unified HTML Dashboard และส่งสรุปรายวันเข้า LINE Notify
# Creator: Khawtommat
# ==========================================================

# ==========================================================
# วิธีใช้:
#   ./micro_soc_report.sh                       (ใช้ microsoc.db ในโฟลเดอร์ปัจจุบัน)
#   ./micro_soc_report.sh -d /path/microsoc.db -o dashboard.html
#   LINE_NOTIFY_TOKEN="xxxx" ./micro_soc_report.sh --line
#
# ตัวเลือก:
#   -d  path ไฟล์ SQLite database (default: microsoc.db)
#   -o  path ไฟล์ HTML dashboard ที่จะสร้าง (default: dashboard.html)
#   --line   ส่งสรุปเข้า LINE Notify ด้วย (ต้องตั้ง env var LINE_NOTIFY_TOKEN)
#   -h  แสดงวิธีใช้
#
# ตั้ง cron ส่งสรุปทุกเช้า 07:00:
#   0 7 * * *  LINE_NOTIFY_TOKEN="xxxx" /path/micro_soc_report.sh --line
# ==========================================================

set -uo pipefail

DB_FILE="microsoc.db"
OUTPUT_FILE="dashboard.html"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
micro_soc_report.sh — ศูนย์บัญชาการ (Central Hub / Dashboard)

วิธีใช้:
  ./micro_soc_report.sh                       (ใช้ microsoc.db ในโฟลเดอร์ปัจจุบัน)
  ./micro_soc_report.sh -d /path/microsoc.db -o dashboard.html
  LINE_NOTIFY_TOKEN="xxxx" ./micro_soc_report.sh --line

ตัวเลือก:
  -d  path ไฟล์ SQLite database (default: microsoc.db)
  -o  path ไฟล์ HTML dashboard ที่จะสร้าง (default: dashboard.html)
  --line   ส่งสรุปเข้า LINE Notify ด้วย (ต้องตั้ง env var LINE_NOTIFY_TOKEN)
  -h  แสดงวิธีใช้
EOF
    exit "${1:-0}"
}

# แยก flag --line ออกก่อนใช้ getopts (getopts ไม่รองรับ long option โดยตรง)
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --line) SEND_LINE=1 ;;
        *) ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]}"

while getopts ":d:o:h" opt; do
    case $opt in
        d) DB_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage 0 ;;
        \?) echo -e "${RED}Error: Invalid option -$OPTARG${NC}" >&2; usage 1 ;;
        :) echo -e "${RED}Error: Option -$OPTARG requires an argument.${NC}" >&2; usage 1 ;;
    esac
done

if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}Error: sqlite3 is not installed. Please install it first.${NC}" >&2
    exit 1
fi

if [ ! -f "${DB_FILE}" ]; then
    echo -e "${RED}Error: Database file '${DB_FILE}' not found.${NC}" >&2
    exit 1
fi

Q() {
    sqlite3 -separator '|' "$DB_FILE" "$1"
}

TODAY=$(date +%Y-%m-%d)
GEN_TIME=$(date +%Y-%m-%d\ %H:%M:%S)

# ----------------------------------------------------------
# ดึงสถิติสรุป
# ----------------------------------------------------------

TOTAL_BANNED=$(Q "SELECT COUNT(*) FROM ips_logs WHERE action='banned';")
TOTAL_ALERTS=$(Q "SELECT COUNT(*) FROM ips_logs;")
BANNED_TODAY=$(Q "SELECT COUNT(*) FROM ips_logs WHERE action='banned' AND date(detected_at)='$TODAY';")
NEW_PORTS_TODAY=$(Q "SELECT COALESCE(SUM(new_ports_count),0) FROM recon_scans WHERE date(scanned_at)='$TODAY';")
TOTAL_TARGETS=$(Q "SELECT COUNT(DISTINCT target) FROM recon_assets;")
TOTAL_OPEN_PORTS=$(Q "SELECT COUNT(*) FROM recon_assets;")

# ----------------------------------------------------------
# สร้าง HTML Dashboard
# ----------------------------------------------------------

cat <<HTML > "$OUTPUT_FILE"
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>Micro-SOC Dashboard</title>
<style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f4f7f6; color: #333; }
    .container { max-width: 1100px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1 { color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; margin: 0 0 8px; }
    .subtitle { color: #7f8c8d; font-size: 13px; margin-bottom: 26px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 10px; }
    .card { background: #f8f9fa; border: 1px solid #e1e4e8; border-radius: 8px; padding: 16px 18px; }
    .card .num { font-size: 28px; font-weight: 700; color: #2c3e50; }
    .card .label { color: #7f8c8d; font-size: 12px; margin-top: 4px; }
    .card.danger .num { color: #e74c3c; }
    .card.ok .num { color: #27ae60; }
    .card.warn .num { color: #f39c12; }
    h2 { color: #34495e; margin-top: 34px; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
    th { background-color: #2c3e50; color: white; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; color: white; font-size: 12px; }
    .badge-banned { background: #e74c3c; }
    .badge-alerted { background: #f39c12; }
    .badge-new { background: #e74c3c; }
    .badge-seen { background: #27ae60; }
    .empty { color: #999; font-style: italic; padding: 12px 0; }
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ Micro-SOC Dashboard</h1>
    <p class="subtitle">อัปเดตล่าสุด: $GEN_TIME &vert; Database: $DB_FILE</p>

    <div class="stats">
        <div class="card danger"><div class="num">$TOTAL_BANNED</div><div class="label">IP ถูกแบนสะสม</div></div>
        <div class="card warn"><div class="num">$BANNED_TODAY</div><div class="label">ถูกแบนวันนี้</div></div>
        <div class="card"><div class="num">$TOTAL_ALERTS</div><div class="label">การแจ้งเตือน login ผิดพลาดสะสม</div></div>
        <div class="card danger"><div class="num">$NEW_PORTS_TODAY</div><div class="label">พอร์ตใหม่ที่พบวันนี้</div></div>
        <div class="card ok"><div class="num">$TOTAL_TARGETS</div><div class="label">เป้าหมายที่เฝ้าระวัง</div></div>
        <div class="card"><div class="num">$TOTAL_OPEN_PORTS</div><div class="label">พอร์ตเปิดที่ติดตามอยู่</div></div>
    </div>

    <h2>🚨 Log Sentinel — IP ที่ตรวจพบล่าสุด</h2>
    <table>
        <tr><th>IP</th><th>จำนวนครั้งพลาด</th><th>สถานะ</th><th>เวลาที่พบล่าสุด</th><th>พบทั้งหมด</th></tr>
HTML

ROWS=$(Q "SELECT l.ip, l.fail_count, l.action, l.detected_at, c.cnt
    FROM ips_logs l
    JOIN (SELECT ip, COUNT(*) cnt FROM ips_logs GROUP BY ip) c ON c.ip = l.ip
    WHERE l.id IN (SELECT MAX(id) FROM ips_logs GROUP BY ip)
    ORDER BY l.detected_at DESC LIMIT 20;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="5" class="empty">ยังไม่มีข้อมูล — รัน log_sentinel.sh ก่อน</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS='|' read -r ip count action detected times_seen; do
        badge_class="badge-alerted"
        [ "$action" = "banned" ] && badge_class="badge-banned"
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$ip</td><td>$count</td><td><span class="badge $badge_class">$action</span></td><td>$detected</td><td>${times_seen}×</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>

    <h2>🔍 Smart Recon — พอร์ต/เซอร์วิสที่ติดตามอยู่</h2>
    <table>
        <tr><th>เป้าหมาย</th><th>พอร์ต</th><th>เซอร์วิส</th><th>สถานะ</th><th>พบครั้งแรก</th><th>พบล่าสุด</th></tr>
HTML

ROWS=$(Q "SELECT target, port||'/'||protocol, service, is_new, first_seen, last_seen FROM recon_assets ORDER BY last_seen DESC LIMIT 30;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="6" class="empty">ยังไม่มีข้อมูล — รัน smart_recon.sh ก่อน</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS=$'|' read -r target port service isnew first last; do
        badge='<span class="badge badge-seen">SEEN BEFORE</span>'
[ "$isnew" = "1" ] && badge='<span class="badge badge-new">NEW</span>'
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$target</td><td>$port</td><td>$service</td><td>$badge</td><td>$first</td><td>$last</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
</div>
</body>
</html>
HTML

echo -e "${GREEN}Dashboard generated: ${OUTPUT_FILE}${NC}"

# ----------------------------------------------------------
# ส่งสรุปเข้า LINE Notify (ถ้าเปิด --line และมี token)
# ผู้ใช้ต้องเปลี่ยนไปใช้ LINE Messaging API แทน — โค้ดนี้เตรียมโครงไว้ให้
# แค่เปลี่ยน URL/header ตาม service ที่เลือกใช้จริง
# ----------------------------------------------------------

if [ "${SEND_LINE:-0}" -eq 1 ]; then
    if [ -z "${LINE_NOTIFY_TOKEN:-}" ]; then
        echo -e "${RED}ไม่พบ env var LINE_NOTIFY_TOKEN — ข้ามการแจ้งเตือน${NC}" >&2
        exit 1
    elif ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบ curl — ข้ามการแจ้งเตือน${NC}"
    else
        MSG=$'\n🛡️ Micro-SOC สรุปประจำวัน '"$TODAY"$'\n'"แบนวันนี้: $BANNED_TODAY | พอร์ตใหม่วันนี้: $NEW_PORTS_TODAY | แจ้งเตือนสะสม: $TOTAL_ALERTS"
    # ตัวอย่างสำหรับ LINE Messaging API (Push Message) — ต้องมี CHANNEL_ACCESS_TOKEN และ USER_ID จริง
    curl -s -X POST "https://api.line.me/v2/bot/message/broadcast" \
    -H "Authorization: Bearer $LINE_NOTIFY_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"messages\":[{\"type\":\"text\",\"text\":$(printf '%s' "$MSG" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}]}" \
    >/dev/null && echo -e "${GREEN}ส่งสรุปเข้า LINE เรียบร้อย${NC}" || echo -e "${RED}[!] ส่ง LINE ไม่สำเร็จ ตรวจสอบ token${NC}"
    fi
fi