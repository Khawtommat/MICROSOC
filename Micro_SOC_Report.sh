#!/bin/bash
# 
# ==========================================================
# micro_soc_report.sh — ศูนย์บัญชาการ (Central Hub / Dashboard)
# ดึงข้อมูลจาก microsoc.db (ips_logs, recon_assets, recon_scans,
# recon_port_history, web_recon_results — ตาม Schema Contract v2)
# สร้าง Unified HTML Dashboard และส่งสรุปรายวันเข้า Telegram
#
# v2 ของสคริปต์นี้: รวมผล Web Recon (web_recon_results) เข้า dashboard,
# แยกความหมายการ์ดสถิติ (IP ไม่ซ้ำ / เหตุการณ์ / IP ที่ถูกแบน / target),
# แยกพอร์ตที่เปิดอยู่ตอนนี้ (recon_assets.state='open') ออกจากประวัติสะสม
# (recon_port_history), แสดงสถานะ scan ที่แท้จริง (ไม่โชว์ scan ที่ล้มเหลว
# ว่าสำเร็จ), escape ค่าทุกค่าจาก SQLite ก่อนแสดงใน HTML, และตรวจสอบ
# relative link ของรายงานไม่ให้ออกนอกโฟลเดอร์โปรเจกต์
# Creator: Khawtommat
# ==========================================================

# ==========================================================
# วิธีใช้:
#   ./micro_soc_report.sh                       (ใช้ microsoc.db ในโฟลเดอร์ปัจจุบัน)
#   ./micro_soc_report.sh -d /path/microsoc.db -o dashboard.html
#   TELEGRAM_BOT_TOKEN="123456:ABC-xxx" TELEGRAM_CHAT_ID="123456789" ./micro_soc_report.sh --telegram
#   ./micro_soc_report.sh -e csv -x export_dir     (export ตารางทั้งหมดเป็น CSV)
#   ./micro_soc_report.sh -e json -x export_dir    (export ตารางทั้งหมดเป็น JSON)
#
# วิธีสร้าง Telegram Bot:
#   1) คุยกับ @BotFather ใน Telegram -> /newbot -> จะได้ TELEGRAM_BOT_TOKEN
#   2) หา TELEGRAM_CHAT_ID ของตัวเอง เช่น คุยกับ @userinfobot หรือเปิด
#      https://api.telegram.org/bot<TOKEN>/getUpdates หลังส่งข้อความหา bot ไปสักครั้ง
#
# ตัวเลือก:
#   -d  path ไฟล์ SQLite database (default: microsoc.db)
#   -o  path ไฟล์ HTML dashboard ที่จะสร้าง (default: dashboard.html)
#   -e  export รายงานเป็นไฟล์เพิ่มเติม: csv | json (ไม่ระบุ = ไม่ export)
#   -x  โฟลเดอร์ปลายทางสำหรับไฟล์ export (default: ./exports)
#   --telegram  ส่งสรุปเข้า Telegram (ต้องตั้ง env var TELEGRAM_BOT_TOKEN และ TELEGRAM_CHAT_ID)
#   -h  แสดงวิธีใช้
#
# ตั้ง cron ส่งสรุปทุกเช้า 07:00:
#   0 7 * * *  TELEGRAM_BOT_TOKEN="xxx" TELEGRAM_CHAT_ID="xxx" /path/micro_soc_report.sh --telegram
# ==========================================================

set -uo pipefail

# เวอร์ชันของ Dashboard — จุดเดียว (single source of truth) ที่ใช้แก้เลข
# เวอร์ชันทั้งไฟล์ แสดงผลทั้งที่ Header และ Footer ของ dashboard.html ที่สร้าง
# อัปเดตเลขนี้ทุกครั้งที่หน้า dashboard มีการเปลี่ยนแปลงที่ผู้ใช้ควรรู้
# (เช่น โครงสร้างข้อมูลใหม่, การ์ด/ตารางใหม่, Schema Contract เปลี่ยนเวอร์ชัน)
DASHBOARD_VERSION="1.3.1"

DB_FILE="microsoc.db"
OUTPUT_FILE="dashboard.html"
EXPORT_FORMAT=""
EXPORT_DIR="exports"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
micro_soc_report.sh — ศูนย์บัญชาการ (Central Hub / Dashboard)

วิธีใช้:
  ./micro_soc_report.sh                       (ใช้ microsoc.db ในโฟลเดอร์ปัจจุบัน)
  ./micro_soc_report.sh -d /path/microsoc.db -o dashboard.html
  TELEGRAM_BOT_TOKEN="xxx" TELEGRAM_CHAT_ID="xxx" ./micro_soc_report.sh --telegram
  ./micro_soc_report.sh -e csv -x export_dir

ตัวเลือก:
  -d  path ไฟล์ SQLite database (default: microsoc.db)
  -o  path ไฟล์ HTML dashboard ที่จะสร้าง (default: dashboard.html)
  -e  export เป็น csv หรือ json
  -x  โฟลเดอร์ปลายทาง export (default: exports)
  --telegram  ส่งสรุปเข้า Telegram (ต้องตั้ง env var TELEGRAM_BOT_TOKEN และ TELEGRAM_CHAT_ID)
  -h  แสดงวิธีใช้
EOF
    exit "${1:-0}"
}

# แยก flag --telegram ออกก่อนใช้ getopts
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --telegram) SEND_TELEGRAM=1 ;;
        --discord) echo -e "${RED}[!] --discord ถูกยกเลิกแล้ว ใช้ --telegram แทน (ดู TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)${NC}" >&2 ;;
        --line) echo -e "${RED}[!] --line ถูกยกเลิกแล้ว ใช้ --telegram แทน (ดู TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)${NC}" >&2 ;;
        *) ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]}"

while getopts ":d:o:e:x:h" opt; do
    case $opt in
        d) DB_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        e) EXPORT_FORMAT="$OPTARG" ;;
        x) EXPORT_DIR="$OPTARG" ;;
        h) usage 0 ;;
        \?) echo -e "${RED}Error: Invalid option -$OPTARG${NC}" >&2; usage 1 ;;
        :) echo -e "${RED}Error: Option -$OPTARG requires an argument.${NC}" >&2; usage 1 ;;
    esac
done

# เดิมสคริปต์นี้รับ TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID ผ่าน env var ที่
# ผู้เรียกต้อง export เองทุกครั้งเท่านั้น ถ้ารันสคริปต์นี้ตรงๆ (ไม่ผ่าน
# MICROSOC.sh wrapper) แล้วลืม export จะส่ง Telegram ไม่ได้ แม้จะมี
# telegram.env วางอยู่ข้างๆ สคริปต์นี้เองก็ตาม — เพิ่ม fallback ให้ลอง
# source telegram.env จากโฟลเดอร์เดียวกับสคริปต์นี้ ถ้ายังไม่มี env var
# มาก่อน (ไม่กระทบกรณีที่ export ไว้แล้ว เพราะเช็คค่าว่างก่อนเสมอ)
if [ "${SEND_TELEGRAM:-0}" -eq 1 ] && [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
    SELF_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    if [ -r "$SELF_DIR/telegram.env" ]; then
        # shellcheck disable=SC1091
        source "$SELF_DIR/telegram.env"
    fi
fi

if [ -n "$EXPORT_FORMAT" ] && [ "$EXPORT_FORMAT" != "csv" ] && [ "$EXPORT_FORMAT" != "json" ]; then
    echo -e "${RED}Error: -e ต้องเป็น csv หรือ json เท่านั้น${NC}" >&2
    usage 1
fi

if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}Error: sqlite3 is not installed. Please install it first.${NC}" >&2
    exit 1
fi

if [ ! -f "${DB_FILE}" ]; then
    echo -e "${RED}Error: Database file '${DB_FILE}' not found.${NC}" >&2
    exit 1
fi

SQL_WARNED=0   # กันไม่ให้ spam คำเตือนซ้ำ ๆ ถ้ามีหลายคิวรีผิดพลาดต่อเนื่องกัน

# Q(): คิวรีที่คืนค่าเป็น "แถว" (อาจหลายบรรทัด) — ถ้า sqlite3 error จริง (เช่น
# ตารางไม่มีอยู่) จะไม่ fabricate ข้อมูล แค่คืนค่าว่าง + เตือนทาง stderr 1 ครั้ง
# ผู้เรียกต้องจัดการ "ว่าง" เป็น "ยังไม่มีข้อมูล" เอง (ของเดิมทำอยู่แล้วหลายจุด)
Q() {
    local out rc errfile
    errfile=$(mktemp)
    out=$(sqlite3 -separator '|' "$DB_FILE" "$1" 2>"$errfile")
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$SQL_WARNED" -eq 0 ]; then
            echo -e "${RED}[!] คำเตือน: มีคิวรีผิดพลาด (ตารางอาจยังไม่มี/ยัง migrate ไม่ครบ) จะถือว่าไม่มีข้อมูลในส่วนนั้น ไม่ใช่สร้างค่าปลอม${NC}" >&2
            SQL_WARNED=1
        fi
        sed "s#^#    [sqlite3] #" "$errfile" >&2
        rm -f "$errfile"
        printf ''
        return
    fi
    rm -f "$errfile"
    printf '%s' "$out"
}

# Qnum(): เหมือน Q() แต่สำหรับคิวรีตัวเลขเดี่ยว (COUNT/SUM) การันตีว่าคืนค่า
# เป็นจำนวนเต็มเสมอ (ว่าง/error/ไม่ใช่ตัวเลข -> 0) เพื่อไม่ให้ arithmetic
# ที่อื่นในสคริปต์พังเพราะตัวแปรว่าง และไม่ไปเดาค่าอื่นที่ไม่ใช่ 0
Qnum() {
    local out
    out=$(Q "$1")
    [[ "$out" =~ ^-?[0-9]+$ ]] && echo "$out" || echo 0
}

# table_exists(): เช็คว่าตารางมีอยู่จริงก่อน query เพื่อแยกเคส "ตารางใหม่
# ยังไม่ถูกสร้าง/migrate" ออกจากเคส "ตารางมีอยู่แต่ยังไม่มีข้อมูล" ให้ข้อความ
# บน dashboard สื่อถูกเคส ไม่ใช่โยน SQL error ดิบ ๆ ให้ผู้ใช้เห็น
table_exists() {
    local name
    name=$(Q "SELECT name FROM sqlite_master WHERE type='table' AND name='$1';")
    [ "$name" = "$1" ]
}

# ป้องกัน HTML injection: ค่าทุกค่าที่มาจาก SQLite (ip, service, banner,
# target, เวลา, ตัวเลข ฯลฯ) ไม่ใช่ข้อมูลที่เรา control การ format ได้ 100%
# (ผู้ใช้แก้ DB มือ หรือข้อมูลเพี้ยนก็เป็นไปได้) ถ้าใส่ลง dashboard.html ตรง ๆ
# โดยไม่ escape อาจเกิด stored XSS ได้ตอนเปิดดู dashboard — escape "ทุกค่า"
# แบบไม่มีข้อยกเว้น แม้แต่ field ที่ปกติควรเป็นตัวเลข/เวลาอยู่แล้วก็ตาม
html_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# ----------------------------------------------------------
# ความปลอดภัยของ Relative Link ไปยังรายงานฉบับเต็ม (web_recon_results.report_path)
# PROJECT_ROOT = โฟลเดอร์ที่เก็บไฟล์ฐานข้อมูล ถือเป็น "โฟลเดอร์โปรเจกต์ที่อนุญาต"
# (Smart_Recon.sh เขียน report_path เป็น relative path จากโฟลเดอร์เดียวกันนี้เสมอ)
# safe_report_link() ปฏิเสธ path แบบ absolute, path ที่มี ".." หรือพยายาม
# resolve ออกนอก PROJECT_ROOT ไม่ว่าด้วยวิธีใด และปฏิเสธถ้าไฟล์ไม่มีอยู่จริง
# คืนค่าว่างเปล่าทุกกรณีที่ไม่ผ่านการตรวจสอบ (ไม่มีลิงก์ ดีกว่าลิงก์ที่ไม่ปลอดภัย)
# ----------------------------------------------------------
PROJECT_ROOT=$(cd "$(dirname -- "$DB_FILE")" 2>/dev/null && pwd -P)
HAVE_REALPATH=1
command -v realpath >/dev/null 2>&1 || HAVE_REALPATH=0

safe_report_link() {
    local rel="$1" abs
    [ -z "$rel" ] && return 0
    [ -z "$PROJECT_ROOT" ] && return 0
    [ "$HAVE_REALPATH" -eq 1 ] || return 0
    case "$rel" in
        /*) return 0 ;;          # ไม่รับ absolute path
    esac
    case "$rel" in
        *..*) return 0 ;;        # กัน path traversal แบบหยาบก่อน realpath
    esac
    abs=$(cd "$PROJECT_ROOT" 2>/dev/null && realpath -m -- "$rel" 2>/dev/null)
    [ -z "$abs" ] && return 0
    case "$abs" in
        "$PROJECT_ROOT"/*) : ;;  # ต้องอยู่ "ใต้" PROJECT_ROOT จริง ๆ เท่านั้น
        *) return 0 ;;
    esac
    [ -f "$abs" ] || return 0    # ไฟล์ต้องมีอยู่จริง ไม่งั้นไม่แสดงลิงก์
    printf '%s' "$rel"
}

TODAY=$(date +%Y-%m-%d)
GEN_TIME=$(date +%Y-%m-%d\ %H:%M:%S)

# ----------------------------------------------------------
# ดึงสถิติสรุป
# แยกความหมายให้ตรงกับของจริงตาม Schema Contract:
#   - UNIQUE_IPS      = จำนวน IP ที่ไม่ซ้ำ (เคยพบ ไม่ว่าสถานะไหน)
#   - TOTAL_ALERTS    = จำนวนเหตุการณ์ login ผิดพลาดที่ถูกบันทึกทั้งหมด (events, ไม่ unique)
#   - TOTAL_BANNED    = จำนวน IP ที่ถูกแบน "ไม่ซ้ำ" (เดิม COUNT(*) นับซ้ำ IP เดิมที่โดนแบนหลายครั้งผิด)
#   - BANNED_TODAY    = จำนวน IP ที่ถูกแบนวันนี้ "ไม่ซ้ำ" (เหตุผลเดียวกับด้านบน)
#   - TOTAL_TARGETS   = จำนวน target ที่ไม่ซ้ำใน recon_assets (ของเดิมถูกอยู่แล้ว)
#   - CURRENT_OPEN_PORTS  = พอร์ตที่ "เปิดอยู่ตอนนี้จริง" (state='open' ตาม Schema Contract)
#   - TOTAL_HISTORY_ENTRIES = จำนวนรายการในประวัติสแกนพอร์ตทั้งหมด (recon_port_history, ทุกสถานะ/ทุกรอบ)
# ----------------------------------------------------------

UNIQUE_IPS=$(Qnum "SELECT COUNT(DISTINCT ip) FROM ips_logs;")
TOTAL_ALERTS=$(Qnum "SELECT COUNT(*) FROM ips_logs;")
TOTAL_BANNED=$(Qnum "SELECT COUNT(DISTINCT ip) FROM ips_logs WHERE action='banned';")
BANNED_TODAY=$(Qnum "SELECT COUNT(DISTINCT ip) FROM ips_logs WHERE action='banned' AND date(detected_at)='$TODAY';")
# นับเฉพาะพอร์ตใหม่จาก scan ที่ status='completed' เท่านั้น ห้ามนับจาก scan ที่ล้มเหลว/บางส่วน
NEW_PORTS_TODAY=$(Qnum "SELECT COALESCE(SUM(new_ports_count),0) FROM recon_scans WHERE date(scanned_at)='$TODAY' AND status='completed';")
TOTAL_TARGETS=$(Qnum "SELECT COUNT(DISTINCT target) FROM recon_assets;")
CURRENT_OPEN_PORTS=$(Qnum "SELECT COUNT(*) FROM recon_assets WHERE state='open';")
if table_exists recon_port_history; then
    TOTAL_HISTORY_ENTRIES=$(Qnum "SELECT COUNT(*) FROM recon_port_history;")
else
    TOTAL_HISTORY_ENTRIES=0
fi

# สแกนล่าสุด: ต้องแสดง "สถานะ" คู่กับเวลาเสมอ ห้ามแสดง scan ที่ล้มเหลวว่าสำเร็จ
LAST_SCAN_ROW=$(Q "SELECT scanned_at, status, scan_type FROM recon_scans ORDER BY id DESC LIMIT 1;")
if [ -z "$LAST_SCAN_ROW" ]; then
    LAST_SCAN_DISPLAY="ยังไม่เคยสแกน"
    LAST_SCAN_BADGE=""
else
    IFS='|' read -r LS_TIME LS_STATUS LS_TYPE <<< "$LAST_SCAN_ROW"
    LAST_SCAN_DISPLAY=$(html_escape "${LS_TIME:-ไม่ทราบเวลา}")
    case "$LS_TYPE" in
        deep) LAST_SCAN_DISPLAY="$LAST_SCAN_DISPLAY (deep scan)" ;;
        fast) LAST_SCAN_DISPLAY="$LAST_SCAN_DISPLAY (fast scan)" ;;
        *)    [ -n "$LS_TYPE" ] && LAST_SCAN_DISPLAY="$LAST_SCAN_DISPLAY ($(html_escape "$LS_TYPE"))" ;;
    esac
    case "$LS_STATUS" in
        completed) LAST_SCAN_BADGE='<span class="badge badge-ok">สำเร็จ</span>' ;;
        failed)    LAST_SCAN_BADGE='<span class="badge badge-banned">ล้มเหลว</span>' ;;
        partial)   LAST_SCAN_BADGE='<span class="badge badge-alerted">บางส่วน</span>' ;;
        running)   LAST_SCAN_BADGE='<span class="badge badge-alerted">กำลังสแกน</span>' ;;
        *)         LAST_SCAN_BADGE="<span class=\"badge\">$(html_escape "${LS_STATUS:-ไม่ทราบสถานะ}")</span>" ;;
    esac
fi

# ----------------------------------------------------------
# Export ตารางทั้งหมดเป็น CSV / JSON (ถ้าขอด้วย -e)
# ----------------------------------------------------------
if [ -n "$EXPORT_FORMAT" ]; then
    mkdir -p "$EXPORT_DIR"
    STAMP=$(date +%Y%m%d-%H%M%S)
    # เพิ่ม recon_port_history และ web_recon_results เข้าชุด export ด้วย
    # (ตารางใหม่ตาม Schema Contract) — guard ด้วย table_exists กัน DB เก่าที่
    # ยังไม่ migrate ไม่ให้ sqlite3 error กลางคัน
    for TBL in ips_logs recon_assets recon_scans recon_port_history web_recon_results; do
        if ! table_exists "$TBL"; then
            echo -e "${RED}[!] ข้าม ${TBL}: ยังไม่มีตารางนี้ในฐานข้อมูล (DB อาจยังไม่ได้ migrate)${NC}" >&2
            continue
        fi
        if [ "$EXPORT_FORMAT" = "csv" ]; then
            OUT="$EXPORT_DIR/${TBL}_${STAMP}.csv"
            sqlite3 -header -csv "$DB_FILE" "SELECT * FROM $TBL;" > "$OUT"
        else
            OUT="$EXPORT_DIR/${TBL}_${STAMP}.json"
            sqlite3 -json "$DB_FILE" "SELECT * FROM $TBL;" > "$OUT"
        fi
        echo -e "${GREEN}Exported ${TBL} -> ${OUT}${NC}"
    done
fi

# สร้าง HTML Dashboard

# ตรวจสิทธิ์ก่อนเริ่มเขียน: หากปลายทางเขียนไม่ได้ การ redirect ของ shell
# อาจล้มเหลวทีละบรรทัด แต่สคริปต์ยังพิมพ์ว่า "Dashboard generated" ได้
# ซึ่งทำให้ผู้ใช้เผลอเปิด dashboard เก่าที่ไม่ได้มีข้อมูล/รูปแบบล่าสุด
OUTPUT_PARENT=$(dirname -- "$OUTPUT_FILE")
if [ ! -d "$OUTPUT_PARENT" ] || [ ! -w "$OUTPUT_PARENT" ]; then
    echo -e "${RED}ไม่สามารถเขียน Dashboard ในโฟลเดอร์: $OUTPUT_PARENT${NC}" >&2
    exit 1
fi
if [ -e "$OUTPUT_FILE" ] && [ ! -w "$OUTPUT_FILE" ]; then
    echo -e "${RED}ไม่สามารถเขียนทับ Dashboard: $OUTPUT_FILE (ตรวจ owner/permission ของไฟล์)${NC}" >&2
    exit 1
fi

# IP Intelligence (โมดูลเสริม, ไฟล์ IP_Intel.sh แยกต่างหาก — ไม่บังคับ):
# ถ้ามี ip_investigation.html อยู่ในโฟลเดอร์โปรเจกต์เดียวกัน ให้โชว์ลิงก์
# เดียวบน dashboard นี้ ถ้าไม่มี (ไม่เคยรัน IP_Intel.sh) จะไม่มีอะไรเปลี่ยน
# จาก dashboard เดิมเลยแม้แต่ไบต์เดียว
IP_INTEL_LINK_HTML=""
if [ -n "$PROJECT_ROOT" ] && [ -f "$PROJECT_ROOT/ip_investigation.html" ]; then
    IP_INTEL_BADGE=""
    TABLE_EXISTS=$(Q "SELECT name FROM sqlite_master WHERE type='table' AND name='ip_risk_assessments';")
    if [ -n "$TABLE_EXISTS" ]; then
        # นับระดับความเสี่ยงล่าสุด "ต่อ IP" (ไม่ใช่นับทุกแถวสะสม เพราะตารางนี้
        # append-only — ต้องเอาแค่แถวล่าสุดของแต่ละ IP มาสรุปสถานะปัจจุบัน)
        RISK_ROWS=$(Q "SELECT t.risk_level, COUNT(*) FROM ip_risk_assessments t
            JOIN (SELECT ip, MAX(assessed_at) AS max_at FROM ip_risk_assessments GROUP BY ip) latest
                ON t.ip = latest.ip AND t.assessed_at = latest.max_at
            GROUP BY t.risk_level;")
        HIGH_CNT=0; CRIT_CNT=0; TOTAL_IP_CNT=0
        if [ -n "$RISK_ROWS" ]; then
            while IFS='|' read -r lvl cnt; do
                [ -z "$lvl" ] && continue
                TOTAL_IP_CNT=$((TOTAL_IP_CNT + cnt))
                [ "$lvl" = "high" ] && HIGH_CNT=$cnt
                [ "$lvl" = "critical" ] && CRIT_CNT=$cnt
            done <<< "$RISK_ROWS"
        fi
        HIGH_RISK_TOTAL=$((HIGH_CNT + CRIT_CNT))
        if [ "$HIGH_RISK_TOTAL" -gt 0 ]; then
            IP_INTEL_BADGE=" &middot; <b>${HIGH_RISK_TOTAL} IP ความเสี่ยงสูง/วิกฤต</b> จากทั้งหมด ${TOTAL_IP_CNT} IP"
        elif [ "$TOTAL_IP_CNT" -gt 0 ]; then
            IP_INTEL_BADGE=" &middot; ตรวจแล้ว ${TOTAL_IP_CNT} IP ไม่พบความเสี่ยงสูง"
        fi
    fi
    IP_INTEL_LINK_HTML='<a href="ip_investigation.html" target="_blank" rel="noopener" style="display:inline-block;margin-top:10px;padding:6px 14px;border-radius:999px;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.28);color:#fff;font-size:12px;font-weight:700;text-decoration:none">🔎 เปิด IP Investigation'"${IP_INTEL_BADGE}"'</a>'
fi

cat <<HTML > "$OUTPUT_FILE"
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<title>Micro-SOC Dashboard v$(html_escape "$DASHBOARD_VERSION")</title>
<style>
    :root { color-scheme: light; --ink: #15243b; --muted: #64748b; --line: #dbe4ef; --surface: #ffffff; --soft: #f6f9fc; --navy: #152c4b; --navy-2: #254e78; --accent: #ec7053; --teal: #17a47d; }
    * { box-sizing: border-box; }
    body { font-family: Inter, "Noto Sans Thai", Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #edf3f9 0%, #f9fbfd 55%, #eaf2f7 100%); color: var(--ink); line-height: 1.45; }
    .container { max-width: 1240px; margin: 32px auto; background: var(--surface); padding: 32px; border-radius: 20px; box-shadow: 0 18px 45px rgba(21,44,75,.12); }
    .dashboard-head { position: relative; overflow: hidden; padding: 30px; margin: -4px 0 26px; border-radius: 16px; color: #fff; background: linear-gradient(120deg, var(--navy), var(--navy-2)); box-shadow: 0 12px 24px rgba(21,44,75,.18); }
    .dashboard-head::after { content: ""; position: absolute; width: 330px; height: 330px; border-radius: 50%; right: -115px; top: -185px; background: rgba(255,255,255,.08); }
    .eyebrow { position: relative; z-index: 1; color: #a9e8d8; font-size: 11px; font-weight: 800; letter-spacing: .14em; }
    h1 { position: relative; z-index: 1; color: #fff; font-size: clamp(25px, 4vw, 34px); letter-spacing: -.5px; padding: 8px 0 5px; margin: 0; }
    .subtitle { position: relative; z-index: 1; color: #d7e4f1; font-size: 13px; margin: 5px 0 0; overflow-wrap: anywhere; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 12px; }
    .card { position: relative; overflow: hidden; background: linear-gradient(145deg, #fff, var(--soft)); border: 1px solid var(--line); border-radius: 12px; padding: 17px 18px; box-shadow: 0 2px 8px rgba(21,44,75,.035); }
    .card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: #b8c8d9; }
    .card.danger::before { background: #e05a4f; } .card.ok::before { background: var(--teal); } .card.warn::before { background: #d99a2b; }
    .card .num { font-size: 29px; line-height: 1; font-weight: 750; color: var(--navy); }
    .card .label { color: var(--muted); font-size: 12px; margin-top: 8px; }
    .card.danger .num { color: #d94b3d; }
    .card.ok .num { color: #15805d; }
    .card.warn .num { color: #c98111; }
    .report-section { margin-top: 22px; padding: 22px; border: 1px solid var(--line); border-radius: 16px; background: #fff; box-shadow: 0 5px 16px rgba(21,44,75,.045); }
    .report-section h2 { color: var(--navy); font-size: 18px; margin: 0; padding-left: 11px; border-left: 4px solid var(--accent); }
    .report-section .subtitle { color: var(--muted); margin: 8px 0 0; }
    .table-wrap { overflow-x: auto; margin-top: 14px; border: 1px solid var(--line); border-radius: 11px; }
    table { width: 100%; border-collapse: collapse; margin: 14px 0; border: 1px solid var(--line); box-shadow: 0 2px 8px rgba(21,44,75,.025); }
    .table-wrap table { min-width: 820px; margin: 0; border: 0; box-shadow: none; }
    th, td { padding: 11px 12px; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
    th { background-color: var(--navy); color: white; border-right-color: rgba(255,255,255,.28); font-size: 12px; letter-spacing: .02em; white-space: nowrap; }
    th:last-child, td:last-child { border-right: 0; }
    tr:nth-child(even) { background-color: #f8fbfe; }
    tr:hover td { background: #edf6ff; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-weight: 700; color: white; font-size: 11px; white-space: nowrap; }
    .badge-banned { background: #d94b3d; }
    .badge-alerted { background: #d58d16; }
    .badge-new { background: #d94b3d; }
    .badge-seen, .badge-ok, .badge-state-open { background: #15805d; }
    .badge-failed { background: #a93636; }
    .badge-info { background: #246b9e; }
    .badge-state-closed { background: #7f8c8d; }
    .badge-state-filtered { background: #f39c12; }
    .badge-state-unknown { background: #95a5a6; }
    .version-info { max-width: 290px; color: #40536c; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .empty { color: #7b8796; font-style: italic; padding: 12px 0; }
    a { color: #1769aa; font-weight: 700; text-decoration-thickness: 1px; text-underline-offset: 2px; }
    a:hover { color: #0e416e; }
    .trend { display: flex; align-items: flex-end; gap: 10px; height: 150px; margin-top: 16px; padding: 12px 10px 0; border: 1px solid var(--line); border-radius: 12px; background: linear-gradient(180deg, #fbfdff, #f4f8fc); }
    .trend .bar-wrap { display: flex; flex-direction: column; align-items: center; flex: 1; height: 100%; justify-content: flex-end; }
    .trend .bar { width: 60%; background: linear-gradient(#ef8168, #d94b3d); border-radius: 5px 5px 0 0; min-height: 2px; transition: height .2s; }
    .trend .bar-val { font-size: 11px; color: #2c3e50; font-weight: bold; margin-bottom: 2px; }
    .trend .bar-day { font-size: 10px; color: #7f8c8d; margin-top: 6px; }
    .footer-note { color: #7b8796; font-size: 11px; margin-top: 30px; text-align: center; }
    .version-tag { display: inline-block; vertical-align: middle; font-size: 12px; font-weight: 700; color: #fff; background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.28); border-radius: 12px; padding: 2px 10px; white-space: nowrap; }
    /* Badge เวอร์ชันแบบ sticky — ผูกตำแหน่งไว้กับความกว้างของ .container เอง
       (ไม่ใช่ขอบ viewport แบบ position:fixed เดิม) จึงไม่มีทางไปทับขอบขวา
       ของตาราง Smart Recon / Log Sentinel / Web Recon ที่กว้างเท่า container
       อยู่แล้ว ไม่ว่าหน้าจอ/หน้าต่างเบราว์เซอร์จะกว้างแคบแค่ไหนก็ตาม ยังคง
       มองเห็นได้ตลอดตอนเลื่อนหน้าลงเพราะ sticky ยึดกับ top ของ viewport */
    .version-sticky-wrap { position: sticky; top: 10px; z-index: 50; text-align: right; margin-bottom: 10px; }
    .version-badge-fixed { display: inline-block; background: #2c3e50; color: #ffffff; font-size: 12px; font-weight: 600; padding: 5px 12px; border-radius: 14px; box-shadow: 0 2px 6px rgba(0,0,0,0.25); white-space: nowrap; }
    @media (max-width: 640px) {
        .container { margin: 0; padding: 20px 16px; border-radius: 0; min-height: 100vh; }
        .dashboard-head { padding: 22px 18px; margin: -4px 0 20px; }
        .report-section { padding: 17px 13px; border-radius: 13px; }
        .version-sticky-wrap { top: 6px; }
        .version-badge-fixed { font-size: 10px; padding: 3px 9px; }
        .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
        .card { padding: 14px; }
        .card .num { font-size: 25px; }
    }
</style>
</head>
<body>
<div class="container">
    <div class="version-sticky-wrap"><span class="version-badge-fixed">Micro-SOC v$(html_escape "$DASHBOARD_VERSION")</span></div>
    <header class="dashboard-head">
        <div class="eyebrow">SECURITY POSTURE OVERVIEW</div>
        <h1>🛡️ Micro-SOC Dashboard <span class="version-tag">v$(html_escape "$DASHBOARD_VERSION")</span></h1>
        <p class="subtitle">อัปเดตล่าสุด: $(html_escape "$GEN_TIME") &vert; Database: $(html_escape "$DB_FILE") &vert; สแกน recon ล่าสุด: $LAST_SCAN_DISPLAY $LAST_SCAN_BADGE</p>
        ${IP_INTEL_LINK_HTML}
    </header>

    <div class="stats">
        <div class="card"><div class="num">$(html_escape "$UNIQUE_IPS")</div><div class="label">IP ไม่ซ้ำที่เคยตรวจพบ (Log Sentinel)</div></div>
        <div class="card"><div class="num">$(html_escape "$TOTAL_ALERTS")</div><div class="label">จำนวนเหตุการณ์ login ผิดพลาดสะสม</div></div>
        <div class="card danger"><div class="num">$(html_escape "$TOTAL_BANNED")</div><div class="label">IP ถูกแบนสะสม (ไม่ซ้ำ)</div></div>
        <div class="card warn"><div class="num">$(html_escape "$BANNED_TODAY")</div><div class="label">IP ถูกแบนวันนี้ (ไม่ซ้ำ)</div></div>
        <div class="card ok"><div class="num">$(html_escape "$TOTAL_TARGETS")</div><div class="label">เป้าหมายที่เฝ้าระวัง</div></div>
        <div class="card danger"><div class="num">$(html_escape "$NEW_PORTS_TODAY")</div><div class="label">พอร์ตใหม่ที่พบวันนี้ (เฉพาะ scan ที่สำเร็จ)</div></div>
        <div class="card"><div class="num">$(html_escape "$CURRENT_OPEN_PORTS")</div><div class="label">พอร์ตที่เปิดอยู่ตอนนี้ (state=open)</div></div>
        <div class="card"><div class="num">$(html_escape "$TOTAL_HISTORY_ENTRIES")</div><div class="label">ประวัติพอร์ตที่เคยบันทึกสะสม (ทุกรอบสแกน)</div></div>
    </div>

    <section class="report-section">
    <p class="section-kicker">LOGIN &amp; ACCESS MONITORING</p>
    <h2>🚨 Log Sentinel — IP ที่ตรวจพบล่าสุด</h2>
    <table>
        <tr><th>IP</th><th>จำนวนครั้งพลาด</th><th>สถานะ</th><th>เวลาที่พบล่าสุด</th><th>พบทั้งหมด</th></tr>
HTML

#ดึงข้อมูล Log Sentinel (ประวัติการถูกโจมตี)
ROWS=$(Q "SELECT l.ip, l.fail_count, l.action, l.detected_at, c.cnt
    FROM ips_logs l
    JOIN (SELECT ip, COUNT(*) cnt FROM ips_logs GROUP BY ip) c ON c.ip = l.ip
    WHERE l.id IN (SELECT MAX(id) FROM ips_logs GROUP BY ip)
    ORDER BY l.detected_at DESC LIMIT 20;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="5" class="empty">ยังไม่มีข้อมูล — รัน log_sentinel.sh ก่อน</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS='|' read -r ip count action detected times_seen; do
        # ครบทั้ง 4 สถานะตาม Schema Contract (ips_logs.action CHECK) แยก badge
        # ให้ความหมายตรงกับจริง แทนที่เดิมที่ ban_failed/already_banned จะถูก
        # จัดเป็น "alerted" ปนกันหมด
        case "$action" in
            banned)         badge_class="badge-banned" ;;
            ban_failed)     badge_class="badge-failed" ;;
            already_banned) badge_class="badge-info" ;;
            *)              badge_class="badge-alerted" ;;
        esac
        ip_h=$(html_escape "$ip")
        count_h=$(html_escape "$count")
        action_h=$(html_escape "$action")
        detected_h=$(html_escape "$detected")
        times_seen_h=$(html_escape "$times_seen")
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$ip_h</td><td>$count_h</td><td><span class="badge $badge_class">$action_h</span></td><td>$detected_h</td><td>${times_seen_h}×</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
    </section>

    <section class="report-section">
    <p class="section-kicker">EXTERNAL ATTACK SURFACE</p>
    <h2>🔍 Smart Recon — พอร์ต/เซอร์วิสที่ติดตามอยู่ (สถานะปัจจุบัน)</h2>
    <div class="table-wrap">
    <table>
        <tr><th>เป้าหมาย</th><th>พอร์ต</th><th>เซอร์วิส</th><th>เวอร์ชัน</th><th>สถานะพอร์ต</th><th>ใหม่/เคยเห็น</th><th>พบครั้งแรก</th><th>พบล่าสุด</th></tr>
HTML

# state มาจาก recon_assets (สถานะปัจจุบันล่าสุดของแต่ละพอร์ต ตาม Schema
# Contract: open/closed/filtered/unknown) แยกจาก "ใหม่/เคยเห็น" (is_new)
# ซึ่งเป็นคนละมิติกัน — พอร์ตที่ state='closed' ยังคงถูกแสดง (มีหลักฐานจริง
# ว่าปิด) แต่พอร์ตที่ "ไม่พบในสแกนล่าสุด" จะไม่ถูกเปลี่ยนเป็น closed เอง
# (ดู Smart_Recon.sh) ตารางนี้แสดงค่า state ตามที่ Schema Contract บันทึกไว้จริง
ROWS=$(Q "SELECT target, port||'/'||protocol, service, version_info, state, is_new, first_seen, last_seen FROM recon_assets ORDER BY last_seen DESC LIMIT 30;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="8" class="empty">ยังไม่มีข้อมูล — รัน smart_recon.sh ก่อน</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS=$'|' read -r target port service version state isnew first last; do
        new_badge='<span class="badge badge-seen">SEEN BEFORE</span>'
        [ "$isnew" = "1" ] && new_badge='<span class="badge badge-new">NEW</span>'
        case "$state" in
            open)     state_badge='<span class="badge badge-state-open">OPEN</span>' ;;
            closed)   state_badge='<span class="badge badge-state-closed">CLOSED</span>' ;;
            filtered) state_badge='<span class="badge badge-state-filtered">FILTERED</span>' ;;
            *)        state_badge="<span class=\"badge badge-state-unknown\">$(html_escape "${state:-UNKNOWN}")</span>" ;;
        esac
        target_h=$(html_escape "$target")
        port_h=$(html_escape "$port")
        service_h=$(html_escape "$service")
        version_h=$(html_escape "${version:-—}")
        first_h=$(html_escape "$first")
        last_h=$(html_escape "$last")
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$target_h</td><td>$port_h</td><td>$service_h</td><td class="version-info">$version_h</td><td>$state_badge</td><td>$new_badge</td><td>$first_h</td><td>$last_h</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
    </div>
    </section>

    <section class="report-section">
    <p class="section-kicker">SEVEN-DAY TREND</p>
    <h2>📈 แนวโน้มการแบน IP (7 วันล่าสุด)</h2>
    <div class="trend">
HTML

# แนวโน้ม 7 วันล่าสุด (นับจำนวน banned ต่อวัน) — คำนวณ max เพื่อ scale ความสูงแท่ง
TREND_ROWS=$(Q "WITH days AS (
        SELECT date('now','localtime','-6 days') AS d UNION ALL
        SELECT date('now','localtime','-5 days') UNION ALL
        SELECT date('now','localtime','-4 days') UNION ALL
        SELECT date('now','localtime','-3 days') UNION ALL
        SELECT date('now','localtime','-2 days') UNION ALL
        SELECT date('now','localtime','-1 days') UNION ALL
        SELECT date('now','localtime')
    )
    SELECT days.d, COALESCE(COUNT(l.id),0)
    FROM days LEFT JOIN ips_logs l ON date(l.detected_at)=days.d AND l.action='banned'
    GROUP BY days.d ORDER BY days.d;")

MAX_VAL=$(printf '%s\n' "$TREND_ROWS" | awk -F'|' '{print $2}' | sort -rn | head -1)
if [ -z "$MAX_VAL" ] || [ "$MAX_VAL" -eq 0 ]; then
    MAX_VAL=1
fi

while IFS='|' read -r d v; do
    [ -z "$d" ] && continue
    HEIGHT=$(( v * 120 / MAX_VAL ))
    [ "$HEIGHT" -lt 2 ] && HEIGHT=2
    DLABEL=$(date -d "$d" +'%d/%m' 2>/dev/null || echo "$d")
    v_h=$(html_escape "$v")
    DLABEL_h=$(html_escape "$DLABEL")
    cat <<EOF >> "$OUTPUT_FILE"
        <div class="bar-wrap"><div class="bar-val">$v_h</div><div class="bar" style="height:${HEIGHT}px"></div><div class="bar-day">$DLABEL_h</div></div>
EOF
done <<< "$TREND_ROWS"

cat <<HTML >> "$OUTPUT_FILE"
    </div>
    </section>

    <section class="report-section">
    <p class="section-kicker">FREQUENT SOURCES</p>
    <h2>🏆 Top 5 IP ที่ถูกแจ้งเตือน/แบนบ่อยที่สุด</h2>
    <table>
        <tr><th>IP</th><th>จำนวนครั้งที่แจ้งเตือน</th><th>จำนวนครั้งที่ถูกแบน</th></tr>
HTML

ROWS=$(Q "SELECT ip, COUNT(*) total, SUM(CASE WHEN action='banned' THEN 1 ELSE 0 END) banned
    FROM ips_logs GROUP BY ip ORDER BY total DESC LIMIT 5;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="3" class="empty">ยังไม่มีข้อมูล</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS='|' read -r ip total banned; do
        ip_h=$(html_escape "$ip")
        total_h=$(html_escape "$total")
        banned_h=$(html_escape "$banned")
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$ip_h</td><td>$total_h</td><td>$banned_h</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
    </section>

    <section class="report-section">
    <p class="section-kicker">SCAN ACTIVITY</p>
    <h2>🗓️ ประวัติ Smart Recon Scan ล่าสุด</h2>
    <table>
        <tr><th>เป้าหมาย</th><th>ประเภท</th><th>ขอบเขต</th><th>สถานะ</th><th>พอร์ตใหม่</th><th>พอร์ตทั้งหมด</th><th>เวลาที่สแกน</th></tr>
HTML

# เรียงด้วย id DESC แทน scanned_at DESC: scanned_at อาจชนกันได้ (หลาย target
# สแกนในนาทีเดียวกัน) ขณะที่ id เรียงตามลำดับการบันทึกจริงเสมอ — และต้องดึง
# status มาแสดงด้วยทุกครั้ง ห้ามโชว์ตัวเลข 0/0 ของ scan ที่ล้มเหลวเฉย ๆ
# โดยไม่บอกว่ามันคือ "ล้มเหลว" ไม่ใช่ "สแกนได้ 0 พอร์ตจริง ๆ"
ROWS=$(Q "SELECT target, scan_type, scan_scope, status, new_ports_count, total_ports, scanned_at FROM recon_scans ORDER BY id DESC LIMIT 10;")
if [ -z "$ROWS" ]; then
    echo '<tr><td colspan="7" class="empty">ยังไม่มีข้อมูล</td></tr>' >> "$OUTPUT_FILE"
else
    while IFS='|' read -r target scan_type scope status newp totalp scanned; do
        case "$status" in
            completed) status_badge='<span class="badge badge-ok">สำเร็จ</span>' ;;
            failed)    status_badge='<span class="badge badge-banned">ล้มเหลว</span>' ;;
            partial)   status_badge='<span class="badge badge-alerted">บางส่วน</span>' ;;
            running)   status_badge='<span class="badge badge-alerted">กำลังสแกน</span>' ;;
            *)         status_badge="<span class=\"badge\">$(html_escape "${status:-ไม่ทราบ}")</span>" ;;
        esac
        target_h=$(html_escape "$target")
        scan_type_h=$(html_escape "$scan_type")
        scope_h=$(html_escape "${scope:-}")
        [ -z "$scope_h" ] && scope_h="-"
        newp_h=$(html_escape "$newp")
        totalp_h=$(html_escape "$totalp")
        scanned_h=$(html_escape "$scanned")
        cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$target_h</td><td>$scan_type_h</td><td>$scope_h</td><td>$status_badge</td><td>$newp_h</td><td>$totalp_h</td><td>$scanned_h</td></tr>
EOF
    done <<< "$ROWS"
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
    </section>

    <section class="report-section">
    <p class="section-kicker">WEB ENUMERATION</p>
    <h2>🌐 Web Recon — Gobuster / Nikto</h2>
    <p class="subtitle" style="margin-bottom:6px;">
        ผลจาก Nikto เป็น "รายการที่ตรวจพบ" เท่านั้น ยังไม่ใช่ช่องโหว่ที่ยืนยันแล้ว
        ต้องตรวจสอบเพิ่มเติมก่อนสรุปผลจริง
    </p>
    <table>
        <tr><th>เป้าหมาย</th><th>URL</th><th>เครื่องมือ</th><th>สถานะ</th><th>พบ (Findings)</th><th>สรุปผล</th><th>เวลาที่รัน</th><th>รายงานฉบับเต็ม</th></tr>
HTML

if ! table_exists web_recon_results; then
    echo '<tr><td colspan="8" class="empty">ยังไม่มีตาราง web_recon_results ในฐานข้อมูลนี้ — กรุณาอัปเดต/รัน Smart_Recon.sh เวอร์ชันล่าสุดอย่างน้อยหนึ่งครั้ง (migration อัตโนมัติ)</td></tr>' >> "$OUTPUT_FILE"
else
    ROWS=$(Q "SELECT target, url, tool, status, findings_count, summary, started_at, finished_at, report_path FROM web_recon_results ORDER BY id DESC LIMIT 20;")
    if [ -z "$ROWS" ]; then
        echo '<tr><td colspan="8" class="empty">ยังไม่มีข้อมูล Web Recon — อาจยังไม่เคยรัน หรือไม่พบพอร์ตที่เป็น Web Service ในรอบสแกนก่อนหน้า</td></tr>' >> "$OUTPUT_FILE"
    else
        while IFS='|' read -r target url tool status findings summary started finished rpath; do
            case "$status" in
                completed) status_badge='<span class="badge badge-ok">สำเร็จ</span>' ;;
                failed)    status_badge='<span class="badge badge-banned">ล้มเหลว</span>' ;;
                running)   status_badge='<span class="badge badge-alerted">กำลังรัน</span>' ;;
                *)         status_badge="<span class=\"badge\">$(html_escape "${status:-ไม่ทราบ}")</span>" ;;
            esac

            # ลิงก์รายงาน: ผ่าน safe_report_link() เสมอ (ตรวจ absolute/".."
            # /ออกนอก PROJECT_ROOT/ไฟล์ไม่มีอยู่จริง) — ไม่ผ่านข้อใดข้อหนึ่งก็
            # ไม่มีลิงก์ แสดง "ไม่มีรายงาน" แทน ครอบคลุมทั้งกรณี "ไม่ได้รัน"
            # (ไม่มีแถวเลย, จัดการไว้ด้านบนแล้ว), "ล้มเหลว" (status=failed มักไม่มี
            # report_path), และ "ไม่มีรายงาน" (report_path ว่าง/ไฟล์หาย/เส้นทางไม่ปลอดภัย)
            # สำหรับรายงานเก่าที่ยังชี้ไป raw .txt/.log (บันทึกไว้ก่อนที่ Smart_Recon.sh
            # จะมี create_web_report_html()) ให้เลือก HTML viewer ก่อนถ้ามี — ของจริง
            # create_web_report_html() เขียนไฟล์ "<raw_file>.html" ไว้ "โฟลเดอร์เดียวกับ
            # raw file" เสมอ (ยืนยันจาก report_path จริงใน DB เช่น
            # smart_report_.../GOBUSTER_p8085.log.html) ไม่เคยมีโฟลเดอร์ web_reports/
            # อยู่จริงในโปรเจกต์นี้เลย — เช็คเดิมจึงไม่มีทาง match ได้เลยสักครั้ง
            viewer_path="${rpath}.html"
            if [ -f "$PROJECT_ROOT/$viewer_path" ]; then
                link=$(safe_report_link "$viewer_path")
            else
                link=$(safe_report_link "$rpath")
            fi
            if [ -n "$link" ]; then
                report_cell="<a href=\"$(html_escape "$link")\" target=\"_blank\" rel=\"noopener\">เปิดรายงาน</a>"
            else
                report_cell='<span class="empty">ไม่มีรายงาน</span>'
            fi

            target_h=$(html_escape "$target")
            url_h=$(html_escape "$url")
            tool_h=$(html_escape "$tool")
            findings_h=$(html_escape "$findings")
            summary_h=$(html_escape "$summary")
            started_h=$(html_escape "${started:-}")
            finished_h=$(html_escape "${finished:-}")
            time_h="$started_h"
            if [ -n "$finished_h" ] && [ "$finished_h" != "$started_h" ]; then
                time_h="${started_h} &rarr; ${finished_h}"
            fi

            cat <<EOF >> "$OUTPUT_FILE"
            <tr><td>$target_h</td><td>$url_h</td><td>$tool_h</td><td>$status_badge</td><td>$findings_h</td><td>$summary_h</td><td>$time_h</td><td>$report_cell</td></tr>
EOF
        done <<< "$ROWS"
    fi
fi

cat <<HTML >> "$OUTPUT_FILE"
    </table>
    </section>
    <p class="footer-note">Micro-SOC Dashboard v$(html_escape "$DASHBOARD_VERSION") — generated $GEN_TIME</p>
</div>
</body>
</html>
HTML

echo -e "${GREEN}Dashboard generated: ${OUTPUT_FILE}${NC}"

# ----------------------------------------------------------
# ส่งสรุปเข้า Telegram ด้วย Bot API (ถ้าเปิด --telegram และตั้ง
# TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)
# วิธีสร้าง bot: คุยกับ @BotFather -> /newbot -> เก็บ token ที่ได้
# วิธีหา chat_id: คุยกับ @userinfobot หรือส่งข้อความหา bot ตัวเองสักครั้ง
# แล้วเปิด https://api.telegram.org/bot<TOKEN>/getUpdates ดู "chat":{"id": ...}
#
# หมายเหตุด้านความปลอดภัย: Telegram Bot API กำหนดให้ token ต้องอยู่ใน URL
# เสมอ (ไม่มีทางเลือกอื่นจาก API เอง) ซึ่งแปลว่า token จะโผล่ใน process list
# (เช่น `ps aux`) ช่วงที่ curl กำลังทำงานได้ ถ้ากังวลเรื่องนี้ ให้รันบนเครื่องที่
# ผู้ใช้อื่นเข้าไม่ถึง และอย่า commit token ลง git/shell history เด็ดขาด
# ----------------------------------------------------------

if [ "${SEND_TELEGRAM:-0}" -eq 1 ]; then
    BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
    CHAT_ID="${TELEGRAM_CHAT_ID:-}"
    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        echo -e "${RED}ไม่พบ env var TELEGRAM_BOT_TOKEN และ/หรือ TELEGRAM_CHAT_ID — ข้ามการแจ้งเตือน${NC}" >&2
    elif ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบ curl — ข้ามการแจ้งเตือน${NC}" >&2
    else
        DATE_DISPLAY=$(date +'%d/%m/%Y %H:%M')
        # เลือก emoji นำหน้าข้อความตามสถานะ: แดงถ้าวันนี้มีการแบน/พบพอร์ตใหม่ ไม่งั้นเขียว
        STATUS_EMOJI="🟢"
        if [ "${BANNED_TODAY:-0}" -gt 0 ] || [ "${NEW_PORTS_TODAY:-0}" -gt 0 ]; then
            STATUS_EMOJI="🔴"
        fi

        # ค่าทั้งหมดด้านล่างมาจาก COUNT()/SUM() ของ sqlite3 (เป็นตัวเลขล้วนอยู่แล้ว)
        # แต่ผ่าน html_escape ซ้ำไว้เป็น defense-in-depth เพราะ parse_mode=HTML
        # ต้องการให้ &, <, > ถูก escape เสมอ ไม่ให้ Telegram ปฏิเสธข้อความ
        MSG_TEXT=$(cat <<MSGEOF
${STATUS_EMOJI} <b>Micro-SOC สรุปประจำวัน</b>
📅 $(html_escape "$DATE_DISPLAY")

🚫 แบนวันนี้: $(html_escape "$BANNED_TODAY")
🆕 พอร์ตใหม่วันนี้: $(html_escape "$NEW_PORTS_TODAY")
📊 แจ้งเตือนสะสม: $(html_escape "$TOTAL_ALERTS")
🔒 แบนสะสม: $(html_escape "$TOTAL_BANNED")
🎯 เป้าหมายที่เฝ้าระวัง: $(html_escape "$TOTAL_TARGETS")
MSGEOF
)

        RESP=$(curl -s -w '\n%{http_code}' -X POST \
            "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
            --data-urlencode "chat_id=${CHAT_ID}" \
            --data-urlencode "parse_mode=HTML" \
            --data-urlencode "text=${MSG_TEXT}")

        HTTP_CODE=$(printf '%s' "$RESP" | tail -n1)
        BODY=$(printf '%s' "$RESP" | sed '$d')

        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "${GREEN}ส่งสรุปเข้า Telegram เรียบร้อย${NC}"
        else
            echo -e "${RED}[!] ส่ง Telegram ไม่สำเร็จ (HTTP ${HTTP_CODE}): ${BODY}${NC}" >&2
        fi
    fi
fi