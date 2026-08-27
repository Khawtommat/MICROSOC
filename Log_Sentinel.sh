#!/bin/bash

# ==========================================================
# log-sentinel.sh — ตรวจจับ IP ที่ login ผิดพลาดถี่ในช่วงเวลาสั้นๆ
# v4: Micro-SOC Edition — เพิ่ม SQLite logging + Auto-Ban (iptables)
# Creator : Khawtommat
# ==========================================================

# ==========================================================
# วิธีใช้:
#   ./Log_Sentinel.sh -f /var/log/auth.log
#   ./Log_Sentinel.sh -f /var/log/auth.log -t 5 -w 600 -o report.txt
#   ./Log_Sentinel.sh -f /var/log/auth.log.2.gz          (อ่านไฟล์ที่ถูก gzip ไว้ได้)
#   ./Log_Sentinel.sh -f /var/log/auth.log -d microsoc.db -b   (เปิด Auto-Ban + บันทึกลง DB)
# ==========================================================

# ==========================================================
# ตัวเลือก:
#   -f  path ไฟล์ log (บังคับ)
#   -t  threshold จำนวนครั้ง (default: 5)
#   -w  ขนาดหน้าต่างเวลาเป็นวินาที (default: 600 = 10 นาที)
#   -o  ไฟล์รายงานผลลัพธ์ (default: log-sentinel-report.txt)
#   -d  path ไฟล์ SQLite database (default: microsoc.db) — ถ้าไม่พบไฟล์ script จะสร้าง schema ให้อัตโนมัติ
#   -b  เปิดโหมด Auto-Ban: สั่ง iptables บล็อก IP ที่เข้าเกณฑ์ (ต้องรันด้วยสิทธิ์ root/sudo)
#   -n  Dry-run: แสดงคำสั่ง iptables ที่ "จะ" รัน แต่ไม่รันจริง (ใช้ตอนทดสอบ)
#   -h  แสดงวิธีใช้
# ==========================================================

set -uo pipefail

LOG_FILE=""
THRESHOLD=5
WINDOW_SECONDS=600
OUTPUT_FILE="log-sentinel-report.txt"
DB_FILE="microsoc.db"
AUTO_BAN=0
DRY_RUN=0

#----------------- ค่าสี ------------------
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'   # ไม่มีสี

usage() {
    cat<<EOF
log-sentinel.sh — ตรวจจับ IP ที่ login ผิดพลาดถี่ในช่วงเวลาสั้นๆ
เกณฑ์: THRESHOLD ครั้ง ภายใน WINDOW_SECONDS วินาที (sliding window, O(n))
 
วิธีใช้:
  ./Log_Sentinel.sh -f /var/log/auth.log
  ./Log_Sentinel.sh -f /var/log/auth.log -t 5 -w 600 -o report.txt
  ./Log_Sentinel.sh -f /var/log/auth.log.2.gz     (อ่านไฟล์ที่ถูก gzip ไว้ได้)
 
ตัวเลือก:
  -f  path ไฟล์ log (บังคับ)
  -t  threshold จำนวนครั้ง (default: 5)
  -w  ขนาดหน้าต่างเวลาเป็นวินาที (default: 600 = 10 นาที)
  -o  ไฟล์รายงานผลลัพธ์ (default: log-sentinel-report.txt)
  -d  path ไฟล์ SQLite database (default: microsoc.db)
  -b  เปิดโหมด Auto-Ban (iptables) — ต้องรันด้วย root/sudo
  -n  Dry-run: ไม่รัน iptables จริง แค่แสดงคำสั่งที่จะรัน
  -h  แสดงวิธีใช้
EOF
exit "${1:-0}"
        }



while getopts "f:t:w:o:d:bnh" opt; do
    case "$opt" in 
        f) LOG_FILE="$OPTARG" ;;
        t) THRESHOLD="$OPTARG" ;;
        w) WINDOW_SECONDS="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        d) DB_FILE="$OPTARG" ;;
        b) AUTO_BAN=1 ;;
        n) DRY_RUN=1 ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done

if [ -z "$LOG_FILE" ]; then
    echo -e "${RED} ERROR: ${NC} ต้องระบุไฟล์ log ด้วย -f เช่น -f /var/log/auth.log"
    usage 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED} ERROR: ${NC} ไม่พบไฟล์ '$LOG_FILE'"
    exit 1
fi

# ----------------------------------------------------------
# ตรวจสอบเครื่องมือที่จำเป็น
# ----------------------------------------------------------

if ! command -v sqlite3 >/dev/null 2>&1; then          # <<< NEW
    echo -e "${RED} ERROR: ${NC} ไม่พบ sqlite3 ..."     # <<< NEW
    exit 1                                              # <<< NEW
fi

if [ "$AUTO_BAN" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then  # <<< NEW ทั้งบล็อก
    if ! command -v iptables >/dev/null 2>&1; then      # <<< NEW
        echo -e "${RED} ERROR: ${NC} ..."                # <<< NEW
        exit 1                                           # <<< NEW
    fi
    if [ "$(id -u)" -ne 0 ]; then                        # <<< NEW
        echo -e "${RED} ERROR: ${NC} ..."                 # <<< NEW
        exit 1                                            # <<< NEW
    fi
fi

# ----------------------------------------------------------
# เตรียม Database: ถ้ายังไม่มีไฟล์ ให้สร้าง schema ให้อัตโนมัติ
# (schema เดียวกับที่กำหนดใน schema.sql — inline ไว้ที่นี่เพื่อให้ script รันได้เดี่ยวๆ)
# ----------------------------------------------------------

init_db() {
    sqlite3 "$DB_FILE" << 'SQL'
CREATE TABLE IF NOT EXISTS ips_logs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
ip TEXT NOT NULL,
fail_count INTEGER NOT NULL,
window_seconds INTEGER NOT NULL,
source_log TEXT,
action TEXT NOT NULL DEFAULT 'alerted' CHECK (action IN ('alerted', 'banned', 'ban_failed', 'already_banned')),
detected_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
banned_at TEXT );
CREATE INDEX IF NOT EXISTS idx_ips_logs_ip ON ips_logs(ip);
CREATE INDEX IF NOT EXISTS idx_ips_logs_detected_at ON ips_logs(detected_at);
SQL
}
init_db

# ----------------------------------------------------------
# ฟังก์ชัน: ตรวจว่า IP นี้ถูก iptables DROP ไปแล้วหรือยัง (กันการ INSERT rule ซ้ำ)
# ----------------------------------------------------------

is_already_banned() {
    local ip="$1"
    iptables -C INPUT -s "$ip" -j DROP 2>/dev/null
    return $?
}

# ----------------------------------------------------------
# ฟังก์ชัน: บันทึกผลลง SQLite (escape single quote กัน SQL injection พื้นฐาน)
# ----------------------------------------------------------

log_to_db() {
    local ip="$1" count="$2" action="$3" banned_at="$4"
    local ip_esc; ip_esc=$(printf '%s' "$ip" | sed "s/'/''/g")
    local src_esc; src_esc=$(printf '%s' "$LOG_FILE" | sed "s/'/''/g")
    local banned_val="NULL"
    [ -n "$banned_at" ] && banned_val="'$banned_at'"

    sqlite3 "$DB_FILE" "INSERT INTO ips_logs (ip, fail_count, window_seconds, source_log, action, banned_at)
    VALUES ('$ip_esc', $count, $WINDOW_SECONDS, '$src_esc', '$action', $banned_val)"
}

echo "กำลังแสกน $LOG_FILE (threshold = $THRESHOLD ครั้ง / $WINDOW_SECONDS วินาที)..."
[ "$AUTO_BAN" -eq 1 ] && echo -e "${CYAN}โหมด Auto-Ban: เปิดใช้งาน$( [ "$DRY_RUN" -eq 1 ] && echo ' (dry-run)')${NC}"
echo "------------------------------------------------"

CAT_CMD="cat"
case "$LOG_FILE" in
    *.gz) CAT_CMD="zcat" ;;
    *) CAT_CMD="cat" ;;
esac

declare -A IP_TIMESTAMPS

mapfile -t RAW_LINES < <("$CAT_CMD" "$LOG_FILE" | grep "Failed password" | awk '{print $1, $2, $3, $11}')

for line in "${RAW_LINES[@]}"; do
    read -r month day time ip <<< "$line"
    ts=$(date -d "$month $day $time" +%s 2>/dev/null)
    [ -z "$ts" ] && continue
    IP_TIMESTAMPS["$ip"]+="$ts " 
done

{
    echo "=== log-sentinel Report (Time-Window) ==="
    echo "วันที่สแกน: $(date)"
    echo "ไฟล์ log: $LOG_FILE"
    echo "เกณฑ์: $THRESHOLD ครั้ง ภายใน $((WINDOW_SECONDS / 60)) นาที"
    echo "Auto-Ban: $([ "$AUTO_BAN" -eq 1 ] && echo "เปิด" || echo "ปิด")" 
    echo ""
} > "$OUTPUT_FILE"

ALERT_COUNT=0
BANNED_COUNT=0

declare -A ALERT_RESULTS

for ip in "${!IP_TIMESTAMPS[@]}"; do
    mapfile -t times < <(echo "${IP_TIMESTAMPS[$ip]}" | tr ' ' '\n' | sort -n)
    total=${#times[@]}
    max_in_window=0

left=0

for ((right = 0; right < total; right++)); do
    while (( times[right] - times[left] > WINDOW_SECONDS )); do
        ((left++))
    done
    count=$((right - left + 1))
    (( count > max_in_window )) && max_in_window=$count
done

if (( max_in_window >= THRESHOLD)); then
    ALERT_RESULTS["$ip"]=$max_in_window
    ALERT_COUNT=$((ALERT_COUNT + 1))
fi
done

while read -r count ip; do
    line="[ALERT] $ip - พบสูงสุด $count ครั้ง ภายใน $((WINDOW_SECONDS / 60)) นาที"
    echo -e "${RED}${line}${NC}"
    echo "$line" >> "$OUTPUT_FILE"

    action="alerted"
    banned_at=""

    if [ "$AUTO_BAN" -eq 1 ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            echo -e "${YELLOW}  [DRY-RUN] จะรัน: iptables -A INPUT -s $ip -j DROP${NC}"
            echo "  [DRY-RUN] iptables -A INPUT -s $ip -j DROP" >> "$OUTPUT_FILE"
        elif is_already_banned "$ip"; then
            echo -e "${CYAN}  [SKIP] $ip ถูกแบนอยู่แล้วใน iptables${NC}"
            echo "  [SKIP] $ip ถูกแบนอยู่แล้ว" >> "$OUTPUT_FILE"
            action="already_banned"
        else
            if iptables -A INPUT -s "$ip" -j DROP 2>/dev/null; then
                banned_at=$(date '+%Y-%m-%d %H:%M:%S')
                echo -e "${GREEN}  [BANNED] $ip ถูกบล็อกผ่าน iptables แล้ว${NC}"
                echo "  [BANNED] $ip ถูกบล็อกเมื่อ $banned_at" >> "$OUTPUT_FILE"
                action="banned"
                BANNED_COUNT=$((BANNED_COUNT + 1))
            else
                echo -e "${RED}  [FAILED] ไม่สามารถแบน $ip ผ่าน iptables ได้${NC}"
                echo "  [FAILED] ไม่สามารถแบน $ip ได้" >> "$OUTPUT_FILE"
                action="ban_failed"
            fi
        fi
    fi

    log_to_db "$ip" "$count" "$action" "$banned_at"
done < <(for ip in "${!ALERT_RESULTS[@]}"; do echo "${ALERT_RESULTS[$ip]} $ip"; done | sort -rn)

echo "-------------------------------------------"

if (( ALERT_COUNT > 0 )); then
    echo -e "${YELLOW}แสกนเสร็จสิ้น พบความผิดปกติ $ALERT_COUNT รายการ${NC} - ดูรายละเอียดที่ $OUTPUT_FILE"
    [ $AUTO_BAN -eq 1 ] && [ $DRY_RUN -eq 0 ] && echo -e "${GREEN}บล็อก IP ใหม่ ไปทั้งหมด $BANNED_COUNT รายการ${NC}"
else
    echo -e "${GREEN}แสกนเสร็จสิ้น ไม่พบความผิดปกติ${NC}"
fi

echo -e "${CYAN}บันทึกผลลง Database: $DB_FILE (ตาราง ips_logs)${NC}"

{
    echo ""
    echo "สรุป: พบ IP ที่น่าสงสัยทั้งหมด $ALERT_COUNT รายการ"
    [ $AUTO_BAN -eq 1 ] && echo "บล็อก IP ใหม่ $BANNED_COUNT รายการ"
} >> "$OUTPUT_FILE"