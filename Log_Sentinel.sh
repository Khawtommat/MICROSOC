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
#   -b  เปิดโหมด Auto-Ban: สั่ง iptables/ip6tables บล็อก IP ที่เข้าเกณฑ์ (ต้องรันด้วยสิทธิ์ root/sudo)
#   -n  Dry-run: แสดงคำสั่ง iptables/ip6tables ที่ "จะ" รัน แต่ไม่รันจริง (ใช้ตอนทดสอบ)
#   -A  path ไฟล์ allowlist (1 IP หรือ IPv4 CIDR ต่อบรรทัด, '#' ใช้คอมเมนต์ได้)
#       IP ใน allowlist จะไม่ถูก Auto-Ban เด็ดขาด (ยังคง "alerted" ปกติ)
#       127.0.0.1 และ ::1 อยู่ใน allowlist เสมอโดย default แม้ไม่ระบุ -A
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
LOW_IMPACT=0
ALLOWLIST_FILE=""

#----------------- ค่าสี ------------------
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'   # ไม่มีสี

# ----------------------------------------------------------
# ฟังก์ชัน: แปลงวินาทีเป็นข้อความอ่านง่าย (เดิมใช้ $((WINDOW_SECONDS / 60)) นาที
# ตรงๆ ทำให้ window ที่ < 60 วินาที เช่น 5 วินาที แสดงผลเป็น "0 นาที" ซึ่งผิด)
# ใช้สำหรับ "แสดงผล" เท่านั้น ไม่กระทบ logic การตรวจจับที่ยังคำนวณเป็นวินาทีดิบ
# ----------------------------------------------------------

format_window() {
    local secs="$1" m s
    m=$(( secs / 60 ))
    s=$(( secs % 60 ))
    if (( m > 0 && s > 0 )); then
        printf '%d นาที %d วินาที' "$m" "$s"
    elif (( m > 0 )); then
        printf '%d นาที' "$m"
    else
        printf '%d วินาที' "$s"
    fi
}

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
  -b  เปิดโหมด Auto-Ban (iptables/ip6tables) — ต้องรันด้วย root/sudo
  -n  Dry-run: ไม่รัน iptables/ip6tables จริง แค่แสดงคำสั่งที่จะรัน
  -L  Low-impact mode: ลด CPU/IO priority ของตัวเอง (renice/ionice) ไม่ให้แย่ง resource server ตอนรัน
  -A  path ไฟล์ allowlist (1 IP หรือ IPv4 CIDR ต่อบรรทัด) ที่ห้าม Auto-Ban เด็ดขาด
      (127.0.0.1 และ ::1 อยู่ใน allowlist เสมอ แม้ไม่ระบุ -A)
  -h  แสดงวิธีใช้
EOF
exit "${1:-0}"
        }



while getopts "f:t:w:o:d:A:bnLh" opt; do
    case "$opt" in 
        f) LOG_FILE="$OPTARG" ;;
        t) THRESHOLD="$OPTARG" ;;
        w) WINDOW_SECONDS="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        d) DB_FILE="$OPTARG" ;;
        A) ALLOWLIST_FILE="$OPTARG" ;;
        b) AUTO_BAN=1 ;;
        n) DRY_RUN=1 ;;
        L) LOW_IMPACT=1 ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done

if [ "$LOW_IMPACT" -eq 1 ]; then
    renice -n 15 -p $$ >/dev/null 2>&1
    command -v ionice >/dev/null 2>&1 && ionice -c 3 -p $$ >/dev/null 2>&1
    echo -e "${CYAN}[*] Low-impact mode: ลด priority ของ process ลงแล้ว${NC}"
fi

if [ -z "$LOG_FILE" ]; then
    echo -e "${RED} ERROR: ${NC} ต้องระบุไฟล์ log ด้วย -f เช่น -f /var/log/auth.log"
    usage 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED} ERROR: ${NC} ไม่พบไฟล์ '$LOG_FILE'"
    exit 1
fi

# ----------------------------------------------------------
# เดิมสคริปต์นี้ไม่ validate -t/-w เองเลย (พึ่งพาแค่ MICROSOC.sh wrapper)
# ทำให้ถ้ารัน Log_Sentinel.sh ตรง ๆ ด้วยค่าที่ไม่ใช่ตัวเลข เช่น
#   -w "0); DROP TABLE ips_logs;--"
# ค่าดิบจะถูกต่อเข้า SQL string ใน log_to_db() แบบไม่ escape → SQL injection
# และถ้าไม่ใช่ตัวเลข ก็จะทำให้ arithmetic ของ sliding window ($(( ... )))
# เงียบ ๆ พัง ตรวจจับผิดพลาดโดยไม่มี error ชัดเจน จึง validate ตั้งแต่ต้นสคริปต์
# ----------------------------------------------------------

if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || [ "$THRESHOLD" -eq 0 ]; then
    echo -e "${RED} ERROR: ${NC} -t ต้องเป็นจำนวนเต็มบวกเท่านั้น (ได้รับ: '$THRESHOLD')"
    exit 1
fi

if ! [[ "$WINDOW_SECONDS" =~ ^[0-9]+$ ]] || [ "$WINDOW_SECONDS" -eq 0 ]; then
    echo -e "${RED} ERROR: ${NC} -w ต้องเป็นจำนวนเต็มบวกเท่านั้น (ได้รับ: '$WINDOW_SECONDS')"
    exit 1
fi

# ----------------------------------------------------------
# ตรวจสอบเครื่องมือที่จำเป็น
# ----------------------------------------------------------

if ! command -v sqlite3 >/dev/null 2>&1; then          # <<< NEW
    echo -e "${RED} ERROR: ${NC} ไม่พบ sqlite3 ..."     # <<< NEW
    exit 1                                              # <<< NEW
fi

if [ "$AUTO_BAN" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
    # เดิมบังคับต้องมี iptables เท่านั้น แต่ตอนนี้รองรับทั้ง IPv4 (iptables) และ
    # IPv6 (ip6tables) จึง fail เฉพาะกรณีที่ไม่มีเครื่องมือใดเลยบนระบบนี้
    # ส่วนกรณีมีแค่ตัวใดตัวหนึ่ง จะปล่อยผ่านตรงนี้ แล้วไป fail-safe เป็นรายไอพี
    # ตอนเจอ IP ที่ต้องใช้เครื่องมือที่ไม่มีจริง (ดู firewall_tool_for ด้านล่าง)
    if ! command -v iptables >/dev/null 2>&1 && ! command -v ip6tables >/dev/null 2>&1; then
        echo -e "${RED} ERROR: ${NC} ไม่พบทั้ง iptables และ ip6tables — ไม่สามารถเปิด Auto-Ban ได้"
        exit 1
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED} ERROR: ${NC} Auto-Ban (-b) ต้องรันด้วยสิทธิ์ root/sudo"
        exit 1
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
    return $?
}

# เดิมเรียก init_db เฉยๆ ไม่เช็คผลลัพธ์เลย ถ้า sqlite3 เขียน schema ไม่สำเร็จ
# (เช่น path ไม่มีสิทธิ์เขียน, disk เต็ม) สคริปต์จะเดินหน้าสแกน/ยิง flush_db_batch
# ต่อไปโดยไม่รู้ตัว แล้วตอนจบก็ยังพิมพ์ว่า "บันทึกผลลง Database" ราวกับสำเร็จ
# เก็บสถานะไว้ใน DB_READY เพื่อใช้ตัดสินใจตอน flush และตอนสรุปผลท้ายสคริปต์
if init_db; then
    DB_READY=1
else
    DB_READY=0
    echo -e "${RED} ERROR: ${NC} สร้าง/เปิด schema ใน database '$DB_FILE' ไม่สำเร็จ (ตรวจสิทธิ์การเขียนไฟล์/พื้นที่ดิสก์) — จะสแกนและสร้างรายงาน .txt ต่อไป แต่จะไม่มีการบันทึกลง Database รอบนี้" >&2
fi

# ----------------------------------------------------------
# ฟังก์ชัน: ตรวจว่า IP นี้ถูก iptables DROP ไปแล้วหรือยัง (กันการ INSERT rule ซ้ำ)
# ----------------------------------------------------------

is_already_banned() {
    local ip="$1" tool="$2"
    "$tool" -C INPUT -s "$ip" -j DROP 2>/dev/null
    return $?
}

# ----------------------------------------------------------
# ฟังก์ชัน: เลือก iptables หรือ ip6tables ให้ตรงกับชนิดของ IP
# (เดิมใช้ iptables ตายตัวทุกกรณี ถ้าเจอ IPv6 คำสั่งจะ error/ไม่ทำอะไรเลย
#  โดยไม่มีใครรู้ตัว — ต้องแยกตามชนิด IP และ fail-safe ถ้าไม่มีเครื่องมือนั้นจริง)
# ----------------------------------------------------------

firewall_tool_for() {
    local ip="$1"
    if [[ "$ip" == *:* ]]; then
        echo "ip6tables"
    else
        echo "iptables"
    fi
}

# ----------------------------------------------------------
# ฟังก์ชัน: ตรวจว่า string เป็น IPv4/IPv6 literal จริง ๆ ก่อนส่งเข้า iptables
# (กันไม่ให้ value ที่ parse ผิดพลาด เช่น username หลุดเข้าไปเป็น -s ของ iptables
#  ซึ่งจะโดน resolve เป็น DNS hostname แทน และอาจถูกใช้เบี่ยงเบนให้แบน IP อื่น)
# ----------------------------------------------------------

is_valid_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
            # เดิมใช้ (( octet <= 255 )) ตรง ๆ ถ้า octet ขึ้นต้นด้วย 0 เช่น "008"
            # bash arithmetic จะตีความเป็นเลขฐาน 8 แล้วเจอ digit 8/9 ที่ไม่ใช่
            # octal digit → เกิด arithmetic error ทำให้ฟังก์ชันปฏิเสธ IP ที่ควรผ่าน
            # บังคับให้ตีความเป็นฐาน 10 เสมอด้วย 10#
            (( 10#$octet <= 255 )) || return 1
        done
        return 0
    fi
    # เช็คหยาบ ๆ สำหรับ IPv6 (ต้องมี ':' และมีแต่ hex digits/':' เท่านั้น)
    if [[ "$ip" == *:* ]] && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        return 0
    fi
    return 1
}

# ----------------------------------------------------------
# ฟังก์ชัน: เตรียมบันทึกผลลง SQLite
# (escape single quote กัน SQL injection พื้นฐาน, ไม่ยิง sqlite3 ทันที
#  แต่สะสมเป็น batch แล้วเขียนทีเดียวตอนจบ เพื่อลดภาระ process spawn /
#  disk I/O ของเครื่อง server เวลามี IP แจ้งเตือนจำนวนมาก)
# ----------------------------------------------------------

# ----------------------------------------------------------
# Allowlist: IP ที่ห้าม Auto-Ban เด็ดขาด (ยังคง "alerted" ตามปกติ แค่ไม่ยิง
# iptables/ip6tables ให้) 127.0.0.1 และ ::1 อยู่ใน allowlist เสมอเป็นค่า default
# เพื่อกัน loopback ถูกแบนโดยไม่ตั้งใจ ไฟล์ -A เสริมเพิ่มได้ (1 รายการ/บรรทัด,
# รองรับ exact IP และ IPv4 CIDR เช่น 10.0.0.0/8, '#' ใช้คอมเมนต์ได้)
# เป็น flag ใหม่แบบ optional จึงไม่กระทบ interface เดิมที่ไม่ได้ใช้ -A
# ----------------------------------------------------------

declare -A ALLOWLIST_EXACT=()
ALLOWLIST_CIDR_V4=()

ip_to_int() {
    local a b c d
    IFS='.' read -r a b c d <<< "$1"
    echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

cidr_match_v4() {
    local ip="$1" cidr="$2"
    local net="${cidr%/*}" prefix="${cidr#*/}"
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    (( prefix >= 0 && prefix <= 32 )) || return 1
    is_valid_ip "$net" || return 1
    local ip_int net_int mask
    ip_int=$(ip_to_int "$ip")
    net_int=$(ip_to_int "$net")
    if (( prefix == 0 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    (( (ip_int & mask) == (net_int & mask) ))
}

load_allowlist() {
    ALLOWLIST_EXACT["127.0.0.1"]=1
    ALLOWLIST_EXACT["::1"]=1
    [ -z "$ALLOWLIST_FILE" ] && return 0
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        echo -e "${YELLOW}[!] ไม่พบไฟล์ allowlist '$ALLOWLIST_FILE' — ใช้เฉพาะ default (loopback) ต่อไป${NC}" >&2
        return 0
    fi
    local raw line
    while IFS= read -r raw || [ -n "$raw" ]; do
        line="${raw%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "$line" ] && continue
        if [[ "$line" == */* ]]; then
            ALLOWLIST_CIDR_V4+=("$line")
        else
            ALLOWLIST_EXACT["$line"]=1
        fi
    done < "$ALLOWLIST_FILE"
}

is_allowlisted() {
    local ip="$1"
    [[ -n "${ALLOWLIST_EXACT[$ip]+x}" ]] && return 0
    if [[ "$ip" != *:* ]]; then
        local cidr
        for cidr in "${ALLOWLIST_CIDR_V4[@]}"; do
            cidr_match_v4 "$ip" "$cidr" && return 0
        done
    fi
    return 1
}

load_allowlist

DB_BATCH=""

log_to_db() {
    local ip="$1" count="$2" action="$3" banned_at="$4"
    local ip_esc; ip_esc=$(printf '%s' "$ip" | sed "s/'/''/g")
    local src_esc; src_esc=$(printf '%s' "$LOG_FILE" | sed "s/'/''/g")
    local banned_val="NULL"
    [ -n "$banned_at" ] && banned_val="'$banned_at'"

    # เดิม $count และ $WINDOW_SECONDS ถูกต่อเข้า SQL ตรง ๆ โดยไม่ escape/validate
    # (ต่างจาก $ip กับ $LOG_FILE ที่ escape single quote ไว้แล้ว) ทำให้เป็นช่องทาง
    # SQL injection ได้ถ้ามีค่าที่ไม่ใช่ตัวเลขหลุดเข้ามา แม้ตอนนี้จะ validate ไว้
    # ตั้งแต่ต้นสคริปต์แล้ว แต่ใส่การบังคับให้เป็นจำนวนเต็มซ้ำตรงนี้ไว้อีกชั้น
    # เป็น defense-in-depth เผื่อ log_to_db ถูกเรียกจากที่อื่นในอนาคต
    local count_safe window_safe
    count_safe=$(printf '%d' "$count" 2>/dev/null) || count_safe=0
    window_safe=$(printf '%d' "$WINDOW_SECONDS" 2>/dev/null) || window_safe=0

    DB_BATCH+="INSERT INTO ips_logs (ip, fail_count, window_seconds, source_log, action, banned_at)
    VALUES ('$ip_esc', $count_safe, $window_safe, '$src_esc', '$action', $banned_val);
"
}

flush_db_batch() {
    [ -z "$DB_BATCH" ] && return 0
    { echo "BEGIN TRANSACTION;"; printf '%s' "$DB_BATCH"; echo "COMMIT;"; } | sqlite3 "$DB_FILE"
    return $?
}

echo "กำลังแสกน $LOG_FILE (threshold = $THRESHOLD ครั้ง / $(format_window "$WINDOW_SECONDS"))..."
[ "$AUTO_BAN" -eq 1 ] && echo -e "${CYAN}โหมด Auto-Ban: เปิดใช้งาน$( [ "$DRY_RUN" -eq 1 ] && echo ' (dry-run)')${NC}"
echo "------------------------------------------------"

CAT_CMD="cat"
case "$LOG_FILE" in
    *.gz) CAT_CMD="zcat" ;;
    *) CAT_CMD="cat" ;;
esac

declare -A IP_TIMESTAMPS

# ตรวจ exit code ของ CAT_CMD ก่อนเชื่อผลลัพธ์ (เช่น .gz เสียหาย/ไม่ใช่ gzip จริง
# จะทำให้ zcat exit ไม่ใช่ 0 แต่ pipeline ยังไหลต่อแบบเงียบๆ ถ้าไม่เช็คตรงนี้)
if ! "$CAT_CMD" "$LOG_FILE" > /dev/null 2>&1; then
    echo -e "${RED} ERROR: ${NC} ไม่สามารถอ่านไฟล์ '$LOG_FILE' ด้วย $CAT_CMD ได้ (ไฟล์อาจเสียหายหรือไม่ใช่ gzip ที่ถูกต้อง)"
    exit 1
fi

mapfile -t RAW_LINES < <("$CAT_CMD" "$LOG_FILE" | grep -i "Failed password")

# หมายเหตุ: เดิมใช้ awk '{print $1,$2,$3,$11}' ซึ่งพังเมื่อ log เป็นรูปแบบ
# "Failed password for invalid user X from IP port ..." เพราะคำว่า "invalid user"
# ดัน field ไปอีก 2 ตำแหน่ง ทำให้ $11 กลายเป็น username แทนที่จะเป็น IP จริง
# (บั๊กนี้ยังทำให้ auto-ban เอา string ที่ไม่ใช่ IP ไปยัด iptables -s ด้วย)
# แก้โดยดึงวันที่ด้วย field ปกติ (เชื่อถือได้เพราะอยู่ต้นบรรทัดเสมอ) และดึง IP
# ด้วย regex ตามคำว่า "from " แทน ซึ่งทนทานต่อทั้งสองรูปแบบของบรรทัด
for line in "${RAW_LINES[@]}"; do
    read -r month day time _ <<< "$line"
    if [[ "$line" =~ from[[:space:]]+([0-9a-fA-F.:]+)[[:space:]]+port ]]; then
        ip="${BASH_REMATCH[1]}"
    else
        continue
    fi
    # เดิม regex match อย่างเดียวก็ยอมรับแล้ว โดยไม่เคยตรวจว่าค่าที่ได้เป็น IP
    # ที่ valid จริง (is_valid_ip เดิมใช้แค่ตอนจะแบนเท่านั้น) ทำให้ string ที่
    # หน้าตาคล้าย IP แต่ผิดรูปแบบ (เช่น octet เกิน 255) หลุดเข้าไปอยู่ในรายงาน/DB
    # ได้ จึงกรองด้วย is_valid_ip ตั้งแต่ตอน parse เลย ไม่ใช่รอถึงขั้นตอนแบน
    is_valid_ip "$ip" || continue
    ts=$(date -d "$month $day $time" +%s 2>/dev/null)
    [ -z "$ts" ] && continue
    # syslog classic format ไม่มีปีกำกับ date -d จึง assume เป็นปีปัจจุบันเสมอ
    # ถ้ากำลังสแกน log เก่าที่คาบเกี่ยวรอยต่อปี (เช่น log เดือนธันวาแต่รันตรวจตอน
    # มกราปีถัดไป) ผลคือได้ timestamp ที่ "อยู่ในอนาคต" เทียบกับตอนนี้ ซึ่งผิดแน่นอน
    # — ถ้าเจอแบบนี้ (ล้ำหน้าปัจจุบันเกิน 1 วัน) ให้ถอยปีลงมา 1 ปีแทน
    now_ts=$(date +%s)
    if (( ts > now_ts + 86400 )); then
        ts=$(date -d "$month $day $time last year" +%s 2>/dev/null)
        [ -z "$ts" ] && continue
    fi
    IP_TIMESTAMPS["$ip"]+="$ts "
done

{
    echo "=== log-sentinel Report (Time-Window) ==="
    echo "วันที่สแกน: $(date)"
    echo "ไฟล์ log: $LOG_FILE"
    echo "เกณฑ์: $THRESHOLD ครั้ง ภายใน $(format_window "$WINDOW_SECONDS")"
    echo "Auto-Ban: $([ "$AUTO_BAN" -eq 1 ] && echo "เปิด" || echo "ปิด")" 
    echo ""
} > "$OUTPUT_FILE"

ALERT_COUNT=0
BANNED_COUNT=0

declare -A ALERT_RESULTS

for ip in "${!IP_TIMESTAMPS[@]}"; do
    mapfile -t times < <(echo "${IP_TIMESTAMPS[$ip]}" | tr ' ' '\n' | grep -v '^$' | sort -n)
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
    line="[ALERT] $ip - พบสูงสุด $count ครั้ง ภายใน $(format_window "$WINDOW_SECONDS")"
    echo -e "${RED}${line}${NC}"
    echo "$line" >> "$OUTPUT_FILE"

    action="alerted"
    banned_at=""

    if [ "$AUTO_BAN" -eq 1 ]; then
        if ! is_valid_ip "$ip"; then
            # จุดกันสุดท้ายก่อนยิงเข้า firewall จริง (แม้ parse ชั้นแรกกรองไปแล้ว
            # ก็ยังตรวจซ้ำตรงนี้เป็น defense-in-depth)
            echo -e "${RED}  [SKIP] ค่า '$ip' ไม่ใช่ IP ที่ถูกต้อง — ข้ามการแบน (ไม่ส่งเข้า firewall)${NC}"
            echo "  [SKIP] '$ip' ไม่ใช่ IP ที่ถูกต้อง ข้ามการแบน" >> "$OUTPUT_FILE"
            action="ban_failed"
        elif is_allowlisted "$ip"; then
            echo -e "${CYAN}  [ALLOWLIST] $ip อยู่ใน allowlist — ข้ามการแบนตามนโยบาย${NC}"
            echo "  [ALLOWLIST] $ip อยู่ใน allowlist ข้ามการแบน" >> "$OUTPUT_FILE"
            action="alerted"
        else
            tool=$(firewall_tool_for "$ip")
            if [ "$DRY_RUN" -eq 1 ]; then
                # Dry-run ต้องไม่แก้ firewall จริงและไม่บันทึกว่า "banned" —
                # action ยังคงเป็นค่า default "alerted" ต่อไป ไม่ถูกแก้ในสาขานี้
                echo -e "${YELLOW}  [DRY-RUN] จะรัน: $tool -A INPUT -s $ip -j DROP${NC}"
                echo "  [DRY-RUN] $tool -A INPUT -s $ip -j DROP" >> "$OUTPUT_FILE"
            elif ! command -v "$tool" >/dev/null 2>&1; then
                # Fail-safe: ระบบไม่มี iptables/ip6tables ตัวที่จำเป็นสำหรับ IP
                # ชนิดนี้ (เช่น เจอ IPv6 แต่เครื่องไม่มี ip6tables) — ข้ามแบบมี
                # เหตุผลชัดเจน ไม่ error ล้มทั้งสคริปต์
                echo -e "${RED}  [SKIP] ไม่พบคำสั่ง $tool บนระบบนี้ — ข้ามการแบน $ip (fail-safe)${NC}"
                echo "  [SKIP] ไม่พบ $tool บนระบบนี้ ข้ามการแบน $ip" >> "$OUTPUT_FILE"
                action="ban_failed"
            elif is_already_banned "$ip" "$tool"; then
                echo -e "${CYAN}  [SKIP] $ip ถูกแบนอยู่แล้วใน $tool${NC}"
                echo "  [SKIP] $ip ถูกแบนอยู่แล้ว ($tool)" >> "$OUTPUT_FILE"
                action="already_banned"
            else
                if "$tool" -A INPUT -s "$ip" -j DROP 2>/dev/null; then
                    banned_at=$(date '+%Y-%m-%d %H:%M:%S')
                    echo -e "${GREEN}  [BANNED] $ip ถูกบล็อกผ่าน $tool แล้ว${NC}"
                    echo "  [BANNED] $ip ถูกบล็อกเมื่อ $banned_at ($tool)" >> "$OUTPUT_FILE"
                    action="banned"
                    BANNED_COUNT=$((BANNED_COUNT + 1))
                else
                    echo -e "${RED}  [FAILED] ไม่สามารถแบน $ip ผ่าน $tool ได้${NC}"
                    echo "  [FAILED] ไม่สามารถแบน $ip ได้ ($tool)" >> "$OUTPUT_FILE"
                    action="ban_failed"
                fi
            fi
        fi
    fi

    log_to_db "$ip" "$count" "$action" "$banned_at"
done < <(for ip in "${!ALERT_RESULTS[@]}"; do echo "${ALERT_RESULTS[$ip]} $ip"; done | sort -rn)

# เดิมเรียก flush_db_batch เฉยๆ แล้วพิมพ์ "บันทึกผลลง Database" แบบไม่มีเงื่อนไข
# ไม่ว่า sqlite3 จะเขียนสำเร็จจริงหรือไม่ — ตอนนี้เช็ค exit code จริงก่อนสรุปผล
DB_FLUSH_OK=1
if [ "$DB_READY" -eq 1 ]; then
    if ! flush_db_batch; then
        DB_FLUSH_OK=0
        echo -e "${RED}[!] บันทึกผลลง Database ล้มเหลว (sqlite3 คืนค่า exit code ไม่ใช่ 0) — ข้อมูลรอบนี้ไม่ถูกบันทึกลง $DB_FILE${NC}" >&2
    fi
else
    DB_FLUSH_OK=0
fi

echo "-------------------------------------------"

if (( ALERT_COUNT > 0 )); then
    echo -e "${YELLOW}แสกนเสร็จสิ้น พบความผิดปกติ $ALERT_COUNT รายการ${NC} - ดูรายละเอียดที่ $OUTPUT_FILE"
    [ $AUTO_BAN -eq 1 ] && [ $DRY_RUN -eq 0 ] && echo -e "${GREEN}บล็อก IP ใหม่ ไปทั้งหมด $BANNED_COUNT รายการ${NC}"
else
    echo -e "${GREEN}แสกนเสร็จสิ้น ไม่พบความผิดปกติ${NC}"
fi

if [ "$DB_FLUSH_OK" -eq 1 ]; then
    echo -e "${CYAN}บันทึกผลลง Database สำเร็จ: $DB_FILE (ตาราง ips_logs)${NC}"
    DB_STATUS_TEXT="สำเร็จ"
else
    echo -e "${RED}คำเตือน: ไม่สามารถยืนยันได้ว่าบันทึกผลลง Database ($DB_FILE) สำเร็จ โปรดตรวจสอบ${NC}" >&2
    DB_STATUS_TEXT="ล้มเหลว — โปรดตรวจสอบ $DB_FILE"
fi

{
    echo ""
    echo "สรุป: พบ IP ที่น่าสงสัยทั้งหมด $ALERT_COUNT รายการ"
    [ $AUTO_BAN -eq 1 ] && echo "บล็อก IP ใหม่ $BANNED_COUNT รายการ"
    echo "บันทึกลง Database: $DB_STATUS_TEXT"
} >> "$OUTPUT_FILE"

# exit code สะท้อนผลจริง: 0 = สแกนและบันทึกสำเร็จ, 2 = สแกนสำเร็จแต่บันทึก DB
# ไม่สำเร็จ (ให้ wrapper อย่าง MICROSOC.sh ตรวจจับ stage failure ได้ถูกต้อง)
if [ "$DB_FLUSH_OK" -eq 1 ]; then
    exit 0
else
    exit 2
fi