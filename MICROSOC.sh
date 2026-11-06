#!/bin/bash

#===========================================================
# MICROSOC.sh — รันระบบ Micro-SOC ทั้งชุดในคำสั่งเดียว
# Created by Khawtommat
# วิธีใช้: ./MICROSOC.sh  (จะถามหาไฟล์ log และ target แบบ interactive)
#
# v2 ของ Launcher นี้ — แก้ให้ตรงกับ Interface จริงของสคริปต์ลูก
# ฉบับที่แก้ไขแล้ว (Log_Sentinel.sh / Smart_Recon.sh /
# Micro_SOC_Report.sh) และปิดช่องโหว่ด้าน Safety เดิม:
#
#   1) Log_Sentinel.sh เวอร์ชันล่าสุดรองรับ -A (allowlist) และ -n
#      (dry-run) เพิ่มจากเดิม (-f -t -w -o -d -b -L -h) และคืน
#      exit code 2 เมื่อ "สแกนสำเร็จแต่บันทึก DB ไม่สำเร็จ" ซึ่งเดิม
#      Launcher นี้มองว่า exit ไม่ใช่ 0 = fail ทั้งหมดเหมือนกันหมด
#      ไม่แยกว่าเป็นแค่ partial — แก้ให้แยกสถานะนี้ออกมาเป็น PARTIAL
#   2) เดิม Auto-Ban (-b) ถูกส่งไปสั่งแบน IP จริงทันทีที่ตอบ "y" ข้อเดียว
#      ไม่มีขั้นยืนยันแยกต่างหาก และไม่เคยส่ง -n (dry-run) ไปให้
#      Log_Sentinel.sh เลยทั้งที่สคริปต์รองรับอยู่แล้ว — แก้ให้ต้อง
#      พิมพ์ยืนยันคำว่า YES ชัดเจนอีกขั้นก่อนจะแก้ไข firewall จริง
#      ถ้าไม่ยืนยัน จะส่ง -b -n (dry-run) แทนโดย "ไม่แตะ firewall จริง"
#      เป็นค่าเริ่มต้นเสมอ
#   3) เดิมส่ง Flag หลายตัวเป็น String เดียวแล้วพึ่ง Word-Splitting
#      ตอนเรียกสคริปต์ลูก (เช่น $BAN_FLAG $LOW_FLAG) ซึ่งเปราะบางและ
#      debug ยาก — เปลี่ยนมาใช้ Bash Array ล้วนสำหรับประกอบ Arguments
#   4) เดิมเช็ค exit code แต่ละ stage แบบ boolean เดียว (STAGE_FAILED)
#      แล้วสรุปแค่ "เสร็จสิ้น" หรือ "เสร็จสิ้นแต่มี error" — เปลี่ยนเป็น
#      สถานะ SUCCESS / PARTIAL / FAILED ตามผลจริงของแต่ละ stage โดย
#      ถือว่า Micro_SOC_Report.sh (stage สุดท้าย ที่สร้าง dashboard.html)
#      ล้มเหลว = FAILED เสมอ เพราะคือผลลัพธ์สุดท้ายที่ผู้ใช้จะเห็น
#   5) เดิมไม่เช็ค python3 ทั้งที่ Smart_Recon.sh ต้องใช้เสมอ (ไม่ใช่แค่
#      ตอนเปิด feature เสริม) — เพิ่มเข้าไปในเช็ค dependency พื้นฐาน
#   6) เดิมพยายามเปิด dashboard.html อัตโนมัติเสมอแม้ Micro_SOC_Report.sh
#      จะ error (ไฟล์อาจไม่ถูกสร้าง/ไม่สมบูรณ์) — แก้ให้เปิดเฉพาะตอน
#      stage นั้นสำเร็จจริง (exit code 0) เท่านั้น
#===========================================================

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# หาตำแหน่งโฟลเดอร์ที่ไฟล์นี้อยู่จริง ไม่ว่าลูกค้าจะรันจากที่ไหนก็ตาม
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# เก็บโฟลเดอร์ที่ผู้ใช้ยืนอยู่ตอนรันคำสั่งไว้ก่อน cd — เพื่อให้ path แบบ relative
# ที่ผู้ใช้พิมพ์ตอนถูกถาม (เช่น -f auth.log, allowlist.txt) ถูก resolve จากตรงนั้น
# ไม่ใช่จากโฟลเดอร์ที่ตัวสคริปต์วางอยู่ (ซึ่งอาจเป็นคนละที่กัน)
ORIGINAL_DIR="$(pwd -P)"
cd "$SCRIPT_DIR" || exit 1

# DB กลางที่สคริปต์ลูกทั้ง 3 ตัวต้องใช้ร่วมกัน — ส่งแบบ explicit ให้ทุกตัว
# แทนที่จะพึ่งค่า default "microsoc.db" ภายในแต่ละสคริปต์เฉยๆ เพื่อกันไม่ให้
# หลุด sync กันถ้า default เปลี่ยนในอนาคต
DB_FILE="microsoc.db"
DASHBOARD_FILE="dashboard.html"

echo "==========================================================="
echo "Starting Micro-SOC..."
echo "==========================================================="

# ----------------------------------------------------------
# เช็คว่ามีไฟล์สคริปต์ลูกครบและรันได้ ก่อนเริ่มถามอะไรทั้งนั้น
# ชื่อไฟล์ตรงกับ Source Code จริง: Log_Sentinel.sh, Smart_Recon.sh,
# Micro_SOC_Report.sh (ไม่ใช่ micro_soc_report.sh — case-sensitive)
# ----------------------------------------------------------
for script in Log_Sentinel.sh Smart_Recon.sh Micro_SOC_Report.sh; do
    if [[ ! -f "$script" ]]; then
        echo -e "${RED}[!] Error: ไม่พบไฟล์ $script ใน $SCRIPT_DIR${NC}"
        exit 1
    fi
    if [[ ! -x "$script" ]]; then
        echo -e "${RED}[!] Error: $script ไม่มีสิทธิ์รัน (executable) — ลองรัน: chmod +x $script${NC}"
        exit 1
    fi
done

# ----------------------------------------------------------
# เช็คเครื่องมือพื้นฐานที่ "ทุกโหมด" ต้องใช้แน่ๆ ก่อนเริ่มถามอะไรทั้งนั้น
#   - sqlite3 / nmap : ใช้โดย Log_Sentinel.sh และ/หรือ Smart_Recon.sh เสมอ
#   - python3        : Smart_Recon.sh ใช้เสมอ (เดิม Launcher ไม่เคยเช็ค)
# ส่วน iptables/ip6tables/curl/gobuster/nikto เป็น dependency แบบมีเงื่อนไข
# จะเช็คอีกทีตอนผู้ใช้เลือกเปิดฟีเจอร์นั้นจริง (ด้านล่าง)
# ----------------------------------------------------------
MISSING=0
for bin in sqlite3 nmap python3; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบคำสั่ง '$bin' กรุณาติดตั้งก่อนใช้งาน Micro-SOC${NC}"
        MISSING=1
    fi
done
[ "$MISSING" -eq 1 ] && exit 1

# ----------------------------------------------------------
# บังคับรับค่าจากผู้ใช้ ไม่มี default — วนถามจนกว่าจะกรอกมาจริง
# ----------------------------------------------------------

LOG_FILE=""
while [ -z "$LOG_FILE" ]; do
    read -r -p "ระบุไฟล์ log ที่ต้องการตรวจสอบ (ห้ามเว้นว่าง): " LOG_FILE_IN
    if [ -z "$LOG_FILE_IN" ]; then
        echo "[!] ต้องระบุชื่อไฟล์ log ห้ามเว้นว่าง กรุณาลองใหม่"
        continue
    fi
    # ถ้าผู้ใช้พิมพ์ path แบบ relative ให้ resolve จากโฟลเดอร์ที่ผู้ใช้ยืนอยู่ตอนรัน
    # คำสั่ง (ORIGINAL_DIR) ไม่ใช่จาก SCRIPT_DIR ที่เรา cd เข้ามาแล้ว
    case "$LOG_FILE_IN" in
        /*) CANDIDATE="$LOG_FILE_IN" ;;
        *)  CANDIDATE="$ORIGINAL_DIR/$LOG_FILE_IN" ;;
    esac
    if [ ! -f "$CANDIDATE" ]; then
        echo -e "${RED}[!] ไม่พบไฟล์ '$LOG_FILE_IN' กรุณาลองใหม่${NC}"
    else
        LOG_FILE="$CANDIDATE"
    fi
done

THRESHOLD=""
while [ -z "$THRESHOLD" ]; do
    read -r -p "Threshold จำนวนครั้ง login ผิดพลาด [default: 5]: " THRESHOLD_IN
    THRESHOLD_IN="${THRESHOLD_IN:-5}"
    if [[ "$THRESHOLD_IN" =~ ^[0-9]+$ ]] && [ "$THRESHOLD_IN" -gt 0 ]; then
        THRESHOLD="$THRESHOLD_IN"
    else
        echo -e "${RED}[!] ต้องเป็นจำนวนเต็มบวกเท่านั้น (เช่น 5) กรุณาลองใหม่${NC}"
    fi
done

WINDOW_SECONDS=""
while [ -z "$WINDOW_SECONDS" ]; do
    read -r -p "ขนาด time window วินาที [default: 600 = 10 นาที]: " WINDOW_IN
    WINDOW_IN="${WINDOW_IN:-600}"
    if [[ "$WINDOW_IN" =~ ^[0-9]+$ ]] && [ "$WINDOW_IN" -gt 0 ]; then
        WINDOW_SECONDS="$WINDOW_IN"
    else
        echo -e "${RED}[!] ต้องเป็นจำนวนเต็มบวกเท่านั้น (เช่น 600) กรุณาลองใหม่${NC}"
    fi
done

TARGET=""
while [[ -z "$TARGET" ]]; do
    read -r -p "ระบุ IP ของเป้าหมาย (ห้ามเว้นว่าง): " TARGET_IN
    # เช็คแค่ -z จะผ่านกรณีกรอกแค่ space ได้ และไม่กันช่องว่างกลาง/ท้ายข้อความ
    TARGET_IN="${TARGET_IN#"${TARGET_IN%%[![:space:]]*}"}"   # trim leading space
    TARGET_IN="${TARGET_IN%"${TARGET_IN##*[![:space:]]}"}"   # trim trailing space
    if [ -z "$TARGET_IN" ]; then
        echo "[!] ต้องระบุ IP/โดเมนของเป้าหมาย ห้ามเว้นว่าง กรุณาลองใหม่"
    elif [[ "$TARGET_IN" =~ [[:space:]] ]]; then
        echo -e "${RED}[!] ระบุได้แค่เป้าหมายเดียว ห้ามมีช่องว่างในค่าที่กรอก${NC}"
    else
        TARGET="$TARGET_IN"
    fi
done

# ----------------------------------------------------------
# Auto-Ban: ต้องผ่าน 2 ขั้นก่อนจะแก้ไข firewall จริง
#   ขั้น 1) ถามว่าต้องการเปิด Auto-Ban หรือไม่ (เหมือนเดิม)
#   ขั้น 2) [ใหม่] ถ้าเปิด ต้องพิมพ์ยืนยันคำว่า "YES" (ตัวใหญ่ทั้งหมด)
#           อีกครั้งแบบชัดเจน ถ้าไม่พิมพ์ตรงตามนี้ จะส่ง -n (dry-run)
#           ให้ Log_Sentinel.sh แทนเสมอ — ค่าเริ่มต้นต้อง "ไม่แก้ไข
#           firewall จริง" ไม่ว่ากรณีใดก็ตามที่ไม่ได้ยืนยันชัดเจน
# LOG_SENTINEL_BAN_ARGS เป็น array เก็บ -b / -n / -A <file> ที่จะต่อท้าย
# เข้า Log_Sentinel.sh เท่านั้น ไม่ปนกับ argument อื่น
# ----------------------------------------------------------
LOG_SENTINEL_BAN_ARGS=()
read -r -p "ต้องการเปิด Auto-Ban เพื่อบล็อก IP ต้องสงสัยหรือไม่? (y/N): " ENABLE_BAN
if [[ "$ENABLE_BAN" =~ ^[Yy]$ ]]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] การเปิด Auto-Ban ต้องรันด้วยสิทธิ์ root — กรุณารันใหม่ด้วย: sudo ./MICROSOC.sh${NC}"
        exit 1
    fi
    # Log_Sentinel.sh เวอร์ชันล่าสุดรองรับทั้ง IPv4 (iptables) และ IPv6
    # (ip6tables) จึงพอแค่มีตัวใดตัวหนึ่งในระบบก็เพียงพอให้เปิดโหมดนี้ได้
    if ! command -v iptables >/dev/null 2>&1 && ! command -v ip6tables >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบทั้ง iptables และ ip6tables — ไม่สามารถเปิด Auto-Ban ได้${NC}"
        exit 1
    fi
    LOG_SENTINEL_BAN_ARGS+=(-b)

    # Allowlist (-A) เป็นฟีเจอร์เสริมของ Log_Sentinel.sh — กัน IP ที่รู้จัก
    # (เช่น IP ทีม/VPN/monitoring) ไม่ให้โดน Auto-Ban พลาด ไม่บังคับกรอก
    read -r -p "ระบุไฟล์ Allowlist (-A) กัน IP ไม่ให้ถูกแบน (เว้นว่างเพื่อข้าม): " ALLOWLIST_IN
    if [ -n "$ALLOWLIST_IN" ]; then
        case "$ALLOWLIST_IN" in
            /*) ALLOWLIST_CANDIDATE="$ALLOWLIST_IN" ;;
            *)  ALLOWLIST_CANDIDATE="$ORIGINAL_DIR/$ALLOWLIST_IN" ;;
        esac
        if [ -f "$ALLOWLIST_CANDIDATE" ]; then
            LOG_SENTINEL_BAN_ARGS+=(-A "$ALLOWLIST_CANDIDATE")
            echo "[*] ใช้ Allowlist: $ALLOWLIST_CANDIDATE"
        else
            echo -e "${YELLOW}[!] ไม่พบไฟล์ '$ALLOWLIST_IN' — ข้าม Allowlist รอบนี้ (จะใช้แค่ loopback default ของ Log_Sentinel.sh)${NC}"
        fi
    fi

    echo -e "${YELLOW}[!] คำเตือน: ขั้นตอนถัดไปจะอนุญาตให้ระบบแก้ไข iptables/ip6tables จริงบนเครื่องนี้${NC}"
    read -r -p "พิมพ์ YES (ตัวพิมพ์ใหญ่ทั้งหมด) เพื่อยืนยันการบล็อกจริง — ค่าอื่นใดจะถือว่าไม่ยืนยัน: " CONFIRM_BAN
    if [ "$CONFIRM_BAN" = "YES" ]; then
        echo -e "${RED}[*] ยืนยันแล้ว — Auto-Ban จะแก้ไข firewall จริงเมื่อเจอ IP ที่เข้าเกณฑ์${NC}"
    else
        LOG_SENTINEL_BAN_ARGS+=(-n)
        echo -e "${CYAN}[*] ไม่ได้พิมพ์ YES ยืนยัน — รัน Auto-Ban แบบ Dry-run เท่านั้น (จะไม่มีการแก้ไข firewall จริงในรอบนี้)${NC}"
    fi
else
    echo "[*] โหมด Auto-Ban ปิดอยู่ — จะแค่แจ้งเตือน ไม่บล็อกอัตโนมัติ"
fi

read -r -p "ต้องการลดภาระเครื่อง/เน็ตเวิร์กตอนรัน (low-impact + gentle scan) หรือไม่? (y/N): " ENABLE_LOW
LOW_IMPACT_ON=0
if [[ "$ENABLE_LOW" =~ ^[Yy]$ ]]; then
    LOW_IMPACT_ON=1
    echo "[*] เปิดโหมดลดภาระเครื่อง/เครือข่ายแล้ว"
fi

read -r -p "ต้องการรัน Nmap Deep Scan (-sC -sV) กับเป้าหมายด้วยหรือไม่? (y/N): " ENABLE_DEEP
DEEP_ON=0
[[ "$ENABLE_DEEP" =~ ^[Yy]$ ]] && DEEP_ON=1

echo ""
echo "เลือก Web Reconnaissance Tool (ใช้เมื่อเจอ port ที่ nmap รายงานเป็น Web Service):"
echo "  1) Gobuster   2) Nikto   3) ทั้งคู่   4) ข้าม"
read -r -p "เลือกเมนู [1-4] (default: 4): " WEB_NUM
case "${WEB_NUM:-4}" in
    1) WEB_CHOICE="gobuster" ;;
    2) WEB_CHOICE="nikto" ;;
    3) WEB_CHOICE="both" ;;
    *) WEB_CHOICE="skip" ;;
esac
# WEB_CHOICE ถูกจำกัดด้วย case ด้านบนให้เป็นหนึ่งใน gobuster|nikto|both|skip
# เสมอ ตรงกับค่าที่ Smart_Recon.sh --web=<value> ยอมรับพอดี จึงส่งต่อได้ตรงๆ
if [[ "$WEB_CHOICE" != "skip" ]]; then
    if [[ "$WEB_CHOICE" == "gobuster" || "$WEB_CHOICE" == "both" ]] && ! command -v gobuster >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ไม่พบคำสั่ง 'gobuster' — Smart_Recon.sh จะข้าม Gobuster ให้อัตโนมัติ${NC}"
    fi
    if [[ "$WEB_CHOICE" == "nikto" || "$WEB_CHOICE" == "both" ]] && ! command -v nikto >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ไม่พบคำสั่ง 'nikto' — Smart_Recon.sh จะข้าม Nikto ให้อัตโนมัติ${NC}"
    fi
fi

echo ""
read -r -p "Export ผลลัพธ์เป็นไฟล์เพิ่มด้วยไหม? (csv/json/none) [default: csv]: " EXPORT_IN
EXPORT_FORMAT="${EXPORT_IN:-csv}"
EXPORT_FORMAT="${EXPORT_FORMAT,,}"   # กันกรณีพิมพ์ "CSV"/"JSON" ตัวใหญ่แล้วหลุดไปเป็น "none" เงียบๆ
if [[ "$EXPORT_FORMAT" != "csv" && "$EXPORT_FORMAT" != "json" ]]; then
    EXPORT_FORMAT="none"
fi

# หาโฮมไดเรกทอรีของ "ผู้ใช้จริง" ที่สั่ง sudo ไม่ใช่ของ root
# (sudo รีเซ็ต $HOME เป็น /root โดย default ทำให้หา telegram.env ไม่เจอ
#  เวลารันด้วย sudo ซึ่งเป็นเคสปกติของสคริปต์นี้เพราะ Auto-Ban ก็ต้องใช้ root)
if [ -n "${SUDO_USER:-}" ]; then
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    REAL_HOME="$HOME"
fi


# เดิมหา telegram.env ที่เดียวคือ $REAL_HOME/microsoc/telegram.env เท่านั้น
# ถ้าผู้ใช้วางไฟล์ไว้ข้างๆ สคริปต์เอง (เคสที่พบบ่อยที่สุด) จะหาไม่เจอแล้ว
# ข้ามการส่ง Telegram ไปแบบเงียบๆ โดยไม่มี error ใดๆ ให้สังเกต — เพิ่มให้
# ลองหาใน SCRIPT_DIR ก่อน แล้วค่อย fallback ไปที่ path เดิมเพื่อความ
# เข้ากันได้ย้อนหลังกับ setup เดิมที่วางไว้ใน ~/microsoc/
TELEGRAM_ENV_CANDIDATES=(
    "$SCRIPT_DIR/telegram.env"
    "${REAL_HOME:-$HOME}/microsoc/telegram.env"
)
if [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
    for TELEGRAM_ENV in "${TELEGRAM_ENV_CANDIDATES[@]}"; do
        if [ -r "$TELEGRAM_ENV" ]; then
            # shellcheck disable=SC1090
            source "$TELEGRAM_ENV"
            break
        fi
    done
fi

echo ""
read -r -p "ต้องการส่งสรุปเข้า Telegram ด้วยหรือไม่? (y/N): " ENABLE_TELEGRAM
TELEGRAM_ON=0
if [[ "$ENABLE_TELEGRAM" =~ ^[Yy]$ ]]; then
    if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
        echo "[!] ยังไม่ได้ตั้งค่า TELEGRAM_BOT_TOKEN และ/หรือ TELEGRAM_CHAT_ID ในเครื่อง — ข้ามการส่ง Telegram รอบนี้"
    elif ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบคำสั่ง curl — ข้ามการส่ง Telegram รอบนี้${NC}"
    else
        TELEGRAM_ON=1
        echo "[*] เปิดใช้งานส่งสรุปเข้า Telegram แล้ว"
    fi
else
    echo "[*] ไม่ส่งสรุปเข้า Telegram"
fi

echo ""
IPINTEL_ON=0
if [ -f "$SCRIPT_DIR/IP_Intel.sh" ]; then
    read -r -p "ต้องการรัน IP Intelligence & Threat Investigation ด้วยหรือไม่? (y/N): " ENABLE_IPINTEL
    if [[ "$ENABLE_IPINTEL" =~ ^[Yy]$ ]]; then
        IPINTEL_ON=1
        echo "[*] เปิดใช้งาน IP Intelligence แล้ว (จะรันหลัง Micro_SOC_Report.sh เสร็จ)"
    else
        echo "[*] ไม่รัน IP Intelligence รอบนี้"
    fi
fi

# ----------------------------------------------------------
# ประกอบ Arguments ของสคริปต์ลูกแต่ละตัวด้วย Bash Array (ไม่พึ่ง
# Word-Splitting ของ String ธรรมดา) ตรงตาม getopts/flag ของไฟล์จริง:
#   Log_Sentinel.sh    : getopts "f:t:w:o:d:A:bnLh"
#   Smart_Recon.sh     : TARGET --non-interactive --deep --web=X --db=X
#                         --gentle --low-impact
#   Micro_SOC_Report.sh: getopts ":d:o:e:x:h"  (+ --telegram แยกนอก getopts)
# ----------------------------------------------------------
LOG_SENTINEL_ARGS=(-f "$LOG_FILE" -t "$THRESHOLD" -w "$WINDOW_SECONDS" -d "$DB_FILE")
[ "$LOW_IMPACT_ON" -eq 1 ] && LOG_SENTINEL_ARGS+=(-L)
LOG_SENTINEL_ARGS+=("${LOG_SENTINEL_BAN_ARGS[@]}")

SMART_RECON_ARGS=("$TARGET" --non-interactive --web="$WEB_CHOICE" --db="$DB_FILE")
[ "$DEEP_ON" -eq 1 ] && SMART_RECON_ARGS+=(--deep)
if [ "$LOW_IMPACT_ON" -eq 1 ]; then
    SMART_RECON_ARGS+=(--gentle --low-impact)
fi

REPORT_ARGS=(-d "$DB_FILE" -o "$DASHBOARD_FILE")
[ "$EXPORT_FORMAT" != "none" ] && REPORT_ARGS+=(-e "$EXPORT_FORMAT")
[ "$TELEGRAM_ON" -eq 1 ] && REPORT_ARGS+=(--telegram)

# ----------------------------------------------------------
# รันแต่ละ Stage แล้วเก็บ exit code จริงไว้แยกตัวแปร (set -uo pipefail
# ไม่มี -e จึงรันต่อได้ทุก stage แม้ตัวก่อนหน้าจะ error — ปลอดภัยที่จะทำแบบนี้
# เพราะทั้ง 3 stage เขียนลง DB/ไฟล์คนละส่วนกัน ไม่ได้พึ่งผลลัพธ์ของกันและกัน
# โดยตรง) แล้วค่อยสรุปสถานะจริงตอนท้าย แทนที่จะพิมพ์ "เสร็จสิ้น!" เหมา
# ----------------------------------------------------------

# จำนวน step ทั้งหมดที่จะรันจริง ขึ้นกับว่าเปิด IP Intelligence หรือไม่
# (ใช้แค่ทำ label [n/TOTAL] ให้ตรงกับที่รันจริง ไม่กระทบ logic อื่น)
TOTAL_STEPS=3
[ "$IPINTEL_ON" -eq 1 ] && TOTAL_STEPS=4

echo ""
echo "[1/$TOTAL_STEPS] Starting Log_Sentinel..."
./Log_Sentinel.sh "${LOG_SENTINEL_ARGS[@]}"
STAGE1_EXIT=$?
case "$STAGE1_EXIT" in
    0) : ;;
    2)
        # exit=2 ตามสัญญาของ Log_Sentinel.sh ฉบับแก้ไขแล้ว = สแกนสำเร็จ
        # แต่บันทึกผลลง Database ไม่สำเร็จ — ถือเป็น partial ไม่ใช่ fail เต็มรูป
        echo -e "${YELLOW}[!] Log_Sentinel.sh: สแกนสำเร็จ แต่บันทึกผลลง Database ไม่สำเร็จ (exit=2) — ข้อมูล login ผิดพลาดใน dashboard อาจไม่ครบ${NC}"
        ;;
    *)
        echo -e "${RED}[!] Log_Sentinel.sh จบด้วย error (exit=$STAGE1_EXIT) — ข้อมูล login ผิดพลาดใน dashboard อาจไม่ครบ${NC}"
        ;;
esac

echo ""
echo "[2/$TOTAL_STEPS] Starting Smart Recon..."
./Smart_Recon.sh "${SMART_RECON_ARGS[@]}"
STAGE2_EXIT=$?
if [ "$STAGE2_EXIT" -ne 0 ]; then
    echo -e "${RED}[!] Smart_Recon.sh จบด้วย error (exit=$STAGE2_EXIT) — ข้อมูล recon ใน dashboard อาจไม่ครบ${NC}"
fi

# ----------------------------------------------------------
# IP Intelligence เป็น stage เสริม ไม่บังคับ และไม่มีผลต่อ SUCCESS/PARTIAL/
# FAILED ของ 3 stage หลักเลย (ดู OVERALL_STATUS ด้านล่าง ซึ่งคำนวณจาก
# STAGE1/STAGE2/STAGE3 เท่านั้น ไม่รวม STAGE_IPINTEL_EXIT)
#
# ***ย้ายมารันตรงนี้ — ก่อน Micro_SOC_Report.sh โดยตั้งใจ***
# เหตุผล: Micro_SOC_Report.sh จะใส่ลิงก์/badge "เปิด IP Investigation"
# บน dashboard.html ก็ต่อเมื่อไฟล์ ip_investigation.html มีอยู่แล้วใน
# PROJECT_ROOT ณ ตอนที่มันรัน (ดู Micro_SOC_Report.sh บรรทัดที่เช็ค
# `-f "$PROJECT_ROOT/ip_investigation.html"`) — เดิม Launcher รัน
# IP_Intel.sh หลัง Micro_SOC_Report.sh เสมอ ทำให้ไฟล์ยังไม่ถูกสร้าง
# ตอนที่ Micro_SOC_Report.sh เช็ค ลิงก์/badge เลยไม่ขึ้นใน dashboard.html
# ของรอบนั้นแม้จะเปิดใช้ IP Intelligence ก็ตาม ต้องรออีก 1 รอบถัดไป
# การสลับลำดับมารันก่อนตรงนี้ทำให้ ip_investigation.html พร้อมใช้งาน
# ก่อนที่ Micro_SOC_Report.sh จะสร้าง dashboard.html เสมอ — Micro_SOC_Report.sh
# ยังคงเป็น stage สุดท้ายที่รันอยู่ดี (ตามคอมเมนต์เดิมที่ว่ามันคือ
# ผลลัพธ์สุดท้ายที่ผู้ใช้จะเห็น) ความเสี่ยงสูง/วิกฤต (ถ้าพบ) จะถูกแจ้ง
# ผ่าน Telegram จากภายใน IP_Intel.sh เอง (ดู --telegram ของสคริปต์นั้น)
# ----------------------------------------------------------
STAGE_IPINTEL_RAN=0
if [ "$IPINTEL_ON" -eq 1 ]; then
    echo ""
    echo "[3/$TOTAL_STEPS] Starting IP Intelligence & Threat Investigation..."
    IPINTEL_ARGS=(-d "$DB_FILE")
    [ "$TELEGRAM_ON" -eq 1 ] && IPINTEL_ARGS+=(--telegram)
    ./IP_Intel.sh "${IPINTEL_ARGS[@]}"
    STAGE_IPINTEL_EXIT=$?
    STAGE_IPINTEL_RAN=1
    if [ "$STAGE_IPINTEL_EXIT" -ne 0 ]; then
        echo -e "${RED}[!] IP_Intel.sh จบด้วย error (exit=$STAGE_IPINTEL_EXIT) — อาจไม่มีไฟล์ ip_investigation.html ให้ dashboard.html อ้างถึง และไม่กระทบสถานะรวมของ 3 stage หลักด้านล่าง${NC}"
    fi
fi

echo ""
echo "[$TOTAL_STEPS/$TOTAL_STEPS] Starting Micro SOC Report..."
./Micro_SOC_Report.sh "${REPORT_ARGS[@]}"
STAGE3_EXIT=$?
if [ "$STAGE3_EXIT" -ne 0 ]; then
    echo -e "${RED}[!] Micro_SOC_Report.sh จบด้วย error (exit=$STAGE3_EXIT) — dashboard.html อาจไม่ถูกสร้าง/ไม่สมบูรณ์${NC}"
fi

# ----------------------------------------------------------
# สรุปสถานะจริงของทั้งชุด:
#   SUCCESS — ทุก stage exit 0
#   PARTIAL — Micro_SOC_Report.sh (stage ที่สร้าง dashboard.html ซึ่งเป็น
#             ผลลัพธ์สุดท้ายที่ผู้ใช้ดู) สำเร็จ แต่มี stage ก่อนหน้า error/partial
#   FAILED  — Micro_SOC_Report.sh เอง error (dashboard.html อาจไม่ถูกสร้าง
#             หรือไม่สมบูรณ์ ถือเป็น fail เสมอไม่ว่า stage อื่นจะเป็นอย่างไร)
# (STAGE_IPINTEL_EXIT ไม่ถูกนำมาคำนวณ OVERALL_STATUS เหมือนเดิมทุกประการ)
# ----------------------------------------------------------
if [ "$STAGE3_EXIT" -ne 0 ]; then
    OVERALL_STATUS="FAILED"
    OVERALL_EXIT=2
elif [ "$STAGE1_EXIT" -ne 0 ] || [ "$STAGE2_EXIT" -ne 0 ]; then
    OVERALL_STATUS="PARTIAL"
    OVERALL_EXIT=1
else
    OVERALL_STATUS="SUCCESS"
    OVERALL_EXIT=0
fi

echo ""
echo "==========================================================="
case "$OVERALL_STATUS" in
    SUCCESS)
        echo -e "${GREEN}สถานะ: SUCCESS — ทุก stage ทำงานสำเร็จ${NC}"
        ;;
    PARTIAL)
        echo -e "${YELLOW}สถานะ: PARTIAL — สร้าง dashboard.html สำเร็จ แต่มีบาง stage มีปัญหา (ดู error ด้านบน) กรุณาตรวจสอบก่อนเชื่อผลทั้งหมดใน dashboard${NC}"
        ;;
    FAILED)
        echo -e "${RED}สถานะ: FAILED — Micro_SOC_Report.sh ล้มเหลว dashboard.html อาจไม่สมบูรณ์หรือไม่ถูกสร้างเลย${NC}"
        ;;
esac
echo "  - Log_Sentinel.sh     : exit=$STAGE1_EXIT"
echo "  - Smart_Recon.sh      : exit=$STAGE2_EXIT"
[ "$STAGE_IPINTEL_RAN" -eq 1 ] && echo "  - IP_Intel.sh         : exit=$STAGE_IPINTEL_EXIT"
echo "  - Micro_SOC_Report.sh : exit=$STAGE3_EXIT"
echo "Dashboard: $SCRIPT_DIR/$DASHBOARD_FILE"
[[ "$EXPORT_FORMAT" != "none" ]] && echo "Export ($EXPORT_FORMAT): $SCRIPT_DIR/exports/"
echo "==========================================================="

# พยายามเปิด dashboard อัตโนมัติถ้ามีโปรแกรมเปิดเบราว์เซอร์ให้ใช้ (เครื่อง desktop)
# — เปิดเฉพาะตอน Micro_SOC_Report.sh สำเร็จจริง (exit=0) เท่านั้น เดิมพยายาม
# เปิดเสมอแม้ dashboard.html จะไม่ถูกสร้าง/ไม่สมบูรณ์เพราะ stage นี้ error
if [ "$STAGE3_EXIT" -eq 0 ]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$SCRIPT_DIR/$DASHBOARD_FILE" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$SCRIPT_DIR/$DASHBOARD_FILE" >/dev/null 2>&1 &
    fi
fi

exit "$OVERALL_EXIT"