#!/usr/bin/bash

# ========================================
# Smart Recon & Report Script — Micro-SOC Edition
# v3: ปรับให้ตรงกับ Schema Contract (schema.sql v2):
#   - ใช้ Nmap XML (-oX) แยกพอร์ต/บริการ/สถานะอย่างมีโครงสร้าง แทนการ
#     grep ข้อความ -oN ล้วน ๆ และใช้ชื่อ service ของ Nmap เป็นหลักฐาน
#     ว่าพอร์ตนั้นเป็น Web Service หรือไม่ (ไม่สมมติว่าทุกพอร์ตเป็นเว็บ)
#   - ตรวจ dependency (nmap, python3, sqlite3 เสมอ / gobuster, nikto,
#     wordlist เฉพาะตอนจะใช้งานจริง) ก่อนเรียกใช้ทุกครั้ง
#   - แยกตรวจ exit code ของ nmap (fast/deep แยกกัน), gobuster และ nikto
#     (แยกต่อ URL ที่สแกน) ไม่ยอมรายงานว่าสำเร็จถ้าคำสั่งล้มเหลวจริง
#   - บันทึก scan_scope/status ลง recon_scans (completed/failed) และ
#     บันทึกผล Gobuster/Nikto ลง web_recon_results ตาม Schema Contract
#   - แยก "สถานะปัจจุบัน" ของพอร์ต (recon_assets) ออกจาก "ประวัติ"
#     (recon_port_history แบบ append-only) และไม่ถือว่าพอร์ตที่ไม่พบ
#     เพราะสแกนล้มเหลว/ไม่ครบ เป็นพอร์ตปิด
#   - แก้บั๊ก HTML escaping ของ $TARGET ที่เดิมไม่ได้ escape ก่อนพิมพ์
#     ลง report.html (stored XSS ได้ถ้า TARGET มาจาก input ภายนอก)
#   - DB schema migration แบบ self-healing (เติมคอลัมน์ที่ขาดให้ DB เดิม
#     โดยอัตโนมัติ ไม่ทำลายข้อมูลเดิม) ทุกครั้งที่รัน
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
GENTLE=0
LOW_IMPACT=0
EXIT_CODE=0   # เปลี่ยนเป็น 1 ทุกครั้งที่มีขั้นตอนใดล้มเหลวจริง (ใช้ตรวจสอบจาก cron ได้)

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
        --gentle) GENTLE=1 ;;
        --low-impact) LOW_IMPACT=1 ;;
        -h|--help)
            cat <<EOF
วิธีใช้:
  โหมด interactive (ถามทีละขั้น):
    ./Smart_Recon.sh TARGET

  โหมด cron / non-interactive:
    ./Smart_Recon.sh TARGET --non-interactive [--deep] [--web=gobuster|nikto|both|skip] [--db=path] [--gentle] [--low-impact]

  --gentle       สแกนช้าลง (nmap -T2, gobuster threads น้อยลง) ลดภาระฝั่ง target/server ที่สแกน
  --low-impact   ลด CPU/IO priority ของ process ตัวเอง (renice/ionice) บนเครื่องที่รัน script

ตัวอย่าง cron ทุกเที่ยงคืน:
  0 0 * * *  /path/Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip --gentle

หมายเหตุ: web recon (gobuster/nikto) จะยิงเฉพาะพอร์ตที่ Nmap รายงานชื่อ
service เป็นกลุ่ม http/https เท่านั้น (ไม่สมมติว่าพอร์ตอื่นเป็นเว็บ)
และ exit code ของ nmap/gobuster/nikto ทุกตัวจะถูกเช็คแยกกัน หากล้มเหลว
จะไม่ถูกบันทึกว่า "สำเร็จ" ใน database

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

# ----------------------------------------------------------
# ตรวจ dependency ที่ "จำเป็นเสมอ" ก่อนเริ่มงานใด ๆ
# (gobuster/nikto/wordlist ตรวจแยกทีหลัง เฉพาะตอนจะใช้งานจริง
#  เพราะ web recon เป็นขั้นตอนทางเลือก ไม่ควรทำให้ network scan ล้มไปด้วย)
# ----------------------------------------------------------
missing_dep=0
for dep in nmap python3 sqlite3; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo -e "${RED}[!] ERROR:${NC} ไม่พบคำสั่ง '$dep' กรุณาติดตั้งก่อนใช้งานสคริปต์นี้"
        missing_dep=1
    fi
done
[ "$missing_dep" -eq 1 ] && exit 1

NMAP_TIMING="-T4"
GOBUSTER_THREADS=10
if [ "$GENTLE" -eq 1 ]; then
    NMAP_TIMING="-T2"
    GOBUSTER_THREADS=5
    echo -e "${CYAN}[*] Gentle mode: สแกนช้าลงเพื่อลดภาระฝั่ง target${NC}"
fi

if [ "$LOW_IMPACT" -eq 1 ]; then
    renice -n 15 -p $$ >/dev/null 2>&1
    command -v ionice >/dev/null 2>&1 && ionice -c 3 -p $$ >/dev/null 2>&1
    echo -e "${CYAN}[*] Low-impact mode: ลด priority ของ process ลงแล้ว${NC}"
fi

# TARGET อาจมีอักขระที่ใช้ตั้งชื่อ directory ไม่ได้ (หรือเป็นอันตรายต่อ path)
# ใช้ตัวแปรแยกสำหรับตั้งชื่อโฟลเดอร์เท่านั้น ส่วน $TARGET ตัวจริงยังใช้
# สแกน/แสดงผลตามปกติ — ป้องกัน report_path ที่ dashboard ใช้ทำ relative
# link พังเพราะ TARGET มี "/" หรืออักขระแปลก ๆ ปน
TARGET_SAFE=$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
OUTPUT_DIR="smart_report_${TARGET_SAFE}_${DATE}"
echo "[*] Target: $TARGET"
echo "[*] Creating Directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ----------------------------------------------------------
# ลิงก์ "กลับไป Dashboard" สำหรับทุกหน้า HTML ที่สคริปต์นี้สร้าง (report.html,
# GOBUSTER_*.log.html, NIKTO_*.txt.html) — หน้าเหล่านี้อยู่ใน $OUTPUT_DIR ซึ่ง
# เป็นโฟลเดอร์ย่อยลึกลงไป 1 ชั้นจาก project root (ที่ dashboard.html อยู่)
# เสมอ จึงใช้ path "../dashboard.html" ได้ตรงๆ ถ้ามีไฟล์นั้นจริง (เช็คก่อน
# เพื่อไม่ให้โชว์ลิงก์ตายในกรณีที่ยังไม่เคยรัน Micro_SOC_Report.sh)
# ----------------------------------------------------------
WEB_BACK_TO_DASHBOARD_HTML=""
WEB_BACK_TO_DASHBOARD_HTML_LIGHT=""
WEB_PROJECT_ROOT=$(cd "$(dirname -- "$OUTPUT_DIR")" 2>/dev/null && pwd -P)
if [ -n "$WEB_PROJECT_ROOT" ] && [ -f "$WEB_PROJECT_ROOT/dashboard.html" ]; then
    # ใช้บนพื้นหลังเข้ม (header ไล่สีของ create_web_report_html)
    WEB_BACK_TO_DASHBOARD_HTML='<a href="../dashboard.html" style="display:inline-block;margin-top:10px;padding:6px 14px;border-radius:999px;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.28);color:#fff;font-size:12px;font-weight:700;text-decoration:none">← กลับไป Dashboard</a>'
    # ใช้บนพื้นหลังขาว/อ่อน (report.html ทั้ง 2 เวอร์ชัน) — สีตัวอักษรเข้ม
    # เพื่อให้อ่านออกบนพื้นขาว ต่างจากตัวบนที่ตัวอักษรขาวบนพื้นเข้ม
    WEB_BACK_TO_DASHBOARD_HTML_LIGHT='<a href="../dashboard.html" style="display:inline-block;margin-bottom:14px;padding:6px 14px;border-radius:999px;background:#eef3f8;border:1px solid #c6d5e4;color:#1468a8;font-size:13px;font-weight:700;text-decoration:none">← กลับไป Dashboard</a>'
fi

# ----------------------------------------------------------
# เตรียม DB: สร้าง schema (v2) ถ้ายังไม่มี + เติมคอลัมน์ที่ขาดให้ DB เดิม
# แบบ self-healing (idempotent, ไม่ทำลายข้อมูลเดิม) ตาม Schema Contract
# ----------------------------------------------------------

init_db() {
    sqlite3 "$DB_FILE" <<'SQL'
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS recon_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    scan_type       TEXT    NOT NULL DEFAULT 'fast',
    scan_scope      TEXT,
    status          TEXT    NOT NULL DEFAULT 'completed'
                    CHECK (status IN ('running', 'completed', 'failed', 'partial')),
    new_ports_count INTEGER NOT NULL DEFAULT 0,
    total_ports     INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT,
    finished_at     TEXT,
    scanned_at      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_recon_scans_target ON recon_scans(target);
-- หมายเหตุ: idx_recon_scans_status สร้างทีหลัง (หลัง migrate_db) เพราะถ้า
-- recon_scans เป็นตารางเดิมที่ยังไม่มีคอลัมน์ status การสร้าง index ตรงนี้
-- จะ error ทันที (CREATE TABLE IF NOT EXISTS ไม่เพิ่มคอลัมน์ให้ตารางที่มีอยู่แล้ว)

CREATE TABLE IF NOT EXISTS recon_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL DEFAULT 'tcp',
    service         TEXT,
    version_info    TEXT,
    state           TEXT    NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open', 'closed', 'filtered', 'unknown')),
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    last_checked_at TEXT,
    last_scan_id    INTEGER REFERENCES recon_scans(id) ON DELETE SET NULL,
    is_new          INTEGER NOT NULL DEFAULT 1,
    UNIQUE(target, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_recon_assets_target ON recon_assets(target);
CREATE INDEX IF NOT EXISTS idx_recon_assets_state ON recon_assets(state);
-- idx_recon_assets_last_scan_id: เหตุผลเดียวกับ idx_recon_scans_status ด้านบน
-- (last_scan_id เป็นคอลัมน์ใหม่ อาจยังไม่มีในตารางเดิม) สร้างทีหลัง migrate_db

CREATE TABLE IF NOT EXISTS recon_port_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
    target          TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT    NOT NULL DEFAULT 'tcp',
    service         TEXT,
    version_info    TEXT,
    state           TEXT    NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open', 'closed', 'filtered')),
    observed_at     TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_recon_port_history_scan_id ON recon_port_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_port_history_target_port
    ON recon_port_history(target, port, protocol);

CREATE TABLE IF NOT EXISTS web_recon_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    url             TEXT    NOT NULL,
    tool            TEXT    NOT NULL CHECK (tool IN ('gobuster', 'nikto')),
    status          TEXT    NOT NULL DEFAULT 'completed'
                    CHECK (status IN ('running', 'completed', 'failed')),
    findings_count  INTEGER NOT NULL DEFAULT 0,
    summary         TEXT,
    report_path     TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    error_message   TEXT,
    scan_id         INTEGER REFERENCES recon_scans(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_web_recon_results_target ON web_recon_results(target);
CREATE INDEX IF NOT EXISTS idx_web_recon_results_tool ON web_recon_results(tool);
CREATE INDEX IF NOT EXISTS idx_web_recon_results_started_at ON web_recon_results(started_at);
CREATE INDEX IF NOT EXISTS idx_web_recon_results_scan_id ON web_recon_results(scan_id);
SQL
}
init_db

# เติมคอลัมน์ที่ขาดให้ DB เดิม (สร้างก่อน v2) โดยไม่แตะข้อมูลเดิมเลย
has_column() {
    local table="$1" col="$2"
    sqlite3 "$DB_FILE" "PRAGMA table_info($table);" 2>/dev/null \
        | awk -F'|' -v c="$col" '$2==c{found=1} END{exit !found}'
}
add_column_if_missing() {
    local table="$1" coldef="$2" colname="$3"
    if ! has_column "$table" "$colname"; then
        if sqlite3 "$DB_FILE" "ALTER TABLE $table ADD COLUMN $coldef;" 2>/dev/null; then
            echo -e "${CYAN}[*] Migration: เพิ่มคอลัมน์ ${table}.${colname}${NC}"
        else
            echo -e "${YELLOW}[!] คำเตือน: เพิ่มคอลัมน์ ${table}.${colname} ไม่สำเร็จ (อาจมีอยู่แล้ว)${NC}" >&2
        fi
    fi
}
add_column_if_missing recon_scans "scan_scope TEXT" scan_scope
add_column_if_missing recon_scans "status TEXT NOT NULL DEFAULT 'completed'" status
add_column_if_missing recon_scans "started_at TEXT" started_at
add_column_if_missing recon_scans "finished_at TEXT" finished_at
add_column_if_missing recon_assets "last_checked_at TEXT" last_checked_at
add_column_if_missing recon_assets "last_scan_id INTEGER REFERENCES recon_scans(id)" last_scan_id

# index บนคอลัมน์ใหม่ ต้องสร้าง "หลัง" ที่คอลัมน์มีอยู่แน่นอนแล้วเท่านั้น
# (ทั้งกรณี DB ใหม่ที่ init_db() เพิ่งสร้างคอลัมน์ไว้ และ DB เดิมที่เพิ่ง
# migrate เติมคอลัมน์ให้ด้านบน) ไม่เช่นนั้นจะ error กับ DB เดิมที่ยังไม่มี
# คอลัมน์นี้ตอน init_db() รัน CREATE TABLE IF NOT EXISTS (ซึ่งเป็น no-op
# สำหรับตารางที่มีอยู่แล้ว ไม่เพิ่มคอลัมน์ให้)
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_recon_scans_status ON recon_scans(status);" 2>/dev/null
sqlite3 "$DB_FILE" "CREATE INDEX IF NOT EXISTS idx_recon_assets_last_scan_id ON recon_assets(last_scan_id);" 2>/dev/null

sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }

# ป้องกัน HTML injection: ค่าอย่าง SERVICE/VERSION มาจาก banner ของ target เอง
# (ไม่ใช่ข้อมูลที่เรา control ได้) ถ้าใส่ลง report.html ตรง ๆ โดยไม่ escape
# เป้าหมายที่ประสงค์ร้ายอาจฝัง <script> ไว้ใน banner แล้วเกิด stored XSS ได้
# หมายเหตุ v3: เดิมสคริปต์ escape SERVICE/VERSION/GOBUSTER/NIKTO แต่ "ลืม"
# escape $TARGET เองตอนพิมพ์ลง report.html (ช่อง <title>/<h1> ด้านบน) ทั้งที่
# TARGET มาจาก argument ที่ผู้ใช้ป้อน แก้ไขแล้วด้านล่าง (ดู TARGET_H)
html_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# สร้างหน้าอ่านผล Web Recon จากไฟล์ raw โดยเก็บ raw .txt/.log ไว้เหมือนเดิม
# ทุกค่าจากไฟล์ผลลัพธ์ต้องผ่าน html_escape() เพราะเป้าหมายอาจส่ง banner/ข้อความ
# ที่มี HTML กลับมาได้ และไฟล์เหล่านี้จะถูกเปิดในเบราว์เซอร์ภายหลัง
create_web_report_html() {
    local tool="$1" raw_file="$2" target_url="$3" output_html="$4"
    local wc_code="${5:-}" wc_base="${6:-}"
    local count=0 line clean line_h line_class title raw_name
    [ -s "$raw_file" ] || return 1

    if [ "$tool" = "nikto" ]; then
        count=$(grep -c '^+ ' "$raw_file" 2>/dev/null); count=${count:-0}; title="Nikto"
    else
        count=$(grep -c . "$raw_file" 2>/dev/null); count=${count:-0}; title="Gobuster"
    fi
    raw_name=$(basename -- "$raw_file")

    {
        cat <<EOF
<!DOCTYPE html>
<html lang="th"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} Web Recon Report</title>
<style>
body{margin:0;background:#eef3f8;color:#18263b;font:15px/1.5 Arial,"Noto Sans Thai",sans-serif}.wrap{max-width:1050px;margin:32px auto;padding:0 18px}.head{padding:28px;border-radius:16px;background:linear-gradient(120deg,#152c4b,#285b89);color:#fff;box-shadow:0 12px 24px #152c4b2e}.eyebrow{color:#a9e8d8;font-size:11px;font-weight:700;letter-spacing:.12em}h1{margin:6px 0;font-size:28px}.meta{color:#d5e4f2;overflow-wrap:anywhere}.summary{display:inline-block;margin-top:16px;padding:6px 11px;border-radius:999px;background:#d8f6e8;color:#126447;font-weight:700}.panel{margin-top:22px;padding:20px;border:1px solid #d8e2ed;border-radius:14px;background:#fff;box-shadow:0 5px 16px #152c4b12}.panel h2{margin:0 0 14px;font-size:18px}.line{padding:11px 13px;border:1px solid #dce5ee;border-radius:8px;background:#fbfdff;margin:8px 0;overflow-wrap:anywhere;white-space:pre-wrap}.finding{border-left:4px solid #e16a4f;background:#fff7f5}.success{border-left:4px solid #1d9b70;background:#f4fcf8}.warning{border-left:4px solid #da951c;background:#fffaf0}.meta-line{color:#5f7084}a{color:#1468a8;font-weight:700}</style>
</head><body><main class="wrap"><header class="head"><div class="eyebrow">WEB RECONNAISSANCE REPORT</div><h1>${title}</h1><div class="meta">Target: $(html_escape "$target_url")</div><span class="summary">พบ ${count} รายการ</span>${WEB_BACK_TO_DASHBOARD_HTML}</header><section class="panel"><h2>ผลการตรวจสอบ</h2>
EOF
        local wc_flags=""
        if [ "$tool" = "gobuster" ] && [ -n "$wc_code" ] && [ -n "$wc_base" ]; then
            wc_flags=$(python3 - "$raw_file" "$wc_code" "$wc_base" <<'PYEOF'
import re, sys
path, code, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
pat = re.compile(r'^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]')
with open(path, 'r', errors='replace') as f:
    for line in f:
        m = pat.match(line.strip())
        if m and m.group(2) == code and abs(int(m.group(3)) - (base + len(m.group(1)))) <= 2:
            print(1)
        else:
            print(0)
PYEOF
)
        fi
        local wc_idx=0
        while IFS= read -r line || [ -n "$line" ]; do
            wc_idx=$((wc_idx+1))
            # ลบ ANSI colour code ที่ Gobuster อาจเขียนลง raw log ก่อนแสดง
            clean=$(printf '%s' "$line" | sed $'s/\033\\[[0-9;]*[[:alpha:]]//g')
            line_class="meta-line"
            local is_wc=""
            if [ -n "$wc_flags" ]; then
                is_wc=$(sed -n "${wc_idx}p" <<< "$wc_flags")
            fi
            if [ "$is_wc" = "1" ]; then
                line_class="warning"
                clean="[น่าจะเป็น wildcard] $clean"
            elif [ "$tool" = "nikto" ] && [[ "$clean" == +\ * ]]; then
                line_class="finding"
            elif [[ "$clean" == *"(Status: 2"* ]]; then
                line_class="success"
            elif [[ "$clean" == *"(Status: 3"* || "$clean" == *"(Status: 4"* || "$clean" == *"(Status: 5"* ]]; then
                line_class="warning"
            fi
            line_h=$(html_escape "$clean")
            printf '<div class="line %s">%s</div>\n' "$line_class" "$line_h"
        done < "$raw_file"
        cat <<EOF
</section><p style="text-align:center;color:#697a8e;font-size:12px">ไฟล์ต้นฉบับ: <a href="$(html_escape "$raw_name")">$(html_escape "$raw_name")</a></p></main></body></html>
EOF
    } > "$output_html"
}

TARGET_H=$(html_escape "$TARGET")

# ----------------------------------------------------------
# ตัว parse ผล Nmap XML (-oX) ด้วย python3: ให้ข้อมูลโครงสร้างชัดเจน
# (port/protocol/state/service name/tunnel/method) แทนการไล่ awk คอลัมน์
# จาก normal text output ซึ่งเดารูปแบบ column ได้ไม่แม่นเท่า และไม่มีทาง
# รู้ "หลักฐาน" ว่า service เป็น http จริงหรือแค่เดาจากเลขพอร์ต
# RUNSTATS_EXIT / HOST_STATUS ใช้เช็คว่าสแกนรอบนี้เชื่อถือได้แค่ไหน
# ----------------------------------------------------------
parse_nmap_xml() {
    local xmlfile="$1" outtsv="$2"
    python3 - "$xmlfile" > "$outtsv" <<'PYEOF'
import sys
import xml.etree.ElementTree as ET

def clean(s):
    if s is None:
        return ""
    return s.replace("\t", " ").replace("\n", " ").strip()

path = sys.argv[1]
try:
    tree = ET.parse(path)
except Exception:
    print("PARSE_ERROR\t1")
    sys.exit(0)

root = tree.getroot()
finished = root.find("runstats/finished")
exit_status = finished.get("exit") if finished is not None else "unknown"
print(f"RUNSTATS_EXIT\t{clean(exit_status)}")

hosts = root.findall("host")
if not hosts:
    print("HOST_STATUS\tno-host")

for host in hosts:
    status_el = host.find("status")
    hstate = status_el.get("state") if status_el is not None else "unknown"
    print(f"HOST_STATUS\t{clean(hstate)}")
    ports_el = host.find("ports")
    if ports_el is None:
        continue
    for port in ports_el.findall("port"):
        portid = port.get("portid", "")
        proto = port.get("protocol", "")
        state_el = port.find("state")
        state = state_el.get("state", "") if state_el is not None else ""
        svc = port.find("service")
        svc_name = svc.get("name", "") if svc is not None else ""
        svc_tunnel = svc.get("tunnel", "") if svc is not None else ""
        svc_method = svc.get("method", "") if svc is not None else ""
        product = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        extrainfo = svc.get("extrainfo", "") if svc is not None else ""
        ver_info = " ".join(x for x in [product, version, extrainfo] if x)
        print(f"PORT\t{portid}\t{proto}\t{state}\t{svc_name}\t{svc_tunnel}\t{svc_method}\t{clean(ver_info)}")
PYEOF
}

# ตีความผล runstats/host status ของไฟล์ XML รอบหนึ่ง ๆ ว่า "เชื่อถือได้" ไหม
# คืนค่า completed หรือ failed เท่านั้น — ตั้งใจไม่เดา "partial" เพราะ nmap
# ไม่มีสัญญาณที่เชื่อถือได้พอจะแยก "ถูกตัดตอนกลางคัน" จาก "สแกนจบปกติแต่
# เจอ 0 พอร์ต" ในกรณีทั่วไป การคืน failed แบบระมัดระวังปลอดภัยกว่าการเดา
# ว่า "น่าจะสำเร็จบางส่วน" ทั้งที่ไม่มีหลักฐานเพียงพอ
nmap_scan_status() {
    local shell_exit="$1" tsv="$2"
    if [ "$shell_exit" -ne 0 ]; then echo "failed"; return; fi
    [ -s "$tsv" ] || { echo "failed"; return; }
    if grep -q "^PARSE_ERROR" "$tsv"; then echo "failed"; return; fi
    local runstats hoststatus
    runstats=$(awk -F'\t' '$1=="RUNSTATS_EXIT"{print $2; exit}' "$tsv")
    [ "$runstats" = "success" ] || { echo "failed"; return; }
    hoststatus=$(awk -F'\t' '$1=="HOST_STATUS"{print $2; exit}' "$tsv")
    [ "$hoststatus" = "up" ] || { echo "failed"; return; }
    echo "completed"
}

map_nmap_state() {
    case "$1" in
        open) echo "open" ;;
        "open|filtered") echo "open" ;;
        closed) echo "closed" ;;
        "closed|filtered") echo "closed" ;;
        filtered) echo "filtered" ;;
        *) echo "" ;;   # สถานะไม่ชัดเจน (เช่น unfiltered จาก ACK scan) -> ข้าม
    esac
}

is_web_service() {
    local name="${1,,}"
    [[ "$name" == *http* ]]
}

scheme_for_service() {
    local name="${1,,}" tunnel="${2,,}"
    if [[ "$tunnel" == "ssl" || "$name" == *https* ]]; then
        echo "https"
    else
        echo "http"
    fi
}

build_web_url() {
    local scheme="$1" port="$2"
    if { [ "$scheme" = "http" ] && [ "$port" = "80" ]; } || { [ "$scheme" = "https" ] && [ "$port" = "443" ]; }; then
        echo "${scheme}://${TARGET}"
    else
        echo "${scheme}://${TARGET}:${port}"
    fi
}

echo "[*] Step 1: Checking target & running Nmap fast scan..."
echo ""
ping -c 4 "$TARGET" 2>/dev/null

NMAP_STARTED_AT=$(date +"%Y-%m-%d %H:%M:%S")

NMAP_FAST_LOG="$OUTPUT_DIR/NMAP_FAST.log"
NMAP_FAST_XML="$OUTPUT_DIR/NMAP_FAST.xml"
NMAP_FAST_TSV="$OUTPUT_DIR/.nmap_fast.tsv"
nmap --top-ports 1000 "$NMAP_TIMING" "$TARGET" -oN "$NMAP_FAST_LOG" -oX "$NMAP_FAST_XML" 2>"$OUTPUT_DIR/NMAP_FAST.err"
NMAP_FAST_EXIT=$?
parse_nmap_xml "$NMAP_FAST_XML" "$NMAP_FAST_TSV"
FAST_STATUS=$(nmap_scan_status "$NMAP_FAST_EXIT" "$NMAP_FAST_TSV")
if [ "$FAST_STATUS" != "completed" ]; then
    echo -e "${RED}[!] Nmap fast scan ไม่สำเร็จ/ไม่น่าเชื่อถือ (exit=$NMAP_FAST_EXIT) ดู $OUTPUT_DIR/NMAP_FAST.err${NC}"
fi

RUN_DEEP=0
if [ "$NON_INTERACTIVE" -eq 1 ]; then
    RUN_DEEP=$DEEP_SCAN_FLAG
else
    echo ""
    read -r -p "[?] Do you want to run Nmap Deep Scan (-sC -sV -Pn) (y/n): " DEEP_SCAN
    [[ "$DEEP_SCAN" =~ ^[Yy]$ ]] && RUN_DEEP=1
fi

if [ "$RUN_DEEP" -eq 1 ]; then
    echo "Running Deep Scan (IT MIGHT TAKE A MOMENT)..."
    NMAP_DEEP_LOG="$OUTPUT_DIR/NMAP_DEEP.log"
    NMAP_DEEP_XML="$OUTPUT_DIR/NMAP_DEEP.xml"
    NMAP_DEEP_TSV="$OUTPUT_DIR/.nmap_deep.tsv"
    nmap -sC -sV -Pn "$NMAP_TIMING" "$TARGET" -oN "$NMAP_DEEP_LOG" -oX "$NMAP_DEEP_XML" 2>"$OUTPUT_DIR/NMAP_DEEP.err"
    NMAP_DEEP_EXIT=$?
    parse_nmap_xml "$NMAP_DEEP_XML" "$NMAP_DEEP_TSV"
    DEEP_STATUS=$(nmap_scan_status "$NMAP_DEEP_EXIT" "$NMAP_DEEP_TSV")

    if [ "$DEEP_STATUS" = "completed" ]; then
        PRIMARY_TSV="$NMAP_DEEP_TSV"; SCAN_TYPE="deep"; SCAN_STATUS="completed"
    else
        echo -e "${RED}[!] Nmap deep scan ไม่สำเร็จ/ไม่น่าเชื่อถือ (exit=$NMAP_DEEP_EXIT) ดู $OUTPUT_DIR/NMAP_DEEP.err${NC}"
        if [ "$FAST_STATUS" = "completed" ]; then
            echo -e "${YELLOW}[!] ใช้ผล Fast scan แทนสำหรับรอบนี้ (fallback)${NC}"
            PRIMARY_TSV="$NMAP_FAST_TSV"; SCAN_TYPE="fast"; SCAN_STATUS="completed"
        else
            PRIMARY_TSV="$NMAP_DEEP_TSV"; SCAN_TYPE="deep"; SCAN_STATUS="failed"
        fi
    fi
else
    PRIMARY_TSV="$NMAP_FAST_TSV"; SCAN_TYPE="fast"; SCAN_STATUS="$FAST_STATUS"
fi

NMAP_FINISHED_AT=$(date +"%Y-%m-%d %H:%M:%S")
SCAN_SCOPE="top-1000"   # ทั้ง fast และ deep ในสคริปต์นี้ไม่ได้ระบุ -p เอง
                        # จึงใช้ค่า default ของ nmap คือ top 1000 พอร์ตเท่ากัน

T_ESC=$(sql_escape "$TARGET")
SCAN_SCOPE_ESC=$(sql_escape "$SCAN_SCOPE")
SCAN_TYPE_ESC=$(sql_escape "$SCAN_TYPE")

# ----------------------------------------------------------
# ถ้า Nmap ล้มเหลว/ไม่น่าเชื่อถือ: ห้ามแตะ recon_assets/recon_port_history
# เด็ดขาด (ไม่มีหลักฐานจริงว่าอะไรเปิด/ปิด) และห้ามรัน web recon ต่อ เพราะ
# ไม่รู้ว่าพอร์ตไหนเป็นเว็บจริง — แค่บันทึกว่ารอบนี้ "ล้มเหลว" ลง recon_scans
# ----------------------------------------------------------
if [ "$SCAN_STATUS" != "completed" ]; then
    sqlite3 "$DB_FILE" "INSERT INTO recon_scans
        (target, scan_type, scan_scope, status, new_ports_count, total_ports, started_at, finished_at)
        VALUES ('$T_ESC', '$SCAN_TYPE_ESC', '$SCAN_SCOPE_ESC', 'failed', 0, 0,
                '$NMAP_STARTED_AT', '$NMAP_FINISHED_AT');" >/dev/null

    REPORT_FILE="$OUTPUT_DIR/report.html"
    cat <<EOF > "$REPORT_FILE"
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Smart Recon Report - $TARGET_H (FAILED)</title></head>
<body>
    ${WEB_BACK_TO_DASHBOARD_HTML_LIGHT}
    <h1>Smart Security Recon Report — Nmap scan ล้มเหลว</h1>
    <p><strong>Target:</strong> $TARGET_H &vert; <strong>Scan Date:</strong> $DATE &vert; <strong>Scan Type ที่พยายาม:</strong> $(html_escape "$SCAN_TYPE")</p>
    <p>Nmap ไม่สามารถสแกนเป้าหมายนี้ได้สำเร็จในรอบนี้ (host อาจไม่ตอบสนอง หรือคำสั่งล้มเหลว)
       จึงไม่มีการบันทึก/อัปเดตสถานะพอร์ตใด ๆ ลงฐานข้อมูล เพื่อไม่ให้ตีความผิดว่าพอร์ตที่เคยเห็นถูกปิดไปแล้ว
       กรุณาดู error log ที่ $(html_escape "$OUTPUT_DIR")/NMAP_*.err</p>
</body>
</html>
EOF
    echo -e "${RED}[✘] Scan ล้มเหลว — ไม่มีการอัปเดตสถานะพอร์ตใด ๆ (กันการตีความผิดว่าพอร์ตปิด)${NC}"
    echo "[+] บันทึกรายงานสถานะล้มเหลวไว้ที่: $REPORT_FILE"
    exit 1
fi

# ----------------------------------------------------------
# ดึงพอร์ตที่เคยเห็นของ target นี้มาครั้งเดียว (แทนการ SELECT ทีละพอร์ต)
# ----------------------------------------------------------
declare -A KNOWN_PORTS=()
while IFS= read -r kp; do
    [ -n "$kp" ] && KNOWN_PORTS["$kp"]=1
done < <(sqlite3 "$DB_FILE" "SELECT port || '/' || protocol FROM recon_assets WHERE target='$T_ESC';")

# ----------------------------------------------------------
# Pass 1: อ่านผล Nmap (จาก XML ที่ parse แล้ว) และตัดสินใจ new/existing
# ต่อพอร์ตไว้ในอาเรย์ก่อน (ยังไม่เขียน DB) เพื่อให้รู้ total/new count
# สำหรับ insert แถว recon_scans แถวเดียวให้ครบถ้วนตั้งแต่ต้น
# ----------------------------------------------------------
declare -a P_PORT=() P_PROTO=() P_STATE=() P_SVC=() P_VER=() P_ISNEW=()
declare -a W_SCHEME=() W_PORT=() W_METHOD=()
declare -a NEW_PORT_LINES=()
NEW_PORTS_COUNT=0
TOTAL_PORTS_COUNT=0

while IFS=$'\t' read -r tag portid proto rawstate svcname tunnel method verinfo; do
    [ "$tag" = "PORT" ] || continue
    [[ "$portid" =~ ^[0-9]+$ ]] || continue

    MSTATE=$(map_nmap_state "$rawstate")
    [ -z "$MSTATE" ] && continue   # สถานะไม่ชัดเจนพอจะบันทึก ข้ามรายการนี้

    TOTAL_PORTS_COUNT=$((TOTAL_PORTS_COUNT + 1))
    P_PORT+=("$portid"); P_PROTO+=("$proto"); P_STATE+=("$MSTATE")
    P_SVC+=("$svcname"); P_VER+=("$verinfo")

    if [ -z "${KNOWN_PORTS[$portid/$proto]:-}" ]; then
        NEW_PORTS_COUNT=$((NEW_PORTS_COUNT + 1))
        NEW_PORT_LINES+=("$portid/$proto ($svcname)")
        P_ISNEW+=("1")
    else
        P_ISNEW+=("0")
    fi

    if [ "$MSTATE" = "open" ] && is_web_service "$svcname"; then
        SCHEME=$(scheme_for_service "$svcname" "$tunnel")
        W_SCHEME+=("$SCHEME"); W_PORT+=("$portid"); W_METHOD+=("$method")
    fi
done < "$PRIMARY_TSV"

# ----------------------------------------------------------
# บันทึก recon_scans แถวเดียวของรอบนี้ (สำเร็จ + จำนวนพอร์ตครบถ้วน) แล้วค่อย
# เอา id ไปผูกกับ recon_assets.last_scan_id / recon_port_history.scan_id
# ----------------------------------------------------------
SCAN_ID=$(sqlite3 "$DB_FILE" "INSERT INTO recon_scans
    (target, scan_type, scan_scope, status, new_ports_count, total_ports, started_at, finished_at)
    VALUES ('$T_ESC', '$SCAN_TYPE_ESC', '$SCAN_SCOPE_ESC', 'completed',
            $NEW_PORTS_COUNT, $TOTAL_PORTS_COUNT, '$NMAP_STARTED_AT', '$NMAP_FINISHED_AT');
    SELECT last_insert_rowid();")

if ! [[ "$SCAN_ID" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}[!] ERROR: บันทึก recon_scans ไม่สำเร็จ ข้ามการอัปเดต recon_assets/history รอบนี้${NC}"
    SCAN_ID=""
fi

# ----------------------------------------------------------
# Pass 2: เขียน recon_assets (สถานะปัจจุบัน) + recon_port_history (ประวัติ
# แบบ append-only ทุกพอร์ตที่ "มีหลักฐาน" จากรอบสแกนนี้จริง ๆ) ในทรานแซกชัน
# เดียว — พอร์ตที่ "ไม่ปรากฏ" ในรอบนี้จะไม่ถูกแตะต้องเลย (ไม่ตั้งเป็น closed)
# ----------------------------------------------------------
if [ -n "$SCAN_ID" ]; then
    DB_BATCH="UPDATE recon_assets SET is_new = 0 WHERE target = '$T_ESC';
"
    for i in "${!P_PORT[@]}"; do
        PORT="${P_PORT[$i]}"; PROTO="${P_PROTO[$i]}"; STATE="${P_STATE[$i]}"
        SVC="${P_SVC[$i]}"; VER="${P_VER[$i]}"; ISNEW="${P_ISNEW[$i]}"

        SV_ESC=$(sql_escape "$SVC")
        VER_ESC=$(sql_escape "$VER")
        ST_ESC=$(sql_escape "$STATE")
        PR_ESC=$(sql_escape "$PROTO")

        if [ "$ISNEW" = "1" ]; then
            DB_BATCH+="INSERT INTO recon_assets
                (target, port, protocol, service, version_info, state, is_new, last_checked_at, last_scan_id)
                VALUES ('$T_ESC', $PORT, '$PR_ESC', '$SV_ESC', '$VER_ESC', '$ST_ESC', 1,
                        datetime('now','localtime'), $SCAN_ID);
"
        else
            DB_BATCH+="UPDATE recon_assets
                SET service='$SV_ESC', version_info='$VER_ESC', state='$ST_ESC',
                    last_seen=datetime('now','localtime'), is_new=0,
                    last_checked_at=datetime('now','localtime'), last_scan_id=$SCAN_ID
                WHERE target='$T_ESC' AND port=$PORT AND protocol='$PR_ESC';
"
        fi

        DB_BATCH+="INSERT INTO recon_port_history
            (scan_id, target, port, protocol, service, version_info, state)
            VALUES ($SCAN_ID, '$T_ESC', $PORT, '$PR_ESC', '$SV_ESC', '$VER_ESC', '$ST_ESC');
"
    done

    # เขียนลง SQLite ทีเดียวทั้งหมดในหนึ่ง transaction (แทนการเปิด process sqlite3
    # ใหม่ทุกพอร์ต) — ลดภาระ CPU/disk I/O ของเครื่องได้มากเมื่อ target มีพอร์ตเปิดเยอะ
    if ! { echo "BEGIN TRANSACTION;"; printf '%s' "$DB_BATCH"; echo "COMMIT;"; } | sqlite3 "$DB_FILE"; then
        echo -e "${RED}[!] ERROR: บันทึก recon_assets/recon_port_history ล้มเหลว (ดู stderr ของ sqlite3)${NC}"
        EXIT_CODE=1
    fi
fi

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

# ----------------------------------------------------------
# เลือกรัน Web Recon Tool: เฉพาะพอร์ตที่ Nmap รายงานชื่อ service กลุ่ม
# http/https เท่านั้น (W_PORT/W_SCHEME ที่เก็บไว้ใน Pass 1) — ไม่มีการ
# hardcode 80/443 อีกต่อไป และไม่สมมติว่าพอร์ตอื่นเป็นเว็บ
# ----------------------------------------------------------
declare -a WEB_RESULT_ROWS_TOOL=() WEB_RESULT_ROWS_URL=() WEB_RESULT_ROWS_STATUS=()
declare -a WEB_RESULT_ROWS_COUNT=() WEB_RESULT_ROWS_PATH=()
GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt"
# เดิมไม่มีการจำกัดเวลารันของ gobuster เลย ถ้า target ตอบช้าผิดปกติหรือค้าง
# (เช่น rate-limit/firewall หน่วง connection โดยไม่ตัดการเชื่อมต่อ) กระบวนการ
# จะค้างไม่มีกำหนด ทำให้ Smart Recon ทั้งรอบค้างตามไปด้วย — ใส่เพดานเวลาไว้
# กันไว้ก่อน (ไม่กระทบ scan ปกติที่เสร็จเร็วกว่านี้มาก)
GOBUSTER_TIMEOUT_SECONDS=600

if [ "${#W_PORT[@]}" -gt 0 ]; then
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        WEB_CHOICE="${WEB_CHOICE_ARG:-skip}"
    else
        echo ""
        echo "======================================="
        echo "[!] พบพอร์ตที่มีหลักฐานว่าเป็น Web Service:"
        for i in "${!W_PORT[@]}"; do
            echo "    - ${W_SCHEME[$i]}://${TARGET}:${W_PORT[$i]} (nmap method: ${W_METHOD[$i]:-unknown})"
        done
        echo "Select a Web Reconnaissance Tool (Web Enumeration):"
        echo "1) Gobuster (Scan For Hidden Directory)"
        echo "2) Nikto (Web Server Scan)"
        echo "3) Run Both Gobuster and Nikto"
        echo "4) Skip this Step"
        echo "======================================="
        read -r -p "เลือกเมนู [1-4]: " WEB_CHOICE_NUM
        case "$WEB_CHOICE_NUM" in
            1) WEB_CHOICE="gobuster" ;;
            2) WEB_CHOICE="nikto" ;;
            3) WEB_CHOICE="both" ;;
            *) WEB_CHOICE="skip" ;;
        esac
    fi

    if [ "$WEB_CHOICE" != "skip" ]; then
        NEED_GOBUSTER=0; NEED_NIKTO=0
        [[ "$WEB_CHOICE" == "gobuster" || "$WEB_CHOICE" == "both" ]] && NEED_GOBUSTER=1
        [[ "$WEB_CHOICE" == "nikto"    || "$WEB_CHOICE" == "both" ]] && NEED_NIKTO=1

        GOBUSTER_OK=1
        if [ "$NEED_GOBUSTER" -eq 1 ]; then
            if ! command -v gobuster >/dev/null 2>&1; then
                echo -e "${RED}[!] ไม่พบคำสั่ง gobuster — ข้าม Gobuster ทุก URL${NC}"; GOBUSTER_OK=0
            elif [ ! -f "$GOBUSTER_WORDLIST" ]; then
                echo -e "${RED}[!] ไม่พบ wordlist: $GOBUSTER_WORDLIST — ข้าม Gobuster ทุก URL${NC}"; GOBUSTER_OK=0
            fi
        fi
        NIKTO_OK=1
        if [ "$NEED_NIKTO" -eq 1 ] && ! command -v nikto >/dev/null 2>&1; then
            echo -e "${RED}[!] ไม่พบคำสั่ง nikto — ข้าม Nikto ทุก URL${NC}"; NIKTO_OK=0
        fi

        WEB_BATCH=""
        for i in "${!W_PORT[@]}"; do
            SCHEME="${W_SCHEME[$i]}"; PORT="${W_PORT[$i]}"
            URL=$(build_web_url "$SCHEME" "$PORT")
            LABEL="p${PORT}"
            URL_ESC=$(sql_escape "$URL")

            if [ "$NEED_GOBUSTER" -eq 1 ]; then
                GB_OUT="$OUTPUT_DIR/GOBUSTER_${LABEL}.log"
                GB_ERR="$OUTPUT_DIR/GOBUSTER_${LABEL}.err"
                STARTED=$(date +"%Y-%m-%d %H:%M:%S")
                if [ "$GOBUSTER_OK" -eq 1 ]; then
                    echo "[*] Running Gobuster on $URL..."
                    GB_EXTRA=()
                    [ "$SCHEME" = "https" ] && GB_EXTRA+=("-k")
                    GB_WC_ECHO=0; GB_WC_CODE=""; GB_WC_BASE=""

                    # ตรวจ wildcard response ก่อนสแกนจริง: ยิง path สุ่มที่ไม่น่ามีอยู่จริง
                    # ไปก่อน 1 ครั้ง ถ้า server ตอบ status+length คงที่ (เช่น 403 ทุก URL
                    # แบบในเคสนี้) ให้สั่ง gobuster --exclude-length ด้วยค่าที่ "วัดได้จริง
                    # ของเป้าหมายนี้" ไม่ hardcode ตายตัวกับทุกเว็บไซต์ ถ้า probe ไม่ชัดเจน
                    # (ยิงไม่สำเร็จ) ก็ปล่อยให้ gobuster ใช้ wildcard-guard ของมันเองตามปกติ
                    WC_CURL_EXTRA=()
                    [ "$SCHEME" = "https" ] && WC_CURL_EXTRA+=("-k")
                    # ยิง probe 2 ครั้งด้วยความยาว path "ต่างกัน" (สั้น ~8 ตัว, ยาว ~34 ตัว)
                    # แทนการยิงครั้งเดียวด้วย path ยาวคงที่แบบเดิม เพราะพบจากหลักฐานจริง
                    # (log จริง: .forward 8 ตัว=8501B, .hta 4 ตัว=8497B, zt 2 ตัว=8495B — สูตร
                    # เดียวกันหมดคือ size = 8493 + len(path)) ว่าบาง target คืน response ที่
                    # "ความยาวแปรผันตรงตามความยาว path ที่ขอ" (error page echo คืน path กลับมา
                    # ในเนื้อหา) การ probe ด้วย path ยาวครั้งเดียวจึงวัดได้ความยาวที่ไม่ตรงกับ
                    # path สั้นๆ ในเวิร์ดลิสต์เลยสักคำ ทำให้ --exclude-length ค่าเดียวกรองไม่ได้
                    # อะไรเลย (เคสจริง: 8082 ได้ 4613 "findings" ปลอม ทั้งที่เป็น wildcard ล้วน)
                    WC_SHORT_PATH="wp$((RANDOM % 9000 + 1000))"
                    WC_LONG_PATH="wprobe_$(date +%s%N)_${RANDOM}_xx_long_probe_pad"
                    WC_RESP1=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" \
                        "${WC_CURL_EXTRA[@]}" --max-time 10 "${URL%/}/$WC_SHORT_PATH" 2>/dev/null)
                    WC_RESP2=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" \
                        "${WC_CURL_EXTRA[@]}" --max-time 10 "${URL%/}/$WC_LONG_PATH" 2>/dev/null)
                    WC_CODE1="${WC_RESP1%% *}"; WC_LEN1="${WC_RESP1##* }"
                    WC_CODE2="${WC_RESP2%% *}"; WC_LEN2="${WC_RESP2##* }"
                    GB_WILDCARD_NOTE=""
                    if [[ "$WC_CODE1" =~ ^[0-9]+$ ]] && [ "$WC_CODE1" != "000" ] \
                       && [[ "$WC_LEN1" =~ ^[0-9]+$ ]] && [ "$WC_CODE1" = "$WC_CODE2" ] \
                       && [[ "$WC_LEN2" =~ ^[0-9]+$ ]]; then
                        WC_PATHDIFF=$(( ${#WC_LONG_PATH} - ${#WC_SHORT_PATH} ))
                        WC_LENDIFF=$(( WC_LEN2 - WC_LEN1 ))
                        if [ "$WC_LENDIFF" -eq "$WC_PATHDIFF" ] && [ "$WC_PATHDIFF" -ne 0 ]; then
                            # ความยาว response แปรผันตรงตาม path (echo pattern) ยืนยันด้วย
                            # ตัวเลขจริง — ของเดิมใช้ --force โดยหวังว่าจะข้าม precheck ของ
                            # gobuster ได้ แต่ตรวจสอบ source จริง (gobusterdir.go, PreRun())
                            # แล้วพบว่า --force ใช้ข้ามได้แค่ "connection error" ของ precheck
                            # เท่านั้น ส่วนการตรวจจับ wildcard จริง (WildcardError) ไม่เช็ค
                            # Force เลย จึง bypass ไม่ได้ไม่ว่าจะส่ง --force กี่รอบ
                            # เปลี่ยนเป็น: ตัด status code ที่ตรวจพบว่าเป็น wildcard ออกจาก
                            # status-codes whitelist ที่ส่งให้ gobuster (-s) แทน เพราะ logic
                            # จริงใน gobuster เช็คว่า status code อยู่ใน positive list หรือไม่
                            # ถ้าไม่อยู่ก็ไม่ถือเป็น hit และไม่ error ตั้งแต่ต้น — status code
                            # อื่น (200, 301 ฯลฯ) ของพอร์ตเดียวกันยังสแกน/รายงานได้ตามปกติ
                            # trade-off ที่ยอมรับแล้ว: path จริงที่บังเอิญตอบ status เดียวกัน
                            # กับ wildcard จะถูกซ่อนไปด้วย เพราะแยกไม่ออกจาก wildcard
                            # หมายเหตุสำคัญ: gobuster ตั้ง status-codes-blacklist="404" เป็น
                            # ค่า default ของมันเองเสมอ ถ้าเราส่ง -s (status-codes) โดยไม่ล้าง
                            # ค่า default นี้ก่อน จะเจอ error "status-codes and
                            # status-codes-blacklist are both set" ทันที (exit=1) ต้องส่ง
                            # -b "" (blacklist ว่าง) คู่กับ -s เสมอเพื่อปิด default blacklist
                            GB_DEFAULT_CODES=(200 204 301 302 307 401 403)
                            GB_FILTERED_CODES=()
                            for c in "${GB_DEFAULT_CODES[@]}"; do
                                [ "$c" != "$WC_CODE1" ] && GB_FILTERED_CODES+=("$c")
                            done
                            GB_STATUS_CODES_CSV=$(IFS=,; echo "${GB_FILTERED_CODES[*]}")
                            GB_EXTRA+=("-s" "$GB_STATUS_CODES_CSV" "-b" "")
                            GB_WC_ECHO=0   # ไม่ต้องพึ่งการนับแยกหลังสแกนอีกต่อไป เพราะ gobuster
                                           # จะไม่รายงาน status code นี้เป็น hit เลยตั้งแต่ต้น
                            GB_WC_CODE="$WC_CODE1"
                            GB_WILDCARD_NOTE="ตรวจพบ wildcard แบบความยาวแปรผันตาม path (status $WC_CODE1 ทุกครั้ง, ${WC_LEN1}B/${WC_LEN2}B ตามความยาว path ที่ขอ) — ตัดสถานะ $WC_CODE1 ออกจาก status-codes ที่ gobuster จะนับเป็นผลที่พบสำหรับเป้าหมายนี้โดยเฉพาะ (เซิร์ฟเวอร์ตอบสถานะนี้มั่วทุก path จึงไม่น่าเชื่อถือ) ผลลัพธ์ status code อื่นยังสแกนได้ตามปกติ หมายเหตุ: path จริงที่บังเอิญตอบสถานะเดียวกันจะถูกซ่อนไปด้วย"
                        else
                            GB_EXTRA+=("--exclude-length" "$WC_LEN1")
                            GB_WILDCARD_NOTE="ตรวจพบ wildcard response คงที่ ($WC_CODE1, ${WC_LEN1} bytes) ของเป้าหมายนี้ — ยกเว้นความยาวนี้ออกจากผลสแกน"
                        fi
                        echo "[*] $GB_WILDCARD_NOTE"
                    fi

                    timeout "$GOBUSTER_TIMEOUT_SECONDS" \
                        gobuster dir -u "$URL" -w "$GOBUSTER_WORDLIST" -t "$GOBUSTER_THREADS" \
                        -o "$GB_OUT" -q "${GB_EXTRA[@]}" 2>"$GB_ERR"
                    GB_EXIT=$?
                    # exit=124 คือรหัสมาตรฐานของ `timeout` เมื่อมันต้องฆ่าโปรเซสลูกเพราะ
                    # เกินเวลาที่กำหนด — แยกข้อความนี้ออกจาก error อื่นๆ ของ gobuster เอง
                    # เพื่อให้เห็นชัดว่าสแกนถูกตัดเพราะหมดเวลา ไม่ใช่ gobuster error ปกติ
                    if [ "$GB_EXIT" -eq 124 ]; then
                        echo "timeout: gobuster ถูกยกเลิกเพราะเกิน ${GOBUSTER_TIMEOUT_SECONDS} วินาที" >> "$GB_ERR"
                    fi
                    FINISHED=$(date +"%Y-%m-%d %H:%M:%S")
                    if [ "$GB_EXIT" -eq 0 ] && [ -f "$GB_OUT" ]; then
                        GB_STATUS="completed"
                        # หมายเหตุ: ห้ามใช้ `grep -c ... || echo 0` เพราะ grep -c คืน
                        # exit code 1 เมื่อไม่มีบรรทัด match แม้จะพิมพ์ "0" ออกมาแล้วก็ตาม
                        # ทำให้ || ทำงานซ้ำ ได้ "0" สองตัวติดกัน (เช่น "0 0") แล้วไปพัง
                        # SQL INSERT ด้านล่าง — ใช้ default ค่าว่างแทนแทน
                        GB_COUNT=$(grep -c . "$GB_OUT" 2>/dev/null)
                        GB_COUNT=${GB_COUNT:-0}
                        GB_RAW_COUNT="$GB_COUNT"
                        GB_ERRMSG=""
                        [ -n "$GB_WILDCARD_NOTE" ] && GB_ERRMSG="$GB_WILDCARD_NOTE"

                        if [ "${GB_WC_ECHO:-0}" -eq 1 ] && [ "$GB_RAW_COUNT" -gt 0 ]; then
                            # แยก "น่าจะเป็น wildcard noise" ออกจาก "น่าจะเป็นของจริง" ด้วย
                            # สูตรเดียวกับตอนตรวจจับ (size = base + len(path)) โดยยอม
                            # คลาดเคลื่อน ±2 ไบต์ (เผื่อ edge case เล็กน้อยจาก encoding) —
                            # ไม่ลบบรรทัดไหนออกจาก $GB_OUT เลย แค่นับแยกสำหรับ findings_count
                            GB_COUNT=$(python3 - "$GB_OUT" "$GB_WC_CODE" "$GB_WC_BASE" <<'PYEOF'
import re, sys
path, code, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
pat = re.compile(r'^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]')
real = 0
try:
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = pat.match(line.strip())
            if not m:
                continue
            word, status, size = m.group(1), m.group(2), int(m.group(3))
            predicted = base + len(word)
            if status == code and abs(size - predicted) <= 2:
                continue  # wildcard-like noise ตามสูตร — ไม่นับ
            real += 1
except Exception:
    print(0); sys.exit(0)
print(real)
PYEOF
)
                            [[ "$GB_COUNT" =~ ^[0-9]+$ ]] || GB_COUNT=0
                            if [ "$GB_COUNT" -ne "$GB_RAW_COUNT" ]; then
                                GB_ERRMSG="${GB_ERRMSG} (gobuster ตอบกลับทั้งหมด ${GB_RAW_COUNT} รายการ ส่วนใหญ่ตรงรูปแบบ wildcard ตามสูตรข้างต้น เหลือที่ไม่ตรงรูปแบบ ${GB_COUNT} รายการ — ดู raw log/HTML ฉบับเต็มเพื่อตรวจทุกบรรทัดเอง เพราะสูตรนี้เป็นการประมาณ ไม่ใช่การยืนยัน)"
                            fi
                        fi
                    else
                        GB_STATUS="failed"
                        GB_COUNT=0
                        GB_ERRMSG=$(tail -c 500 "$GB_ERR" 2>/dev/null | tr -d '\000')
                        # ถ้า gobuster ยังปฏิเสธเพราะ wildcard แม้ probe ของเราจะลอง
                        # exclude-length ไปแล้ว ให้บอกตรงๆ ว่าเป็นข้อจำกัดด้าน
                        # configuration ของเป้าหมายนี้ ไม่ใช่การสแกนที่ล้มเหลวทั่วไป —
                        # schema ปัจจุบันยังไม่มีสถานะ 'partial' สำหรับตารางนี้ (ต้อง
                        # migrate เพิ่มถ้าต้องการแยกสถานะนี้ออกจาก failed จริงๆ)
                        if echo "$GB_ERRMSG" | grep -qi "wildcard"; then
                            GB_ERRMSG="[wildcard response ที่ exclude-length แก้ไม่ได้ทั้งหมด — ไม่ใช่ความล้มเหลวทั่วไป] $GB_ERRMSG"
                        fi
                        echo -e "${RED}[!] Gobuster ล้มเหลวที่ $URL (exit=$GB_EXIT)${NC}"
                        [ -n "$GB_ERRMSG" ] && echo -e "${RED}    -> ${GB_ERRMSG}${NC}"
                        EXIT_CODE=1
                    fi
                else
                    STARTED=$(date +"%Y-%m-%d %H:%M:%S"); FINISHED="$STARTED"
                    GB_STATUS="failed"; GB_COUNT=0
                    GB_ERRMSG="gobuster หรือ wordlist ไม่พร้อมใช้งานบนเครื่องนี้"
                    GB_OUT=""
                    EXIT_CODE=1
                fi
                GB_REPORT_PATH="${GB_OUT:-}"
                if [ "$GB_STATUS" = "completed" ] && [ -n "${GB_OUT:-}" ]; then
                    if create_web_report_html "gobuster" "$GB_OUT" "$URL" "${GB_OUT}.html" "${GB_WC_CODE:-}" "${GB_WC_BASE:-}"; then
                        GB_REPORT_PATH="${GB_OUT}.html"
                    elif [ -s "$GB_OUT" ]; then
                        echo -e "${YELLOW}[!] สร้างหน้า HTML ของ Gobuster ไม่สำเร็จ — ใช้ raw log แทน${NC}" >&2
                    else
                        echo "[*] Gobuster ไม่พบรายการใดเลย (0 บรรทัด) — ไม่มีอะไรให้สร้างเป็นหน้า HTML จึงใช้ raw log (ว่าง) แทน"
                    fi
                fi
                # BUG FIX: เดิมสร้าง summary เป็น "พบ $GB_COUNT รายการ" แบบเดียวกันทุก
                # สถานะ ทำให้สแกนที่ "ล้มเหลวจนไม่ได้แม้แต่เริ่มเทียบกับ wordlist เลย"
                # (เช่น ถูก gobuster ปฏิเสธด้วย wildcard-guard ของมันเองตั้งแต่ก่อนสแกน)
                # แสดงบน Dashboard เป็น "พบ 0 รายการ" เหมือนกับสแกนที่ทำสำเร็จจริงแล้ว
                # ไม่เจออะไรเลย (เช่น target อื่นที่ exclude-length ใช้ได้ผล) ทั้งที่เป็น
                # คนละความหมายกันคนละทาง — ผู้ดู Dashboard แยกไม่ออกว่า "สแกนแล้วไม่เจอ"
                # กับ "ยังไม่ได้สแกนจริงเลย" ให้ summary ของสถานะ failed บอกตรงๆ ว่ายัง
                # ไม่มีผลสแกนจริง แทนที่จะใช้ถ้อยคำที่ฟังดูเหมือนนับผลลัพธ์ได้แล้ว
                if [ "$GB_STATUS" = "completed" ]; then
                    if [ "${GB_WC_ECHO:-0}" -eq 1 ] && [ "${GB_RAW_COUNT:-0}" -ne "$GB_COUNT" ]; then
                        SUMMARY_ESC=$(sql_escape "พบ $GB_COUNT รายการที่น่าจะจริง จากทั้งหมด ${GB_RAW_COUNT:-0} รายการที่ gobuster ตอบกลับ (ส่วนใหญ่ตรงรูปแบบ wildcard ของเป้าหมายนี้ ดู raw log เพื่อตรวจทุกรายการเอง)")
                    else
                        SUMMARY_ESC=$(sql_escape "พบ $GB_COUNT รายการ")
                    fi
                else
                    SUMMARY_ESC=$(sql_escape "สแกนไม่สำเร็จ — ยังไม่ได้เทียบกับ wordlist จริง (ไม่ใช่ผลลัพธ์ 0 รายการที่สแกนแล้วไม่พบ) ดูสาเหตุที่ error_message")
                fi
                ERR_ESC=$(sql_escape "$GB_ERRMSG")
                PATH_ESC=$(sql_escape "$GB_REPORT_PATH")
                WEB_BATCH+="INSERT INTO web_recon_results
                    (target, url, tool, status, findings_count, summary, report_path, started_at, finished_at, error_message, scan_id)
                    VALUES ('$T_ESC', '$URL_ESC', 'gobuster', '$GB_STATUS', $GB_COUNT, '$SUMMARY_ESC',
                            NULLIF('$PATH_ESC',''), '$STARTED', '$FINISHED', NULLIF('$ERR_ESC',''), $SCAN_ID);
"
                WEB_RESULT_ROWS_TOOL+=("gobuster"); WEB_RESULT_ROWS_URL+=("$URL")
                WEB_RESULT_ROWS_STATUS+=("$GB_STATUS"); WEB_RESULT_ROWS_COUNT+=("$GB_COUNT")
                WEB_RESULT_ROWS_PATH+=("$GB_REPORT_PATH")
            fi

            if [ "$NEED_NIKTO" -eq 1 ]; then
                NK_OUT="$OUTPUT_DIR/NIKTO_${LABEL}.txt"
                NK_ERR="$OUTPUT_DIR/NIKTO_${LABEL}.err"
                STARTED=$(date +"%Y-%m-%d %H:%M:%S")
                if [ "$NIKTO_OK" -eq 1 ]; then
                    echo "[*] Running Nikto on $URL..."
                    # -ask no: กัน Nikto หยุดรอ (y/n) กลางสแกนตอนเจอ server header
                    # ที่ไม่รู้จัก (ถาม CIRT.net ว่าจะส่งข้อมูลอัปเดตไหม) ซึ่งเป็นสาเหตุ
                    # ที่ทำให้สแกนค้างนาน (หลายนาที) และไฟล์ -o เขียนไม่ครบ/ไม่เสร็จ
                    nikto -h "$URL" -ask no -Format txt -o "$NK_OUT" >"$NK_ERR" 2>&1
                    NK_EXIT=$?
                    FINISHED=$(date +"%Y-%m-%d %H:%M:%S")

                    # ยืนยันจากไฟล์จริง: Nikto 2.6.0 เติม ".txt" ต่อท้ายชื่อไฟล์ที่ให้
                    # ไปอีกชั้นเสมอ แม้ชื่อนั้นจะลงท้ายด้วย .txt อยู่แล้ว (ได้ไฟล์ชื่อ
                    # "...NIKTO_xxx.txt.txt" ที่มีผลสแกนจริงอยู่ข้างใน) เราแก้พฤติกรรม
                    # ของ nikto เองไม่ได้ เลยต้อง "หา" ไฟล์จริงจากทั้งสองชื่อที่เป็นไปได้
                    # แทนการเช็ค path เดียวแบบเป๊ะๆ เหมือนเดิม
                    NK_REAL_OUT=""
                    for NK_CAND in "$NK_OUT" "${NK_OUT}.txt"; do
                        if [ -f "$NK_CAND" ]; then
                            NK_REAL_OUT="$NK_CAND"
                            break
                        fi
                    done

                    if [ "$NK_EXIT" -ne 0 ]; then
                        # คำสั่งล้มเหลวจริง (เช่น nikto crash กลางสแกน) — สถานะยังเป็น
                        # "failed" เสมอ (ไม่เปลี่ยนเป็น completed) แต่ถ้าไฟล์รายงานมีเนื้อหา
                        # ที่เขียนไปแล้วก่อน crash ให้นับไว้ ไม่ใช่ทิ้งเป็น 0 เฉยๆ เพราะอาจมี
                        # finding จริงที่เจอไปแล้วก่อนพัง (ยืนยันจาก log จริง: nikto ที่ 8082
                        # เจอ XSS จริงก่อน crash แล้วถูกนับเป็น 0 findings ทั้งที่มีหลักฐานอยู่)
                        NK_STATUS="failed"
                        NK_COUNT=0
                        NK_PARTIAL_NOTE=""
                        for NK_CAND in "$NK_OUT" "${NK_OUT}.txt"; do
                            if [ -s "$NK_CAND" ]; then
                                NK_COUNT=$(grep -c '^+ ' "$NK_CAND" 2>/dev/null); NK_COUNT=${NK_COUNT:-0}
                                NK_PARTIAL_NOTE=" (พบไฟล์รายงานบางส่วนก่อน crash ที่ $NK_CAND — มี $NK_COUNT รายการ ยังไม่ครบเพราะสแกนไม่จบ)"
                                NK_OUT="$NK_CAND"
                                break
                            fi
                        done
                        NK_ERRMSG="$(tail -c 500 "$NK_ERR" 2>/dev/null | tr -d '\000')${NK_PARTIAL_NOTE}"
                        echo -e "${RED}[!] Nikto ล้มเหลวที่ $URL (exit=$NK_EXIT)${NC}"
                        [ -n "$NK_PARTIAL_NOTE" ] && echo -e "${YELLOW}   ${NK_PARTIAL_NOTE}${NC}"
                        [ -n "$NK_ERRMSG" ] && echo -e "${RED}    -> ${NK_ERRMSG}${NC}"
                        EXIT_CODE=1
                    elif [ -z "$NK_REAL_OUT" ]; then
                        # exit=0 แต่หาไฟล์รายงานไม่เจอเลยทั้งสองชื่อที่เป็นไปได้
                        NK_STATUS="failed"
                        NK_COUNT=0
                        NK_ERRMSG="คำสั่งจบปกติ (exit=0) แต่ไม่พบไฟล์รายงานที่ $NK_OUT หรือ ${NK_OUT}.txt"
                        echo -e "${RED}[!] Nikto ที่ $URL จบแบบปกติ (exit=0) แต่ไม่พบไฟล์รายงาน${NC}"
                        echo -e "${RED}    -> คาดว่าอยู่ที่ $NK_OUT หรือ ${NK_OUT}.txt${NC}"
                        EXIT_CODE=1
                    elif [ ! -s "$NK_REAL_OUT" ]; then
                        # ไฟล์ถูกสร้างจริงแต่ว่างเปล่า (0 ไบต์) — แยกออกจากกรณีไฟล์หาย
                        NK_STATUS="failed"
                        NK_COUNT=0
                        NK_ERRMSG="พบไฟล์รายงานที่ $NK_REAL_OUT แต่ไฟล์ว่างเปล่า (0 ไบต์)"
                        echo -e "${RED}[!] Nikto ที่ $URL สร้างไฟล์รายงานว่างเปล่า: $NK_REAL_OUT${NC}"
                        EXIT_CODE=1
                    else
                        # พบไฟล์รายงานจริงและมีเนื้อหา = สแกนสำเร็จ ไม่ว่าจะเจอ finding
                        # กี่รายการก็ตาม (0 findings ก็คือ "ไม่พบช่องโหว่" ซึ่งเป็นผล
                        # ที่ถูกต้อง ไม่ใช่ความล้มเหลว)
                        NK_OUT="$NK_REAL_OUT"
                        NK_STATUS="completed"
                        # ห้ามใช้ `grep -c ... || echo 0` เพราะ grep -c คืน exit 1 เมื่อไม่
                        # match แม้จะพิมพ์ "0" แล้ว ทำให้ || ทำงานซ้ำได้ "0 0" ไปพัง SQL
                        NK_COUNT=$(grep -c '^+ ' "$NK_OUT" 2>/dev/null)
                        NK_COUNT=${NK_COUNT:-0}
                        NK_ERRMSG=""
                        echo "[✔] Nikto ที่ $URL สำเร็จ — พบ $NK_COUNT รายการ ($NK_OUT)"
                    fi
                else
                    STARTED=$(date +"%Y-%m-%d %H:%M:%S"); FINISHED="$STARTED"
                    NK_STATUS="failed"; NK_COUNT=0
                    NK_ERRMSG="nikto ไม่พร้อมใช้งานบนเครื่องนี้"
                    NK_OUT=""
                    EXIT_CODE=1
                fi
                NK_REPORT_PATH="${NK_OUT:-}"
                if [ "$NK_STATUS" = "completed" ] && [ -n "${NK_OUT:-}" ]; then
                    if create_web_report_html "nikto" "$NK_OUT" "$URL" "${NK_OUT}.html"; then
                        NK_REPORT_PATH="${NK_OUT}.html"
                    else
                        echo -e "${YELLOW}[!] สร้างหน้า HTML ของ Nikto ไม่สำเร็จ — ใช้ raw report แทน${NC}" >&2
                    fi
                fi
                if [ "$NK_STATUS" = "completed" ]; then
                    SUMMARY_ESC=$(sql_escape "พบ $NK_COUNT findings (ประมาณการจากจำนวนบรรทัดที่ขึ้นต้นด้วย '+')")
                elif [ "$NK_COUNT" -gt 0 ]; then
                    SUMMARY_ESC=$(sql_escape "สแกนไม่จบ (ดู error_message) แต่กู้ผลบางส่วนได้ $NK_COUNT รายการก่อน crash — อาจมีมากกว่านี้ที่ยังไม่ถูกสแกน")
                else
                    SUMMARY_ESC=$(sql_escape "สแกนไม่สำเร็จ ไม่มีผลลัพธ์ที่กู้คืนได้ ดูสาเหตุที่ error_message")
                fi
                ERR_ESC=$(sql_escape "$NK_ERRMSG")
                PATH_ESC=$(sql_escape "$NK_REPORT_PATH")
                WEB_BATCH+="INSERT INTO web_recon_results
                    (target, url, tool, status, findings_count, summary, report_path, started_at, finished_at, error_message, scan_id)
                    VALUES ('$T_ESC', '$URL_ESC', 'nikto', '$NK_STATUS', $NK_COUNT, '$SUMMARY_ESC',
                            NULLIF('$PATH_ESC',''), '$STARTED', '$FINISHED', NULLIF('$ERR_ESC',''), $SCAN_ID);
"
                WEB_RESULT_ROWS_TOOL+=("nikto"); WEB_RESULT_ROWS_URL+=("$URL")
                WEB_RESULT_ROWS_STATUS+=("$NK_STATUS"); WEB_RESULT_ROWS_COUNT+=("$NK_COUNT")
                WEB_RESULT_ROWS_PATH+=("$NK_REPORT_PATH")
            fi
        done

        if [ -n "$WEB_BATCH" ]; then
            if ! { echo "BEGIN TRANSACTION;"; printf '%s' "$WEB_BATCH"; echo "COMMIT;"; } | sqlite3 "$DB_FILE"; then
                echo -e "${RED}[!] ERROR: บันทึก web_recon_results ล้มเหลว (ดู stderr ของ sqlite3)${NC}"
                EXIT_CODE=1
            fi
        fi
    else
        echo "[-] Skip Web Recon"
    fi
else
    echo "[-] ไม่พบหลักฐานจาก Nmap ว่ามีพอร์ตที่เป็น Web Service (http/https) — ข้ามขั้นตอน Web Recon โดยอัตโนมัติ"
fi

# ----------------------------------------------------------
# สร้าง Smart HTML Report
# ----------------------------------------------------------
echo ""
echo "[+] Generating Smart HTML Report..."
REPORT_FILE="$OUTPUT_DIR/report.html"

cat <<EOF> "$REPORT_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Smart Recon Report - $TARGET_H</title>
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
        .badge-fail { background: #c0392b; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .delta-box { padding: 12px 16px; border-radius: 6px; margin-top: 15px; }
        .delta-alert { background: #fdecea; border-left: 5px solid #e74c3c; }
        .delta-ok { background: #eafaf1; border-left: 5px solid #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        ${WEB_BACK_TO_DASHBOARD_HTML_LIGHT}
        <h1>Smart Security Recon Report</h1>
        <p><strong>Target:</strong> $TARGET_H &vert; <strong>Scan Date:</strong> $DATE &vert; <strong>Scan Type:</strong> $(html_escape "$SCAN_TYPE") &vert; <strong>Scan Scope:</strong> $(html_escape "$SCAN_SCOPE")</p>
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

for i in "${!P_PORT[@]}"; do
    PORT_PROTO="${P_PORT[$i]}/${P_PROTO[$i]}"
    STATE="${P_STATE[$i]}"; SERVICE="${P_SVC[$i]}"; VERSION="${P_VER[$i]}"

    IS_NEW_ROW=""
    STATUS_BADGE="<span class=\"badge\">SEEN BEFORE</span>"
    if [ "${P_ISNEW[$i]}" = "1" ]; then
        IS_NEW_ROW=" class=\"new-port\""
        STATUS_BADGE="<span class=\"badge-new\">NEW</span>"
    fi

    PORT_PROTO_H=$(html_escape "$PORT_PROTO")
    STATE_H=$(html_escape "$STATE")
    SERVICE_H=$(html_escape "$SERVICE")
    VERSION_H=$(html_escape "$VERSION")

    cat <<EOF >> "$REPORT_FILE"
            <tr$IS_NEW_ROW>
                <td>$PORT_PROTO_H</td>
                <td><span class="badge">$STATE_H</span></td>
                <td>$SERVICE_H</td>
                <td>$VERSION_H</td>
                <td>$STATUS_BADGE</td>
            </tr>
EOF
done

cat <<EOF >> "$REPORT_FILE"
        </table>
EOF

if [ "${#WEB_RESULT_ROWS_TOOL[@]}" -gt 0 ]; then
    cat <<EOF >> "$REPORT_FILE"
        <h2>Web Reconnaissance Summary</h2>
        <table>
            <tr><th>Tool</th><th>URL</th><th>Status</th><th>Findings</th></tr>
EOF
    for i in "${!WEB_RESULT_ROWS_TOOL[@]}"; do
        TOOL_H=$(html_escape "${WEB_RESULT_ROWS_TOOL[$i]}")
        URL_H=$(html_escape "${WEB_RESULT_ROWS_URL[$i]}")
        ST="${WEB_RESULT_ROWS_STATUS[$i]}"
        CNT_H=$(html_escape "${WEB_RESULT_ROWS_COUNT[$i]}")
        if [ "$ST" = "completed" ]; then BADGE="<span class=\"badge\">COMPLETED</span>"; else BADGE="<span class=\"badge-fail\">FAILED</span>"; fi
        cat <<EOF >> "$REPORT_FILE"
            <tr><td>$TOOL_H</td><td>$URL_H</td><td>$BADGE</td><td>$CNT_H</td></tr>
EOF
    done
    cat <<EOF >> "$REPORT_FILE"
        </table>
EOF
fi

for i in "${!WEB_RESULT_ROWS_PATH[@]}"; do
    FPATH="${WEB_RESULT_ROWS_PATH[$i]}"
    [ -z "$FPATH" ] && continue
    [ -f "$FPATH" ] || continue
    TOOL_H=$(html_escape "${WEB_RESULT_ROWS_TOOL[$i]}")
    URL_H=$(html_escape "${WEB_RESULT_ROWS_URL[$i]}")
    if [[ "$FPATH" == *.html ]]; then
        FNAME_H=$(html_escape "$(basename -- "$FPATH")")
        cat <<EOF >> "$REPORT_FILE"
        <h3>$TOOL_H — $URL_H</h3>
        <p><a href="$FNAME_H" target="_blank" rel="noopener">เปิดรายงานแบบอ่านง่าย</a></p>
EOF
    else
        cat <<EOF >> "$REPORT_FILE"
        <h3>$TOOL_H — $URL_H</h3>
        <pre>$(html_escape "$(cat "$FPATH")")</pre>
EOF
    fi
done

cat <<EOF>> "$REPORT_FILE"
    </div>
</body>
</html>
EOF

echo "[✔] Done! Report Generated at: $REPORT_FILE"
echo -e "${CYAN}บันทึกผลลง database: $DB_FILE (ตาราง recon_scans, recon_assets, recon_port_history, web_recon_results)${NC}"

exit "$EXIT_CODE"