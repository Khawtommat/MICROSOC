#!/bin/bash
#
# ==========================================================
# IP_Intel.sh — IP Intelligence & Threat Investigation สำหรับ Micro-SOC
#
# ดึง IP ที่พบจาก ips_logs (Log_Sentinel) มาเสริมข้อมูล:
#   - RDAP/WHOIS (องค์กร, network range, abuse contact)      [Module A]
#   - GeoIP โดยประมาณ (ประเทศ/เมือง/timezone)                [Module A]
#   - IP Reputation ผ่าน AbuseIPDB (ถ้ามี API key)            [Module A]
#   - พฤติกรรมจาก Security Events ของเราเอง                  [Module B]
#   - Risk Score 0-100 พร้อมเหตุผลประกอบ                     [Module C]
#   - สร้างหน้า ip_investigation.html แยกต่างหาก              [Module D]
#   - แจ้งเตือน Telegram สำหรับ IP ความเสี่ยงสูง (มี cooldown) [Module E]
#
# เป็นสคริปต์แยกต่างหาก ไม่แก้ Log_Sentinel.sh / Smart_Recon.sh /
# Micro_SOC_Report.sh เลย (อ่านจาก microsoc.db อย่างเดียว, เขียนลง
# ตารางใหม่ 4 ตารางที่ไม่ชนกับตารางเดิม) เรียกแยกได้เองหรือให้
# MICROSOC.sh เรียกเป็นขั้นตอนเสริม (ดู MICROSOC.sh)
#
# วิธีใช้:
#   ./IP_Intel.sh                       ตรวจ IP ที่พบล่าสุด 20 รายการใน ips_logs
#   ./IP_Intel.sh --limit 50            ตรวจ 50 รายการล่าสุด
#   ./IP_Intel.sh --check 1.2.3.4       ตรวจ IP เดียวแบบ manual (ไม่ต้องอยู่ใน log)
#   ./IP_Intel.sh --no-reputation       ข้าม AbuseIPDB (ใช้แค่ RDAP/GeoIP)
#   ./IP_Intel.sh --telegram            ส่งแจ้งเตือนเข้า Telegram สำหรับ IP เสี่ยงสูง
#   ./IP_Intel.sh -d /path/microsoc.db -o /path/ip_investigation.html
#
# การตั้งค่า AbuseIPDB (ไม่บังคับ — ถ้าไม่ตั้ง ระบบยังทำงานได้ด้วย RDAP/GeoIP):
#   สร้างไฟล์ ip_intel.env ไว้โฟลเดอร์เดียวกับสคริปต์นี้ (เหมือน telegram.env):
#     ABUSEIPDB_API_KEY="your_key_here"
#   ตั้งสิทธิ์ไฟล์ให้อ่านได้เฉพาะเจ้าของ:  chmod 600 ip_intel.env
#
# ข้อจำกัดด้านเครือข่าย/ความเป็นส่วนตัว:
#   - Private/Loopback/Link-local/Reserved IP จะไม่ถูกส่งไป external API
#     เลย (ดู is_private_ipv4()) — บันทึกไว้ในตารางเฉย ๆ ว่าเป็น private
#   - มี timeout และจำกัดจำนวน IP ต่อรอบ (--limit) กัน rate-limit ของ API
#   - IP ที่เพิ่ง fetch ข้อมูลไปแล้วภายใน cache TTL จะไม่ถูกยิงซ้ำ
# ==========================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

DB_FILE="microsoc.db"
OUTPUT_FILE="ip_investigation.html"
SCHEMA_FILE="$SCRIPT_DIR/schema_ip_intel.sql"
LIMIT=20
MANUAL_IP=""
DO_REPUTATION=1
SEND_TELEGRAM=0
INTEL_CACHE_TTL_HOURS=24
REPUTATION_CACHE_TTL_HOURS=6
ALERT_COOLDOWN_HOURS=6
ALERT_MIN_LEVEL="high"          # ส่งแจ้งเตือนเฉพาะ high/critical เป็นค่าเริ่มต้น
HTTP_TIMEOUT=10

usage() {
    cat <<'EOF'
วิธีใช้: ./IP_Intel.sh [ตัวเลือก]
  -d PATH             path ไฟล์ microsoc.db (default: microsoc.db)
  -o PATH             path ไฟล์ HTML ที่จะสร้าง (default: ip_investigation.html)
  --limit N           จำนวน IP ล่าสุดจาก ips_logs ที่จะตรวจ (default: 20)
  --check IP          ตรวจ IP เดียวแบบ manual (เพิ่มเติมจากที่ดึงจาก log)
  --no-reputation     ข้ามการเรียก AbuseIPDB
  --telegram          ส่งแจ้งเตือนเข้า Telegram สำหรับ IP ความเสี่ยงสูง/วิกฤต
  -h                  แสดงข้อความนี้
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -d) DB_FILE="$2"; shift 2 ;;
        -o) OUTPUT_FILE="$2"; shift 2 ;;
        --limit) LIMIT="$2"; shift 2 ;;
        --check) MANUAL_IP="$2"; shift 2 ;;
        --no-reputation) DO_REPUTATION=0; shift ;;
        --telegram) SEND_TELEGRAM=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo -e "${RED}ไม่รู้จักตัวเลือก: $1${NC}" >&2; usage; exit 1 ;;
    esac
done

if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}--limit ต้องเป็นตัวเลข${NC}" >&2; exit 1
fi

for cmd in curl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[!] ไม่พบคำสั่ง '$cmd' ซึ่งจำเป็นต่อการทำงาน — ติดตั้งก่อนใช้งาน IP_Intel.sh${NC}" >&2
        exit 1
    fi
done
if ! python3 -c "import sqlite3" >/dev/null 2>&1; then
    echo -e "${RED}[!] python3 นี้ไม่มีโมดูล sqlite3 ในตัว — ไม่สามารถทำงานต่อได้${NC}" >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}[!] ไม่พบไฟล์ฐานข้อมูล: $DB_FILE${NC}" >&2
    exit 1
fi
if [ ! -f "$SCHEMA_FILE" ]; then
    echo -e "${RED}[!] ไม่พบ schema_ip_intel.sql ที่ $SCHEMA_FILE (ต้องอยู่โฟลเดอร์เดียวกับ IP_Intel.sh)${NC}" >&2
    exit 1
fi

# ----------------------------------------------------------
# โหลด ip_intel.env (AbuseIPDB key) ถ้ามี — ไม่บังคับ ไม่มีก็ทำงานได้
# (เหมือน telegram.env ของ Micro_SOC_Report.sh: หาในโฟลเดอร์เดียวกับ
# สคริปต์นี้ก่อน) เตือนถ้าไฟล์เปิดให้คนอื่นอ่านได้ (permission ไม่เหมาะสม)
# ----------------------------------------------------------
IP_INTEL_ENV="$SCRIPT_DIR/ip_intel.env"
if [ -z "${ABUSEIPDB_API_KEY:-}" ] && [ -r "$IP_INTEL_ENV" ]; then
    PERM=$(stat -c '%a' "$IP_INTEL_ENV" 2>/dev/null || stat -f '%Lp' "$IP_INTEL_ENV" 2>/dev/null || echo "")
    if [ -n "$PERM" ] && [ "${PERM: -1}" != "0" ]; then
        echo -e "${YELLOW}[!] $IP_INTEL_ENV เปิดให้ user อื่นอ่านได้ (permission $PERM) แนะนำ: chmod 600 $IP_INTEL_ENV${NC}" >&2
    fi
    # shellcheck disable=SC1090
    source "$IP_INTEL_ENV"
fi
# ไม่ log ค่า key เด็ดขาด (ห้าม echo/print ตัวแปรนี้ที่ไหนในสคริปต์)
HAVE_ABUSEIPDB=0
[ -n "${ABUSEIPDB_API_KEY:-}" ] && HAVE_ABUSEIPDB=1
[ "$DO_REPUTATION" -eq 1 ] || HAVE_ABUSEIPDB=0

# โหลด telegram.env ถ้าจะส่งแจ้งเตือน (ใช้ path/pattern เดียวกับ
# Micro_SOC_Report.sh เพื่อให้ตั้งค่าครั้งเดียวใช้ร่วมกันได้)
if [ "$SEND_TELEGRAM" -eq 1 ] && [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then
    TELEGRAM_ENV="$SCRIPT_DIR/telegram.env"
    # shellcheck disable=SC1090
    [ -r "$TELEGRAM_ENV" ] && source "$TELEGRAM_ENV"
fi

# ----------------------------------------------------------
# Helper: sql_escape / html_escape — รูปแบบเดียวกับสคริปต์อื่นในโปรเจกต์
# ----------------------------------------------------------
sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }
html_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

SQL_WARNED=0
Q() {
    local out rc errfile
    errfile=$(mktemp)
    out=$(python3 - "$DB_FILE" "$1" <<'PYEOF' 2>"$errfile"
import sqlite3, sys
db, query = sys.argv[1], sys.argv[2]
con = sqlite3.connect(db)
cur = con.cursor()
cur.execute(query)
rows = cur.fetchall()
for row in rows:
    print("|".join("" if v is None else str(v) for v in row))
PYEOF
)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$SQL_WARNED" -eq 0 ]; then
            echo -e "${RED}[!] คำเตือน: มีคิวรีผิดพลาด${NC}" >&2
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

# ----------------------------------------------------------
# Apply migration (idempotent, additive only — ดู schema_ip_intel.sql)
# ----------------------------------------------------------
if ! python3 - "$DB_FILE" "$SCHEMA_FILE" <<'PYEOF'
import sqlite3, sys
db, schema = sys.argv[1], sys.argv[2]
con = sqlite3.connect(db)
with open(schema) as f:
    con.executescript(f.read())
con.commit()
PYEOF
then
    echo -e "${RED}[!] Migration ล้มเหลว — หยุดทำงาน (ไม่แตะฐานข้อมูลต่อ)${NC}" >&2
    exit 1
fi
echo -e "${GREEN}[*] Schema IP Intelligence พร้อมใช้งาน (migration แบบ additive, ไม่แตะตารางเดิม)${NC}"

# ----------------------------------------------------------
# Module: IP validation + SSRF guard
# รับเฉพาะ IPv4 ที่ถูกรูปแบบเป๊ะเท่านั้นก่อนจะเอาไปต่อ URL เรียก API ใด ๆ
# (ป้องกัน SSRF ผ่านค่าที่มาจาก log/DB/CLI arg ที่อาจถูกแก้ไขหรือพิมพ์ผิด)
# ----------------------------------------------------------
is_valid_ipv4() {
    local ip="$1" IFS=.
    local -a octets
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    read -ra octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    local o
    for o in "${octets[@]}"; do
        [ "${#o}" -gt 1 ] && [ "${o:0:1}" = "0" ] && return 1   # เช่น "01" ไม่ยอมรับ
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

# private/loopback/link-local/reserved (RFC1918, RFC5735 ส่วนที่ใช้บ่อย)
# — ช่วงพวกนี้ไม่มี RDAP/GeoIP สาธารณะที่มีความหมายอยู่แล้ว และการยิง
# request ออกไปโดยไม่จำเป็นอาจเข้าข่าย SSRF หรือรั่วข้อมูลเครือข่ายภายใน
is_private_ipv4() {
    local ip="$1" IFS=.
    local -a o; read -ra o <<< "$ip"
    local a="${o[0]}" b="${o[1]}"
    [ "$a" -eq 10 ] && return 0
    [ "$a" -eq 127 ] && return 0
    [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 0
    [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 0
    [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 0
    [ "$a" -eq 0 ] && return 0
    [ "$a" -ge 224 ] && return 0   # multicast (224-239) + reserved (240-255)
    return 1
}

# ----------------------------------------------------------
# รวบรวมรายการ IP ที่จะตรวจ: จาก ips_logs ล่าสุด N รายการ (distinct)
# บวก --check ที่ระบุมาเพิ่ม (ถ้ามี) — Module B/C ใช้ ips_logs เป็นหลักฐาน
# พฤติกรรมเพราะนี่คือ "IP ที่ Log Sentinel ตรวจพบว่าน่าสงสัยจริง"
# ----------------------------------------------------------
IP_LIST_RAW=$(Q "SELECT DISTINCT ip FROM ips_logs ORDER BY id DESC LIMIT $LIMIT;")
declare -a TARGET_IPS=()
if [ -n "$IP_LIST_RAW" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] && TARGET_IPS+=("$line")
    done <<< "$IP_LIST_RAW"
fi
if [ -n "$MANUAL_IP" ]; then
    if is_valid_ipv4 "$MANUAL_IP"; then
        TARGET_IPS+=("$MANUAL_IP")
    else
        echo -e "${RED}[!] --check $MANUAL_IP ไม่ใช่ IPv4 ที่ถูกต้อง — ข้าม${NC}" >&2
    fi
fi

if [ "${#TARGET_IPS[@]}" -eq 0 ]; then
    echo -e "${YELLOW}[*] ไม่มี IP ให้ตรวจ (ips_logs ว่างและไม่ได้ระบุ --check) — จบการทำงาน${NC}"
    exit 0
fi

echo -e "${BLUE}[*] จะตรวจ ${#TARGET_IPS[@]} IP (unique, รวม --check ถ้ามี)${NC}"

# ----------------------------------------------------------
# http_get: curl พร้อม timeout/retry ที่สมเหตุสมผล ไม่ throw error หยุด
# ทั้งสคริปต์ถ้า API ล้มเหลว (requirement: API ล้มเหลวแล้วระบบหลักยังทำงานได้)
# คืนค่า "HTTP_CODE\nBODY" เสมอ ให้ผู้เรียกตัดสินใจเอง
# ----------------------------------------------------------
http_get() {
    local url="$1"; shift
    local resp
    resp=$(curl -s -w '\n%{http_code}' --max-time "$HTTP_TIMEOUT" "$@" "$url" 2>/dev/null)
    local code body
    code=$(printf '%s' "$resp" | tail -n1)
    body=$(printf '%s' "$resp" | sed '$d')
    printf '%s\n%s' "$code" "$body"
}

# ----------------------------------------------------------
# Module A: RDAP + GeoIP + AbuseIPDB
# ----------------------------------------------------------
fetch_intelligence() {
    local ip="$1"
    # RDAP ผ่าน rdap.org (proxy ไปยัง RIR ที่ถูกต้องให้อัตโนมัติ ไม่ต้อง
    # เดาเองว่า IP นี้อยู่ใน ARIN/RIPE/APNIC/LACNIC/AFRINIC)
    local rdap_resp rdap_code rdap_body
    rdap_resp=$(http_get "https://rdap.org/ip/$ip")
    rdap_code=$(printf '%s' "$rdap_resp" | head -n1)
    rdap_body=$(printf '%s' "$rdap_resp" | tail -n +2)

    local geo_resp geo_code geo_body
    geo_resp=$(http_get "https://ipapi.co/$ip/json/")
    geo_code=$(printf '%s' "$geo_resp" | head -n1)
    geo_body=$(printf '%s' "$geo_resp" | tail -n +2)

    python3 - "$ip" "$rdap_code" "$geo_code" <<PYEOF
import json, sys
ip, rdap_code, geo_code = sys.argv[1], sys.argv[2], sys.argv[3]
rdap_body = """$(printf '%s' "$rdap_body" | sed 's/"/\\"/g')"""
geo_body = """$(printf '%s' "$geo_body" | sed 's/"/\\"/g')"""

org = net_range = abuse_contact = asn = as_org = ""
status = "error"; err = ""
try:
    if rdap_code == "200":
        d = json.loads(rdap_body)
        org = (d.get("name") or "")
        net_range = f"{d.get('startAddress','')}-{d.get('endAddress','')}".strip('-')
        for ent in d.get("entities", []) or []:
            roles = ent.get("roles", []) or []
            if "abuse" in roles:
                for vc in (ent.get("vcardArray") or [None, []])[1]:
                    if isinstance(vc, list) and len(vc) >= 4 and vc[0] == "email":
                        abuse_contact = vc[3]
        asn_list = d.get("asn") or ""
        asn = str(asn_list) if asn_list else ""
        status = "ok"
    elif rdap_code == "404":
        status = "not_found"
    else:
        status = "error"; err = f"RDAP HTTP {rdap_code}"
except Exception as e:
    status = "error"; err = f"RDAP parse error: {e}"

country = region = city = tz = ""
try:
    if geo_code == "200":
        g = json.loads(geo_body)
        if not g.get("error"):
            country = g.get("country_name") or ""
            region = g.get("region") or ""
            city = g.get("city") or ""
            tz = g.get("timezone") or ""
            as_org = g.get("org") or ""
            if not asn and g.get("asn"):
                asn = str(g.get("asn"))
except Exception:
    pass

print(json.dumps({
    "status": status, "error": err, "country": country, "region": region,
    "city": city, "timezone": tz, "asn": asn, "as_org": as_org,
    "network_range": net_range, "rdap_org": org, "abuse_contact": abuse_contact,
}))
PYEOF
}

fetch_reputation() {
    local ip="$1"
    local resp code body
    resp=$(http_get "https://api.abuseipdb.com/api/v2/check" \
        -G --data-urlencode "ipAddress=$ip" --data-urlencode "maxAgeInDays=90" \
        -H "Key: ${ABUSEIPDB_API_KEY}" -H "Accept: application/json")
    code=$(printf '%s' "$resp" | head -n1)
    body=$(printf '%s' "$resp" | tail -n +2)
    python3 - "$code" <<PYEOF
import json, sys
code = sys.argv[1]
body = """$(printf '%s' "$body" | sed 's/"/\\"/g')"""
score = reports = None; last_reported = ""; categories = ""; status = "error"; err = ""
try:
    if code == "200":
        d = json.loads(body).get("data", {})
        score = d.get("abuseConfidenceScore")
        reports = d.get("totalReports")
        last_reported = d.get("lastReportedAt") or ""
        status = "ok"
    elif code == "401" or code == "403":
        status = "error"; err = "AbuseIPDB: API key ไม่ถูกต้องหรือไม่มีสิทธิ์"
    elif code == "429":
        status = "rate_limited"; err = "AbuseIPDB: เกิน rate limit"
    else:
        status = "error"; err = f"AbuseIPDB HTTP {code}"
except Exception as e:
    status = "error"; err = f"AbuseIPDB parse error: {e}"
print(json.dumps({"status": status, "error": err, "score": score, "reports": reports,
                   "last_reported": last_reported, "categories": categories}))
PYEOF
}

# ----------------------------------------------------------
# Module B + C: ดึงพฤติกรรมจาก ips_logs ของเราเอง แล้วให้คะแนนความเสี่ยง
# กฎการให้คะแนน (rule-based, อธิบายได้ทุกแต้ม — ไม่ใช้ black-box):
#   - fail_count สูงสุดที่เคยพบ: >=30 -> +25, >=15 -> +15, >=5 -> +8
#   - เคยถูกแบนจริงอย่างน้อย 1 ครั้ง: +20
#   - จำนวนครั้งที่ถูกบันทึกใน ips_logs (พฤติกรรมต่อเนื่อง): >=5 -> +15, >=2 -> +7
#   - AbuseIPDB score (ถ้ามี): บวกตรง ๆ * 0.4 (คะแนนเต็ม 100 ของ provider
#     คิดเป็นน้ำหนักสูงสุด 40 แต้มของเรา ไม่ให้ provider เดียวชี้ขาดทั้งหมด)
#   - AbuseIPDB reports_count: >=50 -> +10, >=10 -> +5
# รวมแล้ว clamp 0-100 แล้วแปลงเป็นระดับ: <25 low, <50 medium, <80 high, >=80 critical
# ข้อควรรู้: "จำนวน request เยอะอย่างเดียว" ไม่ถูกใช้ให้คะแนนเลย (ตามข้อกำหนด
# ในงานว่าห้ามตัดสินจากปริมาณอย่างเดียว) — ต้องมี fail/ban จริงประกอบเสมอ
# ----------------------------------------------------------
compute_risk() {
    local ip="$1" abuse_score="$2" abuse_reports="$3"
    local stats
    stats=$(Q "SELECT MAX(fail_count), SUM(CASE WHEN action='banned' THEN 1 ELSE 0 END), COUNT(*) FROM ips_logs WHERE ip='$(sql_escape "$ip")';")
    local max_fail banned_count event_count
    IFS='|' read -r max_fail banned_count event_count <<< "$stats"
    max_fail=${max_fail:-0}; banned_count=${banned_count:-0}; event_count=${event_count:-0}
    [[ "$max_fail" =~ ^[0-9]+$ ]] || max_fail=0
    [[ "$banned_count" =~ ^[0-9]+$ ]] || banned_count=0
    [[ "$event_count" =~ ^[0-9]+$ ]] || event_count=0

    local score=0
    local -a reasons=()

    if [ "$max_fail" -ge 30 ]; then score=$((score+25)); reasons+=("Failed login สูงสุด $max_fail ครั้ง (>=30) ในรอบเดียว")
    elif [ "$max_fail" -ge 15 ]; then score=$((score+15)); reasons+=("Failed login สูงสุด $max_fail ครั้ง (>=15) ในรอบเดียว")
    elif [ "$max_fail" -ge 5 ]; then score=$((score+8)); reasons+=("Failed login สูงสุด $max_fail ครั้ง (>=5) ในรอบเดียว")
    fi

    if [ "$banned_count" -gt 0 ]; then
        score=$((score+20)); reasons+=("เคยถูก Auto-Ban จริงแล้ว $banned_count ครั้ง")
    fi

    if [ "$event_count" -ge 5 ]; then score=$((score+15)); reasons+=("พบพฤติกรรมต่อเนื่อง $event_count เหตุการณ์ใน ips_logs")
    elif [ "$event_count" -ge 2 ]; then score=$((score+7)); reasons+=("พบ $event_count เหตุการณ์ใน ips_logs")
    fi

    if [[ "$abuse_score" =~ ^[0-9]+$ ]]; then
        local rep_add=$(( abuse_score * 4 / 10 ))
        score=$((score+rep_add))
        reasons+=("AbuseIPDB confidence score $abuse_score/100")
        if [[ "$abuse_reports" =~ ^[0-9]+$ ]]; then
            if [ "$abuse_reports" -ge 50 ]; then score=$((score+10)); reasons+=("AbuseIPDB มีรายงาน $abuse_reports ครั้ง (>=50)")
            elif [ "$abuse_reports" -ge 10 ]; then score=$((score+5)); reasons+=("AbuseIPDB มีรายงาน $abuse_reports ครั้ง (>=10)")
            fi
        fi
    fi

    [ "$score" -gt 100 ] && score=100
    [ "$score" -lt 0 ] && score=0

    local level="low"
    if [ "$score" -ge 80 ]; then level="critical"
    elif [ "$score" -ge 50 ]; then level="high"
    elif [ "$score" -ge 25 ]; then level="medium"
    fi

    if [ "${#reasons[@]}" -eq 0 ]; then reasons+=("ไม่พบพฤติกรรมผิดปกติที่มีนัยสำคัญจากหลักฐานที่มี"); fi

    local reasons_json
    reasons_json=$(printf '%s\n' "${reasons[@]}" | python3 -c "import json,sys; print(json.dumps([l.rstrip() for l in sys.stdin]))")

    printf '%s|%s|%s|%s|%s' "$score" "$level" "$reasons_json" "$event_count" "$([ -n "$abuse_score" ] && echo 1 || echo 0)"
}

# ----------------------------------------------------------
# level_rank(): แปลงชื่อ risk level เป็นตัวเลขลำดับ (low < medium < high
# < critical) ใช้เทียบกับ $ALERT_MIN_LEVEL ว่าควรส่งแจ้งเตือนหรือไม่
# ("ไม่รู้จัก" ถือว่า error — คืนค่าว่างและ exit code != 0)
# ----------------------------------------------------------
level_rank() {
    case "$1" in
        low)      echo 0 ;;
        medium)   echo 1 ;;
        high)     echo 2 ;;
        critical) echo 3 ;;
        *)        return 1 ;;
    esac
}

# ----------------------------------------------------------
# Telegram alert พร้อม cooldown/dedup (Module E) — เช็คจาก
# ip_investigation_history ว่า "alert_sent" ล่าสุดของ ip+level นี้
# ห่างจากตอนนี้เกิน ALERT_COOLDOWN_HOURS หรือยัง ถ้ายังไม่ถึง ให้ข้าม
# ส่งเฉพาะ level ที่ >= ALERT_MIN_LEVEL (ค่าเริ่มต้น "high" ให้ผลเหมือนของ
# เดิมที่เคย hardcode เป็น high|critical พอดี)
# ----------------------------------------------------------
send_telegram_alert() {
    local ip="$1" level="$2" score="$3" reasons_json="$4"
    [ "$SEND_TELEGRAM" -eq 1 ] || return 0
    local lvl_val min_val
    lvl_val=$(level_rank "$level") || return 0
    min_val=$(level_rank "$ALERT_MIN_LEVEL") || return 0
    [ "$lvl_val" -ge "$min_val" ] || return 0

    local last_alert
    last_alert=$(Q "SELECT performed_at FROM ip_investigation_history WHERE ip='$(sql_escape "$ip")' AND action='alert_sent' ORDER BY performed_at DESC LIMIT 1;")
    if [ -n "$last_alert" ]; then
        local hours_since
        hours_since=$(python3 -c "
from datetime import datetime
try:
    then = datetime.strptime('$last_alert', '%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    print(int((now-then).total_seconds()//3600))
except Exception:
    print(999999)
")
        if [ "$hours_since" -lt "$ALERT_COOLDOWN_HOURS" ]; then
            python3 - "$DB_FILE" "$ip" "alert_skipped_cooldown" "ยังอยู่ใน cooldown ($hours_since/$ALERT_COOLDOWN_HOURS ชม.)" <<'PYEOF'
import sqlite3, sys
db, ip, action, detail = sys.argv[1:5]
con = sqlite3.connect(db)
con.execute("INSERT INTO ip_investigation_history (ip, action, detail) VALUES (?,?,?)", (ip, action, detail))
con.commit()
PYEOF
            echo -e "${YELLOW}    [cooldown] $ip: เพิ่งแจ้งเตือนไปเมื่อ $hours_since ชม.ก่อน — ข้าม${NC}"
            return 0
        fi
    fi

    if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
        echo -e "${RED}    [!] ไม่พบ TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID — ข้ามแจ้งเตือนสำหรับ $ip${NC}" >&2
        return 0
    fi

    local reasons_text level_th emoji
    reasons_text=$(python3 -c "import json,sys; print('\n'.join('- '+r for r in json.loads(sys.argv[1])))" "$reasons_json")
    case "$level" in
        critical) emoji="🔴"; level_th="วิกฤต (Critical)" ;;
        *) emoji="🟠"; level_th="สูง (High)" ;;
    esac

    local msg
    msg=$(cat <<MSGEOF
${emoji} <b>IP ความเสี่ยง${level_th}</b>
🌐 IP: $(html_escape "$ip")
📊 Risk Score: $(html_escape "$score")/100

เหตุผล:
$(html_escape "$reasons_text")

(คะแนนนี้เป็นการประเมินจากข้อมูลที่มี ไม่ใช่การยืนยันว่า IP นี้คือผู้โจมตี)
MSGEOF
)
    local resp code
    resp=$(curl -s -w '\n%{http_code}' --max-time "$HTTP_TIMEOUT" -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "text=${msg}")
    code=$(printf '%s' "$resp" | tail -n1)
    if [ "$code" = "200" ]; then
        echo -e "${GREEN}    [telegram] ส่งแจ้งเตือน $ip สำเร็จ${NC}"
        python3 - "$DB_FILE" "$ip" "alert_sent" "level=$level score=$score" <<'PYEOF'
import sqlite3, sys
db, ip, action, detail = sys.argv[1:5]
con = sqlite3.connect(db)
con.execute("INSERT INTO ip_investigation_history (ip, action, detail) VALUES (?,?,?)", (ip, action, detail))
con.commit()
PYEOF
    else
        echo -e "${RED}    [!] ส่ง Telegram ไม่สำเร็จ (HTTP $code) สำหรับ $ip${NC}" >&2
    fi
}

# ----------------------------------------------------------
# วนตรวจทีละ IP
# ----------------------------------------------------------
for ip in "${TARGET_IPS[@]}"; do
    if ! is_valid_ipv4 "$ip"; then
        echo -e "${YELLOW}[*] ข้าม '$ip' — ไม่ใช่ IPv4 ที่ถูกรูปแบบ${NC}"
        continue
    fi
    echo -e "${BLUE}[*] ตรวจสอบ $ip${NC}"

    IP_ESC=$(sql_escape "$ip")

    if is_private_ipv4 "$ip"; then
        python3 - "$DB_FILE" "$ip" <<'PYEOF'
import sqlite3, sys
db, ip = sys.argv[1], sys.argv[2]
con = sqlite3.connect(db)
con.execute("""INSERT INTO ip_intelligence (ip, is_private, status, source, fetched_at)
                VALUES (?, 1, 'skipped_private', 'private', datetime('now','localtime'))
                ON CONFLICT(ip) DO UPDATE SET is_private=1, status='skipped_private',
                    source='private', fetched_at=datetime('now','localtime')""", (ip,))
con.commit()
PYEOF
        echo -e "${YELLOW}    private/loopback/reserved IP — ไม่เรียก external API${NC}"
        REP_SCORE=""; REP_REPORTS=""
    else
        # เช็ค cache: ข้าม fetch ถ้าเพิ่งดึงไปภายใน TTL
        LAST_FETCH=$(Q "SELECT fetched_at FROM ip_intelligence WHERE ip='$IP_ESC';")
        NEED_FETCH=1
        if [ -n "$LAST_FETCH" ]; then
            AGE_H=$(python3 -c "
from datetime import datetime
try:
    print(int((datetime.now()-datetime.strptime('$LAST_FETCH','%Y-%m-%d %H:%M:%S')).total_seconds()//3600))
except Exception:
    print(999999)
")
            [ "$AGE_H" -lt "$INTEL_CACHE_TTL_HOURS" ] && NEED_FETCH=0
        fi

        if [ "$NEED_FETCH" -eq 1 ]; then
            INTEL_JSON=$(fetch_intelligence "$ip")
            python3 - "$DB_FILE" "$ip" "$INTEL_JSON" <<'PYEOF'
import sqlite3, sys, json
db, ip, intel_json = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(intel_json)
con = sqlite3.connect(db)
con.execute("""INSERT INTO ip_intelligence
    (ip, is_private, country, region, city, timezone, asn, as_org, network_range,
     rdap_org, abuse_contact, source, status, error_message, fetched_at)
    VALUES (?,0,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'))
    ON CONFLICT(ip) DO UPDATE SET
        is_private=0, country=excluded.country, region=excluded.region, city=excluded.city,
        timezone=excluded.timezone, asn=excluded.asn, as_org=excluded.as_org,
        network_range=excluded.network_range, rdap_org=excluded.rdap_org,
        abuse_contact=excluded.abuse_contact, source=excluded.source,
        status=excluded.status, error_message=excluded.error_message,
        fetched_at=datetime('now','localtime')""",
    (ip, d.get("country",""), d.get("region",""), d.get("city",""), d.get("timezone",""),
     d.get("asn",""), d.get("as_org",""), d.get("network_range",""), d.get("rdap_org",""),
     d.get("abuse_contact",""), "rdap+ipapi", d.get("status","error"), d.get("error","")))
con.execute("INSERT INTO ip_investigation_history (ip, action, detail) VALUES (?, 'lookup', ?)",
            (ip, f"intel status={d.get('status')}"))
con.commit()
PYEOF
            echo "    intelligence: fetched"
        else
            echo "    intelligence: ใช้ cache (อายุ ${AGE_H} ชม. < $INTEL_CACHE_TTL_HOURS ชม.)"
        fi

        REP_SCORE=""; REP_REPORTS=""
        if [ "$HAVE_ABUSEIPDB" -eq 1 ]; then
            LAST_REP=$(Q "SELECT fetched_at FROM ip_reputation WHERE ip='$IP_ESC' AND provider='abuseipdb' ORDER BY fetched_at DESC LIMIT 1;")
            REP_NEED_FETCH=1
            if [ -n "$LAST_REP" ]; then
                REP_AGE_H=$(python3 -c "
from datetime import datetime
try:
    print(int((datetime.now()-datetime.strptime('$LAST_REP','%Y-%m-%d %H:%M:%S')).total_seconds()//3600))
except Exception:
    print(999999)
")
                [ "$REP_AGE_H" -lt "$REPUTATION_CACHE_TTL_HOURS" ] && REP_NEED_FETCH=0
            fi
            if [ "$REP_NEED_FETCH" -eq 1 ]; then
                REP_JSON=$(fetch_reputation "$ip")
                read -r REP_SCORE REP_REPORTS REP_STATUS REP_ERR < <(python3 -c "
import json,sys
d=json.loads(sys.argv[1])
print(d.get('score') if d.get('score') is not None else '', d.get('reports') if d.get('reports') is not None else '', d.get('status',''), (d.get('error') or '').replace(' ','_'))
" "$REP_JSON")
                python3 - "$DB_FILE" "$ip" "$REP_JSON" <<'PYEOF'
import sqlite3, sys, json
db, ip, rep_json = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(rep_json)
con = sqlite3.connect(db)
con.execute("""INSERT INTO ip_reputation
    (ip, provider, abuse_score, reports_count, last_reported_at, categories, status, error_message, fetched_at)
    VALUES (?, 'abuseipdb', ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
    (ip, d.get("score"), d.get("reports"), d.get("last_reported",""), d.get("categories",""),
     d.get("status","error"), d.get("error","")))
con.commit()
PYEOF
                echo "    reputation: fetched (status=${REP_STATUS:-?})"
                if [ "${REP_STATUS:-}" != "ok" ] && [ -n "${REP_ERR:-}" ]; then
                    echo "    reputation error: ${REP_ERR//_/ }"
                fi
            else
                read -r REP_SCORE REP_REPORTS < <(Q "SELECT abuse_score, reports_count FROM ip_reputation WHERE ip='$IP_ESC' AND provider='abuseipdb' ORDER BY fetched_at DESC LIMIT 1;" | tr '|' ' ')
                echo "    reputation: ใช้ cache (อายุ ${REP_AGE_H} ชม. < $REPUTATION_CACHE_TTL_HOURS ชม.)"
            fi
        fi
    fi

    IFS='|' read -r RISK_SCORE RISK_LEVEL REASONS_JSON BASED_EVENTS BASED_REP < <(compute_risk "$ip" "${REP_SCORE:-}" "${REP_REPORTS:-}")
    python3 - "$DB_FILE" "$ip" "$RISK_SCORE" "$RISK_LEVEL" "$REASONS_JSON" "$BASED_EVENTS" "$BASED_REP" <<'PYEOF'
import sqlite3, sys
db, ip, score, level, reasons, ev, rep = sys.argv[1:8]
con = sqlite3.connect(db)
con.execute("""INSERT INTO ip_risk_assessments
    (ip, risk_score, risk_level, reasons_json, based_on_events, based_on_reputation)
    VALUES (?,?,?,?,?,?)""", (ip, int(score), level, reasons, int(ev), int(rep)))
con.commit()
PYEOF
    echo -e "    risk: ${RISK_SCORE}/100 (${RISK_LEVEL})"

    send_telegram_alert "$ip" "$RISK_LEVEL" "$RISK_SCORE" "$REASONS_JSON"
done

# ----------------------------------------------------------
# Module D: สร้าง ip_investigation.html (หน้าแยก ไม่แตะ dashboard.html เดิม)
# ข้อมูลทั้งหมด escape เป็น JSON ด้วย python3 json.dumps (ปลอดภัยกว่า
# เขียน escape เองด้วย sed) และปิดช่องโหว่ "</script>" injection ด้วย
# การแทนที่ "</" เป็น "<\/" ในสตริง JSON ก่อนฝังลง <script>
# ----------------------------------------------------------
ROWS_JSON=$(python3 - "$DB_FILE" <<'PYEOF'
import sqlite3, json, sys
db = sys.argv[1]
con = sqlite3.connect(db)
con.row_factory = sqlite3.Row
rows = con.execute("""
    SELECT i.ip, i.country, i.region, i.city, i.as_org, i.asn, i.rdap_org,
           i.abuse_contact, i.network_range, i.is_private, i.status AS intel_status,
           i.fetched_at AS intel_fetched_at
    FROM ip_intelligence i
""").fetchall()
result = []
for r in rows:
    ip = r["ip"]
    risk = con.execute("""SELECT risk_score, risk_level, reasons_json, assessed_at
                           FROM ip_risk_assessments WHERE ip=? ORDER BY assessed_at DESC LIMIT 1""", (ip,)).fetchone()
    rep = con.execute("""SELECT abuse_score, reports_count, last_reported_at, status
                          FROM ip_reputation WHERE ip=? AND provider='abuseipdb'
                          ORDER BY fetched_at DESC LIMIT 1""", (ip,)).fetchone()
    events = con.execute("""SELECT fail_count, action, detected_at, banned_at, source_log
                             FROM ips_logs WHERE ip=? ORDER BY detected_at DESC LIMIT 50""", (ip,)).fetchall()
    history = con.execute("""SELECT action, detail, performed_at FROM ip_investigation_history
                              WHERE ip=? ORDER BY performed_at DESC LIMIT 50""", (ip,)).fetchall()
    result.append({
        "ip": ip, "country": r["country"] or "", "region": r["region"] or "",
        "city": r["city"] or "", "as_org": r["as_org"] or "", "asn": r["asn"] or "",
        "rdap_org": r["rdap_org"] or "", "abuse_contact": r["abuse_contact"] or "",
        "network_range": r["network_range"] or "", "is_private": bool(r["is_private"]),
        "intel_status": r["intel_status"] or "", "intel_fetched_at": r["intel_fetched_at"] or "",
        "risk_score": risk["risk_score"] if risk else None,
        "risk_level": risk["risk_level"] if risk else "low",
        "reasons": json.loads(risk["reasons_json"]) if risk else [],
        "assessed_at": risk["assessed_at"] if risk else "",
        "abuse_score": rep["abuse_score"] if rep else None,
        "abuse_reports": rep["reports_count"] if rep else None,
        "abuse_last_reported": rep["last_reported_at"] if rep else "",
        "events": [dict(e) for e in events],
        "event_count": len(events),
        "history": [dict(h) for h in history],
    })
# เรียงความเสี่ยงสูงสุดก่อน
order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
result.sort(key=lambda x: order.get(x["risk_level"], 9))
out = json.dumps(result, ensure_ascii=False)
out = out.replace("</", "<\\/")   # กัน </script> injection ตอนฝังลง HTML
print(out)
PYEOF
)

TOTAL_IPS=$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$ROWS_JSON" 2>/dev/null || echo 0)
GEN_TIME=$(date +'%Y-%m-%d %H:%M:%S')

# ลิงก์ย้อนกลับไป dashboard.html ถ้ามีอยู่ในโฟลเดอร์เดียวกับไฟล์นี้ (symmetric
# กับลิงก์ที่ Micro_SOC_Report.sh ใส่ไว้จาก dashboard มาหน้านี้อยู่แล้ว —
# เดิมมีแค่ทิศทางเดียว ไม่มีทางกลับ) ถ้าไม่มี dashboard.html ก็ไม่โชว์ลิงก์
BACK_TO_DASHBOARD_HTML=""
OUT_DIR=$(cd "$(dirname -- "$OUTPUT_FILE")" 2>/dev/null && pwd -P)
if [ -n "$OUT_DIR" ] && [ -f "$OUT_DIR/dashboard.html" ]; then
    BACK_TO_DASHBOARD_HTML='<a href="dashboard.html" style="display:inline-block;margin-top:10px;padding:6px 14px;border-radius:999px;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.28);color:#fff;font-size:12px;font-weight:700;text-decoration:none">← กลับไป Dashboard</a>'
fi

cat > "$OUTPUT_FILE" <<HTML
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Micro-SOC — IP Investigation</title>
<style>
  :root{--ink:#15243b;--muted:#64748b;--line:#dbe4ef;--navy:#152c4b;--navy2:#254e78;--accent:#ec7053}
  *{box-sizing:border-box}
  body{font-family:Arial,"Noto Sans Thai",sans-serif;margin:0;background:#eef3f8;color:var(--ink)}
  .wrap{max-width:1300px;margin:0 auto;padding:28px 20px}
  .head{padding:26px;border-radius:14px;background:linear-gradient(120deg,var(--navy),var(--navy2));color:#fff;margin-bottom:18px}
  .head h1{margin:0 0 6px;font-size:26px}
  .head p{margin:0;color:#d7e4f1;font-size:13px}
  .toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
  .toolbar input,.toolbar select{padding:8px 10px;border:1px solid var(--line);border-radius:8px;font-size:13px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(21,44,75,.06)}
  th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
  th{background:var(--navy);color:#fff;position:sticky;top:0}
  tr:hover{background:#f3f8fd;cursor:pointer}
  .badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}
  .badge-low{background:#27ae60}.badge-medium{background:#d99a2b}.badge-high{background:#e05a4f}.badge-critical{background:#a93636}
  .empty{color:var(--muted);text-align:center;padding:30px}
  #detail{display:none;margin-top:16px;background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(21,44,75,.06)}
  #detail h2{margin-top:0}
  #detail .reasons li{margin:4px 0}
  #detail .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:14px 0}
  #detail .grid div{background:#f6f9fc;border:1px solid var(--line);border-radius:8px;padding:10px}
  #detail .grid b{display:block;font-size:11px;color:var(--muted);margin-bottom:3px}
  .note{color:var(--muted);font-size:12px;margin:8px 0 16px}
  .closebtn{float:right;cursor:pointer;color:var(--muted)}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <h1>🔎 IP Investigation</h1>
    <p>อัปเดตล่าสุด: $(html_escape "$GEN_TIME") | ตรวจสอบแล้ว $(html_escape "$TOTAL_IPS") IP | ข้อมูลนี้เป็นการประเมินจากหลักฐานที่มี ไม่ใช่การยืนยันตัวตนผู้โจมตี (IP อาจเป็น VPN/Proxy/NAT/เครื่องที่ถูกควบคุม)</p>
    ${BACK_TO_DASHBOARD_HTML}
  </div>
  <div class="toolbar">
    <input id="searchBox" type="text" placeholder="ค้นหา IP / ประเทศ / องค์กร...">
    <select id="levelFilter">
      <option value="">ทุกระดับความเสี่ยง</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
  </div>
  <table id="ipTable">
    <thead><tr>
      <th>IP</th><th>Country</th><th>ISP/Org</th><th>ASN</th>
      <th>Reputation</th><th>Events</th><th>Risk</th><th>Last Seen</th>
    </tr></thead>
    <tbody id="ipTableBody"></tbody>
  </table>
  <div id="emptyMsg" class="empty" style="display:none">ไม่พบ IP ที่ตรงเงื่อนไข</div>

  <div id="detail">
    <span class="closebtn" onclick="document.getElementById('detail').style.display='none'">✕ ปิด</span>
    <h2 id="d_ip"></h2>
    <p class="note">ค่าความน่าเชื่อถือของตำแหน่งที่ตั้งเป็นการประมาณการจาก GeoIP เท่านั้น ไม่ใช่ตำแหน่งจริงของผู้ใช้งาน</p>
    <div class="grid">
      <div><b>Country / Region / City</b><span id="d_geo"></span></div>
      <div><b>ASN</b><span id="d_asn"></span></div>
      <div><b>Organization</b><span id="d_org"></span></div>
      <div><b>Network Range</b><span id="d_range"></span></div>
      <div><b>Abuse Contact</b><span id="d_abuse_contact"></span></div>
      <div><b>AbuseIPDB Score</b><span id="d_abuse_score"></span></div>
    </div>
    <h3>Risk Score: <span id="d_risk"></span></h3>
    <ul class="reasons" id="d_reasons"></ul>
    <h3>Security Events (ips_logs)</h3>
    <table id="d_events"><thead><tr><th>เวลา</th><th>Fail Count</th><th>Action</th><th>Banned At</th></tr></thead><tbody></tbody></table>
    <h3>ประวัติการตรวจสอบ</h3>
    <table id="d_history"><thead><tr><th>เวลา</th><th>Action</th><th>Detail</th></tr></thead><tbody></tbody></table>
  </div>
</div>
<script id="ipData" type="application/json">${ROWS_JSON}</script>
<script>
const data = JSON.parse(document.getElementById('ipData').textContent);
const tbody = document.getElementById('ipTableBody');
const emptyMsg = document.getElementById('emptyMsg');
function esc(s){ const d=document.createElement('div'); d.textContent = (s===null||s===undefined)?'':s; return d.innerHTML; }
function badge(level){ return '<span class="badge badge-'+level+'">'+level.toUpperCase()+'</span>'; }
function render(list){
  tbody.innerHTML='';
  emptyMsg.style.display = list.length ? 'none' : 'block';
  list.forEach((row, idx)=>{
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>'+esc(row.ip)+(row.is_private?' <small>(private)</small>':'')+'</td>'+
      '<td>'+esc(row.country)+'</td>'+
      '<td>'+esc(row.as_org || row.rdap_org)+'</td>'+
      '<td>'+esc(row.asn)+'</td>'+
      '<td>'+(row.abuse_score!==null?esc(row.abuse_score)+'/100':'—')+'</td>'+
      '<td>'+esc(row.event_count)+'</td>'+
      '<td>'+badge(row.risk_level)+' '+esc(row.risk_score)+'</td>'+
      '<td>'+esc((row.events[0]||{}).detected_at || '')+'</td>';
    tr.onclick = ()=> showDetail(row);
    tbody.appendChild(tr);
  });
}
function showDetail(row){
  document.getElementById('detail').style.display='block';
  document.getElementById('d_ip').textContent = row.ip + (row.is_private ? ' (private/internal IP)' : '');
  document.getElementById('d_geo').textContent = [row.country,row.region,row.city].filter(Boolean).join(' / ') || '—';
  document.getElementById('d_asn').textContent = row.asn || '—';
  document.getElementById('d_org').textContent = row.as_org || row.rdap_org || '—';
  document.getElementById('d_range').textContent = row.network_range || '—';
  document.getElementById('d_abuse_contact').textContent = row.abuse_contact || '—';
  document.getElementById('d_abuse_score').textContent = row.abuse_score!==null ? (row.abuse_score+'/100 ('+(row.abuse_reports||0)+' reports)') : 'ไม่มีข้อมูล (ไม่ได้ตั้งค่า AbuseIPDB หรือยังไม่เคยถูกรายงาน)';
  document.getElementById('d_risk').innerHTML = badge(row.risk_level) + ' ' + row.risk_score + '/100';
  const rl = document.getElementById('d_reasons'); rl.innerHTML='';
  (row.reasons||[]).forEach(r=>{ const li=document.createElement('li'); li.textContent=r; rl.appendChild(li); });
  const evb = document.querySelector('#d_events tbody'); evb.innerHTML='';
  (row.events||[]).forEach(e=>{
    const tr=document.createElement('tr');
    tr.innerHTML = '<td>'+esc(e.detected_at)+'</td><td>'+esc(e.fail_count)+'</td><td>'+esc(e.action)+'</td><td>'+esc(e.banned_at||'—')+'</td>';
    evb.appendChild(tr);
  });
  const hb = document.querySelector('#d_history tbody'); hb.innerHTML='';
  (row.history||[]).forEach(h=>{
    const tr=document.createElement('tr');
    tr.innerHTML = '<td>'+esc(h.performed_at)+'</td><td>'+esc(h.action)+'</td><td>'+esc(h.detail||'')+'</td>';
    hb.appendChild(tr);
  });
  window.scrollTo({top: document.getElementById('detail').offsetTop - 20, behavior:'smooth'});
}
function applyFilters(){
  const q = document.getElementById('searchBox').value.trim().toLowerCase();
  const lvl = document.getElementById('levelFilter').value;
  const filtered = data.filter(row=>{
    if (lvl && row.risk_level !== lvl) return false;
    if (!q) return true;
    return (row.ip||'').toLowerCase().includes(q) ||
           (row.country||'').toLowerCase().includes(q) ||
           (row.as_org||'').toLowerCase().includes(q) ||
           (row.rdap_org||'').toLowerCase().includes(q);
  });
  render(filtered);
}
document.getElementById('searchBox').addEventListener('input', applyFilters);
document.getElementById('levelFilter').addEventListener('change', applyFilters);
render(data);
</script>
</body>
</html>
HTML

echo -e "${GREEN}[✔] สร้าง $OUTPUT_FILE สำเร็จ (${TOTAL_IPS} IP)${NC}"
echo -e "${BLUE}[i] บันทึกผลลง database: $DB_FILE (ตาราง ip_intelligence, ip_reputation, ip_risk_assessments, ip_investigation_history)${NC}"
[ "$HAVE_ABUSEIPDB" -eq 0 ] && echo -e "${YELLOW}[i] ไม่ได้ตั้งค่า ABUSEIPDB_API_KEY — ใช้ได้แค่ RDAP/GeoIP (risk score จะไม่รวมคะแนน reputation)${NC}"
exit 0