-- ==========================================================
-- schema_ip_intel.sql — ส่วนเสริม IP Intelligence & Threat
-- Investigation สำหรับ microsoc.db (ไม่แก้ schema เดิมเลย)
--
-- หลักการ: CREATE TABLE IF NOT EXISTS ทั้งหมด ปลอดภัยสำหรับ DB เดิม
-- ไม่มี ALTER TABLE ของตารางเดิม ไม่มี DROP TABLE ที่ไหนเลย
-- ไฟล์นี้ถูก apply อัตโนมัติทุกครั้งที่รัน IP_Intel.sh (idempotent)
--
-- แยก 4 ตารางตามจุดประสงค์ (Module A/B/C/E ใน task):
--   ip_intelligence        = RDAP/ASN/GeoIP ล่าสุดของแต่ละ IP (1 แถว/IP)
--   ip_reputation          = ผลจาก Reputation provider แต่ละราย
--                            (หลายแถวต่อ IP ได้ — 1 แถวต่อ 1 provider ต่อ
--                            1 ครั้งที่ดึง เพื่อรองรับเพิ่ม provider ใหม่
--                            ในอนาคตโดยไม่ต้องแก้ schema)
--   ip_risk_assessments    = ผลการให้คะแนนความเสี่ยงแต่ละครั้ง (append-only
--                            เพื่อดูย้อนหลังได้ว่าคะแนนเปลี่ยนไปอย่างไร)
--   ip_investigation_history = log การกระทำทุกครั้งที่ระบบ/ผู้ใช้ตรวจสอบ IP
--                            (lookup, alert_sent, manual_check ฯลฯ) ใช้ทั้ง
--                            เป็น audit trail และเป็นฐานของ alert cooldown
-- ==========================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------
-- ip_intelligence: RDAP / ASN / GeoIP ล่าสุดของแต่ละ IP
-- 1 แถวต่อ 1 IP (UPSERT ทับทุกครั้งที่ fetch ใหม่) — ต้องการแค่สถานะล่าสุด
-- ไม่ต้องเก็บประวัติทุกครั้งที่ fetch (ต่างจาก ip_reputation ที่เก็บ
-- ประวัติ เพราะ reputation เปลี่ยนบ่อยกว่าและมีความหมายเชิงเวลามากกว่า)
--
-- fetched_at   = เวลาที่ "ดึงข้อมูล" ครั้งนี้ (แยกจาก first_seen_at ที่เป็น
--                เวลาที่ IP นี้ถูกพบในระบบครั้งแรก ตามข้อกำหนดในงาน)
-- is_private   = 1 ถ้าเป็น private/loopback/link-local/reserved IP
--                (ไม่เคยถูกส่งไป external API เลย ดู IP_Intel.sh)
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_intelligence (
    ip              TEXT    PRIMARY KEY,
    is_private      INTEGER NOT NULL DEFAULT 0,
    country         TEXT,
    region          TEXT,
    city            TEXT,
    timezone        TEXT,
    asn             TEXT,
    as_org          TEXT,
    network_range   TEXT,
    rdap_org        TEXT,
    abuse_contact   TEXT,
    source          TEXT,                              -- เช่น 'rdap+ipapi', 'private', 'lookup_failed'
    status          TEXT    NOT NULL DEFAULT 'ok'
                    CHECK (status IN ('ok', 'not_found', 'error', 'skipped_private', 'rate_limited', 'timeout')),
    error_message   TEXT,
    first_seen_at   TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    fetched_at      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_ip_intelligence_country ON ip_intelligence(country);
CREATE INDEX IF NOT EXISTS idx_ip_intelligence_fetched_at ON ip_intelligence(fetched_at);

-- ----------------------------------------------------------
-- ip_reputation: ผลจาก Reputation provider แต่ละราย (append-only ตาม
-- provider เพื่อดูแนวโน้มย้อนหลังได้ และรองรับเพิ่ม provider ใหม่โดยไม่
-- ต้องแก้ schema — แค่ใส่ provider ใหม่ใน CHECK หรือเอา CHECK ออกถ้าต้องการ
-- ยืดหยุ่นเต็มที่ (ตอนนี้ยังจำกัดไว้ให้ data สะอาด ป้องกัน typo)
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_reputation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL,
    provider        TEXT    NOT NULL
                    CHECK (provider IN ('abuseipdb')),  -- เพิ่ม provider ใหม่ที่นี่ได้ในอนาคต
    abuse_score     INTEGER,                            -- 0-100 (AbuseIPDB abuseConfidenceScore)
    reports_count   INTEGER,
    last_reported_at TEXT,
    categories      TEXT,                               -- เก็บเป็น comma-separated หรือ JSON string
    status          TEXT    NOT NULL DEFAULT 'ok'
                    CHECK (status IN ('ok', 'not_found', 'error', 'no_api_key', 'rate_limited', 'timeout')),
    error_message   TEXT,
    fetched_at      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_fetched_at ON ip_reputation(fetched_at);

-- ----------------------------------------------------------
-- ip_risk_assessments: ผลการให้คะแนนความเสี่ยงแต่ละครั้ง (append-only)
-- reasons เก็บเป็น JSON array ของสตริงเหตุผล เพื่อ trace ย้อนหลังได้ว่า
-- คะแนนนี้มาจากหลักฐานอะไรบ้าง ตามที่ระบุในงาน ("ต้องแสดงเหตุผลประกอบ")
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_risk_assessments (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip                  TEXT    NOT NULL,
    risk_score          INTEGER NOT NULL,                -- 0-100
    risk_level          TEXT    NOT NULL
                        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    reasons_json        TEXT    NOT NULL,                -- JSON array ของเหตุผล (ข้อความ)
    based_on_events      INTEGER NOT NULL DEFAULT 0,       -- จำนวน security events ที่ใช้คำนวณ
    based_on_reputation  INTEGER NOT NULL DEFAULT 0,       -- 1 ถ้ามีข้อมูล reputation ประกอบด้วย
    assessed_at         TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_ip_risk_assessments_ip ON ip_risk_assessments(ip);
CREATE INDEX IF NOT EXISTS idx_ip_risk_assessments_level ON ip_risk_assessments(risk_level);
CREATE INDEX IF NOT EXISTS idx_ip_risk_assessments_assessed_at ON ip_risk_assessments(assessed_at);

-- ----------------------------------------------------------
-- ip_investigation_history: audit trail ของการกระทำทุกครั้งที่เกี่ยวกับ
-- IP หนึ่ง ๆ (lookup/alert_sent/alert_skipped_cooldown/manual_check)
-- ใช้เป็นทั้งประวัติการตรวจสอบ (ตามที่ dashboard ต้องแสดง) และเป็นฐาน
-- ข้อมูลสำหรับ Telegram alert cooldown/deduplication (Module E)
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_investigation_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL,
    action          TEXT    NOT NULL
                    CHECK (action IN ('lookup', 'manual_check', 'alert_sent', 'alert_skipped_cooldown')),
    detail          TEXT,
    performed_at    TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_ip_investigation_history_ip ON ip_investigation_history(ip);
CREATE INDEX IF NOT EXISTS idx_ip_investigation_history_action ON ip_investigation_history(action);
CREATE INDEX IF NOT EXISTS idx_ip_investigation_history_performed_at ON ip_investigation_history(performed_at);