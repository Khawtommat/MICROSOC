-- ==========================================================
-- microsoc.db schema
-- ระบบ Micro-SOC: Log Sentinel (IPS) + Smart Recon (CASM)
-- ==========================================================

PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------
-- ตาราง ips_logs
-- เก็บ IP ที่ log-sentinel ตรวจพบว่า login ผิดพลาดเกินเกณฑ์
-- และสถานะการ Auto-Ban ผ่าน iptables
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ips_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL,
    fail_count      INTEGER NOT NULL,          -- จำนวนครั้งที่ login พลาดสูงสุดใน window
    window_seconds  INTEGER NOT NULL,          -- ขนาด time window ที่ใช้ตรวจจับ (วินาที)
    source_log      TEXT,                      -- path ของไฟล์ log ต้นทาง
    action          TEXT    NOT NULL DEFAULT 'alerted'
                    CHECK (action IN ('alerted', 'banned', 'ban_failed', 'already_banned')),
    detected_at     TEXT    NOT NULL DEFAULT (datetime('now', 'localtime')),
    banned_at       TEXT                       -- เวลาที่สั่ง iptables บล็อกจริง (NULL ถ้าไม่ได้แบน)
);

CREATE INDEX IF NOT EXISTS idx_ips_logs_ip ON ips_logs(ip);
CREATE INDEX IF NOT EXISTS idx_ips_logs_detected_at ON ips_logs(detected_at);

-- ----------------------------------------------------------
-- ตาราง recon_assets
-- เก็บพอร์ต/เซอร์วิสที่ smart-recon สแกนเจอในแต่ละเป้าหมาย
-- ใช้ first_seen / last_seen เพื่อทำ Delta Reporting
-- (พอร์ตใหม่ = first_seen เท่ากับ last_seen ของรอบสแกนล่าสุด)
-- ----------------------------------------------------------
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
    is_new          INTEGER NOT NULL DEFAULT 1,   -- 1 = พบใหม่ในรอบสแกนล่าสุด, 0 = เคยเห็นมาก่อน
    UNIQUE(target, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_recon_assets_target ON recon_assets(target);

-- ----------------------------------------------------------
-- ตาราง recon_scans
-- เก็บ metadata ของแต่ละรอบสแกน ใช้คู่กับ Delta Reporting
-- และให้ dashboard รู้ว่าสแกนล่าสุดเมื่อไหร่ พบพอร์ตใหม่กี่พอร์ต
-- ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS recon_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    scan_type       TEXT    NOT NULL DEFAULT 'fast',   -- fast | deep
    new_ports_count INTEGER NOT NULL DEFAULT 0,
    total_ports     INTEGER NOT NULL DEFAULT 0,
    scanned_at      TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_recon_scans_target ON recon_scans(target);
