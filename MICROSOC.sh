#!/bin/bash

#===========================================================
# MICROSOC.sh — รันระบบ Micro-SOC ทั้งชุดในคำสั่งเดียว
# Created by Khawtommat
# วิธีใช้: ./MICROSOC.sh  (จะถามหาไฟล์ log และ target แบบ interactive)
#===========================================================

set -uo pipefail

# หาตำแหน่งโฟลเดอร์ที่ไฟล์นี้อยู่จริง ไม่ว่าลูกค้าจะรันจากที่ไหนก็ตาม

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$SCRIPT_DIR" || exit 1

echo "==========================================================="
echo "Starting Micro-SOC..."
echo "==========================================================="

for script in Log_Sentinel.sh Smart_Recon.sh Micro_SOC_Report.sh; do
    if [[ ! -x "$script" ]]; then
        echo "[!] Error: $script is not executable or not found."
        exit 1
    fi
done

# ----------------------------------------------------------
# บังคับรับค่าจากผู้ใช้ ไม่มี default — วนถามจนกว่าจะกรอกมาจริง
# ----------------------------------------------------------

LOG_FILE=""
while [ -z "$LOG_FILE" ]; do
    read -r -p "ระบุไฟล์ log ที่ต้องการตรวจสอบ (ห้ามเว้นว่าง): " LOG_FILE
    if [ -z "$LOG_FILE" ]; then
        echo "[!] ต้องระบุชื่อไฟล์ log ห้ามเว้นว่าง กรุณาลองใหม่"
    fi
done

TARGET=""
while [[ -z "$TARGET" ]]; do
    read -r -p "ระบุ IP ของเป้าหมาย (ห้ามเว้นว่าง): " TARGET
    if [ -z "$TARGET" ]; then
        echo "[!] ต้องระบุ IP ของเป้าหมาย ห้ามเว้นว่าง กรุณาลองใหม่"
    fi
done

read -r -p "ต้องการเปิด Auto-Ban ทันทีเมื่อพบ IP ต้องสงสัยหรือไม่? (y/N): " ENABLE_BAN
BAN_FLAG=""
if [[ "$ENABLE_BAN" =~ ^[Yy]$ ]]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] การเปิด Auto-Ban ต้องรันด้วยสิทธิ์ root — กรุณารันใหม่ด้วย: sudo ./MICROSOC.sh"
        exit 1
    fi
    BAN_FLAG="-b"
    echo "[*] เปิดใช้งาน Auto-Ban แล้ว"
else
    echo "[*] โหมด Auto-Ban ปิดอยู่ — จะแค่แจ้งเตือน ไม่บล็อกอัตโนมัติ"
fi

echo ""
echo "[1/3] Starting Log_Sentinel..."
./Log_Sentinel.sh -f "$LOG_FILE" $BAN_FLAG

echo "[2/3] Starting Smart Recon..."
./Smart_Recon.sh "$TARGET" --non-interactive --deep --web=both

echo ""
read -r -p "ต้องการส่งสรุปเข้า LINE ด้วยหรือไม่? (y/N): " ENABLE_LINE
LINE_FLAG=""
if [[ "$ENABLE_LINE" =~ ^[Yy]$ ]]; then
    if [ -z "${LINE_NOTIFY_TOKEN:-}" ]; then
        echo "[!] ยังไม่ได้ตั้งค่า LINE_NOTIFY_TOKEN ในเครื่อง — ข้ามการส่ง LINE รอบนี้"
    else
        LINE_FLAG="--line"
        echo "[*] เปิดใช้งานส่งสรุปเข้า LINE แล้ว"
    fi
else
    echo "[*] ไม่ส่งสรุปเข้า LINE"
fi

echo ""
echo "[3/3] Starting microSOC..."
./Micro_SOC_Report.sh -d microsoc.db -o dashboard.html $LINE_FLAG

echo ""
echo "เสร็จสิ้น! เปิดไฟล์ dashboard.html ดูผลลัพธ์"