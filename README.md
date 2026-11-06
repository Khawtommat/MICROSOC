# 🛡️ Micro-SOC

ระบบเฝ้าระวังความปลอดภัยไซเบอร์ขนาดเล็ก (Micro Security Operations Center) พัฒนาด้วย **Bash + SQLite** รวม 4 ความสามารถหลักที่ปกติต้องซื้อซอฟต์แวร์ SOC ราคาแพงถึงจะมี ไว้ในชุดสคริปต์เดียวที่รันได้บนเครื่อง Linux ทั่วไป

> โปรเจคนี้พัฒนาขึ้นระหว่างการเรียนรู้ เพื่อเป็นเครื่องมือเฝ้าระวังเครือข่ายขนาดเล็กที่ติดตั้งง่าย ไม่ต้องพึ่งพา service ภายนอกที่มีค่าใช้จ่าย

---

## ✨ Features

- **Log Sentinel (IPS)** — ตรวจจับ IP ที่ login ผิดพลาดถี่ผิดปกติด้วย sliding-window algorithm (O(n)) และสั่งบล็อกอัตโนมัติผ่าน `iptables`
- **Smart Recon (CASM)** — สแกนพอร์ต/บริการด้วย `nmap`, `gobuster`, `nikto` พร้อม **Delta Reporting**: แจ้งเตือนเฉพาะพอร์ตที่เปิดใหม่ ลดปัญหา Alert Fatigue
- **IP Intelligence** — เสริมข้อมูล IP ที่น่าสงสัยอัตโนมัติ (RDAP/WHOIS, GeoIP, AbuseIPDB reputation) พร้อมให้ **Risk Score 0-100** แบบมีเหตุผลประกอบทุกแต้ม (rule-based ไม่ใช่ black-box)
- **Unified Dashboard** — สรุปผลทั้งระบบเป็นหน้าเว็บเดียว อ่านง่าย มีปุ่มกลับหน้าแรกจากทุกหน้ารายงานย่อย พร้อมส่งสรุปเข้า **Telegram** อัตโนมัติ
- **All-in-One Launcher** — รันทั้ง 4 ระบบผ่านคำสั่งเดียว ถามค่าที่จำเป็นแบบ interactive ไม่ต้องจำ syntax argument

## 🏗️ Architecture

```
                    ┌─────────────────────────────┐
                    │        MICROSOC.sh          │
                    │   (all-in-one launcher)     │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────┬───────┴───────┐
        ▼                  ▼               ▼
┌───────────────┐  ┌──────────────────┐  ┌──────────────┐
│ Log_Sentinel  │  │  Smart_Recon.sh  │  │  IP_Intel.sh │
│     .sh       │  │                  │  │  (เสริม ไม่   │
│  (ตรวจจับ +   │  │  (สแกนพอร์ต +    │  │   บังคับ)     │
│   Auto-Ban)   │  │  Delta Reporting)│  │              │
└───────┬───────┘  └────────┬─────────┘  └──────┬───────┘
        │                   │                    │
        └───────────────────┼────────────────────┘
                             ▼
                   ┌─────────────────┐
                   │  microsoc.db    │  (SQLite: ips_logs, recon_*,
                   └────────┬────────┘   ip_intelligence, ip_risk_*)
                             ▼
                   ┌─────────────────────┐
                   │ Micro_SOC_Report.sh │
                   │  → dashboard.html   │
                   │  → Telegram         │
                   └─────────────────────┘
```

## 📁 องค์ประกอบไฟล์

| ไฟล์                   | หน้าที่                                                                        |
|------------------------|----------------------------------------------------------------------------------|
| `Log_Sentinel.sh`      | ตรวจจับ IP ต้องสงสัยจาก log (`auth.log` / `secure`) + Auto-Ban ผ่าน `iptables` |
| `Smart_Recon.sh`       | สแกนพอร์ต/บริการ + Web recon (`gobuster`, `nikto`) พร้อม Delta Reporting       |
| `IP_Intel.sh`          | เสริมข้อมูล IP (RDAP/GeoIP/AbuseIPDB) + คำนวณ Risk Score — stage เสริม        |
| `Micro_SOC_Report.sh`  | สร้าง HTML Dashboard รวมผล + ส่งสรุปเข้า Telegram                             |
| `MICROSOC.sh`          | รันทั้ง 4 ระบบข้างต้นในคำสั่งเดียว แบบ interactive                             |
| `schema.sql`           | โครงสร้างฐานข้อมูลหลัก (5 ตาราง)                                               |
| `schema_ip_intel.sql`  | โครงสร้างฐานข้อมูลเสริมของ `IP_Intel.sh` (4 ตาราง แยกจากข้างบน)               |
| `sample_data.sql`      | ข้อมูลตัวอย่าง (ปลอมทั้งหมด) สำหรับลองระบบโดยไม่ต้องมี log/target จริง         |
| `Guide.txt`            | คู่มือฉบับเต็ม อธิบายทุก flag/ตัวอย่างการใช้งานของแต่ละสคริปต์                |

## 🔧 ติดตั้ง

```bash
# ติดตั้งเครื่องมือที่จำเป็น (Kali Linux มีให้ครบอยู่แล้ว)
sudo apt install sqlite3 nmap gobuster nikto curl python3

# clone แล้วให้สิทธิ์รันไฟล์
git clone https://github.com/Khawtommat/MICROSOC.git
cd MICROSOC
chmod +x *.sh
```

## 🚀 เริ่มใช้งาน

### ลองด้วยข้อมูลตัวอย่าง (เร็วที่สุด ไม่ต้องมี log/target จริง)

```bash
sqlite3 microsoc.db < schema.sql
sqlite3 microsoc.db < sample_data.sql
./Micro_SOC_Report.sh -d microsoc.db -o dashboard.html
```

เปิด `dashboard.html` ดูผลได้ทันที

### รันระบบเต็มรูปแบบกับข้อมูลจริง

```bash
./MICROSOC.sh
```

สคริปต์จะถามทีละขั้นตอน:

1. ไฟล์ log ที่ต้องการตรวจสอบ (เช่น `/var/log/auth.log` หรือ `/var/log/secure`)
2. IP/domain เป้าหมายที่ต้องการสแกน
3. ต้องการเปิด Auto-Ban ทันทีหรือไม่ (ต้องรันด้วย `sudo -E` ถ้าเลือกเปิด)
4. ต้องการส่งสรุปเข้า Telegram หรือไม่
5. ต้องการรัน IP Intelligence เสริมข้อมูล IP ที่เจอหรือไม่ (ถามเฉพาะตอนมีไฟล์ `IP_Intel.sh`)

### รันแยกทีละส่วน (สำหรับ cron job)

```bash
# ตรวจจับ + แบนอัตโนมัติ
sudo ./Log_Sentinel.sh -f /var/log/auth.log -b

# สแกนแบบไม่ต้องตอบคำถาม (เหมาะกับ cron)
./Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip

# เสริมข้อมูล IP ที่เจอ
./IP_Intel.sh

# สร้าง dashboard + ส่ง Telegram
./Micro_SOC_Report.sh -d microsoc.db -o dashboard.html --telegram
```

## 🔔 การตั้งค่า Telegram

1. คุยกับ [@BotFather](https://t.me/BotFather) ใน Telegram พิมพ์ `/newbot` ทำตามขั้นตอนจนได้ **Bot Token**
2. หา **Chat ID** ของตัวเอง/กลุ่มที่จะรับแจ้งเตือน เช่นคุยกับ `@userinfobot`
3. ตั้งค่าเป็น environment variable ก่อนรัน หรือสร้างไฟล์ `telegram.env` ไว้โฟลเดอร์เดียวกับสคริปต์:

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-xxx"
export TELEGRAM_CHAT_ID="123456789"
```

⚠️ **ห้าม commit ไฟล์ `.env` ขึ้น git เด็ดขาด** มี token/API key อยู่ข้างใน (`.gitignore` ของ repo นี้กันไว้ให้แล้ว)

## 🌐 การตั้งค่า IP Intelligence / AbuseIPDB (ไม่บังคับ)

`IP_Intel.sh` ใช้ RDAP + GeoIP ได้ฟรีทันทีโดยไม่ต้องตั้งค่าอะไร ถ้าอยากได้คะแนน reputation จาก AbuseIPDB เพิ่ม:

1. สมัครฟรีที่ [abuseipdb.com](https://www.abuseipdb.com) (free tier 1,000 request/วัน ไม่มีค่าใช้จ่าย)
2. สร้างไฟล์ `ip_intel.env`:
   ```bash
   ABUSEIPDB_API_KEY="your_key_here"
   ```

## ⏰ ตั้งเป็น Cron Job (รันอัตโนมัติทุกวัน)

```bash
crontab -e
```

```cron
# ตรวจจับ log ทุก 10 นาที
*/10 * * * *  /path/to/Log_Sentinel.sh -f /var/log/auth.log -b

# สแกนพื้นผิวการโจมตีทุกเที่ยงคืน
0 0 * * *  /path/to/Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip

# เสริมข้อมูล IP ใหม่ทุกชั่วโมง
0 * * * *  /path/to/IP_Intel.sh

# ส่งสรุปเข้า Telegram ทุกเช้า 07:00
0 7 * * *  TELEGRAM_BOT_TOKEN="xxx" TELEGRAM_CHAT_ID="xxx" /path/to/Micro_SOC_Report.sh --telegram
```

## 🧪 การทดสอบ

โปรเจคผ่านการทดสอบด้วย:

- ไฟล์ log จำลอง 10,000 บรรทัด (ผสมการเชื่อมต่อปกติและรูปแบบการโจมตี)
- สแกนจริงกับ VM ทดสอบ (AlmaLinux) ผ่าน VirtualBox Host-only Network
- ยืนยัน Auto-Ban, Delta Reporting, และ Telegram Notification ทำงานถูกต้องครบวงจร

## ⚠️ ข้อควรระวัง

ใช้สแกน ตรวจจับ หรือทดสอบเฉพาะระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบเป็นลายลักษณ์อักษรเท่านั้น ผู้พัฒนาไม่รับผิดชอบต่อการนำไปใช้ในทางที่ผิดกฎหมาย

## 👤 ผู้พัฒนา

Khawtommat
