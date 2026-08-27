# 🛡️ Micro-SOC

ระบบเฝ้าระวังความปลอดภัยไซเบอร์ขนาดเล็ก (Micro Security Operations Center) พัฒนาด้วย **Bash + SQLite**
รวม 3 ความสามารถหลักที่ปกติต้องซื้อซอฟต์แวร์ SOC ราคาแพงถึงจะมี ไว้ในสคริปต์เดียวที่รันได้บนเครื่อง Linux ทั่วไป

> โปรเจคนี้พัฒนาขึ้นระหว่างฝึกงานที่ศูนย์คอมพิวเตอร์ เพื่อเป็นเครื่องมือเฝ้าระวังเครือข่ายขนาดเล็กที่ติดตั้งง่าย ไม่ต้องพึ่งพา service ภายนอกที่มีค่าใช้จ่าย

---

## ✨ Features

- **Log Sentinel (IPS)** — ตรวจจับ IP ที่ login ผิดพลาดถี่ผิดปกติด้วย sliding-window algorithm (O(n)) และสั่งบล็อกอัตโนมัติผ่าน `iptables`
- **Smart Recon (CASM)** — สแกนพอร์ต/บริการด้วย `nmap`, `gobuster`, `nikto` พร้อม **Delta Reporting**: แจ้งเตือนเฉพาะพอร์ตที่เปิดใหม่ ลดปัญหา Alert Fatigue
- **Unified Dashboard** — สรุปผลทั้งระบบเป็นหน้าเว็บเดียว อ่านง่าย พร้อมส่งสรุปประจำวันเข้า **LINE** อัตโนมัติ
- **All-in-One Launcher** — รันทั้ง 3 ระบบผ่านคำสั่งเดียว ถามค่าที่จำเป็นแบบ interactive ไม่ต้องจำ syntax argument

## 🏗️ Architecture

```
                    ┌─────────────────────────────┐
                    │        MICROSOC.sh          │
                    │   (all-in-one launcher)     │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────┴───────┐
        ▼                          ▼
┌───────────────┐        ┌──────────────────┐
│ Log_Sentinel  │        │  Smart_Recon.sh  │
│     .sh       │        │                  │
│  (ตรวจจับ +   │        │  (สแกนพอร์ต +    │
│   Auto-Ban)   │        │  Delta Reporting)│
└───────┬───────┘        └────────┬─────────┘
        │                         │
        └────────────┬────────────┘
                     ▼
            ┌─────────────────┐
            │  microsoc.db    │  (SQLite: ips_logs, recon_assets, recon_scans)
            └────────┬────────┘
                      ▼
            ┌─────────────────────┐
            │ Micro_SOC_Report.sh │
            │  → dashboard.html   │
            │  → LINE Notify      │
            └─────────────────────┘
```

## 📁 องค์ประกอบไฟล์

| ไฟล์ | หน้าที่ |
|---|---|
| `Log_Sentinel.sh` | ตรวจจับ IP ต้องสงสัยจาก log (`auth.log` / `secure`) + Auto-Ban ผ่าน `iptables` |
| `Smart_Recon.sh` | สแกนพอร์ต/บริการ + Web recon (`gobuster`, `nikto`) พร้อม Delta Reporting |
| `Micro_SOC_Report.sh` | สร้าง HTML Dashboard รวมผล + ส่งสรุปเข้า LINE |
| `MICROSOC.sh` | รันทั้ง 3 ระบบข้างต้นในคำสั่งเดียว แบบ interactive |
| `schema.sql` | โครงสร้างฐานข้อมูล SQLite (3 ตาราง) |
| `sample_data.sql` | ข้อมูลตัวอย่าง (ปลอมทั้งหมด) สำหรับลองระบบโดยไม่ต้องมี log/target จริง |

## 🔧 ติดตั้ง

```bash
# ติดตั้งเครื่องมือที่จำเป็น (Kali Linux มีให้ครบอยู่แล้ว)
sudo apt install sqlite3 nmap gobuster nikto

# clone แล้วให้สิทธิ์รันไฟล์
git clone https://github.com/<username>/micro-soc.git
cd micro-soc
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
4. ต้องการส่งสรุปเข้า LINE หรือไม่

### รันแยกทีละส่วน (สำหรับ cron job)

```bash
# ตรวจจับ + แบนอัตโนมัติ
sudo ./Log_Sentinel.sh -f /var/log/auth.log -b

# สแกนแบบไม่ต้องตอบคำถาม (เหมาะกับ cron)
./Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip

# สร้าง dashboard + ส่ง LINE
./Micro_SOC_Report.sh -d microsoc.db -o dashboard.html --line
```

## 🔔 การตั้งค่า LINE Notify

1. สร้าง Provider + Messaging API Channel ผ่าน [LINE Developers Console](https://developers.line.biz/console/)
2. สแกน QR เพิ่มเพื่อนกับ Official Account ที่สร้างไว้
3. คัดลอก Channel Access Token แล้วตั้งค่า:

```bash
echo 'export LINE_NOTIFY_TOKEN="channel-access-token-ของคุณ"' >> ~/.zshrc
source ~/.zshrc
```

## ⏰ ตั้งเป็น Cron Job (รันอัตโนมัติทุกวัน)

```bash
crontab -e
```

```
# ตรวจจับ log ทุก 10 นาที
*/10 * * * *  /path/to/Log_Sentinel.sh -f /var/log/auth.log -b

# สแกนพื้นผิวการโจมตีทุกเที่ยงคืน
0 0 * * *  /path/to/Smart_Recon.sh 192.168.1.10 --non-interactive --web=skip

# ส่งสรุปเข้า LINE ทุกเช้า 07:00
0 7 * * *  LINE_NOTIFY_TOKEN="xxxx" /path/to/Micro_SOC_Report.sh --line
```

## 🧪 การทดสอบ

โปรเจคผ่านการทดสอบด้วย:
- ไฟล์ log จำลอง 10,000 บรรทัด (ผสมการเชื่อมต่อปกติและรูปแบบการโจมตี)
- สแกนจริงกับ VM ทดสอบ (AlmaLinux) ผ่าน VirtualBox Host-only Network
- ยืนยัน Auto-Ban, Delta Reporting, และ LINE Notification ทำงานถูกต้องครบวงจร

## ⚠️ ข้อควรระวัง

ใช้สแกน ตรวจจับ หรือทดสอบเฉพาะระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้ทดสอบเป็นลายลักษณ์อักษรเท่านั้น
ผู้พัฒนาไม่รับผิดชอบต่อการนำไปใช้ในทางที่ผิดกฎหมาย

## 👤 ผู้พัฒนา

Khawtommat
