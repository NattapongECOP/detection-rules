# Playbook — Telegram Traffic from a Server Zone

**Rule:** [`net_firewall_telegram_c2_from_server.yml`](../sigma/firewall/net_firewall_telegram_c2_from_server.yml)
**Severity:** 🟠 High · **ATT&CK:** T1102 (Web Service) · T1567 (Exfiltration over Web Service)
**Telemetry:** NGFW / Firewall app-id log — ไม่ต้องมี Sysmon

## TL;DR
เซิร์ฟเวอร์ (โซน server/DMZ) ต่อออก Telegram — ผิดปกติมาก มัลแวร์นิยมใช้ Telegram Bot API เป็นช่องทาง C2 และส่งข้อมูลออก เพราะกลมกลืนกับทราฟฟิกแชตทั่วไป

## Triage (0–15 นาที)
- **เซิร์ฟเวอร์ไหน** (`src_ip`) และควรต่อ Telegram ไหม (ปกติไม่ควร)
- ปริมาณ/ความถี่ — ต่อเป็นจังหวะ (beaconing) หรือส่งก้อนใหญ่ (exfil)
- มี process แปลกบนเซิร์ฟเวอร์นั้นไหม (ตรวจ EDR)

## Contain
1. **Block Telegram จากโซนเซิร์ฟเวอร์** ที่ firewall (ควรอนุญาตเฉพาะที่จำเป็น)
2. แยกเซิร์ฟเวอร์ + หา process/สคริปต์ที่ใช้ Telegram bot token
3. ตรวจว่ามีข้อมูลถูกส่งออกไปแล้วหรือไม่ (ประเมินขอบเขต)
4. หมุน secret/credential ที่อยู่บนเซิร์ฟเวอร์

## Hunt
```spl
index=firewall action=allow app="*telegram*"
  (src_zone="*server*" OR src_zone="*dmz*" OR src_zone="*datacenter*")
| stats count sum(bytes_out) as out by src_ip, dst_ip, _time
| sort - out
```

## หมายเหตุไทย
- ทำ allowlist เฉพาะเซิร์ฟเวอร์ที่ใช้ Telegram แจ้งเตือนโดยชอบ (bot monitoring) แล้วเฝ้าที่เหลือ
- หากยืนยัน exfil ของข้อมูลส่วนบุคคล → ประเมิน PDPA ภายใน 72 ชม.

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-09-16</sub>
