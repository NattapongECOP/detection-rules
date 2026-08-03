# Playbook — Sensitive Data Egress to Personal / External Destination

**Rule:** [`dlp_sensitive_data_egress_external.yml`](../sigma/dlp/dlp_sensitive_data_egress_external.yml)
**Severity:** 🟠 High · **ATT&CK:** T1567.002 (Exfiltration to Cloud Storage) · T1052 (Exfil over Physical Medium)
**Telemetry:** DLP alert log — ไม่ต้องมี Sysmon

## TL;DR
DLP พบข้อมูลอ่อนไหว (ระดับ High/Critical) ถูกส่งออกไปยังปลายทางส่วนตัว/นอกองค์กร (เมลส่วนตัว, คลาวด์ส่วนตัว, เว็บฝากไฟล์, USB) และ "ไม่ถูกบล็อก" — แปลว่าข้อมูลออกไปแล้ว อาจเป็น insider หรือการเตรียม exfil ก่อน ransomware

## Triage (0–15 นาที)
- **ใคร/ไฟล์อะไร/ไปไหน** (`user`, `filename`, `destination`) และปริมาณเท่าไร
- เป็นงานปกติของคน ๆ นี้ไหม (แผนก/หน้าที่) หรือผิดวิสัย
- เกิดครั้งเดียวหรือ **หลายครั้งเป็นชุด** (สัญญาณ staging exfil)
- มีสัญญาณบัญชีถูกยึดก่อนหน้าไหม (login ผิดปกติ)

## Contain
1. ถ้าเป็นการรั่วที่ไม่ควร → **ระงับบัญชี/สิทธิ์** ผู้ใช้ + ติดต่อ HR/หัวหน้าตามนโยบาย
2. **บล็อกปลายทาง** (โดเมนเมล/คลาวด์ส่วนตัว) ที่ proxy/DLP + ปรับ policy จาก Monitor → Block
3. ประเมินขอบเขตข้อมูลที่ออกไป (จำนวน record/ประเภท) เพื่อประเมินผลกระทบ
4. เก็บหลักฐานสำหรับการสอบสวน

## Hunt
```spl
index=dlp (severity=High OR severity=Critical)
  (destination="*gmail*" OR destination="*personal*" OR destination="*dropbox*"
   OR destination="*wetransfer*" OR destination="*usb*")
  NOT action IN ("Block","Blocked","Prevent","Quarantine")
| stats count sum(bytes) as total by user, destination, _time
| sort - count
```
ขยายผล: หา user ที่ส่งออกหลายครั้งในช่วงสั้น ๆ · เทียบกับวันลาออก/แจ้งลาออก (insider risk)

## หมายเหตุไทย
- ข้อมูลส่วนบุคคล (PII) รั่ว = เข้าข่าย **PDPA** ต้องประเมินแจ้งภายใน 72 ชม. และแจ้งเจ้าของข้อมูลหากเสี่ยงสูง
- แนะนำตั้ง DLP policy ข้อมูลสำคัญเป็น **Block** (ไม่ใช่ Monitor) สำหรับปลายทางส่วนตัว

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-08-21</sub>
