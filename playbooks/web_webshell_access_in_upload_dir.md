# Playbook — Webshell Access in Web Access Logs

**Rule:** [`web_webshell_access_in_upload_dir.yml`](../sigma/web/web_webshell_access_in_upload_dir.yml)
**Severity:** 🟠 High · **ATT&CK:** T1505.003 (Web Shell) · T1190 (Exploit Public-Facing App)
**Telemetry:** Web server access log / WAF / reverse proxy — log ที่แทบทุกเว็บมี

## TL;DR
มี request เรียกไฟล์สคริปต์ในโฟลเดอร์อัปโหลด หรือส่งพารามิเตอร์สั่งคำสั่ง (cmd=, whoami) — สัญญาณว่ามี webshell ถูกฝังและกำลังถูกใช้รันคำสั่งบนเซิร์ฟเวอร์เว็บ

## Triage (0–15 นาที)
- **ไฟล์ไหน** (`c-uri`) — มีอยู่จริงบนเซิร์ฟเวอร์ไหม, ถูกสร้างเมื่อไร (ตรวจ mtime)
- **ใครเรียก** (`src_ip`) — ภายใน/ภายนอก, ยิงซ้ำหลายครั้งไหม, UA เป็น tool (curl/python) หรือไม่
- **สำเร็จไหม** — `sc-status` 200 + response ผิดปกติ = คำสั่งทำงานแล้ว
- หา request ก่อนหน้าที่ **อัปโหลด/สร้างไฟล์นั้น** (POST ไป endpoint upload)

## Contain
1. **ลบไฟล์ webshell** ออกจากเว็บรูท + สำรองไว้เป็นหลักฐาน
2. **Block src_ip** + virtual patch ที่ WAF
3. **แยกเซิร์ฟเวอร์/สแกน** หา webshell อื่น (grep หา eval/base64_decode/system ใน webroot)
4. อุดช่องโหว่ต้นทาง (unrestricted upload / RCE) + อัปเดต CMS/แพตช์
5. หมุน credential/secret ที่อยู่บนเครื่อง (DB config ฯลฯ)

## Hunt
```spl
index=web (c_uri="*/uploads/*.php*" OR c_uri="*/media/*.php*" OR c_uri="*cmd=*"
  OR c_uri="*whoami*" OR c_uri="*/tmp/*.php*")
| stats count values(c_uri) as urls values(status) as codes by src_ip, _time
| sort - count
```
ขยายผล: หาไฟล์สคริปต์ในโฟลเดอร์ที่ปกติมีแต่รูป/ไฟล์แนบ · เทียบกับ log การอัปโหลด

## หมายเหตุไทย
- webshell เป็นก้าวสำคัญของ **web defacement หน่วยงานรัฐ** — ตั้งเฝ้าเว็บ .go.th เป็นพิเศษ
- หากข้อมูลส่วนบุคคลถูกเข้าถึง → ประเมิน **PDPA (72 ชม.)** และพิจารณาแจ้ง **ThaiCERT/NCSA**

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-07-13</sub>
