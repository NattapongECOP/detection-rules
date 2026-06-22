# Playbook — Lure File (LNK/Document) Launching a LOLBin

**Rule:** [`proc_creation_win_lnk_lure_lolbin_execution.yml`](../sigma/thailand/proc_creation_win_lnk_lure_lolbin_execution.yml)
**Severity:** 🟠 High · **ATT&CK:** T1204.002 (Malicious File) · T1218.005 (mshta) · T1059.001 (PowerShell)
**Actor context:** Mustang Panda / Stately Taurus — 2026 เจาะตำรวจไทยด้วยเอกสารลวง → shortcut → Yokai backdoor

## TL;DR
ผู้ใช้เปิด "ไฟล์ลวง" (shortcut/เอกสาร) แล้วมันแอบเรียก LOLBin (mshta/powershell/rundll32) ไปโหลดหรือรันโค้ดจากภายนอก — สัญญาณ initial access ของ APT/มัลแวร์ที่ใช้ไฟล์หลอกเปิด

## Triage (0–15 นาที)
- **เครื่อง/ผู้ใช้ไหน** + ไฟล์ต้นทางคืออะไร (ชื่อ .lnk/.doc/.zip ที่เปิด)
- **ปลายทาง** — URL/IP ใน CommandLine คืออะไร, ยัง live ไหม, อายุโดเมน (WHOIS)
- **ลูกหลาน** — process นี้ spawn อะไรต่อ (เช่น โหลด .exe/.dll, สร้าง scheduled task, แตะ registry Run)
- มาทาง LINE/อีเมล/USB? ตรวจ mail/proxy log ย้อนกลับ

## Contain
1. **Isolate เครื่อง** ออกจากเครือข่ายทันที (อาจมี backdoor ฝังแล้ว)
2. **Block โดเมน/IP ปลายทาง** ที่ DNS/proxy/firewall
3. **สแกน EDR หา persistence** — Run key, scheduled task, service, DLL sideload (Mustang Panda ชอบ sideload DLL ผ่าน binary ที่เซ็นถูกต้อง)
4. Reset credential ของผู้ใช้ + เพิกถอน session ถ้าสงสัยถูกขโมย

## Hunt
```spl
index=sysmon EventCode=1 ParentImage="*\\explorer.exe"
  (Image="*\\mshta.exe" OR Image="*\\powershell.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe")
  (CommandLine="*http*" OR CommandLine="*.dll*" OR CommandLine="*-enc*" OR CommandLine="*FromBase64String*")
| stats count values(CommandLine) as cmd by Computer, User, _time
| sort - count
```
ขยายผล: pivot จาก IP/โดเมน → เครื่องอื่นที่ติดต่อปลายทางเดียวกัน · หา .lnk แปลก ๆ ใน `%TEMP%`, Downloads, ไฟล์แนบ

## หมายเหตุไทย
- กลุ่ม APT (Mustang Panda) มักปลอมเป็น "เอกสารราชการ/หน่วยงานสากล" เล็งหน่วยงานรัฐไทย → แจ้งเตือนทีมที่รับเอกสารภายนอกบ่อย
- ถ้าเป็นหน่วยงานรัฐ/โครงสร้างพื้นฐานสำคัญ → พิจารณาแจ้ง **ThaiCERT/NCSA** และประเมิน **PDPA** หากมีข้อมูลส่วนบุคคลเกี่ยวข้อง

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-22</sub>
