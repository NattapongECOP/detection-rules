# Playbook — Windows Defender / Security Tooling Tampering

**Rule:** [`proc_creation_win_defender_tampering.yml`](../sigma/windows/proc_creation_win_defender_tampering.yml)
**Severity:** 🟠 High · **ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)
**Telemetry:** EDR / process log — ไม่ต้องมี Sysmon

## TL;DR
มีคำสั่งปิด/ลดความสามารถ หรือเพิ่ม exclusion ให้ Windows Defender — ผู้โจมตี (โดยเฉพาะ ransomware) มักปิดแอนติไวรัสก่อนปล่อย payload ถือเป็นสัญญาณก่อนโจมตีที่ความเชื่อมั่นสูง

## Triage (0–15 นาที)
- **เครื่อง/ผู้ใช้ไหน** และ **คำสั่งเต็ม** (`CommandLine`) — ปิดอะไร/ยกเว้น path ไหน
- **process แม่** คืออะไร (ถ้ามาจาก Office/เบราว์เซอร์/สคริปต์แปลก = อันตราย)
- มี **change ticket** ของ IT รองรับไหม (การปิดชั่วคราวที่ชอบธรรม)
- ดูเหตุการณ์ถัด ๆ ไป — มีการรันไฟล์แปลก/เข้ารหัสไฟล์ตามมาไหม

## Contain
1. ถ้าไม่ใช่การกระทำที่ชอบ → **แยกเครื่อง (isolate)** ทันที
2. **เปิด Defender / real-time protection กลับ** + ลบ exclusion ที่ถูกเพิ่ม
3. สแกนหา payload/persistence ที่อาจถูกวางระหว่างที่ AV ถูกปิด
4. เปิด **Tamper Protection** ของ Defender เพื่อกันการปิดในอนาคต

## Hunt
```spl
index=edr (Image="*\\powershell.exe" OR Image="*\\reg.exe" OR Image="*\\sc.exe" OR Image="*\\cmd.exe")
  (CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*Add-MpPreference -ExclusionPath*"
   OR CommandLine="*stop WinDefend*" OR CommandLine="*DisableAntiSpyware*")
| stats count values(CommandLine) as cmd by Computer, User, _time
| sort - count
```
ขยายผล: หาเครื่องอื่นที่มีคำสั่งเดียวกันในช่วงเวลาใกล้กัน (สัญญาณการแพร่กระจายก่อน ransomware)

## หมายเหตุไทย
- **เปิด Tamper Protection + จำกัดสิทธิ์ admin** คือการป้องกันที่ได้ผลที่สุด
- การปิด AV แล้วตามด้วยการเข้ารหัสไฟล์ = เข้าข่ายเหตุ ransomware → เริ่ม IR เต็มรูปแบบและพิจารณาแจ้ง PDPA/ThaiCERT

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-08-14</sub>
