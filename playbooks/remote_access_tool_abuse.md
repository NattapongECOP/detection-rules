# Playbook — Remote Access Software Execution (AnyDesk / TeamViewer)

**Rule:** [`proc_creation_win_remote_access_tool_abuse.yml`](../sigma/windows/proc_creation_win_remote_access_tool_abuse.yml)
**Severity:** 🟡 Medium · **ATT&CK:** T1219 (Remote Access Software)
**Telemetry:** EDR / process log — ไม่ต้องมี Sysmon

## TL;DR
พบการรันเครื่องมือรีโมท (AnyDesk/TeamViewer/UltraViewer ฯลฯ) หากองค์กรไม่ได้ใช้เป็นทางการ มักเกิดจากมิจฉาชีพหลอกให้เหยื่อติดตั้งเพื่อยึดเครื่อง หรือผู้โจมตีใช้เข้าถึงระยะไกล

## Triage (0–15 นาที)
- **เครื่อง/ผู้ใช้ไหน** และรันจาก path ไหน (Downloads/Temp = น่าสงสัย)
- ผู้ใช้ถูกโทร/ทักหลอกให้ติดตั้งหรือไม่ (สอบถามตรง)
- มี session รีโมทที่ **ต่อจากภายนอก** อยู่ไหม (ดู log ของเครื่องมือ/firewall)

## Contain
1. ถ้าไม่ใช่การใช้ที่ชอบ → **ตัดการเชื่อมต่อ + ถอนโปรแกรม** ทันที + แยกเครื่อง
2. ตรวจสิ่งที่ถูกทำระหว่างรีโมท (โอนเงิน/ติดตั้งมัลแวร์/เปลี่ยนรหัส)
3. reset credential ของผู้ใช้ + ตรวจบัญชีการเงิน/อีเมล
4. บล็อกไฟล์รีโมทแบบพกพา (aa_v3.exe) ด้วย application control

## Hunt
```spl
index=edr (Image="*\\AnyDesk.exe" OR Image="*\\aa_v3.exe" OR Image="*\\TeamViewer.exe"
  OR Image="*\\UltraViewer_Desktop.exe" OR Image="*\\rustdesk.exe")
| stats count values(Image) as tools by Computer, User, _time
| sort - count
```

## หมายเหตุไทย
- แก๊งคอลเซ็นเตอร์มักอ้างเป็นธนาคาร/ตำรวจ/บริษัทขนส่ง แล้วหลอกให้โหลด AnyDesk — เตือนพนักงานและลูกค้า
- หากมีการโอนเงิน/ข้อมูลรั่ว → แจ้งความ + ประเมิน PDPA

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-09-02</sub>
