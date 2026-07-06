# Playbook — Member Added to a Privileged AD Group

**Rule:** [`security_4732_privileged_group_member_added.yml`](../sigma/active_directory/security_4732_privileged_group_member_added.yml)
**Severity:** 🟠 High · **ATT&CK:** T1098 (Account Manipulation) · T1078.002 (Domain Accounts)
**Telemetry:** AD / DC Security log (Event ID 4728 / 4732 / 4756) — ไม่ต้องมี Sysmon

## TL;DR
มีการเพิ่มสมาชิกเข้ากลุ่มสิทธิ์สูง (Domain Admins / Administrators ฯลฯ) — วิธีที่ผู้โจมตีใช้ฝังตัวและยกระดับสิทธิ์หลังยึดระบบได้ การเพิ่มโดยชอบธรรมพบไม่บ่อย ต้องตรวจทุกครั้ง

## Triage (0–15 นาที)
- **ใครเพิ่ม / เพิ่มใคร** — `SubjectUserName` (คนทำ), `MemberName` (บัญชีที่ถูกเพิ่ม), `TargetUserName` (กลุ่ม)
- มี **change ticket / การอนุมัติ** รองรับหรือไม่
- บัญชีที่ถูกเพิ่มเป็นบัญชีใหม่/แปลกหรือไม่ (เทียบ 4720 การสร้างบัญชีก่อนหน้า)

## Contain
1. ถ้าไม่มีการอนุมัติ → **ถอนสมาชิกออกจากกลุ่มทันที**
2. **ปิด/รีเซ็ต** บัญชีที่ถูกเพิ่ม + บัญชีคนทำ (อาจถูกยึด)
3. หา activity ของบัญชีสิทธิ์สูงนั้นย้อนหลัง (lateral movement, การเข้าถึงข้อมูล)

## Hunt
```spl
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
  (Group_Name="*Admins*" OR Group_Name="*Administrators*")
| table _time, ComputerName, Subject_Account_Name, Member_Name, Group_Name
```

## หมายเหตุไทย
- ตั้ง **แจ้งเตือนแบบเรียลไทม์** สำหรับกลุ่ม Domain/Enterprise Admins — ทุกการเปลี่ยนแปลงควรมีคนรับรู้ทันที
- แนะนำใช้ **PAM / just-in-time access** เพื่อลดการเป็นสมาชิกถาวรของกลุ่มสิทธิ์สูง

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-07-06</sub>
