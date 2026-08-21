# Playbook — Kerberoasting (RC4 Service Ticket Requests, 4769)

**Rule:** [`security_4769_kerberoasting_rc4.yml`](../sigma/active_directory/security_4769_kerberoasting_rc4.yml)
**Severity:** 🟡 Medium · **ATT&CK:** T1558.003 (Kerberoasting)
**Telemetry:** AD / Domain Controller Security log (Event 4769) — ไม่ต้องมี Sysmon

## TL;DR
มีการขอตั๋ว Kerberos แบบ RC4 (0x17) ให้บัญชีบริการที่มี SPN — เทคนิค Kerberoasting ที่ผู้โจมตีใช้ดึงตั๋วไปถอดรหัสผ่านของบัญชีบริการแบบ offline เพื่อยกระดับสิทธิ์ใน Active Directory

## Triage (0–15 นาที)
- **ใครขอ** (`TargetUserName`, `IpAddress`) และขอให้บริการใด (`ServiceName`)
- ขอ **หลายบัญชีบริการในเวลาสั้น ๆ** หรือไม่ (สัญญาณเด่นของ Kerberoasting)
- เครื่องต้นทางเป็นของผู้ใช้ทั่วไปที่ไม่ควรทำสิ่งนี้หรือไม่

## Contain
1. ระบุเครื่องต้นทาง → **แยกเครื่อง** + สแกน (Rubeus/impacket)
2. **รีเซ็ตรหัสผ่านบัญชีบริการ** ที่ถูกขอตั๋ว (ตั้งรหัสยาว สุ่ม) และเปลี่ยนให้ใช้ **AES**
3. ปิดการใช้ RC4 ในโดเมนถ้าเป็นไปได้ + ใช้ gMSA สำหรับบัญชีบริการ
4. ตรวจการใช้บัญชีบริการนั้นย้อนหลัง (อาจถูกถอดรหัสสำเร็จแล้ว)

## Hunt
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
  NOT Service_Name="*$" NOT Service_Name="krbtgt"
| stats dc(Service_Name) as spn_count values(Service_Name) as spns by Account_Name, Client_Address
| where spn_count >= 3
```

## หมายเหตุไทย
- บัญชีบริการที่มีสิทธิ์สูง + รหัสอ่อน = เป้า Kerberoasting → ตั้งรหัสยาว (25+ ตัว) และใช้ AES/gMSA
- Kerberoasting มักเป็นก้าวก่อนยึด Domain → ยกระดับความสำคัญหากพบร่วมกับสัญญาณอื่น

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-09-23</sub>
