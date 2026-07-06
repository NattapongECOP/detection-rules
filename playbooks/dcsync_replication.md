# Playbook — DCSync (Directory Replication by Non-DC Account)

**Rule:** [`security_4662_dcsync_replication.yml`](../sigma/active_directory/security_4662_dcsync_replication.yml)
**Severity:** 🟠 High · **ATT&CK:** T1003.006 (OS Credential Dumping: DCSync)
**Telemetry:** AD / DC Security log (Event ID 4662) — ไม่ต้องมี Sysmon

## TL;DR
มีบัญชีที่ไม่ใช่ Domain Controller ขอสิทธิ์ replication ของ AD — เทคนิค DCSync ที่ใช้ดึง hash รหัสผ่านของทุกบัญชี (รวม krbtgt) มักเป็นก้าวก่อน Golden Ticket / ransomware

## Triage (0–15 นาที)
- **ใครทำ** — `SubjectUserName` เป็นบัญชีอะไร ควรมีสิทธิ์ replication ไหม (ปกติมีแค่ DC + Entra Connect)
- **จากเครื่องไหน** — หา logon ของบัญชีนี้ (4624) เพื่อรู้ต้นทาง
- เป็นบัญชี sync ที่ชอบธรรม (MSOL_/Entra) หรือไม่ → ถ้าใช่ = FP, เพิ่ม filter

## Contain
1. ถ้าไม่ใช่บัญชี replication ที่ชอบธรรม → **ปิดบัญชีทันที** + เพิกถอน session
2. ประเมินว่า hash ถูกดึงไปแล้ว → **รีเซ็ต `krbtgt` สองครั้ง** + รีเซ็ตรหัสบัญชีสิทธิ์สูง
3. แยกเครื่องต้นทาง (isolate) + สแกน EDR หา Mimikatz/impacket
4. ตรวจ Golden/Silver Ticket (logon ที่ผิดปกติหลังเหตุการณ์)

## Hunt
```spl
index=wineventlog EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
  NOT Account_Name="*$" NOT Account_Name="MSOL_*"
| stats count values(Account_Name) as who by ComputerName, _time
```

## หมายเหตุไทย
- DCSync = สัญญาณว่า attacker ได้สิทธิ์ระดับ Domain แล้ว → ยกระดับเป็นเหตุการณ์ร้ายแรง
- หากยืนยันการรั่วของ credential ระดับองค์กร → พิจารณาแจ้ง **PDPA (72 ชม.)** และ **ThaiCERT/NCSA**

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-07-06</sub>
