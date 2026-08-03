# Playbook — Sensitive Service Exposed to the Internet

**Rule:** [`net_firewall_sensitive_service_exposed_internet.yml`](../sigma/firewall/net_firewall_sensitive_service_exposed_internet.yml)
**Severity:** 🟠 High · **ATT&CK:** T1133 (External Remote Services)
**Telemetry:** NGFW / Firewall traffic log — ไม่ต้องมี Sysmon

## TL;DR
ไฟร์วอลล์อนุญาตให้เชื่อมต่อจากอินเทอร์เน็ตเข้ามายังบริการสำคัญ (SSH, SMB, ฐานข้อมูล, WinRM ฯลฯ) โดยตรง — เป็นช่องทางที่ผู้โจมตีสแกนหาและใช้เจาะระบบ

## Triage (0–15 นาที)
- **บริการ/เครื่องไหน** ถูกเปิด (`dst_ip`, `dst_port`) และตั้งใจเปิดหรือไม่
- **ใครเข้ามา** (`src_ip`) — มีการเชื่อมต่อจากต่างประเทศ/รัว ๆ (scan/brute) ไหม
- เป็น rule ที่ตั้งไว้โดยชอบ (พาร์ทเนอร์/VPN) หรือเป็นการเปิดโดยไม่ตั้งใจ (misconfig)

## Contain
1. ถ้าไม่จำเป็นต้องเปิด → **ปิด/จำกัด rule ที่ firewall** ให้เหลือเฉพาะ IP ที่อนุญาต
2. ย้ายบริการไปหลัง **VPN / bastion / Zero Trust** แทนการเปิดตรง
3. ตรวจ log การเข้าถึงย้อนหลัง — มี login สำเร็จจากภายนอกไหม (อาจถูกเจาะแล้ว)
4. ถ้าสงสัยถูกเจาะ → reset credential ของบริการนั้น + สแกนเครื่อง

## Hunt
```spl
index=firewall action=allow (src_zone="*wan*" OR src_zone="*untrust*" OR src_zone="*outside*")
  (dst_port=22 OR dst_port=23 OR dst_port=21 OR dst_port=445 OR dst_port=5985
   OR dst_port=1433 OR dst_port=3306 OR dst_port=5432)
| stats count values(dst_port) as ports values(src_ip) as sources by dst_ip
| sort - count
```
ขยายผล: จับคู่กับผล external scan (Shodan/ASM) เพื่อยืนยัน asset ที่โผล่ออกเน็ต

## หมายเหตุไทย
- บริการฐานข้อมูล/รีโมทที่เปิดออกเน็ต = ความเสี่ยงสูงต่อการรั่วของข้อมูลส่วนบุคคล (PDPA)
- แนะนำตรวจ attack surface ภายนอกเป็นระยะ และปิดสิ่งที่ไม่จำเป็น

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-08-07</sub>
