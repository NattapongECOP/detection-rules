# Playbook — FortiGate SSL-VPN Login from Unexpected Foreign Country

**Rule:** [`net_vpn_fortigate_sslvpn_login_foreign_country.yml`](../sigma/firewall/net_vpn_fortigate_sslvpn_login_foreign_country.yml)
**Severity:** 🟡 Medium · **ATT&CK:** T1078 (Valid Accounts) · T1133 (External Remote Services)
**Threat context:** 2026 "FortiBleed" — credential harvesting จาก FortiGate 430,000+ เครื่องทั่วโลก

## TL;DR
มีผู้ล็อกอิน SSL-VPN **สำเร็จ** ด้วยบัญชีที่ถูกต้อง แต่ต้นทางมาจากประเทศที่อยู่นอกรายการที่อนุญาต — อาจเป็นการนำ credential ที่ถูกขโมยไปใช้เข้าระบบองค์กร

## Triage (0–15 นาที)
- **ใคร/จากไหน** — user, `remip`, `srccountry` ตรงกับพฤติกรรมปกติของคนนี้ไหม
- **เดินทางจริงหรือไม่** — ติดต่อผู้ใช้/หัวหน้ายืนยัน (ลา/ไปต่างประเทศ?)
- **impossible travel** — มี login จากในไทยในช่วงเวลาใกล้กันไหม (คนเดียวอยู่ 2 ที่ไม่ได้)
- ดูว่ามี **auth fail รัว ๆ** ก่อนหน้า (brute-force) จาก IP เดียวกันหรือไม่

## Contain
1. ถ้ายืนยันว่าไม่ใช่เจ้าตัว → **ตัด session VPN** ของ user ทันที + **disable บัญชี**
2. **บังคับ reset รหัสผ่าน** และ **เปิด/รีเซ็ต MFA** ของบัญชีนั้น
3. **Block `remip`** ที่ firewall + ตรวจว่า attacker เข้าถึงอะไรไปแล้ว (lateral movement)
4. ระดับองค์กร: **อัปเดต FortiOS** เป็นเวอร์ชันล่าสุด + บังคับ reset รหัส VPN ทุกบัญชีหากสงสัยรั่วเป็นวงกว้าง

## Hunt
```spl
index=fortigate subtype=vpn action=tunnel-up tunneltype=*ssl*
  NOT srccountry IN ("Thailand","Reserved")
| stats count values(srccountry) as countries values(remip) as src by user, _time
| sort - count
```
ขยายผล: หา user ที่มี login สำเร็จจากหลายประเทศในวันเดียว · เทียบ baseline ประเทศปกติของแต่ละ user

## หมายเหตุไทย
- เปิด **MFA บน SSL-VPN** คือการป้องกันที่ได้ผลที่สุดต่อ credential ที่ถูกขโมย
- หากยืนยันว่าบัญชีถูกใช้โดยผู้อื่นและมีข้อมูลส่วนบุคคลเกี่ยวข้อง → ประเมินแจ้ง **PDPA ภายใน 72 ชม.** และพิจารณาแจ้ง **ThaiCERT/NCSA**

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-30</sub>
