# Playbook — Popular Software Installer from Non-Official Domain

**Rule:** [`proxy_fake_software_installer_download.yml`](../sigma/proxy/proxy_fake_software_installer_download.yml)
**Severity:** 🟠 High · **ATT&CK:** T1204.002 (Malicious File) · T1608 (Stage Capabilities)
**Telemetry:** Web Proxy / Secure Web Gateway — ไม่ต้องมี Sysmon

## TL;DR
มีการดาวน์โหลดตัวติดตั้งของโปรแกรมยอดนิยม (Chrome/Zoom/AnyDesk ฯลฯ) จากโดเมนที่ไม่ใช่ทางการ — มักเป็นตัวติดตั้งปลอมที่แฝงมัลแวร์ ผ่านโฆษณาปลอมหรือผลค้นหาปลอม (SEO poisoning)

## Triage (0–15 นาที)
- **ใคร/ไฟล์อะไร/จากโดเมนไหน** (`src_ip`, `c-uri`, `r-dns`) — อายุโดเมน, reputation
- ดาวน์โหลดสำเร็จไหม (sc-status 200) และถูกรันหรือยัง (ตรวจ EDR ต่อ)
- ผู้ใช้ค้นหาโปรแกรมนั้นผ่าน Google/โฆษณาหรือไม่ (บริบท SEO poisoning)

## Contain
1. **Block โดเมน/IP** ปลายทางที่ proxy/firewall
2. ถ้าติดตั้งไปแล้ว → **แยกเครื่อง + สแกน EDR** หา infostealer/backdoor
3. reset credential ของผู้ใช้ (infostealer ขโมยรหัสในเบราว์เซอร์)
4. แจ้งเตือนทั้งองค์กร + สอนให้โหลดจากเว็บทางการเท่านั้น

## Hunt
```spl
index=proxy (c_uri="*.exe" OR c_uri="*.msi")
  (c_uri="*chrome*" OR c_uri="*zoom*" OR c_uri="*anydesk*" OR c_uri="*teamviewer*")
  NOT (r_dns="*.google.com" OR r_dns="*.zoom.us" OR r_dns="*.anydesk.com" OR r_dns="*.teamviewer.com")
| stats count values(c_uri) as urls by src_ip, r_dns
| sort - count
```

## หมายเหตุไทย
- สอนผู้ใช้: ดาวน์โหลดโปรแกรมจาก **เว็บทางการ** เท่านั้น อย่ากดจากโฆษณา/ผลค้นหาด้านบน
- ตั้ง DNS/proxy บล็อกโดเมน typosquat ของแบรนด์ยอดนิยมเชิงรุก

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-09-09</sub>
