# Playbook — Thai Government / e-Service Impersonation Domain

**Rule:** [`dns_query_win_thai_gov_eservice_phishing_domain.yml`](../sigma/thailand/dns_query_win_thai_gov_eservice_phishing_domain.yml)
**Severity:** 🟠 High · **ATT&CK:** T1566.002 (Phishing: Spearphishing Link)

## TL;DR
มีเครื่องในองค์กร query โดเมนที่เลียนแบบบริการรัฐไทย (ThaID, คืนภาษี, ประกันสังคม ฯลฯ) แต่ **ไม่ได้อยู่บน `.go.th`** — รูปแบบเดียวกับสแกม SMS/LINE ที่หลอกให้ "ยืนยันตัวตน / ลงทะเบียน / คืนภาษี" แล้วขโมย credential หรือหลอกติดตั้งแอปอันตราย

## Triage (0–15 นาที)
- **ใครเปิด** — user/เครื่องไหน, เปิดผ่าน browser หรือแอป
- **มาจากไหน** — referrer เป็น LINE/SMS gateway/อีเมล? ตรวจ proxy/mail log ย้อนกลับ
- **กรอกข้อมูลไปหรือยัง** — ถามผู้ใช้ตรง ๆ ว่าใส่เลขบัตร ปชช./รหัส/OTP ไปไหม
- เช็คว่าโดเมนยัง live ไหม + WHOIS อายุโดเมน (โดเมนสแกมมักจดใหม่ < 30 วัน)

## Contain
1. **Block โดเมน + IP** ที่ DNS sinkhole / proxy / firewall ทันที
2. ถ้าผู้ใช้กรอก credential ไป → **บังคับ reset รหัส + เพิกถอน session** และเปิด MFA
3. ถ้าถูกหลอกติดตั้งแอป/ไฟล์ → แยกเครื่อง (isolate) + สแกน EDR
4. แจ้งเตือนพนักงานทั้งองค์กร (โดเมนสแกมมักยิงเป็นชุด)

## Hunt
```spl
index=dns (query="*thaid*" OR query="*taxrefund*" OR query="*rd-go*" OR query="*sso-th*" OR query="*gov-th*")
  NOT query="*.go.th" NOT query="*.gov.th"
| stats count values(query) as domains by src_ip, _time
| sort - count
```
ขยายผล: หา endpoint อื่นที่ resolve โดเมนเดียวกัน, pivot จาก IP → โดเมนพี่น้องที่ host ร่วมกัน

## หมายเหตุไทย
- บริการรัฐจริง **อยู่บน `.go.th` / `.gov.th` เท่านั้น** — ใช้เป็นหลักสอนผู้ใช้สังเกตเอง
- ถ้ามีข้อมูลส่วนบุคคล (เลขบัตร ปชช./ข้อมูลการเงิน) รั่ว → ประเมินแจ้ง **PDPA ภายใน 72 ชม.** และพิจารณาแจ้ง **ThaiCERT/NCSA**
- พบเป็นวงกว้าง → ส่ง IOC ให้ ISAC/หน่วยงานที่เกี่ยวข้องเพื่อ takedown

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-06-15</sub>
