# Playbook — OAuth Application Consent / Permission Grant (Entra ID)

**Rule:** [`azuread_oauth_consent_granted.yml`](../sigma/m365/azuread_oauth_consent_granted.yml)
**Severity:** 🟡 Medium · **ATT&CK:** T1528 (Steal Application Access Token) · T1550.001
**Telemetry:** Microsoft 365 / Entra ID Audit log — ไม่ต้องมี Sysmon
**Threat context:** 2026 AiTM phishing (Evilginx) บน Microsoft 365 — ขโมย session ทะลุ MFA แล้วฝังตัวด้วย OAuth consent

## TL;DR
มีการให้สิทธิ์ (consent) แก่แอป OAuth ในองค์กร — หากเป็นแอปที่ไม่รู้จัก อาจเป็นการฝังตัวหลังบัญชีถูกยึด เพราะ access token ที่ได้จะใช้เข้าถึงเมล/ข้อมูลได้ต่อเนื่อง แม้เปลี่ยนรหัสหรือรีเซ็ต MFA แล้ว

## Triage (0–15 นาที)
- **แอปอะไร / ใคร consent** — `ObjectId` (ชื่อแอป), `UserId` (ผู้ให้สิทธิ์)
- **ขอ scope อะไร** — Mail.Read/Mail.ReadWrite/Files.Read.All/offline_access = ความเสี่ยงสูง
- **แอปนี้รู้จักไหม** — publisher ได้รับการยืนยันไหม, เพิ่งสร้างใหม่หรือไม่
- ตรวจ sign-in ของผู้ใช้ช่วงก่อนหน้า — มี login จาก IP/ประเทศแปลก (สัญญาณ AiTM) ไหม

## Contain
1. ถ้าเป็นแอปอันตราย → **เพิกถอน consent / ลบ service principal** (Revoke) ทันที
2. **เพิกถอน refresh token** ของผู้ใช้ (Revoke sign-in sessions) + reset รหัส + ตรวจ/รีเซ็ต MFA
3. ตรวจ inbox rule ที่ถูกสร้างใหม่ (มักคู่กับ BEC) + mailbox forwarding
4. เปิดนโยบาย **admin consent workflow** เพื่อไม่ให้ผู้ใช้ consent เองได้

## Hunt
```spl
index=o365 Workload=AzureActiveDirectory
  (Operation="Consent to application" OR Operation="Add OAuth2PermissionGrant"
   OR Operation="Add delegated permission grant")
| table _time, UserId, ObjectId, ClientIP, ResultStatus
| sort - _time
```
ขยายผล: หาแอปที่หลายผู้ใช้ consent ในช่วงเวลาใกล้กัน · เทียบ ClientIP กับ sign-in ที่ผิดปกติ

## หมายเหตุไทย
- เปิด **MFA แล้วยังไม่พอ** — ต้องเฝ้า OAuth consent + ใช้ Conditional Access ควบคู่
- หากข้อมูลส่วนบุคคลในเมลถูกเข้าถึง → ประเมิน **PDPA (72 ชม.)** และพิจารณาแจ้ง **ThaiCERT/NCSA**

<sub>ECOP MDR Playbook · ฉบับตั้งต้น 2026-07-20</sub>
