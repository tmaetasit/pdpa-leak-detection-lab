# วันที่ 4: Mini SWG (Shadow AI upload)

mitmproxy ทำหน้าที่ SWG อยู่บน Ubuntu VM (`192.168.56.102:8080`) Windows VM ตั้ง proxy ชี้มาที่นี่
addon ดึงไฟล์ที่อัปโหลดและข้อความที่วางใน prompt มาสแกนด้วย scanner ตัวเดิม ดูปลายทางใน mini Cloud
Registry แล้วเขียน JSON ลง `/var/log/pdpa-swg/swg.json` ซึ่ง Wazuh manager อ่านเอง

```
Edge (Windows VM) ──proxy──► mitmproxy :8080 (Ubuntu) ──► mock site 127.0.0.1:8000 (*.test เท่านั้น)
                                │  scan + registry          เว็บจริง + มีไฟล์/เลขบัตร → proxy ตอบ 403 เอง
                                ▼
                     /var/log/pdpa-swg/swg.json ──► Wazuh manager ──► rules 100122–100141
```

**ความปลอดภัยของ lab:** ทดสอบกับเว็บ `*.test` เท่านั้น (ชื่อสงวนตาม RFC 6761 ไม่มีบนอินเทอร์เน็ต)
และ addon มี safety guard (`pdpa_sinkhole`, เปิดเป็นค่าเริ่มต้น): ถ้าส่งไฟล์ไปบริการจริงใน registry
หรือส่งเลขบัตรไปเว็บจริงใด ๆ proxy จะตอบ 403 เองโดยไม่ต่อออกไป (`connection_strategy=lazy`
ทำให้ยังไม่เปิด connection ไปปลายทางจนกว่า addon จะตัดสินใจ)

## 1. Ubuntu VM: ติดตั้ง (ผ่าน SSH จาก Windows VM)

```bash
sudo apt update && sudo apt install -y python3-venv git
cd ~ && git clone https://github.com/tmaetasit/pdpa-leak-detection-lab.git pdpa-lab
cd ~/pdpa-lab
python3 -m venv .venv && .venv/bin/pip install -r requirements-swg.txt
.venv/bin/python -m pytest -q tests/test_swg.py      # ต้องมี pytest: .venv/bin/pip install pytest
sudo mkdir -p /var/log/pdpa-swg && sudo chown maetasit: /var/log/pdpa-swg
```

ดู IP ของ Windows VM (`ipconfig` ที่ Windows) แล้วผูกกับชื่อ user:

```bash
echo 'PDPA_CLIENTS=192.168.56.XXX=tt' | sudo tee /etc/default/pdpa-swg
sudo cp swg/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pdpa-mock-site pdpa-swg
systemctl --no-pager status pdpa-swg | head -5
ls ~/.mitmproxy/          # CA ถูกสร้างตอน mitmdump เริ่มครั้งแรก
sudo ufw status           # ถ้า active: sudo ufw allow from 192.168.56.0/24 to any port 8080 proto tcp
```

## 2. Wazuh manager: rule + อ่าน log

```bash
sudo cp wazuh/pdpa_rules.xml /var/ossec/etc/rules/pdpa_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/pdpa_rules.xml
sudo tee -a /var/ossec/etc/ossec.conf < wazuh/manager_ossec_snippet.xml
sudo /var/ossec/bin/wazuh-logtest     # วางทีละบรรทัดจาก swg/sample_events.jsonl
sudo systemctl restart wazuh-manager
```

ผลที่ควรได้จาก `swg/sample_events.jsonl` (ตามลำดับบรรทัด):

| # | กรณี | rule | level |
| --- | --- | --- | --- |
| 1 | critical 120 IDs → ShadowAI | 100122 | 12 |
| 2 | high 25 IDs → ShadowAI (unsanctioned, risk high) | 100123 (ยกระดับ) | 12 |
| 3 | high 25 IDs → Corp Copilot (sanctioned) | 100111 | 10 |
| 4 | prompt มี 1 ID → ShadowAI | 100124 | 7 |
| 5 | ไฟล์ clean → ShadowAI | 100141 | 5 |
| 6 | ไฟล์ clean → QuickShare | 100140 | 3 |
| 7 | ไฟล์ clean → chatgpt.com (sinkholed) | 100141 | 5 |

## 3. Windows VM: certificate + proxy + bypass list (Admin PowerShell)

```powershell
scp maetasit@192.168.56.102:/home/maetasit/.mitmproxy/mitmproxy-ca-cert.cer C:\pdpa-lab\
Import-Certificate -FilePath C:\pdpa-lab\mitmproxy-ca-cert.cer -CertStoreLocation Cert:\LocalMachine\Root

$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty $k ProxyServer   '192.168.56.102:8080'
Set-ItemProperty $k ProxyOverride 'localhost;127.*;192.168.56.*;*.local;<local>'
Set-ItemProperty $k ProxyEnable   1
```

ปิด Edge ทุกหน้าต่างแล้วเปิดใหม่ ตรวจที่ Settings → Network & internet → Proxy

Bypass มี 2 ชั้น เหมือน SWG จริง:
- **ฝั่ง client** (`ProxyOverride`): traffic ใน lab ไม่ผ่าน proxy เลย รวมถึง dashboard `https://192.168.56.102`
- **ฝั่ง proxy** (`no_decrypt` ใน `swg/cloud_registry.json`): ผ่าน proxy แต่ไม่ถอด TLS เช่น ธนาคาร โรงพยาบาล
  Windows Update และหน้า login ของ Microsoft

ปิด proxy เมื่อเลิกทดสอบ: `Set-ItemProperty $k ProxyEnable 0`

## 4. ทดสอบ

หาไฟล์ทดสอบแต่ละระดับ:

```powershell
cd C:\pdpa-lab; .\.venv\Scripts\Activate.ps1
python -m scanner.scan testdata | Select-String 'CRITICAL|HIGH' | Select-Object -First 4
```

แบบสคริปต์ (curl.exe ใช้ Windows cert store, `--ssl-no-revoke` เพราะ CA ของ lab ไม่มี CRL):

```powershell
$p = '-x','http://192.168.56.102:8080','--ssl-no-revoke'
curl.exe @p -F "file=@C:\pdpa-lab\testdata\<critical>.xlsx" https://chat.shadow-ai.test/api/upload
curl.exe @p -F "file=@C:\pdpa-lab\testdata\<high>.csv"      https://chat.shadow-ai.test/api/upload
curl.exe @p -F "file=@C:\pdpa-lab\testdata\<high>.csv"      https://copilot.corp.test/api/upload
curl.exe @p -F "file=@C:\pdpa-lab\testdata\<clean>.docx"    https://chatgpt.com/backend-api/files   # ต้องได้ 403 จาก safety guard
```

แบบผู้ใช้จริง (สำหรับคลิป): เปิด Edge ไปที่ `https://chat.shadow-ai.test` อัปโหลดไฟล์ และวางข้อความที่มีเลขบัตรปลอมในช่อง prompt

ตรวจผล:
- Ubuntu: `tail -f /var/log/pdpa-swg/swg.json` และ `journalctl -u pdpa-swg -f`
- ยืนยันว่าไม่มีอะไรออกนอก lab: `journalctl -u pdpa-swg | grep "server connect" | grep -v 127.0.0.1:8000` ต้องไม่มีปลายทาง AI/cloud จริง
- Dashboard → Discover: `rule.id:(100122 or 100123 or 100124 or 100140 or 100141 or 100111)`
- Bypass: เปิด `https://www.scb.co.th` ใน Edge แล้วดู certificate ต้องเป็นของธนาคาร ไม่ใช่ mitmproxy

## ปัญหาที่อาจเจอ

| อาการ | สาเหตุ / ทางแก้ |
| --- | --- |
| Edge ขึ้น `NET::ERR_CERT_AUTHORITY_INVALID` | ยังไม่ได้ import CA ลง LocalMachine\Root หรือยังไม่ปิด-เปิด Edge |
| 502 Bad Gateway ที่เว็บ `.test` | `pdpa-mock-site` ไม่ทำงาน: `systemctl status pdpa-mock-site` |
| Edge เปิด `chat.shadow-ai.test` แล้วไปหน้าค้นหา | พิมพ์ `https://` นำหน้า |
| ไม่มี log แต่เว็บเปิดได้ | Edge ไม่ได้ใช้ proxy (ดู Settings → Proxy) หรือไฟล์เป็นชนิดที่ scanner ไม่อ่าน |
| alert ไม่ขึ้นแต่ไฟล์ log มีบรรทัด | ลืม localfile ใน `ossec.conf` ของ manager หรือยังไม่ restart manager |
