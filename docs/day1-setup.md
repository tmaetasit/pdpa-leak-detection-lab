# วันที่ 1: ตั้ง lab (Wazuh + Windows endpoint + Sysmon)

**เป้าหมายของวัน:** เปิด Wazuh dashboard จากเครื่องหลักได้ เห็น Windows VM ขึ้นสถานะ **Active** และเห็น event ของ Sysmon ไหลเข้า dashboard

**เวลาโดยประมาณ:** 5–6 ชั่วโมง (ส่วนใหญ่คือรอดาวน์โหลดและติดตั้ง)

```
PC หลัก (Windows, 32GB)
 ├─ VirtualBox
 │   ├─ VM 1: Ubuntu 24.04 Server  ── Wazuh (manager + indexer + dashboard)
 │   └─ VM 2: Windows 11           ── Wazuh agent + Sysmon
 └─ เบราว์เซอร์ → https://<IP ของ Ubuntu>  (Wazuh dashboard)
```

---

## ขั้นที่ 0: เช็กเครื่องหลัก (10 นาที)

1. เปิด **Task Manager → Performance → CPU** ดูบรรทัด **Virtualization** ต้องเป็น **Enabled**
   - ถ้าเป็น Disabled: เข้า BIOS (กด Del ตอนเปิดเครื่อง) เมนบอร์ด MSI อยู่ที่ **OC → CPU Features → Intel Virtualization Tech → Enabled**
2. ถ้าเคยเปิด Hyper-V, WSL2 หรือ Docker Desktop ไว้ VirtualBox จะยังรันได้แต่ช้าลง ถ้า VM ช้ามาก ค่อยกลับมาปิดทีหลัง ไม่ต้องทำตอนนี้
3. เตรียมพื้นที่ดิสก์ว่างอย่างน้อย **150GB** (คุณมีเหลือ ~800GB สบาย)

## ขั้นที่ 1: ติดตั้ง VirtualBox (20 นาที)

1. ดาวน์โหลด **VirtualBox** และ **Extension Pack** เวอร์ชันเดียวกันจาก virtualbox.org
2. ติดตั้ง VirtualBox แล้วดับเบิลคลิกไฟล์ Extension Pack เพื่อติดตั้งต่อ (ต้องใช้สำหรับ USB 2.0/3.0 ในวันที่ 3)
3. สร้าง **Host-only network**: File → Tools → Network Manager → Host-only Networks → Create
   จดช่วง IP ไว้ (ปกติคือ `192.168.56.0/24`) เปิด DHCP Server ไว้

> ทุก VM จะมี 2 network adapter: **NAT** (ออกอินเทอร์เน็ต) + **Host-only** (คุยกันภายใน lab และให้เครื่องหลักเปิด dashboard ได้)

## ขั้นที่ 2: Ubuntu VM + Wazuh (2 ชั่วโมง)

### 2.1 สร้าง VM

| ค่า | ใช้ |
| --- | --- |
| ISO | Ubuntu Server 24.04 LTS |
| CPU | 4 vCPU |
| RAM | 8 GB |
| Disk | 60 GB (dynamic) |
| Adapter 1 | NAT |
| Adapter 2 | Host-only |

ตอนติดตั้ง Ubuntu: เลือก **Install OpenSSH server** ไว้ด้วย จะได้ SSH จากเครื่องหลักแล้ว copy-paste คำสั่งได้สะดวก

### 2.2 ดู IP และตั้งให้คงที่

```bash
ip -4 addr       # หา IP วง 192.168.56.x (เช่น 192.168.56.10)
```

ถ้าอยากให้ IP ไม่เปลี่ยน แก้ `/etc/netplan/50-cloud-init.yaml` ส่วน adapter ตัวที่สอง (ชื่อมักเป็น `enp0s8`):

```yaml
    enp0s8:
      dhcp4: false
      addresses: [192.168.56.10/24]
```

แล้วรัน `sudo netplan apply`

จากนี้เครื่องหลัก SSH เข้าได้ด้วย `ssh <user>@192.168.56.10`

### 2.3 ติดตั้ง Wazuh แบบ all-in-one

```bash
sudo apt update && sudo apt -y upgrade
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

ใช้เวลาประมาณ 15–30 นาที จบแล้วจะแสดง **User: admin** และ **Password** ให้ **จดรหัสไว้ทันที**
ถ้าลืม ดูได้ด้วย:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

ปิด auto-update ของ Wazuh กันอัปเกรดเองแล้ว lab พัง:

```bash
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list && sudo apt update
```

### 2.4 ทดสอบ

เปิดเบราว์เซอร์บนเครื่องหลัก → `https://192.168.56.10` → กด accept certificate warning (ปกติ เพราะเป็น self-signed) → login ด้วย admin

> **ถ้าติดตั้งพังเกิน 3 ชั่วโมง:** ลบ VM ทิ้งแล้วใช้ **Wazuh OVA** (virtual machine สำเร็จรูป) แทน import เข้า VirtualBox ได้เลย ไม่ต้องเสียวันกับขั้นนี้

## ขั้นที่ 3: Windows VM (1.5 ชั่วโมง)

### 3.1 สร้าง VM

| ค่า | ใช้ |
| --- | --- |
| ISO | Windows 11 Enterprise **Evaluation** (ฟรี 90 วัน จาก Microsoft Evaluation Center) |
| CPU | 2 vCPU |
| RAM | 4–6 GB |
| Disk | 60 GB |
| Adapter 1 | NAT |
| Adapter 2 | Host-only |

VirtualBox 7 จะเปิด TPM 2.0 และ Secure Boot ให้อัตโนมัติเมื่อเลือกชนิด Windows 11

ตั้งชื่อผู้ใช้ในเครื่องว่า **`labuser`** (ให้ตรงกับ path ใน config ของโปรเจกต์) ติดตั้ง **Guest Additions** ด้วยเพื่อ copy-paste ระหว่างเครื่องได้

### 3.2 ทดสอบว่าเห็น Ubuntu

ใน PowerShell ของ Windows VM:

```powershell
Test-NetConnection 192.168.56.10 -Port 1514
```

`TcpTestSucceeded : True` = พร้อม

## ขั้นที่ 4: ติดตั้ง Wazuh agent (20 นาที)

1. ใน Wazuh dashboard: **Agents management → Summary → Deploy new agent**
2. เลือก **Windows (MSI)** → Server address ใส่ `192.168.56.10` → ตั้งชื่อ agent เช่น `win-endpoint-01`
3. dashboard จะสร้างคำสั่ง PowerShell ให้ copy ไปรันใน Windows VM แบบ **Run as Administrator**
4. เริ่ม service:

```powershell
NET START Wazuh
```

5. กลับไป dashboard ภายใน 1–2 นาที agent ควรขึ้น **Active** สีเขียว

> ใช้คำสั่งที่ dashboard สร้างให้ ไม่ต้องพิมพ์เอง เพราะจะตรงกับเวอร์ชันของ manager เสมอ

## ขั้นที่ 5: ติดตั้ง Sysmon (30 นาที)

Sysmon คือเครื่องมือฟรีของ Microsoft ที่บันทึกพฤติกรรมบนเครื่อง (process, network, file) ละเอียดกว่า Windows log ปกติ เป็นตัวแทน "EDR sensor" ใน lab นี้

1. ดาวน์โหลด **Sysmon** จาก Microsoft Sysinternals แตกไฟล์ไว้ที่ `C:\Tools\Sysmon`
2. ดาวน์โหลด config ที่ชุมชนใช้กันแพร่หลาย: `sysmonconfig-export.xml` จาก GitHub repo **SwiftOnSecurity/sysmon-config** วางไว้โฟลเดอร์เดียวกัน
3. PowerShell (Admin):

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

4. เช็ก: Event Viewer → Applications and Services Logs → Microsoft → Windows → **Sysmon → Operational** ต้องมี event

### 5.1 ส่ง Sysmon เข้า Wazuh

เปิด Notepad แบบ Administrator → เปิด `C:\Program Files (x86)\ossec-agent\ossec.conf` → เพิ่มก่อนบรรทัด `</ossec_config>` อันสุดท้าย:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
Restart-Service -Name wazuh
```

## ขั้นที่ 6: เตรียม Python ไว้สำหรับวันที่ 2–3 (15 นาที)

ใน Windows VM:

1. ติดตั้ง **Python 3.12 ขึ้นไป** ติ๊ก **Add python.exe to PATH**
2. สร้างโฟลเดอร์ `C:\pdpa-lab` แล้ว copy โปรเจกต์นี้เข้าไป
3. ```powershell
   cd C:\pdpa-lab
   pip install -r requirements.txt
   python -m pytest -q
   ```
   ต้องผ่านทั้งหมด

## ขั้นที่ 7: Snapshot (5 นาที)

ปิด VM ทั้งสองแล้วทำ **Snapshot** ชื่อ `day1-clean` ถ้าวันหลังพัง กลับมาที่จุดนี้ได้ใน 1 นาที

---

## เช็กลิสต์จบวัน

- [ ] เปิด Wazuh dashboard จากเครื่องหลักได้
- [ ] Agent `win-endpoint-01` สถานะ **Active**
- [ ] เห็น event Sysmon ใน dashboard: **Threat Hunting → Events** ค้นหา `data.win.system.providerName: Microsoft-Windows-Sysmon`
- [ ] `python -m pytest -q` ผ่านใน Windows VM
- [ ] Snapshot `day1-clean` ของทั้งสอง VM

## ปัญหาที่เจอบ่อย

| อาการ | ทางแก้ |
| --- | --- |
| VM เปิดไม่ขึ้น "VT-x is not available" | เปิด Virtualization ใน BIOS (ขั้นที่ 0) |
| Agent ขึ้น **Never connected** | เช็ก Test-NetConnection ขั้น 3.2, เช็กว่า server address ตอน deploy คือ IP วง Host-only |
| Dashboard เปิดไม่ได้หลัง reboot Ubuntu | รอ 2–3 นาที indexer เริ่มช้า ถ้ายังไม่ได้: `sudo systemctl restart wazuh-indexer wazuh-manager wazuh-dashboard` |
| ไม่เห็น event Sysmon | เช็กว่าแก้ ossec.conf ถูกที่ (ใน `<ossec_config>`) และ restart service แล้ว |

**จดปัญหาที่เจอและวิธีแก้ไว้ทุกครั้ง** ส่วนนี้จะกลายเป็นหัวข้อ "สิ่งที่เรียนรู้" ใน case study และเป็นเรื่องที่คนสัมภาษณ์ชอบถาม
