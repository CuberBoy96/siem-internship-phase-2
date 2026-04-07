# 🛡️ Detection Engineering Lab: SMB Credential Access & Logon Detection — The "Liquid Gold" Playbook

![MITRE](https://img.shields.io/badge/MITRE-T1021.002-red)
![Technique](https://img.shields.io/badge/Technique-SMB%20Authentication-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

# 📌 Project Overview

Detecting unauthorized access via **SMB (Server Message Block)** is critical for identifying **credential-based attacks** and stopping **lateral movement**.

Attackers commonly use SMB to:

- Test stolen credentials
- Access shared files
- Upload malicious payloads
- Move laterally across systems

This lab demonstrates how to:

✔️ Simulate SMB authentication  
✔️ Analyze Windows logon events  
✔️ Build high-fidelity Splunk detections  
✔️ Detect brute-force attacks  

---

# 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-SMBClient
▼
Windows Target System
│
│ Network Authentication
▼
Windows Security Logs
│
▼
Splunk SIEM
│
▼
SMB Logon Detection 🚨

```
---

## ⚔️ Phase 1: Attack Simulation (Credential Access)

Attackers often use **Impacket SMB tools** to test credentials or browse remote shares.

If attackers possess:

- Password lists
- Credential dumps
- Default credentials

They may attempt:

- 🔓 Password Spraying  
- 🔓 Brute Force  
- 🔓 Credential Validation  

---

## 💻 Attack Execution

Executed from the Kali Linux attacker machine:

```bash
# Connecting to the target via SMB
impacket-smbclient abhay:CB@i510400f@10.193.10.80

```

---
## 🧪 Actions Inside SMB Session

Once connected, attackers may execute:

- ls      # List shares
- get     # Download files
- put     # Upload malicious files

---
## ✅ Result

- ✔️ SMB connection established
- ✔️ Credentials validated
- ✔️ Remote share access available

---
## 📂 Phase 2: The Data Decoder (Windows Event IDs)

To detect SMB activity, monitor Windows Logon Events.

Windows records:

- ✔️ Successful logins
- ✔️ Failed logins
- ✔️ Privileged logins

---
## 🧩 Critical Windows Event IDs

|Event Type	|Event ID	|Description |
|-----------|---------|------------|
|Successful Logon	|4624	|Access granted |
|Failed Logon	|4625	|Authentication failed |
|Special Logon	|4672	|Admin privileges assigned |

---
## 🔑 The "Logon Type" Secret

For SMB activity:
```
Logon Type = 3
```
Meaning:

- 🌐 Network Logon
- 📡 Remote authentication

---
## 🏆 Phase 3: The "Universal" Splunk Query (Liquid Gold)

This query detects network-based logons.
```spl
index=* (EventCode=4624 OR EventCode=4625)
Logon_Type=3

| eval Status = if(EventCode==4624,
                   "Success",
                   "Failure")

| eval Source_IP = coalesce(Source_Network_Address,
                            ip,
                            src_ip)

| table _time,
         TargetUserName,
         Source_IP,
         Status,
         WorkstationName

| sort - _time

```

---
## 🔍 Hunting for Brute Force Attacks

Attackers often attempt multiple passwords rapidly.

Detect using:
```spl
index=* EventCode=4625
Logon_Type=3

| stats count by
        TargetUserName,
        Source_Network_Address

| where count > 10

```

---
## 📊 Phase 4: Lab Results & Observations

Splunk dashboard:
```
smb_logon_detection
```
Captured:

- ✔️ Successful SMB logons
- ✔️ Network-origin authentication
- ✔️ External source identification


---
## 🔎 Observed Activity

|Observation	|Result |
|-------------|-------|
|Logon Success	|Multiple events |
|User	|abhay |
|Logon |Type	3 |
|Source	Kali |Linux |
|Authentication	|Network-based |

---
## 🛠️ Troubleshooting Visibility "Blockers"

If SMB attempts don't appear in Splunk:

## 1️⃣ Enable Logon Auditing

Run:
```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

```
---
## 2️⃣ Verify Source IP Mapping

Some logs may display:
```
::1
```
Meaning:

Localhost traffic.

Check:
```
Source_Network_Address
```
Field.

---
## 3️⃣ Check Firewall Logs

If connection is blocked:

You may see:

- ❌ No 4624/4625 events

Instead check:

- Windows Firewall Logs
- Network Flow Logs

---
## 🗺️ MITRE ATT&CK Mapping

|Technique	|ID	|Description |
|-----------|---|------------|
|SMB Remote Services	|T1021.002	|Lateral movement via SMB |
|Valid Accounts	|T1078	|Credential-based access |
|Brute Force	|T1110	|Password guessing |

---
## 🚩 Indicators of Compromise (IOCs)

Watch for:

- ⚠️ Multiple failed logins (4625)
- ⚠️ Successful remote SMB logins (4624)
- ⚠️ Logon Type 3 activity
- ⚠️ Unknown source IP addresses

---
## 🛡️ Defensive Recommendations

Strengthen authentication security:

- ✔️ Disable SMBv1
- ✔️ Enforce Multi-Factor Authentication (MFA)
- ✔️ Monitor Logon Type 3 events
- ✔️ Alert on repeated login failures
- ✔️ Restrict SMB access to trusted hosts

---
## 🧠 Key Takeaway

Monitoring Logon Type 3 events provides powerful visibility into network-based authentication activity.

Combining:

- ✔️ Successful Logons (4624)
- ✔️ Failed Logons (4625)
- ✔️ Source IP Tracking

Creates high-confidence SMB detection.

---
## 🏁 Lab Conclusion

By analyzing:

- ✔️ Network authentication logs
- ✔️ Failed login patterns
- ✔️ Source IP behavior

We successfully built a reliable SMB credential detection strategy, capable of identifying:

- 🔓 Unauthorized logins
- 🔓 Brute-force attempts
- 🔓 Lateral movement

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
