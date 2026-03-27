
## 🟣 Use Case 4 — Single Combined Splunk Query
Log Tampering / Event Log Clearing Detection

This one query detects the full log tampering chain, including:

- Execution of wevtutil.exe
- Log clearing command execution
- Security log cleared event
- Suspicious command execution

---

## 🔍 Master Detection Query — Use Case 4
```spl
index=* (EventCode=4688 OR EventCode=1102)
| eval Activity=case
(
EventCode==4688 AND like(New_Process_Name,"%wevtutil.exe%"),
"Log Utility Execution (wevtutil)",
EventCode==4688 AND like(CommandLine,"%cl%"),
"Event Log Clearing Command Detected",
EventCode==1102,
"Security Log Cleared"
)
| stats count
values(Activity) as Detected_Activities
values(Account_Name) as Users
values(CommandLine) as Commands
values(New_Process_Name) as Processes
by _time
| sort -_time

```

---

## 🎯 What This Query Detects (Full Use Case 4 Flow)

This covers your complete log tampering scenario.

- wevtutil executed	Event 4688
- Log clear command issued	CommandLine detection
- Security log cleared	Event 1102
  
---

## 🧪 Real Attack Scenario (Windows Victim)

Run this on Windows victim machine:
```cmd
wevtutil cl Security

```
OR:
```cmd
wevtutil cl System

```
OR:
```cmd
wevtutil cl Application

```
These commands clear Windows logs.

---

## 📊 Expected Splunk Logs

After attack:

- 4688 → wevtutil.exe executed
- 1102 → Security log cleared

Detected_Activities:

- Log Utility Execution (wevtutil)
- Event Log Clearing Command Detected
- Security Log Cleared

---

## ⭐ SOC-Level Correlation Version (Recommended)

This version detects real attacker cleanup behavior.
```spl
index=* (EventCode=4688 OR EventCode=1102)
| eval Activity=case
(
EventCode==4688 AND like(New_Process_Name,"%wevtutil.exe%"),
"Log Utility Execution",
EventCode==4688 AND like(CommandLine,"%cl%"),
"Log Clear Command",
EventCode==1102,
"Security Log Cleared"
)
| stats values(Activity) as Activities
values(Account_Name) as Users
values(CommandLine) as Commands
by Account_Name
| where mvcount(Activities) >= 2

```
This detects multi-step tampering.

---

## 🚨 Best Alert Query for Use Case 4

Use this to create Splunk Alert.
```spl
index=* EventCode=1102
| table _time Account_Name

```

---

## 📊 Expected Output Example

|time               |Detected_Activities      |
|-------------------|-------------------------|
|14:22:11           |Log Utility Execution    |
|14:22:15           |Log Clear Command        |
|14:22:16           |Security Log Cleared     |

---

## 🧠 Why This Use Case Is Important

Attackers always try to hide traces after intrusion.

Common real-world behavior:
```
Gain Access → Run Attack → Clear Logs → Escape Detection

```
This use case detects that cleanup phase.

---

## 🔥 Real SOC Tip

If you see:
```
wevtutil.exe
+
EventCode 1102

```

---

🚨 CRITICAL — LOG TAMPERING DETECTED

---
Because normal users almost never clear logs.
