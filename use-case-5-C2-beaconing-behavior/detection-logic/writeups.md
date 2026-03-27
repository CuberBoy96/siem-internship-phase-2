
## 🔴 Use Case 5 — Hidden User Account Creation Detection

This is a very strong SOC use case, because attackers often create backdoor admin accounts to maintain persistence.

We'll build:

- ✅ One Single Combined Splunk Query
- ✅ Detect full hidden user creation chain
- ✅ Ready for GitHub documentation
- ✅ SOC-level correlation logic

## 🔴 Use Case 5 — Single Combined Splunk Query
Hidden User Account Creation Detection

This one query detects:

- New user creation
- User added to Administrators group
- Privileged rights assignment
- Suspicious hidden-style usernames

---

## 🔍 Master Detection Query — Use Case 5

```spl
index=* (EventCode=4720 OR EventCode=4732 OR EventCode=4672)
| eval Activity=case
(
EventCode==4720,
"User Account Created",
EventCode==4732,
"User Added to Administrators Group",
EventCode==4672,
"Administrative Privileges Assigned"
)
| stats count
values(Activity) as Detected_Activities
values(TargetUserName) as Created_User
values(SubjectUserName) as Performed_By
by _time
| sort -_time

```

---

## 🎯 What This Query Detects (Full Use Case 5 Flow)

This covers your complete hidden user persistence scenario.

- New user created	Event 4720
- Added to admin group	Event 4732
- Admin privileges assigned	Event 4672
  
---

## 🧪 Real Attack Scenario (Windows Victim)

Run this on Windows victim machine:
```cmd
net user hiddenadmin Pass123@ /add

```

Then:
```cmd
net localgroup administrators hiddenadmin /add

```

Optional stealth-style account:
```cmd
net user support$ Pass123@ /add
net localgroup administrators support$ /add

```
Attackers often use:
```cmd
support$
backup$
svc_admin
systemhelp

```
These look legitimate or hidden.

---

## 📊 Expected Splunk Logs

After attack:

- 4720 → User Created
- 4732 → Added to Administrators
- 4672 → Privileged Token Assigned

Detected_Activities:

- User Account Created
- User Added to Administrators Group
- Administrative Privileges Assigned

---

## ⭐ SOC-Level Correlation Version (Recommended)

This version detects multi-step persistence behavior.
```spl
index=* (EventCode=4720 OR EventCode=4732 OR EventCode=4672)
| eval Activity=case
(
EventCode==4720,"User Created",
EventCode==4732,"Added to Admin Group",
EventCode==4672,"Admin Privileges Assigned"
)
| stats values(Activity) as Activities
values(TargetUserName) as Created_User
values(SubjectUserName) as Performed_By
by TargetUserName
| where mvcount(Activities) >= 2

```
This detects real privilege persistence chains.

---

## 🚨 Best Alert Query for Use Case 5

Use this to create Splunk Alert.
```spl
index=* (EventCode=4720 OR EventCode=4732)
| stats count
values(EventCode) as Events
by TargetUserName
| where count >= 2

```

---

## 📊 Expected Output Example
|time                |Detected_Activities                |
|--------------------|-----------------------------------|
|16:12:01            |User Account Created               |
|16:12:05            |User Added to Administrators Group |
|16:12:08            |Administrative Privileges Assigned |

---

## 🧠 Why This Use Case Matters

Attackers create hidden backdoor accounts to maintain long-term access.

Typical attacker flow:
```
Gain Access → Create Hidden User → Add Admin Rights → Maintain Persistence

```
This detection stops that persistence.

---

##🔥 Real SOC Tip

If you detect:
```
User Created
+
Added to Admin Group

```
---

🚨 CRITICAL — BACKDOOR ACCOUNT CREATED

Because normal users rarely create admin accounts.

---
