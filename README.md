# 💻 Windows Ransomware Detection Lab  

## 🔹 Overview  
Ransomware attacks are one of the most dangerous threats faced by organizations. This project simulates **Windows Event Logs (Sysmon + Security logs)** that include both normal activity and ransomware-like behavior.  

The lab demonstrates how to:  
- Detect **file encryption activity**  
- Identify **suspicious process execution** (PowerShell, cmd, wmic abuse)  
- Spot **persistence techniques** used by ransomware  
- Map detections to **MITRE ATT&CK**  

---

## 🔹 Dataset  
Dataset: `datasets/windows_event_logs.csv`  

The log entries include:  
- **Normal Events**  
  - User logon/logoff (Event ID 4624, 4634)  
  - File read/write operations  
  - Normal PowerShell usage  

- **Suspicious/Malicious Events**  
  - Multiple file modifications in short time (encryption behavior)  
  - Process execution: `vssadmin delete shadows`, `cipher.exe`  
  - Persistence via `Run` registry key modification  
  - Network connection to suspicious IPs for C2  

---

## 🔹 Detection Logic  

### 📌 SPL (Splunk Queries)  

**1. Detect mass file encryption activity**  
```spl
index=win_event_logs
| search EventID=11 OR EventID=4663
| stats count by process_name, target_file
| where count > 100
```

**2. Detect shadow copy deletion (common ransomware behavior)**  
```spl
index=win_event_logs
| search EventID=1 process_name="vssadmin.exe" CommandLine="*delete shadows*"
| table _time, user, process_name, CommandLine
```

**3. Detect persistence in registry keys**  
```spl
index=win_event_logs
| search EventID=13 registry_key_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
| table _time, user, process_name, registry_key_path
```

---

## 🔹 Sigma Rules  

### 🛡️ Ransomware – Shadow Copy Deletion  
```yaml
title: Ransomware Shadow Copy Deletion
id: 1122aabb-3344-ccdd-5566-77889900aa11
status: experimental
description: Detects shadow copy deletion often used by ransomware to prevent recovery
author: Tirthraj Sisodiya
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: "vssadmin.exe"
    CommandLine|contains: "delete shadows"
  condition: selection
fields:
  - EventID
  - CommandLine
  - User
falsepositives:
  - Legitimate system maintenance
level: critical
```

### 🛡️ Ransomware – Mass Encryption Behavior  
```yaml
title: Ransomware Mass File Encryption
id: 2233bbcc-4455-ddee-6677-889900aabb22
status: experimental
description: Detects when a process rapidly modifies large numbers of files (encryption activity)
author: Tirthraj Sisodiya
logsource:
  product: windows
  category: file_event
detection:
  selection:
    EventID: 4663
  condition: selection
fields:
  - EventID
  - ProcessName
  - TargetFilename
falsepositives:
  - Backup software
level: high
```

---

## 🔹 MITRE ATT&CK Mapping  

| Technique | ID | Description |  
|-----------|----|-------------|  
| File and Directory Discovery | T1083 | Ransomware scanning files |  
| Modify Registry | T1112 | Persistence via Run keys |  
| Inhibit System Recovery | T1490 | Shadow copy deletion |  
| Data Encrypted for Impact | T1486 | File encryption ransomware behavior |  
| Command and Scripting Interpreter | T1059 | Abuse of PowerShell, cmd |  

---

## 🔹 Skills Demonstrated  
- Windows Event Log & Sysmon analysis  
- Ransomware behavior detection  
- Splunk SPL queries for ransomware hunting  
- Sigma rules for process & file event detection  
- Mapping endpoint threats to MITRE ATT&CK  

---

⚡ **Author:** Tirthraj Sisodiya  
🔗 LinkedIn: [linkedin.com/in/tirthraj-cybersecurity](https://linkedin.com/in/tirthraj-cybersecurity)  
