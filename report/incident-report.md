# Incident Report: APT29-Style Intrusion (SCRANTON & NASHUA)

| | |
|---|---|
| **Analyst** | Umang Udeshi |
| **Severity** | Critical |
| **Status** | Investigated - containment recommended |
| **Data source** | OTRF Security-Datasets, APT29 Day 1 (196,081 Windows events: Sysmon, Security, PowerShell) |
| **Scope** | 2 hosts compromised, 1 user account confirmed compromised |

> This investigation was performed on a public, emulated dataset (MITRE ATT&CK Evaluations - APT29) for training and portfolio purposes.

---

## 1. Executive Summary

On 1 May 2020, user **pbeesly** opened a malicious file disguised as a Word document on host **SCRANTON**. The file gave an attacker hidden remote access. Within 3 minutes the attacker gained administrator rights without triggering a Windows security prompt, then ran hidden code concealed inside an image file.

The attacker then **stole stored passwords** from SCRANTON, used them to **move to a second machine, NASHUA**, stole passwords there as well, and packed collected data into a **password-protected archive** ready to be taken out of the network.

The full chain - from first click to data staged for theft - took **about 20 minutes**.

**Business impact:** credentials for all users logged into SCRANTON and NASHUA should be treated as compromised. Data collected from pbeesly's profile was prepared for exfiltration.

---

## 2. Affected Assets

| Asset | Role in incident |
|---|---|
| **SCRANTON.dmevals.local** (10.0.1.4) | Patient zero - initial access, privilege escalation, credential theft |
| **NASHUA.dmevals.local** (10.0.1.6) | Lateral movement target - credential theft, data staging |
| **DMEVALS\pbeesly** | Victim account, used by attacker for lateral movement |

---

## 3. Attack Timeline (UTC, 1 May 2020)

| Time | Host | Event | MITRE ATT&CK | Detected by |
|---|---|---|---|---|
| 22:55:56 | SCRANTON | User double-clicks `cod.3aka3.scr`, disguised as `.doc` via a hidden right-to-left override character | T1204.002, T1036.002 | **D04** |
| 22:56:04 | SCRANTON | Malware launches hidden `cmd.exe` (reverse shell) | T1059.003 | Gap |
| 22:56:14 | SCRANTON | Attacker switches to PowerShell | T1059.001 | - |
| 22:58:18 | SCRANTON | Registry key `HKCU\Software\Classes\Folder\shell\open\command` hijacked with a hidden PowerShell payload | T1548.002 | **D01** |
| 22:58:30 | SCRANTON | `DelegateExecute` value set empty to enable the hijack | T1548.002 | **D01** |
| 22:58:42 | SCRANTON | `sdclt.exe` (auto-elevating) triggered - reads hijacked key | T1548.002 | - |
| 22:58:44 | SCRANTON | Elevated hidden PowerShell runs payload decoded from pixels of `monkey.png` (steganography), executed in memory | T1059.001, T1027.003, T1140 | **D05** |
| 23:05:16 | SCRANTON | PowerShell opens `lsass.exe` with full access - credential dumping | T1003.001 | **D02** |
| 23:09:24 | SCRANTON → NASHUA | PowerShell connects to NASHUA on port 5985 (WinRM) | T1021.006 | **D03** |
| 23:09:29 | NASHUA | `wsmprovhost.exe` opens `lsass.exe` with full access - credential dumping on second host | T1003.001 | **D02** |
| 23:16:19 | NASHUA | `Rar.exe` (from `C:\Windows\Temp`) creates encrypted archive with hidden file names | T1560.001, T1074.001 | **D06** |

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Malicious file | `C:\ProgramData\victim\‮cod.3aka3.scr` (contains U+202E RTLO character) |
| SHA1 | `4B7FA56A4E85F88B98D11A6E018698AE3FBA5E62` |
| Steganography carrier | `C:\Users\pbeesly\Downloads\monkey.png` |
| Registry persistence/escalation | `HKCU\Software\Classes\Folder\shell\open\command` |
| Attacker tool | `C:\Windows\Temp\Rar.exe` |
| Staged archive | `C:\Users\pbeesly\Desktop\working.zip` |
| Archive password | `fGzq5yKw` (captured from command line) |
| Lateral movement | 10.0.1.4 → 10.0.1.6 : TCP 5985 |

---

## 5. Key Findings

1. **Initial access relied on user deception.** A right-to-left override character made an executable screensaver look like a document.
2. **The attacker avoided file-based antivirus.** The main payload was hidden in image pixels and run only in memory.
3. **Privilege escalation needed no exploit.** A standard user-writable registry key plus a trusted Windows binary gave admin rights silently.
4. **One data source was not enough.** On NASHUA, commands ran inside the remote session's memory, so process logs showed nothing - network logs (port 5985) revealed the movement.
5. **Logging quality mattered.** A case inconsistency ("Security" vs "security") would have hidden 30% of security events from exact-match queries.

---

## 6. Recommendations

### Immediate (containment)
- Isolate SCRANTON and NASHUA from the network.
- Reset passwords for **pbeesly** and **every account that has logged into either host**.
- Block the SHA1 hash and remove the `.scr`, `monkey.png`, `Rar.exe` and staged archives.
- Delete the hijacked registry key.
- Search proxy/firewall logs for outbound transfer of `working.zip` to confirm whether exfiltration occurred.

### Short term (Essential Eight)
| Control | How it would have helped |
|---|---|
| **Application control** | Blocks the `.scr` in ProgramData and `Rar.exe` in Temp from running |
| **Restrict administrative privileges** | UAC bypass gives no admin rights if the user is not a local admin; LSASS dumping requires admin |
| **Multi-factor authentication** | Limits reuse of stolen credentials for remote access |
| **User application hardening** | Restricts PowerShell (Constrained Language Mode) |

### Longer term
- Enable **LSA Protection (RunAsPPL)** and **Credential Guard** to protect LSASS.
- Set UAC to **"Always notify"** to break the auto-elevation bypass family.
- Restrict **WinRM** to admin jump hosts via host firewall.
- Build a detection for the remaining gap: hidden `cmd.exe` spawned by unusual parents (T1059.003).

---

## 7. Detection Coverage

Six detections were built and tested against the full dataset (196,081 events):

| ID | Detection | True positives | False positives |
|---|---|---|---|
| D01 | UAC bypass via registry hijack | 2 | 0 |
| D02 | LSASS credential dumping | 3 | 0 |
| D03 | WinRM lateral movement | 4 | 0 |
| D04 | RTLO masquerading / .scr execution | 1 | 0 |
| D05 | Suspicious PowerShell (risk scoring) | 1 | 0 |
| D06 | Encrypted archive staging | 1 | 0 |

Rules: [`/detections`](../detections) · Full queries: [`/docs/hunting-queries.kql`](../docs/hunting-queries.kql)
