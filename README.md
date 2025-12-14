# SOC Detection Home Lab

## Project Overview
This project simulates a realistic corporate environment to emulate adversary tradecraft and develop detection engineering skills. The infrastructure was built from scratch using **VMware Workstation Pro**, featuring a segmented network with a perimeter firewall (**pfSense**) and centralized telemetry collection via a SIEM (**Splunk**).

**Key Objectives**
* **Infrastructure as Code:** Deployed a Domain Controller, Firewall, and SIEM from ISO/OVA sources.
* **Telemetry Generation:** Configured Sysmon, Zeek, and Suricata to generate high-fidelity logs for analysis.
* **Adversary Emulation:** Executed attacks mapped to the **MITRE ATT&CK** framework (T1046, T1059.001, T1136.001).
* **Detection Engineering:** Developed Splunk queries to detect and alert on specific malicious behaviors.

---

## Logical Network Architecture
The lab features a private LAN (`192.168.1.0/24`) segmented from the internet by a firewall. All endpoint and network activity is forwarded to a central Splunk indexer for analysis.

<p align="center">
  <img src="https://github.com/chalithah/soc-detection-lab/blob/main/images/0-network-diagram.png">
  <br>
  <em><b>Fig 1:</b> Logical network architecture showing LAN segmentation (192.168.1.0/24) with pfSense firewall, Splunk SIEM, and attack/target endpoints.</em>
</p>

### Lab Inventory
| Role | Hostname | OS | IP Address |
| :--- | :--- | :--- | :--- |
| **Firewall** | pfSense | FreeBSD | `192.168.1.1` (LAN) |
| **SIEM** | Splunk | Ubuntu | `192.168.1.20` |
| **Identity** | ADDC01 | Windows Server 2022 | `192.168.1.10` |
| **IDS/NSM** | Zeek-Suricata | Ubuntu | `192.168.1.30` |
| **Target** | Windows-10 | Windows 10 Ent | `192.168.1.100` |
| **Attacker** | Kali | Kali Linux | `192.168.1.250` |

![Lab Overview](images/1-lab-overview.png)

---

## Phase 1: Infrastructure and Segmentation

### 1. Perimeter Firewall Configuration
Deployed **pfSense** as the network gateway, configuring firewall rules and interfaces to separate the lab environment from the home network while allowing log forwarding traffic on port 9997.
![pfSense Config](images/2-pfsense-config.png)
![pfSense Web Interface](images/3-pfsense-web.png)

### 2. Active Directory and Endpoint Management
Promoted a Windows Server 2022 to a Domain Controller (`MYDFIR.local`) and used **Active Directory Users and Computers** to create Organizational Units (IT, Sales) and simulated user accounts. Joined a Windows 10 workstation to the domain to enforce centralized Group Policies.
![AD Users](images/3-ad-users.png)
![Domain Join](images/4-domain-join.png)

---

## Phase 2: Visibility and Logging Configuration

### 1. Endpoint Visibility (GPO and Sysmon)
Default Windows logging often misses critical context. Configured a Group Policy Object (GPO) to enable **Advanced Audit Policies** (Process Creation, Logon Events) and deployed **Sysmon** (using the Olaf Hartong configuration) to capture command-line arguments and parent process IDs.
![GPO Config](images/5-gpo-audit.png)

### 2. Network Security Monitoring
Deployed a Linux-based sensor running **Zeek** and **Suricata** to capture network artifacts. Configured the Splunk Universal Forwarder to ingest specific transaction logs:
* **Zeek:** Monitors `conn.log` (connections), `dns.log` (DNS queries), and `http.log` (web traffic).
* **Suricata:** Captures IDS alerts written to `/var/log/suricata/eve.json`.

![Zeek Configuration](images/7-linux-inputs.png)

### 3. Log Ingestion Pipeline
Manually configured `inputs.conf` across Windows, Linux, and FreeBSD endpoints to ensure data was correctly parsed and routed to the `mydfir-detect` index.

| Windows Input Config | Firewall Input Config |
| :---: | :---: |
| ![Windows Config](images/6-windows-inputs.png) | ![Firewall Config](images/8-pfsense-inputs.png) |

### 4. Data Ingestion Validation
Verified that Splunk was successfully ingesting logs from all four distinct data sources: Windows Endpoint, Active Directory, Network Sensors, and the Firewall.
![Splunk Data Flow](images/9-splunk-data-flow.png)

---

## Phase 3: Adversary Emulation

### Scenario 1: Network Service Discovery (T1046)
**Attack:** Used `nmap` from the Kali machine to scan the Domain Controller for open ports and services, simulating a reconnaissance phase.
![Nmap Scan](images/10-nmap-attack.png)

**Detection:** Queried the `sourcetype="pfsense"` logs in Splunk and identified a massive spike in firewall "block" events originating from the attacker's IP (`192.168.1.250`).
![Nmap Detection](images/11-nmap-detect.png)

### Scenario 2: Command and Control via PowerShell (T1059.001)
**Attack:** Generated a malicious payload (`invoices.docx.exe`) using **MSFVenom**. The payload was executed on the victim endpoint, establishing a reverse TCP connection (Meterpreter session) back to the C2 server.
![Malware Execution](images/12-malware-exec.png)
![C2 Session](images/13-c2-session.png)

**Detection:** The **Suricata** IDS detected the anomalous traffic pattern and forwarded an alert to Splunk, flagging the potential C2 activity.
![C2 Detection](images/14-c2-detect.png)

### Scenario 3: Local Account Creation (T1136.001)
**Attack:** Using the **Atomic Red Team** framework, executed a script to programmatically create a local admin account ("NewLocalUser") on the target machine, simulating an adversary attempting to establish persistence.
![Atomic Attack](images/15-atomic-attack.png)

**Detection:** Searched Splunk for **Event ID 4720** (User Account Created). The log detail revealed the exact time of creation and the user account responsible, confirming the persistence attempt.
![Atomic Detection](images/16-atomic-detect.png)

---

## Lessons Learned
* **Log Parsing:** Raw logs from pfSense and Zeek required specific source type configurations (`sourcetype=pfsense`, `sourcetype=bro:json`) to be properly indexed and searchable in Splunk.
* **FreeBSD Compatibility:** Identified that the standard Linux Splunk Forwarder is incompatible with the FreeBSD kernel in pfSense 2.7. Resolved this by troubleshooting kernel compatibility and downgrading to pfSense 2.6 to ensure stable log forwarding.
* **The Power of Sysmon:** Without Sysmon Event ID 1 (Process Creation), investigating the `invoices.docx.exe` malware would have lacked critical context like the parent process ID and command line arguments.
