# DFIR Case Study — Phishing Intrusion & Data Exfiltration on WKSTN01

> Academic incident-response and digital-forensics project — TEK-UP University, *Art de Protection des Secrets* module.
> A full **build → attack → investigate** exercise: we built our own lab, executed a real attack chain in an isolated
> environment, preserved the evidence ourselves, then investigated it as if the case had just landed on our desk.

![Platform](https://img.shields.io/badge/platform-Windows%2010-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.14.6-red)
![Forensics](https://img.shields.io/badge/forensics-Volatility%203%20%7C%20Autopsy-purple)
![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-5%20techniques-orange)
![Report](https://img.shields.io/badge/report-PDF%2018%20pages-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**Analyst A (host / endpoint / SIEM):** Oussama Hamada  
**Analyst B (network / malware):** Amir Ghdiri

---

## Table of Contents

1. [Scenario](#scenario)
2. [Lab Environment](#lab-environment)
3. [Attack Chain](#attack-chain)
4. [Key Findings](#key-findings)
5. [Investigation Methodology](#investigation-methodology)
6. [Tools Used](#tools-used)
7. [Repository Structure](#repository-structure)
8. [Methodological Transparency](#methodological-transparency)
9. [Author](#author)

---

## Scenario

On **2026-10-07 (~15:01 UTC)**, a single Windows 10 workstation (`WKSTN01`) was compromised in a simulated
spear-phishing attack. The attacker delivered a malicious executable disguised as an invoice, established a
Meterpreter C2 channel, planted a persistence mechanism, attempted credential theft, and exfiltrated a
simulated customer data file — all within a 30-minute window.

The investigation was conducted "blind": analysts worked from preserved evidence only, without referring to the
known attack scenario, and verdicts were drawn strictly from artifacts.

> **Note on raw evidence:** This repository contains documentation only — reports, runbooks, IOCs, and detection
> rules. The raw forensic evidence (memory dump, disk image, PCAP, malware binary) is **not published**: hosting
> live malware is prohibited and the images are too large for GitHub. All findings are reproducible from the
> documented methodology.

---

## Lab Environment

Isolated host-only network — `192.168.100.0/24`, no internet access for WKSTN01.

| Host | IP | Role |
|------|-----|------|
| `WKSTN01` | `.40` | Victim — Windows 10 Pro, Sysmon (SwiftOnSecurity) + Wazuh agent |
| `kali` | `.30` | Attacker — Metasploit / msfvenom |
| `rhel-wazuh` | `.10` | SIEM — Wazuh 4.14.6 (Docker stack) |
| `ANALYST01` | `.50` | Analyst workstation — SIFT Workstation |

The lab was built from scratch: VM creation, OS hardening, Sysmon deployment, Wazuh enrollment, and baseline
snapshotting are all documented in the runbooks.

---

## Attack Chain

```
T1566.001           T1204.002          T1547.001            T1003.001          T1041
Phishing        →   Execution      →   Persistence      →   Credential     →   Exfiltration
invoice_october     Start-Process      HKCU\Run key         Access (kiwi)      customers.csv
.exe delivered      (PowerShell)       WindowsUpdate=        lsass / SAM        via curl POST
via HTTP            15:01:32 UTC       sysupdate.exe                            to :8000
```

**Attack window:** `2026-10-07 ~15:01 → 15:30 UTC`  
**Payload SHA-256:** `5EB50394034D6A28DBAAF84CAF6C9D9A96A9FB2B23D3A00CCF246E9D5EE864A2`  
**C2:** `192.168.100.30:4444` TCP (Meterpreter reverse_tcp)  
**Exfil endpoint:** `http://192.168.100.30:8000/exfil/customers` — 133 bytes received

---

## Key Findings

| # | Hypothesis | Verdict | Primary Artifact |
|---|-----------|---------|-----------------|
| H1 | User execution of malicious file | **Confirmed** | Sysmon Event 1 + Prefetch `INVOICE_OCTOBER.EXE-45D1FC4B.pf` |
| H2 | Run-key persistence (HKCU) | **Confirmed (written) — not armed on final disk state** | Sysmon Event 13 @15:05:09 + hivexsh divergence |
| H3 | Credential theft via LSASS | **Inconclusive** | Zero Sysmon Event 10; memory image predates attack window |
| H4 | Non-standard C2 port (4444/TCP) | **Confirmed** | Sysmon Event 3 @15:01:30 + 15:21:21 UTC |
| H5 | Exfiltration from user profile | **Confirmed** | MFT + Security Event 4688 + server-side receipt log |

**3 confirmed · 1 partial (write confirmed, arming not) · 1 inconclusive**

The inconclusive result on H3 is documented honestly: zero Sysmon Event 10 records across 13,115 events is
statistically unusual, but the memory snapshot predates the attack window — absence of evidence is not evidence
of absence.

---

## Investigation Methodology

Each finding follows a **trace → tool → verdict** chain. No conclusion was stated without a named artifact and a
tool output to back it.

| Artifact | Tool | What it proved |
|----------|------|---------------|
| Memory (`.vmem`) | **Volatility 3** | Process list, network connections, code injection |
| Disk (`.vmdk`) | **qemu-nbd + ntfs-3g** (read-only mount) | Dropped files, MFT timestamps, Prefetch |
| Registry (`NTUSER.DAT`) | **hivexsh** | Run key contents — divergence from Sysmon log documented |
| Windows logs (`.evtx`) | **evtx_dump.py** | Logons (4624/4625), process creation (4688), Sysmon 1/3/10/11/13 |
| Network (`.pcap`) | **Wireshark** | Payload delivery, C2 channel, exfiltration POST |
| Malware triage | **strings + YARA + VirusTotal** | Meterpreter stager classification |
| Chain of custody | **sha256sum** | Integrity at every preservation step |

---

## Tools Used

| Category | Tools |
|----------|-------|
| Memory forensics | Volatility 3 |
| Disk forensics | Autopsy, qemu-nbd, ntfs-3g, The Sleuth Kit |
| Log analysis | evtx_dump.py, Wazuh 4.14.6 |
| Network analysis | Wireshark, tcpdump |
| Registry analysis | hivexsh |
| Malware triage | strings, YARA, VirusTotal |
| Attack simulation | Metasploit Framework, msfvenom |
| Monitoring | Sysmon (SwiftOnSecurity config), Wazuh agent |

---

## Repository Structure

```
.
├── report/                 Final forensic report (PDF, 18 pages)
├── runbooks/               Week-by-week execution runbooks
│   ├── semaine-0.md        Build lab + execute attack + freeze evidence
│   ├── semaine-1.md        Memory and disk analysis (Volatility, Autopsy)
│   └── semaine-2.md        Log analysis + hypothesis verdicts
├── analysis/               Analyst A investigation documents
│   ├── rapport-hote-s2.md  Host-side findings (week 2)
│   ├── hypotheses-endpoint.md  Hypothesis table with verdicts + artifacts
│   ├── arbre-processus.md  Process tree reconstruction
│   ├── rapport-s4.md       Full timeline and synthesis (week 4)
│   └── rapport-s5-endpoint-A.md  Remediation and lessons learned (week 5)
├── evidence-docs/          Evidence package description (no raw files)
│   └── README-evidence.md  Chain of custody + acquisition notes
├── iocs/
│   └── iocs-consolidated.csv  All indicators of compromise
├── detection/              Custom YARA rule for the Meterpreter stager
├── architecture/           Lab setup and project planning (interactive HTML)
│   ├── Projet 4 — Architecture allégée.html
│   └── Projet 4 — Plan DFIR allégé (6 semaines).html
└── screenshots/            Investigation screenshots
```

---

## Methodological Transparency

Two issues discovered during the investigation are documented openly rather than swept under the rug:

**Memory snapshot timing:** The `.vmem` file in the evidence vault comes from a VM suspend on 2026-10-10 (three
days after the attack), not 2026-10-07. The attack-window memory state was overwritten. This is why H3
(credential theft) could not be confirmed from memory — and why we say *inconclusive* rather than *confirmed*
or *denied*.

**Registry divergence on H2:** Sysmon Event 13 proves the Run key was written to disk at 15:05:09 UTC.
`hivexsh` on the mounted `NTUSER.DAT` shows only OneDrive in the Run key, and `sysupdate.exe` is absent from
the filesystem. Both facts are true simultaneously: the hive was not flushed before the subsequent VM session
overwrote it. The Sysmon log is the authoritative source for what happened; the disk state reflects what
survived.

These aren't failures of the investigation — they're failures of the evidence collection process, documented
honestly so a reviewer knows exactly what the conclusions rest on.

---

## Contributors

| | Name | Role | Links |
|-|------|------|-------|
| <img src="https://github.com/oussema-007.png" width="40" style="border-radius:50%"> | **Oussama Hamada** | Analyst A — host / endpoint / SIEM | [GitHub](https://github.com/oussema-007) · [LinkedIn](https://www.linkedin.com/in/oussama-hamada-034b32229/) |
| | **Amir Ghdiri** | Analyst B — network / malware | — |

*TEK-UP University (Tunisia) — 6-week academic exercise. Analysis documents and the forensic report are written in French.*
