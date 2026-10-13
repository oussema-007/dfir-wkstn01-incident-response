# DFIR Case Study — Phishing Intrusion & Data Exfiltration on WKSTN01

> Academic incident-response & digital-forensics project (TEK-UP University, *Art de Protection des Secrets* module).
> A full **build → attack → investigate** exercise: we built our own lab, executed a real attack chain in an isolated
> environment, preserved the evidence ourselves, then investigated it as if the case had just landed on our desk.

**Team:** Oussama Hamada (Analyst A — host / endpoint + SIEM) · Amir Ghdiri (Analyst B — network / malware)

---

## ⚠️ Note on evidence
This repository contains **documentation only** — reports, runbooks, IOCs and detection rules.
The raw forensic evidence (memory dump, disk image, PCAP, the malware binary) is **intentionally not published**:
hosting live malware is prohibited, and the images are too large for GitHub. All findings below are reproducible
from the documented methodology.

---

## The scenario

A single Windows 10 workstation (`WKSTN01`) was compromised in a simulated attack on **2026-10-07**. The attacker
delivered a malicious executable disguised as an invoice, opened a Meterpreter command-and-control channel,
attempted persistence, and exfiltrated a (simulated) customer data file.

### Lab environment (isolated host-only network, `192.168.100.0/24`)
| Host | IP | Role |
|------|-----|------|
| `WKSTN01` | .40 | Victim — Windows 10 Pro, Sysmon + Wazuh agent |
| `kali` | .30 | Attacker — Metasploit / msfvenom |
| `rhel-wazuh` | .10 | SIEM — Wazuh 4.14.6 (Docker) |
| `ANALYST01` | .50 | Analyst workstation — SIFT Workstation |

### Attack chain (MITRE ATT&CK)
`T1566.001` Phishing → `T1204.002` Execution → `T1547.001` Persistence → `T1003.001` Credential Access → `T1041` Exfiltration

---

## Key findings

| # | Hypothesis | Verdict |
|---|-----------|---------|
| H1 | User execution of malicious file | ✅ **Confirmed** |
| H2 | Run-key persistence (HKCU) | ✅ **Confirmed (written) — not armed** on final disk state |
| H3 | Credential theft (LSASS) | ❓ **Inconclusive** — no positive evidence, honestly reported |
| H4 | Non-standard C2 port (4444) | ✅ **Confirmed** (host + network) |
| H5 | Exfiltration from user profile | ✅ **Confirmed** (133-byte CSV, proven end-to-end) |

Two methodological points are documented transparently: a memory snapshot that didn't cover the attack window
(overwritten during evidence collection), and a credential-theft step that could not be proven with the preserved
evidence. Conclusions were drawn from the evidence — not copied from the known scenario.

---

## Methodology — "trace → tool → verdict"

| Artifact source | Tool | What it proved |
|-----------------|------|----------------|
| Memory (`.vmem`) | **Volatility 3** | processes, network connections, injection |
| Disk (`.vmdk`) | **qemu-nbd + ntfs-3g** (read-only mount) | dropped files, timestamps, Prefetch |
| Registry (`NTUSER.DAT`) | **hivexsh** | auto-start `Run` key |
| Windows logs (`.evtx`) | **evtx_dump.py** | logons (4624/4625), process creation (4688), Sysmon 1/3/10/11/13 |
| Network (`.pcap`) | **Wireshark** | delivery, C2 channel, exfiltration |
| Malware triage | **strings + YARA + VirusTotal** | Meterpreter stager classification |
| Integrity | **sha256sum** | chain-of-custody at every step |

---

## Repository structure

```
.
├── report/              Final forensic report (PDF, 18 pages)
├── runbooks/            Week-by-week execution runbooks (S0–S2)
├── analysis/            Host findings, hypotheses, process tree, timeline (S4), remediation (S5)
├── evidence-docs/       Evidence package description + SHA-256 manifest (no raw evidence)
├── iocs/                Consolidated indicators of compromise (CSV)
├── detection/           Custom YARA rule for the stager
├── architecture/        Lab architecture & 6-week plan (interactive HTML)
└── screenshots/         Investigation screenshots
```

---

## Author

**Oussama Hamada** — Cybersecurity Engineering student, TEK-UP University (Tunisia)
[GitHub](https://github.com/oussema-007) · [LinkedIn](https://www.linkedin.com/in/oussama-hamada-034b32229/)

*Reports are written in French. This project was completed as a two-person academic exercise.*
