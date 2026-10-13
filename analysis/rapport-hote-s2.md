# Rapport findings hôte — Projet 4 (DFIR), Semaine 2, Analyste A

**Analyste :** Oussama Hamada (A — hôte/endpoint + SIEM).
**Date de l'investigation :** 2026-10-11.
**Fenêtre d'attaque :** 2026-10-07 ~13:14 → 15:30 UTC.
**Cible :** WKSTN01 (Windows 10 Pro, 192.168.100.40, VMnet10).
**Évidence :** `~/dfir-s1/evidence/` sur ANALYST01, vérifiée 40/40 OK au
MANIFEST.sha256.
**Périmètre :** host-only. Les findings réseau/malware côté B (Amir) sont
hors du scope de ce rapport.

---

## 1. Résumé

L'investigation côté hôte confirme une intrusion sur WKSTN01 le 2026-10-07
entre 14:09 et 15:30 UTC. Le vecteur initial est une exécution utilisateur
d'un binaire téléchargé par PowerShell (`invoice_october.exe`), lancé à
15:01:32 sous un contexte élevé (`IntegrityLevel High`). Le processus
établit un canal réseau vers `192.168.100.30:4444` (TCP, port non-standard
— confirmation définitive attendue du PCAP d'Amir en S3), écrit une clé
Run HKCU pointant vers `C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe`
(persistance tentée mais non armée sur l'état disque final), puis exfiltre
un fichier CSV du profil utilisateur via deux `curl POST` vers
`192.168.100.30:8000`. L'accès aux identifiants (hypothèse H3) ne peut
être tranché avec l'instrumentation disponible.

| Hypothèse | Verdict |
|-----------|---------|
| H1 — Exécution manuelle | Confirmée |
| H2 — Persistance Run HKCU | Confirmée (écriture) — non armée |
| H3 — Accès LSASS | Non concluante — canal muet |
| H4 — C2 port non-standard | Confirmée côté hôte — PCAP pendant S3 |
| H5 — Exfiltration profil utilisateur | Confirmée |

**Incident de collecte à signaler :** le fichier mémoire du coffre
(`04-memory/WKSTN01-3f1f74a8.vmem`) provient d'un suspend du 2026-10-10,
pas de la fenêtre d'attaque du 07-10. Les resume+suspend successifs
requis par `semaine-0.md` §10.3 pour l'export des `.evtx` ont écrasé la
mémoire d'origine. Chaîne de custody intègre (hash MANIFEST OK), mais
l'investigation mémoire perd son utilité pour H3. Documenté dans
`semaine-2.md` §1.5 et dans la custody (voir §9 du runbook).

---

## 2. Processus suspect identifié

**Binaire malveillant :** `C:\Users\WKSTN01\Downloads\invoice_october.exe`

| Attribut | Valeur |
|----------|--------|
| PID | 3568 |
| SHA256 | `5EB50394034D6A28DBAAF84CAF6C9D9A96A9FB2B23D3A00CCF246E9D5EE864A2` |
| MD5 | `0B3C1C3CBC0DE6FE01E6CEF2F9D13DE0` |
| IMPHASH | `C2D02FC98F1D75D7B9457468EC75DA0E` |
| Taille | 7 680 octets |
| Horodatage dépôt (Sysmon 11) | 2026-10-07 14:09:48 UTC |
| Horodatage exécution (Sysmon 1 + Prefetch) | 2026-10-07 15:01:32 UTC |
| Parent | `powershell.exe` PID 5668 (session utilisateur `WKSTN01\WKSTN01`) |
| IntegrityLevel | High |
| Ligne de commande | `"C:\Users\WKSTN01\Downloads\invoice_october.exe"` (sans argument) |

**Convergence multi-sources :** Sysmon 1, Security 4688 et Prefetch
concordent sur le PID, le parent et l'horodatage. Hash binaire identique
disque et coffre — intégrité disque confirmée.

**Nuance par rapport au récit S0 §9.2 :** le parent est `powershell.exe`,
pas `explorer.exe`. L'exécution n'est pas un double-clic Explorer mais un
`Start-Process` lancé depuis une session PowerShell — cohérent avec le
script du §9.2 (`Start-Process "$dl\invoice_october.exe"`).

---

## 3. Persistance trouvée

**Clé Run écrite (Sysmon 13 @15:05:09 UTC) :**

```
HKU\S-1-5-21-2904912346-1412300821-689064062-1001
 \SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
 = C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe
```

Écrite par PID 3568 (`invoice_october.exe`). Technique ATT&CK T1547.001.

**Binaire de persistance créé (Sysmon 11 @15:08:33 UTC) :**
`C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe` par le même PID 3568.

**État sur disque final (divergence) :**

- `hivexsh` sur `/mnt/wkstn01/Users/WKSTN01/NTUSER.DAT` → clé Run contient
  uniquement `OneDrive` (pas de `WindowsUpdate`)
- `sudo find /mnt/wkstn01/Users/WKSTN01/ -iname 'sysupdate*'` → vide
- mtime `NTUSER.DAT` = 2026-10-07 12:55:22 (antérieur à l'écriture Sysmon)

**Interprétation.** La persistance a été écrite et le binaire déposé
pendant l'attaque (Sysmon le prouve), mais ni l'un ni l'autre ne subsiste
sur l'état disque final. Deux hypothèses causales plausibles, non
tranchées : hive NTUSER.DAT non flushé avant un suspend ultérieur, ou
profil nettoyé entre les sessions du 10-10. Dans les deux cas,
**persistance tentée et instrumentée, mais non armée** — pas de Sysmon 1
pour `sysupdate.exe` dans la fenêtre observée (le binaire n'a jamais été
exécuté).

---

## 4. Accès aux identifiants

**Verdict :** non concluant.

**Ce qui a été vérifié :**
- Sysmon event 10 (process access) sur `lsass.exe` → **0 occurrences** sur
  13 115 events dans la fenêtre d'attaque
- Capture mémoire du coffre non exploitable (voir §1 — anomalie `.vmem`
  du 10-10). Pas d'analyse `malfind` possible sur l'état mémoire au
  moment de l'attaque.

**Réserve méthodologique.** Le fichier `sysmonconfig-export.xml`
effectivement chargé sur WKSTN01 n'a pas été préservé dans le coffre
(`08-malware/` ne contient que le binaire malveillant). Impossible de
prouver que la config active logguait bien les accès à `lsass.exe`.
L'absence d'event 10 peut donc signifier soit « aucun accès LSASS
suspect », soit « config Sysmon qui ne logguait pas cet événement ».

**Dépendance S3.** Si l'analyse malware d'Amir révèle un payload type
mimikatz embarqué dans `invoice_october.exe`, H3 pourra être rebasculée
vers « confirmée (par analyse malware) » indépendamment de l'instrumentation
Sysmon.

**Précaution pour les projets futurs :** préserver systématiquement le
`sysmonconfig-export.xml` chargé dans `08-malware/` au moment du scellement
S0, en complément du binaire malveillant — sans la config, l'absence
d'event n'est jamais interprétable.

---

## 5. Logs clés — tableau synthétique

| Horodatage UTC | Canal | Event ID | Résumé | Hypothèse |
|-----------------|-------|----------|--------|-----------|
| 2026-10-07 14:09:48 | Sysmon | 11 | Création `Downloads\invoice_october.exe` par `powershell.exe` PID 5668 | H1 (dépôt) |
| 2026-10-07 15:01:30 | Sysmon | 3 | `invoice_october.exe` → `192.168.100.30:4444` TCP | H4 |
| 2026-10-07 15:01:32 | Sysmon | 1 | Exécution `invoice_october.exe` PID 3568, parent `powershell.exe` | H1 (exécution) |
| 2026-10-07 15:01:40 | Prefetch | — | `INVOICE_OCTOBER.EXE-45D1FC4B.pf` | H1 (confirmation) |
| 2026-10-07 15:01:53 | Security | 4688 | Même exécution, même parent | H1 (confirmation) |
| 2026-10-07 15:05:09 | Sysmon | 13 | Écriture `Run\WindowsUpdate = …\sysupdate.exe` par PID 3568 | H2 (écriture) |
| 2026-10-07 15:05:54 | MFT | — | Création `Documents\customers.csv` (133 o) | H5 |
| 2026-10-07 15:05:55 | Security | 4688 | `curl.exe POST customers.csv → :8000` par `cmd.exe` | H5 (exfil #1) |
| 2026-10-07 15:08:33 | Sysmon | 11 | Création `AppData\Roaming\sysupdate.exe` par PID 3568 | H2 (dépôt) |
| 2026-10-07 15:08:54 | attack.log | — | POST reçu côté serveur, 133 o | H5 (reception) |
| 2026-10-07 15:09:53 | Security | 4688 | Second `curl.exe POST` identique | H5 (exfil #2) |
| 2026-10-07 15:21:21 | Sysmon | 3 | Seconde connexion `invoice_october.exe` → `:4444` | H4 (persistance canal) |

**Événements bénins notables :**
- Security 4625 @13:06:40 — un bad password à la console locale
  (LogonType 2, IP 127.0.0.1). Antérieur à l'attaque, probablement une
  frappe ratée par l'utilisateur. Pas lié à l'intrusion.
- Sysmon 1 enfants d'`invoice_october.exe` : `backgroundTaskHost.exe`
  @15:05:46, `SearchProtocolHost.exe` @15:08:47 — effets de bord
  UWP/indexeur consécutifs à la création de fichiers, pas des composants
  de la chaîne malveillante.

**Canal muet documenté.** `Application.evtx` ne contient que des events
`SecurityCenter → SECURITY_PRODUCT_STATE_ON` à 11:05 sur
`Computer=DESKTOP-6268TBA` (hostname pré-rename) — aucun event dans la
fenêtre d'attaque. Canal inexploitable, à mentionner mais pas à inspecter
en profondeur.

---

## 6. Tableau de clôture des hypothèses

Reporté in extenso de `~/dfir-s1/hypotheses-endpoint.md` (fichier
compagnon) :

| # | Hypothèse | Verdict |
|---|-----------|---------|
| H1 | Exécution manuelle par l'utilisateur | **CONFIRMÉE** |
| H2 | Persistance Run HKCU | **CONFIRMÉE (écriture) — persistance non armée** |
| H3 | Accès identifiants LSASS | **NON CONCLUANTE — canal muet, réserve méthodologique** |
| H4 | C2 port non-standard | **CONFIRMÉE côté hôte — validation PCAP pendante (S3)** |
| H5 | Exfiltration profil utilisateur | **CONFIRMÉE** |

---

## 7. Écarts assumés au runbook `semaine-2.md`

Documentés ici pour transparence méthodologique :

- **Autopsy GUI non lancé** (prévu §2.3). Exploration directe du montage
  NTFS lecture-seule via `qemu-nbd` + `ntfs-3g` + `hivexsh` + `grep` +
  `find`. Mêmes artefacts couverts (MFT, Prefetch, profil utilisateur,
  ruches registre), plus rapide, pas d'attente d'ingestion. Si validation
  Autopsy exigée pour l'évaluation, prévoir ~2h en S5 ou S6 pour un
  rattrapage.
- **Mémoire non exploitée pour l'attaque** — anomalie `.vmem` du 10-10
  (§1.5 du runbook).
- **Scope S3/S4 effleuré** — identification précise du port C2
  (`:4444`) et de la commande d'exfil complète (`curl.exe POST ...`),
  reconstruction d'une timeline hôte, mention de techniques ATT&CK
  (T1547.001, T1041) : ces éléments sont des sous-produits naturels de
  l'analyse Sysmon/Security côté A, pas des empiètements sur le travail
  d'Amir. Garde-fou : aucune table ATT&CK consolidée dans ce rapport
  (c'est le travail S4), toute conclusion C2 porte la mention « côté
  hôte, à corréler avec le PCAP en S3 ».

---

## 8. Fichiers produits

| Fichier | Chemin sur ANALYST01 |
|---------|------------------------|
| Sorties Volatility | `~/dfir-s1/out/memory/{pslist,pstree,cmdline,netscan,malfind}.txt` |
| Sorties EVTX | `~/dfir-s1/out/evtx/{security,sysmon,powershell,application,system}.xml` |
| Log rehash S1 | `~/dfir-s1/rehash-s1.log` |
| Hypothèses finalisées | `~/dfir-s1/hypotheses-endpoint.md` |
| Rapport (ce fichier) | `~/dfir-s1/out/rapport-hote-s2.md` |
| Arbre de processus | `~/dfir-s1/out/arbre-processus.md` |
