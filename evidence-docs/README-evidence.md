# Dossier de preuves — Projet 4 (DFIR) · WKSTN01

**Cas :** Intrusion par phishing et exfiltration de données (simulation
académique). **Cible :** WKSTN01 (192.168.100.40, Windows 10).
**Attaquant :** Kali (192.168.100.30). **SIEM :** Wazuh (192.168.100.10).
**Fenêtre d'attaque :** 2026-10-07, ~14:00 → 15:30 UTC.
**Équipe :** A = Oussama Hamada (hôte/endpoint + SIEM) · B = Amir Ghdiri
(réseau/malware).

> **Note administrative.** La doc S0 (`semaine-0.md`) cite « Aladine Fadhli »
> comme rôle B par erreur de copier-coller. Le binôme officiel du Projet 4
> est **Amir Ghdiri**. Aladine est coéquipier sur un autre projet
> (LogSentinel). Correction documentée en intake S1, pas dans la custody.

---

## 1. Contenu du coffre (`evidence/`)

| Dossier | Contenu |
|---|---|
| `00-baseline/` | Hashes des outils connus-bons (Sysmon, config, MSI Wazuh) |
| `01-pcap/` | `wk0.pcap` — capture réseau de la fenêtre d'attaque |
| `02-exfil/` | `exfil_20261007T150854Z.bin` — blob exfiltré reçu côté serveur |
| `03-timeline/` | `attack.log` — journal opérateur horodaté UTC |
| `04-memory/` | `WKSTN01-3f1f74a8.vmem` — ⚠️ voir note d'anomalie §4 |
| `05-disk/` | `WKSTN01-*.vmdk` — chaîne de snapshots disque |
| `06-evtx/` | `Security/System/Application/Sysmon/PowerShell.evtx` |
| `07-wazuh/` | `wk0-alerts.json` — alertes SIEM de la fenêtre |
| `08-malware/` | `invoice_october.exe` — payload |
| `MANIFEST.sha256` | Empreinte SHA-256 de chaque fichier |

**Vérification d'intégrité :**
```bash
cd evidence && sha256sum --check MANIFEST.sha256
# Attendu : toutes les lignes OK, 0 FAILED
```

## 2. Empreintes clés (références rapides)

| Fichier | SHA-256 |
|---|---|
| `invoice_october.exe` | `5eb50394034d6a28dbaaf84caf6c9d9a96a9fb2b23d3a00ccf246e9d5ee864a2` |
| `wk0.pcap` | `61a96bae9481853172fc42e83bfec4848a8af84dc53f59bc052e751dea0fe1a7` |
| `exfil_20261007T150854Z.bin` | `5f682e65dadd885e7d9db9d106fdcb9cee6f99d84c303002e96d8ed09b837665` |
| `attack.log` | `45c877b854dbe2ebd351706caeb249f9b7649347af74820b3916da37099c0d1b` |

## 3. Chaîne de custody

| Date/Heure (UTC) | Qui | Action | Depuis → Vers | Intégrité |
|---|---|---|---|---|
| 2026-10-10T15:41:51Z | BOTH | Scellement S0 (MANIFEST + README) | collecte → coffre `rhel-wazuh` | MANIFEST généré |
| *(S1)* | Oussama | Copie S1 pour investigation | `rhel-wazuh:~/dfir-wk0-vault/evidence/` → `ANALYST01:~/dfir-s1/evidence/` | `sha256sum --check` — 0 FAILED |
| *(S1)* | Amir | Réception paquet réseau/malware | coffre → poste B | sous-manifest vérifié |
| **2026-10-11T22:00:00Z** | **A (Oussama)** | **Audit S2 — anomalie de collecte identifiée** | — | **MANIFEST OK (pas d'altération)** |

> **➤ LIGNE A1 À COLLER dans `rhel-wazuh:~/dfir-wk0-vault/evidence/README.md`
> (dernière étape S2, encore `pending`) :** la ligne « 2026-10-11T22:00:00Z »
> ci-dessus + le paragraphe §4 ci-dessous. Détail de l'anomalie :
> analyse du `04-memory/WKSTN01-3f1f74a8.vmem` → ~78 processus Windows
> standards tous horodatés **2026-10-10**, aucune trace du binaire, aucune
> connexion vers `192.168.100.30`. Croisement PCAP (`capinfos`), alertes
> Wazuh (`jq`), `attack.log` et `strings` sur le `.vmem` confirment : le
> fichier mémoire scellé provient d'un suspend du **10-10**, pas de la
> fenêtre d'attaque du **07-10**.

## 4. Note d'anomalie de collecte (`.vmem` 10-10 vs attaque 07-10)

L'audit S2 (2026-10-11) a établi que `04-memory/WKSTN01-3f1f74a8.vmem`,
bien que correctement hashé et scellé en S0, **ne correspond pas** à la
capture mémoire de la fenêtre d'attaque. Les `resume+suspend` successifs de
WKSTN01 entre le 07-10 et le 10-10 (requis par `semaine-0.md` §10.3 pour
l'export des `.evtx`) ont **écrasé la mémoire d'origine** ; le `.vmem`
conservé reflète l'état système au dernier suspend (10-10).

**Il n'y a pas eu d'altération post-scellement — la chaîne de custody reste
intègre, le MANIFEST reste valide.** L'investigation hôte (H1, H2, H4, H5)
a été conduite depuis le **disque** et les **EVTX**, qui couvrent bien la
fenêtre d'attaque. Seule **H3** (accès LSASS) perd son outil principal et
est classée **non concluante** (voir `rapport-s4.md` §4).

**Précaution futurs projets :** capturer le `.vmem` *avant* tout cycle
resume/suspend, ou le promouvoir immédiatement sous un nom horodaté qui
empêche l'écrasement ; et préserver `sysmonconfig-export.xml` dans le coffre.

---

> **Actions lab restantes pour toi (A) :** (1) coller la ligne de custody +
> ce §4 dans le README du coffre sur rhel-wazuh ; (2) à la fin, rejouer
> `sha256sum --check MANIFEST.sha256` → doit rester `0 FAILED` (le README
> n'est pas dans le MANIFEST, c'est normal).
