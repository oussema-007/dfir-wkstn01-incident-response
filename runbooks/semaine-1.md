# Projet 4 — Semaine 1 (intake, preuves vers VM analyste, plan d'investigation)

**Scope.** Semaine légère (~3h/personne). On traite le dossier comme s'il
venait d'arriver : on ne réutilise pas la connaissance qu'on a du scénario
qu'on a nous-mêmes construit en S0, on part des preuves. Trois livrables
communs (note d'intake, preuves copiées + re-hashées sur une VM analyste,
chaîne de custody à jour) + deux livrables côté A (liste d'artefacts hôte,
3–5 hypothèses endpoint) + la préparation du paquet/template pour B (Amir)
côté réseau.

**Correction au dossier S0.** `semaine-0.md` attribue le rôle B (attaquant)
à Aladine tout du long (`Team: A=Oussama Hamada, B=Aladine Fadhli` en
Appendix B, et dans le corps du §9). C'est une erreur de copier-coller —
le binôme officiel du Projet 4 est **Amir Ghdiri** (rôle B), Aladine
travaille avec vous sur un autre projet (LogSentinel). La correction du nom
part dans la note d'intake (§5) comme item explicite, pas dans la chaîne
de custody elle-même (qui ne documente que la manipulation des preuves,
pas la composition de l'équipe).

**Équipe.**
- **A (Oussama)** — hôte/endpoint, + SIEM (c'est votre machine)
- **B (Amir Ghdiri)** — réseau/malware

**Réutilisé de S0 (ne pas toucher) :**
- Coffre de preuves `rhel-wazuh:~/dfir-wk0-vault/evidence/` — emplacement
  autoritaire, scellé, `MANIFEST.sha256` vérifié `OK` à la clôture de S0.
  On ne modifie jamais rien dedans ; on copie, on vérifie la copie.
- Copie de travail sur `kali:~/dfir-wk0/evidence/` (dépréciée pour
  l'investigation — gardée comme filet de sécurité seulement)
- Paquet réseau/malware (~11 Mo : `wk0.pcap`, blob exfil, `invoice_october.exe`,
  `attack.log`, README, sous-manifest) déjà transféré à Amir et confirmé
  reçu — rien à refaire côté transfert.

**Nouveau dans cette phase :** une VM Analyste, isolée sur VMnet10 comme
WKSTN01 (pas de NAT une fois les outils installés), IP proposée
`192.168.100.50` — adaptez si vous préférez une autre adresse libre.

**Format.** Identique à `semaine-0.md` : sections numérotées, callouts
`Watch out` inline, chaque section se termine par `Checkpoint` +
`Live run ⬜ pending`. Remplissez les champs `Live run` au fur et à mesure.
Les templates réutilisables (note d'intake, table de custody, hypothèses,
message pour Amir) sont en appendice — copiez-les dans leurs propres
fichiers plutôt que de les laisser dans ce runbook.

> **Watch out — ne relancez pas WKSTN01.** Toutes les preuves ont été
> extraites et scellées en S0. La remarrer (même brièvement) casse le
> postulat « scène figée » sur lequel repose toute l'investigation à venir
> et invaliderait potentiellement les hashes de `clean-baseline-pre-attack`
> si vous touchiez au disque par erreur. Si vous avez besoin d'un détail
> que vous pensiez avoir manqué, c'est un signe qu'il faut l'ajouter à la
> liste des "artefacts à vérifier" (§6), pas de retourner sur la VM.

---

## 0. Prérequis

Confirmez que le coffre S0 est toujours intact avant d'en faire une copie :

```bash
# Sur rhel-wazuh
cd ~/dfir-wk0-vault/evidence
sha256sum --check MANIFEST.sha256 2>&1 | tail -5
# Attendu : toutes les lignes en "OK", aucune en "FAILED"

du -sh .   # taille totale — sert à dimensionner la VM Analyste en §1
```

> **Watch out — si une seule ligne du `--check` n'est pas `OK`,
> arrêtez-vous ici.** Ne copiez rien avant d'avoir compris pourquoi (bit
> rot du disque hôte, fichier tronqué lors de la promotion S0→coffre,
> etc.). Un coffre qui échoue sa propre vérification d'intégrité n'est
> plus une preuve fiable — c'est un incident de custody à documenter, pas
> un détail à ignorer.

**Checkpoint :** coffre vérifié intact, taille connue pour dimensionner la
VM Analyste.
**Live run :** ⬜ _pending_ — `MANIFEST.sha256` check : `_____`, taille du
coffre : `_____ Go`.

---

## 1. Monter (ou confirmer) la VM Analyste

Scope volontairement minimal cette semaine : la boîte existe, elle est
isolée, les preuves y tiennent. L'installation des outils d'analyse
(Volatility 3, Autopsy, Autoruns, EvtxECmd, Wireshark, YARA) est différée
à S2/S3, au moment où vous vous en servez réellement — pas de budget pour
ça dans les ~3h de cette semaine.

| Réglage            | Valeur                                         |
|---------------------|------------------------------------------------|
| Nom                | `ANALYST01` (ou autre — adaptez partout si changé) |
| vCPU               | 2                                               |
| RAM                | 4 Go (4096 Mo) — budget prévu dans l'archi      |
| Disque             | 60 Go, thin-provisioned — large pour preuves + outils S2/S3 |
| Réseau adapter 1   | **Custom → VMnet10** (192.168.100.0/24), IP proposée `.50` |
| Réseau adapter 2   | **NAT, temporaire** — nécessaire pour l'installation de l'OS et des paquets en S2/S3. Débranchez-le avant toute analyse réelle une fois les outils installés (voir Watch out ci-dessous). |

> **Watch out — le NAT sur la VM Analyste n'est pas comme celui de Kali.**
> Celui de Kali reste branché en permanence (c'est le poste attaquant, pas
> celui qui manipule les preuves). Sur la VM Analyste, le NAT ne sert qu'à
> installer l'OS/les outils. Une fois que les preuves y sont copiées et
> que vous commencez l'analyse (S2), débranchez l'adaptateur NAT —
> standard en DFIR : le poste d'analyse ne doit pas pouvoir « téléphoner »
> vers l'extérieur une fois qu'il manipule un binaire malveillant ou des
> données potentiellement sensibles (customers.csv contient des faux PII,
> mais le réflexe est le même qu'en vrai).

Choix d'OS — pas tranché, deux options raisonnables :

- **Ubuntu / SIFT Workstation** (recommandé) : script d'installation SIFT
  ajoute Volatility 3, Wireshark, YARA et Autopsy (CLI/Linux build) en une
  commande ; cohérent avec le reste du lab qui est déjà Linux (rhel-wazuh,
  Kali). Autoruns.exe n'existe pas nativement sur Linux, mais Autopsy a
  son propre module d'extraction des clés Run depuis les ruches — ça
  couvre l'exigence prof sans Autoruns à proprement parler.
- **Windows 10/11** : Autopsy GUI natif + Autoruns.exe natif + EvtxECmd
  natif, mais réinstallation manuelle de chaque outil, pas de script
  tout-en-un.

Si vous n'avez pas de préférence, partez sur SIFT — ça réduit le travail
de S2. Créez la VM, installez l'OS, configurez le réseau (même méthode que
WKSTN01 §2a dans `semaine-0.md` : adaptateur nommé explicitement, pas de
`Where-Object Status -eq Up`/équivalent qui attrape plusieurs interfaces).

```bash
# Sur ANALYST01, une fois l'OS installé — fixer l'IP host-only
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.100.50/24 \
    ipv4.method manual
sudo nmcli con up "Wired connection 1"
ping -c2 192.168.100.10   # doit répondre — confirme VMnet10 OK
```

**Checkpoint :** `ANALYST01` installée, IP `.50` jointe sur VMnet10, ping
vers rhel-wazuh OK.
**Live run :** ⬜ _pending_ — OS choisi : `_____`, IP confirmée : `_____`,
disque libre : `_____ Go`.

---

## 2. Copier les preuves du coffre vers la VM Analyste

`rhel-wazuh` impose l'authentification par clé en SSH entrant (vu en S0 —
c'est pour ça qu'on avait dû *pousser* depuis rhel-wazuh plutôt que tirer
depuis Kali). Même logique ici : on pousse depuis rhel-wazuh vers
`ANALYST01`.

```bash
# Sur ANALYST01 — vérifier la place avant de commencer
df -h ~   # doit couvrir au moins 2x la taille du coffre (copie + marge)
```

```bash
# Sur rhel-wazuh
mkdir -p ~/dfir-s1-push
rsync -av --progress ~/dfir-wk0-vault/evidence/ \
    analyst@192.168.100.50:~/dfir-s1/evidence/
# rsync plutôt que scp : reprend proprement si la connexion tombe sur un
# gros fichier (.vmem / .vmdk) — scp recommence le fichier entier depuis 0
```

> **Watch out — gardez l'arborescence identique.** `MANIFEST.sha256`
> contient des chemins relatifs (`./01-pcap/wk0.pcap`, etc.). Si le `rsync`
> change la structure (slash de fin oublié qui copie le *contenu* du
> dossier `evidence/` plutôt que le dossier lui-même, par exemple), la
> vérification du §3 échouera sur un mismatch de chemin et pas de hash —
> ne confondez pas les deux en diagnostiquant.

**Checkpoint :** copie complète sur `ANALYST01`, même arborescence que le
coffre.
**Live run :** ⬜ _pending_ — taille copiée : `_____ Go`, durée du
transfert : `_____`.

---

## 3. Re-hasher sur la VM Analyste + vérifier contre MANIFEST.sha256

```bash
# Sur ANALYST01
cd ~/dfir-s1/evidence
sha256sum --check MANIFEST.sha256 2>&1 | tee ~/dfir-s1/rehash-s1.log | tail -5
grep -c ': OK$' ~/dfir-s1/rehash-s1.log
grep -c 'FAILED' ~/dfir-s1/rehash-s1.log   # doit être 0
```

> **Watch out — un `FAILED` ici ne veut pas forcément dire que la preuve
> est corrompue.** Ça peut être une copie incomplète (réseau coupé en
> plein milieu). Avant de paniquer : comparez la taille du fichier en
> échec entre rhel-wazuh et ANALYST01 (`ls -la` des deux côtés). Si les
> tailles diffèrent, c'est un problème de transfert — relancez juste ce
> fichier avec `rsync`, pas tout le coffre. Si les tailles sont identiques
> mais le hash diffère, là c'est sérieux — documentez-le comme incident de
> custody avant d'aller plus loin.

**Checkpoint :** 100% des fichiers du MANIFEST vérifiés `OK` sur la copie
locale.
**Live run :** ⬜ _pending_ — fichiers vérifiés : `_____`, `FAILED` : `_____`
(doit être 0).

---

## 4. Mettre à jour la chaîne de custody

Ajoutez une ligne à la table de custody existante dans le `README.md` du
coffre (celle écrite à la clôture de S0, §11) — ne créez pas un second
fichier de custody séparé, la chaîne doit rester dans un seul document.

```bash
# Sur rhel-wazuh — éditez la table dans README.md, nouvelle ligne :
```

| Date/Heure (UTC) | Qui    | Action                                   | Depuis → Vers                          | Résultat intégrité |
|-------------------|--------|-------------------------------------------|------------------------------------------|----------------------|
| `____-__-__T__:__Z` | Oussama | Copie S1 pour investigation | `rhel-wazuh:~/dfir-wk0-vault/evidence/` → `ANALYST01:~/dfir-s1/evidence/` | `sha256sum --check` — 0 FAILED |

Committez/sauvegardez le README mis à jour, et re-hashez-le lui-même si le
MANIFEST le couvre (sinon notez-le comme hors-MANIFEST, c'est normal — le
README évolue, les preuves non).

**Checkpoint :** table de custody à jour avec l'événement de copie S1,
horodaté en UTC.
**Live run :** ⬜ _pending_ — ligne ajoutée : ⬜.

---

## 5. Rédiger la note d'intake (1 page)

Remplissez le template de l'Appendix A. Deux pièges à éviter :

> **Watch out — n'écrivez pas la note comme si vous saviez déjà tout.**
> Pédagogiquement, l'exercice S1 simule la réception d'un dossier par un
> analyste qui n'a pas construit le lab. « Ce qu'on sait » doit venir de
> ce que les preuves montrent à l'inspection superficielle (nom de
> fichiers, alertes Wazuh visibles, métadonnées), pas de votre mémoire du
> scénario d'attaque que vous avez vous-mêmes exécuté en S0. Gardez les 5
> techniques ATT&CK et les noms de fichiers malveillants (`sysupdate.exe`,
> etc.) comme hypothèses à confirmer en S2/S3, pas comme faits acquis dans
> l'intake.

> **Watch out — la correction Aladine→Amir va dans l'intake, pas dans la
> custody.** La chaîne de custody documente qui a manipulé les preuves et
> quand (fait, immuable). La composition de l'équipe est une métadonnée de
> projet — elle va dans la note d'intake comme un point de clarification
> administrative, séparé de la timeline des preuves.

**Checkpoint :** note d'intake écrite, ≤ 1 page, correction d'équipe
mentionnée.
**Live run :** ⬜ _pending_.

---

## 6. (A) Lister les artefacts hôte à analyser

Inventaire — pas d'analyse encore, juste la liste de ce que vous
ouvrirez en S2 et pourquoi. Basé sur ce qui est dans le coffre :

**Mémoire** (`WKSTN01-<hex>.vmem`, ~3 Go) :
- Liste de processus (`pslist`/`pstree`) — repérer le processus
  d'exécution initiale et tout enfant suspect
- Connexions réseau en mémoire (`netscan`) — confirmer le canal observé
  côté hôte, à recouper avec le PCAP d'Amir
- `malfind` — détection d'injection, même si la chaîne d'attaque S0 n'en
  utilisait pas explicitement, ça fait partie du passage standard
- Commandes lancées (`cmdline`) — arguments de lancement des processus
  suspects

**Disque** (`.vmdk`, 27 fichiers, chaîne de snapshots) :
- MFT / fichiers créés dans le profil utilisateur (`Downloads`,
  `AppData\Roaming`, `Documents`)
- Prefetch — preuve d'exécution et horodatage
- Ruches de registre (`NTUSER.DAT`, `SOFTWARE`) — clé `Run`, services
- Tout fichier de données créé dans `Documents` pendant la fenêtre
  d'attaque

**Journaux Windows** (5 `.evtx`) :
- `Security.evtx` — 4624/4625 (logons), 4688 (création de processus)
- `System.evtx` — services, démarrage/arrêt
- `Microsoft-Windows-Sysmon%4Operational.evtx` — events 1 (process
  create), 3 (network connect), 10 (process access — intéressant pour
  tout accès à `lsass.exe`), 11 (file create), 13 (registry value set)
- `Microsoft-Windows-PowerShell%4Operational.evtx` — script block logging

**Alertes Wazuh** (export JSON, fenêtre d'attaque) : recoupement SIEM —
sert à corréler les IOCs trouvés manuellement avec ce que la règle Wazuh
a (ou n'a pas) détecté automatiquement.

**Checkpoint :** liste d'artefacts hôte écrite, chaque entrée justifiée
par ce qu'elle doit prouver.
**Live run :** ⬜ _pending_.

---

## 7. (A) Rédiger 3–5 hypothèses endpoint

Formulez-les comme de vraies hypothèses à valider/invalider en S2 — pas
comme des certitudes (voir Watch out §5). Point de départ (voir Appendix C
pour le template complet avec colonnes « comment confirmer / infirmer ») :

1. **Accès initial via exécution d'un fichier par l'utilisateur** — vecteur
   de type exécution manuelle plutôt que vulnérabilité distante
2. **Persistance via une clé Run du registre** (plutôt qu'une tâche
   planifiée ou un service) — HKCU, pas HKLM (pas de droits SYSTEM
   nécessaires pour ce type de clé)
3. **Accès aux identifiants via lecture mémoire de LSASS** — signature
   typique d'un outil type mimikatz plutôt qu'un dump SAM hors-ligne
4. **Canal de commande-et-contrôle persistant sur un port non-standard**
   (pas 80/443) — à confirmer par `netscan` côté mémoire et le PCAP d'Amir
5. **Exfiltration de données depuis le profil utilisateur, pas depuis un
   partage réseau** — cohérent avec un accès initial limité à un seul
   poste, pas de mouvement latéral

**Checkpoint :** 3–5 hypothèses écrites, chacune avec un artefact du §6
qui permettrait de la confirmer ou de l'infirmer.
**Live run :** ⬜ _pending_.

---

## 8. Préparer le point de sync avec B (Amir)

Le paquet réseau/malware est déjà chez Amir (confirmé reçu). Ce qui reste
pour que son côté S1 avance : qu'il produise sa propre liste d'artefacts
réseau + 3–5 hypothèses réseau, miroir des §6–7 côté hôte. Utilisez
l'Appendix D comme message à lui envoyer — il contient le même garde-fou
« hypothèses, pas certitudes » que le Watch out du §5, pour que son
document ait le même niveau de rigueur que le vôtre.

**Checkpoint :** message envoyé à Amir avec le template §D.
**Live run :** ⬜ _pending_ — envoyé le `_____`, réponse attendue avant le
point de sync de fin de semaine.

---

## 9. Livrables + sign-off S1

- [ ] **(BOTH)** Note d'intake (1 page) — §5 / Appendix A
- [ ] **(BOTH)** Preuves copiées sur `ANALYST01` + re-hashées, 0 `FAILED` — §2–3
- [ ] **(BOTH)** Chaîne de custody mise à jour (coffre `README.md`) — §4
- [ ] **(A)** Liste d'artefacts hôte — §6
- [ ] **(A)** 3–5 hypothèses endpoint — §7
- [ ] **(B — Amir)** Liste d'artefacts réseau — en attente
- [ ] **(B — Amir)** 3–5 hypothèses réseau — en attente

Signé par : `A ____________________` `B ____________________` le
`__________`.

---

## Quick Reference

| Chose                        | Valeur                                                |
|-------------------------------|--------------------------------------------------------|
| Coffre (autoritaire)          | `rhel-wazuh:~/dfir-wk0-vault/evidence/`                |
| ANALYST01 IP                  | `192.168.100.50` (proposée, adaptez si changée)        |
| ANALYST01 evidence locale     | `~/dfir-s1/evidence/`                                  |
| Vérif intégrité (coffre)      | `sha256sum --check MANIFEST.sha256`                     |
| Vérif intégrité (copie S1)    | même commande, depuis `~/dfir-s1/evidence/`            |
| Rôle A                        | Oussama Hamada — hôte/endpoint + SIEM                  |
| Rôle B                        | Amir Ghdiri — réseau/malware                           |
| Paquet Amir                   | transféré + reçu (confirmé avant S1)                   |

---

## Appendix A — Note d'intake (template)

```
=== Note d'intake — Projet 4 (DFIR) ===
Date : <date>
Équipe : A = Oussama Hamada (hôte/endpoint), B = Amir Ghdiri (réseau/malware)
Correction administrative : le rôle B dans la doc S0 (semaine-0.md) cite
  Aladine Fadhli par erreur de copier-coller ; le binôme officiel du
  Projet 4 est Amir Ghdiri. Aladine est coéquipier sur un autre projet
  (LogSentinel, infrastructure Wazuh/Kali réutilisée ici).

Contexte :
  <d'où vient le dossier, dans le cadre du scénario académique —
  un seul poste, WKSTN01, signalé par le SIEM>

Ce qu'on sait (depuis l'inspection initiale des preuves, pas depuis la
  construction du lab) :
  - <ex : alertes Wazuh sur agent WKSTN01 dans une fenêtre de ~X minutes>
  - <ex : .vmem, .vmdk, PCAP, .evtx, alertes présents et intègres>

Ce qu'on ne sait pas encore :
  - <vecteur d'accès initial exact>
  - <étendue de la persistance>
  - <données réellement exfiltrées, destination>
  - <si WKSTN01 est le seul poste touché>

Objectifs de l'investigation :
  - Hôte (A) : reconstruire la chaîne d'exécution, identifier la
    persistance, évaluer l'accès aux identifiants
  - Réseau (B) : identifier le C2, confirmer/quantifier l'exfiltration,
    trianguler les IOCs réseau

Hors scope :
  - Mouvement latéral (pas de DC01 dans ce lab)
  - Tout poste autre que WKSTN01

Contraintes :
  - Lab isolé (VMnet10 host-only) — pas de risque production
  - Calendrier académique : 6 semaines du prof, S1 cette semaine
```

---

## Appendix B — Chaîne de custody (table, à ajouter au README du coffre)

```
| Date/Heure (UTC) | Qui | Action | Depuis → Vers | Résultat intégrité |
|-------------------|-----|--------|------------------|----------------------|
| ...               | ... | ...    | ...              | ...                  |
```

Une ligne par mouvement ou accès aux preuves — copie, export, ouverture
en lecture pour analyse (S2+). Ne documentez pas les lectures du
`MANIFEST.sha256` lui-même (vérification, pas manipulation).

---

## Appendix C — Hypothèses endpoint (template, une ligne par hypothèse)

```
| # | Hypothèse | Artefact(s) pour confirmer | Artefact(s) pour infirmer |
|---|-----------|------------------------------|------------------------------|
| 1 | ...       | ...                          | ...                          |
```

---

## Appendix D — Message pour Amir (B)

```
Salut Amir,

On attaque S1 du Projet 4 (intake + preuves vers VM analyste + plan
d'investigation). Le paquet réseau/malware que je t'ai envoyé (wk0.pcap,
blob exfil, invoice_october.exe, attack.log, README, sous-manifest) —
avant d'aller plus loin, confirme-moi juste que le hash du sous-manifest
correspond toujours de ton côté.

Ce qu'il me faut pour fin de semaine, miroir de ce que je fais côté hôte :

1. Liste des artefacts réseau que tu vas analyser en S2/S3 (PCAP, alertes
   Wazuh — pourquoi chacun, qu'est-ce que tu cherches dedans)
2. 3–5 hypothèses réseau — formulées comme hypothèses à confirmer/infirmer
   avec un artefact précis, pas comme des certitudes. Pense C2 (canal,
   port, protocole) et exfiltration (destination, volume, timing).

On se sync 30 min en fin de semaine pour relire les deux plans
ensemble avant de démarrer l'analyse S2.

Oussama
```
