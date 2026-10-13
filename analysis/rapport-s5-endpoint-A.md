# Projet 4 — Semaine 5 : confinement, éradication, reprise, prévention (côté A — endpoint)

**Analyste A (Oussama Hamada — hôte/endpoint).** Complète la partie réseau
d'Amir (`Rapport_incident…` §5). Le tableau contrôles → ATT&CK en §5 est le
livrable **joint** (A + B).

> La partie réseau (blocage IP Kali, ports 4444/8000/8080, DLP, HTTPS) est
> traitée par B et n'est pas répétée ici ; seuls les volets **endpoint**
> sont développés ci-dessous, puis fusionnés dans le rapport final S6.

---

## 1. Confinement (endpoint)

| Action | Détail | Justification (preuve) |
|---|---|---|
| Isoler WKSTN01 | Couper l'interface réseau / isolation VLAN | Canal C2 actif sur :4444 (Sysmon 3 + PCAP ~21 min) |
| Geler l'état | Dump mémoire + image disque **avant** tout nettoyage | Déjà fait en S0 — mais noter l'anomalie `.vmem` (coffre = 10-10) |
| Traiter le compte local `WKSTN01` comme compromis | Désactiver la session, forcer déconnexion | T1003.001 **non écartée** (voir `rapport-s4.md` §4) — prudence |
| Neutraliser l'auto-start | Vérifier/retirer `Run\WindowsUpdate` avant remise en route | Sysmon 13 prouve l'écriture, même si non armée sur disque |

## 2. Éradication (endpoint)

| Action | Détail |
|---|---|
| Supprimer le payload | `Downloads\invoice_october.exe` + copie `AppData\Roaming\sysupdate.exe` (SHA256 `5eb50394…`) |
| Supprimer la persistance | Clé `HKCU\…\Run\WindowsUpdate` |
| Recherche d'artefacts résiduels | Scan AV à jour + règles YARA publiques Meterpreter sur tout le profil utilisateur |
| Vérifier l'absence de latéral | Confirmer qu'aucune autre IP que `192.168.100.30` n'a été contactée pendant la fenêtre (cohérent H5, pas de DC01) |

## 3. Reprise (endpoint)

| Action | Détail |
|---|---|
| Reconstruction complète | **Réimager** WKSTN01 depuis une image propre — pas de nettoyage partiel (accès élevé obtenu) |
| Rotation des identifiants | Réinitialiser le mot de passe du compte local WKSTN01 et de tout compte utilisé sur ce poste |
| Remise en service progressive | Rebrancher uniquement après validation des préventions §4 et contrôle d'intégrité |

## 4. Prévention (endpoint)

| Mesure | Technique bloquée/détectée |
|---|---|
| Sensibilisation phishing (exécutables déguisés en factures) | T1566.001 / T1204.002 |
| Restriction d'exécution (AppLocker / WDAC) : interdire les binaires non signés depuis `Downloads` et `AppData` | T1204.002 / T1547.001 |
| Règles Wazuh/Sysmon sur les IOCs : connexion :4444, écriture clé `Run`, accès `lsass.exe` | T1071 / T1547.001 / T1003.001 |
| Durcissement LSASS : **RunAsPPL** + **Credential Guard** | T1003.001 |
| Préserver systématiquement `sysmonconfig-export.xml` dans le coffre | (leçon S2 : rend l'absence d'event interprétable) |
| Capturer le `.vmem` **avant** tout cycle resume/suspend | (leçon S2 : évite l'anomalie mémoire du 10-10) |

---

## 5. Tableau joint — contrôles → ATT&CK (livrable BOTH)

Pour chaque technique de la chaîne S4, au moins un contrôle qui l'aurait
**bloquée (B)** ou **détectée (D)**. E = endpoint (A), N = réseau (B).

| Technique | Contrôle préventif / détectif | B/D | Côté |
|---|---|---|---|
| T1566.001 Phishing | Sensibilisation + filtrage des exécutables entrants ; proxy bloquant `application/x-msdos-program` | B | E+N |
| T1204.002 Exécution | AppLocker/WDAC (pas de binaire non signé depuis `Downloads`/`AppData`) | B | E |
| T1204.002 Exécution | Sysmon 1 + 4688 (command-line logging) → règle Wazuh | D | E |
| T1547.001 Persistance | Surveillance écriture clés `Run` (Sysmon 13) → alerte Wazuh | D | E |
| T1547.001 Persistance | AppLocker interdit l'exécution depuis `AppData\Roaming` | B | E |
| T1003.001 Credentials | RunAsPPL + Credential Guard | B | E |
| T1003.001 Credentials | Sysmon 10 sur `lsass.exe` (config préservée et vérifiée) | D | E |
| T1041 Exfiltration | DLP / inspection applicative (patterns SSN, e-mail) en sortie | B | N |
| T1041 Exfiltration | Filtrage de sortie (egress) vers ports/IP non approuvés | B | N |
| T1071 / C2 :4444 | Blocage egress des ports non-standard + alerte Wazuh sur :4444 | B+D | N+E |
| T1071 / C2 | Règle Wazuh 100100 (réutilisée de LogSentinel) sur la signature C2 | D | N |

*Prêt à fusionner avec la partie réseau d'Amir dans le rapport final S6.*
