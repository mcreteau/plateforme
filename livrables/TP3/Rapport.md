## A1 — Exploitation du rapport SILEX-7

### IoC

| Type | Valeur |
|---|---|
| SHA-256 LoaderX | `4a40e42c6e880884906a6629e9077950d0c76c31566c351b0ebe4ef177ef94b6` |
| SHA-256 document Word piégé | `e2fa6d7d5f7fb9cdf6da75e743e46335b017cf0ca925ee70a723170222738df4` |
| SHA-256 rclone renommé | `ce4e403d6a434c66be9a9768ddfeaed916d25f01fd5d80f96358c76d811b9270` |
| Domaine de téléchargement | `silex-update.example` |
| Domaine C2/exfiltration | `cdn-metrics-sync.example` |
| IP C2/exfiltration | `203.0.113.77` |
| IP relais RDP | `198.51.100.23` |

### Artefacts caractéristiques

- **Mutex :** `Global\SilexMutex_7A2F`
- **User-Agent :** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) SLX7/2.3`
- **Clé de persistance :** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SvcHostUpdater`
- **Chemin PDB :** `C:\dev\loaderx\Release\ldx.pdb`
- **Chaîne UTF-16 :** `SilexStage2Payload`
- **Version :** `LoaderX v2.3 build 0417`

### Commandes observées

```text
powershell.exe -nop -w hidden -enc <base64>
```

```text
wmic /node:<hôte> process call create
```

```text
vssadmin.exe delete shadows /all /quiet
```

```text
wbadmin delete catalog -quiet
```

Le binaire `rclone.exe` est renommé en :

```text
svchost64.exe
```

### TTP et techniques ATT&CK

| Identifiant | Technique | Élément observé |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Archive ZIP contenant un document Word ou `.lnk` |
| T1204.002 | User Execution: Malicious File | Ouverture du fichier malveillant par l’utilisateur |
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell encodé lancé depuis Office |
| T1047 | Windows Management Instrumentation | Exécution distante avec `wmic` |
| T1021.001 | Remote Services: Remote Desktop Protocol | Mouvement latéral par RDP |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Synchronisation par rclone vers un stockage objet |
| T1490 | Inhibit System Recovery | Suppression des clichés VSS et du catalogue Windows |
| T1486 | Data Encrypted for Impact | Déploiement d’une charge de chiffrement |

### Pyramide de la douleur

#### Indicateurs jetables

- Les **hashes** : très précis, mais facilement modifiés après recompilation ou modification du fichier.
- Les **adresses IP** : susceptibles de changer ou d’être réattribuées.
- Les **domaines** : peuvent être remplacés rapidement par l’attaquant.
- Le nom `svchost64.exe` : facilement modifiable.

#### Indicateurs intermédiaires

- Le mutex `Global\SilexMutex_7A2F`.
- La clé de registre `SvcHostUpdater`.
- Le User-Agent contenant `SLX7/2.3`.
- Le chemin PDB.
- La chaîne `SilexStage2Payload`.

Ces éléments sont plus coûteux à modifier, mais restent propres à une version ou à une campagne de LoaderX.

#### Indicateurs durables

- **L’outil LoaderX** et son fonctionnement de chargeur de seconde étape.
- Les **TTP** : phishing ciblé, PowerShell encodé, WMI, RDP, exfiltration cloud, suppression des sauvegardes et chiffrement.
- La chaîne d’attaque globale et le ciblage des PME industrielles.

Les TTP sont les indicateurs les plus durables, car ils décrivent le comportement opérationnel de l’attaquant plutôt qu’une valeur technique facilement remplaçable.

## A2 — Règle YARA LoaderX

La règle créée détecte le chargeur LoaderX de SILEX-7 à partir de plusieurs chaînes caractéristiques :

- `LoaderX v2.3 build 0417` ;
- `Global\SilexMutex_7A2F` ;
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SvcHostUpdater` ;
- `SilexStage2Payload`, recherchée au format UTF-16 avec le modificateur `wide`.

La condition `uint16(0) == 0x5A4D` ancre la détection sur l’en-tête `MZ` d’un fichier PE. La règle exige
simultanément au moins trois de ces quatre chaînes afin d’éviter les faux positifs causés par un indicateur isolé.
Les métadonnées indiquent la référence du rapport, l’auteur, la date et le niveau TLP.

```yara
rule silex7_loaderx
{
    meta:
        description = "Detects the SILEX-7 LoaderX PE loader"
        author = "TomCaz"
        date = "2026-11-10"
        reference = "IT320-TR-2026-03 - data/rapport-acteur.txt"
        tlp = "clear"

    strings:
        $version = "LoaderX v2.3 build 0417" ascii
        $mutex = "Global\\SilexMutex_7A2F" ascii
        $run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHostUpdater" ascii
        $stage2 = "SilexStage2Payload" wide

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
```

### Résultats des tests

Les commandes demandées ont été exécutées dans le conteneur Docker :

```console
root@b1cadbb6712e:/work# yara -r rules/yara/myrule.yar data/samples/
silex7_loaderx data/samples//loaderx-sample.bin
root@b1cadbb6712e:/work# yara -r rules/yara/myrule.yar data/corpus-sain/
```

La règle compile correctement et détecte uniquement le fichier attendu dans `data/samples/` :
**TP = 1**.

La commande sur `data/corpus-sain/` ne produit aucune sortie : **FP = 0**.

La règle répond ainsi au critère demandé : elle détecte l’échantillon LoaderX et aucun fichier bénin du corpus.

## A3 — Règle Sigma PowerShell encodé

J’ai choisi la technique **T1059.001 — PowerShell**, observable dans
`data/logs/malveillant/powershell-encode.jsonl`. La règle recherche un processus
`powershell.exe` dont la ligne de commande contient `-enc` et `hidden`, lancé par
une application Microsoft Office.

```yaml
title: SILEX-7 PowerShell encodé lancé depuis Office
id: 7f8a6c2d-2f7d-4c8f-a5e1-1b9d6c3e4a72
status: experimental
description: Détecte l'exécution de PowerShell encodé et masqué depuis une application Office.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: TomCaz
date: 2026-11-10
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_ps:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - '-enc'
      - 'hidden'
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
  condition: selection_ps and selection_parent
falsepositives:
  - Macros d'entreprise légitimes lançant PowerShell encodé
level: high
```

### Test de la règle

La commande de test a été exécutée avec `sigma-test.py` :

```console
root@b1cadbb6712e:/work# sigma-test.py rules/sigma/silex7-t1059.001.yml data/logs/malveillant/powershell-encode.jsonl data/logs/benin/
Règle : SILEX-7 PowerShell encodé lancé depuis Office  (tags : attack.execution, attack.t1059.001)
Fichiers malveillants détectés : 1/1   FN : 0
   OK  powershell-encode.jsonl (1 événements)
Faux positifs sur le corpus bénin : 0 événement(s) dans 0 fichier(s)
VERDICT : acceptable (FP = 0, FN = 0, TP > 0)
```

La règle obtient donc **TP = 1**, **FN = 0** et **FP = 0**.

### Conversion vers des backends

Conversion Lucene pour Elasticsearch/OpenSearch avec `ecs_windows` :

```text
Parsing Sigma rules  [####################################]  100%
(process.executable.caseless:*\\powershell.exe AND (process.command_line:*\-enc* AND process.command_line:*hidden*)) AND (process.parent.executable.caseless:(*\\WINWORD.EXE OR *\\EXCEL.EXE OR *\\POWERPNT.EXE OR *\\OUTLOOK.EXE))
```

Conversion Splunk avec `sysmon` :

```text
Parsing Sigma rules  [####################################]  100%
EventID=1 Image="*\\powershell.exe" CommandLine="*-enc*" CommandLine="*hidden*" ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE")
```

Conversion Kusto avec `sysmon` :

```text
Parsing Sigma rules  [####################################]  100%
EventID == 1 and ((Image endswith "\\powershell.exe" and (CommandLine contains "-enc" and CommandLine contains "hidden")) and (ParentImage endswith "\\WINWORD.EXE" or ParentImage endswith "\\EXCEL.EXE" or ParentImage endswith "\\POWERPNT.EXE" or ParentImage endswith "\\OUTLOOK.EXE"))
```

Le pipeline `ecs_windows` convertit les champs Sysmon Windows vers la
normalisation ECS d’Elastic. Ainsi, `Image` devient `process.executable`,
`CommandLine` devient `process.command_line` et `ParentImage` devient
`process.parent.executable`. Il adapte donc les noms de champs à ceux attendus
par Elasticsearch/OpenSearch, sans changer le comportement détecté.

## A4 — Mapping ATT&CK manuel

En me limitant aux techniques proposées dans `prompts/candidats-attack.txt`,
j'identifie les huit techniques suivantes dans le rapport :

| Identifiant | Technique | Élément du rapport |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Archive ZIP contenant un document Word ou un fichier `.lnk` |
| T1204.002 | User Execution: Malicious File | Ouverture du fichier malveillant par l'utilisateur |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Macro Office lançant PowerShell avec `-enc` |
| T1047 | Windows Management Instrumentation | Commande `wmic /node:<hôte> process call create` |
| T1021.001 | Remote Services: Remote Desktop Protocol | Connexions RDP pour le mouvement latéral |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Synchronisation par rclone vers un stockage objet |
| T1490 | Inhibit System Recovery | Suppression des clichés VSS et du catalogue Windows |
| T1486 | Data Encrypted for Impact | Déploiement d'une charge de chiffrement |

Cette liste correspond exactement à l'annexe du rapport :

```text
T1566.001 · T1204.002 · T1059.001 · T1047 · T1021.001 · T1567.002 · T1490 · T1486
```

Le mapping manuel contient donc **8 techniques correctes sur 8**. Par rapport
à l'annexe de l'éditeur, la précision est de **8/8 = 100 %** et le rappel de
**8/8 = 100 %**. Aucune technique n'est inventée, manquée ou hors de la liste
fermée.

### Questions : que faudrait-il ajouter ou retirer ?

Pour rester strictement conforme au mapping de l'éditeur, je ne retirerais
aucune technique et je n'en ajouterais aucune : les huit techniques de
l'annexe sont toutes justifiées par le rapport.

Pour une cartographie comportementale plus détaillée, on pourrait toutefois
ajouter :

- **T1547.001**, pour la persistance par clé `Run` ;
- **T1105**, pour le téléchargement de LoaderX ;
- **T1027**, pour la charge de seconde étape chiffrée et la commande PowerShell
  encodée ;
- éventuellement **T1071.001**, pour les requêtes HTTP de LoaderX.

Ces ajouts sont défendables, mais ils ne figurent pas dans l'annexe de
l'éditeur. **T1003.001** ne devrait pas être ajouté automatiquement : le
rapport mentionne le vol d'identifiants en mémoire, mais ne décrit pas
explicitement l'accès à la mémoire de LSASS. Il s'agit donc d'une inférence
moins solide que les huit techniques retenues.

## B1 — Génération avec n8n et Ollama

Le workflow `n8n/workflows/rapport-vers-regles.json` a été importé puis
exécuté avec succès. Les trois sorties ont été générées dans le dossier
`out/ia/` :

- [silex-7-ia.yar](out/ia/silex-7-ia.yar) ;
- [silex-7-ia.yml](out/ia/silex-7-ia.yml) ;
- [attack-ia.json](out/ia/attack-ia.json).

Le journal [generations.jsonl](out/ia/generations.jsonl) indique que le modèle
utilisé est **qwen2.5:7b-instruct**. Les temps de réponse sont de 7,5 secondes
pour YARA, 9,4 secondes pour Sigma et 25,4 secondes pour le mapping ATT&CK.
Le workflow a produit huit techniques ATT&CK et aucune technique hors de la
liste fermée.

### Observations sur la règle YARA générée

La règle contient trois artefacts pertinents : le mutex, le User-Agent complet
et le nom de section `SilexStage2Payload`. Cependant, plusieurs défauts sont
visibles avant le test :

- la condition utilise `($mutex or $user_agent or $section_name)`, donc un seul
  indicateur suffit à déclencher la règle ;
- aucun indicateur n'est déclaré `wide`, alors que `SilexStage2Payload` est
  décrit comme une chaîne UTF-16 dans le rapport ;
- le User-Agent contient le préfixe générique `Mozilla/5.0`, ce qui peut
  augmenter les faux positifs, même si le suffixe `SLX7/2.3` est plus spécifique ;
- les métadonnées sont discutables : la date est `2026-03-18`, le TLP est
  `amber` alors que le rapport indique `TLP:CLEAR`, et la référence est moins
  complète que celle demandée.

La règle compile probablement, mais elle devra être testée sur `data/samples/`
et `data/corpus-sain/`. Elle nécessitera vraisemblablement une correction de
la condition et de la chaîne UTF-16.

### Observations sur la règle Sigma générée

La règle vise la bonne famille de comportement, mais elle est moins fiable que
la règle humaine :

- le champ `CommandLine` est écrit sous forme de bloc YAML contenant `-enc`,
  sans modificateur `contains` ;
- le champ `ParentImage` regroupe `WINWORD.EXE|EXCEL.EXE` dans une valeur
  unique, au lieu de déclarer deux valeurs alternatives ;
- le titre décrit l'accès initial par macro, alors que la détection porte sur
  une création de processus PowerShell ;
- les métadonnées sont incomplètes ou incohérentes, notamment l'absence
  d'auteur explicite, la date `2023-10-01` et le niveau `medium` ;
- le tag `attack.phishing_spearphishing_attachment` n'est pas présenté sous
  la forme ATT&CK standard attendue.

La règle doit donc être testée et probablement corrigée avant d'être utilisée.

### Observations sur le mapping ATT&CK

Le modèle retrouve les huit techniques de l'annexe du rapport, dans le même
ensemble que le mapping manuel. Les identifiants sont tous dans la liste
fermée et `hors_liste` est vide. Le champ `unmapped` contient toutefois une
chaîne vide (`[""]`), ce qui ressemble à un défaut de nettoyage ou de
post-traitement plutôt qu'à une véritable technique non mappée.

En résumé, le LLM fournit rapidement une première version exploitable, mais
la lecture humaine reste indispensable : les règles générées ne doivent pas
être acceptées sans compilation, test sur les corpus et vérification des
métadonnées.

## B2 — Test des règles générées par l'IA

Les règles générées par le workflow ont été testées sans correction préalable.
La règle YARA compile et détecte l'échantillon LoaderX :

```console
root@e06619875d53:/work# yara -r out/ia/silex-7-ia.yar data/samples/
silex7_loaderx data/samples//loaderx-sample.bin
root@e06619875d53:/work# yara -r out/ia/silex-7-ia.yar data/corpus-sain/
```

Le résultat est **TP = 1** sur `data/samples/` et **FP = 0** sur
`data/corpus-sain/`. La règle YARA compile donc sans correction et détecte
uniquement le fichier LoaderX dans les jeux de test.

La règle Sigma compile également, mais elle ne détecte aucun fichier
malveillant lorsqu'elle est testée sur l'ensemble du dossier :

```console
root@e06619875d53:/work# sigma-test.py out/ia/silex-7-ia.yml data/logs/malveillant/ data/logs/benin/
Règle : LoaderX Initial Access via Macro Execution  (tags : attack.t1566.001, attack.phishing_spearphishing_attachment, attack.execution)
Fichiers malveillants détectés : 0/3   FN : 3
   MISS powershell-encode.jsonl (0 événements)
   MISS service-creation.jsonl (0 événements)
   MISS ssh-bruteforce.jsonl (0 événements)
Faux positifs sur le corpus bénin : 0 événement(s) dans 0 fichier(s)
VERDICT : à retravailler — aucun fichier malveillant détecté (TP = 0) ; 3 fichier(s) malveillant(s) non détecté(s) (FN > 0) — passez un seul fichier si la règle ne vise qu'une technique
```

Pour la règle Sigma, le bilan est **TP = 0**, **FP = 0** et **FN = 3**.
L'absence de faux positif ne compense pas l'absence totale de détection :
le verdict est donc **à retravailler**. La règle ne compile pas avec une
erreur de syntaxe, mais sa sélection ne correspond pas au format des événements
Sysmon fournis. Aucune règle corrigée `-ia-corrige` n'a été créée à ce stade,
car la consigne demande d'abord de relever honnêtement le résultat de la
génération IA.

## B3 — Comparaison du mapping ATT&CK IA

Le fichier `out/ia/attack-ia.json` contient huit techniques dans le champ
`techniques`. Elles correspondent toutes aux huit techniques du mapping de
l'éditeur :

| Technique | Présente dans le mapping IA | Correcte par rapport à l'annexe |
|---|---:|---:|
| T1566.001 | Oui | Oui |
| T1204.002 | Oui | Oui |
| T1059.001 | Oui | Oui |
| T1047 | Oui | Oui |
| T1021.001 | Oui | Oui |
| T1567.002 | Oui | Oui |
| T1490 | Oui | Oui |
| T1486 | Oui | Oui |

Le champ `hors_liste` est vide : aucun identifiant produit par le modèle ne
se trouve en dehors de la liste fermée. Le champ `unmapped` contient
`[""]`, c'est-à-dire une chaîne vide. Ce n'est pas une technique manquée ou
inventée, mais un défaut de nettoyage de la sortie JSON.

Le LLM n'a donc produit aucune technique inventée, aucune technique manquée
et aucune confusion entre deux techniques voisines. Il n'a notamment pas
ajouté `T1003.001`, qui aurait été une inférence insuffisamment étayée à partir
de la mention du vol d'identifiants en mémoire. Les identifiants sont donc
corrects, même si l'évidence associée à `T1021.001` est imparfaite : le modèle
cite surtout le vol d'identifiants, alors que le rapport justifie cette
technique par les connexions RDP.

### Précision et rappel

Pour le mapping humain, les huit techniques sélectionnées sont exactement
celles de l'annexe :

- précision : **8 techniques correctes / 8 proposées = 100 %** ;
- rappel : **8 techniques correctes / 8 attendues = 100 %**.

Pour le mapping du LLM :

- précision : **8 techniques correctes / 8 proposées = 100 %** ;
- rappel : **8 techniques correctes / 8 attendues = 100 %**.

Le mapping IA atteint donc les mêmes scores que le mapping humain sur ce
rapport. La différence se situe dans la qualité de certaines justifications
et dans la valeur parasite `[""]` du champ `unmapped`, pas dans les
identifiants retenus.
