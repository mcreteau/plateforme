# Comparatif humain — IA

## Résultats

| Critère | Humain | LLM (qwen2.5:7b-instruct, prompts fournis) |
|---|---|---|
| YARA : compile sans correction | Oui | Oui |
| YARA : TP sur `samples/` (sur 1 attendu) | 1/1 | 1/1 |
| YARA : FP sur `corpus-sain/` (sur environ 60) | 0 | 0 |
| YARA : position des chaînes dans la pyramide de la douleur | Le mutex, la clé Run, le chemin PDB et les chaînes LoaderX sont des indicateurs relativement spécifiques. Les TTP et l'outil LoaderX sont plus durables que les hash, IP et domaines. | Le mutex, le User-Agent et le nom de section sont pertinents, mais la règle accepte un seul indicateur sur trois. Le préfixe `Mozilla/5.0` est générique et la chaîne UTF-16 n'est pas déclarée `wide`. |
| Sigma : compile · TP · FP · FN | Oui · 1 · 0 · 0 | Oui · 0 · 0 · 3 sur l'ensemble des fichiers malveillants testés |
| Sigma : qualité des métadonnées · pertinence du logsource | Métadonnées complètes, référence ATT&CK, auteur et date cohérents. Logsource `process_creation` / `windows` adapté aux événements Sysmon. | Métadonnées incomplètes ou incohérentes : date `2023-10-01`, niveau `medium`, absence d'auteur explicite et tag ATT&CK non standard. Le logsource est pertinent, mais la sélection ne correspond pas au format des événements et ne détecte rien. |
| Mapping ATT&CK : précision · rappel (réf. annexe) | 100 % · 100 % | 100 % · 100 % |
| Mapping ATT&CK : techniques inventées ou hors liste | Aucune | Aucune. `hors_liste` est vide ; `unmapped` contient seulement une chaîne vide parasite. |
| Temps passé | Environ 1 heure pour les parties A1 à A4 et les tests | Génération exécutée par n8n ; latence de 7,5 s pour YARA, 9,4 s pour Sigma et 25,4 s pour ATT&CK. |

## Analyse

La règle YARA humaine est plus stricte : elle exige trois indicateurs sur
quatre et conserve l'ancrage sur le format PE. Elle obtient les mêmes
résultats de test que la règle IA sur les fichiers fournis, mais elle est
moins exposée aux faux positifs sur des fichiers réels grâce à sa condition
plus discriminante. La règle IA est donc fonctionnelle sur cet échantillon,
mais sa condition `or` est trop permissive.

La règle Sigma humaine détecte correctement l'événement PowerShell encodé
lancé depuis Office. La règle IA compile, mais ne détecte aucun des fichiers
malveillants testés. Ses sélections `CommandLine` et `ParentImage` ne sont
pas écrites avec les modificateurs et les valeurs alternatives adaptés aux
événements Sysmon. Elle nécessite une correction avant toute utilisation.

Le mapping ATT&CK est le point fort du LLM dans cette exécution. Le modèle
retrouve exactement les huit techniques de l'annexe, sans identifiant hors
liste ni technique inventée. Le mapping humain obtient le même score, avec
des justifications plus directement liées aux éléments du rapport. Dans un
workflow réel, le JSON doit aussi être validé afin de supprimer les valeurs
vides comme celle présente dans `unmapped`.

## Conclusion

Le LLM est utile pour produire rapidement une première ébauche de règles et
pour proposer un mapping ATT&CK à partir d'un rapport CTI.  
Il ne doit toutefois pas être considéré comme un analyste autonome.  
Dans un CERT, je lui confierais l'extraction initiale des IoC, des TTP et des
propositions YARA/Sigma, sous supervision humaine.  
Les règles générées devraient être soumises à une validation syntaxique et
fonctionnelle automatique avant toute mise en production.  
La validation devrait compiler YARA et Sigma dans un conteneur isolé.  
Elle devrait exécuter les règles sur un corpus malveillant et un corpus bénin.
Une règle ne serait acceptée que si elle compile, obtient TP > 0, FN = 0 et
FP = 0 sur le périmètre prévu.  
Un nœud n8n `Execute Command` pourrait lancer YARA et `sigma-test.py`.  
Un nœud `IF` transmettrait uniquement les résultats acceptables vers MISP ;
les autres seraient renvoyés pour correction humaine ou nouvelle génération.
