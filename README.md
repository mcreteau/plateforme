ls
<img src="assets/logo-carre.png" alt="Enseirb-Matmeca" width="110" align="right">

# Plateforme IT320 — votre mini-CERT

Dépôt de départ de chaque groupe. Vous l'enrichissez à chaque séance ; à la fin, `docker compose up -d` sur un clone propre doit tout relancer.

## Architecture cible (séance 4)

```
 Sources                     Orchestration            Plateforme            Sorties
 ───────                     ─────────────            ──────────            ───────
 abuse.ch, OTX (flux) ─────────────────────────────▶ MISP ──────▶ blocklist / export STIX
 Cowrie (honeypot) ──▶ tools/cowrie-to-misp.py ────▶ MISP
 RSS CERT-FR ──▶ n8n ──▶ Ollama (extraction JSON) ──▶ validation ──▶ MISP [ia-non-verifie] ──▶ relecture humaine
 Rapport acteur ─▶ n8n ──▶ Ollama (YARA/Sigma/ATT&CK) ─▶ tests auto ──▶ MISP (attributs yara/sigma)
 ransomware.live ▶ n8n ──▶ filtre secteur/membres ──▶ Ollama (résumé) ──▶ validation ──▶ MISP ──▶ alerte membre
 MISP ──▶ connecteur MISP ──▶ OpenCTI (rapports, indicateurs, graphe ATT&CK via connecteur MITRE)
 dnstwist ───────▶ n8n ──▶ nouveautés ──────────────────────────────────▶ MISP
```

## Démarrage

Dans l'ordre, depuis le dossier `plateforme/` :

```
cp .env.example .env
# 1. Générer la clé API MISP AVANT le premier `up` (elle est injectée à l'initialisation de misp-core et lue par n8n) :
python3 -c "import secrets;print(secrets.token_hex(20))"      # -> MISP_API_KEY dans .env
<<<<<<< HEAD
# 2. Compléter le reste de .env : OLLAMA_URL et OLLAMA_AUTH (donnés au tableau), OTX_API_KEY, ABUSECH_AUTH_KEY, mots de passe.
=======
	# 2. Compléter le reste de .env : OLLAMA_URL (donné au tableau), OTX_API_KEY, ABUSECH_AUTH_KEY, mots de passe.
>>>>>>> d6d42ca (blah)
# 3. Créer les dossiers écrits par les conteneurs et les rendre inscriptibles (Cowrie = uid 999, n8n = uid 1000) :
sh tools/init-dirs.sh                 # équivalent : mkdir -p data/cowrie out && chmod -R 777 data/cowrie out
# 4. Lancer :
docker compose up -d
docker compose ps                     # attendre que misp-nginx soit healthy (3 à 5 min la première fois)
```

MISP : https://localhost:8443 (certificat auto-signé ; compte `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD`, mot de passe à changer à la première connexion). La clé API de `.env` est déjà active : inutile d'en créer une dans l'interface. n8n : http://localhost:5678 (créer le compte propriétaire au premier accès). Cowrie : `ssh -p 2222 root@localhost`.

Si vous avez lancé `up` sans clé API : arrêtez (`docker compose down -v`, ce qui efface les volumes MISP), renseignez `MISP_API_KEY`, relancez. Sinon, créez la clé dans MISP (Administration → List Auth Keys → Add), copiez-la dans `.env` et redémarrez n8n (`docker compose up -d n8n`). Plus simple, sans rien effacer : corrigez `MISP_API_KEY` dans `.env` (40 caractères hexadécimaux, vérifiables par `grep -cE '^MISP_API_KEY=[0-9a-f]{40}$' .env`, qui doit afficher `1`), puis `docker compose exec misp-core /var/www/MISP/app/Console/cake user change_authkey admin@admin.test $(grep '^MISP_API_KEY=' .env | cut -d= -f2)` et `docker compose up -d n8n`. Symptôme d'une clé refusée : « Forbidden » dans n8n, `403` sur l'API.

OpenCTI, séance 4 : en 2026, vous n'installez pas OpenCTI. Vous importez vos données dans l'OpenCTI mutualisé, avec le compte de votre groupe. Pour exporter un événement de votre MISP au format attendu, depuis `plateforme/` :

```
docker compose --profile tools run --rm osint-tools misp-vers-opencti.py <id d'événement> <numéro de groupe>
```

Le fichier est écrit dans `out/`, et l'import se fait par *Data* → *Import* (voir `seance4/tp.md`, partie B). L'en-tête du script explique ce qu'il retire et pourquoi.

Votre propre OpenCTI (sur une VM du groupe, ou chez vous avec 16 Go de RAM : facultatif en 2026) : prérequis `sudo sysctl -w vm.max_map_count=262144` (à persister dans `/etc/sysctl.d/99-opensearch.conf`), compléter la section OpenCTI de `.env` (six UUID : `OPENCTI_ADMIN_TOKEN`, `OPENCTI_HEALTHCHECK_ACCESS_KEY`, `CONNECTOR_MITRE_ID`, `CONNECTOR_MISP_ID`, `CONNECTOR_EXPORT_STIX_ID`, `CONNECTOR_IMPORT_STIX_ID`), puis `docker compose -f docker-compose.opencti.yml up -d` ; interface sur http://<vm>:8080 ; premier démarrage 10 à 15 min, puis le connecteur MITRE charge ATT&CK pendant plus d'une heure (mesuré le 1er novembre 2026) : la plateforme est utilisable pendant ce temps, mais les relations arrivent en dernier.

### Outils en ligne de commande (conteneur `osint-tools`)

Le service `osint-tools` est sous le profil `tools` : il ne démarre pas avec `up`. Le dépôt complet est monté dans `/work` (donc `/work/tools`, `/work/rules`, `/work/data`, `/work/out`), qui est aussi le répertoire courant ; les scripts `*.py` sont en plus dans le PATH.

```
docker compose --profile tools build                                   # une fois (télécharge les outils Go)
docker compose --profile tools run --rm osint-tools bash               # shell dans /work
docker compose --profile tools run --rm osint-tools cowrie-to-misp.py
docker compose --profile tools run --rm osint-tools otx-to-misp.py --max 5
docker compose --profile tools run --rm osint-tools yara -r rules/yara/exemple-loaderx.yar data/samples/
docker compose --profile tools run --rm osint-tools sigma-test.py rules/sigma/exemple-powershell-encode.yml data/logs/malveillant/powershell-encode.jsonl data/logs/benin/
docker compose --profile tools run --rm osint-tools sigma convert -t lucene -p ecs_windows rules/sigma/exemple-powershell-encode.yml
docker compose --profile tools run --rm osint-tools theHarvester -d <domaine> -b crtsh
```

Depuis ce conteneur, MISP est joignable à `https://misp-nginx:8443` (variable `MISP_URL`, certificat non vérifié via `MISP_VERIFY_SSL=false`), pas à `localhost:8443`.

## Clés API

| Service | Variable `.env` | Obtention | Nécessaire pour |
|---|---|---|---|
| MISP | `MISP_API_KEY` | générée par vous (40 hex) avant le premier `up` | n8n, scripts `tools/` |
| abuse.ch (URLhaus, Feodo Tracker, MalwareBazaar, ThreatFox) | `ABUSECH_AUTH_KEY` | compte gratuit sur https://auth.abuse.ch | facultatif : flux URLhaus du TP 2 (A2, optionnel) |
| AlienVault OTX | `OTX_API_KEY` | compte gratuit sur https://otx.alienvault.com | `tools/otx-to-misp.py` |
| Shodan (facultatif) | `SHODAN_API_KEY` | compte Shodan | enrichissement bonus |

**Flux MISP du TP 2 (état vérifié le 28 octobre 2026).** Les flux par défaut « CIRCL OSINT Feed » et « The Botvrij.eu Data » (format MISP) fonctionnent sans authentification : ce sont ceux du TP. Côté abuse.ch, qui exige une Auth-Key depuis le 30 juin 2025 : le flux par défaut « URLHaus Malware URLs » de MISP 2.5.50 pointe vers `https://urlhaus.abuse.ch/downloads/csv_recent/`, qui répond `410 Gone` avec ou sans clé ; l'export se télécharge désormais à `https://urlhaus-api.abuse.ch/v2/files/exports/<clé>/recent.csv`, la clé dans le chemin (page https://urlhaus.abuse.ch/api/) : modifier l'URL du flux dans MISP, et ne jamais pousser cette configuration dans le dépôt. « Feodo IP Blocklist » répond encore, mais Feodo Tracker annonce que ses jeux de données sont vides : le fichier ne contient plus que quatre entrées de mars 2026.

## Contenu

```
docker-compose.yml, docker-compose.opencti.yml, .env.example
n8n/workflows/   certfr-ollama-misp.json (séance 2) · rapport-vers-regles.json (séance 3) · ransomware-watch.json (séance 4, à créer)
prompts/         extraction-certfr.md · gen-yara.md · gen-sigma.md · map-attack.md · candidats-attack.txt (liste fermée de techniques ATT&CK)
tools/           Dockerfile · init-dirs.sh · make-data.py · cowrie-to-misp.py · otx-to-misp.py · sigma-test.py · misp_client.py
data/            osint/ (pack hors ligne TP 1) · llm-precalcule/ (sorties LLM de secours TP 2 et 3) ·            certfr/ (alerte-2026-01..03.xml figées + alerte-piegee.xml) · cowrie/cowrie-24h-sample.json (synthétique) ·
                 rapport-acteur.{txt,md} (acteur fictif SILEX-7, outil LoaderX) · samples/ (loaderx-sample.bin inerte + 3 bénins) ·
                 corpus-sain/ (~60 fichiers bénins) · logs/{malveillant,benin}/ · ransomware/recentvictims.json · fuite-simulee.txt · membres.txt
rules/           yara/exemple-loaderx.yar · sigma/exemple-powershell-encode.yml · (vos règles)
notebooks/       msticpy-intro.ipynb
livrables/       vos rendus (TP 1, 2, 3)
out/             sorties des workflows (certfr-*.jsonl, ia/)
```

Toutes les données de `data/` sont générées par `tools/make-data.py` (synthétiques, fictives : IP RFC 5737, domaines `.example`, acteur et outil inventés). L'acteur fil rouge est **SILEX-7** (fictif), décrit dans `data/rapport-acteur.txt` ; son chargeur **LoaderX** est reconstitué, inerte, dans `data/samples/loaderx-sample.bin`. Le corpus sain compte une soixantaine de fichiers (pas 200), dont quelques pièges volontaires (chaînes génériques, en-têtes MZ).

## Dépannage

**misp-core ou misp-nginx n'est jamais `healthy`.** `docker compose logs misp-core | tail -50` (puis `misp-nginx` : sans certificat, il s'arrête sur « SSL certificate is NOT present » ; relancer `docker compose up -d`, qui rejoue `misp-certs`). Causes usuelles : `MISP_API_KEY` vide ou de mauvaise longueur (40 caractères hexadécimaux), mot de passe MariaDB changé après la première initialisation (`docker compose down -v` puis relancer), moins de 4 Go de RAM disponibles. Le premier démarrage peut dépasser 5 minutes sur un poste lent : `start_period` est de 120 s, patientez avant de conclure.

**n8n : `EACCES: permission denied, open '/out/...'`.** Le dossier `out/` n'est pas inscriptible par l'uid 1000 : `sh tools/init-dirs.sh` (ou `chmod -R 777 out`), puis relancer l'exécution. Même cause si Cowrie redémarre en boucle : `chmod -R 777 data/cowrie`.

**n8n : `$env.OLLAMA_URL` vide ou `require is not defined`.** Vérifiez `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` et `NODE_FUNCTION_ALLOW_BUILTIN=*` dans `docker-compose.yml`, et que l'image est bien une 1.x (`n8nio/n8n:1.123.62`, celle de `docker-compose.yml`) : n8n 2.x isole les nœuds Code dans des task runners sans accès au système de fichiers ni aux variables d'environnement par défaut.

**Ollama injoignable.** Testez depuis le poste puis depuis n8n :
```
set -a; . ./.env; set +a      # charge OLLAMA_URL et OLLAMA_AUTH dans le shell
curl -s -H "Authorization: $OLLAMA_AUTH" $OLLAMA_URL/api/tags | head -c 300
docker compose exec n8n sh -c 'wget -qO- --header="Authorization: $OLLAMA_AUTH" $OLLAMA_URL/api/tags' | head -c 300
curl -s -H "Authorization: $OLLAMA_AUTH" $OLLAMA_URL/api/generate -d '{"model":"qwen2.5:7b-instruct","prompt":"Réponds OK","stream":false}'
```
Si le premier marche et pas le deuxième : résolution DNS du conteneur (utilisez l'IP), ou pare-feu de la salle. Une réponse 401 : `OLLAMA_AUTH` manque ou est faux dans `.env` (après correction : `docker compose up -d n8n` pour que n8n relise la variable). Si le modèle n'est pas listé dans `/api/tags`, changez `OLLAMA_MODEL`.

**Flux abuse.ch vide ou en erreur dans MISP.** Auth-Key manquante (voir « Clés API ») ; repli : CIRCL OSINT Feed et Botvrij.eu.

**OpenCTI reste `unhealthy` / `starting`.** Dans l'ordre : (1) `sysctl vm.max_map_count` doit valoir 262144 (sinon OpenSearch s'arrête : `docker compose -f docker-compose.opencti.yml logs opensearch | grep -i max_map_count`) ; (2) `free -h` : OpenSearch a besoin de ses 2 Go (`OPENSEARCH_MEMORY`), la plateforme de 2 Go de plus ; (3) `OPENCTI_HEALTHCHECK_ACCESS_KEY` doit être renseigné (le healthcheck interroge `/health?health_access_key=…`) ; (4) `docker compose -f docker-compose.opencti.yml logs opencti | tail -50`. Le worker utilise l'image dédiée `opencti/worker:<version>` (même version que `opencti/platform`) : un worker qui redémarre en boucle avec une erreur Python indique un mélange de versions.

**Connecteur MISP → OpenCTI sans rapport.** `MISP_BASEURL_FROM_VM` doit être l'adresse du MISP du groupe vue depuis la VM (pas `localhost`), la clé `MISP_API_KEY` identique, et les événements MISP postérieurs à `MISP_IMPORT_FROM_DATE` et portant l'un des tags de `MISP_IMPORT_TAGS` (les événements non publiés sont importés par défaut, mais publiez-les en cas de doute). La période de collecte est `CONNECTOR_DURATION_PERIOD: PT5M`.

## Règles

Aucun secret dans le dépôt (`.env` est ignoré par Git). Aucune donnée personnelle réelle. Tout événement MISP créé par un workflow LLM porte le tag `workflow:ia-non-verifie` jusqu'à relecture. La charte OSINT s'applique.

---

<img src="assets/logo-em.png" alt="Enseirb-Matmeca" width="160">

*César Lizurey · [cesar.lizurey.fr](https://cesar.lizurey.fr) · IT320 OSINT et Cyber Threat Intelligence, ENSEIRB-MATMECA*
