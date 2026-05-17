# SAFE-Shop

SAFE-Shop e una web app per stimare l'affidabilita di un sito e-commerce, dominio o IP pubblico.

L'app analizza indicatori tecnici, reputazionali e di sicurezza, calcola uno score percentuale e mostra un report sintetico pensato per aiutare l'utente a riconoscere possibili siti rischiosi.

> Il progetto ha finalita didattiche e informative. Il risultato e una stima indicativa: non garantisce che un sito sia sicuro e non sostituisce verifiche professionali o il giudizio dell'utente.

## Funzionalita

- Analisi di URL, domini e IP pubblici.
- Normalizzazione automatica dell'input, anche quando manca `https://`.
- Controllo DNS e infrastruttura IP.
- Rilevamento CDN/provider comuni, come Cloudflare, Akamai, CloudFront, Fastly e Google Cloud.
- Controllo blacklist da fonte pubblica esterna.
- Analisi euristica del dominio: TLD rischiosi, parole sospette, sottodomini eccessivi, URL lunghi, IP diretti.
- Verifica HTTPS.
- Stima dell'eta del dominio tramite WHOIS.
- Controllo reputazione VirusTotal per domini e IP.
- Cache MongoDB dei risultati VirusTotal per evitare chiamate API ripetute.
- Storico analisi e statistiche aggregate per hostname.
- Chat AI contestuale con Gemini su Vertex AI, usando credenziali ADC e non API key.
- Domande rapide su attendibilita dei prodotti, reclami pubblici, proprietario del sito e convenienza dell'acquisto.
- Grounding con Google Search per integrare informazioni web pubbliche e aggiornate quando Vertex AI e configurato.
- Interfaccia web responsive con score, dettagli tecnici, statistiche e siti popolari.

## Stack Tecnologico

- Node.js
- TypeScript
- Express
- MongoDB
- Axios
- @google/genai
- dotenv
- whois-json
- HTML, CSS e JavaScript vanilla

## Struttura Del Progetto

```text
SAFE-Shop/
+-- Static/
|   +-- index.html       # Interfaccia web
|   +-- index.css        # Stili frontend
|   +-- index.js         # Logica frontend
|   +-- libreria.js      # Helper per richieste HTTP
+-- server.ts            # Server Express e logica analisi
+-- queryStringParser.ts # Utility del progetto
+-- package.json         # Script e dipendenze
+-- tsconfig.json        # Configurazione TypeScript
+-- .env                 # Variabili d'ambiente locali
+-- README.md
```

## Requisiti

- Node.js 20 o superiore
- npm
- MongoDB locale o remoto, opzionale ma consigliato
- API key VirusTotal, opzionale ma consigliata
- Google Cloud CLI, opzionale: serve solo per usare la spiegazione AI con Gemini/Vertex AI

Senza MongoDB l'app puo comunque rispondere alle analisi, ma non salva storico, statistiche e cache VirusTotal.

Senza VirusTotal l'app funziona comunque, ma il controllo malware/reputazione esterna rimane disattivato.

## Installazione

Installa le dipendenze:

```bash
npm install
```

Configura il file `.env` nella root del progetto:

```env
# Database
dbName="safeshop"
connectionStringLocal="mongodb://127.0.0.1:27017"

# Server
PORT=3000

# VirusTotal
VIRUSTOTAL_API_KEY="inserisci_la_tua_api_key"

# Gemini Vertex AI con ADC, senza API key
GOOGLE_CLOUD_PROJECT="lyrical-edition-496616-s8"
GOOGLE_CLOUD_LOCATION="global"
GOOGLE_GENAI_USE_VERTEXAI="true"
GEMINI_MODEL="gemini-2.5-flash"
GEMINI_TIMEOUT_MS=20000
```

Per usare Gemini non serve Python e non serve una chiave API. Installa Google Cloud CLI, poi fai login ADC:

```bash
gcloud auth application-default login
```

Verifica anche che nel progetto Google Cloud sia attiva la Vertex AI API.

Avvia il server:

```bash
npm start
```

Apri l'app nel browser:

```text
http://localhost:3000
```

## Script Disponibili

```bash
npm start
```

Avvia il server con `tsx server.ts`.

```bash
npm test
```

Esegue il controllo TypeScript con `tsc --noEmit`.

## Variabili D'Ambiente

| Variabile | Default | Descrizione |
| --- | --- | --- |
| `PORT` | `3000` | Porta HTTP del server Express. |
| `dbName` | `safeshop` | Nome database MongoDB. |
| `DB_NAME` | `safeshop` | Alternativa a `dbName`. |
| `connectionStringLocal` | vuota | Stringa di connessione MongoDB locale. |
| `MONGODB_URI` | vuota | Stringa di connessione MongoDB remota, utile per Atlas. |
| `MONGODB_DISABLED` | `false` | Se `true`, disabilita il salvataggio su MongoDB. |
| `URL_CHECK_RETENTION_DAYS` | `30` | Giorni di retention dello storico `url_checks`. |
| `VIRUSTOTAL_API_KEY` | vuota | API key VirusTotal. |
| `VIRUSTOTAL_TIMEOUT_MS` | `8000` | Timeout richiesta VirusTotal in millisecondi. |
| `VIRUSTOTAL_CACHE_DAYS` | `30` | Giorni di validita della cache VirusTotal. |
| `GOOGLE_CLOUD_PROJECT` | vuota | ID progetto Google Cloud usato da Vertex AI. |
| `GOOGLE_CLOUD_LOCATION` | `global` | Location Vertex AI usata da Gemini. |
| `GOOGLE_GENAI_USE_VERTEXAI` | `true` | Indica allo SDK Google Gen AI di usare Vertex AI. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Modello Gemini usato dalla chat AI. |
| `GEMINI_TIMEOUT_MS` | `20000` | Timeout richiesta Gemini in millisecondi. |

Nota: dopo ogni modifica al file `.env` bisogna riavviare il server, perche Node legge le variabili d'ambiente all'avvio.

## Come Funziona L'Analisi

Quando l'utente inserisce un URL, dominio o IP:

1. Il backend normalizza l'input.
2. Verifica che il dominio sia valido o che l'IP sia pubblico.
3. Risolve DNS IPv4, IPv6 e CNAME.
4. Controlla se il dominio e presente nella blacklist caricata all'avvio.
5. Se il dominio non e in blacklist, calcola metriche locali.
6. Recupera eta dominio con WHOIS.
7. Interroga VirusTotal, usando prima la cache MongoDB.
8. Calcola lo score finale.
9. Salva analisi e statistiche su MongoDB.
10. Restituisce il report al frontend.
11. Se richiesto dall'utente, invia i dati del report e la domanda della chat a Gemini su Vertex AI.
12. Gemini puo usare Google Search grounding per cercare informazioni pubbliche aggiornate sul sito, come recensioni, reclami, azienda proprietaria e segnali di rischio.

## Algoritmo Di Punteggio

Lo score base va da 0 a 100 ed e calcolato con pesi:

| Metrica | Peso |
| --- | ---: |
| Dominio | 25% |
| HTTPS | 15% |
| Recensioni/popolarita apparente | 20% |
| Reputazione euristica | 20% |
| Eta dominio | 20% |

Poi vengono applicate regole aggiuntive:

- Se il dominio e in blacklist, lo score diventa `0`.
- Se VirusTotal segnala `malicious > 0`, lo score diventa `0`.
- Se VirusTotal segnala `suspicious > 0`, vengono sottratti 25 punti.
- Se VirusTotal segnala molti motori puliti (`clean > 50`), vengono aggiunti 5 punti.
- Lo score finale viene sempre limitato tra `0` e `100`.

Livelli di rischio:

| Score | Livello |
| --- | --- |
| `70-100` | `LOW` / Affidabile |
| `40-69` | `MEDIUM` / Medio |
| `0-39` | `HIGH` / Rischioso |

## Controllo VirusTotal

SAFE-Shop usa l'endpoint VirusTotal v3:

- `/domains/{hostname}` per domini
- `/ip_addresses/{ip}` per IP

Il risultato viene mostrato nel frontend con:

- numero di rilevamenti malevoli
- numero di rilevamenti sospetti
- numero di motori senza rilevamenti
- stato sintetico della verifica
- data dell'ultima analisi disponibile

Stati possibili:

| Stato | Significato |
| --- | --- |
| `NOT_CONFIGURED` | API key assente. |
| `NOT_FOUND` | VirusTotal non ha dati utili per il dominio/IP. |
| `CLEAN` | Nessun rilevamento malevolo o sospetto. |
| `SUSPICIOUS` | Almeno un motore segnala il sito come sospetto. |
| `MALICIOUS` | Almeno un motore segnala il sito come malevolo. |
| `UNAVAILABLE` | Errore o timeout durante il controllo. |

### Cache VirusTotal

Per evitare chiamate API duplicate, SAFE-Shop usa la collection MongoDB `virustotal_cache`.

Flusso:

1. Cerca un risultato recente per `hostname`.
2. Se esiste e non e scaduto, lo riusa.
3. Se non esiste, chiama VirusTotal.
4. Salva il risultato in cache.
5. Se due richieste identiche arrivano nello stesso momento, la seconda aspetta la prima.

La durata default della cache e 30 giorni e si puo modificare con:

```env
VIRUSTOTAL_CACHE_DAYS=30
```

## MongoDB

Il progetto usa tre collection principali:

| Collection | Scopo |
| --- | --- |
| `url_checks` | Storico delle singole analisi. |
| `url_stats` | Statistiche aggregate per hostname. |
| `virustotal_cache` | Cache dei risultati VirusTotal. |

Indici creati automaticamente:

- `url_checks`: `{ hostname: 1, timestamp: -1 }`
- `url_checks`: TTL su `timestamp`
- `url_stats`: `{ hostname: 1 }`
- `virustotal_cache`: `{ hostname: 1 }` unico
- `virustotal_cache`: TTL su `timestamp`

Se MongoDB non e disponibile, il server ritorna comunque un risultato di analisi ma non persiste storico, statistiche e cache.

## API

### `POST /api/analizza`

Analizza un URL, dominio o IP.

Request:

```json
{
  "url": "https://example.com"
}
```

Response sintetica:

```json
{
  "hostname": "example.com",
  "score": 86,
  "dominio": 80,
  "https": 100,
  "recensioni": 50,
  "reputazione": 80,
  "eta": 100,
  "ip": "93.184.216.34",
  "blacklist": false,
  "virusTotal": {
    "checked": true,
    "malicious": 0,
    "suspicious": 0,
    "clean": 92,
    "status": "CLEAN",
    "label": "Nessun rilevamento",
    "lastUpdate": "2026-05-17T13:24:00.000Z"
  },
  "stats": {
    "checkCount": 1,
    "avgScore": 86,
    "riskLevel": "LOW"
  }
}
```

### `GET /api/history/:hostname`

Restituisce le ultime analisi salvate per un hostname.

Esempio:

```text
GET /api/history/example.com
```

Response:

```json
{
  "hostname": "example.com",
  "history": [
    {
      "score": 86,
      "timestamp": "2026-05-17T15:17:15.151Z",
      "results": {}
    }
  ]
}
```

## Frontend

La pagina principale e servita da `Static/index.html`.

Mostra:

- score percentuale
- livello di rischio
- dettagli dominio, HTTPS, reputazione e eta
- stato infrastruttura IP/DNS
- presenza in blacklist
- card VirusTotal con stato e conteggi
- statistiche aggregate
- siti popolari gia pronti da analizzare

## Troubleshooting

### La chiave VirusTotal e corretta ma risulta non configurata

Riavvia il server dopo aver modificato `.env`:

```bash
npm start
```

Il file `.env` viene letto solo all'avvio.

### VirusTotal ritorna `UNAVAILABLE`

Possibili cause:

- timeout della richiesta
- rate limit della API key gratuita
- connessione assente
- errore temporaneo del servizio

In questo caso SAFE-Shop non penalizza lo score.

### MongoDB non salva i risultati

Controlla che MongoDB sia avviato e che `connectionStringLocal` o `MONGODB_URI` siano corretti.

Per disabilitare volutamente MongoDB:

```env
MONGODB_DISABLED=true
```

### Il frontend sembra non aggiornarsi

Ricarica ignorando la cache del browser:

```text
Ctrl + F5
```

## Sicurezza

- Non pubblicare mai la tua `VIRUSTOTAL_API_KEY`.
- Non committare stringhe di connessione con credenziali reali.
- Le analisi sono indicative: anche uno score alto non garantisce che un sito sia sicuro.
- Un dominio legittimo puo essere compromesso e un dominio nuovo puo essere legittimo.

## Licenza

Il progetto include il file [LICENSE](LICENSE).
