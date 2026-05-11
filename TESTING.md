# 🧪 TESTING GUIDE - SAFE-Shop v2.0

## ✅ PRE-REQUISITI

Prima di testare:
1. ✅ MongoDB Atlas account (oppure MongoDB locale)
2. ✅ Node.js v16+ installato
3. ✅ `.env` correttamente configurato

---

## 🚀 QUICK START

### 1️⃣ Avviare il server

```bash
npm install    # Se prima volta
npm start      # Avvia server su port 3000
```

**Output atteso:**
```
Server in ascolto sulla porta 3000
✓ MongoDB connesso
✓ Blacklist caricata: 1234
```

---

## 🌐 TEST VIA FRONTEND (Più facile!)

### 1. Apri il browser
```
http://localhost:3000
```

### 2. Inserisci un URL
```
amazon.it    (oppure https://www.github.com)
```

### 3. Clicca "Analizza"

### 4. Verifica i risultati
- ✅ Vedi il punteggio (e.g., "75%")
- ✅ Vedi "Affidabile/Medio/Rischioso"
- ✅ Vedi dettagli: Dominio, HTTPS, Eta, etc

### 5. **NUOVO** - Scroll down per vedereSTATISTICHE
```
📊 Ricerche precedenti: 1
📅 Primo controllo: 11/05/2026
⏰ Ultimo controllo: 11/05/2026
📈 Punteggio medio: 75
⚠️ Livello rischio: MEDIUM (giallo)
```

### 6. Inserisci STESSO URL di nuovo
```
amazon.it
```

### 7. Clicca "Analizza" di nuovo

### 8. Verifica STATISTICHE aggiornate
```
📊 Ricerche precedenti: 2         ← INCREMENTATO!
📅 Primo controllo: 11/05/2026    ← STESSO
⏰ Ultimo controllo: 11/05/2026 (12:45)  ← AGGIORNATO!
📈 Punteggio medio: 75             ← MEDIA
⚠️ Livello rischio: MEDIUM         ← CALCOLO
```

---

## 🔴 TEST VIA CURL (Avanzato)

### TEST 1: Primo check
```bash
curl -X POST http://localhost:3000/api/analizza \
  -H "Content-Type: application/json" \
  -d '{"url":"amazon.it"}'
```

**Risposta attesa:**
```json
{
  "dominio": 80,
  "https": 100,
  "recensioni": 50,
  "reputazione": 65,
  "eta": 90,
  "ip": "54.239.28.30",
  "blacklist": false,
  "stats": {
    "checkCount": 1,
    "firstCheck": "2026-05-11T12:30:00.000Z",
    "lastCheck": "2026-05-11T12:30:00.000Z",
    "avgScore": 81,
    "riskLevel": "MEDIUM"
  }
}
```

✅ **Se vedi `checkCount: 1` e `stats` - FUNZIONA!**

---

### TEST 2: Secondo check stesso URL
```bash
curl -X POST http://localhost:3000/api/analizza \
  -H "Content-Type: application/json" \
  -d '{"url":"amazon.it"}'
```

**Risposta attesa:**
```json
{
  "dominio": 80,
  "https": 100,
  "recensioni": 50,
  "reputazione": 65,
  "eta": 90,
  "ip": "54.239.28.30",
  "blacklist": false,
  "stats": {
    "checkCount": 2,              ← ✅ INCREMENTATO
    "firstCheck": "2026-05-11T12:30:00.000Z",
    "lastCheck": "2026-05-11T12:31:15.000Z",   ← ✅ AGGIORNATO
    "avgScore": 81,
    "riskLevel": "MEDIUM"
  }
}
```

✅ **Se checkCount è passato da 1 a 2 - PERFETTO!**

---

### TEST 3: Cronologia API
```bash
curl http://localhost:3000/api/history/amazon.it
```

**Risposta attesa:**
```json
{
  "hostname": "amazon.it",
  "history": [
    {
      "score": 81,
      "timestamp": "2026-05-11T12:31:15.000Z",
      "results": { ... }
    },
    {
      "score": 81,
      "timestamp": "2026-05-11T12:30:00.000Z",
      "results": { ... }
    }
  ]
}
```

✅ **Se vedi 2 elementi nella history - CRONOLOGIA FUNZIONA!**

---

### TEST 4: URL su blacklist
```bash
curl -X POST http://localhost:3000/api/analizza \
  -H "Content-Type: application/json" \
  -d '{"url":"notabaddomain.tk"}'
```

**Risposta attesa (se su blacklist):**
```json
{
  "dominio": 0,
  "https": 0,
  "recensioni": 0,
  "reputazione": 0,
  "eta": 0,
  "ip": "non trovato",
  "blacklist": true,
  "stats": { ... }
}
```

✅ **Se `blacklist: true` - BLACKLIST CHECK FUNZIONA!**

---

### TEST 5: URL invalido
```bash
curl -X POST http://localhost:3000/api/analizza \
  -H "Content-Type: application/json" \
  -d '{"url":"invalid!!!url"}'
```

**Risposta attesa:**
```
"URL non valido"  (status 400)
```

✅ **Se errore 400 - ERROR HANDLING FUNZIONA!**

---

## 📊 MONGODB VERIFICATION

### Verificare i dati salvati

#### Via MongoDB Compass (GUI)
1. Apri MongoDB Compass
2. Connetti a cluster
3. Naviga a `safeshop` → `url_checks`
4. Dovresti vedere i tuoi check salvati

#### Via Mongo CLI
```bash
# Connettiti ad Atlas
mongosh "mongodb+srv://admin:password@cluster0.xyz.mongodb.net/safeshop"

# Query 1: Vedi tutti i check
db.url_checks.find().pretty()

# Query 2: Vedi statistiche
db.url_stats.find().pretty()

# Query 3: Vedi check solo per amazon.it
db.url_checks.find({hostname: "amazon.it"}).pretty()

# Query 4: Conta quanti check per dominio
db.url_checks.aggregate([
  {$group: {_id: "$hostname", count: {$sum: 1}}},
  {$sort: {count: -1}}
]).pretty()
```

---

## 🐛 TROUBLESHOOTING

### ❌ Problema: "MongoDB non connesso"
```
✗ Errore MongoDB: MongoServerError: connect ECONNREFUSED
```

**Soluzioni:**
1. Verifica stringa `.env`
```
connectionStringAtlas="mongodb+srv://admin:admin@cluster0.rbjmk9y.mongodb.net/?appName=Cluster0"
```

2. Verifica credenziali sono corrette
3. Aggiungi IP al whitelist su MongoDB Atlas:
   - Vai a Security → Network Access
   - Clicca "Add Current IP" oppure "0.0.0.0/0"

---

### ❌ Problema: "Ricerche precedenti sempre 1"
Significa non sta salvando su MongoDB.

**Debug:**
```javascript
// Apri console del browser (F12)
// Vedi se stats arriva dal backend
console.log(dati.stats)
```

**Se stats non arriva:**
- Controlla server logs
- Verifica MongoDB connection

---

### ❌ Problema: "Port 3000 already in use"
```
Error: listen EADDRINUSE: address already in use :::3000
```

**Soluzioni:**
1. Cambia port in `.env`:
```
PORT=5000
```

2. Oppure uccidi processo:
```bash
# Windows
taskkill /PID <process_id> /F

# Linux/Mac
lsof -i :3000
kill -9 <PID>
```

---

### ❌ Problema: "HTTPS sempre 100"
Se tutti gli URL hanno HTTPS=100 anche con HTTP:

**È un bug di questo tipo:**
```javascript
// ❌ SBAGLIATO (nell'endpoint)
const https = url.startsWith("https://") ? 100 : 0;
// Poi non lo usa

// ✅ GIUSTO (viene usato in verificaUrl)
function verificaUrl(url) {
    const https = url.startsWith("https://") ? 100 : 0;
    // ... calculate https score
}
```

**Verificare che calcoloPunteggio riceva il valore giusto.**

---

## 📈 PERFORMANCE TEST

### Testare con molti URL

```bash
#!/bin/bash
# test.sh - esegui 10 check random

URLS=("amazon.it" "google.com" "github.com" "stackoverflow.com" "reddit.com" "facebook.com" "youtube.com" "netflix.com" "twitter.com" "linkedin.com")

for url in "${URLS[@]}"
do
    echo "Testing: $url"
    curl -X POST http://localhost:3000/api/analizza \
      -H "Content-Type: application/json" \
      -d "{\"url\":\"$url\"}"
    echo ""
    sleep 1
done
```

**Risultato atteso:**
- Tutti e 10 gli URL salvati
- Query `db.url_stats.countDocuments()` deve ritornare 10
- Query `db.url_checks.countDocuments()` deve ritornare 10

---

## ✅ CHECKLIST DI TESTING

- [ ] Server avvia senza errori
- [ ] MongoDB si connette (`✓ MongoDB connesso`)
- [ ] Blacklist carica (`✓ Blacklist caricata`)
- [ ] Primo check appare nel frontend
- [ ] Vedo section "Statistiche"
- [ ] Ricerche precedenti = 1
- [ ] Secondo check incrementa a 2
- [ ] `checkCount` incrementa correttamente
- [ ] `lastCheck` si aggiorna
- [ ] `avgScore` calcola la media
- [ ] `riskLevel` colorato correttamente
- [ ] `/api/history` ritorna cronologia
- [ ] Dati su MongoDB Compass visibili
- [ ] URL blacklist funziona
- [ ] Error handling per URL invalido

---

## 🎯 SCENARI DI TEST CONSIGLIATI

### Scenario 1: E-commerce affidabile
```
URL: amazon.it
Atteso: score 80+, riskLevel LOW, verde
```

### Scenario 2: Sito nuovo sospetto
```
URL: https://test123xyz.tk
Atteso: score < 50, riskLevel HIGH, rosso
```

### Scenario 3: Sito compromesso
```
URL: https://free-gift-prize.xyz
Atteso: score < 40 (parole rosse), rischioso
```

### Scenario 4: Tracciamento
```
1. Inserire: amazon.it → checkCount = 1
2. Inserire: google.com → google checkCount = 1
3. Inserire: amazon.it → amazon checkCount = 2 ✓
```

---

## 📞 SUPPORTO

Se qualcosa non funziona:
1. Controlla console browser (F12 → Console)
2. Controlla server logs (dove hai fatto `npm start`)
3. Controlla MongoDB connection
4. Verifica `.env` configuration

**Domande frequenti:**
- "Perché checkCount non incrementa?" → MongoDB non connesso
- "Perché vedo sempre HIGH risk?" → Blacklist non caricata
- "Perché statistiche non appaiono?" → JS error in aggiornaStats

---

**Divertiti a testare! 🚀**
