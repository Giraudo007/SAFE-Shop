//A. import delle librerie
import express from "express";
import dotenv from "dotenv";
import { MongoClient, Db } from "mongodb";
import cors from "cors";
import dns from "dns/promises";
import whois from "whois-json";
import axios from "axios";


//B. configurazioni
const app = express();
dotenv.config({ path: ".env" });
const connStr = process.env.connectionStringAtlas!;
const port = parseInt(process.env.PORT!);
let blacklist: string[] = [];
let db: Db;
let client: MongoClient;

//C. creazione ed avvio del server HTTP
const server = app.listen(port, async function () {
    console.log("Server in ascolto sulla porta " + port);

    try {
        // Connessione MongoDB
        client = new MongoClient(connStr);
        await client.connect();
        db = client.db("safeshop");
        console.log("✓ MongoDB connesso");

        // Creare indici
        await db.collection("url_checks").createIndex({ hostname: 1, timestamp: -1 });
        await db.collection("url_stats").createIndex({ hostname: 1 });

    } catch (err) {
        console.error("✗ Errore MongoDB:", err);
    }

    try {
        const response = await axios.get(
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json"
        );

        blacklist = response.data;

        console.log("✓ Blacklist caricata:", blacklist.length);

    } catch (err) {
        console.error("✗ Errore caricamento blacklist", err);
    }
});

//D. middleware
//middleware 1: request log
app.use(function (req, res, next) {
    console.log("Ricevuta richiesta: " + req.method + ": " + req.originalUrl);
    next();
});

//middleware 2: gestione delle risorse statiche
app.use(express.static("./static"));

//middleware 3: gestione dei parametri post
app.use(express.json({ "limit": "5mb" }));

//middleware 4: CORS
app.use(cors());


//E. gestione delle root dinamiche
app.post("/api/analizza", async (req: any, res) => {

    let url = req.body.url;

    if (!url) {
        res.status(400).send("URL mancante");
        return;
    }

    if (!url.startsWith("http")) {
        url = "https://" + url;
    }

    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname;

        let ip: any = "non trovato";

        try {
            const addresses = await dns.resolve4(hostname);
            if (addresses && addresses.length > 0) {
                ip = addresses[0];
            }
        } catch {
            // DNS non trovato
        }

        const cleanHost = hostname
            .replace(/^www\./, "")
            .toLowerCase();

        const dominioBlacklist = blacklist.some(d =>
            cleanHost === d || cleanHost.endsWith("." + d)
        );

        if (dominioBlacklist) {
            const risultato = {
                dominio: 0,
                https: 0,
                recensioni: 0,
                reputazione: 0,
                eta: 0,
                ip,
                blacklist: true
            };

            // Salva in DB
            if (db) {
                await db.collection("url_checks").insertOne({
                    url,
                    hostname,
                    timestamp: new Date(),
                    score: 0,
                    results: risultato,
                    userFingerprint: "user_" + new Date().getTime()
                });

                // Aggiorna contatore
                await db.collection("url_stats").updateOne(
                    { hostname },
                    {
                        $inc: { checkCount: 1 },
                        $set: {
                            lastCheck: new Date(),
                            riskLevel: "HIGH"
                        },
                        $setOnInsert: {
                            url,
                            hostname,
                            firstCheck: new Date(),
                            avgScore: 0
                        }
                    },
                    { upsert: true }
                );
            }

            res.send({
                ...risultato,
                stats: {
                    checkCount: 1,
                    firstCheck: new Date(),
                    lastCheck: new Date(),
                    riskLevel: "HIGH"
                }
            });

            return;
        }

        const eta = await calcolaEtaDominio(hostname);
        const risultato = verificaUrl(url);
        const punteggio = calcolaPunteggio(risultato, eta);

        // Salva in DB
        if (db) {
            await db.collection("url_checks").insertOne({
                url,
                hostname,
                timestamp: new Date(),
                score: punteggio,
                results: { ...risultato, eta, ip },
                userFingerprint: "user_" + new Date().getTime()
            });

            // Aggiorna statistiche
            const urlStats = await db.collection("url_stats").findOne({ hostname });
            let avgScore = punteggio;
            
            if (urlStats) {
                avgScore = (urlStats.avgScore * (urlStats.checkCount || 1) + punteggio) / ((urlStats.checkCount || 1) + 1);
            }

            let riskLevel = "HIGH";
            if (punteggio >= 70) riskLevel = "LOW";
            else if (punteggio >= 40) riskLevel = "MEDIUM";

            await db.collection("url_stats").updateOne(
                { hostname },
                {
                    $inc: { checkCount: 1 },
                    $set: {
                        lastCheck: new Date(),
                        avgScore,
                        riskLevel
                    },
                    $setOnInsert: {
                        url,
                        hostname,
                        firstCheck: new Date()
                    }
                },
                { upsert: true }
            );
        }

        const stats = await db?.collection("url_stats").findOne({ hostname });

        res.send({
            dominio: risultato.dominio,
            https: risultato.https,
            recensioni: risultato.recensioni,
            reputazione: risultato.reputazione,
            eta,
            ip,
            blacklist: false,
            stats: {
                checkCount: stats?.checkCount || 1,
                firstCheck: stats?.firstCheck || new Date(),
                lastCheck: stats?.lastCheck || new Date(),
                avgScore: stats?.avgScore || punteggio,
                riskLevel: stats?.riskLevel || "MEDIUM"
            }
        });

    } catch (err) {
        console.error("Errore analisi:", err);
        res.status(400).send("URL non valido");
    }
});

function verificaUrl(url: string) {
    const https = url.startsWith("https://") ? 100 : 0;

    let dominio = 80;

    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const parts = hostname.split(".");
        const sld = parts[parts.length - 2] || "";

        const tldRischiosi = /\.(xyz|tk|top|click|gq|ml|cf|ga|pw|icu|buzz|rest|skin|monster|cyou|cc|ws|su)$/i;
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
        const paroleSospetteSld = /login|secure|verify|paypa|amaz0n|amaz|ebay1|account|update|confirm|banking|wallet|signin/i;
        const trattinoMultiplo = (sld.match(/-/g) || []).length >= 2;
        const sottodominiEccessivi = parts.length > 3 && !hostname.startsWith("www.");
        const numereMistiLettere = /[a-z]+\d+[a-z]+|\d+[a-z]+\d+/i.test(sld);
        const urlLungo = url.length > 100;

        if (isIp) dominio -= 50;
        if (tldRischiosi.test(hostname)) dominio -= 10;
        if (paroleSospetteSld.test(sld)) dominio -= 20;
        if (numereMistiLettere) dominio -= 15;
        if (trattinoMultiplo) dominio -= 10;
        if (sottodominiEccessivi) dominio -= 5;
        if (urlLungo) dominio -= 5;
        if (/\.(gov|edu|org)$/.test(hostname)) dominio += 10;

        dominio = Math.min(Math.max(dominio, 0), 100);

    } catch {
        dominio = 10;
    }

    let recensioni = 50;

    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
        // const dominioSemplice = hostname.split(".")[0].length <= 8 && !/[-\d]/.test(hostname.split(".")[0]);
        const pathProfondo = parsed.pathname.split("/").filter(Boolean).length >= 2;
        const troppiParam = Array.from(parsed.searchParams.keys()).length > 4;

        // if (dominioSemplice) recensioni += 25;
        if (pathProfondo) recensioni += 10;
        if (troppiParam) recensioni -= 15;

        recensioni = Math.min(Math.max(recensioni, 0), 100);

    } catch {
        recensioni = 20;
    }

    // REPUTAZIONE / INDICE DI FIDUCIA
    let reputazione = 60;

    try {
        const parsed = new URL(url);
        const fullUrl = url.toLowerCase();
        const pathname = parsed.pathname.toLowerCase();

        const paroleRosse = /free|hack|crack|keygen|warez|pirat|cheat|nulled|phish|malware/i;
        const paroleArancioni = /download|gift|prize|winner|reward|promo|discount/i;
        const redirect = /redirect|redir|goto|out\.php|click\.php/i;
        const fileEseguibile = /\.(exe|bat|msi|dmg|apk|zip|rar|7z)$/i;
        const encodingSospetto = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length > 5;

        if (https == 100) reputazione += 20;
        if (paroleRosse.test(fullUrl)) reputazione -= 35;
        if (paroleArancioni.test(pathname)) reputazione -= 15;
        if (redirect.test(pathname)) reputazione -= 20;
        if (fileEseguibile.test(pathname)) reputazione -= 25;
        if (encodingSospetto) reputazione -= 15;

        reputazione = Math.min(Math.max(reputazione, 0), 100);

    } catch {
        reputazione = 10;
    }

    return { dominio, https, recensioni, reputazione };
}

// Calcola punteggio finale
function calcolaPunteggio(risultato: any, eta: number): number {
    const dominio = Math.min(Math.max(risultato.dominio, 0), 100);
    const https = Math.min(Math.max(risultato.https, 0), 100);
    const recensioni = Math.min(Math.max(risultato.recensioni, 0), 100);
    const reputazione = Math.min(Math.max(risultato.reputazione, 0), 100);
    const etaNorm = Math.min(Math.max(eta, 0), 100);

    const punteggio =
        dominio * 0.25 +
        https * 0.15 +
        recensioni * 0.20 +
        reputazione * 0.20 +
        etaNorm * 0.20;

    return Math.round(punteggio);
}

// Nuovo endpoint: cronologia di un hostname
app.get("/api/history/:hostname", async (req, res) => {
    const { hostname } = req.params;

    if (!db) {
        res.status(500).send("Database non disponibile");
        return;
    }

    try {
        const history = await db.collection("url_checks")
            .find({ hostname })
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();

        res.send({
            hostname,
            history: history.map(h => ({
                score: h.score,
                timestamp: h.timestamp,
                results: h.results
            }))
        });
    } catch (err) {
        res.status(500).send("Errore recupero cronologia");
    }
});

async function calcolaEtaDominio(hostname: string): Promise<number> {
    try {
        const result: any = await whois(hostname);
        console.log("WHOIS result:", result);

        const data = Array.isArray(result) ? result[0] : result;

        const creationDate =
            data.creationDate ||
            data.createdDate ||
            data.created ||
            data.domainCreated;

        if (!creationDate) {
            console.log("Nessuna data WHOIS trovata");
            return 40;
        }

        const created = new Date(creationDate);
        const now = new Date();

        const anni = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);

        if (anni >= 10) return 100;
        if (anni >= 5) return 80;
        if (anni >= 2) return 60;
        if (anni >= 1) return 40;
        return 20;

    } catch (err) {
        console.error("Errore WHOIS:", err);
        return 50;
    }
}

//F. default route e gestione errori
app.use(function (req, res) {
    if (req.originalUrl.startsWith("/api/"))
        res.status(404).json({ error: "Risorsa non trovata" });
    else
        res.status(404).send("<h1>Risorsa non trovata</h1>");
});

//G. gestione errori
app.use(function (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) {
    console.error("✗ ERRORE:", err.stack);
    res.status(500).json({ error: "Errore interno del server" });
});