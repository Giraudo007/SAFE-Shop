// A. import delle librerie
import express from "express";
import dotenv from "dotenv";
import { MongoClient, Db } from "mongodb";
import cors from "cors";
import dns from "dns/promises";
import whois from "whois-json";
import axios from "axios";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

type UrlMetrics = {
    dominio: number;
    https: number;
    recensioni: number;
    reputazione: number;
};

type AnalysisStoredResult = UrlMetrics & {
    eta: number;
    ip: string;
    blacklist: boolean;
};

type StatsSummary = {
    checkCount: number;
    firstCheck: Date;
    lastCheck: Date;
    avgScore: number;
    riskLevel: RiskLevel;
};

// B. configurazioni
dotenv.config({ path: ".env", quiet: true });

const app = express();
const connStr = process.env.connectionStringAtlas || process.env.MONGODB_URI || "";
const dbName = process.env.dbName || process.env.DB_NAME || "safeshop";
const port = Number.parseInt(process.env.PORT || "3000", 10);
const mongoDisabled = /^(1|true|yes)$/i.test(process.env.MONGODB_DISABLED || "");

let blacklist = new Set<string>();
let db: Db | undefined;
let client: MongoClient | undefined;

// C. creazione ed avvio del server HTTP
const server = app.listen(port, async function () {
    console.log("Server in ascolto sulla porta " + port);

    await inizializzaDatabase();
    await caricaBlacklist();
});

process.on("SIGINT", async () => {
    await client?.close();
    server.close(() => process.exit(0));
});

// D. middleware
app.use(function (req, res, next) {
    console.log("Ricevuta richiesta: " + req.method + ": " + req.originalUrl);
    next();
});

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.static("./Static"));

// E. gestione delle route dinamiche
app.post("/api/analizza", async (req, res) => {
    try {
        const parsedUrl = normalizzaUrlInput(req.body?.url);
        const url = parsedUrl.toString();
        const hostname = normalizzaHostname(parsedUrl.hostname);
        const ip = await risolviIp(parsedUrl.hostname);
        const blacklistTrovata = isInBlacklist(hostname);

        let metriche: UrlMetrics;
        let eta: number;

        if (blacklistTrovata) {
            metriche = {
                dominio: 0,
                https: 0,
                recensioni: 0,
                reputazione: 0
            };
            eta = 0;
        } else {
            eta = await calcolaEtaDominio(hostname);
            metriche = verificaUrl(url);
        }

        const score = blacklistTrovata ? 0 : calcolaPunteggio(metriche, eta);
        const results: AnalysisStoredResult = {
            ...metriche,
            eta,
            ip,
            blacklist: blacklistTrovata
        };
        const stats = await salvaAnalisi(url, hostname, score, results);

        res.json({
            ...results,
            score,
            hostname,
            stats
        });
    } catch (err) {
        console.error("Errore analisi:", err);
        res.status(400).json({ error: "URL non valido" });
    }
});

app.get("/api/history/:hostname", async (req, res) => {
    const hostname = normalizzaHostname(req.params.hostname);

    if (!hostname) {
        res.status(400).json({ error: "Hostname non valido" });
        return;
    }

    if (!db) {
        res.status(503).json({
            error: "Database non disponibile",
            hostname,
            history: []
        });
        return;
    }

    try {
        const history = await db.collection("url_checks")
            .find({ hostname })
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();

        res.json({
            hostname,
            history: history.map(h => ({
                score: h.score,
                timestamp: h.timestamp,
                results: h.results
            }))
        });
    } catch (err) {
        console.error("Errore recupero cronologia:", err);
        res.status(500).json({ error: "Errore recupero cronologia" });
    }
});

async function inizializzaDatabase() {
    if (mongoDisabled || !connStr) {
        console.warn("MongoDB non configurato: i risultati non saranno salvati.");
        return;
    }

    try {
        client = new MongoClient(connStr);
        await client.connect();
        db = client.db(dbName);

        await db.collection("url_checks").createIndex({ hostname: 1, timestamp: -1 });
        await db.collection("url_stats").createIndex({ hostname: 1 });

        console.log("MongoDB connesso");
    } catch (err) {
        db = undefined;
        console.error("Errore MongoDB:", err);
    }
}

async function caricaBlacklist() {
    try {
        const response = await axios.get(
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json",
            { timeout: 10000 }
        );

        const data = response.data;
        const valori = Array.isArray(data)
            ? data
            : data && typeof data === "object"
                ? Object.values(data).flat()
                : [];

        blacklist = new Set(
            valori
                .map(normalizzaVoceBlacklist)
                .filter((value): value is string => Boolean(value))
        );

        console.log("Blacklist caricata: " + blacklist.size);
    } catch (err) {
        blacklist = new Set();
        console.error("Errore caricamento blacklist:", err);
    }
}

function normalizzaUrlInput(rawUrl: unknown): URL {
    if (typeof rawUrl !== "string" || !rawUrl.trim()) {
        throw new Error("URL mancante");
    }

    const trimmed = rawUrl.trim();
    const hasProtocol = /^[a-z][a-z\d+\-.]*:\/\//i.test(trimmed);
    const value = hasProtocol ? trimmed : "https://" + trimmed;
    const parsed = new URL(value);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error("Protocollo non supportato");
    }

    if (!parsed.hostname || /\s/.test(parsed.hostname)) {
        throw new Error("Hostname non valido");
    }

    return parsed;
}

function normalizzaHostname(hostname: string | undefined): string {
    return (hostname || "")
        .trim()
        .toLowerCase()
        .replace(/\.$/, "")
        .replace(/^www\./, "");
}

function normalizzaVoceBlacklist(value: unknown): string | null {
    let raw: string | undefined;

    if (typeof value === "string") {
        raw = value;
    } else if (value && typeof value === "object") {
        const item = value as Record<string, unknown>;
        const candidate = item.domain || item.hostname || item.host || item.url;
        if (typeof candidate === "string") {
            raw = candidate;
        }
    }

    if (!raw) {
        return null;
    }

    let cleaned = raw.trim().toLowerCase();
    cleaned = cleaned.replace(/^https?:\/\//, "");

    const hostPart = cleaned.split(/[/?#]/)[0];
    if (!hostPart) {
        return null;
    }

    cleaned = hostPart
        .replace(/:\d+$/, "")
        .replace(/^\*\./, "")
        .replace(/^\.+/, "")
        .replace(/\.$/, "")
        .replace(/^www\./, "");

    if (!cleaned || /\s/.test(cleaned)) {
        return null;
    }

    return cleaned;
}

function isInBlacklist(hostname: string): boolean {
    const parts = normalizzaHostname(hostname).split(".");

    for (let i = 0; i < parts.length - 1; i++) {
        const candidate = parts.slice(i).join(".");
        if (blacklist.has(candidate)) {
            return true;
        }
    }

    return false;
}

async function risolviIp(hostname: string): Promise<string> {
    try {
        const addresses = await withTimeout(dns.resolve4(hostname), 5000);
        return addresses[0] || "non trovato";
    } catch {
        return "non trovato";
    }
}

async function salvaAnalisi(
    url: string,
    hostname: string,
    score: number,
    results: AnalysisStoredResult
): Promise<StatsSummary> {
    const timestamp = new Date();

    if (!db) {
        return creaStatsDefault(score, timestamp);
    }

    try {
        const statsCollection = db.collection("url_stats");
        const previous = await statsCollection.findOne({ hostname });
        const previousCount = Number(previous?.checkCount || 0);
        const checkCount = previousCount + 1;
        const previousAvg = Number(previous?.avgScore || 0);
        const avgScore = previousCount > 0
            ? ((previousAvg * previousCount) + score) / checkCount
            : score;
        const firstCheck = normalizzaData(previous?.firstCheck) || timestamp;
        const riskLevel = calcolaLivelloRischio(avgScore);

        await db.collection("url_checks").insertOne({
            url,
            hostname,
            timestamp,
            score,
            results,
            userFingerprint: "user_" + timestamp.getTime()
        });

        await statsCollection.updateOne(
            { hostname },
            {
                $set: {
                    url,
                    hostname,
                    checkCount,
                    lastCheck: timestamp,
                    avgScore,
                    riskLevel
                },
                $setOnInsert: {
                    firstCheck
                }
            },
            { upsert: true }
        );

        return {
            checkCount,
            firstCheck,
            lastCheck: timestamp,
            avgScore,
            riskLevel
        };
    } catch (err) {
        console.error("Errore salvataggio analisi:", err);
        return creaStatsDefault(score, timestamp);
    }
}

function creaStatsDefault(score: number, timestamp: Date): StatsSummary {
    return {
        checkCount: 1,
        firstCheck: timestamp,
        lastCheck: timestamp,
        avgScore: score,
        riskLevel: calcolaLivelloRischio(score)
    };
}

function normalizzaData(value: unknown): Date | null {
    if (!value) {
        return null;
    }

    const date = value instanceof Date ? value : new Date(String(value));
    return Number.isNaN(date.getTime()) ? null : date;
}

function verificaUrl(url: string): UrlMetrics {
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
        const numeriMistiLettere = /[a-z]+\d+[a-z]+|\d+[a-z]+\d+/i.test(sld);
        const urlLungo = url.length > 100;

        if (isIp) dominio -= 50;
        if (tldRischiosi.test(hostname)) dominio -= 10;
        if (paroleSospetteSld.test(sld)) dominio -= 20;
        if (numeriMistiLettere) dominio -= 15;
        if (trattinoMultiplo) dominio -= 10;
        if (sottodominiEccessivi) dominio -= 5;
        if (urlLungo) dominio -= 5;
        if (/\.(gov|edu|org)$/.test(hostname)) dominio += 10;

        dominio = limitaPunteggio(dominio);
    } catch {
        dominio = 10;
    }

    let recensioni = 50;

    try {
        const parsed = new URL(url);
        const pathProfondo = parsed.pathname.split("/").filter(Boolean).length >= 2;
        const troppiParam = Array.from(parsed.searchParams.keys()).length > 4;

        if (pathProfondo) recensioni += 10;
        if (troppiParam) recensioni -= 15;

        recensioni = limitaPunteggio(recensioni);
    } catch {
        recensioni = 20;
    }

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

        if (https === 100) reputazione += 20;
        if (paroleRosse.test(fullUrl)) reputazione -= 35;
        if (paroleArancioni.test(pathname)) reputazione -= 15;
        if (redirect.test(pathname)) reputazione -= 20;
        if (fileEseguibile.test(pathname)) reputazione -= 25;
        if (encodingSospetto) reputazione -= 15;

        reputazione = limitaPunteggio(reputazione);
    } catch {
        reputazione = 10;
    }

    return { dominio, https, recensioni, reputazione };
}

function calcolaPunteggio(risultato: UrlMetrics, eta: number): number {
    const dominio = limitaPunteggio(risultato.dominio);
    const https = limitaPunteggio(risultato.https);
    const recensioni = limitaPunteggio(risultato.recensioni);
    const reputazione = limitaPunteggio(risultato.reputazione);
    const etaNorm = limitaPunteggio(eta);

    const punteggio =
        dominio * 0.25 +
        https * 0.15 +
        recensioni * 0.20 +
        reputazione * 0.20 +
        etaNorm * 0.20;

    return Math.round(punteggio);
}

function calcolaLivelloRischio(score: number): RiskLevel {
    if (score >= 70) return "LOW";
    if (score >= 40) return "MEDIUM";
    return "HIGH";
}

function limitaPunteggio(value: number): number {
    return Math.min(Math.max(value, 0), 100);
}

async function calcolaEtaDominio(hostname: string): Promise<number> {
    try {
        const result = await withTimeout(whois(hostname), 8000);
        const creationDate = estraiDataCreazione(result);

        if (!creationDate) {
            return 40;
        }

        const created = normalizzaData(creationDate);
        if (!created) {
            return 40;
        }

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

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error("Timeout operazione esterna"));
        }, timeoutMs);

        promise
            .then(resolve, reject)
            .finally(() => clearTimeout(timeout));
    });
}

function estraiDataCreazione(value: unknown): unknown {
    if (!value) {
        return null;
    }

    if (Array.isArray(value)) {
        for (const item of value) {
            const found = estraiDataCreazione(item);
            if (found) return found;
        }
        return null;
    }

    if (typeof value !== "object") {
        return null;
    }

    const candidates = [
        "creationdate",
        "createddate",
        "created",
        "domaincreated",
        "registered",
        "registrationdate"
    ];

    for (const [key, fieldValue] of Object.entries(value as Record<string, unknown>)) {
        if (candidates.includes(key.toLowerCase())) {
            if (Array.isArray(fieldValue)) {
                return fieldValue[0] || null;
            }
            return fieldValue;
        }
    }

    return null;
}

// F. default route e gestione errori
app.use(function (req, res) {
    if (req.originalUrl.startsWith("/api/")) {
        res.status(404).json({ error: "Risorsa non trovata" });
    } else {
        res.status(404).send("<h1>Risorsa non trovata</h1>");
    }
});

// G. gestione errori
app.use(function (
    err: Error & { status?: number; type?: string },
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
) {
    if (err.type === "entity.parse.failed" || err.status === 400) {
        res.status(400).json({ error: "JSON non valido" });
        return;
    }

    console.error("ERRORE:", err.stack);
    res.status(500).json({ error: "Errore interno del server" });
});
