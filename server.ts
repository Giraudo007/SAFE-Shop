// A. import delle librerie
import express from "express";
import dotenv from "dotenv";
import { MongoClient, Db } from "mongodb";
import cors from "cors";
import dns from "dns/promises";
import net from "net";
import whois from "whois-json";
import axios from "axios";
import { GoogleGenAI } from "@google/genai";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

type UrlMetrics = {
    dominio: number;
    https: number;
    recensioni: number;
    reputazione: number;
};

type IpStatus = "OK" | "WARNING";

type IpInfo = {
    primary: string;
    ipv4: string[];
    ipv6: string[];
    resolved: boolean;
    status: IpStatus;
    label: string;
    note: string;
    provider: string | null;
    usesCdn: boolean;
};

type VirusTotalStatus = "NOT_CONFIGURED" | "NOT_FOUND" | "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNAVAILABLE";

type VirusTotalInfo = {
    checked: boolean;
    malicious: number;
    suspicious: number;
    clean: number;
    lastUpdate: Date | null;
    status: VirusTotalStatus;
    label: string;
    note: string;
};

type AnalysisStoredResult = UrlMetrics & {
    eta: number;
    ip: string;
    ipInfo: IpInfo;
    blacklist: boolean;
    virusTotal: VirusTotalInfo;
};

type GeminiExplainPayload = {
    url: string;
    hostname: string;
    score: number;
    riskLevel: RiskLevel;
    results: {
        dominio: number;
        https: number;
        recensioni: number;
        reputazione: number;
        eta: number;
        blacklist: boolean;
        ipStatus: string;
        ipNote: string;
        virusTotalStatus: string;
        malicious: number;
        suspicious: number;
        clean: number;
    };
};

type GeminiChatMessage = {
    role: "user" | "model";
    text: string;
};

type GeminiSource = {
    title: string;
    uri: string;
    domain: string;
};

type GeminiChatPayload = GeminiExplainPayload & {
    question: string;
    history: GeminiChatMessage[];
};

type VirusTotalApiStats = {
    malicious?: number;
    suspicious?: number;
    undetected?: number;
    harmless?: number;
};

type VirusTotalApiResponse = {
    data?: {
        attributes?: {
            last_analysis_stats?: VirusTotalApiStats;
            last_analysis_date?: number;
        };
    };
};

type StatsSummary = {
    checkCount: number;
    firstCheck: Date;
    lastCheck: Date;
    avgScore: number;
    riskLevel: RiskLevel;
};

type UrlStatsDocument = StatsSummary & {
    hostname: string;
    url: string;
    scoreTotal: number;
};

type VirusTotalCacheDocument = {
    hostname: string;
    virusTotal: VirusTotalInfo;
    timestamp: Date;
};

// B. configurazioni
dotenv.config({ path: ".env", quiet: true });

const app = express();
const connStr = process.env.connectionStringLocal || process.env.MONGODB_URI || "";
const dbName = process.env.dbName || process.env.DB_NAME || "safeshop";
const port = Number.parseInt(process.env.PORT || "3000", 10);
const mongoDisabled = /^(1|true|yes)$/i.test(process.env.MONGODB_DISABLED || "");
const checkHistoryRetentionDays = parsePositiveInteger(process.env.URL_CHECK_RETENTION_DAYS, 30);
const checkHistoryRetentionSeconds = checkHistoryRetentionDays * 24 * 60 * 60;
const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY || "";
const virusTotalTimeoutMs = parsePositiveInteger(process.env.VIRUSTOTAL_TIMEOUT_MS, 8000);
const virusTotalCacheDays = parsePositiveInteger(process.env.VIRUSTOTAL_CACHE_DAYS, 30);
const virusTotalCacheSeconds = virusTotalCacheDays * 24 * 60 * 60;
const virusTotalCacheMs = virusTotalCacheSeconds * 1000;
const googleCloudProject = process.env.GOOGLE_CLOUD_PROJECT
    || process.env.GCLOUD_PROJECT
    || process.env.GCP_PROJECT
    || process.env.PROJECT_ID
    || "";
const googleCloudLocation = process.env.GOOGLE_CLOUD_LOCATION || process.env.VERTEX_AI_LOCATION || "global";
const geminiModelName = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const geminiTimeoutMs = parsePositiveInteger(process.env.GEMINI_TIMEOUT_MS, 20000);

let blacklist = new Set<string>();
let db: Db | undefined;
let client: MongoClient | undefined;
let server: ReturnType<typeof app.listen> | undefined;
let databaseInitPromise: Promise<Db | undefined> | undefined;
const virusTotalPendingRequests = new Map<string, Promise<VirusTotalInfo>>();
let geminiClient: GoogleGenAI | undefined;

class UserInputError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "UserInputError";
    }
}

// C. creazione ed avvio del server HTTP
process.on("SIGINT", async () => {
    await client?.close();

    if (server) {
        server.close(() => process.exit(0));
        return;
    }

    process.exit(0);
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
        const ipInfo = await analizzaInfrastrutturaIp(parsedUrl.hostname);
        const blacklistTrovata = isInBlacklist(hostname);

        validaEsistenzaRicerca(hostname, ipInfo, blacklistTrovata);

        let metriche: UrlMetrics;
        let eta: number;
        let virusTotal: VirusTotalInfo;
        const virusTotalPromise = controllaVirusTotal(hostname);

        if (blacklistTrovata) {
            metriche = {
                dominio: 0,
                https: 0,
                recensioni: 0,
                reputazione: 0
            };
            eta = 0;
            virusTotal = await virusTotalPromise;
        } else {
            const [etaDominio, virusTotalResult] = await Promise.all([
                calcolaEtaDominio(hostname),
                virusTotalPromise
            ]);

            eta = etaDominio;
            virusTotal = virusTotalResult;
            metriche = verificaUrl(url);
        }

        const score = blacklistTrovata ? 0 : calcolaPunteggio(metriche, eta, virusTotal);
        const results: AnalysisStoredResult = {
            ...metriche,
            eta,
            ip: ipInfo.primary,
            ipInfo,
            blacklist: blacklistTrovata,
            virusTotal
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
        res.status(400).json({
            error: err instanceof UserInputError ? err.message : "URL non valido"
        });
    }
});

app.get("/api/history/:hostname", async (req, res) => {
    const hostname = normalizzaHostname(req.params.hostname);

    if (!hostname) {
        res.status(400).json({ error: "Hostname non valido" });
        return;
    }

    try {
        const history = await withMongoRetry(database => database.collection("url_checks")
            .find({ hostname })
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray());

        if (!history) {
            res.status(503).json({
                error: "Database non disponibile",
                hostname,
                history: []
            });
            return;
        }

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

app.post("/api/gemini/spiega", async (req, res) => {
    try {
        const payload = normalizzaRichiestaSpiegazioneGemini(req.body);
        const explanation = await generaSpiegazioneGemini(payload);

        res.json({
            explanation,
            model: geminiModelName,
            location: googleCloudLocation
        });
    } catch (err) {
        console.error("Errore Gemini:", err);

        if (err instanceof UserInputError) {
            res.status(400).json({ error: err.message });
            return;
        }

        const message = err instanceof Error ? err.message : "Gemini non disponibile";
        const isConfigurationError = message.includes("GOOGLE_CLOUD_PROJECT")
            || message.includes("credenziali")
            || message.includes("autenticarsi")
            || message.includes("Vertex AI API");

        res.status(isConfigurationError ? 503 : 500).json({
            error: message
        });
    }
});

app.post("/api/gemini/chat", async (req, res) => {
    try {
        const payload = normalizzaRichiestaChatGemini(req.body);
        const result = await generaRispostaChatGemini(payload);

        res.json({
            answer: result.answer,
            sources: result.sources,
            model: geminiModelName,
            location: googleCloudLocation
        });
    } catch (err) {
        console.error("Errore chat Gemini:", err);

        if (err instanceof UserInputError) {
            res.status(400).json({ error: err.message });
            return;
        }

        const message = err instanceof Error ? err.message : "Gemini non disponibile";
        const isConfigurationError = message.includes("GOOGLE_CLOUD_PROJECT")
            || message.includes("credenziali")
            || message.includes("autenticarsi")
            || message.includes("Vertex AI API");

        res.status(isConfigurationError ? 503 : 500).json({
            error: message
        });
    }
});

async function inizializzaDatabase(): Promise<Db | undefined> {
    if (mongoDisabled || !connStr) {
        console.warn("MongoDB non configurato: i risultati non saranno salvati.");
        return undefined;
    }

    if (db) {
        return db;
    }

    if (databaseInitPromise) {
        return databaseInitPromise;
    }

    databaseInitPromise = creaConnessioneDatabase().finally(() => {
        databaseInitPromise = undefined;
    });

    return databaseInitPromise;
}

async function creaConnessioneDatabase(): Promise<Db | undefined> {
    console.log("🔌 Tentativo connessione a MongoDB:", connStr.substring(0, 50) + "...");

    let mongoClient: MongoClient | undefined;

    try {
        mongoClient = new MongoClient(connStr, {
            serverSelectionTimeoutMS: 5000
        });
        await mongoClient.connect();

        const database = mongoClient.db(dbName);

        console.log("📁 Database selezionato:", dbName);

        const indexesUrl = await database.collection("url_checks").createIndex({ hostname: 1, timestamp: -1 });
        console.log("📍 Indice creato su url_checks:", indexesUrl);

        await configuraPuliziaStorico(database);
        
        const indexesStats = await database.collection("url_stats").createIndex({ hostname: 1 });
        console.log("📍 Indice creato su url_stats:", indexesStats);

        await configuraCacheVirusTotal(database);

        client = mongoClient;
        db = database;

        console.log("✅ MongoDB connesso e pronto!");
        return database;
    } catch (err) {
        await mongoClient?.close().catch(() => undefined);
        db = undefined;
        client = undefined;
        console.error("❌ ERRORE connessione MongoDB:", err);
        return undefined;
    }
}

async function configuraPuliziaStorico(database: Db): Promise<void> {
    const collection = database.collection("url_checks");
    const ttlIndexName = "url_checks_timestamp_ttl";
    const indexes = await collection.indexes();
    const timestampIndex = indexes.find(index => isTimestampIndexKey(index.key));

    if (timestampIndex) {
        if (timestampIndex.expireAfterSeconds != checkHistoryRetentionSeconds) {
            await database.command({
                collMod: "url_checks",
                index: {
                    name: timestampIndex.name,
                    expireAfterSeconds: checkHistoryRetentionSeconds
                }
            });
        }

        console.log(`🧹 Storico url_checks mantenuto per ${checkHistoryRetentionDays} giorni:`, timestampIndex.name);
        return;
    }

    const ttlIndex = await collection.createIndex(
        { timestamp: 1 },
        {
            name: ttlIndexName,
            expireAfterSeconds: checkHistoryRetentionSeconds
        }
    );

    console.log(`🧹 Storico url_checks mantenuto per ${checkHistoryRetentionDays} giorni:`, ttlIndex);
}

async function configuraCacheVirusTotal(database: Db): Promise<void> {
    const collection = database.collection("virustotal_cache");
    const hostnameIndex = await collection.createIndex({ hostname: 1 }, { unique: true });
    console.log("Indice creato su virustotal_cache:", hostnameIndex);

    const ttlIndexName = "virustotal_cache_timestamp_ttl";
    const indexes = await collection.indexes();
    const timestampIndex = indexes.find(index => index.name == ttlIndexName || isTimestampIndexKey(index.key));

    if (timestampIndex) {
        if (timestampIndex.expireAfterSeconds != virusTotalCacheSeconds) {
            await database.command({
                collMod: "virustotal_cache",
                index: {
                    name: timestampIndex.name,
                    expireAfterSeconds: virusTotalCacheSeconds
                }
            });
        }

        console.log(`Cache VirusTotal mantenuta per ${virusTotalCacheDays} giorni:`, timestampIndex.name);
        return;
    }

    const ttlIndex = await collection.createIndex(
        { timestamp: 1 },
        {
            name: ttlIndexName,
            expireAfterSeconds: virusTotalCacheSeconds
        }
    );

    console.log(`Cache VirusTotal mantenuta per ${virusTotalCacheDays} giorni:`, ttlIndex);
}

function isTimestampIndexKey(key: unknown): boolean {
    if (!key || typeof key != "object") {
        return false;
    }

    const fields = Object.entries(key as Record<string, unknown>);
    return fields.length == 1 && fields[0]?.[0] == "timestamp" && fields[0]?.[1] == 1;
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
    const parsed = Number.parseInt(value || "", 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

async function getDatabase(): Promise<Db | undefined> {
    if (db) {
        return db;
    }

    return inizializzaDatabase();
}

async function resetDatabaseConnection(): Promise<void> {
    const currentClient = client;

    db = undefined;
    client = undefined;
    databaseInitPromise = undefined;

    await currentClient?.close().catch(() => undefined);
}

function isMongoNotConnectedError(err: unknown): boolean {
    return err instanceof Error && err.name == "MongoNotConnectedError";
}

async function withMongoRetry<T>(operation: (database: Db) => Promise<T>): Promise<T | null> {
    let database = await getDatabase();

    if (!database) {
        return null;
    }

    try {
        return await operation(database);
    } catch (err) {
        if (!isMongoNotConnectedError(err)) {
            throw err;
        }

        console.warn("Connessione MongoDB chiusa: provo a riconnettere una volta.");
        await resetDatabaseConnection();
        database = await getDatabase();

        if (!database) {
            return null;
        }

        return operation(database);
    }
}

async function generaSpiegazioneGemini(payload: GeminiExplainPayload): Promise<string> {
    const client = getGeminiClient();
    const prompt = creaPromptSpiegazioneGemini(payload);

    try {
        const result = await withTimeout(
            client.models.generateContent({
                model: geminiModelName,
                contents: prompt,
                config: {
                    systemInstruction: "Sei l'assistente di SAFE-Shop. Spiega risultati di sicurezza web in italiano semplice, senza inventare dati e senza dare garanzie assolute.",
                    maxOutputTokens: 420,
                    temperature: 0.25
                }
            }),
            geminiTimeoutMs
        );
        const text = estraiTestoGemini(result);

        if (!text) {
            throw new Error("Gemini non ha restituito testo. Riprova tra poco.");
        }

        return text;
    } catch (err) {
        throw new Error(creaMessaggioErroreGemini(err));
    }
}

async function generaRispostaChatGemini(payload: GeminiChatPayload): Promise<{ answer: string; sources: GeminiSource[] }> {
    const client = getGeminiClient();
    const prompt = creaPromptChatGemini(payload);

    try {
        const result = await withTimeout(
            client.models.generateContent({
                model: geminiModelName,
                contents: prompt,
                config: {
                    systemInstruction: "Sei SAFE-Shop AI. Aiuti l'utente a valutare siti e-commerce con prudenza, dati tecnici e fonti web pubbliche. Non inventare prove, non diffamare aziende o persone, e distingui sempre tra fatto verificato, segnale di rischio e ipotesi.",
                    maxOutputTokens: 720,
                    temperature: 0.35,
                    tools: [{ googleSearch: {} }]
                }
            }),
            geminiTimeoutMs
        );
        const answer = estraiTestoGemini(result);

        if (!answer) {
            throw new Error("Gemini non ha restituito testo. Riprova tra poco.");
        }

        return {
            answer,
            sources: estraiFontiGemini(result)
        };
    } catch (err) {
        throw new Error(creaMessaggioErroreGemini(err));
    }
}

function getGeminiClient(): GoogleGenAI {
    if (!googleCloudProject) {
        throw new Error("Configura GOOGLE_CLOUD_PROJECT nel file .env prima di usare Gemini.");
    }

    if (!geminiClient) {
        geminiClient = new GoogleGenAI({
            vertexai: true,
            project: googleCloudProject,
            location: googleCloudLocation,
            apiVersion: "v1"
        });
    }

    return geminiClient;
}

function normalizzaRichiestaSpiegazioneGemini(body: unknown): GeminiExplainPayload {
    if (!isRecord(body)) {
        throw new UserInputError("Dati analisi non validi.");
    }

    const results = isRecord(body.results) ? body.results : body;
    const ipInfo = isRecord(results.ipInfo) ? results.ipInfo : {};
    const virusTotal = isRecord(results.virusTotal) ? results.virusTotal : {};
    const hostname = normalizzaHostname(leggiStringa(body.hostname) || leggiStringa(results.hostname));

    if (!hostname) {
        throw new UserInputError("Dati analisi non validi: hostname mancante.");
    }

    const score = limitaPunteggio(normalizzaNumero(body.score ?? results.score, 0));
    const riskLevel = normalizzaRiskLevel(body.riskLevel)
        || normalizzaRiskLevel(results.riskLevel)
        || calcolaLivelloRischio(score);

    return {
        url: leggiStringa(body.url) || leggiStringa(results.url) || hostname,
        hostname,
        score,
        riskLevel,
        results: {
            dominio: limitaPunteggio(normalizzaNumero(results.dominio, 0)),
            https: limitaPunteggio(normalizzaNumero(results.https, 0)),
            recensioni: limitaPunteggio(normalizzaNumero(results.recensioni, 0)),
            reputazione: limitaPunteggio(normalizzaNumero(results.reputazione, 0)),
            eta: limitaPunteggio(normalizzaNumero(results.eta, 0)),
            blacklist: leggiBoolean(results.blacklist),
            ipStatus: leggiStringa(ipInfo.label, leggiStringa(results.ip, "Non disponibile")),
            ipNote: leggiStringa(ipInfo.note, "Stato infrastruttura non disponibile."),
            virusTotalStatus: leggiStringa(virusTotal.label, leggiStringa(virusTotal.status, "Non disponibile")),
            malicious: normalizzaConteggio(virusTotal.malicious),
            suspicious: normalizzaConteggio(virusTotal.suspicious),
            clean: normalizzaConteggio(virusTotal.clean)
        }
    };
}

function normalizzaRichiestaChatGemini(body: unknown): GeminiChatPayload {
    const base = normalizzaRichiestaSpiegazioneGemini(body);

    if (!isRecord(body)) {
        throw new UserInputError("Dati chat non validi.");
    }

    const question = leggiStringa(body.question);

    if (!question) {
        throw new UserInputError("Scrivi una domanda sul sito analizzato.");
    }

    if (question.length > 600) {
        throw new UserInputError("Domanda troppo lunga: usa massimo 600 caratteri.");
    }

    return {
        ...base,
        question,
        history: normalizzaCronologiaChat(body.history)
    };
}

function normalizzaCronologiaChat(value: unknown): GeminiChatMessage[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .slice(-8)
        .map(item => {
            if (!isRecord(item)) {
                return null;
            }

            const role = item.role == "user" ? "user" : item.role == "model" ? "model" : null;
            const text = leggiStringa(item.text);

            if (!role || !text) {
                return null;
            }

            return {
                role,
                text: text.slice(0, 900)
            };
        })
        .filter((item): item is GeminiChatMessage => Boolean(item));
}

function creaPromptSpiegazioneGemini(payload: GeminiExplainPayload): string {
    return [
        "Spiega questo risultato SAFE-Shop a uno studente o utente non tecnico.",
        "Regole:",
        "- Rispondi in italiano.",
        "- Usa massimo 8 frasi brevi.",
        "- Evidenzia perche il sito sembra affidabile, medio o rischioso.",
        "- Cita i segnali principali: HTTPS, dominio, eta, blacklist, IP e VirusTotal.",
        "- Non dire mai che un sito e sicuro al 100%.",
        "- Chiudi con 2 consigli pratici.",
        "",
        "Dati dell'analisi:",
        JSON.stringify(payload, null, 2)
    ].join("\n");
}

function creaPromptChatGemini(payload: GeminiChatPayload): string {
    return [
        "Rispondi alla domanda dell'utente sul sito analizzato.",
        "",
        "Obiettivo:",
        "- Valutare se il sito, i prodotti o il venditore mostrano segnali di affidabilita o rischio.",
        "- Usare i dati tecnici SAFE-Shop e, quando serve, informazioni pubbliche aggiornate dal web tramite Google Search.",
        "- Cercare segnali come recensioni ricorrenti, reclami, mancati rimborsi, prodotti contraffatti, societa proprietaria, contatti aziendali, pagine legali, notizie e possibili truffe.",
        "",
        "Regole di risposta:",
        "- Rispondi in italiano.",
        "- Se la domanda chiede una decisione, inizia con 'Risposta breve: si', 'Risposta breve: no' oppure 'Risposta breve: non abbastanza dati'.",
        "- Distingui tra dati certi e segnali non conclusivi.",
        "- Non accusare persone o aziende di truffa senza fonti solide; usa formule come 'segnale di rischio', 'da verificare', 'non confermato'.",
        "- Non garantire mai che un acquisto sia sicuro al 100%.",
        "- Chiudi con un consiglio pratico per l'utente.",
        "",
        "Dati SAFE-Shop:",
        JSON.stringify({
            url: payload.url,
            hostname: payload.hostname,
            score: payload.score,
            riskLevel: payload.riskLevel,
            results: payload.results
        }, null, 2),
        "",
        "Cronologia recente:",
        JSON.stringify(payload.history, null, 2),
        "",
        "Domanda utente:",
        payload.question
    ].join("\n");
}

function estraiTestoGemini(response: {
    text?: string | undefined;
    candidates?: Array<{ content?: { parts?: Array<{ text?: unknown }> } | undefined }> | undefined;
}): string {
    if (typeof response.text == "string" && response.text.trim()) {
        return response.text.trim();
    }

    return (response.candidates || [])
        .flatMap(candidate => candidate.content?.parts || [])
        .map(part => typeof part.text == "string" ? part.text.trim() : "")
        .filter(Boolean)
        .join("\n")
        .trim();
}

function estraiFontiGemini(response: {
    candidates?: Array<{
        groundingMetadata?: {
            groundingChunks?: Array<{
                web?: {
                    title?: string;
                    uri?: string;
                    domain?: string;
                };
            }>;
        };
    }> | undefined;
}): GeminiSource[] {
    const sources = new Map<string, GeminiSource>();

    for (const candidate of response.candidates || []) {
        for (const chunk of candidate.groundingMetadata?.groundingChunks || []) {
            const web = chunk.web;
            const uri = leggiStringa(web?.uri);

            if (!uri || sources.has(uri)) {
                continue;
            }

            sources.set(uri, {
                uri,
                title: leggiStringa(web?.title, "Fonte web"),
                domain: leggiStringa(web?.domain)
            });
        }
    }

    return Array.from(sources.values()).slice(0, 5);
}

function creaMessaggioErroreGemini(err: unknown): string {
    const details = descriviErroreEsterno(err);
    const lower = details.toLowerCase();

    if (lower.includes("default credentials")
        || lower.includes("could not load")
        || lower.includes("adc")
        || lower.includes("unable to authenticate")
        || lower.includes("authentication")) {
        return "Gemini non puo autenticarsi: esegui gcloud auth application-default login e riavvia il server.";
    }

    if (lower.includes("permission") || lower.includes("denied") || lower.includes("403")) {
        return "Google Cloud ha rifiutato la richiesta: verifica che Vertex AI API sia attiva e che il tuo account abbia accesso al progetto.";
    }

    if (lower.includes("not found") && lower.includes("model")) {
        return "Modello Gemini non trovato in Vertex AI: controlla GEMINI_MODEL e GOOGLE_CLOUD_LOCATION nel file .env.";
    }

    return "Gemini non disponibile: " + details;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value == "object" && value !== null && !Array.isArray(value);
}

function leggiStringa(value: unknown, fallback = ""): string {
    return typeof value == "string" && value.trim() ? value.trim() : fallback;
}

function leggiBoolean(value: unknown): boolean {
    return value == true || value == 1 || value == "1" || value == "true";
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
            : data && typeof data == "object"
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
    if (typeof rawUrl != "string" || !rawUrl.trim()) {
        throw new UserInputError("Inserisci un URL, dominio o IP da analizzare.");
    }

    const trimmed = rawUrl.trim();
    const hasProtocol = /^[a-z][a-z\d+\-.]*:\/\//i.test(trimmed);
    const value = hasProtocol ? trimmed : "https://" + trimmed;
    const parsed = new URL(value);

    if (parsed.protocol != "http:" && parsed.protocol != "https:") {
        throw new UserInputError("Protocollo non supportato: usa http o https.");
    }

    if (!parsed.hostname || /\s/.test(parsed.hostname)) {
        throw new UserInputError("Nome dominio o IP non valido.");
    }

    const hostname = normalizzaHostname(parsed.hostname);

    if (!isIpLiteral(hostname) && !isDominioPubblicoValido(hostname)) {
        throw new UserInputError("Inserisci un dominio completo, ad esempio amazon.it, oppure un IP pubblico valido.");
    }

    return parsed;
}

function normalizzaHostname(hostname: string | undefined): string {
    return (hostname || "")
        .trim()
        .toLowerCase()
        .replace(/^\[(.*)\]$/, "$1")
        .replace(/\.$/, "")
        .replace(/^www\./, "");
}

function normalizzaVoceBlacklist(value: unknown): string | null {
    let raw: string | undefined;

    if (typeof value == "string") {
        raw = value;
    } else if (value && typeof value == "object") {
        const item = value as Record<string, unknown>;
        const candidate = item.domain || item.hostname || item.host || item.url;
        if (typeof candidate == "string") {
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

async function analizzaInfrastrutturaIp(hostname: string): Promise<IpInfo> {
    const normalizedHost = normalizzaHostname(hostname);
    const ipVersion = net.isIP(normalizedHost);

    if (ipVersion != 0) {
        const isPublic = isIpPubblico(normalizedHost);

        return {
            primary: normalizedHost,
            ipv4: ipVersion == 4 ? [normalizedHost] : [],
            ipv6: ipVersion == 6 ? [normalizedHost] : [],
            resolved: isPublic,
            status: isPublic ? "OK" : "WARNING",
            label: isPublic ? "IP valido" : "IP non pubblico",
            note: isPublic
                ? "L'indirizzo IP inserito e valido e pubblico."
                : "L'indirizzo IP inserito e privato, locale o riservato: non indica un negozio raggiungibile pubblicamente.",
            provider: null,
            usesCdn: false
        };
    }

    const [ipv4, ipv6, cname] = await Promise.all([
        risolviRecordDns(() => dns.resolve4(normalizedHost)),
        risolviRecordDns(() => dns.resolve6(normalizedHost)),
        risolviRecordDns(() => dns.resolveCname(normalizedHost))
    ]);

    const allIps = [...ipv4, ...ipv6];
    const hasPublicIp = allIps.some(isIpPubblico);
    const provider = identificaProviderInfrastruttura(cname, allIps);
    const usesCdn = Boolean(provider);

    if (allIps.length == 0) {
        return {
            primary: "non trovato",
            ipv4,
            ipv6,
            resolved: false,
            status: "WARNING",
            label: "DNS non risolto",
            note: "Il dominio non restituisce IP: segnale tecnico da controllare.",
            provider,
            usesCdn
        };
    }

    if (!hasPublicIp) {
        return {
            primary: allIps[0] || "non trovato",
            ipv4,
            ipv6,
            resolved: false,
            status: "WARNING",
            label: "IP non pubblico",
            note: "Il dominio risolve solo verso IP privati o riservati: non sembra un negozio pubblico raggiungibile da Internet.",
            provider,
            usesCdn
        };
    }

    if (usesCdn && provider) {
        return {
            primary: allIps[0] || "non trovato",
            ipv4,
            ipv6,
            resolved: true,
            status: "OK",
            label: "CDN rilevata",
            note: `Dominio raggiungibile tramite ${provider}. Protegge l'infrastruttura, ma non garantisce da sola l'affidabilita del negozio.`,
            provider,
            usesCdn
        };
    }

    return {
        primary: allIps[0] || "non trovato",
        ipv4,
        ipv6,
        resolved: true,
        status: "OK",
        label: "DNS OK",
        note: "Il dominio restituisce IP validi: e un segnale tecnico positivo, non una garanzia assoluta.",
        provider,
        usesCdn
    };
}

function validaEsistenzaRicerca(hostname: string, ipInfo: IpInfo, blacklistTrovata: boolean): void {
    if (blacklistTrovata) {
        return;
    }

    if (ipInfo.resolved) {
        return;
    }

    if (isIpLiteral(hostname)) {
        throw new UserInputError("L'IP inserito non e pubblico o non puo essere verificato come indirizzo raggiungibile da Internet.");
    }

    if (ipInfo.label == "IP non pubblico") {
        throw new UserInputError("Il dominio inserito esiste, ma punta solo a IP privati o riservati.");
    }

    throw new UserInputError("Il dominio inserito non esiste o non restituisce un IP valido. Controlla il nome e riprova.");
}

async function controllaVirusTotal(hostname: string): Promise<VirusTotalInfo> {
    if (!virusTotalApiKey) {
        return creaVirusTotalInfo(
            "NOT_CONFIGURED",
            false,
            0,
            0,
            0,
            null,
            "Non configurato",
            "Aggiungi VIRUSTOTAL_API_KEY al file .env per abilitare il controllo."
        );
    }

    const normalizedHost = normalizzaHostname(hostname);
    const pendingRequest = virusTotalPendingRequests.get(normalizedHost);

    if (pendingRequest) {
        console.log("VirusTotal richiesta gia in corso:", normalizedHost);
        return pendingRequest;
    }

    const request = controllaVirusTotalConCache(normalizedHost).finally(() => {
        virusTotalPendingRequests.delete(normalizedHost);
    });

    virusTotalPendingRequests.set(normalizedHost, request);
    return request;
}

async function controllaVirusTotalConCache(normalizedHost: string): Promise<VirusTotalInfo> {
    const cachedResult = await trovaVirusTotalCache(normalizedHost);

    if (cachedResult) {
        console.log("VirusTotal cache hit:", normalizedHost);
        return cachedResult;
    }

    const result = await chiediVirusTotalApi(normalizedHost);
    await salvaVirusTotalCache(normalizedHost, result);

    return result;
}

async function chiediVirusTotalApi(normalizedHost: string): Promise<VirusTotalInfo> {
    const resource = net.isIP(normalizedHost) ? "ip_addresses" : "domains";

    try {
        const response = await axios.get<VirusTotalApiResponse>(
            `https://www.virustotal.com/api/v3/${resource}/${encodeURIComponent(normalizedHost)}`,
            {
                headers: { "x-apikey": virusTotalApiKey },
                timeout: virusTotalTimeoutMs
            }
        );

        const attributes = response.data.data?.attributes;
        const stats = attributes?.last_analysis_stats || {};
        const malicious = normalizzaConteggio(stats.malicious);
        const suspicious = normalizzaConteggio(stats.suspicious);
        const clean = normalizzaConteggio(stats.undetected) + normalizzaConteggio(stats.harmless);
        const lastUpdate = normalizzaUnixDate(attributes?.last_analysis_date);

        if (malicious > 0) {
            return creaVirusTotalInfo(
                "MALICIOUS",
                true,
                malicious,
                suspicious,
                clean,
                lastUpdate,
                "Malware rilevato",
                "VirusTotal segnala rilevazioni malevole: il punteggio viene bloccato a zero."
            );
        }

        if (suspicious > 0) {
            return creaVirusTotalInfo(
                "SUSPICIOUS",
                true,
                malicious,
                suspicious,
                clean,
                lastUpdate,
                "Sospetto",
                "VirusTotal segnala rilevazioni sospette: il punteggio viene penalizzato."
            );
        }

        if (clean > 0) {
            return creaVirusTotalInfo(
                "CLEAN",
                true,
                malicious,
                suspicious,
                clean,
                lastUpdate,
                "Nessun rilevamento",
                "VirusTotal non riporta rilevazioni malevole o sospette."
            );
        }

        return creaVirusTotalInfo(
            "NOT_FOUND",
            true,
            0,
            0,
            0,
            lastUpdate,
            "Nessun dato",
            "VirusTotal non ha analisi utili per questo dominio o IP."
        );
    } catch (err) {
        if (axios.isAxiosError(err) && err.response?.status == 404) {
            return creaVirusTotalInfo(
                "NOT_FOUND",
                true,
                0,
                0,
                0,
                null,
                "Nessun dato",
                "VirusTotal non conosce ancora questo dominio o IP."
            );
        }

        console.warn("VirusTotal non disponibile:", descriviErroreEsterno(err));
        return creaVirusTotalInfo(
            "UNAVAILABLE",
            false,
            0,
            0,
            0,
            null,
            "Non disponibile",
            "Controllo VirusTotal non riuscito: il punteggio non viene penalizzato."
        );
    }
}

async function trovaVirusTotalCache(hostname: string): Promise<VirusTotalInfo | null> {
    const document = await withMongoRetry(database => database.collection("virustotal_cache").findOne({ hostname }));

    if (!document) {
        return null;
    }

    const cacheDocument = document as Partial<VirusTotalCacheDocument>;
    const timestamp = normalizzaData(cacheDocument.timestamp);

    if (!timestamp || isVirusTotalCacheScaduta(timestamp)) {
        return null;
    }

    return normalizzaVirusTotalInfo(cacheDocument.virusTotal);
}

async function salvaVirusTotalCache(hostname: string, virusTotal: VirusTotalInfo): Promise<void> {
    if (!deveSalvareVirusTotalCache(virusTotal)) {
        return;
    }

    await withMongoRetry(async database => {
        await database.collection("virustotal_cache").updateOne(
            { hostname },
            {
                $set: {
                    hostname,
                    virusTotal,
                    timestamp: new Date()
                }
            },
            { upsert: true }
        );
    });
}

function deveSalvareVirusTotalCache(virusTotal: VirusTotalInfo): boolean {
    return virusTotal.checked && virusTotal.status != "UNAVAILABLE";
}

function isVirusTotalCacheScaduta(timestamp: Date): boolean {
    return Date.now() - timestamp.getTime() > virusTotalCacheMs;
}

function normalizzaVirusTotalInfo(value: unknown): VirusTotalInfo | null {
    if (!value || typeof value != "object") {
        return null;
    }

    const item = value as Partial<VirusTotalInfo>;
    const status = normalizzaVirusTotalStatus(item.status);

    if (!status) {
        return null;
    }

    return {
        checked: Boolean(item.checked),
        malicious: normalizzaConteggio(item.malicious),
        suspicious: normalizzaConteggio(item.suspicious),
        clean: normalizzaConteggio(item.clean),
        lastUpdate: normalizzaData(item.lastUpdate),
        status,
        label: typeof item.label == "string" ? item.label : status,
        note: typeof item.note == "string" ? item.note : ""
    };
}

function normalizzaVirusTotalStatus(value: unknown): VirusTotalStatus | null {
    if (typeof value != "string") {
        return null;
    }

    if (
        value == "NOT_CONFIGURED" ||
        value == "NOT_FOUND" ||
        value == "CLEAN" ||
        value == "SUSPICIOUS" ||
        value == "MALICIOUS" ||
        value == "UNAVAILABLE"
    ) {
        return value;
    }

    return null;
}

function creaVirusTotalInfo(
    status: VirusTotalStatus,
    checked: boolean,
    malicious: number,
    suspicious: number,
    clean: number,
    lastUpdate: Date | null,
    label: string,
    note: string
): VirusTotalInfo {
    return {
        checked,
        malicious,
        suspicious,
        clean,
        lastUpdate,
        status,
        label,
        note
    };
}

function normalizzaConteggio(value: unknown): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? Math.trunc(parsed) : 0;
}

function normalizzaUnixDate(value: unknown): Date | null {
    const parsed = Number(value);

    if (!Number.isFinite(parsed) || parsed <= 0) {
        return null;
    }

    const date = new Date(parsed * 1000);
    return Number.isNaN(date.getTime()) ? null : date;
}

function descriviErroreEsterno(err: unknown): string {
    if (axios.isAxiosError(err)) {
        const status = err.response?.status ? `HTTP ${err.response.status}` : err.code || "errore rete";
        return `${status}: ${err.message}`;
    }

    return err instanceof Error ? err.message : String(err);
}

async function risolviRecordDns<T>(resolver: () => Promise<T[]>): Promise<T[]> {
    try {
        return await withTimeout(resolver(), 5000);
    } catch {
        return [];
    }
}

function identificaProviderInfrastruttura(cnameRecords: string[], ips: string[]): string | null {
    const cname = cnameRecords.join(" ").toLowerCase();

    const providers = [
        { name: "Cloudflare", pattern: /cloudflare/ },
        { name: "Akamai", pattern: /akamai|edgesuite|edgekey/ },
        { name: "Amazon CloudFront", pattern: /cloudfront/ },
        { name: "Fastly", pattern: /fastly/ },
        { name: "Google Cloud", pattern: /googlehosted|googleusercontent|ghs\.google/ },
        { name: "Shopify", pattern: /myshopify|shops\.myshopify/ },
        { name: "Wix", pattern: /wixdns|wixsite/ },
        { name: "Squarespace", pattern: /squarespace/ }
    ];

    const cnameProvider = providers.find(provider => provider.pattern.test(cname))?.name;

    if (cnameProvider) {
        return cnameProvider;
    }

    if (ips.some(isCloudflareIp)) {
        return "Cloudflare";
    }

    return null;
}

function isIpLiteral(value: string): boolean {
    return net.isIP(normalizzaHostname(value)) != 0;
}

function isDominioPubblicoValido(hostname: string): boolean {
    const normalizedHost = normalizzaHostname(hostname);

    if (!normalizedHost.includes(".") || normalizedHost.length > 253) {
        return false;
    }

    const labels = normalizedHost.split(".");
    const tld = labels[labels.length - 1] || "";

    return labels.length >= 2 && labels.every(isEtichettaDnsValida) && isTldValido(tld);
}

function isEtichettaDnsValida(label: string): boolean {
    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
}

function isTldValido(tld: string): boolean {
    return /^[a-z]{2,63}$/.test(tld) || /^xn--[a-z0-9-]{2,59}$/.test(tld);
}

function isIpPubblico(ip: string): boolean {
    const normalizedIp = normalizzaHostname(ip);
    const ipVersion = net.isIP(normalizedIp);

    if (ipVersion == 4) {
        return isIpv4Pubblico(normalizedIp);
    }

    if (ipVersion == 6) {
        return isIpv6Pubblico(normalizedIp);
    }

    return false;
}

function isIpv4Pubblico(ip: string): boolean {
    const reservedRanges = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32"
    ];

    return !reservedRanges.some(range => isIpv4InCidr(ip, range));
}

function isIpv6Pubblico(ip: string): boolean {
    const normalizedIp = ip.toLowerCase();
    const ipv4MappedMatch = normalizedIp.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    const firstBlock = normalizedIp.split(":")[0] || "";
    const firstByte = Number.parseInt(firstBlock.slice(0, 2), 16);

    if (ipv4MappedMatch?.[1]) {
        return isIpv4Pubblico(ipv4MappedMatch[1]);
    }

    if (normalizedIp == "::" || normalizedIp == "::1") {
        return false;
    }

    if (/^fe[89a-f]/.test(normalizedIp)) {
        return false;
    }

    if (normalizedIp.startsWith("2001:db8:") || normalizedIp == "2001:db8::") {
        return false;
    }

    if (Number.isFinite(firstByte) && (firstByte & 0xfe) == 0xfc) {
        return false;
    }

    if (Number.isFinite(firstByte) && firstByte == 0xff) {
        return false;
    }

    return true;
}

function isCloudflareIp(ip: string): boolean {
    if (ip.startsWith("2606:4700:") || ip.startsWith("2a06:98c0:")) {
        return true;
    }

    const ranges = [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17"
    ];

    return ranges.some(range => isIpv4InCidr(ip, range));
}

function isIpv4InCidr(ip: string, cidr: string): boolean {
    const [rangeIp, prefixRaw] = cidr.split("/");
    const prefix = Number.parseInt(prefixRaw || "", 10);
    const ipNumber = ipv4ToNumber(ip);
    const rangeNumber = ipv4ToNumber(rangeIp || "");

    if (ipNumber == null || rangeNumber == null || !Number.isFinite(prefix)) {
        return false;
    }

    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (ipNumber & mask) === (rangeNumber & mask);
}

function ipv4ToNumber(ip: string): number | null {
    const parts = ip.split(".").map(part => Number.parseInt(part, 10));

    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) {
        return null;
    }

    return parts.reduce((value, part) => ((value << 8) + part) >>> 0, 0);
}

async function salvaAnalisi(
    url: string,
    hostname: string,
    score: number,
    results: AnalysisStoredResult
): Promise<StatsSummary> {
    const timestamp = new Date();

    try {
        const existingStats = await trovaStatsEsistenti(hostname, score, timestamp);

        if (existingStats) {
            console.log("Salvataggio non necessario per hostname:", hostname);
            return existingStats;
        }

        console.log("💾 Inizio salvataggio per hostname:", hostname);

        console.log("✍️ Inserting in url_checks - hostname:", hostname, "score:", score);
        
        const insertResult = await withMongoRetry(database => database.collection("url_checks").insertOne({
            url,
            hostname,
            timestamp,
            score,
            results,
            userFingerprint: "user_" + timestamp.getTime()
        }));

        if (!insertResult) {
            console.warn("Database non disponibile - ritorno stats default");
            return creaStatsDefault(score, timestamp);
        }
        
        console.log("✅ Inserito in url_checks con ID:", insertResult.insertedId);

        console.log("🔄 Aggiornamento atomico url_stats");

        const stats = await aggiornaStatsUrl(url, hostname, score, timestamp);

        if (!stats) {
            console.warn("Database non disponibile durante aggiornamento stats - ritorno stats default");
            return creaStatsDefault(score, timestamp);
        }

        console.log("✅ Salvataggio completato!");

        return stats;
    } catch (err) {
        console.error("❌ ERRORE salvataggio analisi:", err);
        return creaStatsDefault(score, timestamp);
    }
}

async function trovaStatsEsistenti(
    hostname: string,
    fallbackScore: number,
    fallbackTimestamp: Date
): Promise<StatsSummary | null> {
    const statsDocument = await withMongoRetry(database => database.collection("url_stats").findOne({ hostname }));

    if (statsDocument) {
        return creaStatsDaDocumento(statsDocument as Partial<UrlStatsDocument>, fallbackScore, fallbackTimestamp);
    }

    const checkDocument = await withMongoRetry(database => database.collection("url_checks").findOne(
        { hostname },
        { sort: { timestamp: -1 } }
    ));

    if (!checkDocument) {
        return null;
    }

    const existingScore = normalizzaNumero(checkDocument.score, fallbackScore);
    const existingTimestamp = normalizzaData(checkDocument.timestamp) || fallbackTimestamp;

    return creaStatsDefault(existingScore, existingTimestamp);
}

async function aggiornaStatsUrl(
    url: string,
    hostname: string,
    score: number,
    timestamp: Date
): Promise<StatsSummary | null> {
    const statsDocument = await withMongoRetry(database => database.collection("url_stats").findOneAndUpdate(
        { hostname },
        [
            {
                $set: {
                    url,
                    hostname,
                    firstCheck: { $ifNull: ["$firstCheck", timestamp] },
                    lastCheck: timestamp,
                    checkCount: { $add: [{ $ifNull: ["$checkCount", 0] }, 1] },
                    scoreTotal: {
                        $add: [
                            {
                                $ifNull: [
                                    "$scoreTotal",
                                    {
                                        $multiply: [
                                            { $ifNull: ["$avgScore", 0] },
                                            { $ifNull: ["$checkCount", 0] }
                                        ]
                                    }
                                ]
                            },
                            score
                        ]
                    }
                }
            },
            {
                $set: {
                    avgScore: { $divide: ["$scoreTotal", "$checkCount"] }
                }
            },
            {
                $set: {
                    riskLevel: {
                        $switch: {
                            branches: [
                                { case: { $gte: ["$avgScore", 70] }, then: "LOW" },
                                { case: { $gte: ["$avgScore", 40] }, then: "MEDIUM" }
                            ],
                            default: "HIGH"
                        }
                    }
                }
            }
        ],
        { upsert: true, returnDocument: "after" }
    ));

    return creaStatsDaDocumento(statsDocument as Partial<UrlStatsDocument> | null, score, timestamp);
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

function creaStatsDaDocumento(
    document: Partial<UrlStatsDocument> | null | undefined,
    fallbackScore: number,
    fallbackTimestamp: Date
): StatsSummary | null {
    if (!document) {
        return null;
    }

    const checkCount = normalizzaNumero(document.checkCount, 1);
    const avgScore = normalizzaNumero(document.avgScore, fallbackScore);
    const riskLevel = normalizzaRiskLevel(document.riskLevel) || calcolaLivelloRischio(avgScore);

    return {
        checkCount,
        firstCheck: normalizzaData(document.firstCheck) || fallbackTimestamp,
        lastCheck: normalizzaData(document.lastCheck) || fallbackTimestamp,
        avgScore,
        riskLevel
    };
}

function normalizzaNumero(value: unknown, fallback: number): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizzaRiskLevel(value: unknown): RiskLevel | null {
    if (value == "LOW" || value == "MEDIUM" || value == "HIGH") {
        return value as RiskLevel;
    }

    return null;
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
        const isIp = isIpLiteral(hostname);
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

        if (https == 100) reputazione += 20;
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

function calcolaPunteggio(risultato: UrlMetrics, eta: number, virusTotal?: VirusTotalInfo): number {
    const dominio = limitaPunteggio(risultato.dominio);
    const https = limitaPunteggio(risultato.https);
    const recensioni = limitaPunteggio(risultato.recensioni);
    const reputazione = limitaPunteggio(risultato.reputazione);
    const etaNorm = limitaPunteggio(eta);

    let punteggio =
        dominio * 0.25 +
        https * 0.15 +
        recensioni * 0.20 +
        reputazione * 0.20 +
        etaNorm * 0.20;

    if (virusTotal?.malicious && virusTotal.malicious > 0) {
        return 0;
    }

    if (virusTotal?.suspicious && virusTotal.suspicious > 0) {
        punteggio -= 25;
    }

    if (virusTotal?.clean && virusTotal.clean > 50) {
        punteggio += 5;
    }

    return Math.round(limitaPunteggio(punteggio));
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

async function avviaServer(): Promise<void> {
    await inizializzaDatabase();
    await caricaBlacklist();

    server = app.listen(port, function () {
        console.log("Server in ascolto sulla porta " + port);
    });
}

avviaServer().catch(err => {
    console.error("Errore avvio server:", err);
    process.exit(1);
});
