//A. import delle librerie
import http from "http";
import fs from "fs";
import express from "express";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";
import queryStringParser from "./queryStringParser";
import cors from "cors";
import dns from "dns/promises";
import whois from "whois-json";
import axios from "axios";


//B. configurazioni
//riconosce i tipi automaticamente (non è any) -> grazie @types/node in devDependencies (sviluppo)
const app = express();
//stessa cosa -> const app: express.Express = express();
dotenv.config({ path: ".env" });
const connStr = process.env.connectionStringAtlas;
const port = parseInt(process.env.PORT!);
const dbName = process.env.dbName;
let blacklist: string[] = [];

//C. creazione ed avvio del server HTTP
const server: http.Server = http.createServer(app);
let paginaErr = "";

//server in ascolto sulla porta 1337
server.listen(port, async function () {
    console.log("Server in ascolto sulla porta " + port);

    fs.readFile("./static/error.html", function (err, content) { //content è una sequenza di byte
        if (err)
            paginaErr = "<h1>Risorsa non trovata</h1>";
        else
            paginaErr = content.toString();
    })

    try {
        const response = await axios.get(
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json"
        );

        blacklist = response.data;

        console.log("Blacklist caricata:", blacklist.length);

    } catch (err) {
        console.error("Errore caricamento blacklist", err);
    }
});

//D. middleware
//middleware 1: request log
app.use(function (req, res, next) //se si omette => come risorsa "/"
{
    console.log("Ricevuta richiesta: " + req.method + ": " + req.originalUrl);
    next(); //passa al middleware successivo
});

//middleware 2: gestione delle risorse statiche
app.use(express.static("./static"));

//middleware 3: gestione dei parametri post
app.use(express.json({ "limit": "5mb" })); //i parametri post sono restituiti in req.body
//i parametri get invece sono restituiti come json in req.query

//middleware 4: parsing dei parametri GET
app.use("/", queryStringParser);

//middleware 5: log dei parametri
app.use((req: any, res, next) => {
    if (req.body && Object.keys(req.body).length > 0)
        console.log("   Parametri body: " + JSON.stringify(req.body));

    if (req["parsedQuery"] && Object.keys(req["parsedQuery"]).length > 0)
        console.log("   Parametri query: " + JSON.stringify(req["parsedQuery"]));

    next();
});

//middleware 6: Vincoli CORS (controlli lato server che consentono di accettare richieste anche da fuori dal dominio -> cioè diverso dal server da cui arrivano le pagine)
const corsOptions = {
    origin: function (origin: any, callback: any) {
        return callback(null, true);
    },
    credentials: true
};
app.use("/", cors(corsOptions));


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

        const https = url.startsWith("https://") ? 100 : 0;

        let ip: any = "non trovato";
        let dnsValido = false;

        try {
            const addresses = await dns.resolve4(hostname); // più affidabile per ipv4
            if (addresses && addresses.length > 0) {
                ip = addresses[0];
                dnsValido = true;
            }
        } catch {
            dnsValido = false;
        }

        const cleanHost = hostname
            .replace(/^www\./, "")
            .toLowerCase();

        const dominioBlacklist = blacklist.some(d =>
            cleanHost === d || cleanHost.endsWith("." + d)
        );

        if (dominioBlacklist) {
            res.send({
                dominio: 0,
                https: 0,
                recensioni: 0,
                reputazione: 0,
                eta: 0,
                ip,
                blacklist: true
            });

            return;
        }

        const eta = await calcolaEtaDominio(hostname);

        const risultato = verificaUrl(url);

        res.send({
            dominio: risultato.dominio,
            https: risultato.https,
            recensioni: risultato.recensioni,
            reputazione: risultato.reputazione,
            eta,
            ip,
            blacklist: false
        });

    } catch (err) {
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

//F. default root e gestione errori
app.use(function (req, res) {
    if (req.originalUrl.startsWith("/api/"))
        res.status(404).send("Risorsa non trovata");
    else if (req.accepts("html"))
        res.status(404).send(paginaErr);
    else
        res.sendStatus(404)
});

//G. gestione errori
app.use(function (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) {
    console.error("*** ERRORE ***:\n" + err.stack); //elenco completo degli errori
    res.status(500).send("Errore interno del server");
});