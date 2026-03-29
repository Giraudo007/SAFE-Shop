//A. import delle librerie
import http from "http";
import fs from "fs";
import express from "express";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import queryStringParser from "./queryStringParser";
import cors from "cors";

//B. configurazioni
//riconosce i tipi automaticamente (non è any) -> grazie @types/node in devDependencies (sviluppo)
const app = express();
//stessa cosa -> const app: express.Express = express();
dotenv.config({ path: ".env" });
const connStr = process.env.connectionStringAtlas;
const port = parseInt(process.env.PORT!);
const dbName = process.env.dbName;

//C. creazione ed avvio del server HTTP
const server: http.Server = http.createServer(app);
let paginaErr = "";

//server in ascolto sulla porta 1337
server.listen(port, function () {
    console.log("Server in ascolto sulla porta " + port);

    fs.readFile("./static/error.html", function (err, content) { //content è una sequenza di byte
        if (err)
            paginaErr = "<h1>Risorsa non trovata</h1>";
        else
            paginaErr = content.toString();
    })
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
app.get("/api/getCollections", async function (req, res, next) {
    const client = new MongoClient(connStr!);

    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const db = client.db(dbName);

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await db.listCollections().toArray().catch(err => res.status(500).send("Errore lettura collezioni: " + err));

    res.send(data);

    client.close();
});

//con filtri
app.get("/api/:collection", async (req: any, res, next) => {
    const selectedCollection = req.params.collection;
    const filters = req["parsedQuery"];

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.find(filters).toArray();

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

app.get("/api/:collection/:id", async (req, res, next) => {
    const selectedCollection = req.params.collection;
    const id = req.params.id;

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.findOne({ "_id": new ObjectId(id) });

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

app.post("/api/:collection/", async (req, res, next) => {
    const selectedCollection = req.params.collection;
    const newRecord = req.body;

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.insertOne(newRecord);

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

app.patch("/api/:collection/:id", async (req, res, next) => {
    const selectedCollection = req.params.collection;
    const id = req.params.id;
    const action = req.body;

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.updateOne({ "_id": new ObjectId(id) }, { "$set": action });

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

app.delete("/api/:collection/:id", async (req, res, next) => {
    const selectedCollection = req.params.collection;
    const _id = req.params.id;

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.deleteOne({ "_id": new ObjectId(_id) });

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

app.delete("/api/:collection", async (req: any, res, next) => {
    const selectedCollection = req.params.collection;
    const filters = req["parsedQuery"];

    const client = new MongoClient(connStr!);
    await client.connect().catch(err => {
        res.status(503).send("Errore di connessione al DBMS")
        return;
    });

    const collection = client.db(dbName).collection(selectedCollection);

    const cmd = collection.deleteMany(filters);

    //restituisce elenco delle collezioni del db (formato JSON)
    const data = await cmd.catch(err => res.status(500).send("Errore di connessione al dbms: " + err));

    res.send(data);

    client.close();
})

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