"use strict"

window.onload = function () {

    let btn = document.getElementById("btnAnalizza");
    btn.addEventListener("click", analizza);
}

async function analizza() {

    let url = document.getElementById("txtUrl").value;

    if (!url) {
        alert("Inserisci un URL");
        return;
    }

    // let risposta = await inviaRichiesta("POST", "/analizza", { url });

    // if (!risposta) return;
    let dati = verificaUrl(url)

    let punteggio = calcolaPunteggio(dati)

    aggiornaRisultato(punteggio);
    aggiornaDettagli(dati);
}



function verificaUrl(url) {

    const https = url.startsWith("https://") ? 100 : 0;


    let dominio = 80;

    try {
        const parsed   = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const parts    = hostname.split(".");
        const sld      = parts[parts.length - 2] || "";

        const tldRischiosi       = /\.(xyz|tk|top|click|gq|ml|cf|ga|pw|icu|buzz|rest|skin|monster|cyou|cc|ws|su)$/i;
        const isIp               = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
        const paroleSospetteSld  = /login|secure|verify|paypa|amaz0n|amaz|ebay1|account|update|confirm|banking|wallet|signin/i;
        const trattinoMultiplo   = (sld.match(/-/g) || []).length >= 2;
        const sottodominiEccessivi = parts.length > 3 && !hostname.startsWith("www.");
        const numereMistiLettere = /[a-z]+\d+[a-z]+|\d+[a-z]+\d+/i.test(sld);
        const urlLungo            = url.length > 100;

        if (isIp)                        dominio -= 50;  
        if (tldRischiosi.test(hostname)) dominio -= 10; 
        if (paroleSospetteSld.test(sld)) dominio -= 20;
        if (numereMistiLettere)          dominio -= 15;
        if (trattinoMultiplo)            dominio -= 10;
        if (sottodominiEccessivi)        dominio -= 5;
        if (urlLungo)                    dominio -= 5;
        if (/\.(gov|edu|org)$/.test(hostname)) dominio += 10; 

        dominio = Math.min(Math.max(dominio, 0), 100);

    } catch {
        dominio = 10;
    }

    let recensioni = 50;

    try {
        const parsed   = new URL(url);
        const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
        const dominioSemplice = hostname.split(".")[0].length <= 8 && !/[-\d]/.test(hostname.split(".")[0]);
        const pathProfondo    = parsed.pathname.split("/").filter(Boolean).length >= 2;
        const troppiParam     = [parsed.searchParams.keys()].length > 4;

        if (dominioSemplice) recensioni += 25; 
        if (pathProfondo)    recensioni += 10; 
        if (troppiParam)     recensioni -= 15;

        recensioni = Math.min(Math.max(recensioni, 0), 100);

    } catch {
        recensioni = 20;
    }

    // REPUTAZIONE / INDICE DI FIDUCIA
    let reputazione = 60; 

    try {
        const parsed   = new URL(url);
        const fullUrl  = url.toLowerCase();
        const pathname = parsed.pathname.toLowerCase();

        const paroleRosse    = /free|hack|crack|keygen|warez|pirat|cheat|nulled|phish|malware/i;
        const paroleArancioni = /download|gift|prize|winner|reward|promo|discount/i;
        const redirect       = /redirect|redir|goto|out\.php|click\.php/i;
        const fileEseguibile = /\.(exe|bat|msi|dmg|apk|zip|rar|7z)$/i;
        const encodingSospetto = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length > 5;

        if (https == 100)                   reputazione += 20;
        if (paroleRosse.test(fullUrl))      reputazione -= 35;
        if (paroleArancioni.test(pathname)) reputazione -= 15;
        if (redirect.test(pathname))        reputazione -= 20;
        if (fileEseguibile.test(pathname))  reputazione -= 25;
        if (encodingSospetto)               reputazione -= 15;

        reputazione = Math.min(Math.max(reputazione, 0), 100);

    } catch {
        reputazione = 10;
    }

    return { dominio, https, recensioni, reputazione };
}



function calcolaPunteggio(dati) {
    const dominio = Math.min(Math.max(dati.dominio, 0), 100);
    const https = Math.min(Math.max(dati.https, 0), 100);
    const recensioni = Math.min(Math.max(dati.recensioni, 0), 100);
    const reputazione = Math.min(Math.max(dati.reputazione, 0), 100);

    const punteggio = 
        dominio * 0.30 +
        https * 0.15 +
        recensioni * 0.25 +
        reputazione * 0.30;

    return Math.round(punteggio);
}



// AGGIORNA RISULTATO PRINCIPALE
function aggiornaRisultato(punteggio) {

    let lblPercentuale = document.getElementById("lblPercentuale");
    let lblLivello = document.getElementById("lblLivello");

    lblPercentuale.innerText = punteggio + "%";

    let livello = "";
    let colore = "";

    if (punteggio >= 70) {
        livello = "Affidabile";
        colore = "green";
    }
    else if (punteggio >= 40) {
        livello = "Medio";
        colore = "orange";
    }
    else {
        livello = "Rischioso";
        colore = "red";
    }

    lblLivello.innerText = livello;

    lblPercentuale.style.color = colore;
}



// AGGIORNA DETTAGLI
function aggiornaDettagli(dati) {

    document.getElementById("dominio").innerText = dati.dominio;

    document.getElementById("https").innerText =
        dati.https == 100 ? "Sicuro" : "Non sicuro";

    document.getElementById("recensioni").innerText =
        dati.recensioni;

    document.getElementById("reputazione").innerText =
        dati.reputazione;
}



function random(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}