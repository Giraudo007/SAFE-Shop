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
    let dati = await inviaRichiesta("POST", "/analizza", { url });
    if (!dati) return;

    let punteggio = calcolaPunteggio(dati)

    aggiornaRisultato(punteggio);
    aggiornaDettagli(dati);
}




function calcolaPunteggio(dati) {
    const dominio = Math.min(Math.max(dati.dominio, 0), 100);
    const https = Math.min(Math.max(dati.https, 0), 100);
    const recensioni = Math.min(Math.max(dati.recensioni, 0), 100);
    const reputazione = Math.min(Math.max(dati.reputazione, 0), 100);
    const eta = Math.min(Math.max(dati.eta, 0), 100);

    const punteggio =
        dominio * 0.25 +
        https * 0.15 +
        recensioni * 0.20 +
        reputazione * 0.20 +
        eta * 0.20;

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

    document.getElementById("https").innerText = dati.https == 100 ? "Sicuro" : "Non sicuro";

    document.getElementById("recensioni").innerText = dati.recensioni;

    document.getElementById("reputazione").innerText = dati.reputazione;

    document.getElementById("eta").innerText = dati.eta;
}



function random(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}