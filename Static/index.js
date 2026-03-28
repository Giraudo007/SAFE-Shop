// ===============================
// SAFE-SHOP - LOGICA PRINCIPALE
// ===============================

// quando clicchi il bottone
document.getElementById("btnAnalizza").addEventListener("click", analizza);


// ===============================
// FUNZIONE PRINCIPALE
// ===============================
function analizza() {

    // prendo l'URL inserito
    let url = document.getElementById("txtUrl").value;

    // controllo base (se vuoto)
    if (url.trim() == "") {
        alert("Inserisci un URL!");
        return;
    }

    // ---------------------------
    // DATI SIMULATI (mock)
    // ---------------------------
    let dati = generaDatiFinti(url);

    // ---------------------------
    // CALCOLO PUNTEGGIO
    // ---------------------------
    let punteggio = calcolaPunteggio(dati);

    // ---------------------------
    // AGGIORNA UI
    // ---------------------------
    aggiornaRisultato(punteggio);
    aggiornaDettagli(dati);
}



// ===============================
// GENERA DATI RANDOM (SIMULAZIONE)
// ===============================
function generaDatiFinti(url) {

    return {
        dominio: random(20, 100),         // età dominio
        https: Math.random() > 0.3 ? 100 : 0,  // più probabile sicuro
        recensioni: random(30, 100),
        reputazione: random(20, 100)
    };
}



// ===============================
// CALCOLO PUNTEGGIO PESATO
// ===============================
function calcolaPunteggio(dati) {

    let punteggio =
        dati.dominio * 0.30 +
        dati.https * 0.15 +
        dati.recensioni * 0.25 +
        dati.reputazione * 0.30;

    return Math.round(punteggio);
}



// ===============================
// AGGIORNA RISULTATO PRINCIPALE
// ===============================
function aggiornaRisultato(punteggio) {

    let lblPercentuale = document.getElementById("lblPercentuale");
    let lblLivello = document.getElementById("lblLivello");

    lblPercentuale.innerText = punteggio + "%";

    // livello
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

    // colore del cerchio
    lblPercentuale.style.color = colore;
}



// ===============================
// AGGIORNA DETTAGLI
// ===============================
function aggiornaDettagli(dati) {

    document.getElementById("dominio").innerText = dati.dominio;

    document.getElementById("https").innerText =
        dati.https == 100 ? "Sicuro" : "Non sicuro";

    document.getElementById("recensioni").innerText =
        dati.recensioni;

    document.getElementById("reputazione").innerText =
        dati.reputazione;
}



// ===============================
// FUNZIONE RANDOM UTILE
// ===============================
function random(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}