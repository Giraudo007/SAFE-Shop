"use strict";

let isLoading = false;

window.onload = function () {
    const btn = document.getElementById("btnAnalizza");
    const input = document.getElementById("txtUrl");

    btn.addEventListener("click", analizza);
    input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            analizza();
        }
    });
};

async function analizza() {
    if (isLoading) return;

    const input = document.getElementById("txtUrl");
    const url = input.value.trim();

    if (!url) {
        mostraFeedback("Inserisci un URL da analizzare.", "error");
        input.focus();
        return;
    }

    setLoading(true);
    mostraFeedback("", "");

    try {
        const dati = await inviaRichiesta("POST", "/analizza", { url });
        const punteggio = Number.isFinite(dati.score) ? dati.score : calcolaPunteggio(dati);

        aggiornaRisultato(punteggio);
        aggiornaDettagli(dati);
        aggiornaStats(dati.stats);
        mostraFeedback("Analisi completata.", "success");

        await aggiornaCronologia(dati.hostname);
    } catch (err) {
        const message = err instanceof Error ? err.message : "Errore durante l'analisi.";
        mostraFeedback(message, "error");
    } finally {
        setLoading(false);
    }
}

function calcolaPunteggio(dati) {
    const dominio = limitaPunteggio(dati.dominio);
    const https = limitaPunteggio(dati.https);
    const recensioni = limitaPunteggio(dati.recensioni);
    const reputazione = limitaPunteggio(dati.reputazione);
    const eta = limitaPunteggio(dati.eta);

    const punteggio =
        dominio * 0.25 +
        https * 0.15 +
        recensioni * 0.20 +
        reputazione * 0.20 +
        eta * 0.20;

    return Math.round(punteggio);
}

function aggiornaRisultato(punteggio) {
    const lblPercentuale = document.getElementById("lblPercentuale");
    const lblLivello = document.getElementById("lblLivello");
    const circle = document.querySelector(".score-circle");
    const risk = getRiskInfo(punteggio);

    lblPercentuale.innerText = punteggio + "%";
    lblPercentuale.style.color = risk.color;
    lblLivello.innerText = risk.label;

    circle.classList.remove("risk-low", "risk-medium", "risk-high");
    circle.classList.add(risk.className);
}

function aggiornaDettagli(dati) {
    setText("dominio", formatScore(dati.dominio));
    setText("https", dati.https === 100 ? "Sicuro" : "Non sicuro");
    setText("recensioni", formatScore(dati.recensioni));
    setText("reputazione", formatScore(dati.reputazione));
    setText("eta", formatScore(dati.eta));
    setText("ip", dati.ip || "non trovato");
    setText("blacklist", dati.blacklist ? "Presente" : "Non presente");

    const blacklistCard = document.getElementById("blacklistCard");
    blacklistCard.classList.toggle("is-danger", Boolean(dati.blacklist));
}

function aggiornaStats(stats) {
    if (!stats) return;

    setText("checkCount", stats.checkCount || 0);
    setText("avgScore", Number(stats.avgScore || 0).toFixed(1));
    setText("firstCheck", formatDate(stats.firstCheck));
    setText("lastCheck", formatDate(stats.lastCheck));

    const riskLevel = document.getElementById("riskLevel");
    const risk = getRiskInfoFromLevel(stats.riskLevel);
    riskLevel.innerText = stats.riskLevel || "SCONOSCIUTO";
    riskLevel.style.color = risk.color;
}

async function aggiornaCronologia(hostname) {
    const historyList = document.getElementById("historyList");
    const historyEmpty = document.getElementById("historyEmpty");

    if (!hostname) {
        renderCronologia([]);
        return;
    }

    try {
        const data = await inviaRichiesta("GET", "/history/" + encodeURIComponent(hostname));
        renderCronologia(data.history || []);
    } catch {
        historyList.innerHTML = "";
        historyEmpty.innerText = "Cronologia non disponibile.";
        historyEmpty.hidden = false;
    }
}

function renderCronologia(history) {
    const historyList = document.getElementById("historyList");
    const historyEmpty = document.getElementById("historyEmpty");

    historyList.innerHTML = "";

    if (!history.length) {
        historyEmpty.innerText = "Nessuna cronologia disponibile.";
        historyEmpty.hidden = false;
        return;
    }

    historyEmpty.hidden = true;

    history.forEach(function (item) {
        const risk = getRiskInfo(item.score || 0);
        const row = document.createElement("div");
        row.className = "history-item";

        const meta = document.createElement("div");
        meta.className = "history-meta";

        const date = document.createElement("strong");
        date.innerText = formatDate(item.timestamp);

        const details = document.createElement("span");
        details.innerText = item.results && item.results.blacklist
            ? "Blacklist rilevata"
            : "Analisi standard";

        const score = document.createElement("span");
        score.className = "history-score " + risk.className;
        score.innerText = (item.score || 0) + "%";

        meta.appendChild(date);
        meta.appendChild(details);
        row.appendChild(meta);
        row.appendChild(score);
        historyList.appendChild(row);
    });
}

function setLoading(value) {
    isLoading = value;

    const btn = document.getElementById("btnAnalizza");
    const input = document.getElementById("txtUrl");

    btn.disabled = value;
    input.disabled = value;
    btn.innerText = value ? "Analisi..." : "Analizza";
}

function mostraFeedback(message, type) {
    const feedback = document.getElementById("feedback");

    feedback.innerText = message;
    feedback.className = "feedback";

    if (type) {
        feedback.classList.add(type);
    }
}

function getRiskInfo(score) {
    if (score >= 70) {
        return {
            label: "Affidabile",
            color: "var(--green)",
            className: "risk-low"
        };
    }

    if (score >= 40) {
        return {
            label: "Medio",
            color: "var(--yellow)",
            className: "risk-medium"
        };
    }

    return {
        label: "Rischioso",
        color: "var(--red)",
        className: "risk-high"
    };
}

function getRiskInfoFromLevel(level) {
    if (level === "LOW") return getRiskInfo(70);
    if (level === "MEDIUM") return getRiskInfo(40);
    if (level === "HIGH") return getRiskInfo(0);
    return { color: "var(--text)", className: "" };
}

function limitaPunteggio(value) {
    const numberValue = Number(value);
    if (!Number.isFinite(numberValue)) return 0;
    return Math.min(Math.max(numberValue, 0), 100);
}

function formatScore(value) {
    return limitaPunteggio(value) + "/100";
}

function formatDate(value) {
    if (!value) return "-";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "-";

    return date.toLocaleString("it-IT", {
        dateStyle: "short",
        timeStyle: "short"
    });
}

function setText(id, value) {
    document.getElementById(id).innerText = value;
}
