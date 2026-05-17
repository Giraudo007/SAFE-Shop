"use strict";

let isLoading = false;

const virusTotalCardClasses = ["is-success", "is-warning", "is-danger", "vt-clean", "vt-warning", "vt-danger", "vt-muted"];

const popularSites = [
    {
        name: "Temu",
        url: "https://www.temu.com",
        tag: "Marketplace",
        note: "Offerte molto cercate"
    },
    {
        name: "AliExpress",
        url: "https://www.aliexpress.com",
        tag: "Marketplace",
        note: "Venditori internazionali"
    },
    {
        name: "Shein",
        url: "https://www.shein.com",
        tag: "Moda",
        note: "Shopping low cost"
    },
    {
        name: "Vinted",
        url: "https://www.vinted.it",
        tag: "Second hand",
        note: "Acquisti tra utenti"
    },
    {
        name: "Subito",
        url: "https://www.subito.it",
        tag: "Annunci",
        note: "Vendite tra privati"
    },
    {
        name: "eBay",
        url: "https://www.ebay.it",
        tag: "Aste e shop",
        note: "Marketplace storico"
    },
    {
        name: "Etsy",
        url: "https://www.etsy.com",
        tag: "Artigianato",
        note: "Negozi indipendenti"
    },
    {
        name: "Wish",
        url: "https://www.wish.com",
        tag: "Marketplace",
        note: "Prodotti a basso prezzo"
    }
];

window.onload = function () {
    const btn = document.getElementById("btnAnalizza");
    const input = document.getElementById("txtUrl");

    btn.addEventListener("click", analizza);
    input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            analizza();
        }
    });

    renderSitiPopolari();
};

async function analizza(urlSuggerito) {
    if (isLoading) return;

    const input = document.getElementById("txtUrl");
    const url = typeof urlSuggerito === "string" ? urlSuggerito : input.value.trim();

    if (typeof urlSuggerito === "string") {
        input.value = url;
    }

    if (!url) {
        mostraFeedback("Inserisci un URL da analizzare.", "error");
        input.focus();
        return;
    }

    resetAnalisi();
    setLoading(true);
    mostraFeedback("", "");

    try {
        const dati = await inviaRichiesta("POST", "/analizza", { url });
        const punteggio = Number.isFinite(dati.score) ? dati.score : calcolaPunteggio(dati);

        aggiornaRisultato(punteggio);
        aggiornaDettagli(dati);
        aggiornaStats(dati.stats);
        mostraFeedback("Analisi completata.", "success");
    } catch (err) {
        const message = err instanceof Error ? err.message : "Errore durante l'analisi.";
        mostraFeedback(message, "error");
    } finally {
        setLoading(false);
    }
}

function resetAnalisi() {
    const lblPercentuale = document.getElementById("lblPercentuale");
    const lblLivello = document.getElementById("lblLivello");
    const circle = document.querySelector(".score-circle");
    const ipCard = document.getElementById("ipCard");
    const blacklistCard = document.getElementById("blacklistCard");
    const virusTotalCard = document.getElementById("virusTotalCard");
    const riskLevel = document.getElementById("riskLevel");

    lblPercentuale.innerText = "--%";
    lblPercentuale.style.color = "var(--text)";
    lblLivello.innerText = "In attesa di analisi";

    circle.classList.remove("risk-low", "risk-medium", "risk-high");

    setText("dominio", "--");
    setText("https", "--");
    setText("recensioni", "--");
    setText("reputazione", "--");
    setText("eta", "--");
    setText("ipStatus", "--");
    setText("ip", "IP non ancora verificato");
    setText("ipNote", "Stato tecnico del dominio");
    setText("blacklist", "--");
    setText("virusTotalStatus", "--");
    setText("virusTotalBadge", "In attesa");
    setText("virusTotalMalicious", "--");
    setText("virusTotalSuspicious", "--");
    setText("virusTotalClean", "--");
    setText("virusTotalNote", "Reputazione malware del dominio o IP");

    ipCard.classList.remove("is-success", "is-warning");
    blacklistCard.classList.remove("is-danger");
    setVirusTotalCardState(virusTotalCard, "vt-muted");

    setText("checkCount", "0");
    setText("avgScore", "-");
    setText("firstCheck", "-");
    setText("lastCheck", "-");
    riskLevel.innerText = "-";
    riskLevel.style.color = "var(--text)";
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
    aggiornaInfrastruttura(dati);
    setText("blacklist", dati.blacklist ? "Presente" : "Non presente");
    aggiornaVirusTotal(dati.virusTotal);

    const blacklistCard = document.getElementById("blacklistCard");
    blacklistCard.classList.toggle("is-danger", Boolean(dati.blacklist));
}

function aggiornaInfrastruttura(dati) {
    const info = dati.ipInfo || {};
    const ipCard = document.getElementById("ipCard");
    const ips = formatIpList(info);
    const label = info.label || (dati.ip && dati.ip !== "non trovato" ? "DNS OK" : "DNS non risolto");
    const note = info.note || "L'IP e un segnale tecnico, non una garanzia assoluta.";
    const status = info.status || (dati.ip && dati.ip !== "non trovato" ? "OK" : "WARNING");

    setText("ipStatus", label);
    setText("ip", ips);
    setText("ipNote", note);

    ipCard.classList.toggle("is-success", status === "OK");
    ipCard.classList.toggle("is-warning", status !== "OK");
}

function aggiornaVirusTotal(info) {
    const virusTotalCard = document.getElementById("virusTotalCard");

    if (!info) {
        setText("virusTotalStatus", "Non disponibile");
        setText("virusTotalBadge", "Non disponibile");
        setText("virusTotalMalicious", "0");
        setText("virusTotalSuspicious", "0");
        setText("virusTotalClean", "0");
        setText("virusTotalNote", "Il controllo VirusTotal non ha restituito risultati.");
        setVirusTotalCardState(virusTotalCard, "vt-muted");
        return;
    }

    const malicious = normalizzaConteggio(info.malicious);
    const suspicious = normalizzaConteggio(info.suspicious);
    const clean = normalizzaConteggio(info.clean);
    const view = getVirusTotalView(info, malicious, suspicious, clean);

    setText("virusTotalStatus", info.label || "Non disponibile");
    setText("virusTotalBadge", view.badge);
    setText("virusTotalMalicious", formatCount(malicious));
    setText("virusTotalSuspicious", formatCount(suspicious));
    setText("virusTotalClean", formatCount(clean));
    setText("virusTotalNote", formatVirusTotalNote(info));

    setVirusTotalCardState(virusTotalCard, view.className);
}

function getVirusTotalView(info, malicious, suspicious, clean) {
    if (malicious > 0 || info.status === "MALICIOUS") {
        return { badge: "Bloccato", className: "vt-danger" };
    }

    if (suspicious > 0 || info.status === "SUSPICIOUS") {
        return { badge: "Da verificare", className: "vt-warning" };
    }

    if (info.status === "CLEAN" || clean > 0) {
        return { badge: "Pulito", className: "vt-clean" };
    }

    if (info.status === "UNAVAILABLE") {
        return { badge: "Non raggiunto", className: "vt-warning" };
    }

    if (info.status === "NOT_CONFIGURED") {
        return { badge: "Non attivo", className: "vt-muted" };
    }

    if (info.status === "NOT_FOUND") {
        return { badge: "Nessun dato", className: "vt-muted" };
    }

    return { badge: "Neutro", className: "vt-muted" };
}

function formatVirusTotalNote(info) {
    const note = info.note || "Stato VirusTotal non disponibile.";
    const lastUpdate = info.lastUpdate ? " Ultimo aggiornamento: " + formatDate(info.lastUpdate) + "." : "";
    return note + lastUpdate;
}

function setVirusTotalCardState(card, className) {
    card.classList.remove(...virusTotalCardClasses);
    card.classList.add(className);
}

function normalizzaConteggio(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? Math.trunc(parsed) : 0;
}

function formatIpList(info) {
    const ipv4 = Array.isArray(info.ipv4) ? info.ipv4 : [];
    const ipv6 = Array.isArray(info.ipv6) ? info.ipv6 : [];
    const parts = [];

    if (ipv4.length > 0) {
        parts.push("IPv4: " + ipv4.slice(0, 3).join(", "));
    }

    if (ipv6.length > 0) {
        parts.push("IPv6: " + ipv6.slice(0, 2).join(", "));
    }

    if (parts.length === 0 && info.primary && info.primary !== "non trovato") {
        parts.push("IP: " + info.primary);
    }

    return parts.length > 0 ? parts.join(" | ") : "Nessun IP trovato";
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

function renderSitiPopolari() {
    const container = document.getElementById("popularSites");

    if (!container) {
        return;
    }

    container.innerHTML = "";

    popularSites.forEach(function (site) {
        const card = document.createElement("article");
        card.className = "popular-site";

        const header = document.createElement("div");
        header.className = "popular-site-head";

        const name = document.createElement("strong");
        name.innerText = site.name;

        const tag = document.createElement("span");
        tag.innerText = site.tag;

        const url = document.createElement("span");
        url.className = "popular-site-url";
        url.innerText = site.url.replace("https://www.", "");

        const note = document.createElement("p");
        note.innerText = site.note;

        const button = document.createElement("button");
        button.type = "button";
        button.className = "popular-site-action";
        button.innerText = "Analizza";
        button.addEventListener("click", function () {
            analizza(site.url);
        });

        header.appendChild(name);
        header.appendChild(tag);
        card.appendChild(header);
        card.appendChild(url);
        card.appendChild(note);
        card.appendChild(button);
        container.appendChild(card);
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

function formatCount(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? String(parsed) : "0";
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
