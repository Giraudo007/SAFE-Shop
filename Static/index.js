"use strict";

let isLoading = false;
let isGeminiLoading = false;
let lastAnalysisData = null;
let geminiHistory = [];

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
    const geminiForm = document.getElementById("geminiForm");
    const quickPrompts = document.querySelectorAll(".ai-chip");

    btn.addEventListener("click", analizza);
    geminiForm.addEventListener("submit", function (event) {
        event.preventDefault();
        inviaDomandaGemini();
    });
    quickPrompts.forEach(function (button) {
        button.addEventListener("click", function () {
            inviaDomandaGemini(button.dataset.question || button.innerText);
        });
    });
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
        lastAnalysisData = {
            ...dati,
            url,
            score: punteggio,
            riskLevel: getRiskLevelCode(punteggio)
        };

        aggiornaRisultato(punteggio);
        aggiornaDettagli(dati);
        aggiornaStats(dati.stats);
        resetChatAi(true);
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

    lastAnalysisData = null;
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
    resetChatAi(false);
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

async function inviaDomandaGemini(domandaRapida) {
    if (isGeminiLoading || !lastAnalysisData) {
        return;
    }

    const input = document.getElementById("geminiQuestion");
    const question = typeof domandaRapida === "string" ? domandaRapida.trim() : input.value.trim();

    if (!question) {
        input.focus();
        return;
    }

    input.value = "";
    aggiungiMessaggioChat("user", question);
    const pendingMessage = aggiungiMessaggioChat("assistant", "Sto controllando analisi tecnica e informazioni pubbliche...");
    setGeminiLoading(true);
    setText("geminiMeta", "");

    try {
        const response = await inviaRichiesta("POST", "/gemini/chat", {
            url: lastAnalysisData.url,
            hostname: lastAnalysisData.hostname,
            score: lastAnalysisData.score,
            riskLevel: lastAnalysisData.riskLevel,
            results: lastAnalysisData,
            question,
            history: geminiHistory.slice(-8)
        });
        const answer = response.answer || "Gemini non ha restituito una risposta.";

        aggiornaMessaggioChat(pendingMessage, answer, response.sources || []);
        salvaTurnoChat("user", question);
        salvaTurnoChat("model", answer);
        setText("geminiMeta", response.model ? "Modello: " + response.model + " - Area: " + response.location : "");
    } catch (err) {
        const message = err instanceof Error ? err.message : "Gemini non disponibile.";
        aggiornaMessaggioChat(pendingMessage, message, []);
        setText("geminiMeta", "Controlla login ADC, progetto Google Cloud e Vertex AI API.");
    } finally {
        setGeminiLoading(false);
    }
}

function resetChatAi(enabled) {
    geminiHistory = [];
    setText("geminiMeta", "");
    svuotaChatAi(enabled
        ? "Analisi completata. Puoi chiedermi se i prodotti sembrano attendibili, se ci sono reclami pubblici o chi c'e dietro al sito."
        : "Esegui un'analisi e poi chiedimi informazioni sul sito.");
    abilitaChatAi(Boolean(enabled));
}

function svuotaChatAi(message) {
    const chat = document.getElementById("geminiChat");

    chat.innerHTML = "";
    aggiungiMessaggioChat("assistant", message);
}

function aggiungiMessaggioChat(role, text, sources) {
    const chat = document.getElementById("geminiChat");
    const message = document.createElement("div");
    const paragraph = document.createElement("p");

    message.className = role === "user" ? "ai-message ai-message-user" : "ai-message ai-message-assistant";
    paragraph.innerText = text;
    message.appendChild(paragraph);
    aggiungiFontiMessaggio(message, sources || []);
    chat.appendChild(message);
    chat.scrollTop = chat.scrollHeight;

    return message;
}

function aggiornaMessaggioChat(message, text, sources) {
    const paragraph = message.querySelector("p");

    paragraph.innerText = text;
    message.querySelectorAll(".ai-sources").forEach(function (sourceBlock) {
        sourceBlock.remove();
    });
    aggiungiFontiMessaggio(message, sources || []);

    const chat = document.getElementById("geminiChat");
    chat.scrollTop = chat.scrollHeight;
}

function aggiungiFontiMessaggio(message, sources) {
    if (!Array.isArray(sources) || sources.length === 0) {
        return;
    }

    const list = document.createElement("div");
    list.className = "ai-sources";

    sources.slice(0, 5).forEach(function (source) {
        const link = document.createElement("a");
        link.href = source.uri;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.innerText = source.domain || source.title || "Fonte";
        list.appendChild(link);
    });

    message.appendChild(list);
}

function salvaTurnoChat(role, text) {
    geminiHistory.push({ role, text });

    if (geminiHistory.length > 10) {
        geminiHistory = geminiHistory.slice(-10);
    }
}

function abilitaChatAi(value) {
    const input = document.getElementById("geminiQuestion");
    const btn = document.getElementById("btnInviaAi");
    const quickPrompts = document.querySelectorAll(".ai-chip");
    const disabled = !value || isLoading || isGeminiLoading;

    input.disabled = disabled;
    btn.disabled = disabled;
    quickPrompts.forEach(function (button) {
        button.disabled = disabled;
    });
}

function setGeminiLoading(value) {
    isGeminiLoading = value;

    const btn = document.getElementById("btnInviaAi");

    btn.disabled = value || !lastAnalysisData;
    btn.innerText = value ? "Cerco..." : "Invia";
    abilitaChatAi(Boolean(lastAnalysisData) && !value);
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
    abilitaChatAi(Boolean(lastAnalysisData) && !value);
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

function getRiskLevelCode(score) {
    if (score >= 70) return "LOW";
    if (score >= 40) return "MEDIUM";
    return "HIGH";
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
