async function inviaRichiesta(method, url = "", params = {}) {
    method = method.toUpperCase();
    url = "/api" + url;

    const options = {
        method,
        headers: {}
    };

    if (method === "GET" || method === "DELETE") {
        const queryParams = new URLSearchParams(params).toString();
        if (queryParams) {
            url += "?" + queryParams;
        }
    } else {
        options.body = JSON.stringify(params);
        options.headers["Content-Type"] = "application/json";
    }

    const response = await fetch(url, options);
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
        ? await response.json()
        : await response.text();

    if (!response.ok) {
        const message = payload && typeof payload === "object" && payload.error
            ? payload.error
            : payload || "Errore server";
        throw new Error(message);
    }

    return payload;
}
