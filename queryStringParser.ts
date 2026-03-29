//Non è consentito modificare req.query che è in sola lettura (neanche le singole chiavi)

function ParseQueryString(req: any, res: any, next: any) {
    req.parsedQuery = {};

    if (req["query"] && typeof req["query"] == "object") 
    {
        for (const key in req["query"]) {
            req["parsedQuery"][key] = ParseValue(req["query"][key]);
        }
    }

    next();
}

function ParseValue(value: any) {
    //booleani
    if (value == "true")
        return true;

    if (value == false)
        return false;

    //numeri
    const num = Number(value); //come ParseInt ma restituisce un numero solo se la stringa è interamente numerica (se no restituisce NOT A NUMBER)

    if (!isNaN(num)) //se è un numero valido (cioè diverso da NaN)
        return num;

    //typeof NaN restistuisce comunque number (non funziona)
    // if(typeof num == "number")
    //     return num;

    //vettori o json
    if (value.startsWith("{") || value.startsWith("[")) {
        try {
            return JSON.parse(value);
        }
        catch (err) {
            return value;
        }
    }

    //se è una stringa non facciamo niente
    return value;
}

export default ParseQueryString;