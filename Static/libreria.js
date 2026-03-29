async function inviaRichiesta(method, url="", params={}) {
	method = method.toUpperCase()
	url = "/api" + url;	

	let options = {
		method: method,
		headers: {},
	}

	if(method=="GET" || method=="DELETE") {
		const queryParams = new URLSearchParams(params);
		url += "?" + queryParams.toString();
	}
	else {
		options.body = JSON.stringify(params)
		options.headers["Content-Type"]="application/json";  
	}

	try{
		const response = await fetch(url, options);

		if (!response.ok) {
			let err = await response.text();
			throw err;
		}

		return await response.json();
	}
	catch(err){
		console.error(err);
		alert("Errore server");
	}
}