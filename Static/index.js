"use strict"

document.getElementById("btnAnalizza").addEventListener("click", analizza);

function analizza() {
    alert("Funziona!");
}

function analizza() {

    let dati = {
        dominio: Math.floor(Math.random() * 100),
        https: Math.random() > 0.5 ? 100 : 0,
        recensioni: Math.floor(Math.random() * 100),
        reputazione: Math.floor(Math.random() * 100)
    };

    console.log(dati);
}