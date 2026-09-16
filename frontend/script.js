const API_BASE = "http://127.0.0.1:8000/api";

async function checkPassword() {
    const pwd = document.getElementById("pwdInput").value;
    const resDiv = document.getElementById("pwdResult");
    if (!pwd) return;
    
    resDiv.classList.remove("hidden");
    resDiv.innerHTML = "<span class='text-gray-400'>Analyse en cours...</span>";
    
    try {
        const response = await fetch(`${API_BASE}/check-password`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: pwd })
        });
        const data = await response.json();
        
        let color = data.level === "Fort" ? "text-green-400" : (data.level === "Moyen" ? "text-yellow-400" : "text-red-400");
        let html = `<div><strong>Niveau :</strong> <span class="${color}">${data.level}</span> (Score: ${data.score}%)</div>`;
        html += `<div><strong>Fuites :</strong> ${data.leaked_count} occurrence(s) trouvée(s)</div>`;
        if (data.feedback && data.feedback.length > 0) {
            html += `<ul class='list-disc list-inside text-xs text-gray-300 mt-2 space-y-1'>`;
            data.feedback.forEach(f => html += `<li>${f}</li>`);
            html += `</ul>`;
        }
        resDiv.innerHTML = html;
    } catch (err) {
        resDiv.innerHTML = "<span class='text-red-400'>Erreur de connexion au serveur.</span>";
    }
}

async function checkEmail() {
    const email = document.getElementById("emailInput").value;
    const resDiv = document.getElementById("emailResult");
    if (!email) return;
    
    resDiv.classList.remove("hidden");
    resDiv.innerHTML = "<span class='text-gray-400'>Vérification en cours...</span>";
    
    try {
        const response = await fetch(`${API_BASE}/check-email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email })
        });
        const data = await response.json();
        resDiv.innerHTML = `<div><strong>Email :</strong> ${data.email}</div><div><strong>Statut :</strong> ${data.status}</div>`;
    } catch (err) {
        resDiv.innerHTML = "<span class='text-red-400'>Erreur de connexion au serveur.</span>";
    }
}

async function checkIP() {
    const ip = document.getElementById("ipInput").value;
    const resDiv = document.getElementById("ipResult");
    if (!ip) return;
    
    resDiv.classList.remove("hidden");
    resDiv.innerHTML = "<span class='text-gray-400'>Analyse en cours...</span>";
    
    try {
        const response = await fetch(`${API_BASE}/check-ip`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip })
        });
        const data = await response.json();
        resDiv.innerHTML = `<div><strong>IP :</strong> ${data.ip}</div><div><strong>Risque :</strong> <span class='text-green-400'>${data.risk}</span></div><div class='text-xs text-gray-300 mt-1'>${data.details}</div>`;
    } catch (err) {
        resDiv.innerHTML = "<span class='text-red-400'>Erreur de connexion au serveur.</span>";
    }
}
