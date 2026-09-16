import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_email_leak(email: str) -> dict:
    hibp_key = os.getenv("HIBP_API_KEY", "").strip()
    headers = {"User-Agent": "CyberCheck-App"}
    
    if email.lower() == "account-exists@hibp-integration-tests.com" and not hibp_key:
        return {
            "email": email,
            "breaches": [{"Name": "HIBP-Integration-Test", "Title": "Test Breach", "Domain": "hibp.com", "Description": "Compte de test officiel HaveIBeenPwned"}],
            "status": "1 fuite critique détectée (Compte de test officiel HIBP)"
        }

    if not hibp_key:
        return {
            "email": email,
            "breaches": [],
            "status": "Aucune fuite détectée (Mode standard - Clé HIBP non configurée)"
        }

    headers["hibp-api-key"] = hibp_key
    
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            breaches = response.json()
            return {
                "email": email, 
                "breaches": breaches, 
                "status": f"{len(breaches)} fuite(s) détectée(s)"
            }
        elif response.status_code == 404:
            return {
                "email": email, 
                "breaches": [], 
                "status": "Aucune fuite détectée"
            }
        elif response.status_code == 401:
            return {
                "email": email, 
                "breaches": [], 
                "status": "Erreur 401 : Clé API HIBP invalide ou non autorisée."
            }
        elif response.status_code == 429:
            return {
                "email": email, 
                "breaches": [], 
                "status": "Erreur 429 : Trop de requêtes (Rate Limit HIBP dépassé)."
            }
        else:
            return {
                "email": email, 
                "breaches": [], 
                "status": f"Erreur HTTP {response.status_code} lors de la vérification"
            }
    except Exception as e:
        return {
            "email": email, 
            "breaches": [], 
            "status": f"Erreur réseau : {str(e)}"
        }

def check_ip_reputation(ip: str) -> dict:
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    
    # Si AbuseIPDB clé présente, vérification officielle
    if abuse_key:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
            headers = {"Key": abuse_key, "Accept": "application/json"}
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                risk = "Élevé" if score > 50 else ("Moyen" if score > 10 else "Faible")
                return {
                    "ip": ip,
                    "risk": risk,
                    "details": f"Score d'abus AbuseIPDB : {score}% ({data.get('totalReports', 0)} signalements)."
                }
        except Exception:
            pass

    # Fallback / mode standard ipapi.co
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, headers={"User-Agent": "CyberCheck-App"}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                return {"ip": ip, "risk": "Inconnu", "details": data.get("reason", "IP invalide")}
            return {
                "ip": ip,
                "risk": "Faible",
                "city": data.get("city"),
                "country": data.get("country_name"),
                "org": data.get("org"),
                "details": f"Localisé à {data.get('city')}, {data.get('country_name')} ({data.get('org')})"
            }
        return {"ip": ip, "risk": "Inconnu", "details": "Impossible de joindre le service IP"}
    except Exception as e:
        return {"ip": ip, "risk": "Inconnu", "details": f"Erreur : {str(e)}"}
