import hashlib
import re
import requests

def analyze_password_strength(password: str) -> dict:
    score = 0
    feedback = []
    
    if len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
        feedback.append("Mot de passe un peu court (recommandé : 12+ caractères).")
    else:
        feedback.append("Mot de passe trop court (< 8 caractères).")
        
    if re.search(r"[A-Z]", password):
        score += 20
    else:
        feedback.append("Ajoutez des majuscules.")
        
    if re.search(r"[a-z]", password):
        score += 20
    else:
        feedback.append("Ajoutez des minuscules.")
        
    if re.search(r"[0-9]", password):
        score += 20
    else:
        feedback.append("Ajoutez des chiffres.")
        
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    else:
        feedback.append("Ajoutez des caractères spéciaux.")

    level = "Faible"
    if score >= 80:
        level = "Fort"
    elif score >= 50:
        level = "Moyen"

    # Vérification fuite HIBP (k-Anonymity)
    sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    leaked_count = 0
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    leaked_count = int(count)
                    break
    except Exception:
        pass

    if leaked_count > 0:
        feedback.append(f"ALERTE : Ce mot de passe apparaît {leaked_count} fois dans des bases de données compromises !")
        level =Critique = "Critique" if level != "Faible" else level
        
    return {
        "score": score,
        "level": level if leaked_count == 0 else "Critique",
        "leaked_count": leaked_count,
        "feedback": feedback
    }
