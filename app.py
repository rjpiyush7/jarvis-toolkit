from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ================= PASSWORD CHECK =================
@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')

    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*" for c in password):
        score += 1

    if score <= 1:
        strength = "Weak"
    elif score <= 3:
        strength = "Medium"
    else:
        strength = "Strong"

    return jsonify({"strength": strength, "score": score})


# ================= URL CHECK =================
import requests
import whois
from datetime import datetime
import socket
from urllib.parse import unquote

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "Empty URL"})

    score = 0
    reasons = []

    # -------- DECODE URL --------
    url = unquote(url)

    # -------- BASIC CHECKS --------
    if not url.startswith("https"):
        score += 20
        reasons.append("Not using HTTPS")

    bad_words = ["login","verify","free","bank","update","secure","account"]
    for word in bad_words:
        if word in url.lower():
            score += 15
            reasons.append(f"Contains '{word}' keyword")

    if "@" in url:
        score += 20
        reasons.append("Contains '@' (redirect trick)")

    if url.count("//") > 1:
        score += 10
        reasons.append("Multiple '//' found")

    if len(url) > 75:
        score += 10
        reasons.append("URL too long")

    # -------- PARSE --------
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        protocol = parsed.scheme
        path = parsed.path
    except:
        return jsonify({"error": "Invalid URL"})

    # -------- IP DETECTION --------
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 25
        reasons.append("Uses IP address")

    # -------- DNS LOOKUP --------
    ip_address = "Unknown"
    try:
        ip_address = socket.gethostbyname(domain)
    except:
        reasons.append("DNS resolution failed")

    # -------- DOMAIN AGE --------
    domain_age = "Unknown"
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            domain_age = f"{age_days} days"

            if age_days < 30:
                score += 25
                reasons.append("Very new domain (phishing risk)")
    except:
        domain_age = "Unavailable"
        reasons.append("Domain age could not be determined")

    # -------- VIRUSTOTAL --------
    vt_result = "Unavailable"
    try:
        API_KEY = "d0b1c778dcd23ffc7cdcf572f1413156c932e9bd385d1d66291783863e4407f8" #whois api used
        headers = {"x-apikey": API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code == 200:
            vt_result = "Checked (processing)"
    except:
        vt_result = "Error"

    # -------- REDIRECT CHECK --------
    redirects = 0
    try:
        r = requests.get(url, timeout=5)
        redirects = len(r.history)

        if redirects > 2:
            score += 15
            reasons.append("Multiple redirects detected")
    except:
        reasons.append("Unable to check redirects")

    # -------- FINAL SCORE --------
    if score >= 70:
        status = "HIGH RISK"
    elif score >= 40:
        status = "SUSPICIOUS"
    elif score > 0:
        status = "LOW RISK"
    else:
        status = "SAFE"

    confidence = min(100, score)

    return jsonify({
        "status": status,
        "score": score,
        "confidence": confidence,
        "protocol": protocol,
        "domain": domain,
        "path": path,
        "ip": ip_address,
        "domain_age": domain_age,
        "redirects": redirects,
        "virustotal": vt_result,
        "reasons": reasons
    })


# ================= RUN SERVER =================
if __name__ == '__main__':
    app.run(debug=True)