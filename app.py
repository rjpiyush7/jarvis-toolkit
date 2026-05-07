from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import os
import requests
import whois
import socket
from datetime import datetime
from urllib.parse import urlparse, unquote

app = Flask(__name__)
CORS(app)

# ================= PAGE ROUTES =================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/password')
def password_page():
    return render_template('password.html')

@app.route('/url')
def url_page():
    return render_template('url.html')

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
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "Empty URL"})

    score = 0
    reasons = []

    url = unquote(url)

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

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        protocol = parsed.scheme
        path = parsed.path
    except:
        return jsonify({"error": "Invalid URL"})

    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 25
        reasons.append("Uses IP address")

    ip_address = "Unknown"
    try:
        ip_address = socket.gethostbyname(domain)
    except:
        reasons.append("DNS resolution failed")

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

    vt_result = "Unavailable"
    try:
        API_KEY = os.environ.get("VT_API_KEY")
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

    redirects = 0
    try:
        r = requests.get(url, timeout=5)
        redirects = len(r.history)

        if redirects > 2:
            score += 15
            reasons.append("Multiple redirects detected")
    except:
        reasons.append("Unable to check redirects")

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
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
