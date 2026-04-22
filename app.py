import os
import random
import time
import json
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

VT_API_KEY = os.environ.get("VT_API_KEY", "")

user_cyber_score = 0
user_scans = 0

def calculate_rank(points):
    if points < 50: return "Beginner"
    if points < 150: return "Analyst"
    return "Cyber Hero"

def calculate_badges(points):
    badges = []
    if points >= 50: badges.append("Phishing Hunter")
    if points >= 150: badges.append("Threat Detector")
    return badges

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "bank", "account", "paypal"]

def shannon_entropy(text):
    import math
    if not text: return 0.0
    freq = {}
    for ch in text: freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def check_virustotal(url):
    if not VT_API_KEY or not REQUESTS_AVAILABLE:
        return {"available": False}
    try:
        headers = {"x-apikey": VT_API_KEY}
        import base64
        url_b64 = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        report_resp = http_requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_b64}",
            headers=headers,
            timeout=5,
        )
        if report_resp.status_code == 200:
            stats = report_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"available": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except:
        pass
    return {"available": False}

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    global user_cyber_score, user_scans
    body = request.get_json(force=True, silent=True) or {}
    url = body.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
        
    flags = []
    risk = 0
    
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            flags.append(f"Suspicious keyword: {kw}")
            risk += 20
            
    if url.startswith("http://"):
        flags.append("Insecure HTTP connection")
        risk += 30
        
    entropy = shannon_entropy(url)
    if entropy > 4.0:
        flags.append(f"High entropy ({entropy:.2f})")
        risk += 20
        
    vt = check_virustotal(url)
    if vt.get("available"):
        if vt["malicious"] > 0:
            flags.append(f"VirusTotal: {vt['malicious']} malicious engines")
            risk += 40
        
    risk = min(risk, 100)
    verdict = "Safe"
    points_earned = 5
    if risk >= 60:
        verdict = "Malicious"
        points_earned = 20
    elif risk >= 30:
        verdict = "Suspicious"
        points_earned = 10
        
    user_cyber_score += points_earned
    user_scans += 1
        
    return jsonify({
        "url": url,
        "risk_score": risk,
        "verdict": verdict,
        "flags": flags,
        "entropy": entropy,
        "points_earned": points_earned,
        "total_score": user_cyber_score,
        "rank": calculate_rank(user_cyber_score)
    })

@app.route("/scan_phone", methods=["POST"])
def scan_phone():
    global user_cyber_score
    body = request.get_json(force=True, silent=True) or {}
    phone = body.get("phone", "").strip()
    
    if not phone:
        return jsonify({"error": "No phone provided"}), 400
        
    countries = ["USA", "UK", "Canada", "Germany", "India", "Australia"]
    carriers = ["Verizon", "AT&T", "T-Mobile", "Vodafone", "O2", "Jio", "Airtel"]
    types = ["Mobile", "Landline", "VoIP"]
    
    country = random.choice(countries)
    carrier = random.choice(carriers)
    p_type = random.choice(types)
    
    flags = []
    risk = 10
    
    if re.search(r"(\d)\1{3,}", phone):
        flags.append("Repeated digits detected (Suspicious)")
        risk += 40
        p_type = "VoIP"
        
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7 or len(digits) > 15:
        flags.append("Invalid phone length")
        risk += 30
        
    risk = min(risk, 100)
    verdict = "Safe"
    if risk >= 60: verdict = "Malicious"
    elif risk >= 30: verdict = "Suspicious"
    
    services = ["Gmail", "Instagram", "Facebook", "WhatsApp"]
    tracker = []
    
    suspicious_service = random.choice(services) if risk > 20 else None
    
    for s in services:
        status = "Suspicious" if s == suspicious_service else "Active"
        minutes_ago = random.randint(1, 1440)
        last_login = (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M")
        tracker.append({"service": s, "last_login": last_login, "status": status})
        
    return jsonify({
        "phone": phone,
        "country": country,
        "carrier": carrier,
        "type": p_type,
        "risk_level": risk,
        "verdict": verdict,
        "flags": flags,
        "tracker": tracker,
        "note": "This is simulated intelligence"
    })

@app.route("/api/identity", methods=["GET"])
def api_identity():
    countries = ["USA", "Russia", "China", "Brazil", "India", "UK", "Germany"]
    loc = random.choice(countries)
    
    trust_score = random.randint(20, 100)
    device_trust = "Secure" if trust_score > 60 else "Suspicious"
    
    return jsonify({
        "location": loc,
        "device_trust": device_trust,
        "trust_score": trust_score
    })

@app.route("/api/audit", methods=["POST"])
def api_audit():
    body = request.get_json(force=True, silent=True) or {}
    app_name = body.get("app_name", "Unknown App")
    permissions = body.get("permissions", "")
    
    perms_list = [p.strip().lower() for p in permissions.split(",") if p.strip()]
    
    sensitive = ["camera", "mic", "microphone", "contacts", "location"]
    risk = 10
    flags = []
    
    for p in perms_list:
        if p in sensitive:
            risk += 30
            flags.append(f"Sensitive permission: {p}")
            
    risk = min(risk, 100)
    verdict = "High Risk" if risk >= 60 else "Medium Risk" if risk >= 30 else "Low Risk"
    
    return jsonify({
        "app_name": app_name,
        "risk_score": risk,
        "verdict": verdict,
        "flags": flags
    })

@app.route("/api/ai", methods=["POST"])
def api_ai():
    body = request.get_json(force=True, silent=True) or {}
    query = body.get("query", "").lower()
    
    if "url" in query or "link" in query:
        response = "Phishing is a method where attackers trick you into clicking malicious links. Always verify the domain name and look for HTTPS, though even HTTPS can be used by scammers. Do not click links from unknown sources."
    elif "scam" in query:
        response = "Scams often rely on urgency or fear. If a message demands immediate action or asks for sensitive info, pause and verify the sender. Use our Threat Scanner to check suspicious URLs or phone numbers."
    elif "safe" in query:
        response = "To stay safe online: 1. Use strong, unique passwords. 2. Enable 2FA. 3. Keep software updated. 4. Be skeptical of unsolicited messages. 5. Regularly monitor your app permissions."
    elif "app" in query or "permission" in query:
        response = "Apps often request more permissions than they need. Be wary of apps asking for your camera, microphone, or contacts if their core functionality doesn't require it. Use our App Auditor to check risk levels."
    else:
        response = "Hello! I am the Cyber-Sentinel AI. I can help you understand phishing, scam detection, safe online practices, and app permission risks. How can I assist you today?"
        
    return jsonify({"response": response})

@app.route("/api/score", methods=["GET"])
def api_score():
    return jsonify({
        "total_score": user_cyber_score,
        "rank": calculate_rank(user_cyber_score),
        "badges": calculate_badges(user_cyber_score),
        "scans": user_scans
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
