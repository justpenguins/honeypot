from flask import Flask, request, render_template
import requests
import datetime
import json
import os

app = Flask(__name__)

# Helper Functions

def log_attack(data):
    folder_path = "logs/"
    os.makedirs(folder_path, exist_ok=True)

    data = detect_injections(data)

    current_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"log_{current_datetime}.json"
    
    file_path = os.path.join(folder_path, file_name)

    try:
        with open(file_path, "a") as f:
            json.dump(data, f)
            f.write('\n')
        print(f"[LOG] Written to {file_path}")  # Debug print
    except Exception as e:
        print(f"[ERROR] Failed to write log: {e}")

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return "Geo lookup failed"
    except Exception as e:
        return f"Geo error: {str(e)}"
    
def detect_injections(data):
    types = {
        "sql":['ORDER BY', 'AND', "admin' --", "admin' #", "' or 1=1--", "' or 1=1#"],
        "xss":['<script>', '</script>', 'onerror=', 'alert(', 'document.cookie'],
        "command":[],
    }

    threat_type = None
    threat_level = 'Low'
    inputs = json.dumps(data)

    for category, signs in types.items():
        for sign in signs:
            if sign.lower() in inputs.lower():
                threat_type = category
                threat_level = 'high' if category in ['sql', 'xss'] else 'medium'
                break
            if threat_type:
                break
    
    if threat_type:
        data["threat_type"] = threat_type
        data["threat_level"] = threat_level
    else:
        data["threat_type"] = "unknown"
        data["threat_level"] = "info"

    return data
    


# Routes
@app.route("/")
def index():
    return render_template("landing.html")

@app.route("/admin")
def fake_admin():
    log_attack({
        "timestamp": str(datetime.datetime.now()),
        "endpoint": "/admin",
        "ip": request.remote_addr,
        "headers": dict(request.headers)
    })
    return "404 Not Found", 404

@app.route("/login", methods=["GET", "POST"]) # CHange to only post later, when actual data is being passed
def fake_login():
    location_data = get_location(request.remote_addr)
    log_attack({
        "timestamp": str(datetime.datetime.now()),
        "endpoint": "/login",
        "ip": request.remote_addr,
        "location": location_data,
        "username": request.form.get("username"),
        "password": request.form.get("password"),
        "body": str(request.data),
        "headers": dict(request.headers)
    })
    return "Invalid credentials"

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
