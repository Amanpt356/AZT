from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
import tldextract
import datetime
import json
import os
import random
import csv

from reputation.checker import check_domain_reputation
from ml.domain_model import domain_ml_check
from ml.url_model import url_ml_check
import psutil

def get_running_processes():
    try:
        processes = [p.info['name'] for p in psutil.process_iter(['name'])]
        return list(set(processes)) # unique names
    except:
        return ["chrome.exe", "firefox.exe", "discord.exe", "spotify.exe", "svchost.exe", "system"]


app = FastAPI()

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# cache to avoid repeated ML analysis
domain_cache = {}

# System Management State
system_state = {
    "is_sniffing": False,
    "timeout_remaining": 0,
    "blocked_apps": ["malware_updater.exe"]
}

# ------------------------------
# LOG HANDLING
# ------------------------------

def load_logs():
    try:
        if not os.path.exists("logs.json"):
            return []
        with open("logs.json","r") as file:
            return json.load(file)
    except:
        return []


def save_logs(logs):
    with open("logs.json","w") as file:
        json.dump(logs,file,indent=2)


# ------------------------------
# RULE STORAGE (for frontend)
# ------------------------------

def load_rules():
    try:
        path = "reputation/blacklist.txt"
        if not os.path.exists(path):
            return []
        with open(path, "r") as file:
            # Each line is a domain, return as dict for frontend compatibility
            return [{"domain": line.strip()} for line in file if line.strip()]
    except:
        return []


def save_rules(rules):
    try:
        path = "reputation/blacklist.txt"
        os.makedirs("reputation", exist_ok=True)
        with open(path, "w") as file:
            for rule in rules:
                file.write(f"{rule['domain']}\n")
    except Exception as e:
        print(f"Error saving blacklist: {e}")


# ------------------------------
# MAIN URL CHECK API
# ------------------------------

@app.post("/check_url")
def check_url(data: dict):
    url = data.get("url", "")
    if not url:
        return {"error": "url required"}
        
    browser = data.get("browser","unknown")
    
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname.lower() if parsed_url.hostname else ""
    
    extracted = tldextract.extract(url)
    registered_domain = extracted.domain + "." + extracted.suffix

    # ------------------------------
    # MANUAL BLACKLIST CHECK
    # ------------------------------
    manual_rules = load_rules()
    is_blocked = False
    for rule in manual_rules:
        blacklisted_domain = rule["domain"].lower()
        # Block if:
        # 1. Hostname exactly matches (e.g. www.amazon.com == www.amazon.com)
        # 2. Hostname is a subdomain of blacklisted (e.g. news.google.com ends with .google.com)
        # 3. Blacklisted is a subdomain of hostname (e.g. user blocks 'amazon.com', we catch 'www.amazon.com')
        if hostname == blacklisted_domain or \
           hostname.endswith("." + blacklisted_domain) or \
           blacklisted_domain.endswith("." + hostname) or \
           registered_domain == blacklisted_domain:
            is_blocked = True
            break

    if is_blocked:
        decision = "BLOCK"
        reason = "manual_blacklist"
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "domain": hostname,
            "decision": decision,
            "reason": reason,
            "browser": browser
        }
        logs = load_logs()
        logs.append(log_entry)
        save_logs(logs)
        return log_entry

    domain = registered_domain
    if domain in domain_cache:
        decision, reason = domain_cache[domain]
    else:
        decision, reason = check_domain_reputation(domain)
        if decision == "ALLOW" and reason == "unknown":
            # Only perform ML if not in manual/trusted/malicious lists
            ml_decision, ml_reason = domain_ml_check(domain)
            if ml_decision == "BLOCK":
                decision = ml_decision
                reason = ml_reason
            else:
                ml_decision, ml_reason = url_ml_check(url)
                if ml_decision == "BLOCK":
                    decision = ml_decision
                    reason = ml_reason

        domain_cache[domain] = (decision, reason)

    timestamp = datetime.datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "domain": domain,
        "decision": decision,
        "reason": reason,
        "browser": browser
    }

    logs = load_logs()
    logs.append(log_entry)
    save_logs(logs)
    return log_entry


# ------------------------------
# WEB LOG/RULE API
# ------------------------------

@app.get("/logs")
def get_logs():
    return load_logs()

@app.get("/rules")
def get_rules():
    return load_rules()

@app.post("/add_rule")
def add_rule(rule: dict):
    rules = load_rules()
    rules.append(rule)
    save_rules(rules)
    return {"status":"rule added"}

@app.post("/delete_rule")
def delete_rule(rule: dict):
    rules = load_rules()
    rules = [r for r in rules if r["domain"] != rule["domain"]]
    save_rules(rules)
    return {"status":"rule removed"}


# ------------------------------
# SYSTEM MONITORING API (MOCKS)
# ------------------------------

@app.get("/status")
def get_status():
    if system_state["is_sniffing"] and system_state["timeout_remaining"] > 0:
        system_state["timeout_remaining"] -= 3 # Decrease by check interval
    elif system_state["timeout_remaining"] <= 0:
        system_state["is_sniffing"] = False
        
    return system_state

@app.post("/start")
def start_sniffer(timeout: int = 60):
    system_state["is_sniffing"] = True
    system_state["timeout_remaining"] = timeout
    return {"status": "started"}

@app.post("/stop")
def stop_sniffer():
    system_state["is_sniffing"] = False
    system_state["timeout_remaining"] = 0
    return {"status": "stopped"}

@app.post("/block")
def block_app(app_name: str):
    if app_name not in system_state["blocked_apps"]:
        system_state["blocked_apps"].append(app_name)
    return {"status": "blocked"}

@app.post("/unblock")
def unblock_app(app_name: str):
    if app_name in system_state["blocked_apps"]:
        system_state["blocked_apps"].remove(app_name)
    return {"status": "unblocked"}

@app.get("/packets")
def get_packets():
    # Return samples from the dataset to simulate "live" traffic
    try:
        dataset_path = "../AZT_NO_Network_Threat_Dataset.csv"
        if not os.path.exists(dataset_path):
             # Fallback if path is different
             dataset_path = "AZT_NO_Network_Threat_Dataset.csv"
             
        packets = []
        with open(dataset_path, mode='r') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            # Pick 20 random recent-ish looking rows
            sample_rows = random.sample(rows, min(20, len(rows)))
            
            processes = get_running_processes()
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for row in sample_rows:
                status = "Good" if row['label'] == 'Normal' else "Bad"
                # Use real process names from system
                src_proc = random.choice(processes) if processes else "system"
                dst_proc = random.choice(processes) if processes else "external"
                
                packets.append({
                    "timestamp": current_time,
                    "src_proc": src_proc,
                    "dst_proc": dst_proc,
                    "dst_port": row['dst_port'],
                    "packet_size": row['packet_size'],
                    "bytes": row['bytes'],
                    "status": status
                })
        return packets
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
