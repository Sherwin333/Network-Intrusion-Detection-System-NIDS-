import socket
import threading
import csv
import random
from datetime import datetime

LOG_FILE = "attack_log.csv"

# List of ports considered as attack triggers
MALICIOUS_PORTS = [21, 22, 23, 80, 443]

# Simulated attack feature generator
def generate_attack_row(ip, port):
    return {
        "protocol_type": "tcp",
        "service": "http" if port == 80 else "ftp",
        "flag": "SF",
        "src_bytes": random.randint(5000, 20000),   # High = suspicious
        "dst_bytes": random.randint(10, 100),
        "count": random.randint(20, 100),
        "src_ip": ip,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "label": "attack"  # 🔹 Added fixed label for attacks
    }

# Append entry to CSV
def log_attack(data):
    file_exists = False
    try:
        with open(LOG_FILE, 'r') as f:
            file_exists = True
    except FileNotFoundError:
        pass

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# Listener logic
def honeypot_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"🎯 Honeypot listening on port {port}")

    while True:
        conn, addr = s.accept()
        ip = addr[0]
        print(f"⚠️ Attack connection from {ip} on port {port}")
        attack_row = generate_attack_row(ip, port)
        log_attack(attack_row)
        conn.close()

# Launch listeners on malicious ports
if __name__ == "__main__":
    for port in MALICIOUS_PORTS:
        threading.Thread(target=honeypot_listener, args=(port,), daemon=True).start()

    print("🧪 Honeypot active. Waiting for attackers...")
    while True:
        pass  # Keep main thread alive
