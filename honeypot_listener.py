import socket
import csv
from datetime import datetime

HOST = "0.0.0.0"
PORT = 8085  # You can change to 8080 if 80 is in use or requires admin

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(5)

print(f"Honeypot listening on port {PORT}...")


while True:
    conn, addr = sock.accept()
    src_ip = addr[0]
    timestamp = datetime.now().isoformat()

    with open("traffic_log.csv", mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, PORT, 0, 0, 1])
        print(f"⚠️ Connection attempt from {src_ip}")
    conn.close()
