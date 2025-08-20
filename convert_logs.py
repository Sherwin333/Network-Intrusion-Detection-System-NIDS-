import pandas as pd
import os

log_file = "honeypot/honeypot_logs.csv"
output_file = "data/live_test_with_attacks.csv"

if not os.path.exists(log_file):
    print("❌ No honeypot_logs.csv found. Run honeypot_server.py first!")
    exit()

try:
    df = pd.read_csv(log_file)
except Exception as e:
    print("❌ Failed to read honeypot logs:", e)
    exit()

# Create a simple converted format matching what the model expects
converted = []

for _, row in df.iterrows():
    converted.append({
        "protocol_type": "tcp",  # static for demo
        "service": "http" if row.get("src_port", 0) == 80 else "other",
        "flag": "SF",
        "src_bytes": row.get("src_bytes", 0),
        "dst_bytes": row.get("dst_bytes", 0),
        "count": row.get("count", 0),
        "label": "attack" if row.get("Prediction") == "attack" else "normal"
    })

# Save converted data
converted_df = pd.DataFrame(converted)
converted_df.to_csv(output_file, index=False)

print(f"✅ Converted data saved to {output_file}")
