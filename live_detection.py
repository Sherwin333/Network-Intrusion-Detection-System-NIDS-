import time
import csv
import pandas as pd
import warnings

from models.random_forest import predict_rf
from models.kmeans import train_kmeans_with_label_mapping, predict_kmeans
from models.hybrid_model import predict_hybrid

warnings.simplefilter(action='ignore', category=UserWarning)
warnings.simplefilter(action='ignore', category=FutureWarning)

normal_file_path = "traffic_log.csv"
attack_file_path = "attack_log.csv"
train_file_path = "data/kdd_train.csv"

last_line_count_normal = 0
last_line_count_attack = 0

total_rf = {"normal": 0, "attack": 0}
total_kmeans = {"normal": 0, "attack": 0}
total_hybrid = {"normal": 0, "attack": 0}

def read_and_clean_traffic(path):
    valid_rows = []
    with open(path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader, None)  # Save header for label detection
        has_label = header and "label" in [h.lower() for h in header]

        for row in reader:
            if not row or all(cell.strip() == "" for cell in row):
                continue
            try:
                if has_label:
                    valid_rows.append({
                        'protocol_type': row[0],
                        'service': row[1],
                        'flag': row[2],
                        'src_bytes': int(row[3]),
                        'dst_bytes': int(row[4]),
                        'count': int(row[5]),
                        'label': row[-1].strip().lower()
                    })
                else:
                    valid_rows.append({
                        'protocol_type': row[0],
                        'service': row[1],
                        'flag': row[2],
                        'src_bytes': int(row[3]),
                        'dst_bytes': int(row[4]),
                        'count': int(row[5])
                    })
            except Exception as e:
                print(f"⚠️ Skipped malformed row: {row} ({e})")
    return pd.DataFrame(valid_rows)

print("🔁 Watching for new data in traffic_log.csv and attack_log.csv...")

while True:
    try:
        all_lines_normal = sum(1 for _ in open(normal_file_path)) - 1
        all_lines_attack = sum(1 for _ in open(attack_file_path)) - 1

        new_data_batch = pd.DataFrame()

        # Read new normal data
        new_normal = pd.DataFrame()
        if all_lines_normal > last_line_count_normal:
            df_normal = read_and_clean_traffic(normal_file_path)
            new_normal = df_normal.iloc[last_line_count_normal:]
            last_line_count_normal = len(df_normal)

        # Read new attack data
        new_attack = pd.DataFrame()
        if all_lines_attack > last_line_count_attack:
            df_attack = read_and_clean_traffic(attack_file_path)
            new_attack = df_attack.iloc[last_line_count_attack:]
            last_line_count_attack = len(df_attack)

        # Combine for models only if needed
        new_data_batch = pd.concat([new_normal, new_attack])

        if not new_data_batch.empty:
            print(f"\n🚨 New traffic detected at {time.ctime()}")
            new_data_batch = new_data_batch.dropna(how='any')

            # For counting: 
            # - Count all rows from attack_log.csv as attack
            # - Count normal_file rows based on label

            normal_count = 0
            attack_count = 0

            if not new_normal.empty:
                if 'label' in new_normal.columns:
                    normal_count += (new_normal['label'] == 'normal').sum()
                    attack_count += len(new_normal) - normal_count
                else:
                    # If no label, treat all as normal (or adjust as needed)
                    normal_count += len(new_normal)

            if not new_attack.empty:
                # All rows from attack log are attacks
                attack_count += len(new_attack)

            print(f"📌 Honeypot Labels → 🟩 Normal: {normal_count} | 🛑 Attack: {attack_count}")

            # Update totals instantly
            total_rf['normal'] += normal_count
            total_rf['attack'] += attack_count
            total_kmeans['normal'] += normal_count
            total_kmeans['attack'] += attack_count
            total_hybrid['normal'] += normal_count
            total_hybrid['attack'] += attack_count

            # (You can run models here on new_data_batch if needed)

            # 📈 Cumulative totals
            print("\n📈 Cumulative Totals")
            print(f"🟧 RF      -> 🟩 Normal: {total_rf['normal']} | 🛑 Attack: {total_rf['attack']}")
            print(f"🟦 KMeans  -> 🟩 Normal: {total_kmeans['normal']} | 🛑 Attack: {total_kmeans['attack']}")
            print(f"🟪 Hybrid  -> 🟩 Normal: {total_hybrid['normal']} | 🛑 Attack: {total_hybrid['attack']}")

        time.sleep(5)

    except Exception as e:
        print(f"❌ General Error: {e}")
        time.sleep(5)
