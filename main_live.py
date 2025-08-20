import pandas as pd
from joblib import load
import sys
import os

print("🚨 Starting Live Attack Detection...\n")

# === Step 1: Load live honeypot data ===
log_file = "data/traffic_log.csv"

if not os.path.exists(log_file):
    print("❌ Error: File not found ->", log_file)
    sys.exit(1)

if os.path.getsize(log_file) == 0:
    print("❌ Error: traffic_log.csv is empty.")
    sys.exit(1)

try:
    df = pd.read_csv(log_file)
    print("✅ Live data loaded successfully.")
except Exception as e:
    print("❌ Failed to load CSV:", e)
    sys.exit(1)

# === Step 2: Add required features (fill with defaults if missing) ===
required_features = ['count', 'dst_bytes', 'src_bytes']
for feature in required_features:
    if feature not in df.columns:
        df[feature] = 0  # Use default value if missing

# === Step 3: Select only required features for prediction ===
try:
    X = df[required_features]
except KeyError as e:
    print("❌ Missing required columns for prediction:", e)
    sys.exit(1)

# === Step 4: Load trained model ===
model_path = "models/random_forest_model.joblib"
try:
    model = load(model_path)
    print("✅ Random Forest model loaded.")
except FileNotFoundError:
    print("❌ Error: Model not found at", model_path)
    sys.exit(1)

# === Step 5: Predict using Random Forest ===
try:
    predictions = model.predict(X)
    df['Prediction'] = ['normal' if p == 1 else 'attack' for p in predictions]
except Exception as e:
    print("❌ Prediction error:", e)
    sys.exit(1)

# === Step 6: Display results ===
print("\n📊 Detection Results:")

# Use specific display columns if available
display_cols = ['timestamp', 'ip', 'port', 'Prediction']
existing_cols = [col for col in display_cols if col in df.columns]

# If those specific columns are missing, just show all available
if not existing_cols:
    existing_cols = df.columns

print(df[existing_cols])
