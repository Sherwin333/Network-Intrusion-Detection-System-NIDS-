from models.random_forest import run_random_forest
from models.kmeans import run_kmeans
from models.hybrid_model import run_hybrid
import os
import shutil

test_path = "data/zero.csv"
train_path = "data/kdd_train.csv"

# Only run if test file exists (honeypot may or may not be running)
if os.path.exists(test_path):
    print("✅ Found test file, running NIDS models...\n")

    print("🌲 Running Random Forest...")
    run_random_forest(test_path)

    print("\n📊 Running K-Means...")
    run_kmeans(train_path, test_path)

    print("\n🧬 Running Hybrid Model...")
    run_hybrid(test_path)

else:
    print("❌ Test file not found. Skipping model execution.")



# Copy honeypot output to test file if exists
if os.path.exists("traffic_log.csv"):
    shutil.copy("traffic_log.csv", test_path)