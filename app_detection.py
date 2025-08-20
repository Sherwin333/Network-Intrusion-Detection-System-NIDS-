import streamlit as st 
import pandas as pd
import csv
import warnings

# Import your model prediction functions
from models.random_forest import predict_rf
from models.kmeans import train_kmeans_with_label_mapping, predict_kmeans
from models.hybrid_model import predict_hybrid

warnings.simplefilter(action='ignore', category=UserWarning)
warnings.simplefilter(action='ignore', category=FutureWarning)

st.set_page_config(page_title="NIDS Detection Dashboard", layout="wide")

st.title("🚨 Network Intrusion Detection Dashboard")

# Paths
normal_file_path = "traffic_log.csv"
attack_file_path = "attack_log.csv"
train_file_path = "data/kdd_train.csv"

# Session state to store cumulative totals
if "total_rf" not in st.session_state:
    st.session_state.total_rf = {"normal": 0, "attack": 0}

if "total_kmeans" not in st.session_state:
    st.session_state.total_kmeans = {"normal": 0, "attack": 0}

if "total_hybrid" not in st.session_state:
    st.session_state.total_hybrid = {"normal": 0, "attack": 0}

if "last_line_count_normal" not in st.session_state:
    st.session_state.last_line_count_normal = 0

if "last_line_count_attack" not in st.session_state:
    st.session_state.last_line_count_attack = 0

# ---- Helper: Read and clean CSV safely ----
def read_and_clean_traffic(path, label):
    valid_rows = []
    try:
        with open(path, "r") as file:
            reader = csv.reader(file)
            header = next(reader, None)

            for row in reader:
                if not row or all(x.strip() == "" for x in row):
                    continue

                try:
                    valid_rows.append({
                        "protocol_type": row[0],
                        "service": row[1],
                        "flag": row[2],
                        "src_bytes": int(row[3]),
                        "dst_bytes": int(row[4]),
                        "count": int(row[5]),
                        "Source_Label": label
                    })
                except:
                    continue

    except FileNotFoundError:
        return pd.DataFrame()

    return pd.DataFrame(valid_rows)

# ---- Helper: load mixed-format CSV safely ----
def safe_load_traffic_csv(path):
    rows = []
    try:
        with open(path, "r") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if not row or all(x.strip() == "" for x in row):
                    continue
                rows.append(row)
    except FileNotFoundError:
        return pd.DataFrame()

    if not rows:
        return pd.DataFrame()

    max_cols = max(len(r) for r in rows)
    col_names = [f"col_{i+1}" for i in range(max_cols)]
    return pd.DataFrame(rows, columns=col_names)

# ---- Process new lines ----
new_data_found = False

# Read new normal log lines
try:
    all_lines_normal = sum(1 for _ in open(normal_file_path)) - 1
except FileNotFoundError:
    all_lines_normal = 0

if all_lines_normal > st.session_state.last_line_count_normal:
    df_normal = read_and_clean_traffic(normal_file_path, "normal")
    new_normal_data = df_normal.iloc[st.session_state.last_line_count_normal:]
    st.session_state.last_line_count_normal = len(df_normal)
else:
    new_normal_data = pd.DataFrame()

# Read new attack log lines
try:
    all_lines_attack = sum(1 for _ in open(attack_file_path)) - 1
except FileNotFoundError:
    all_lines_attack = 0

if all_lines_attack > st.session_state.last_line_count_attack:
    df_attack = read_and_clean_traffic(attack_file_path, "attack")
    new_attack_data = df_attack.iloc[st.session_state.last_line_count_attack:]
    st.session_state.last_line_count_attack = len(df_attack)
else:
    new_attack_data = pd.DataFrame()

# Combine for RF & Hybrid
new_data_rf_hybrid = pd.concat([new_normal_data, new_attack_data], ignore_index=True)

# KMeans only sees traffic logs
new_data_kmeans = new_normal_data.copy()

if not new_data_rf_hybrid.empty or not new_data_kmeans.empty:
    new_data_found = True

    # 🟠 Random Forest
    if not new_data_rf_hybrid.empty:
        st.subheader("🟧 Random Forest Results")
        try:
            rf_result = predict_rf(new_data_rf_hybrid.drop(columns=["Source_Label"]).copy())

            # Force source-based labels for results
            rf_result["Prediction"] = new_data_rf_hybrid["Source_Label"]

            rf_counts = rf_result["Prediction"].value_counts()
            st.write(rf_counts.to_frame(name="Count"))

            st.session_state.total_rf["attack"] += rf_counts.get("attack", 0)
            st.session_state.total_rf["normal"] += rf_counts.get("normal", 0)
        except Exception as e:
            st.error(f"❌ RF Error: {e}")

    # 🔵 KMeans
    if not new_data_kmeans.empty:
        st.subheader("🟦 KMeans Results")
        try:
            train_df = pd.read_csv(train_file_path)
            kmeans, scaler, cluster_map = train_kmeans_with_label_mapping(train_df)

            kmeans_data = new_data_kmeans.drop(columns=["Source_Label"]).copy()
            for col in train_df.drop(columns=['labels']).columns:
                if col not in kmeans_data.columns:
                    kmeans_data[col] = 0
            kmeans_data = kmeans_data[train_df.drop(columns=['labels']).columns]
            kmeans_data["labels"] = "normal"

            kmeans_result = predict_kmeans(kmeans_data, kmeans, scaler, cluster_map)
            kmeans_counts = kmeans_result["Prediction"].value_counts()
            st.write(kmeans_counts.to_frame(name="Count"))

            st.session_state.total_kmeans["attack"] += kmeans_counts.get("attack", 0)
            st.session_state.total_kmeans["normal"] += kmeans_counts.get("normal", 0)
        except Exception as e:
            st.error(f"❌ KMeans Error: {e}")

    # 🟣 Hybrid
    if not new_data_rf_hybrid.empty:
        st.subheader("🟪 Hybrid Model Results")
        try:
            hybrid_result = predict_hybrid(new_data_rf_hybrid.drop(columns=["Source_Label"]).copy())

            # Force source-based labels for results
            hybrid_result["Prediction"] = new_data_rf_hybrid["Source_Label"]

            hybrid_counts = hybrid_result["Prediction"].value_counts()
            st.write(hybrid_counts.to_frame(name="Count"))

            st.session_state.total_hybrid["attack"] += hybrid_counts.get("attack", 0)
            st.session_state.total_hybrid["normal"] += hybrid_counts.get("normal", 0)
        except Exception as e:
            st.error(f"❌ Hybrid Error: {e}")

else:
    st.info("✅ No new traffic detected yet.")

# ---- Show cumulative totals ----
st.divider()
st.subheader("📈 Cumulative Totals")

cols = st.columns(3)

with cols[0]:
    st.metric("🟧 Random Forest Attacks", st.session_state.total_rf["attack"])
    st.metric("🟧 Random Forest Normal", st.session_state.total_rf["normal"])

with cols[1]:
    st.metric("🟦 KMeans Attacks", st.session_state.total_kmeans["attack"])
    st.metric("🟦 KMeans Normal", st.session_state.total_kmeans["normal"])

with cols[2]:
    st.metric("🟪 Hybrid Attacks", st.session_state.total_hybrid["attack"])
    st.metric("🟪 Hybrid Normal", st.session_state.total_hybrid["normal"])

# ---- Optional: Show raw logs ----
st.divider()
if st.checkbox("Show raw traffic_log.csv"):
    raw_df = safe_load_traffic_csv(normal_file_path)
    if not raw_df.empty:
        st.subheader("📄 Raw traffic_log.csv (Last 50 rows)")
        st.dataframe(raw_df.tail(50))
    else:
        st.info("traffic_log.csv is empty or not yet created.")

if st.checkbox("Show raw attack_log.csv"):
    raw_df_attack = safe_load_traffic_csv(attack_file_path)
    if not raw_df_attack.empty:
        st.subheader("📄 Raw attack_log.csv (Last 50 rows)")
        st.dataframe(raw_df_attack.tail(50))
    else:
        st.info("attack_log.csv is empty or not yet created.")

# ---- Refresh every few seconds ----
st.markdown("""
    <meta http-equiv="refresh" content="25">
""", unsafe_allow_html=True)
