import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

def train_kmeans_with_label_mapping(df):
    cat_cols = ['protocol_type', 'service', 'flag']
    df[cat_cols] = df[cat_cols].apply(lambda col: LabelEncoder().fit_transform(col.astype(str)))

    X = df.drop(columns=['labels'], errors='ignore')
    y = df['labels'] if 'labels' in df.columns else pd.Series(['normal'] * len(df))

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=2, random_state=42)
    cluster_labels = kmeans.fit_predict(X_scaled)

    cluster_to_label = {}
    for cluster in np.unique(cluster_labels):
        cluster_y = y[cluster_labels == cluster]
        majority = cluster_y.mode()[0] if not cluster_y.empty else 'unknown'
        cluster_to_label[cluster] = 'attack' if majority != 'normal' else 'normal'

    return kmeans, scaler, cluster_to_label

def predict_kmeans(df, kmeans, scaler, cluster_to_label):
    cat_cols = ['protocol_type', 'service', 'flag']
    df[cat_cols] = df[cat_cols].apply(lambda col: LabelEncoder().fit_transform(col.astype(str)))

    X = df.drop(columns=['labels'], errors='ignore')
    X_scaled = scaler.transform(X)

    cluster_labels = kmeans.predict(X_scaled)
    df['Cluster'] = cluster_labels
    df['Prediction'] = [cluster_to_label.get(label, 'unknown') for label in cluster_labels]
    return df

def run_kmeans(train_path, test_path):
    print(f"📊 K-Means training on: {train_path}")
    train_df = pd.read_csv(train_path)

    print(f"🔍 Predicting using test file: {test_path}")
    test_df = pd.read_csv(test_path)

    # Dummy fallback for honeypot-only traffic
    for col in ['protocol_type', 'service', 'flag']:
        if col not in test_df.columns:
            test_df[col] = 'tcp'

    kmeans, scaler, cluster_to_label = train_kmeans_with_label_mapping(train_df)
    result_df = predict_kmeans(test_df, kmeans, scaler, cluster_to_label)

    print(result_df[['src_ip', 'Prediction']] if 'src_ip' in result_df.columns else result_df[['Prediction']])
