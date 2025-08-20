import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

def predict_rf(df):
    model = joblib.load("models/random_forest_model.joblib")

    # Handle missing categorical columns
    cat_cols = ['protocol_type', 'service', 'flag']
    for col in cat_cols:
        if col not in df.columns:
            df[col] = 'unknown'
        df[col] = LabelEncoder().fit_transform(df[col].astype(str))

    # Ensure required numeric features exist
    required_features = ['count', 'dst_bytes', 'src_bytes']
    for col in required_features:
        if col not in df.columns:
            df[col] = 0

    X = df[required_features]
    predictions = model.predict(X)
    df['Prediction'] = ['normal' if p == 1 else 'attack' for p in predictions]
    return df

# ✅ Wrapper used in main.py
def run_random_forest(test_file):
    print(f"📊 Random Forest analyzing: {test_file}")
    df = pd.read_csv(test_file)

    # Add dummy fields for honeypot traffic
    for col in ['protocol_type', 'service', 'flag']:
        if col not in df.columns:
            df[col] = 'tcp'  # or 'http', 'SF' as default

    result_df = predict_rf(df)
    print(result_df[['src_ip', 'Prediction']] if 'src_ip' in result_df.columns else result_df[['Prediction']])
