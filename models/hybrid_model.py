import pandas as pd
from models.random_forest import predict_rf
from models.kmeans import train_kmeans_with_label_mapping, predict_kmeans

def predict_hybrid(data):
    if len(data) < 1:
        raise ValueError("Not enough data for Hybrid (min 1 sample)")

    # Train KMeans once (or you can load from saved model)
    train_df = pd.read_csv("data/kdd_train.csv")
    kmeans, scaler, cluster_map = train_kmeans_with_label_mapping(train_df)

    # Prepare KMeans test data
    kmeans_data = data.copy()
    for col in train_df.drop(columns=['labels']).columns:
        if col not in kmeans_data.columns:
            kmeans_data[col] = 0
    kmeans_data = kmeans_data[train_df.drop(columns=['labels']).columns]
    kmeans_data['labels'] = 'normal'

    # Predict from both models
    rf_result = predict_rf(data.copy())
    kmeans_result = predict_kmeans(kmeans_data, kmeans, scaler, cluster_map)

    # Combine predictions
    hybrid_predictions = []
    for rf_pred, km_pred in zip(rf_result['Prediction'], kmeans_result['Prediction']):
        if rf_pred == 'attack' or km_pred == 'attack':
            hybrid_predictions.append('attack')
        else:
            hybrid_predictions.append('normal')

    result_df = data.copy()
    result_df['Prediction'] = hybrid_predictions
    return result_df
