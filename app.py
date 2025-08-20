import streamlit as st
import pandas as pd
from models.random_forest import predict_rf
from models.kmeans import train_kmeans_with_label_mapping, predict_kmeans
from models.hybrid_model import predict_hybrid

# Set page config
st.set_page_config(page_title="Network Intrusion Detection", layout="centered")
st.title("🛡️ Network Intrusion Detection System")
st.write("Upload training and test CSVs to detect intrusions using ML models.")

# Sidebar - Model selection
st.sidebar.header("Model Settings")
model_choice = st.sidebar.radio("Choose a model:", ["Random Forest", "KMeans", "Hybrid"])

# Sidebar - Upload kdd_train.csv for KMeans
st.sidebar.subheader("KMeans Training File (kdd_train.csv)")
training_file = st.sidebar.file_uploader("Upload Training CSV", type=["csv"], key="train_file")

# Main - Upload test data
uploaded_file = st.file_uploader("Upload Test Network CSV (e.g., zero.csv)", type=["csv"], key="test_file")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.write("### Preview of Uploaded Test Data", df.head())

    if st.button("Run Detection"):
        st.info("Running selected model...")

        try:
            if model_choice == "Random Forest":
                results = predict_rf(df)

            elif model_choice == "KMeans":
                if training_file is None:
                    st.error("❗ Please upload kdd_train.csv for KMeans training in the sidebar.")
                    st.stop()

                train_df = pd.read_csv(training_file)
                (kmeans, scaler, cluster_to_label) = train_kmeans_with_label_mapping(train_df)

                required_cols = train_df.drop(columns=["labels"]).columns

                # Ensure test data has all necessary columns
                for col in required_cols:
                    if col not in df.columns:
                        df[col] = 0  # default fill if missing

                df = df[required_cols]
                df['labels'] = 'normal'  # dummy label

                results = predict_kmeans(df, kmeans, scaler, cluster_to_label)

            elif model_choice == "Hybrid":
                results = predict_hybrid(df)

            else:
                st.error("Invalid model selected.")
                results = None

        except Exception as e:
            st.error(f"Error during detection: {e}")
            results = None

        if results is not None:
            st.success("✅ Detection Completed")
            st.write("### Prediction Summary", results['Prediction'].value_counts().reset_index(name='Count').rename(columns={'index': 'Prediction'}))
            st.dataframe(results)

            csv = results.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Results as CSV",
                data=csv,
                file_name='detection_results.csv',
                mime='text/csv'
            )
