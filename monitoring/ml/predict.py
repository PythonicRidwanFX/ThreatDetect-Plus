import os
import joblib
import pandas as pd

# ==========================================
# Paths
# ==========================================

BASE_DIR = os.path.dirname(__file__)

MODEL_PATH = os.path.join(BASE_DIR, "random_forest.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")

# ==========================================
# Load trained files
# ==========================================

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(ENCODER_PATH)
feature_columns = joblib.load(FEATURES_PATH)


def predict_network_traffic(features_dict):
    """
    Predict whether network traffic is BENIGN or an ATTACK.

    Parameters
    ----------
    features_dict : dict
        Dictionary containing the feature values.

    Returns
    -------
    dict
        {
            "status": "Normal" or "Attack",
            "attack_type": "...",
            "confidence": 0.98
        }
    """

    # Create DataFrame
    sample = pd.DataFrame([features_dict])

    # Ensure columns are in the correct order
    sample = sample.reindex(columns=feature_columns, fill_value=0)

    # Scale features
    sample_scaled = scaler.transform(sample)

    # Prediction
    prediction = model.predict(sample_scaled)[0]

    probabilities = model.predict_proba(sample_scaled)[0]

    confidence = float(max(probabilities))

    attack_name = label_encoder.inverse_transform([prediction])[0]

    status = "Normal" if attack_name == "BENIGN" else "Attack"

    return {
        "status": status,
        "attack_type": attack_name,
        "confidence": round(confidence * 100, 2)
    }