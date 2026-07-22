import os
import logging
from datetime import datetime

import joblib
import pandas as pd

logger = logging.getLogger(__name__)

# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ML_DIR = os.path.join(BASE_DIR, "..", "ml")

MODEL_PATH = os.path.join(ML_DIR, "random_forest.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(ML_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(ML_DIR, "feature_columns.pkl")

# Confidence threshold
ATTACK_THRESHOLD = 70.0

# ==========================================================
# LOAD MODELS
# ==========================================================

model = None
scaler = None
encoder = None
feature_columns = []

MODEL_LOADED = False

try:

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    encoder = joblib.load(ENCODER_PATH)
    feature_columns = joblib.load(FEATURES_PATH)

    MODEL_LOADED = True

    logger.info("Machine Learning model loaded successfully.")

except Exception as e:

    logger.exception("Unable to load ML models")

    print("Machine Learning Model Error:", e)

# ==========================================================
# MODEL STATUS
# ==========================================================

def model_status():
    return {
        "loaded": MODEL_LOADED,
        "model": os.path.basename(MODEL_PATH),
        "timestamp": datetime.now().isoformat(),
    }

# ==========================================================
# PREPROCESS
# ==========================================================

def preprocess(features):
    """
    Convert extracted flow features into the exact format
    used during model training.
    """

    df = pd.DataFrame([features])

    # Keep exactly the training columns
    df = df.reindex(
        columns=feature_columns,
        fill_value=0,
    )

    print("\n" + "=" * 70)
    print("FEATURE VECTOR SENT TO RANDOM FOREST")
    print("=" * 70)

    for column in feature_columns:
        print(f"{column:<35} {df.iloc[0][column]}")

    print("=" * 70)

    return scaler.transform(df)
# ==========================================================
# PREDICT
# ==========================================================

def predict(features):

    if not MODEL_LOADED:

        return {
            "attack": False,
            "label": "MODEL_NOT_LOADED",
            "confidence": 0,
            "probabilities": {},
            "threshold": ATTACK_THRESHOLD,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }

    try:

        # =====================================================
        # SHOW TOP INPUT FEATURES
        # =====================================================

        print("\nTop Input Features")
        print("=" * 60)

        for name, value in sorted(
            features.items(),
            key=lambda x: abs(float(x[1])) if isinstance(x[1], (int, float)) else 0,
            reverse=True
        )[:10]:

            print(f"{name:<35} {value}")

        print("=" * 60)

        # =====================================================
        # PREPROCESS
        # =====================================================

        X = preprocess(features)

        # =====================================================
        # PREDICTION
        # =====================================================

        prediction = model.predict(X)[0]

        probabilities = model.predict_proba(X)[0]

        confidence = round(float(max(probabilities) * 100), 2)

        label = encoder.inverse_transform([prediction])[0]

        probability_map = {}

        for cls, prob in zip(
            encoder.classes_,
            probabilities,
        ):

            probability_map[cls] = round(
                float(prob * 100),
                2,
            )

        # =====================================================
        # SHOW PROBABILITIES
        # =====================================================

        print("\nPrediction Probabilities")
        print("=" * 60)

        for cls, prob in zip(
            encoder.classes_,
            probabilities,
        ):

            print(f"{cls:<30} {prob * 100:.2f}%")

        print("=" * 60)

        # =====================================================
        # FINAL RESULT
        # =====================================================

        attack = (
            label != "BENIGN"
            and confidence >= ATTACK_THRESHOLD
        )

        print("\nPrediction Result")
        print("=" * 60)
        print("Label      :", label)
        print("Confidence :", confidence)
        print("Attack     :", attack)
        print("Threshold  :", ATTACK_THRESHOLD)
        print("=" * 60)

        return {

            "attack": attack,

            "label": label,

            "confidence": confidence,

            "threshold": ATTACK_THRESHOLD,

            "probabilities": probability_map,

            "timestamp": datetime.now().strftime("%H:%M:%S"),

        }

    except Exception as e:

        logger.exception("Prediction Error")

        return {

            "attack": False,

            "label": "ERROR",

            "confidence": 0,

            "threshold": ATTACK_THRESHOLD,

            "probabilities": {},

            "timestamp": datetime.now().strftime("%H:%M:%S"),

            "error": str(e),

        }
# ==========================================================
# HEALTH CHECK
# ==========================================================

def health():

    return {

        "model_loaded": MODEL_LOADED,

        "feature_count": len(feature_columns),

        "classes": (
            list(encoder.classes_)
            if MODEL_LOADED
            else []
        ),

    }