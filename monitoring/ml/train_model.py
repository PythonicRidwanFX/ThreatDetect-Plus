import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_FOLDER = os.path.join(BASE_DIR, "dataset")

MODEL_PATH = os.path.join(BASE_DIR, "random_forest.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")

# ==========================================================
# LOAD DATASET
# ==========================================================

csv_files = glob.glob(os.path.join(DATASET_FOLDER, "*.csv"))

if not csv_files:
    raise FileNotFoundError("No dataset found.")

frames = []

for file in csv_files:
    print("Loading:", os.path.basename(file))
    frames.append(pd.read_csv(file, low_memory=False))

dataset = pd.concat(frames, ignore_index=True)

dataset.columns = dataset.columns.str.strip()

dataset.replace([np.inf, -np.inf], np.nan, inplace=True)

dataset.dropna(inplace=True)

dataset.drop_duplicates(inplace=True)

# ==========================================================
# FEATURES USED BY LIVE SYSTEM
# ==========================================================

FEATURE_COLUMNS = [

    "Destination Port",
    "Flow Duration",

    "Total Fwd Packets",
    "Total Backward Packets",

    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",

    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",

    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",

    "Flow Bytes/s",
    "Flow Packets/s",

    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",

    "Min Packet Length",
    "Max Packet Length",

    "Average Packet Size",

    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "URG Flag Count",

    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",

    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",

    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",

]

missing = [c for c in FEATURE_COLUMNS if c not in dataset.columns]

if missing:
    print("\nMissing Columns:")
    print(missing)
    raise Exception("Dataset missing required columns.")

X = dataset[FEATURE_COLUMNS]

encoder = LabelEncoder()

y = encoder.fit_transform(dataset["Label"])

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)

X_test = scaler.transform(X_test)

print("\nTraining Random Forest...\n")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, pred))

print(classification_report(
    y_test,
    pred,
    target_names=encoder.classes_
))

joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(encoder, ENCODER_PATH)
joblib.dump(FEATURE_COLUMNS, FEATURES_PATH)

print("\n===================================")
print("MODEL TRAINED SUCCESSFULLY")
print("===================================")

print("Features:", len(FEATURE_COLUMNS))
print("Model:", MODEL_PATH)
print("Scaler:", SCALER_PATH)
print("Encoder:", ENCODER_PATH)
print("Feature List:", FEATURES_PATH)