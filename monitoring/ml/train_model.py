import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ===========================================
# Paths
# ===========================================

BASE_DIR = os.path.dirname(__file__)

DATASET_FOLDER = os.path.join(BASE_DIR, "dataset")

MODEL_PATH = os.path.join(BASE_DIR, "random_forest.pkl")

SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")

FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")

# ===========================================
# Load all CSV files
# ===========================================

csv_files = glob.glob(os.path.join(DATASET_FOLDER, "*.csv"))

if not csv_files:
    raise FileNotFoundError("No CSV files found in dataset folder.")

print(f"Found {len(csv_files)} dataset files.\n")

dataframes = []

for file in csv_files:
    print("Loading:", os.path.basename(file))
    df = pd.read_csv(file, low_memory=False)
    dataframes.append(df)

dataset = pd.concat(dataframes, ignore_index=True)

print("\nDataset merged successfully.")
print("Original Shape:", dataset.shape)

# ===========================================
# FIX COLUMN NAMES
# ===========================================

# Remove leading/trailing spaces
dataset.columns = dataset.columns.str.strip()

print("\nColumns Found:")
print(dataset.columns.tolist())

# Ensure Label column exists
if "Label" not in dataset.columns:
    raise Exception(
        f"'Label' column not found.\nAvailable columns:\n{dataset.columns.tolist()}"
    )

# ===========================================
# Clean Dataset
# ===========================================

dataset.replace([np.inf, -np.inf], np.nan, inplace=True)

dataset.dropna(inplace=True)

dataset.drop_duplicates(inplace=True)

print("\nShape after cleaning:", dataset.shape)

# ===========================================
# Encode Labels
# ===========================================

label_encoder = LabelEncoder()

dataset["Label"] = label_encoder.fit_transform(dataset["Label"])

print("\nAttack Classes:")
print(label_encoder.classes_)

# ===========================================
# Features / Target
# ===========================================

X = dataset.drop(columns=["Label"])

# Keep only numeric columns
X = X.select_dtypes(include=[np.number])

y = dataset["Label"]

print("\nNumber of Features:", X.shape[1])

# ===========================================
# Train/Test Split
# ===========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# ===========================================
# Scale Features
# ===========================================

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)

X_test = scaler.transform(X_test)

# ===========================================
# Train Random Forest
# ===========================================

print("\nTraining Random Forest...\n")

model = RandomForestClassifier(
    n_estimators=30,      # Faster training
    max_depth=20,         # Limits tree depth
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ===========================================
# Evaluate
# ===========================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", accuracy)

print("\nClassification Report:\n")

print(classification_report(y_test, predictions))

print("\nConfusion Matrix:\n")

print(confusion_matrix(y_test, predictions))

# ===========================================
# Save Everything
# ===========================================

joblib.dump(model, MODEL_PATH)

joblib.dump(scaler, SCALER_PATH)

joblib.dump(label_encoder, ENCODER_PATH)

joblib.dump(list(X.columns), FEATURES_PATH)

print("\n===================================")
print("Model Saved Successfully")
print("===================================")

print("Model:", MODEL_PATH)
print("Scaler:", SCALER_PATH)
print("Encoder:", ENCODER_PATH)
print("Features:", FEATURES_PATH)