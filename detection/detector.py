# detection/detector.py
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import MODEL_PATH

# ── Load model once at import ──
model = joblib.load(MODEL_PATH)
CLASSES = model.classes_
print(f"[DETECTOR] Model loaded → classes: {list(CLASSES)}")

# ── Map integer labels → attack names ──
# Standard NSL-KDD encoding: 0=Normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R
# If your output is different, adjust this map accordingly
LABEL_MAP = {
    0: "normal",
    1: "dos",
    2: "probe",
    3: "r2l",
    4: "u2r",
}

# ── Attack severity per category ──
SEVERITY_MAP = {
    "normal": None,
    "dos":    "critical",
    "probe":  "medium",
    "r2l":    "high",
    "u2r":    "critical",
}

def classify_traffic(feature_vector: list) -> dict:
    """
    Takes a list of numeric NSL-KDD features,
    returns a detection result dict.
    """
    features = np.array(feature_vector).reshape(1, -1)
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = float(max(probabilities))

    # Convert int label → string name
    label = LABEL_MAP.get(int(prediction), f"unknown_{prediction}")
    is_attack = label != "normal"
    severity = SEVERITY_MAP.get(label, "medium") if is_attack else None

    return {
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "label_id":   int(prediction),
        "prediction": label.upper(),
        "confidence": round(confidence, 4),
        "is_attack":  is_attack,
        "severity":   severity,
    }

def classify_from_dataframe(df: pd.DataFrame) -> list:
    """
    Batch classify a DataFrame of traffic records.
    Returns list of result dicts.
    """
    results = []
    for _, row in df.iterrows():
        result = classify_traffic(row.tolist())
        results.append(result)
    return results