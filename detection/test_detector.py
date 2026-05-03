# detection/test_detector.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.detector import classify_traffic, model

print(f"Feature count expected: {model.n_features_in_}")
print(f"Classes: {list(model.classes_)}\n")

# Simulate a dummy traffic vector (all zeros = safe test)
dummy_features = [0] * model.n_features_in_

result = classify_traffic(dummy_features)
print("── Test Result ──")
for k, v in result.items():
    print(f"  {k}: {v}")