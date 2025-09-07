import hashlib
import json
import os
from typing import Dict, List, Optional

import joblib


def ensure_dirs() -> None:
    """Create required directories if missing."""
    for path in [
        os.path.join("artifacts", "static_jsons"),
        os.path.join("artifacts", "reports"),
        os.path.join("artifacts", "threat_intel"),
        os.path.join("models"),
        os.path.join("data"),
    ]:
        os.makedirs(path, exist_ok=True)


def get_sha256(path: str) -> str:
    """Compute SHA256 of a file in a memory-efficient way."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def vectorize_feature_dict(feature_dict: Dict, feature_order: List[str]) -> List[int]:
    """Vectorize a feature dictionary using a fixed feature order.

    Assumes binary features (0/1). Missing keys default to 0.
    """
    vector = []
    for key in feature_order:
        value = feature_dict.get(key, 0)
        if isinstance(value, bool):
            value = int(value)
        try:
            value = int(value)
        except Exception:
            value = 0
        vector.append(value)
    return vector


def load_model(model_path: str):
    """Load a joblib-saved model; raise FileNotFoundError if missing."""
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Train the model first.")
    return joblib.load(model_path)


def load_bank_whitelist(path: Optional[str] = None) -> Dict[str, str]:
    """Load a map of official bank package IDs to human names.

    Default looks for ml/bank_whitelist.json. Returns empty dict if missing.
    Schema: {"com.bank.package": "Bank Name", ...}
    """
    if path is None:
        path = os.path.join("ml", "bank_whitelist.json")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}



