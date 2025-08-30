"""
Model validation and consistency checker for production deployment.
Ensures model outputs remain consistent across redeployments.
"""

import os
import hashlib
import joblib
import numpy as np
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ModelValidator:
    """Validates model consistency and provides versioning information."""
    
    def __init__(self, model_path: str = "models/xgb_model.joblib"):
        self.model_path = model_path
        self.model_hash = None
        self.feature_order_hash = None
        self.threshold_hash = None
        
    def get_model_hash(self) -> str:
        """Get SHA256 hash of the model file."""
        if self.model_hash is None:
            with open(self.model_path, 'rb') as f:
                content = f.read()
                self.model_hash = hashlib.sha256(content).hexdigest()
        return self.model_hash
    
    def get_feature_order_hash(self, feature_order: list) -> str:
        """Get hash of feature order to ensure consistency."""
        feature_str = "|".join(sorted(feature_order))
        return hashlib.sha256(feature_str.encode()).hexdigest()
    
    def get_threshold_hash(self, threshold: float) -> str:
        """Get hash of threshold configuration."""
        threshold_str = f"{threshold:.6f}"
        return hashlib.sha256(threshold_str.encode()).hexdigest()
    
    def validate_model_consistency(self, model_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Validate model consistency and return version info."""
        try:
            # Get hashes
            model_hash = self.get_model_hash()
            feature_order = model_obj.get("feature_order", [])
            feature_hash = self.get_feature_order_hash(feature_order)
            threshold = model_obj.get("tuned_threshold", 0.61)
            threshold_hash = self.get_threshold_hash(threshold)
            
            # Create version info
            version_info = {
                "model_hash": model_hash,
                "feature_order_hash": feature_hash,
                "threshold_hash": threshold_hash,
                "model_version": f"{model_hash[:8]}_{feature_hash[:8]}",
                "threshold": float(threshold),
                "feature_count": int(len(feature_order)),
                "model_type": type(model_obj.get("model")).__name__,
                "is_consistent": True
            }
            
            # Log version info
            logger.info(f"Model loaded successfully: {version_info['model_version']}")
            logger.info(f"Threshold: {threshold}")
            logger.info(f"Features: {len(feature_order)}")
            
            return version_info
            
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return {
                "is_consistent": False,
                "error": str(e)
            }
    
    def test_model_prediction_consistency(self, model_obj: Dict[str, Any], test_input: np.ndarray) -> Dict[str, Any]:
        """Test if model produces consistent predictions."""
        try:
            model = model_obj["model"]
            
            # Make multiple predictions
            predictions = []
            probabilities = []
            
            for _ in range(3):
                pred = model.predict(test_input)[0]
                prob = model.predict_proba(test_input)[0, 1]
                predictions.append(pred)
                probabilities.append(prob)
            
            # Check consistency
            pred_consistent = len(set(predictions)) == 1
            prob_consistent = all(abs(prob - probabilities[0]) < 1e-6 for prob in probabilities)
            
            return {
                "predictions_consistent": pred_consistent,
                "probabilities_consistent": prob_consistent,
                "test_predictions": [int(p) for p in predictions],
                "test_probabilities": [float(p) for p in probabilities],
                "is_consistent": pred_consistent and prob_consistent
            }
            
        except Exception as e:
            logger.error(f"Prediction consistency test failed: {e}")
            return {
                "is_consistent": False,
                "error": str(e)
            }

def get_model_version_info() -> Dict[str, Any]:
    """Get current model version information for deployment tracking."""
    validator = ModelValidator()
    
    try:
        # Load model
        model_obj = joblib.load("models/xgb_model.joblib")
        
        # Validate consistency
        version_info = validator.validate_model_consistency(model_obj)
        
        # Test prediction consistency
        test_input = np.zeros((1, len(model_obj["feature_order"])))
        prediction_test = validator.test_model_prediction_consistency(model_obj, test_input)
        
        # Add additional model information from new format
        additional_info = {}
        if "model_version" in model_obj:
            additional_info["model_version"] = model_obj["model_version"]
        if "training_date" in model_obj:
            additional_info["training_date"] = model_obj["training_date"]
        if "metrics" in model_obj:
            additional_info["training_metrics"] = model_obj["metrics"]
        if "data_info" in model_obj:
            additional_info["training_data_info"] = model_obj["data_info"]
        
        # Convert all numpy types to Python types for JSON serialization
        def convert_numpy_types(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_numpy_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy_types(item) for item in obj]
            else:
                return obj
        
        # Convert all values to JSON-serializable types
        version_info = convert_numpy_types(version_info)
        prediction_test = convert_numpy_types(prediction_test)
        additional_info = convert_numpy_types(additional_info)
        
        version_info.update(prediction_test)
        version_info.update(additional_info)
        
        return version_info
        
    except Exception as e:
        logger.error(f"Failed to get model version info: {e}")
        return {
            "is_consistent": False,
            "error": str(e)
        }

if __name__ == "__main__":
    # Test model validation
    version_info = get_model_version_info()
    print("Model Version Info:")
    print(f"Version: {version_info.get('model_version', 'Unknown')}")
    print(f"Consistent: {version_info.get('is_consistent', False)}")
    print(f"Threshold: {version_info.get('threshold', 'Unknown')}")
    print(f"Features: {version_info.get('feature_count', 'Unknown')}")
