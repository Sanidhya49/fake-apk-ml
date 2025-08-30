"""Train model on features.csv and save model + SHAP summary.

Usage:
    python -m ml.train
    python -m ml.train --config custom_config.yaml
"""

import os
import argparse
import yaml
from typing import List, Dict, Any, Optional
import warnings
warnings.filterwarnings('ignore')

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support, roc_curve, roc_auc_score
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from sklearn.calibration import CalibratedClassifierCV
from datetime import datetime


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load training configuration from file or use defaults."""
    default_config = {
        # Model parameters
        "model_type": "xgboost",  # "xgboost" or "randomforest"
        "xgboost_params": {
            "n_estimators": 200,
            "max_depth": 4,
            "learning_rate": 0.1,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "eval_metric": "logloss",
            "random_state": 42,
            "tree_method": "hist"
        },
        "randomforest_params": {
            "n_estimators": 300,
            "max_depth": 10,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42
        },
        
        # Training parameters
        "test_size": 0.25,
        "random_state": 42,
        "cv_folds": 5,
        
        # Threshold tuning
        "threshold_tuning": True,
        "threshold_range": [0.1, 0.9],  # min, max
        "threshold_step": 0.05,
        "threshold_metric": "f1",  # "f1", "precision", "recall", "balanced_accuracy"
        
        # Calibration
        "enable_calibration": True,
        "calibration_method": "isotonic",  # "isotonic" or "sigmoid"
        "calibration_cv": 3,
        
        # Novelty detection
        "enable_novelty_detector": True,
        "novelty_contamination": 0.1,
        "min_legit_samples": 20,
        
        # SHAP analysis
        "enable_shap": True,
        "shap_top_features": 3,
        "shap_max_samples": 100,
        
        # Output
        "save_model": True,
        "save_artifacts": True,
        "model_version": None  # Auto-generated if None
    }
    
    if config_path and os.path.exists(config_path):
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
        # Merge user config with defaults
        for key, value in user_config.items():
            if key in default_config:
                if isinstance(value, dict) and isinstance(default_config[key], dict):
                    default_config[key].update(value)
                else:
                    default_config[key] = value
    
    return default_config


def _get_feature_columns(df: pd.DataFrame) -> List[str]:
    """Get numeric feature columns, excluding metadata fields."""
    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    # Exclude metadata columns
    exclude_cols = ['sha256', 'label', 'file_name', 'package', 'version', 'app_label_text']
    feature_cols = [col for col in numeric_cols if col not in exclude_cols]
    return feature_cols


def tune_threshold(y_true: np.ndarray, y_proba: np.ndarray, config: Dict[str, Any]) -> float:
    """Tune threshold using specified metric and range."""
    if not config["threshold_tuning"]:
        return 0.5
    
    min_thresh, max_thresh = config["threshold_range"]
    step = config["threshold_step"]
    metric = config["threshold_metric"]
    
    thresholds = np.arange(min_thresh, max_thresh + step, step)
    best_score = -1.0
    best_threshold = 0.5
    
    print(f"Tuning threshold using {metric} metric...")
    
    for threshold in thresholds:
        y_pred = (y_proba >= threshold).astype(int)
        
        if metric == "f1":
            _, _, score, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
        elif metric == "precision":
            score, _, _, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
        elif metric == "recall":
            _, score, _, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
        elif metric == "balanced_accuracy":
            score = (y_pred == y_true).mean()
        else:
            continue
        
        if score > best_score:
            best_score = score
            best_threshold = threshold
    
    print(f"Best threshold: {best_threshold:.4f} ({metric}: {best_score:.4f})")
    return best_threshold


def create_model(config: Dict[str, Any]):
    """Create model based on configuration."""
    model_type = config["model_type"].lower()
    
    if model_type == "xgboost":
        try:
            from xgboost import XGBClassifier
            model = XGBClassifier(**config["xgboost_params"])
            return model, "xgboost"
        except ImportError:
            print("XGBoost not available, falling back to RandomForest")
            model_type = "randomforest"
    
    if model_type == "randomforest":
        model = RandomForestClassifier(**config["randomforest_params"])
        return model, "randomforest"
    
    raise ValueError(f"Unsupported model type: {model_type}")


def main():
    parser = argparse.ArgumentParser(description="Train APK fake detection model")
    parser.add_argument("--config", type=str, help="Path to configuration YAML file")
    parser.add_argument("--features", type=str, default="artifacts/features.csv", help="Path to features CSV")
    parser.add_argument("--output", type=str, default="models/xgb_model.joblib", help="Output model path")
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Auto-generate model version if not specified
    if config["model_version"] is None:
        config["model_version"] = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"[START] Starting model training with configuration:")
    print(f"   Model Type: {config['model_type']}")
    print(f"   Threshold Tuning: {config['threshold_tuning']}")
    print(f"   Calibration: {config['enable_calibration']}")
    print(f"   Model Version: {config['model_version']}")
    print()
    
    # Load data
    features_path = args.features
    if not os.path.exists(features_path):
        raise FileNotFoundError(f"{features_path} not found. Run feature_builder first.")

    print(f"[DATA] Loading data from {features_path}")
    df = pd.read_csv(features_path)
    
    # Filter data
    before = len(df)
    df = df[df["label"].isin(["legit", "fake"])].copy()
    dropped = before - len(df)
    if dropped > 0:
        print(f"   Dropped {dropped} rows with unknown labels")
    
    print(f"   Dataset: {len(df)} samples ({df['label'].value_counts().to_dict()})")
    
    # Prepare features and labels
    feature_cols = _get_feature_columns(df)
    print(f"   Features: {len(feature_cols)} numeric features")

    label_map = {"legit": 0, "fake": 1}
    y = df["label"].map(label_map)
    X = df[feature_cols].astype(float).values

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y.values, 
        test_size=config["test_size"], 
        random_state=config["random_state"], 
        stratify=y.values
    )
    
    print(f"   Train: {len(X_train)} samples, Test: {len(X_test)} samples")
    print()
    
    # Create and train model
    print("[MODEL] Creating model...")
    model, model_name = create_model(config)
    
    # Cross-validation
    print("[CV] Running cross-validation...")
    cv_scores = cross_val_score(
        model, X_train, y_train, 
        cv=StratifiedKFold(n_splits=config["cv_folds"], shuffle=True, random_state=config["random_state"]),
        scoring='f1'
    )
    print(f"   CV F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Train final model
    print("[TRAIN] Training final model...")
        model.fit(X_train, y_train)
    
    # Calibration
    if config["enable_calibration"]:
        print("[CALIB] Calibrating probabilities...")
        try:
            calib = CalibratedClassifierCV(
                model, 
                method=config["calibration_method"], 
                cv=config["calibration_cv"]
            )
        calib.fit(X_train, y_train)
            final_model = calib
        model_name += "+cal"
    except Exception as e:
            print(f"   Calibration failed ({e}), using raw model")
            final_model = model
    else:
        final_model = model

    # Evaluation
    print("[EVAL] Evaluating model...")
    y_pred = final_model.predict(X_test)
    y_proba = final_model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    acc = float(accuracy_score(y_test, y_pred))
    pr, rc, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    auc = float(roc_auc_score(y_test, y_proba))
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, digits=4))
    print(f"ROC AUC: {auc:.4f}")
    print(f"Accuracy: {acc:.4f}")
    print(f"Precision: {pr:.4f}")
    print(f"Recall: {rc:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print()
    
    # Threshold tuning
    tuned_threshold = tune_threshold(y_test, y_proba, config)
    
    # Save model
    if config["save_model"]:
        print("[SAVE] Saving model...")
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        
        model_data = {
            "model": final_model,
        "feature_order": feature_cols,
        "label_map": {"0": "legit", "1": "fake"},
        "model_name": model_name,
        "tuned_threshold": tuned_threshold,
            "model_version": config["model_version"],
            "training_config": config,
            "metrics": {
                "accuracy": acc,
                "precision": float(pr),
                "recall": float(rc),
                "f1": float(f1),
                "auc": auc,
                "cv_f1_mean": float(cv_scores.mean()),
                "cv_f1_std": float(cv_scores.std())
            },
            "training_date": datetime.now().isoformat(),
            "data_info": {
                "total_samples": len(df),
                "train_samples": len(X_train),
                "test_samples": len(X_test),
                "feature_count": len(feature_cols),
                "label_distribution": df["label"].value_counts().to_dict()
            }
        }
        
        joblib.dump(model_data, args.output)
        print(f"   Model saved to: {args.output}")
    
    # Novelty detector
    if config["enable_novelty_detector"]:
        print("[NOVELTY] Creating novelty detector...")
    try:
        legit_mask = (y == 0).values
        X_legit = df.loc[legit_mask, feature_cols].astype(float).values
            
            if X_legit.shape[0] >= config["min_legit_samples"]:
                nov = IsolationForest(
                    random_state=config["random_state"], 
                    contamination=config["novelty_contamination"]
                )
            nov.fit(X_legit)
                
                novelty_path = "models/novelty.joblib"
            joblib.dump({
                "model": nov,
                "feature_order": feature_cols,
                "type": "isolation_forest",
                    "training_date": datetime.now().isoformat()
                }, novelty_path)
                print(f"   Novelty detector saved to: {novelty_path}")
        else:
                print(f"   Skipping novelty detector (need {config['min_legit_samples']}+ legit samples, got {X_legit.shape[0]})")
    except Exception as e:
            print(f"   Novelty detector failed: {e}")
    
    # SHAP analysis
    if config["enable_shap"]:
        print("[SHAP] Generating SHAP analysis...")
        try:
            import shap
            
            # Limit samples for performance
            max_samples = min(config["shap_max_samples"], len(X_test))
            X_test_shap = X_test[:max_samples]
            y_test_shap = y_test[:max_samples]
            
            # Get SHAP values
        try:
            explainer = shap.TreeExplainer(model)
                shap_values = explainer.shap_values(X_test_shap)
            if isinstance(shap_values, list):
                sv = shap_values[1]
            else:
                sv = shap_values
        except Exception:
                # Fallback to KernelExplainer
            background = X_train[:50]
            explainer = shap.KernelExplainer(model.predict_proba, background)
                sv = explainer.shap_values(X_test_shap)[1]

            # Generate top features summary
        top_rows = []
            for i in range(len(X_test_shap)):
            row_sv = sv[i]
                top_idx = np.argsort(np.abs(row_sv))[::-1][:config["shap_top_features"]]
            for rank, j in enumerate(top_idx, 1):
                top_rows.append({
                    "sample_index": int(i),
                    "feature": feature_cols[j],
                    "shap_value": float(row_sv[j]),
                    "rank": int(rank),
                })
            
        shap_df = pd.DataFrame(top_rows)
            shap_path = os.path.join("artifacts", "shap_summary.csv")
            os.makedirs(os.path.dirname(shap_path), exist_ok=True)
            shap_df.to_csv(shap_path, index=False)
            print(f"   SHAP summary saved to: {shap_path}")
            
    except Exception as e:
            print(f"   SHAP analysis failed: {e}")

    # MLflow tracking (optional)
    try:
        import mlflow
        print("[MLFLOW] Logging to MLflow...")
        with mlflow.start_run(run_name=f"fake-apk-ml-{config['model_version']}"):
            mlflow.log_param("model_name", model_name)
            mlflow.log_param("model_version", config["model_version"])
            mlflow.log_param("feature_count", len(feature_cols))
            mlflow.log_param("tuned_threshold", tuned_threshold)
            mlflow.log_metric("accuracy", acc)
            mlflow.log_metric("precision", float(pr))
            mlflow.log_metric("recall", float(rc))
            mlflow.log_metric("f1", float(f1))
            mlflow.log_metric("auc", auc)
            mlflow.log_metric("cv_f1_mean", float(cv_scores.mean()))
            mlflow.log_metric("cv_f1_std", float(cv_scores.std()))
            
            # Log model
            if config["save_model"]:
                mlflow.log_artifact(args.output)
            
            # Log SHAP
            if config["enable_shap"]:
                shap_path = os.path.join("artifacts", "shap_summary.csv")
                if os.path.exists(shap_path):
                    mlflow.log_artifact(shap_path)
        
        print("   MLflow logging completed")
    except Exception as e:
        print(f"   MLflow logging failed: {e}")
    
    print()
    print("[SUCCESS] Training completed successfully!")
    print(f"[THRESHOLD] Final threshold: {tuned_threshold:.4f}")
    print(f"[PERFORMANCE] Model performance: F1={f1:.4f}, AUC={auc:.4f}")
    print(f"[SAVED] Model saved: {args.output}")


if __name__ == "__main__":
    main()



