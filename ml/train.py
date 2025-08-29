"""Train model on features.csv and save model + SHAP summary.

Usage:
    python -m ml.train
"""

import os
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from sklearn.calibration import CalibratedClassifierCV


def _get_feature_columns(df: pd.DataFrame) -> List[str]:
    # Use numeric-only columns to avoid string ID/metadata fields
    # (e.g., package, version, app_label_text) from entering the model.
    return df.select_dtypes(include=["number"]).columns.tolist()


def main():
    features_path = os.path.join("artifacts", "features.csv")
    if not os.path.exists(features_path):
        raise FileNotFoundError("artifacts/features.csv not found. Run feature_builder first.")

    df = pd.read_csv(features_path)
    # Filter out any rows without known labels (e.g., scans outside data/legit|data/fake)
    before = len(df)
    df = df[df["label"].isin(["legit", "fake"])].copy()
    dropped = before - len(df)
    if dropped > 0:
        print(f"Info: Dropped {dropped} rows with unknown label from features.csv")
    feature_cols = _get_feature_columns(df)

    # Map labels
    label_map = {"legit": 0, "fake": 1}
    y = df["label"].map(label_map)
    if y.isna().any():
        raise ValueError("Found unknown labels. Ensure data paths include /data/legit/ or /data/fake/.")

    X = df[feature_cols].astype(float).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y.values, test_size=0.25, random_state=42, stratify=y.values
    )

    # Try XGBoost, else fallback to RandomForest
    model = None
    try:
        from xgboost import XGBClassifier  # type: ignore

        model = XGBClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
            tree_method="hist",
        )
        model.fit(X_train, y_train)
        model_name = "xgboost"
    except Exception as e:
        print(f"XGBoost unavailable or failed ({e}). Falling back to RandomForest.")
        model = RandomForestClassifier(n_estimators=300, random_state=42)
        model.fit(X_train, y_train)
        model_name = "randomforest"

    # Calibration (improves probability quality)
    try:
        calib = CalibratedClassifierCV(model, method="isotonic", cv=3)
        calib.fit(X_train, y_train)
        cal_model = calib
        model_name += "+cal"
    except Exception as e:
        print(f"Calibration skipped ({e}); using raw model probabilities")
        cal_model = model

    # Evaluation
    y_pred = cal_model.predict(X_test)
    try:
        y_proba = cal_model.predict_proba(X_test)[:, 1]
    except Exception:
        # Some classifiers may not support predict_proba
        y_proba = (y_pred == 1).astype(float)

    print("Classification report:\n", classification_report(y_test, y_pred, digits=4))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

    # Compute simple metrics for optional tracking
    acc = float(accuracy_score(y_test, y_pred))
    pr, rc, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)

    # Determine best threshold by maximizing F1 on validation set
    try:
        fpr, tpr, thr = roc_curve(y_test, y_proba)
        # Evaluate F1 across candidate thresholds
        best_f1 = -1.0
        best_thr = 0.5
        import numpy as _np
        for t in thr:
            yp = (y_proba >= t).astype(int)
            _p, _r, _f1, _ = precision_recall_fscore_support(y_test, yp, average="binary", zero_division=0)
            if _f1 > best_f1:
                best_f1 = float(_f1)
                best_thr = float(t)
        tuned_threshold = max(0.3, min(0.9, best_thr))
        print(f"Selected tuned threshold = {tuned_threshold:.4f} (max F1 on validation)")
    except Exception as e:
        print(f"Threshold tuning failed ({e}); defaulting to 0.61")
        tuned_threshold = 0.61

    # Save model and feature order for inference
    os.makedirs("models", exist_ok=True)
    joblib.dump({
        "model": cal_model,
        "feature_order": feature_cols,
        "label_map": {"0": "legit", "1": "fake"},
        "model_name": model_name,
        "tuned_threshold": tuned_threshold,
    }, os.path.join("models", "xgb_model.joblib"))
    print("Saved model -> models/xgb_model.joblib")

    # Novelty detector (fit on legit-only samples)
    try:
        legit_mask = (y == 0).values
        X_legit = df.loc[legit_mask, feature_cols].astype(float).values
        if X_legit.shape[0] >= 20:  # need enough samples
            nov = IsolationForest(random_state=42, contamination=0.1)
            nov.fit(X_legit)
            joblib.dump({
                "model": nov,
                "feature_order": feature_cols,
                "type": "isolation_forest",
            }, os.path.join("models", "novelty.joblib"))
            print("Saved novelty detector -> models/novelty.joblib")
        else:
            print("Skipping novelty detector (too few legit samples)")
    except Exception as e:
        print(f"Skipping novelty detector due to: {e}")

    # SHAP summary (top-3 per sample)
    try:
        import shap  # type: ignore

        # Use TreeExplainer if possible; else KernelExplainer
        explainer = None
        try:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_test)
            # shap_values can be array (binary) or list (multiclass). Take positive class.
            if isinstance(shap_values, list):
                sv = shap_values[1]
            else:
                sv = shap_values
        except Exception:
            # KernelExplainer fallback is expensive; limit to first 50 samples
            background = X_train[:50]
            explainer = shap.KernelExplainer(model.predict_proba, background)
            sv = explainer.shap_values(X_test[:50])[1]
            X_test = X_test[:50]
            y_test = y_test[:50]

        top_rows = []
        for i in range(len(X_test)):
            row_sv = sv[i]
            # top 3 absolute shap values
            top_idx = np.argsort(np.abs(row_sv))[::-1][:3]
            for rank, j in enumerate(top_idx, 1):
                top_rows.append({
                    "sample_index": int(i),
                    "feature": feature_cols[j],
                    "shap_value": float(row_sv[j]),
                    "rank": int(rank),
                })
        shap_df = pd.DataFrame(top_rows)
        out_csv = os.path.join("artifacts", "shap_summary.csv")
        os.makedirs(os.path.dirname(out_csv), exist_ok=True)
        shap_df.to_csv(out_csv, index=False)
        print(f"Saved SHAP top-3 per sample -> {out_csv}")
    except Exception as e:
        print(f"Skipping SHAP due to: {e}")

    # Optional MLflow tracking
    try:
        import mlflow  # type: ignore
        with mlflow.start_run(run_name="fake-apk-ml"):
            mlflow.log_param("model_name", model_name)
            mlflow.log_param("feature_count", len(feature_cols))
            mlflow.log_metric("accuracy", acc)
            mlflow.log_metric("precision", float(pr))
            mlflow.log_metric("recall", float(rc))
            mlflow.log_metric("f1", float(f1))
            try:
                mlflow.log_artifact(os.path.join("models", "xgb_model.joblib"))
            except Exception:
                pass
            shap_csv = os.path.join("artifacts", "shap_summary.csv")
            if os.path.exists(shap_csv):
                try:
                    mlflow.log_artifact(shap_csv)
                except Exception:
                    pass
        print("Logged metrics to MLflow (if available)")
    except Exception as e:
        print(f"Skipping MLflow tracking: {e}")


if __name__ == "__main__":
    main()



