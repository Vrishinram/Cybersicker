"""
CYBERSICKER — ML Anomaly Detection Engine
Deep autoencoder + PCA for IoT network traffic analysis.
Caches and persists trained model + StandardScaler + PCA for fast inference.
Supports TensorFlow / Keras with graceful scikit-learn MLP fallback if TensorFlow is absent.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

try:
    import tensorflow as tf
    from tensorflow.keras.layers import Dense
    from tensorflow.keras.models import Sequential, load_model
    HAS_TF = True
except ImportError:
    HAS_TF = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Cybersicker.MLDetection")

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

MITRE_MAP = [
    {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
]


def _load_numeric(filepath: str | Path) -> pd.DataFrame:
    path = Path(filepath)
    if not path.is_file():
        fallback = BASE_DIR / "KDDTrain+.txt"
        if fallback.is_file() and path.name in ("KDDTrain+.txt", "KDDTrain+.csv"):
            path = fallback
        else:
            raise FileNotFoundError(f"Traffic file not found: {filepath}")

    dataset = pd.read_csv(path, header=None)
    numeric = dataset.select_dtypes(include=["number"])
    if numeric.empty:
        raise ValueError("No numeric columns found to analyze.")
    return numeric


def _build_autoencoder(input_dim: int):
    if HAS_TF:
        model = Sequential(
            [
                tf.keras.Input(shape=(input_dim,)),
                Dense(16, activation="relu"),
                Dense(8, activation="relu"),
                Dense(16, activation="relu"),
                Dense(input_dim, activation="linear"),
            ]
        )
        model.compile(optimizer="adam", loss="mse")
        return model
    else:
        # Fallback neural network autoencoder using scikit-learn MLPRegressor
        return MLPRegressor(
            hidden_layer_sizes=(16, 8, 16),
            activation="relu",
            max_iter=15,
            random_state=42,
        )


def _severity(anomaly_pct: float) -> dict[str, Any]:
    if anomaly_pct > 10:
        return {
            "level": "CRITICAL",
            "confidence": "CRITICAL — Multiple attack patterns detected",
            "verdict": "HIGH RISK",
        }
    if anomaly_pct > 5:
        return {
            "level": "HIGH",
            "confidence": "HIGH — Significant anomaly activity",
            "verdict": "HIGH RISK",
        }
    if anomaly_pct > 2:
        return {
            "level": "MEDIUM",
            "confidence": "MEDIUM — Suspicious patterns detected",
            "verdict": "MODERATE",
        }
    return {
        "level": "LOW",
        "confidence": "LOW — Normal network behavior",
        "verdict": "LOW RISK",
    }


def analyze_network_data(
    filepath: str | Path,
    anomaly_threshold: float = 0.5,
    retrain: bool = False,
) -> dict[str, Any]:
    """
    Run ML-based anomaly detection using deep autoencoder and PCA.
    Persists and reloads model, scaler, and PCA artifacts in `models/`.
    """
    path = Path(filepath)
    if not path.is_file():
        fallback = BASE_DIR / "KDDTrain+.txt"
        if fallback.is_file() and path.name in ("KDDTrain+.txt", "KDDTrain+.csv"):
            path = fallback
        else:
            raise FileNotFoundError(f"Traffic file not found: {filepath}")

    numeric_data = _load_numeric(path)
    total = len(numeric_data)

    model_path = MODEL_DIR / ("autoencoder.keras" if HAS_TF else "autoencoder_mlp.joblib")
    scaler_path = MODEL_DIR / "scaler.joblib"
    pca_path = MODEL_DIR / "pca.joblib"
    meta_path = MODEL_DIR / "metadata.json"

    if (
        not retrain
        and model_path.exists()
        and scaler_path.exists()
        and pca_path.exists()
    ):
        logger.info("Loading persisted autoencoder, scaler, and PCA from %s", MODEL_DIR)
        model = load_model(model_path) if HAS_TF else joblib.load(model_path)
        scaler: StandardScaler = joblib.load(scaler_path)
        pca: PCA = joblib.load(pca_path)
        scaled = scaler.transform(numeric_data)
        reduced = pca.transform(scaled)
        input_dim = reduced.shape[1]
        trained = False
    else:
        logger.info("Fitting scaler, PCA, and training autoencoder...")
        scaler = StandardScaler()
        scaled = scaler.fit_transform(numeric_data)
        pca = PCA(n_components=0.95)
        reduced = pca.fit_transform(scaled)
        input_dim = reduced.shape[1]

        model = _build_autoencoder(input_dim)
        if HAS_TF:
            model.fit(reduced, reduced, epochs=5, batch_size=256, verbose=0)
            model.save(model_path)
        else:
            model.fit(reduced, reduced)
            joblib.dump(model, model_path)

        joblib.dump(scaler, scaler_path)
        joblib.dump(pca, pca_path)
        meta_path.write_text(
            json.dumps({"input_dim": input_dim, "total_trained_samples": total, "backend": "tensorflow" if HAS_TF else "sklearn"}),
            encoding="utf-8",
        )
        trained = True
        logger.info("Saved autoencoder model + preprocessors to %s", MODEL_DIR)

    if HAS_TF:
        reconstructions = model.predict(reduced, verbose=0)
    else:
        reconstructions = model.predict(reduced)

    mse = np.mean(np.power(reduced - reconstructions, 2), axis=1)
    anomaly_mask = mse > anomaly_threshold
    num_anomalies = int(np.sum(anomaly_mask))
    anomaly_pct = (num_anomalies / total * 100) if total else 0.0
    sev = _severity(anomaly_pct)

    top_idx = np.argsort(mse)[-min(10, total):][::-1].tolist()
    top_scores = [round(float(mse[i]), 4) for i in top_idx]

    report = {
        "event": "SCAN_COMPLETE",
        "filepath": str(path),
        "anomalies_detected": num_anomalies,
        "total_records": total,
        "anomaly_percentage": round(anomaly_pct, 2),
        "threshold": anomaly_threshold,
        "model": "Autoencoder (16→8→16) + PCA (0.95)" if HAS_TF else "MLP Autoencoder (16→8→16) + PCA (0.95)",
        "features_in": int(numeric_data.shape[1]),
        "features_pca": int(input_dim),
        "mean_mse": round(float(np.mean(mse)), 4),
        "max_mse": round(float(np.max(mse)), 4),
        "p95_mse": round(float(np.percentile(mse, 95)), 4),
        "top_anomaly_rows": top_idx,
        "top_anomaly_scores": top_scores,
        "mitre_attack": MITRE_MAP,
        "nist_csf": ["DE.CM-01", "DE.AE-02"],
        "severity": sev["level"],
        "confidence": sev["confidence"],
        "verdict": sev["verdict"],
        "cached_model": not trained,
    }
    return report


def run_network_scan(filepath: str | Path, anomaly_threshold: float = 0.5, retrain: bool = False):
    """Backward-compatible wrapper — returns anomaly count or error string."""
    try:
        report = analyze_network_data(filepath, anomaly_threshold=anomaly_threshold, retrain=retrain)
        return int(report["anomalies_detected"])
    except Exception as e:
        logger.error("Scan Error: %s", e, exc_info=True)
        return f"Scan Error: {e}"


if __name__ == "__main__":
    default = BASE_DIR / "KDDTrain+.txt"
    target = str(default) if default.is_file() else "KDDTrain+.txt"
    print(json.dumps(analyze_network_data(target), indent=2))
