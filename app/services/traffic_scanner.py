"""
CYBERSICKER — Live Autoencoder Traffic Scanner & Inference Service
Performs in-memory deep autoencoder anomaly detection on raw packet traffic
using persisted StandardScaler and PCA feature compression pipelines.
Eliminates all hardcoded file paths.
"""

from __future__ import annotations

import io
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.TrafficScanner")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BASE_DIR / "models"
DEFAULT_THRESHOLD = 0.042

MITRE_ANOMALY_MAP = [
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    {"id": "T1571", "name": "Non-Standard Port Protocol", "tactic": "Command and Control"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
]

# NSL-KDD Standard Numerical Feature Dimensions
KDD_NUMERICAL_FEATURE_NAMES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]


class AutoencoderScanner:
    """Dynamic in-memory inference pipeline for network packet log anomaly detection."""

    def __init__(self):
        self.scaler: Optional[StandardScaler] = None
        self.pca: Optional[PCA] = None
        self.model: Any = None
        self._load_pipeline()

    def _load_pipeline(self):
        """Loads the persisted StandardScaler, PCA projection, and Autoencoder model."""
        scaler_file = MODEL_DIR / "scaler.joblib"
        pca_file = MODEL_DIR / "pca.joblib"
        model_file = MODEL_DIR / "autoencoder_mlp.joblib"

        try:
            if scaler_file.is_file():
                self.scaler = joblib.load(scaler_file)
            if pca_file.is_file():
                self.pca = joblib.load(pca_file)
            if model_file.is_file():
                self.model = joblib.load(model_file)
            logger.info("Persisted autoencoder artifacts loaded from %s", MODEL_DIR)
        except Exception as e:
            logger.warning("Could not pre-load autoencoder models: %s", e)

    def process_dataframe(
        self,
        df: pd.DataFrame,
        anomaly_threshold: float = DEFAULT_THRESHOLD,
        source_name: str = "in_memory_stream"
    ) -> Dict[str, Any]:
        """
        Executes feature extraction, standard scaling, PCA projection,
        autoencoder reconstruction, MSE calculation, and anomaly classification.
        """
        start_time = time.time()

        # Isolate numerical features
        numeric_df = df.select_dtypes(include=[np.number])
        if numeric_df.empty:
            raise ValueError("No numeric features found in the provided network traffic dataset.")

        total_records = len(numeric_df)
        if total_records == 0:
            raise ValueError("Provided network traffic dataset contains 0 records.")

        # Ensure pipeline is loaded
        if self.scaler is None or self.pca is None or self.model is None:
            self._load_pipeline()

        n_features = numeric_df.shape[1]
        raw_values = numeric_df.values

        # If features match trained scaler dimensionality (38 KDD numerical features)
        if self.scaler and getattr(self.scaler, "n_features_in_", None) == n_features:
            scaled = self.scaler.transform(raw_values)
            reduced = self.pca.transform(scaled)
            reconstructed = self.model.predict(reduced)
            # MSE reconstruction error: mean((reduced - reconstructed)^2)
            mse_scores = np.mean(np.square(reduced - reconstructed), axis=1)
        else:
            # Fit adaptive dynamic scaler & PCA on the fly if user uploaded arbitrary custom CSV
            logger.info("Custom feature count (%d) differs from standard KDD baseline; using adaptive scaler.", n_features)
            adaptive_scaler = StandardScaler()
            scaled = adaptive_scaler.fit_transform(raw_values)
            
            # Ensure PCA components do not exceed min(n_samples, n_features)
            max_possible_dim = min(n_features, total_records)
            if max_possible_dim > 1:
                pca_dim = max(1, min(max_possible_dim - 1, 16))
                adaptive_pca = PCA(n_components=pca_dim)
                reduced = adaptive_pca.fit_transform(scaled)
                reconstructed = adaptive_pca.inverse_transform(reduced)
            else:
                reduced = scaled
                reconstructed = np.zeros_like(scaled)

            mse_scores = np.mean(np.square(scaled - reconstructed), axis=1)

        # Evaluate anomalies against threshold
        anomaly_mask = mse_scores > anomaly_threshold
        anomalies_detected = int(np.sum(anomaly_mask))
        anomaly_pct = round((anomalies_detected / total_records) * 100, 2)

        mean_mse = round(float(np.mean(mse_scores)), 5)
        max_mse = round(float(np.max(mse_scores)), 5)
        p95_mse = round(float(np.percentile(mse_scores, 95)), 5)

        # Identify top anomaly indices
        top_indices = np.argsort(mse_scores)[-min(5, total_records):][::-1].tolist()
        top_scores = [round(float(mse_scores[i]), 5) for i in top_indices]

        # Identify high-risk feature dimensions contributing to anomalies
        high_risk_dimensions = []
        if anomalies_detected > 0:
            anom_samples = raw_values[anomaly_mask]
            norm_samples = raw_values[~anomaly_mask] if np.any(~anomaly_mask) else raw_values

            anom_means = np.mean(anom_samples, axis=0)
            norm_means = np.mean(norm_samples, axis=0) + 1e-6
            deviations = np.abs((anom_means - norm_means) / norm_means)

            top_dim_indices = np.argsort(deviations)[-min(4, len(deviations)):][::-1]
            for dim_idx in top_dim_indices:
                dim_name = (
                    KDD_NUMERICAL_FEATURE_NAMES[dim_idx]
                    if dim_idx < len(KDD_NUMERICAL_FEATURE_NAMES)
                    else f"feature_dim_{dim_idx}"
                )
                high_risk_dimensions.append({
                    "feature": dim_name,
                    "deviation_ratio": round(float(deviations[dim_idx]), 2),
                    "anomalous_mean": round(float(anom_means[dim_idx]), 2),
                })
        else:
            high_risk_dimensions.append({"feature": "All features nominal", "deviation_ratio": 1.0, "anomalous_mean": 0.0})

        # Calculate severity and verdict
        if anomaly_pct > 15.0 or max_mse > (anomaly_threshold * 10):
            severity = "CRITICAL"
            verdict = "HIGH RISK — Active Attack Vector Detected"
        elif anomaly_pct > 5.0 or max_mse > (anomaly_threshold * 4):
            severity = "HIGH"
            verdict = "ELEVATED RISK — Suspicious Telemetry Patterns"
        elif anomaly_pct > 1.0:
            severity = "MEDIUM"
            verdict = "MODERATE RISK — Transient Traffic Deviation"
        else:
            severity = "LOW"
            verdict = "NOMINAL — Baseline Network Conditions"

        latency_ms = int((time.time() - start_time) * 1000)

        # Emit telemetry event
        telemetry_service.emit({
            "event": "AUTOENCODER_INFERENCE_COMPLETE",
            "source": source_name,
            "records": total_records,
            "anomalies": anomalies_detected,
            "anomaly_percentage": anomaly_pct,
            "latency_ms": latency_ms,
        })

        return {
            "event": "SCAN_COMPLETE",
            "source": source_name,
            "total_records": total_records,
            "anomalies_detected": anomalies_detected,
            "anomaly_percentage": anomaly_pct,
            "threshold": anomaly_threshold,
            "mean_mse": mean_mse,
            "max_mse": max_mse,
            "p95_mse": p95_mse,
            "severity": severity,
            "verdict": verdict,
            "high_risk_dimensions": high_risk_dimensions,
            "top_anomaly_indices": top_indices,
            "top_anomaly_scores": top_scores,
            "mitre_attack": MITRE_ANOMALY_MAP,
            "nist_csf": ["DE.AE-1 (Anomalous Activity Detection)", "DE.CM-1 (Network Monitoring)"],
            "latency_ms": latency_ms,
        }

    def scan_csv_bytes(
        self,
        file_bytes: bytes,
        filename: str = "upload.csv",
        threshold: float = DEFAULT_THRESHOLD
    ) -> Dict[str, Any]:
        """Parses CSV bytes in-memory and executes autoencoder anomaly detection."""
        try:
            stream = io.BytesIO(file_bytes)
            df = pd.read_csv(stream, header=None)
            return self.process_dataframe(df, anomaly_threshold=threshold, source_name=filename)
        except Exception as e:
            logger.error("Failed to parse and scan uploaded CSV bytes: %s", e)
            raise ValueError(f"Failed to scan network traffic payload: {str(e)}")

    def scan_records(
        self,
        records: List[List[Union[float, int]]],
        threshold: float = DEFAULT_THRESHOLD,
        source_name: str = "json_payload"
    ) -> Dict[str, Any]:
        """Scans structured numerical matrix passed via JSON."""
        df = pd.DataFrame(records)
        return self.process_dataframe(df, anomaly_threshold=threshold, source_name=source_name)


# Global singleton instance
traffic_scanner_service = AutoencoderScanner()
