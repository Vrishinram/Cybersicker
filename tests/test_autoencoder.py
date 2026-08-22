"""
Tests for Cybersicker Autoencoder Anomaly Detection Engine
"""

import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from autoencoder import _load_numeric, _build_autoencoder, analyze_network_data, run_network_scan


@pytest.fixture
def dummy_traffic_csv(tmp_path):
    """Create a temporary dataset with normal and anomalous samples."""
    np.random.seed(42)
    # 50 normal rows with 5 numeric features + 1 text column
    data = np.random.normal(loc=0.0, scale=1.0, size=(50, 5))
    df = pd.DataFrame(data)
    df["label"] = "normal"
    # 5 anomalous rows with high values
    anom_data = np.random.normal(loc=15.0, scale=2.0, size=(5, 5))
    anom_df = pd.DataFrame(anom_data)
    anom_df["label"] = "anomaly"
    combined = pd.concat([df, anom_df], ignore_index=True)

    csv_path = tmp_path / "traffic.csv"
    combined.to_csv(csv_path, header=False, index=False)
    return csv_path


def test_load_numeric(dummy_traffic_csv):
    df = _load_numeric(dummy_traffic_csv)
    assert df.shape[1] == 5
    assert len(df) == 55


def test_build_autoencoder():
    model = _build_autoencoder(input_dim=4)
    assert model is not None


def test_analyze_network_data_and_persistence(dummy_traffic_csv):
    # First pass: fits and trains model
    report1 = analyze_network_data(dummy_traffic_csv, anomaly_threshold=1.0, retrain=True)
    assert report1["event"] == "SCAN_COMPLETE"
    assert report1["total_records"] == 55
    assert report1["cached_model"] is False

    # Second pass: reloads cached model and preprocessors
    report2 = analyze_network_data(dummy_traffic_csv, anomaly_threshold=1.0, retrain=False)
    assert report2["event"] == "SCAN_COMPLETE"
    assert report2["cached_model"] is True
    assert report2["total_records"] == 55


def test_run_network_scan_wrapper(dummy_traffic_csv):
    anomalies = run_network_scan(dummy_traffic_csv, anomaly_threshold=1.0)
    assert isinstance(anomalies, int)
    assert anomalies >= 0
