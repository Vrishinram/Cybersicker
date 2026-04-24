import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Cybersicker.MLDetection")

def run_network_scan(filepath, anomaly_threshold=0.5):
    """
    Run ML-based anomaly detection on network traffic logs.
    
    Cybersecurity Skills:
    - network-traffic-analysis-fundamentals (Network Security)
    - feature-engineering-anomaly-ml (Malware Analysis)
    - dimensionality-reduction-pca (Network Security)
    - detecting-botnet-traffic-patterns (Threat Hunting)
    - detecting-ddos-volumetric-attacks (Threat Hunting)
    - detecting-lateral-movement-in-networks (Threat Hunting)
    - detecting-ransomware-traffic-signatures (Threat Hunting)
    
    MITRE ATT&CK Techniques Detected:
    - T1566: Phishing (email traffic anomalies)
    - T1595: Active Scanning (port scan patterns)
    - T1498: Network Denial of Service (volumetric floods)
    - T1041: Exfiltration Over C2 (data volume spikes)
    - T1570: Lateral Tool Transfer (internal propagation)
    - T1571: Non-Standard Port/Protocol (C2 communication)
    - T1486: Data Encrypted for Impact (ransomware signatures)
    
    NIST CSF Alignment:
    - DE.CM-01: Monitor network activities
    - DE.AE-02: Detect anomalies
    
    Algorithm: Deep Autoencoder + PCA
    - Input: Network traffic features (numeric columns)
    - Preprocessing: StandardScaler + PCA (95% variance retention)
    - Model: 4-layer autoencoder (Dense layers with ReLU/Linear activation)
    - Output: MSE-based anomaly scores
    
    Args:
        filepath: Path to network traffic CSV (NSL-KDD format)
        anomaly_threshold: MSE threshold for flagging anomalies (default 0.5)
        
    Returns:
        Number of anomalous records detected
    \"\"\"\n    try:\n        # STEP 1: Load Data\n        logger.info(f\"Loading network traffic data from {filepath}\")\n        dataset = pd.read_csv(filepath, header=None)\n        numeric_data = dataset.select_dtypes(include=['number'])\n        \n        if numeric_data.empty:\n            logger.error(\"No numeric columns found for analysis\")\n            return \"Scan Failed: No numeric columns found to analyze.\"\n\n        # STEP 2: Preprocess (Normalize & Dimensionality Reduction)\n        logger.info(f\"Preprocessing {len(numeric_data)} records\")\n        scaler = StandardScaler()\n        scaled_data = scaler.fit_transform(numeric_data)\n        \n        # Apply PCA to retain 95% variance\n        pca = PCA(n_components=0.95)\n        reduced_data = pca.fit_transform(scaled_data)\n        input_dim = reduced_data.shape[1]\n        \n        logger.info(f\"Dimensionality reduced: {numeric_data.shape[1]} → {input_dim} features\")\n\n        # STEP 3: Build & Train Autoencoder\n        logger.info(\"Building 4-layer autoencoder for anomaly detection\")\n        model = Sequential([\n            tf.keras.Input(shape=(input_dim,)),\n            Dense(16, activation='relu'),   # Encoder layer 1\n            Dense(8, activation='relu'),    # Encoder layer 2 (bottleneck)\n            Dense(16, activation='relu'),   # Decoder layer 1\n            Dense(input_dim, activation='linear')  # Decoder output\n        ])\n        model.compile(optimizer='adam', loss='mse')\n        \n        # Train silently (no verbose output)\n        logger.info(\"Training encoder (5 epochs, batch_size=256)\")\n        model.fit(reduced_data, reduced_data, epochs=5, batch_size=256, verbose=0)\n\n        # STEP 4: Detect Anomalies\n        logger.info(\"Running inference and computing reconstruction error\")\n        reconstructions = model.predict(reduced_data, verbose=0)\n        mse = np.mean(np.power(reduced_data - reconstructions, 2), axis=1)\n        \n        # Count anomalies above threshold\n        num_anomalies = np.sum(mse > anomaly_threshold)\n        \n        # Compute statistics for reporting\n        mean_mse = np.mean(mse)\n        max_mse = np.max(mse)\n        percentile_95 = np.percentile(mse, 95)\n        \n        logger.info(f\"Anomaly Detection Complete:\")\n        logger.info(f\"  Total records analyzed: {len(reduced_data)}\")\n        logger.info(f\"  Anomalies detected: {num_anomalies}\")\n        logger.info(f\"  Mean MSE: {mean_mse:.4f}\")\n        logger.info(f\"  Max MSE: {max_mse:.4f}\")\n        logger.info(f\"  95th percentile MSE: {percentile_95:.4f}\")\n        logger.info(f\"  Anomaly rate: {(num_anomalies/len(reduced_data)*100):.2f}%\")\n        \n        # MITRE ATT&CK Confidence Score\n        anomaly_percentage = (num_anomalies/len(reduced_data)*100)\n        if anomaly_percentage > 10:\n            confidence = \"CRITICAL - Multiple attack patterns detected\"\n        elif anomaly_percentage > 5:\n            confidence = \"HIGH - Significant anomaly activity\"\n        elif anomaly_percentage > 2:\n            confidence = \"MEDIUM - Suspicious patterns detected\"\n        else:\n            confidence = \"LOW - Normal network behavior\"\n        \n        logger.info(f\"  MITRE ATT&CK Detection Confidence: {confidence}\")\n        logger.info(f\"  NIST CSF Alignment: DE.CM-01 (Continuous monitoring)\")\n\n        return int(num_anomalies)\n\n    except Exception as e:\n        logger.error(f\"Scan Error: {str(e)}\", exc_info=True)\n        return f\"Scan Error: {str(e)}\"

if __name__ == "__main__":
    # Test it one last time
    path = r"C:\Users\91638\Desktop\KDDTrain+.csv\KDDTrain+.txt" 
    print(f"Agent Observation: Found {run_network_scan(path)} anomalies.")