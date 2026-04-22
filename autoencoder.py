import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

def run_network_scan(filepath, anomaly_threshold=0.5):
    try:
        # 1. Load Data
        dataset = pd.read_csv(filepath, header=None)
        numeric_data = dataset.select_dtypes(include=***REMOVED***'number'***REMOVED***)
        
        if numeric_data.empty:
            return "Scan Failed: No numeric columns found to analyze."

        # 2. Preprocess
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(numeric_data)
        pca = PCA(n_components=0.95)
        reduced_data = pca.fit_transform(scaled_data)
        input_dim = reduced_data.shape***REMOVED***1***REMOVED***

        # 3. Build & Train (Silently)
        model = Sequential(***REMOVED***
            tf.keras.Input(shape=(input_dim,)),
            Dense(16, activation='relu'),
            Dense(8, activation='relu'), 
            Dense(16, activation='relu'),
            Dense(input_dim, activation='linear') 
        ***REMOVED***)
        model.compile(optimizer='adam', loss='mse')
        model.fit(reduced_data, reduced_data, epochs=5, batch_size=256, verbose=0)

        # 4. Detect
        reconstructions = model.predict(reduced_data, verbose=0)
        mse = np.mean(np.power(reduced_data - reconstructions, 2), axis=1)
        num_anomalies = np.sum(mse > anomaly_threshold)

        return int(num_anomalies)

    except Exception as e:
        return f"Scan Error: {str(e)}"

if __name__ == "__main__":
    # Test it one last time
    path = r"C:\Users\91638\Desktop\KDDTrain+.csv\KDDTrain+.txt" 
    print(f"Agent Observation: Found {run_network_scan(path)} anomalies.")