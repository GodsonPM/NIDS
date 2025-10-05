import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
import os
import numpy as np

# --- CRITICAL: FEATURE LIST DEFINITION ---
# These are the 11 features extracted from the live traffic sniffer (backend/sniffer.py).
SNIFFER_FEATURES = [
    'size', 'ip_header_len', 'ip_ttl', 'sport', 'dport', 
    'tcp_syn_flag', 'tcp_ack_flag', 'tcp_window',
    'protocol_TCP', 'protocol_UDP', 'protocol_ICMP'
]

# --- FILE PATHS ---
MODEL_FILENAME = 'rf_model.pkl'
MODEL_PATH = os.path.join('models', MODEL_FILENAME)
MODEL_DIR = 'models'

# NOTE: ADJUST THIS PATH TO YOUR DOWNLOADED CSV FILE
# Assuming your main training CSV is named 'NF-UNSW-NB15.csv'
DATASET_FILENAME = 'NF-UNSW-NB15.csv'
DATASET_PATH = os.path.join(os.path.dirname(__file__), DATASET_FILENAME)

def preprocess_and_train():
    """Loads the NF-UNSW-NB15 dataset, preprocesses it, and trains a lightweight RF model."""
    try:
        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)

        print(f"Loading dataset from: {DATASET_PATH}")
        
        # --- FIX: Changed separator to comma (',') which the debug output confirmed ---
        df = pd.read_csv(DATASET_PATH, sep=',', low_memory=False, skipinitialspace=True)
        
        # --- DEBUG: Show actual columns found in CSV ---
        print("\n--- DEBUG: Columns found after loading CSV ---")
        print(df.columns.tolist())
        print("-------------------------------------------\n")

        # --- 1. Feature Mapping and Cleaning ---
        
        # Map original column names to the names the sniffer expects.
        rename_map = {
            'IN_BYTES': 'size',             # Packet size proxy
            'L4_SRC_PORT': 'sport',         # Source port
            'L4_DST_PORT': 'dport',         # Destination port
            'PROTOCOL': 'protocol_num',     # Protocol number
            'TCP_FLAGS': 'tcp_flags_val'    # TCP flags value
        }
        
        # Filter map to include only columns present in the DataFrame
        actual_rename_map = {k: v for k, v in rename_map.items() if k in df.columns}
        
        # Apply renaming
        df.rename(columns=actual_rename_map, inplace=True)
        
        # Drop rows with missing values that are critical for training
        # We use the *renamed* columns here.
        df.dropna(subset=['size', 'sport', 'dport'], inplace=True)
        
        # --- 2. Feature Engineering to Match Sniffer's Output ---
        
        # 2a. TCP Flags 
        if 'tcp_flags_val' in df.columns:
            # Defensive conversion: Ensure it's numeric before bitwise operations
            df['tcp_flags_val'] = pd.to_numeric(df['tcp_flags_val'], errors='coerce').fillna(0).astype(int)
            # Bit 2 (0x02) is SYN, Bit 4 (0x10) is ACK
            df['tcp_syn_flag'] = np.where((df['tcp_flags_val'] & 0x02) > 0, 1, 0)
            df['tcp_ack_flag'] = np.where((df['tcp_flags_val'] & 0x10) > 0, 1, 0)
        else:
            df['tcp_syn_flag'] = 0
            df['tcp_ack_flag'] = 0

        # 2b. Protocol One-Hot Encoding
        if 'protocol_num' in df.columns:
            df['protocol_num'] = pd.to_numeric(df['protocol_num'], errors='coerce').fillna(-1).astype(int)
            df['protocol_TCP'] = np.where(df['protocol_num'] == 6, 1, 0) # TCP
            df['protocol_UDP'] = np.where(df['protocol_num'] == 17, 1, 0) # UDP
            df['protocol_ICMP'] = np.where(df['protocol_num'] == 1, 1, 0) # ICMP
        else:
            df['protocol_TCP'] = 0
            df['protocol_UDP'] = 0
            df['protocol_ICMP'] = 0
            
        # 2c. Placeholder Features (Filling in values for features existing only in the sniffer)
        df['ip_header_len'] = 20    
        
        # Defensive code for TTL and Window size (which may not exist in flow data)
        df['ip_ttl'] = 128
        df['tcp_window'] = 8192

        # --- 3. Label Extraction ---
        
        # Directly target the confirmed 'Attack' column for the binary label
        if 'Attack' in df.columns:
            # The 'Attack' column may be string ('Benign' for Normal, others for Attack)
            y = df['Attack'].apply(lambda x: 0 if x == 'Benign' else 1).astype(int)
        else:
            print("CRITICAL: The required binary label column 'Attack' was not found in the dataset.")
            print("Please confirm the name of the column containing the 0/1 attack label.")
            return

        # --- 4. Final Feature Alignment and Training ---
        
        # Use only a fraction of the data to avoid memory issues and speed up training
        df_sampled = df.sample(n=min(len(df), 10000), random_state=42) # Limit to 10k samples
        y = y.loc[df_sampled.index] # Align labels with sampled data
        df = df_sampled # Use sampled data going forward
        
        # Create final feature matrix X, ensuring correct order and presence of all 11 SNIFFER_FEATURES
        X_aligned = pd.DataFrame(0, index=df.index, columns=SNIFFER_FEATURES)
        for col in X_aligned.columns:
            # Check if the feature was generated from the CSV data
            if col in df.columns and col not in ['Attack']:
                X_aligned[col] = df[col]
            # Handle placeholder columns that were set as single values
            elif col in ['ip_header_len', 'ip_ttl', 'tcp_window']:
                 X_aligned[col] = df[col]
        
        X = X_aligned.values
        
        # 5. Train the Model
        print(f"Starting training on {len(X)} samples...")
        model = RandomForestClassifier(n_estimators=10, random_state=42, n_jobs=-1)
        model.fit(X, y)
        
        # 6. Save the Model
        final_payload = {
            'model': model,
            'features': SNIFFER_FEATURES 
        }
        
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(final_payload, f)
            
        print("-" * 50)
        print(f"SUCCESS: Lightweight ML model trained using your flow data features saved to: {MODEL_PATH}")
        print("The model now uses the specific features available in your dataset.")
        print("-" * 50)

    except FileNotFoundError:
        print("-" * 50)
        print(f"ERROR: Dataset file '{DATASET_FILENAME}' not found at {DATASET_PATH}")
        print(f"Please place your CSV file in the NIDS_App/ root directory and ensure the name is correct.")
        print("-" * 50)
    except Exception as e:
        # Check if the exception is due to a DataFrame column error
        if isinstance(e.args, tuple) and len(e.args) > 0 and isinstance(e.args[0], list):
            print(f"CRITICAL ERROR during training: Column access failed on list {e.args[0]}")
        else:
            print(f"CRITICAL ERROR during training: {e}")

        print(f"Exception details: {e}")
        print("A critical error occurred during data processing. Please check if your CSV is malformed or if column names contain extra whitespace.")

if __name__ == '__main__':
    preprocess_and_train()
