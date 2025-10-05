import time
import requests
import json
import logging
import threading
import base64
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Packet

# Local module imports
# Assuming the package structure NIDS_App/backend/
try:
    from .ml_engine import MLEngine
    from .extractor import extract_features, packet_to_log_data
except ImportError:
    # Fallback for direct execution (python backend/sniffer.py)
    from ml_engine import MLEngine
    from extractor import extract_features, packet_to_log_data

# --- Configuration (Loaded from settings.json) ---
CONFIG_PATH = 'storage/settings.json'
SETTINGS = {}

def load_settings():
    """Load configuration settings from JSON file."""
    global SETTINGS
    try:
        with open(CONFIG_PATH, 'r') as f:
            SETTINGS = json.load(f)
        return SETTINGS
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {CONFIG_PATH}. Using defaults.")
        SETTINGS = {
            "api_host": "127.0.0.1",
            "api_port": 5000,
            "sensitivity": 0.5
        }
        return SETTINGS
    except Exception as e:
        print(f"Error loading settings: {e}")
        return {}

# Load settings immediately
CONFIG = load_settings()
API_URL = f"http://{CONFIG.get('api_host', '127.0.0.1')}:{CONFIG.get('api_port', 5000)}/api/traffic/ingest"

# --- ML Model Initialization ---
ml_engine = MLEngine()

# --- Global State ---
LIVE_PACKETS = []
BATCH_SIZE = 10 
SEND_INTERVAL = 1 
last_send_time = time.time()
lock = threading.Lock()

# --- Packet Processing and ML Inference ---

def process_packet(packet: Packet):
    """
    Extracts features, runs ML prediction, and prepares the log entry.
    """
    global LIVE_PACKETS

    # 1. Feature Extraction
    features = extract_features(packet)
    
    if features is None:
        # Ignore non-IP or unprocessable packets
        return

    # 2. ML Prediction
    # Returns (classification: 0 or 1, confidence: float)
    classification, confidence = ml_engine.predict(features)
    
    # 3. Apply Sensitivity Threshold
    # If confidence in classification 1 (Anomaly) is below the threshold, treat as Normal (0)
    sensitivity = CONFIG.get('sensitivity', 0.5)
    if classification == 1 and confidence < sensitivity:
        classification = 0
        confidence = 1.0 - confidence # Flip confidence to the Normal prediction
        
    # 4. Prepare Log Data
    log_entry = packet_to_log_data(packet, classification, confidence)

    # Add features for debugging/future logging
    log_entry['ml_features'] = str(features)

    # Add raw packet data for hex view (base64 encoded for JSON serialization)
    log_entry['raw_data'] = base64.b64encode(bytes(packet)).decode('ascii')
    
    with lock:
        LIVE_PACKETS.append(log_entry)
        
    # Log to console for real-time feedback
    status = f"{log_entry['classification']}: {log_entry['confidence']}"
    print(f"[{time.strftime('%H:%M:%S')}] {log_entry['src_ip']:<15} -> {log_entry['dst_ip']:<15} | Proto: {log_entry['protocol']:<3} | {status:<20}")

# --- API Communication ---

def send_traffic_batch():
    """Sends the accumulated packets to the Flask API."""
    global LIVE_PACKETS, last_send_time
    
    # Lock the list while copying and clearing
    with lock:
        if not LIVE_PACKETS:
            return
        
        # Take all current packets
        batch_to_send = LIVE_PACKETS[:]
        LIVE_PACKETS.clear()
        
    try:
        # Prepare payload
        payload = {'logs': batch_to_send}
        
        # Send POST request to the API
        response = requests.post(
            API_URL, 
            json=payload, 
            timeout=1
        )
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        
        # Optional: Log successful send
        # print(f"Successfully sent {len(batch_to_send)} packets to API.")

    except requests.exceptions.RequestException as e:
        # Log error but keep running the sniffer
        print(f"Error sending data to API ({API_URL}): {e}")
        
    last_send_time = time.time()

def api_sender_thread():
    """Worker thread to periodically send packets to the API."""
    while True:
        send_traffic_batch()
        time.sleep(SEND_INTERVAL)

# --- Main Execution ---

if __name__ == '__main__':
    print("--- NIDS Live Packet Sniffer ---")
    print(f"ML Model loaded. Sensitivity: {CONFIG.get('sensitivity')}")
    print(f"API Target: {API_URL}")
    print("Starting packet capture. Press Ctrl+C to stop.\n")

    # Start the background thread for sending data
    sender = threading.Thread(target=api_sender_thread, daemon=True)
    sender.start()

    try:
        # Start sniffing packets. This function blocks until interrupted.
        # IF YOU GET PERMISSION ERRORS, TRY RUNNING WITH 'sudo' or as Administrator.
        sniff(prn=process_packet, store=0)
        
    except KeyboardInterrupt:
        print("\nSniffer interrupted by user.")
        
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")
        print("Hint: Scapy often requires elevated privileges (sudo/Administrator).")

    print("Sniffer stopped.")
