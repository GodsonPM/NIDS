import json
import time
import random
import os
from flask import Flask, jsonify, request, g
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
import folium

# --- Configuration (Load Configuration) ---
CONFIG_FILE = 'storage/settings.json'

def load_config(filepath):
    """Loads configuration from a JSON file, using defaults if file is missing."""
    default_config = {
        "db_path": "storage/logs.db",
        "model_path": "models/rf_model.pkl",
        "api_host": "127.0.0.1",
        "api_port": 5000,
        "sensitivity": 0.5,
        "role": "Analyst",
        "theme": "Dark"
    }
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)
            return {**default_config, **config}
    except Exception as e:
        print(f"Error loading config: {e}. Using defaults.")
        return default_config

# Global configuration store
CONFIG = load_config(CONFIG_FILE)

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Data Storage (In-memory store for recent data) ---
LIVE_PACKET_LOG = []
ALERT_HISTORY = []
LAST_PACKET_ID = 0
MAX_LIVE_PACKETS = 50 

# --- Helper Functions ---
def get_live_logs():
    """Retrieves the list of most recent packets."""
    return LIVE_PACKET_LOG

def get_alert_history():
    """Retrieves the list of active/recent alerts."""
    return [alert for alert in ALERT_HISTORY if alert['status'] == 'New']

def get_packet_by_id(packet_id):
    """Retrieves a single, detailed packet by its ID from the live log."""
    packet_id = int(packet_id)
    for packet in LIVE_PACKET_LOG:
        if packet.get('id') == packet_id:
            return packet
    return None

def get_geolocation(ip):
    """Get latitude and longitude for an IP address using geopy."""
    try:
        geolocator = Nominatim(user_agent="nids_app")
        location = geolocator.geocode(ip, timeout=5)
        if location:
            return {"lat": location.latitude, "lon": location.longitude, "address": location.address}
        else:
            # Fallback for common IPs
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                return {"lat": 37.7749, "lon": -122.4194, "address": "Local Network"}  # San Francisco
            return {"lat": 0, "lon": 0, "address": "Unknown"}
    except (GeocoderTimedOut, GeocoderUnavailable):
        return {"lat": 0, "lon": 0, "address": "Geolocation Timeout"}

def generate_traffic_map():
    """Generate an HTML map showing traffic flows."""
    logs = get_live_logs()

    if not logs:
        # Create empty map centered on world
        m = folium.Map(location=[20, 0], zoom_start=2)
        folium.Marker([20, 0], popup="No traffic data available").add_to(m)
    else:
        # Create map centered on first IP location
        first_ip = logs[0]['src_ip']
        first_loc = get_geolocation(first_ip)
        m = folium.Map(location=[first_loc['lat'], first_loc['lon']], zoom_start=2)

        # Track unique IPs and their locations
        ip_locations = {}
        traffic_flows = []

        for log in logs[-20:]:  # Last 20 packets for performance
            src_ip = log['src_ip']
            dst_ip = log['dst_ip']
            classification = log.get('classification', 'Normal')

            # Get or cache locations with exception handling
            if src_ip not in ip_locations:
                try:
                    ip_locations[src_ip] = get_geolocation(src_ip)
                except Exception:
                    ip_locations[src_ip] = {"lat": 0, "lon": 0, "address": "Unknown"}
            if dst_ip not in ip_locations:
                try:
                    ip_locations[dst_ip] = get_geolocation(dst_ip)
                except Exception:
                    ip_locations[dst_ip] = {"lat": 0, "lon": 0, "address": "Unknown"}

            src_loc = ip_locations[src_ip]
            dst_loc = ip_locations[dst_ip]

            # Add markers
            color = 'red' if 'anomaly' in classification.lower() else 'blue'
            folium.Marker(
                [src_loc['lat'], src_loc['lon']],
                popup=f"Source: {src_ip}<br>{src_loc['address']}",
                icon=folium.Icon(color=color)
            ).add_to(m)

            folium.Marker(
                [dst_loc['lat'], dst_loc['lon']],
                popup=f"Destination: {dst_ip}<br>{dst_loc['address']}",
                icon=folium.Icon(color='green')
            ).add_to(m)

            # Add flow line
            folium.PolyLine(
                [(src_loc['lat'], src_loc['lon']), (dst_loc['lat'], dst_loc['lon'])],
                color=color,
                weight=2,
                opacity=0.7,
                popup=f"Flow: {src_ip} → {dst_ip}<br>Classification: {classification}"
            ).add_to(m)

    return m._repr_html_()

# --- NEW: Endpoint to receive packets from the sniffer ---
@app.route('/api/traffic/ingest', methods=['POST'])
def ingest_packet():
    """Receives classified packets from the sniffer and adds them to the log."""
    global LAST_PACKET_ID, LIVE_PACKET_LOG, ALERT_HISTORY

    try:
        data = request.get_json()

        if 'logs' in data:
            # Batch ingestion
            ingested_ids = []
            for log_entry in data['logs']:
                LAST_PACKET_ID += 1
                log_entry['id'] = LAST_PACKET_ID
                LIVE_PACKET_LOG.append(log_entry)
                ingested_ids.append(LAST_PACKET_ID)

                # For testing purposes, create alerts for approximately half the packets
                if random.random() < 0.5:
                    ALERT_HISTORY.append({
                        "alert_id": len(ALERT_HISTORY) + 1,
                        "packet_id": LAST_PACKET_ID,
                        "timestamp": log_entry['timestamp'],
                        "src_ip": log_entry['src_ip'],
                        "attack_type": random.choice(["DDoS", "Port Scan", "Brute Force"]),
                        "confidence": log_entry.get('confidence', '0.90'),
                        "status": "New"
                    })

            LIVE_PACKET_LOG = LIVE_PACKET_LOG[-MAX_LIVE_PACKETS:] # Keep memory manageable
            return jsonify({"message": f"Batch ingested {len(ingested_ids)} packets successfully.", "ids": ingested_ids}), 201

        else:
            # Single packet ingestion (fallback)
            packet_data = data
            LAST_PACKET_ID += 1
            packet_data['id'] = LAST_PACKET_ID
            LIVE_PACKET_LOG.append(packet_data)
            LIVE_PACKET_LOG = LIVE_PACKET_LOG[-MAX_LIVE_PACKETS:]

            if random.random() < 0.5:
                ALERT_HISTORY.append({
                    "alert_id": len(ALERT_HISTORY) + 1,
                    "packet_id": LAST_PACKET_ID,
                    "timestamp": packet_data['timestamp'],
                    "src_ip": packet_data['src_ip'],
                    "attack_type": random.choice(["DDoS", "Port Scan", "Brute Force"]),
                    "confidence": packet_data.get('confidence', '0.90'),
                    "status": "New"
                })

            return jsonify({"message": "Packet ingested successfully.", "id": LAST_PACKET_ID}), 201

    except Exception as e:
        print(f"Error ingesting packet: {e}")
        return jsonify({"message": f"Ingestion failed: {e}"}), 400


# --- Existing API Endpoints (Modified to use real data from LIVE_PACKET_LOG) ---

@app.route('/api/traffic/live', methods=['GET'])
def get_live_traffic():
    """Endpoint for the Live Traffic Monitor."""
    response_data = {
        "logs": get_live_logs(),
        "role": CONFIG['role'],
        "sensitivity": CONFIG['sensitivity']
    }
    return jsonify(response_data)

@app.route('/api/alerts/history', methods=['GET'])
def get_alerts_history():
    """Endpoint for the Detection Dashboard."""
    return jsonify({"alerts": get_alert_history()})


@app.route('/api/analytics/trends', methods=['GET'])
def get_analytics_trends():
    """Endpoint for Analytics & Trends."""
    logs = get_live_logs()
    
    classification_counts = {}
    protocol_counts = {}
    ip_counts = {}

    if not logs:
        # FALLBACK: Use a simple mock to ensure the frontend displays something if traffic is zero
        classification_stats = [("Normal", 10), ("Anomaly", 0)] 
        protocol_stats = [("TCP", 5), ("UDP", 3), ("ICMP", 2)]
        ip_stats = [("0.0.0.0", 0)]
    else:
        for log in logs:
            c = log.get("classification", "Unknown")
            p = log.get("protocol", "Unknown")
            ip = log.get("src_ip", "Unknown")

            classification_counts[c] = classification_counts.get(c, 0) + 1
            protocol_counts[p] = protocol_counts.get(p, 0) + 1

            # Count all source IPs, not just anomalous ones
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        classification_stats = sorted(classification_counts.items(), key=lambda item: item[1], reverse=True)
        protocol_stats = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
        ip_stats = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:10]

    response_data = {
        "classification_stats": classification_stats,
        "protocol_stats": protocol_stats,
        "ip_stats": ip_stats
    }
    return jsonify(response_data)


@app.route('/api/packet/<int:packet_id>', methods=['GET'])
def get_packet_details(packet_id):
    """Endpoint for the Packet Inspector, retrieving detailed packet info."""
    packet = get_packet_by_id(packet_id)

    if packet:
        return jsonify({"message": f"Packet {packet_id} found.", "details": packet})
    else:
        return jsonify({
            "message": f"Packet ID {packet_id} not found in recent logs.", 
            "details": None
        }), 404


@app.route('/api/settings', methods=['POST'])
def save_settings():
    """Endpoint to update global settings."""
    try:
        data = request.get_json()
        CONFIG.update(data)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(CONFIG, f, indent=4)
        return jsonify({"message": "Settings saved successfully.", "config": CONFIG})
    except Exception as e:
        return jsonify({"message": f"Failed to save settings: {e}"}), 500

@app.route('/api/alerts/action', methods=['POST'])
def handle_alert_action():
    """Endpoint to handle alert actions (FP, Block IP)."""
    data = request.get_json()
    alert_id = data.get('alert_id')
    action = data.get('action')
    src_ip = data.get('src_ip')
    
    for alert in ALERT_HISTORY:
        if alert.get('alert_id') == alert_id:
            alert['status'] = "Processed" 
            break
            
    return jsonify({
        "message": f"Action '{action}' processed for Alert ID {alert_id}. Status updated."
    })

@app.route('/api/traffic/map', methods=['GET'])
def get_traffic_map():
    """Endpoint for the Network Flow Visualization / Geo-IP Map."""
    try:
        map_html = generate_traffic_map()
        # Return raw HTML with correct content-type for frontend QWebEngineView
        return map_html, 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({"error": f"Failed to generate map: {str(e)}"}), 500


if __name__ == '__main__':
    print(f"--- Flask API running on http://{CONFIG['api_host']}:{CONFIG['api_port']} ---")
    app.run(host=CONFIG['api_host'], port=CONFIG['api_port'], debug=True, use_reloader=False)
