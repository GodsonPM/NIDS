from scapy.all import Packet, IP, TCP, UDP

def extract_features(packet: Packet) -> list:
    """
    Converts a Scapy packet into a structured feature vector for the ML model.
    
    The feature order must match the training data used in generate_model.py:
    ['protocol', 'length', 'ttl', 'flags_count']
    
    Args:
        packet: A Scapy packet object.
        
    Returns:
        A list of numerical features, or None if the packet is not processable.
    """
    features = [0, 0, 0, 0] # Initialize with defaults
    
    # 1. Packet Length (total size)
    features[1] = len(packet)
    
    # 2. IP Layer Features (Source/Dest IP are too high-cardinality for this simple model, 
    #    focus on transport/network stats)
    if IP in packet:
        ip_layer = packet[IP]
        features[2] = ip_layer.ttl # TTL
        
        # 3. Protocol (TCP=6, UDP=17)
        features[0] = ip_layer.proto # Protocol number (6 for TCP, 17 for UDP)

        # 4. TCP/UDP Flags (Focus on TCP flags count for anomaly detection)
        if TCP in packet:
            tcp_layer = packet[TCP]
            # Simple count of critical flags (SYN, ACK, FIN, RST)
            flags_count = (tcp_layer.flags.S + tcp_layer.flags.A + 
                           tcp_layer.flags.F + tcp_layer.flags.R)
            features[3] = flags_count
        elif UDP in packet:
            # UDP has no flags, count is 0
            features[3] = 0
            
        return features

    return None

def packet_to_log_data(packet: Packet, classification: int, confidence: float) -> dict:
    """Extracts human-readable log data from a packet."""
    log_data = {
        'timestamp': packet.time,
        'src_ip': None,
        'dst_ip': None,
        'protocol': 'Other',
        'size': len(packet),
        'flags': '',
        'classification': 'Anomaly' if classification == 1 else 'Normal',
        'confidence': f'{confidence:.4f}'
    }

    if IP in packet:
        log_data['src_ip'] = packet[IP].src
        log_data['dst_ip'] = packet[IP].dst
        log_data['protocol'] = packet[IP].proto
        
        if TCP in packet:
            log_data['protocol'] = 'TCP'
            log_data['flags'] = str(packet[TCP].flags)
        elif UDP in packet:
            log_data['protocol'] = 'UDP'
            
    return log_data

if __name__ == '__main__':
    # Simple test for feature extraction
    from scapy.all import IP, TCP, sniff
    print("Testing feature extraction (requires elevated permissions to sniff)...")
    try:
        # A simple SYN packet
        pkt = IP(src="192.168.1.1", dst="8.8.8.8") / TCP(dport=80, flags="S")
        features = extract_features(pkt)
        print(f"Features for a SYN packet: {features}")
    except Exception as e:
        print(f"Could not test Scapy: {e}. Ensure scapy is installed and run with sufficient permissions.")
