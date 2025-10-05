import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
import json
from backend.api import app, load_config

def test_load_config():
    """Test configuration loading."""
    config = load_config('storage/settings.json')
    assert isinstance(config, dict)
    assert 'sensitivity' in config
    assert 'role' in config
    assert 'theme' in config

def test_api_get_live_traffic(client):
    """Test the live traffic endpoint."""
    with app.test_client() as client:
        response = client.get('/api/traffic/live')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'logs' in data
        assert 'role' in data
        assert 'sensitivity' in data

def test_api_get_alerts_history(client):
    """Test the alerts history endpoint."""
    with app.test_client() as client:
        response = client.get('/api/alerts/history')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'alerts' in data

def test_api_get_analytics_trends(client):
    """Test the analytics trends endpoint."""
    with app.test_client() as client:
        response = client.get('/api/analytics/trends')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'classification_stats' in data
        assert 'protocol_stats' in data
        assert 'ip_stats' in data

def test_api_get_packet_details_not_found(client):
    """Test packet details endpoint with non-existent packet."""
    with app.test_client() as client:
        response = client.get('/api/packet/99999')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'details' in data
        assert data['details'] is None

def test_api_settings_post(client):
    """Test settings update endpoint."""
    with app.test_client() as client:
        payload = {
            'sensitivity': 0.7,
            'role': 'Admin',
            'theme': 'Dark'
        }
        response = client.post('/api/settings',
                              data=json.dumps(payload),
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data

def test_api_alerts_action_false_positive(client):
    """Test alerts action endpoint for false positive."""
    with app.test_client() as client:
        payload = {
            'alert_id': 1,
            'action': 'false_positive',
            'src_ip': '192.168.1.1'
        }
        response = client.post('/api/alerts/action',
                              data=json.dumps(payload),
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data

def test_api_alerts_action_block_ip(client):
    """Test alerts action endpoint for block IP."""
    with app.test_client() as client:
        payload = {
            'alert_id': 2,
            'action': 'block_ip',
            'src_ip': '192.168.1.2'
        }
        response = client.post('/api/alerts/action',
                              data=json.dumps(payload),
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
