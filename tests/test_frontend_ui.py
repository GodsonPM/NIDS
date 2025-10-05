import pytest
from PyQt5.QtWidgets import QApplication
from frontend.ui_main import NIDSApp
import sys
import time
from unittest.mock import patch, MagicMock

@pytest.fixture(scope="module")
def app():
    app = QApplication(sys.argv)
    yield app
    app.quit()

def test_live_traffic_monitor_tab(app):
    # Mock the API response
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {
            "id": 1,
            "timestamp": "2023-10-01T12:00:00Z",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "protocol": "TCP",
            "size": 60,
            "classification": "Normal",
            "confidence": 0.95
        }
    ]

    with patch('requests.get', return_value=mock_response):
        window = NIDSApp()
        window.show()

        # Navigate to Live Traffic Monitor tab
        window.tabs.setCurrentIndex(0)  # Assuming first tab is Live Traffic Monitor

        # Allow some time for data to load and update
        time.sleep(1)

        # Manually trigger update_ui_data to populate table
        window._update_live_traffic_data({"logs": mock_response.json.return_value, "role": "Analyst", "sensitivity": 0.5})

        # Check if the traffic table has rows populated
        traffic_table = window.traffic_table
        row_count = traffic_table.rowCount()
        assert row_count > 0, "Live Traffic Monitor table should have rows populated"

        # Check if status label shows OK
        status_text = window.status_label.text()
        assert "OK" in status_text, "Status should show OK"

        # Close the window
        window.close()
