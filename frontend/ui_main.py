import sys
import json
import time
import requests
import base64
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QTextEdit, QLabel, QSlider, QComboBox, QPushButton,
    QGroupBox, QMessageBox, QFileDialog, QGridLayout
)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtWebEngineWidgets import QWebEngineView

# --- Configuration Constants ---
API_BASE_URL = "http://127.0.0.1:5000/api"

# Function to load configuration safely (copied from backend)
def load_config(filepath):
    """Loads configuration from a JSON file, using defaults if file is missing."""
    default_config = {
        "db_path": "storage/logs.db",
        "model_path": "models/rf_model.pkl",
        "api_host": "127.0.0.1",
        "api_port": 5000,
        "sensitivity": 0.5,
        "theme": "Light"  # CHANGED to Light/Default Theme
    }
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)
            # Merge loaded config with defaults to ensure all keys exist
            # Ensure theme is correctly set, defaulting to "Light" if not found
            if 'theme' not in config:
                config['theme'] = 'Light' 
            return {**default_config, **config}
    except FileNotFoundError:
        print(f"Configuration file not found at {filepath}. Using defaults.")
        return default_config
    except json.JSONDecodeError:
        print(f"Configuration file at {filepath} is invalid. Using defaults.")
        return default_config

CONFIG = load_config('storage/settings.json')


# --- Worker Thread for API Calls ---
class ApiWorker(QThread):
    """A separate thread to handle API requests asynchronously."""
    data_ready = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def __init__(self, url, method='GET', payload=None):
        super().__init__()
        self.url = url
        self.method = method
        self.payload = payload

    def run(self):
        try:
            if self.method == 'GET':
                response = requests.get(self.url, timeout=5)
            elif self.method == 'POST':
                response = requests.post(self.url, json=self.payload, timeout=5)
            else:
                self.error_signal.emit(f"Unsupported method: {self.method}")
                return

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type:
                # Treat as raw HTML (e.g., for /traffic/map)
                self.data_ready.emit({'map_html': response.text})
            else:
                # Treat as JSON for all other endpoints
                self.data_ready.emit(response.json())

        except requests.exceptions.RequestException as e:
            error_message = f"API Error: {e}. Ensure the Flask API is running."
            self.error_signal.emit(error_message)
        except json.JSONDecodeError:
            self.error_signal.emit("API Error: Invalid JSON response.")


class NIDSApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NIDS Desktop Monitor")
        self.setGeometry(100, 100, 1400, 800)
        self.current_sensitivity = CONFIG['sensitivity']
        self.current_packet_details = None # Store selected packet details for export
        self.current_theme = CONFIG['theme'] # Initialize theme state (now "Light" by default)

        self.central_widget = QWidget()
        self.central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(self.central_widget)

        self.tabs = QTabWidget()
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(15, 15, 15, 15)

        # Initialize labels before applying theme or creating header
        self.status_label = QLabel()

        self.create_header()
        self.create_tabs()
        self.main_layout.addWidget(self.tabs)

        # Apply theme first for initial styling
        self.apply_theme(self.current_theme)

        # Connect signal to handle reliable loading when tabs are switched
        self.tabs.currentChanged.connect(self.handle_tab_change)

        # Timer for real-time data updates (1 second interval)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_ui_data)
        self.timer.start(1000)

        # Initial display update (uses theme colors)
        self.update_status_display("Status: Loading...")

    # --- Theme Management and Styling (Enhanced Modern Dark Mode) ---
    def update_status_display(self, current_text):
        """Updates the visual appearance of the status and role labels based on content and theme."""
        
        # Define Color Constants for easy modification
        if self.current_theme == "Dark":
            ok_color = "#34D399" # Emerald Green
            err_color = "#F87171" # Red
            warn_color = "#FBBF24" # Amber
        else: # Light Theme Colors
            ok_color = "darkgreen"
            err_color = "darkred"
            warn_color = "orange"

        # Update Status with Unicode Emojis for quick visual feedback
        if "API Error" in current_text:
            status_html = f"Status: <b style='color:{err_color}'>🛑 API Error</b>"
        elif "Loading" in current_text:
            status_html = f"Status: <b style='color:{warn_color}'>⏳ Loading...</b>"
        elif "OK" in current_text:
            status_html = f"Status: <b style='color:{ok_color}'>✅ OK</b>"
        else:
            status_html = current_text # Fallback

        self.status_label.setText(status_html)

    def apply_theme(self, theme):
        """Applies dark or light theme based on selection, including comprehensive stylesheet."""
        
        # Modern Dark Theme Palette
        BG_MAIN = QColor(20, 25, 30)        # Deep, main background
        FG_DEFAULT = QColor(220, 225, 230)  # Light gray text
        BASE_CARD = QColor(30, 37, 45)      # Card/Widget background (subtle lift)
        BASE_INPUT = QColor(40, 50, 60)     # Text field/Table cell background
        HIGHLIGHT = QColor(0, 150, 255)     # Primary Highlight (Vibrant Blue)
        RED_ALERT = QColor(255, 80, 80)     # Anomaly/Error color

        if theme == "Dark":
            palette = QPalette()
            
            # Apply color palette to standard controls
            palette.setColor(QPalette.Window, BG_MAIN)
            palette.setColor(QPalette.WindowText, FG_DEFAULT)
            palette.setColor(QPalette.Base, BASE_INPUT)
            palette.setColor(QPalette.Text, FG_DEFAULT)
            palette.setColor(QPalette.Button, BASE_CARD)
            palette.setColor(QPalette.ButtonText, FG_DEFAULT)
            palette.setColor(QPalette.Highlight, HIGHLIGHT)
            palette.setColor(QPalette.HighlightedText, BG_MAIN)
            self.setPalette(palette)
            
            dark_stylesheet = f"""
                /* Global Font and Spacing */
                * {{
                    font-family: "Inter", sans-serif;
                    font-size: 10pt;
                    color: {FG_DEFAULT.name()};
                }}

                /* QMainWindow, Central Widget, and Main Layout */
                QMainWindow, QWidget#CentralWidget {{
                    background-color: {BG_MAIN.name()};
                }}

                /* QTabWidget Tabs */
                QTabWidget::pane {{
                    border: 1px solid {BASE_CARD.name()};
                    background: {BG_MAIN.name()};
                    border-radius: 8px;
                    padding: 5px;
                }}
                QTabBar::tab {{
                    background: {BASE_CARD.name()};
                    color: {FG_DEFAULT.name()};
                    border: 1px solid {BASE_CARD.name()};
                    border-bottom-color: {BG_MAIN.name()};
                    padding: 8px 15px;
                    min-width: 100px;
                    font-size: 9pt;
                    border-top-left-radius: 6px;
                    border-top-right-radius: 6px;
                }}
                QTabBar::tab:selected {{
                    background: {BG_MAIN.name()};
                    border-bottom: 3px solid {HIGHLIGHT.name()};
                    font-weight: bold;
                    margin-bottom: -1px;
                }}

                /* QGroupBox titles and borders */
                QGroupBox {{
                    color: {HIGHLIGHT.name()};
                    border: 1px solid {BASE_CARD.name()};
                    margin-top: 2ex;
                    padding-top: 10px;
                    padding-bottom: 5px;
                    border-radius: 8px;
                    font-weight: bold;
                }}
                QGroupBox::title {{
                    subcontrol-origin: margin;
                    subcontrol-position: top center;
                    padding: 0 5px;
                    color: {FG_DEFAULT.name()};
                    font-size: 11pt;
                }}

                /* QPushButton (Default) */
                QPushButton {{
                    background-color: {BASE_CARD.name()};
                    border: 1px solid {BASE_INPUT.name()};
                    padding: 8px 15px;
                    border-radius: 6px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    background-color: {BASE_INPUT.name()};
                }}

                /* Primary Buttons (Save Settings, Export) */
                QPushButton#primaryButton {{
                    background-color: {HIGHLIGHT.name()};
                    color: {BG_MAIN.name()};
                    font-weight: bold;
                    border: none;
                }}
                QPushButton#primaryButton:hover {{
                    background-color: {HIGHLIGHT.darker(120).name()};
                }}

                /* QTableWidget, QTextEdit, QComboBox, QSlider */
                QTableWidget, QTextEdit, QComboBox, QSlider {{
                    background-color: {BASE_INPUT.name()};
                    border: 1px solid {BASE_CARD.name()};
                    padding: 5px;
                    border-radius: 4px;
                    selection-background-color: {HIGHLIGHT.name()};
                }}

                /* QComboBox dropdown list */
                QComboBox QAbstractItemView {{
                    background-color: {BASE_INPUT.name()};
                    color: {FG_DEFAULT.name()};
                    selection-background-color: {HIGHLIGHT.name()};
                    selection-color: {BG_MAIN.name()};
                }}

                /* Table Items */
                QTableWidget::item {{
                    background-color: {BASE_INPUT.name()};
                    color: {FG_DEFAULT.name()};
                    border: none;
                }}

                /* Table Headers */
                QHeaderView::section {{
                    background-color: {BASE_CARD.name()};
                    color: {FG_DEFAULT.name()};
                    padding: 8px;
                    border: 1px solid {BG_MAIN.name()};
                    font-weight: bold;
                }}

                /* Table Grid */
                QTableWidget {{
                    gridline-color: {BASE_CARD.name()};
                }}

                /* QSlider Groove */
                QSlider::groove:horizontal {{
                    border: 1px solid {BASE_CARD.name()};
                    height: 8px;
                    background: {BASE_CARD.name()};
                    margin: 2px 0;
                    border-radius: 4px;
                }}

                /* QSlider Handle */
                QSlider::handle:horizontal {{
                    background: {HIGHLIGHT.name()};
                    border: 1px solid {FG_DEFAULT.name()};
                    width: 16px;
                    margin: -4px 0;
                    border-radius: 8px;
                }}
            """
            self.setStyleSheet(dark_stylesheet)
            
        else: # Light Mode (Reset to system default)
            # Reset palette and clear custom stylesheet to use system defaults
            self.setPalette(QApplication.instance().style().standardPalette())
            light_stylesheet = f"""
                /* Global Font and Spacing */
                * {{
                    font-family: "Inter", sans-serif;
                    font-size: 10pt;
                }}

                /* Header Widget Background */
                QWidget#HeaderWidget {{
                    background-color: #f8f9fa;
                }}
            """
            self.setStyleSheet(light_stylesheet)

        self.current_theme = theme
        # Re-apply status display to pick up new theme colors
        self.update_status_display(self.status_label.text() or "Status: Loading...")

    def toggle_theme(self):
        """Toggles between Dark and Light mode."""
        new_theme = "Light" if self.current_theme == "Dark" else "Dark"
        self.apply_theme(new_theme)
        # Update the combobox in the settings tab if it exists
        if hasattr(self, 'theme_combo'):
            self.theme_combo.setCurrentText(new_theme)
        self.save_settings()

    # --- UI Layout Creation ---
    def create_header(self):
        """Creates the professional header with status and role information."""
        header_widget = QWidget()
        header_widget.setObjectName("HeaderWidget")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 10)

        title = QLabel("Network IDS Desktop Monitor")
        title.setFont(QFont("Inter", 18, QFont.ExtraBold))

        header_layout.addWidget(title)
        header_layout.addStretch(1)

        info_layout = QHBoxLayout()
        info_layout.setSpacing(20)
        info_layout.addWidget(self.status_label)

        header_layout.addLayout(info_layout)

        self.main_layout.addWidget(header_widget)

    def create_tabs(self):
        """Sets up all the main tab views."""
        self.create_live_traffic_tab()
        self.create_detection_dashboard_tab()
        self.create_analytics_tab()
        self.create_packet_inspector_tab()
        self.create_settings_tab()

        self.tabs.addTab(self.live_traffic_tab, "Live Traffic Monitor")
        self.tabs.addTab(self.detection_dashboard_tab, "Detection Dashboard")
        self.tabs.addTab(self.analytics_tab, "Analytics & Trends")
        self.tabs.addTab(self.packet_inspector_tab, "Packet Inspector")
        self.tabs.addTab(self.settings_tab, "Settings & Tuning")

    def create_live_traffic_tab(self):
        """Tab 1: Live Traffic Monitor (Table and Chart Placeholder)."""
        self.live_traffic_tab = QWidget()
        layout = QVBoxLayout(self.live_traffic_tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # 1. Live Packet Table
        self.traffic_table = QTableWidget(0, 6)
        self.traffic_table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Src IP", "Dst IP", "Protocol", "Classification"
        ])
        
        header = self.traffic_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) 
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents) 
        header.setSectionResizeMode(2, QHeaderView.Stretch)         
        header.setSectionResizeMode(3, QHeaderView.Stretch)         
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)        

        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_table.clicked.connect(self.handle_packet_selection)

        layout.addWidget(self.traffic_table)

    def create_detection_dashboard_tab(self):
        """Tab 2: Detection Dashboard (Alert Table)."""
        self.detection_dashboard_tab = QWidget()
        layout = QVBoxLayout(self.detection_dashboard_tab)
        layout.setContentsMargins(5, 5, 5, 5)

        self.alert_table = QTableWidget(0, 7)
        self.alert_table.setHorizontalHeaderLabels([
            "Alert ID", "Packet ID", "Timestamp", "Source IP", "Attack Type", "Confidence", "Action"
        ])
        
        header = self.alert_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents) 

        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.alert_table)

    def create_analytics_tab(self):
        """Tab 3: Analytics & Trends (ASCII Charts for Breakdown)."""
        self.analytics_tab = QWidget()
        layout = QVBoxLayout(self.analytics_tab)
        layout.setContentsMargins(10, 10, 10, 10)

        chart_area = QHBoxLayout()
        chart_area.setSpacing(15)

        # Helper function for setting up the text editor for charts
        def create_chart_box(title):
            gb = QGroupBox(title)
            gb.setFont(QFont("Inter", 11, QFont.Bold))
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Monospace", 9))
            text_edit.setText("Loading analytics data...")
            gb.setLayout(QVBoxLayout())
            gb.layout().addWidget(text_edit)
            return gb, text_edit

        # Group Box 1: Classification Breakdown
        gb1, self.classification_chart = create_chart_box('Classification Breakdown (Normal vs. Anomaly)')
        chart_area.addWidget(gb1)

        # Group Box 2: Protocol Breakdown
        gb2, self.protocol_chart = create_chart_box('Protocol Breakdown')
        chart_area.addWidget(gb2)

        # Group Box 3: Top Source IPs
        gb3, self.ip_chart = create_chart_box('Top Source IPs')
        chart_area.addWidget(gb3)

        layout.addLayout(chart_area)
        layout.addStretch(1)

    def create_packet_inspector_tab(self):
        """Tab 4: Packet Inspector (Hex view, Header Breakdown, Export)."""
        self.packet_inspector_tab = QWidget()
        layout = QVBoxLayout(self.packet_inspector_tab)
        layout.setContentsMargins(5, 5, 5, 5)

        # 1. Header Breakdown (Tree/Text)
        breakdown_group = QGroupBox("Header Breakdown")
        breakdown_group.setFont(QFont("Inter", 11, QFont.Bold))
        self.breakdown_view = QTextEdit()
        self.breakdown_view.setReadOnly(True)
        self.breakdown_view.setText("Select a packet from the Live Traffic Monitor to inspect its details.")
        breakdown_group.setLayout(QVBoxLayout())
        breakdown_group.layout().addWidget(self.breakdown_view)
        
        # 2. Hex View
        hex_group = QGroupBox("Raw Hex View")
        hex_group.setFont(QFont("Inter", 11, QFont.Bold))
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Monospace", 9))
        hex_group.setLayout(QVBoxLayout())
        hex_group.layout().addWidget(self.hex_view)

        inspector_layout = QHBoxLayout()
        inspector_layout.addWidget(breakdown_group, 1)
        inspector_layout.addWidget(hex_group, 1)

        layout.addLayout(inspector_layout)

        # 3. Export Button (Styled as primary action)
        export_button = QPushButton("⬇️ Export Selected Packet Details (JSON)")
        export_button.setObjectName("primaryButton")
        export_button.clicked.connect(self.export_packet_data)
        
        # Use HBox to center the button
        export_hbox = QHBoxLayout()
        export_hbox.addStretch(1)
        export_hbox.addWidget(export_button, 1) # Allow button to stretch a bit
        export_hbox.addStretch(1)
        layout.addLayout(export_hbox)

    def create_settings_tab(self):
        """Tab 5: Settings & Tuning (ML Model, Sensitivity, Filters)."""
        self.settings_tab = QWidget()
        layout = QVBoxLayout(self.settings_tab)
        layout.setContentsMargins(30, 30, 30, 30) # Larger margins for settings
        
        form_layout = QVBoxLayout()
        form_layout.setSpacing(25)

        # Group 1: ML Tuning
        ml_group = QGroupBox("ML Model Tuning")
        ml_group.setFont(QFont("Inter", 11, QFont.Bold))
        ml_layout = QVBoxLayout(ml_group)
        ml_layout.setSpacing(10)
        
        # Sensitivity Slider
        ml_layout.addWidget(QLabel("<b>Detection Sensitivity Threshold:</b> (Higher = More Alerts)"))
        
        h_layout_sensitivity = QHBoxLayout()
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setRange(10, 90) # Represents 0.10 to 0.90
        self.sensitivity_slider.setValue(int(self.current_sensitivity * 100))
        self.sensitivity_slider.setTickInterval(10)
        self.sensitivity_slider.setTickPosition(QSlider.TicksBelow)
        
        self.sensitivity_label = QLabel(f"{self.current_sensitivity:.2f}")
        self.sensitivity_label.setFixedWidth(50) # Fix width for label
        self.sensitivity_slider.valueChanged.connect(lambda v: self.sensitivity_label.setText(f"{v / 100:.2f}"))

        h_layout_sensitivity.addWidget(self.sensitivity_slider)
        h_layout_sensitivity.addWidget(self.sensitivity_label)
        ml_layout.addLayout(h_layout_sensitivity)
        
        # Model Selection (Static for this version)
        ml_layout.addWidget(QLabel("<b>Active ML Model Path:</b>"))
        model_label = QLabel(f"<i>{CONFIG['model_path']}</i>")
        ml_layout.addWidget(model_label)
        
        form_layout.addWidget(ml_group)

        # Group 2: User and UI Settings
        user_group = QGroupBox("User and UI Preferences")
        user_group.setFont(QFont("Inter", 11, QFont.Bold))
        user_layout = QGridLayout(user_group) # Use grid for better alignment
        user_layout.setVerticalSpacing(15)
        user_layout.setHorizontalSpacing(20)

        # Theme Toggle
        user_layout.addWidget(QLabel("UI Theme:"), 0, 0)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentText(CONFIG['theme'])
        self.theme_combo.currentIndexChanged.connect(lambda: self.apply_theme(self.theme_combo.currentText()))
        user_layout.addWidget(self.theme_combo, 0, 1)

        form_layout.addWidget(user_group)
        
        # Save Button (Styled as primary)
        self.save_button = QPushButton("💾 Apply & Save Settings")
        self.save_button.setObjectName("primaryButton")
        self.save_button.clicked.connect(self.save_settings)
        
        # Use HBox to center the button
        save_hbox = QHBoxLayout()
        save_hbox.addStretch(1)
        save_hbox.addWidget(self.save_button, 1)
        save_hbox.addStretch(1)
        
        form_layout.addLayout(save_hbox)

        layout.addLayout(form_layout)
        layout.addStretch(1)

    # --- Interaction Handlers for Tabs and Data ---
    def handle_tab_change(self, index):
        """Triggers specific actions when a tab is selected (Reliable loading for Analytics)."""
        # Index 2 is "Analytics & Trends"
        if index == 2:
            print("Analytics tab selected. Triggering on-demand data refresh.")
            # Manually trigger a refresh for the analytics data when the tab is opened
            self._start_api_call(
                url=f"{API_BASE_URL}/analytics/trends",
                callback=self._update_analytics_data,
                tag="TrendsOnDemand"
            )

    # --- Data Fetching and Updating ---
    def update_ui_data(self):
        """Initiates API calls to refresh all tabs (happens every 1 second)."""
        # 1. Live Data, Alerts, and Config Status
        self._start_api_call(
            url=f"{API_BASE_URL}/traffic/live",
            callback=self._update_live_traffic_data,
            tag="Traffic"
        )

        # 2. Alert History
        self._start_api_call(
            url=f"{API_BASE_URL}/alerts/history",
            callback=self._update_alert_data,
            tag="Alerts"
        )

    def _start_api_call(self, url, callback, tag):
        """Helper to start an asynchronous API worker."""
        worker = ApiWorker(url, method='GET')
        setattr(self, f'{tag}_worker', worker) 

        worker.data_ready.connect(callback)
        worker.error_signal.connect(self._handle_api_error)
        worker.start()

    def _handle_api_error(self, message):
        """Displays API connection errors in the status bar."""
        print(f"DEBUG: API error received: {message}")  # Debug print for API errors
        self.update_status_display(f"Status: API Error")
        print(message)
        if self.timer.isActive():
            if "Ensure the Flask API is running" in message:
                self.timer.stop()
                self.show_message("Connection Lost", "Real-time updates stopped due to API error. Please check the backend server.", is_error=True)


    def _update_live_traffic_data(self, data):
        """Updates the Live Traffic table."""

        self.current_sensitivity = data.get('sensitivity', self.current_sensitivity)
        self.update_status_display("Status: OK") # Update to OK status

        logs = data.get('logs', [])
        print(f"DEBUG: Received logs: {logs}")  # Debug print to check logs data

        # Logs are now individual entries, no need to flatten
        flattened_logs = logs

        self.traffic_table.setRowCount(len(flattened_logs))

        # Define anomaly colors based on current theme for text and background
        if self.current_theme == "Dark":
             anomaly_text_color = QColor(255, 80, 80) # Vibrant Red
             anomaly_bg_color = QColor(100, 40, 40) # Brighter red background for better visibility
        else:
             anomaly_text_color = QColor(180, 0, 0) # Dark Red for high contrast on light background
             anomaly_bg_color = QColor(255, 230, 230) # Light Red background for subtle highlight

        for row, log in enumerate(flattened_logs):
            if not isinstance(log, dict):
                print(f"Skipping malformed log entry: {log}")
                continue

            print(f"DEBUG: Processing log entry keys: {list(log.keys())}")  # Debug print keys

            for col, key in enumerate(["id", "timestamp", "src_ip", "dst_ip", "protocol", "classification"]):
                value = str(log.get(key, ''))
                print(f"DEBUG: Key: {key}, Value: {value}")  # Debug print key-value
                item = QTableWidgetItem(value)
                
                # Highlight Anomalies
                is_anomaly = (key == "classification" and "anomaly" in value.lower())
                
                if is_anomaly:
                    item.setForeground(anomaly_text_color)
                    item.setBackground(anomaly_bg_color)
                
                # Center ID and Protocol columns for cleaner look
                if key in ["id", "protocol"]:
                     item.setTextAlignment(Qt.AlignCenter)


                self.traffic_table.setItem(row, col, item)

        self.traffic_table.scrollToBottom()
        self.traffic_table.repaint()


    def _update_alert_data(self, data):
        """Updates the Detection Dashboard alert table."""
        print(f"DEBUG: Received alert data: {data}")  # Debug print to check alert data
        alerts = data.get('alerts', [])
        if not alerts:
            self.alert_table.setRowCount(1)
            no_alert_item = QTableWidgetItem("No alerts to display")
            no_alert_item.setTextAlignment(Qt.AlignCenter)
            self.alert_table.setSpan(0, 0, 1, 7)  # Span across all columns
            self.alert_table.setItem(0, 0, no_alert_item)
            # Clear any existing widgets in the last column
            for row in range(self.alert_table.rowCount()):
                self.alert_table.setCellWidget(row, 6, None)
            return
        
        self.alert_table.setRowCount(len(alerts))
        
        for row, alert in enumerate(alerts):
            keys = ["alert_id", "packet_id", "timestamp", "src_ip", "attack_type", "confidence"]
            
            for col, key in enumerate(keys):
                value = str(alert.get(key, ''))
                item = QTableWidgetItem(value)
                
                if key == "confidence":
                    item.setText(f"{float(value):.2f}")
                    item.setTextAlignment(Qt.AlignCenter)
                elif key in ["alert_id", "packet_id"]:
                    item.setTextAlignment(Qt.AlignCenter)

                self.alert_table.setItem(row, col, item)

            # Add Action Buttons in the last column
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(5, 5, 5, 5)

            # Mark False Positive Button (Orange/Yellow for caution)
            fp_btn = QPushButton("FP")
            fp_btn.setToolTip("Mark as False Positive (Dismiss Alert)")
            fp_btn.setFixedSize(40, 25)
            fp_btn.setStyleSheet("""
                QPushButton {
                    background-color: #FBBF24; /* Amber */
                    color: black;
                    font-weight: bold;
                    font-size: 6pt;
                    border-radius: 4px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #FCD34D;
                }
            """)
            fp_btn.clicked.connect(lambda _, aid=alert['alert_id']: self.handle_alert_action(aid, "false_positive"))
            
            # Block IP Button (Deep Red for destructive action)
            block_btn = QPushButton("Block")
            block_btn.setToolTip(f"Simulate Blocking Source IP: {alert['src_ip']}")
            block_btn.setFixedSize(50, 25)
            block_btn.setStyleSheet("""
                QPushButton {
                    background-color: #E74C3C; /* Deep Red */
                    color: white;
                    font-weight: bold;
                    font-size: 6pt;
                    border-radius: 4px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #C0392B;
                }
            """)
            block_btn.clicked.connect(lambda _, aid=alert['alert_id'], ip=alert['src_ip']: self.handle_alert_action(aid, "block_ip", ip))

            action_layout.addWidget(fp_btn)
            action_layout.addWidget(block_btn)
            action_layout.addStretch(1)

            self.alert_table.setCellWidget(row, 6, action_widget)
            self.alert_table.setRowHeight(row, 35)


    def _update_analytics_data(self, data):
        """Updates the Analytics tab with ASCII charts."""

        classification_stats = data.get('classification_stats', [])
        protocol_stats = data.get('protocol_stats', [])
        ip_stats = data.get('ip_stats', [])

        self.classification_chart.setHtml(
            self._render_bar_chart(classification_stats, title="Classification Count", scale=50)
        )
        self.protocol_chart.setHtml(
            self._render_bar_chart(protocol_stats, title="Protocol Traffic", scale=50)
        )
        self.ip_chart.setHtml(
            self._render_bar_chart(ip_stats, title="Top Source IPs", scale=50)
        )

    def _update_traffic_map(self, data):
        """Updates the Network Flow Visualization map."""
        map_html = data.get('map_html', '<html><body><h3 style="text-align: center; margin-top: 50px;">Map loading...</h3></body></html>')
        self.map_view.setHtml(map_html)

    def _render_bar_chart(self, stats, title, scale=50):
        """Generates an ASCII bar chart from data [(label, count), ...]."""
        if not stats:
            return f"{title} (Last Hour):\n\nNo data available. Ensure the sniffer is running and generating traffic."

        max_count = max(item[1] for item in stats) if stats else 1
        output = [f"<b>{title}</b> (Last Hour):\n"] # Use HTML bold
        output.append("-" * 30 + "\n")

        for label, count in stats:
            label = str(label).ljust(15)
            # Use a slightly different Unicode block character
            bar_length = int((count / max_count) * scale)
            bar = '█' * bar_length
            output.append(f"{label} {bar} ({count})")

        return "\n".join(output)

    # --- Packet Inspector Handlers ---
    def handle_packet_selection(self, index):
        """Handles click on the Live Traffic table."""
        row = index.row()
        packet_id = self.traffic_table.item(row, 0).text()
        
        # Switch to Packet Inspector tab
        self.tabs.setCurrentIndex(3)
        
        # Display loading state while fetching
        self.breakdown_view.setText(f"Fetching details for Packet ID: {packet_id}...")
        self.hex_view.setText("Loading raw data...")

        # Fetch the details
        self._start_api_call(
            url=f"{API_BASE_URL}/packet/{packet_id}",
            callback=self.display_packet_details,
            tag="PacketInspector"
        )

    def display_packet_details(self, data):
        """Displays the detailed information in the Packet Inspector tab."""
        self.current_packet_details = None

        if not data.get('details'):
            # Clear details and show a descriptive error
            self.breakdown_view.setText("Error: Could not retrieve packet details. The packet ID may have been flushed from the server's memory, or the API failed to find it.")
            self.hex_view.setText("")
            return

        details = data['details']
        self.current_packet_details = details
        
        # Define colors for the breakdown view based on theme
        anomaly_html_color = '#F87171' if self.current_theme == 'Dark' else '#B91C1C'
        normal_html_color = '#34D399' if self.current_theme == 'Dark' else '#059669'
        
        # Header Breakdown (Formatted String)
        header_text = f"<b>Packet ID:</b> {details.get('id')}<br>"
        header_text += f"<b>Timestamp:</b> {details.get('timestamp')}<br>"
        header_text += f"<b>Source IP:</b> {details.get('src_ip')}<br>"
        header_text += f"<b>Dest IP:</b> {details.get('dst_ip')}<br>"
        header_text += f"<b>Protocol:</b> {details.get('protocol')}<br>"
        header_text += f"<b>Size:</b> {details.get('size')} bytes<br>"
        
        # Color the classification text
        classification = details.get('classification', 'N/A')
        color = anomaly_html_color if 'anomaly' in classification.lower() else normal_html_color
        header_text += f"<b>Classification:</b> <span style='color:{color}'>{classification}</span><br>"
        
        header_text += "<br>--- Detailed Headers (Raw JSON) ---<br>"
        header_text += f"<pre>{json.dumps(details, indent=2)}</pre>"

        self.breakdown_view.setHtml(header_text) 

        # Raw Hex View
        raw_data = details.get('raw_data')
        if raw_data is None:
            self.hex_view.setText("No raw data available.")
        elif isinstance(raw_data, str):
            # Decode base64 string to bytes, then to hex
            try:
                decoded_bytes = base64.b64decode(raw_data)
                hex_str = ' '.join(f"{b:02X}" for b in decoded_bytes)
                self.hex_view.setText(hex_str)
            except Exception as e:
                self.hex_view.setText(f"Error decoding raw data: {e}")
        else:
            # Fallback for unexpected types
            self.hex_view.setText(str(raw_data))

    def export_packet_data(self):
        """Opens a file dialog to save the currently selected packet's details."""
        if not self.current_packet_details:
            self.show_message("Export Failed", "Please select a packet from the 'Live Traffic Monitor' first.")
            return

        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Save Packet Details", 
                                                  f"packet_{self.current_packet_details.get('id', time.time())}.json", 
                                                  "JSON Files (*.json)", options=options)
        
        if fileName:
            try:
                with open(fileName, 'w') as f:
                    json.dump(self.current_packet_details, f, indent=4)
                self.show_message("Export Successful", f"Packet details saved to:\n{fileName}")
            except Exception as e:
                self.show_message("Export Error", f"Failed to save file: {e}", is_error=True)


    def save_settings(self):
        """Gathers settings and sends them to the API to be saved."""
        new_sensitivity = self.sensitivity_slider.value() / 100.0
        new_theme = self.theme_combo.currentText()

        settings_payload = {
            "sensitivity": new_sensitivity,
            "theme": new_theme
        }

        self.current_theme = new_theme # Update theme locally before API call returns
        self.apply_theme(new_theme) # Re-apply theme immediately

        self.settings_worker = ApiWorker(
            url=f"{API_BASE_URL}/settings",
            method='POST',
            payload=settings_payload
        )
        self.settings_worker.data_ready.connect(lambda data: self.show_message("Settings Saved", data.get('message', 'Configuration updated successfully.')))
        self.settings_worker.error_signal.connect(lambda err: self.show_message("Error Saving Settings", err, is_error=True))
        self.settings_worker.start()


    def handle_alert_action(self, alert_id, action_type, source_ip=None):
        """Handles actions like False Positive or Block IP."""

        message = ""
        if action_type == "false_positive":
            message = f"Marking Alert ID {alert_id} as False Positive. This will dismiss the alert."
        elif action_type == "block_ip" and source_ip:
            message = f"Simulating blocking of IP {source_ip} due to Alert ID {alert_id}. This will dismiss the alert."

        reply = QMessageBox.question(self, 'Confirm Action',
            message + "\n\nDo you want to proceed?", QMessageBox.Yes |
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            action_payload = {
                "alert_id": alert_id,
                "action": action_type,
                "src_ip": source_ip
            }

            self.alert_action_worker = ApiWorker(
                url=f"{API_BASE_URL}/alerts/action",
                method='POST',
                payload=action_payload
            )
            self.alert_action_worker.data_ready.connect(lambda data: self.show_message("Action Success", data.get('message', 'Alert status updated.')))
            self.alert_action_worker.error_signal.connect(lambda err: self.show_message("Action Failed", err, is_error=True))
            self.alert_action_worker.start()
        else:
            self.show_message("Action Cancelled", "The user action was cancelled.")

    def closeEvent(self, event):
        """Handle application close event to properly terminate running threads."""
        # Wait for any running workers to finish
        workers_to_wait = ['settings_worker', 'alert_action_worker', 'Traffic_worker', 'Alerts_worker', 'TrendsOnDemand_worker', 'PacketInspector_worker']
        for worker_name in workers_to_wait:
            if hasattr(self, worker_name):
                worker = getattr(self, worker_name)
                if worker.isRunning():
                    worker.wait(1000)  # Wait up to 1 second for thread to finish
        event.accept()


    def show_message(self, title, message, is_error=False):
        """Displays a custom QMessageBox instead of using print() for feedback."""
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        if is_error:
            msg.setIcon(QMessageBox.Critical)
        else:
            msg.setIcon(QMessageBox.Information)
        msg.exec_()


if __name__ == '__main__':
    print("--- NIDS Frontend Starting ---")
    print("Ensure the following are running in separate terminals:")
    print("1. Sniffer: python backend/sniffer.py")
    print("2. API: python backend/api.py")
    
    app = QApplication(sys.argv)
    window = NIDSApp()
    window.show()
    sys.exit(app.exec_())
