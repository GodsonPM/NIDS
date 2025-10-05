import pickle
import numpy as np
import json

class MLEngine:
    """
    Loads a pre-trained ML model and handles real-time inference.
    """
    def __init__(self, config_path='storage/settings.json'):
        self.model = None
        self.config_path = config_path
        self.model_path = self._load_model_path()
        self._load_model()

    def _load_model_path(self):
        """Loads model path from settings.json."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                return config.get('model_path', 'models/rf_model.pkl')
        except Exception as e:
            print(f"Error loading settings for model path: {e}")
            return 'models/rf_model.pkl'

    def _load_model(self):
        """Loads the pre-trained model from disk."""  
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                # Extract the actual model from the dict
                if isinstance(model_data, dict) and 'model' in model_data:
                    self.model = model_data['model']
                else:
                    self.model = model_data
            print(f"ML Engine: Successfully loaded model from {self.model_path}")
        except FileNotFoundError:
            print(f"ML Engine Error: Model file not found at {self.model_path}.")
            print("Please run 'python generate_model.py' first.")
            self.model = None
        except Exception as e:
            print(f"ML Engine Error: Failed to load model: {e}")
            self.model = None

    def predict(self, features: list) -> tuple:
        """
        Performs real-time classification on the feature vector.
        
        Args:
            features: A list/array of numerical features (e.g., [6, 60, 64, 1]).
            
        Returns:
            A tuple (classification_label: int, confidence_score: float).
        """
        if self.model is None:
            return 0, 0.0 # Default to Normal with 0 confidence if model is missing

        try:
            # Reshape features for model input (1 sample, N features)
            X = np.array(features).reshape(1, -1)
            
            # Classification (0 or 1)
            classification = self.model.predict(X)[0]
            
            # Confidence/Probability (for the predicted class)
            probabilities = self.model.predict_proba(X)[0]
            confidence = probabilities[classification]
            
            return int(classification), float(confidence)
            
        except Exception as e:
            print(f"ML Engine Prediction Error: {e}. Input features: {features}")
            return 0, 0.0 # Safe default
            
if __name__ == '__main__':
    # Test the ML engine (requires model to be generated first)
    engine = MLEngine()
    
    # Test Case 1: Normal Packet (TCP, length 60, TTL 128, 1 flag)
    normal_features = [6, 60, 128, 1]
    cls, conf = engine.predict(normal_features)
    print(f"Test Normal: Class={cls}, Confidence={conf:.4f}")

    # Test Case 2: Potential Anomaly (TCP, length 1400, low TTL 64, 4 flags)
    anomaly_features = [6, 1400, 64, 4] 
    cls, conf = engine.predict(anomaly_features)
    print(f"Test Anomaly: Class={cls}, Confidence={conf:.4f}")
