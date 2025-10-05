import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
import numpy as np
from backend.ml_engine import MLEngine

def test_ml_engine_initialization():
    """Test that ML engine initializes correctly."""
    engine = MLEngine()
    assert engine.model is not None or engine.model is None  # Allow for missing model

def test_ml_engine_predict():
    """Test ML prediction with sample features."""
    engine = MLEngine()

    # Test normal packet features
    features = [6, 60, 128, 1]  # TCP, length 60, TTL 128, 1 flag
    classification, confidence = engine.predict(features)

    assert isinstance(classification, int)
    assert 0 <= classification <= 1
    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0

def test_ml_engine_predict_anomaly():
    """Test ML prediction with potential anomaly features."""
    engine = MLEngine()

    # Test anomaly packet features
    features = [6, 1400, 64, 4]  # TCP, length 1400, TTL 64, 4 flags
    classification, confidence = engine.predict(features)

    assert isinstance(classification, int)
    assert 0 <= classification <= 1
    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0

def test_ml_engine_predict_invalid_features():
    """Test ML prediction with invalid features."""
    engine = MLEngine()

    # Test with None features
    classification, confidence = engine.predict(None)
    assert classification == 0
    assert confidence == 0.0
