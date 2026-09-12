import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from app.main import app

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["model_loaded"] is True
        assert data["model_version"] == "1.0.0"

def test_model_info_endpoint():
    with TestClient(app) as client:
        response = client.get("/model-info")
        assert response.status_code == 200
        data = response.json()
        assert "Random Forest" in data["model_name"]
        assert len(data["features"]) == 18
        assert "metrics" in data
        assert data["metrics"]["accuracy"] == 1.0

def test_predict_benign_url():
    payload = {
        "features": {
            "url_length": 22,
            "hostname_length": 14,
            "path_length": 1,
            "query_length": 0,
            "dot_count": 2,
            "subdomain_count": 1,
            "path_segment_count": 0,
            "query_params_count": 0,
            "special_char_count": 4,
            "digits_count": 0,
            "hyphen_count": 0,
            "underscore_count": 0,
            "at_symbol_count": 0,
            "percent_count": 0,
            "uses_https": 1,
            "is_ip_address": 0,
            "suspicious_keyword_count": 0,
            "suspicious_hostname_pattern": 0
        }
    }
    with TestClient(app) as client:
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == "benign"
        assert data["probability"] < 0.5
        assert len(data["top_contributing_features"]) > 0

def test_predict_malicious_url():
    payload = {
        "features": {
            "url_length": 45,
            "hostname_length": 12,
            "path_length": 24,
            "query_length": 0,
            "dot_count": 3,
            "subdomain_count": 0,
            "path_segment_count": 2,
            "query_params_count": 0,
            "special_char_count": 6,
            "digits_count": 8,
            "hyphen_count": 1,
            "underscore_count": 0,
            "at_symbol_count": 0,
            "percent_count": 0,
            "uses_https": 0,
            "is_ip_address": 1,
            "suspicious_keyword_count": 2,
            "suspicious_hostname_pattern": 1
        }
    }
    with TestClient(app) as client:
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == "malicious"
        assert data["probability"] > 0.5
