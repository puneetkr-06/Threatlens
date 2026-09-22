import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
from fastapi.testclient import TestClient
from core.inspector import RequestInspector
from main import app


def test_request_inspector_url_decoding():
    """Verify recursive URL-decoding prevents multi-layer evasion."""
    # Double-encoded payload: %2527 -> %27 -> '
    double_encoded = "%2527%20OR%201=1"
    normalized = RequestInspector.normalize_string(double_encoded)
    assert normalized == "' OR 1=1"

    # Triple-encoded payload
    triple_encoded = "%252527%20OR%201=1"
    normalized = RequestInspector.normalize_string(triple_encoded)
    assert normalized == "' OR 1=1"


def test_waf_health_endpoint():
    """Verify WAF health status endpoint."""
    client = TestClient(app)
    response = client.get("/waf/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "high_threshold" in data
    assert "low_threshold" in data


if __name__ == "__main__":
    test_request_inspector_url_decoding()
    print("[PASS] test_request_inspector_url_decoding")
    test_waf_health_endpoint()
    print("[PASS] test_waf_health_endpoint")
    print("All unit tests passed successfully!")
