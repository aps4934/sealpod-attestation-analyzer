import os
import json
import subprocess
import requests
import pytest

API_URL = "http://localhost:8080/verify"

@pytest.fixture(scope="session", autouse=True)
def wait_for_services():
    """Wait for the verify API to be healthy before running tests."""
    for _ in range(30):
        try:
            requests.post(API_URL, json={}, timeout=1)
            # Service is alive if it responds (even with 400 on empty JSON)
            break
        except requests.exceptions.ConnectionError:
            import time
            time.sleep(0.5)
    else:
        pytest.fail("Verification service did not start in time.")

def get_base_config():
    """Load the default valid container configuration spec."""
    with open("/app/container_config.json", "r", encoding="utf-8") as f:
        return json.load(f)

def test_endpoint_contract():
    """Verify that a valid attestation block returns HTTP 200 with the correct contract layout, including the layers list and normalized package ecosystems."""
    container_config = get_base_config()
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 200
    res_data = resp.json()
    
    assert res_data["verified"] is True
    assert res_data["signer"] == "release-signer@sealpod.io"
    
    # Assert layers are returned correctly
    layers = res_data["layers"]
    assert len(layers) == 2
    assert "sha256:452d3a39e80b2a37abf2ad303a7c64bb93740e57dfc665e8a1d3617f9d8a36ef" in layers
    assert "sha256:d8c2bef31f4e14f286937ce665e8a1d3669bf06c5905b01387fb64db8c2d8296" in layers
    
    # Assert ecosystem normalization
    packages = res_data["packages"]
    assert len(packages) == 3
    
    pkg_map = {pkg["name"]: pkg for pkg in packages}
    assert pkg_map["numpy"]["ecosystem"] == "PyPI"
    assert pkg_map["lodash"]["ecosystem"] == "npm"
    assert pkg_map["openssl"]["ecosystem"] == "Debian"

def test_invalid_signature():
    """Verify that an attestation block with a tampered/invalid signature is rejected with HTTP 400."""
    container_config = get_base_config()
    # Tamper with the signature payload
    attestation = container_config["custom"]["sealpod"]["attestations"][0]
    attestation["signature"] = "SGVsbG8gV29ybGQ=" # Invalid signature bytes
    
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    assert resp.json()["verified"] is False
    assert "failed" in resp.json().get("error", "").lower() or "verification" in resp.json().get("error", "").lower()

def test_untrusted_ca_chain():
    """Verify that an attestation signed by a certificate outside the trusted root/intermediate CA chain is rejected with HTTP 400."""
    container_config = get_base_config()
    # Replace the certificate with a self-signed one (not signed by the intermediate CA)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed Attacker")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    container_config["custom"]["sealpod"]["attestations"][0]["certificate"] = cert_pem

    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    assert resp.json()["verified"] is False
    assert "chain" in resp.json().get("error", "").lower() or "untrusted" in resp.json().get("error", "").lower() or "certificate" in resp.json().get("error", "").lower()

def test_mismatched_signer():
    """Verify that an attestation payload where the signer email does not match the certificate's Subject Alternative Name is rejected with HTTP 400."""
    # Load pre-signed configuration with mismatched signer email
    mismatched_path = "/tests/mismatched_signer_config.json"
    if not os.path.exists(mismatched_path):
        mismatched_path = os.path.join(os.path.dirname(__file__), "mismatched_signer_config.json")
        
    with open(mismatched_path, "r", encoding="utf-8") as f:
        container_config = json.load(f)
    
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    res_json = resp.json()
    assert res_json["verified"] is False
    
    err_msg = res_json.get("error", "").lower()
    assert "signer" in err_msg or "mismatch" in err_msg or "email" in err_msg

def test_expired_certificate():
    """Verify that an attestation signed by an expired leaf certificate is rejected with HTTP 400."""
    # Load pre-signed configuration with expired leaf certificate
    expired_path = "/tests/expired_cert_config.json"
    if not os.path.exists(expired_path):
        expired_path = os.path.join(os.path.dirname(__file__), "expired_cert_config.json")
        
    with open(expired_path, "r", encoding="utf-8") as f:
        container_config = json.load(f)
        
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    res_json = resp.json()
    assert res_json["verified"] is False
    
    err_msg = res_json.get("error", "").lower()
    assert "expired" in err_msg or "time" in err_msg or "valid" in err_msg

def test_client_run_and_dot_graph():
    """Verify that client.py executes successfully, queries the OSV service, and produces a complete Graphviz DOT graph containing all required nodes and layer/package/CVE mapping relationships."""
    # Execute the client script to generate the DOT graph
    output_dot = "/app/graph.dot"
    if os.path.exists(output_dot):
        os.remove(output_dot)
        
    cmd = ["python", "/app/client.py", "--config", "/app/container_config.json", "--output", output_dot]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Client run failed: {res.stderr}"
    
    assert os.path.exists(output_dot), "DOT graph was not generated"
    
    # Read the DOT graph content
    with open(output_dot, "r", encoding="utf-8") as f:
        dot_content = f.read()
        
    # Check that it contains expected structures
    assert "digraph" in dot_content
    assert '"Signer: release-signer@sealpod.io"' in dot_content
    
    # Assert layer nodes exist
    layer1 = "sha256:452d3a39e80b2a37abf2ad303a7c64bb93740e57dfc665e8a1d3617f9d8a36ef"
    layer2 = "sha256:d8c2bef31f4e14f286937ce665e8a1d3669bf06c5905b01387fb64db8c2d8296"
    assert f'"Layer: {layer1}"' in dot_content
    assert f'"Layer: {layer2}"' in dot_content
    
    # Assert package nodes exist
    assert '"Package: numpy (1.26.4)"' in dot_content
    assert '"Package: lodash (4.17.20)"' in dot_content
    assert '"Package: openssl (3.0.2-0ubuntu1)"' in dot_content
    
    # Assert CVE nodes exist
    assert '"CVE-2024-37891"' in dot_content
    assert '"CVE-2020-8203"' in dot_content
    assert '"CVE-2022-0778"' in dot_content
    
    # Assert Signer -> Layer relationships
    assert f'"Signer: release-signer@sealpod.io" -> "Layer: {layer1}"' in dot_content
    assert f'"Signer: release-signer@sealpod.io" -> "Layer: {layer2}"' in dot_content
    
    # Assert Layer -> Package mapping (each package resides on ALL layers)
    assert f'"Layer: {layer1}" -> "Package: numpy (1.26.4)"' in dot_content
    assert f'"Layer: {layer2}" -> "Package: numpy (1.26.4)"' in dot_content
    
    assert f'"Layer: {layer1}" -> "Package: lodash (4.17.20)"' in dot_content
    assert f'"Layer: {layer2}" -> "Package: lodash (4.17.20)"' in dot_content
    
    assert f'"Layer: {layer1}" -> "Package: openssl (3.0.2-0ubuntu1)"' in dot_content
    assert f'"Layer: {layer2}" -> "Package: openssl (3.0.2-0ubuntu1)"' in dot_content
    
    # Assert Package -> CVE mappings
    assert '"Package: numpy (1.26.4)" -> "CVE-2024-37891"' in dot_content
    assert '"Package: lodash (4.17.20)" -> "CVE-2020-8203"' in dot_content
    assert '"Package: openssl (3.0.2-0ubuntu1)" -> "CVE-2022-0778"' in dot_content
