import os
import json
import subprocess
import requests
import pytest
from cryptography import x509

API_URL = "http://localhost:8080/verify"

@pytest.fixture(scope="session", autouse=True)
def wait_for_services():
    # Wait for the verify API to be healthy
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
    with open("/app/container_config.json", "r", encoding="utf-8") as f:
        return json.load(f)

def test_endpoint_contract():
    # Verify valid OCI config verification returns expected contract
    container_config = get_base_config()
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 200
    res_data = resp.json()
    
    assert res_data["verified"] is True
    assert res_data["signer"] == "release-signer@sealpod.io"
    
    # Assert ecosystem normalization
    packages = res_data["packages"]
    assert len(packages) == 3
    
    pkg_map = {pkg["name"]: pkg for pkg in packages}
    assert pkg_map["numpy"]["ecosystem"] == "PyPI"
    assert pkg_map["lodash"]["ecosystem"] == "npm"
    assert pkg_map["openssl"]["ecosystem"] == "Debian"

def test_invalid_signature():
    container_config = get_base_config()
    # Tamper with the signature payload
    attestation = container_config["custom"]["sealpod"]["attestations"][0]
    attestation["signature"] = "SGVsbG8gV29ybGQ=" # Invalid signature bytes
    
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    assert resp.json()["verified"] is False
    assert "failed" in resp.json().get("error", "").lower() or "verification" in resp.json().get("error", "").lower()

def test_untrusted_ca_chain():
    container_config = get_base_config()
    # Replace the certificate with a self-signed one (not signed by the intermediate CA)
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
    container_config = get_base_config()
    attestation = container_config["custom"]["sealpod"]["attestations"][0]
    
    # Payload claims signer is 'attacker@malicious.com'
    # But certificate SAN matches 'release-signer@sealpod.io'
    import base64
    payload_bytes = base64.urlsafe_b64decode(attestation["payload"] + "===")
    payload_data = json.loads(payload_bytes)
    payload_data["signer"] = "attacker@malicious.com"
    
    # We must re-encode and re-sign with our valid leaf key to make the signature match the malicious payload,
    # but the verification MUST fail because the signer email does not match the certificate email!
    # Just re-encode the altered payload and verify rejection
    # (email mismatch or signature verification check)
    
    # Re-encode payload
    canonical_payload = json.dumps(payload_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    encoded_payload = base64.urlsafe_b64encode(canonical_payload).decode('utf-8').rstrip('=')
    
    # We don't have the leaf private key inside the container at test runtime, but we can verify that
    # the verify endpoint rejects it (either due to invalid signature or mismatched signer email).
    attestation["payload"] = encoded_payload
    
    resp = requests.post(API_URL, json={"container_config": container_config})
    assert resp.status_code == 400
    assert resp.json()["verified"] is False

def test_client_run_and_dot_graph():
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
    assert '"Layer: sha256:452d3a39e80b2a37abf2ad303a7c64bb93740e57dfc665e8a1d3617f9d8a36ef"' in dot_content
    assert '"Layer: sha256:d8c2bef31f4e14f286937ce665e8a1d3669bf06c5905b01387fb64db8c2d8296"' in dot_content
    
    # Assert package nodes exist
    assert '"Package: numpy (1.26.4)"' in dot_content
    assert '"Package: lodash (4.17.20)"' in dot_content
    assert '"Package: openssl (3.0.2-0ubuntu1)"' in dot_content
    
    # Assert CVE nodes exist
    assert '"CVE-2024-37891"' in dot_content
    assert '"CVE-2020-8203"' in dot_content
    assert '"CVE-2022-0778"' in dot_content
    
    # Assert relationship links exist
    assert '"Signer: release-signer@sealpod.io" -> "Layer: sha256:452d3a39e80b2a37abf2ad303a7c64bb93740e57dfc665e8a1d3617f9d8a36ef"' in dot_content
    assert '"Layer: sha256:452d3a39e80b2a37abf2ad303a7c64bb93740e57dfc665e8a1d3617f9d8a36ef" -> "Package: numpy (1.26.4)"' in dot_content
    assert '"Package: numpy (1.26.4)" -> "CVE-2024-37891"' in dot_content
