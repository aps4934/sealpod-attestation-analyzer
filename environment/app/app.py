import os
import json
import base64
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

KEYS_DIR = "/app/keys"

# Dummy verification logic that the agent needs to repair
def verify_sealpod_attestation(attestation):
    # BUG 1: Uses standard b64decode instead of urlsafe_b64decode.
    # This will throw an exception on payloads containing '-' or '_'
    try:
        payload_bytes = base64.b64decode(attestation.get("payload", ""))
        payload = json.loads(payload_bytes)
    except Exception as e:
        return {"verified": False, "error": f"Payload decode failure: {str(e)}"}

    # BUG 2: Direct loading of public key without certificate chain validation.
    # It doesn't verify against root.crt or intermediate.crt, meaning any self-signed cert is accepted!
    try:
        cert_pem = attestation.get("certificate", "").encode('utf-8')
        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = leaf_cert.public_key()
    except Exception as e:
        return {"verified": False, "error": f"Invalid certificate: {str(e)}"}

    # BUG 3: Does not canonicalize JSON payload before verification.
    # JCS (RFC 8785) is required to ensure key ordering matches the signature calculation.
    # BUG 4: Verifies over the decoded payload bytes instead of the raw base64url string.
    try:
        sig_bytes = base64.b64decode(attestation.get("signature", ""))
        
        # In Draft 1, we verified over decoded bytes, but we changed to base64url string.
        # This code still verifies over the raw decoded bytes, which will fail for the final format.
        public_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return {"verified": False, "error": "Signature verification failed"}
    except Exception as e:
        return {"verified": False, "error": f"Verification error: {str(e)}"}

    # BUG 5: Does not check if the Subject Alternative Name (SAN) email matches the payload "signer".
    
    # Return verification payload data
    # BUG 6: Package ecosystems are not normalized (returns pip/npm/deb instead of PyPI/npm/Debian)
    return {
        "verified": True,
        "signer": payload.get("signer"),
        "packages": [
            {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "ecosystem": pkg.get("type") # Mismatched key/values
            }
            for pkg in payload.get("packages", [])
        ]
    }

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json() or {}
    oci_config = data.get("oci_config", {})
    
    attestations = oci_config.get("custom", {}).get("sealpod", {}).get("attestations", [])
    if not attestations:
        return jsonify({"verified": False, "error": "No attestations found"}), 400
        
    result = verify_sealpod_attestation(attestations[0])
    if not result.get("verified"):
        return jsonify(result), 400
        
    # Append the config layers to the response
    result["layers"] = oci_config.get("rootfs", {}).get("diff_ids", [])
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
