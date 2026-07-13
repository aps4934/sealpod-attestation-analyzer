import json
import base64
import datetime
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

ROOT_CERT_PATH = "/app/keys/root.crt"
INT_CERT_PATH = "/app/keys/intermediate.crt"

def base64url_decode(s: str) -> bytes:
    # Re-add padding
    rem = len(s) % 4
    if rem > 0:
        s += '=' * (4 - rem)
    return base64.urlsafe_b64decode(s.encode('utf-8'))

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def JCS_canonicalize(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def validate_cert_chain(leaf_cert: x509.Certificate) -> bool:
    with open(ROOT_CERT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(INT_CERT_PATH, "rb") as f:
        int_cert = x509.load_pem_x509_certificate(f.read())

    # 1. Verify intermediate CA cert is signed by root
    root_pub_key = root_cert.public_key()
    root_pub_key.verify(
        int_cert.signature,
        int_cert.tbs_certificate_bytes,
        ec.ECDSA(int_cert.signature_hash_algorithm)
    )

    # 2. Verify leaf cert is signed by intermediate
    int_pub_key = int_cert.public_key()
    int_pub_key.verify(
        leaf_cert.signature,
        leaf_cert.tbs_certificate_bytes,
        ec.ECDSA(leaf_cert.signature_hash_algorithm)
    )

    # 3. Verify leaf cert dates
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < leaf_cert.not_valid_before_utc or now > leaf_cert.not_valid_after_utc:
        raise Exception("Certificate dates are invalid (expired or not yet active)")

    return True

def verify_sealpod_attestation(attestation):
    try:
        # Load Leaf Cert
        cert_pem = attestation.get("certificate", "").encode('utf-8')
        leaf_cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return {"verified": False, "error": f"Failed to load leaf certificate: {str(e)}"}

    # 1. Validate Certificate Chain
    try:
        validate_cert_chain(leaf_cert)
    except Exception as e:
        return {"verified": False, "error": f"Certificate chain validation failed: {str(e)}"}

    # 2. Decode signature and payload
    try:
        sig_bytes = base64url_decode(attestation.get("signature", ""))
        raw_payload = attestation.get("payload", "")
        payload_bytes = base64url_decode(raw_payload)
        payload = json.loads(payload_bytes)
    except Exception as e:
        return {"verified": False, "error": f"Decoding error: {str(e)}"}

    # 3. Verify signature over raw base64url payload string
    try:
        public_key = leaf_cert.public_key()
        # The signature is calculated over the ASCII bytes of the raw base64url payload string
        public_key.verify(sig_bytes, raw_payload.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return {"verified": False, "error": "Signature verification failed"}
    except Exception as e:
        return {"verified": False, "error": f"Verification execution error: {str(e)}"}

    # 4. Check SAN email matches payload signer
    signer_email = payload.get("signer")
    try:
        san_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        if signer_email not in emails:
            return {"verified": False, "error": "Signer email does not match SAN in Leaf certificate"}
    except Exception as e:
        return {"verified": False, "error": f"SAN validation error: {str(e)}"}

    # Normalization map
    ecosystem_map = {
        "pip": "PyPI",
        "npm": "npm",
        "deb": "Debian"
    }

    # Return normalized verified output
    return {
        "verified": True,
        "signer": signer_email,
        "packages": [
            {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "ecosystem": ecosystem_map.get(pkg.get("type"), "PyPI")
            }
            for pkg in payload.get("packages", [])
        ]
    }

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json() or {}
    container_config = data.get("container_config", {})
    
    attestations = container_config.get("custom", {}).get("sealpod", {}).get("attestations", [])
    if not attestations:
        return jsonify({"verified": False, "error": "No attestations found"}), 400
        
    result = verify_sealpod_attestation(attestations[0])
    if not result.get("verified"):
        return jsonify(result), 400
        
    result["layers"] = container_config.get("rootfs", {}).get("diff_ids", [])
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
