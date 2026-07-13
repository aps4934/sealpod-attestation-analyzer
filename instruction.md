We had a security incident where a rogue container image bypassed our admission controllers because of an issue in our SealPod attestation validation. 

Your task is to repair the signature verification API at `/app/app.py` and complete the vulnerability analysis client at `/app/client.py`.

### Requirements & Specification:

1. **Verify the custom SealPod Attestation Block in the Container Configuration:**
   The container image configuration spec is located at `/app/container_config.json`. It contains a custom `custom.sealpod.attestations` metadata block containing:
   * `layers`: The list of layers (diff_ids) to verify.
   * `payload`: Base64url-encoded JSON object containing signer identity, timestamp, and package list.
   * `signature`: Base64url-encoded ECDSA signature over the payload.
   * `certificate`: PEM-encoded leaf signing certificate.
   
   The verification system must implement the following cryptographic specification:
   * **JSON Canonicalization:** The parsed JSON payload must be canonicalized following **RFC 8785 (JCS)** (sorting keys, stripping whitespace).
   * **Signature Verification:** The signature must be verified over the raw base64url payload string (not the decoded bytes). The signature uses ECDSA with SHA-256 (P-256 curve).
   * **Certificate Chain Validation:** The leaf certificate must be validated against the trusted Intermediate and Root CA certificates located in `/app/keys/`.
   * **Validity Check:** Ensure the leaf certificate is within its valid timeframe (not expired, not yet active).
   * **Identity Verification:** The `signer` email in the payload must match the Subject Alternative Name (SAN) RFC822Name field in the leaf certificate.
   
   You can consult the historical incident transcript at `/app/incident_transcript.txt` for discussion context, failing drafts, and reference logic if needed.

2. **Repair the Flask Verification Endpoint:**
   Fix the `/verify` POST endpoint in `/app/app.py`. The endpoint must accept a JSON body containing `{"container_config": <dict>}` and return:
   * **On Success (HTTP 200):**
     ```json
     {
       "verified": true,
       "signer": "<email>",
       "layers": ["sha256:...", ...],
       "packages": [
         {
           "name": "<package>",
           "version": "<version>",
           "ecosystem": "<normalized_ecosystem>"
         }
       ]
     }
     ```
     Ecosystem names must be normalized: `pip` -> `PyPI`, `npm` -> `npm`, `deb` -> `Debian`.
   * **On Failure (HTTP 400):**
     ```json
     {
       "verified": false,
       "error": "<reason>"
     }
     ```

3. **Complete the Analysis & Visualization Script:**
   Complete `/app/client.py` so that it:
   * Extracts the container config's attestation data.
   * Submits the container configuration payload to the `/verify` endpoint of the local Flask API.
   * Queries the local mock OSV.dev endpoint (at `http://localhost:8082/v1/query`) to fetch vulnerability data for each verified package.
   * Generates a Graphviz DOT file at `/app/graph.dot` mapping:
     * Signer certificate DN/email -> Layers
     * Layers -> Packages
     * Packages -> CVEs (if any)

All paths in your code must be absolute. The services will be run in the background during evaluation.
