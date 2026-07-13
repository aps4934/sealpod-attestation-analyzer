We had a security incident where a rogue container image bypassed our admission controllers because of an issue in our SealPod attestation validation. 

Your task is to repair our signature verification API at `/app/app.py` and complete the vulnerability analysis client at `/app/client.py`.

### Requirements:
1. **Reverse-Engineer the SealPod Attestation Block:**
   The image configuration spec at `/app/oci_config.json` contains a custom `custom.sealpod.attestations` block. The signature, canonicalization, hashing, and certificate validation rules for this block are undocumented, but details are scattered throughout the incident troubleshooting transcript at `/app/incident_transcript.txt`. Read the transcript to determine the exact verification protocol.
   
2. **Repair the Verification Endpoint:**
   Fix the `/verify` POST endpoint in `/app/app.py`. It must ingest the OCI config payload, validate the certificate chain against the trusted root and intermediate certificates in `/app/keys/`, verify the signature over the canonicalized payload, and return a validated list of packages and layers. It must match the expected integration test contract.

3. **Complete the Analysis & Visualization Script:**
   Complete `/app/client.py` so that it:
   * Extracts the OCI config's attestation data.
   * Submits it to `/verify` on the local Flask API.
   * Queries the local mock OSV.dev endpoint (at `http://localhost:8082/v1/query`) to fetch vulnerability data for each package.
   * Generates a Graphviz DOT file at `/app/graph.dot` mapping:
     * Signer certificate DN/email -> Layers
     * Layers -> Packages
     * Packages -> CVEs (if any)

All paths in your code must be absolute. The services will be run in the background during evaluation.
