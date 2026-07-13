# SealPod Container Attestation Analyzer

This repository contains a Terminus-Bench 2.0 task designed for the Snorkel AI platform. The task challenges AI coding agents to reverse-engineer a custom, undocumented cryptographic container image attestation block (`SealPod`) embedded in an OCI spec, and repair a Flask analysis service and a vulnerability visualization script.

## Task Structure
```
S1/
├── instruction.md         # Task prompt for the agent
├── task.toml              # Metadata and run limits
├── environment/
│   ├── Dockerfile         # Digest-pinned base image + dependencies (tmux, asciinema, graphviz)
│   └── app/               # Challenge workspace files (Flask API, mock OSV, keys, spec)
├── solution/
│   ├── solve.sh           # Oracle entrypoint script
│   ├── app.py             # Solved Flask verification service reference
│   └── client.py          # Solved vulnerability visualization reference
└── tests/
    ├── test.sh            # Main test runner (starts servers, runs pytest, writes reward.txt)
    └── test_outputs.py    # Pytest integration tests
```

---

## Snorkel Platform Submission Answers

These are the exact text answers to fill in the submission form on the Snorkel Expert Platform:

### 1. Difficulty Explanation
> **Question:** *Describe in your own words why your task is challenging for humans and agents to solve.*
>
> **Answer:**
> This task is challenging for both humans and AI agents due to the following factors:
> 1. **Undocumented Cryptographic Format:** The exact signature format, JSON canonicalization protocol (RFC 8785), and hashing parameters are not explicitly described in the main instructions. Instead, they must be parsed and inferred by reading a long chat transcript (~60k tokens) containing early contradictory drafts, debugging discussions, and reviewer comments.
> 2. **Multi-level Certificate Validation:** The verifier service must perform proper cryptographic validation of a multi-tiered certificate authority chain (Leaf -> Intermediate -> Root CA). Most agents or simple implementations fail to check the chain, date validity, or match the signer's identity in the Subject Alternative Name (SAN) of the leaf certificate against the payload.
> 3. **API and Graph Contract Alignments:** The agent must align the Flask service's verification responses with a strict endpoint schema expected by integration tests and produce a Graphviz DOT visualization linking specific container layers, packages, and vulnerabilities queried from a mock OSV service.
> Because of these combined cryptographic constraints and long-context reasoning requirements, the task has a low success rate for naive AI agents (python tasks are required to be Hard difficulty).

### 2. Solution Explanation
> **Question:** *Describe your high-level approach to this task and key insights in forming the solution.*
>
> **Answer:**
> The reference solution repairs the Flask verification service and the analysis script:
> 1. **Flask API (`app.py`):** We replace standard base64 decoding with URL-safe base64 decoding to support attestation payloads containing URL-safe characters. We implement RFC 8785 JSON canonicalization (JCS) before verifying signatures. We load the Root and Intermediate CA certs to validate the full signature chain of the Leaf certificate, check date validity, verify the ECDSA signature over the base64url payload bytes, and assert that the leaf certificate's SAN RFC822Name field contains the signer email.
> 2. **Package Normalization:** Ecosystem package formats are mapped from `pip`/`npm`/`deb` to `PyPI`/`npm`/`Debian` as expected by the client interface contract.
> 3. **Analysis Client (`client.py`):** We complete the vulnerability mapping loop by querying the local mock OSV.dev endpoint with standard package query JSON payloads, parsing unique CVE IDs from the `aliases` field, and generating a syntactically correct Graphviz DOT graph linking verified container layers to packages and their related CVEs.

### 3. Verification Explanation
> **Question:** *Explain how your tests are verifying correctness.*
>
> **Answer:**
> Our integration test suite (`tests/test_outputs.py`) performs active functional verification using `pytest`:
> 1. **`test_endpoint_contract`**: Validates that a correct configuration payload returns HTTP 200, successfully normalizes the ecosystems to PyPI/npm/Debian, and correctly outputs signature data.
> 2. **`test_invalid_signature`**: Checks that a tampered signature returns HTTP 400 and reports verification failure.
> 3. **`test_untrusted_ca_chain`**: Asserts that a self-signed leaf certificate not belonging to the trusted Intermediate/Root CA is rejected.
> 4. **`test_mismatched_signer`**: Asserts that if a payload claims a signer email different from the certificate's SAN email, verification is rejected.
> 5. **`test_client_run_and_dot_graph`**: Executes the client script, verifies it exits with 0, and parses the output `graph.dot` to verify that all nodes and edges (Signer, Layers, Packages, and CVEs) are present and properly connected.

### 4. Comments for Reviewer (optional)
> **Answer:**
> This is a non-milestone security/cryptography task category submission. It uses an approved canonical base image (`python:3.13-slim-bookworm`). The task includes a mock OSV.dev server running inside the container to avoid external API dependency failures and ensure that all agent tests are fully deterministic and fast. Tmux and asciinema are installed in the Dockerfile as required by the runtime guidelines.

### 5. Rubric Checkbox & Metadata
* **Does this task use an approved canonical base image?:** `Yes` (uses `python:3.13-slim-bookworm`)
* **Did you use a Task Inspiration from the Task Gallery for this submission?:** `No`
* **How long did it take you to complete this submission?:** `180` (minutes)
* **Prompt Check (I reviewed my prompt and):**
  * Ensured it does not list an excessive number of requirements (20+) -> `Checked`
  * Made it sound natural and human -> `Checked`
  * Removed any unnecessary hints and verified it does not reveal the solution -> `Checked`
