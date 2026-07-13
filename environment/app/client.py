import os
import json
import argparse
import requests

def parse_args():
    parser = argparse.ArgumentParser(description="SealPod Attestation Security Analyzer")
    parser.add_argument("--config", required=True, help="Path to OCI config JSON")
    parser.add_argument("--output", required=True, help="Path to write the DOT graph file")
    return parser.parse_args()

def main():
    args = parse_args()
    
    if not os.path.exists(args.config):
        print(f"Error: Config file {args.config} not found.")
        return
        
    with open(args.config, "r", encoding="utf-8") as f:
        container_config = json.load(f)
        
    # 1. Call verification endpoint
    verify_url = "http://localhost:8080/verify"
    try:
        response = requests.post(verify_url, json={"container_config": container_config})
        if response.status_code != 200:
            print(f"Error: Attestation verification failed: {response.text}")
            return
        res_data = response.json()
    except Exception as e:
        print(f"Error connecting to verification service: {e}")
        return

    # Extract verified components
    signer = res_data.get("signer")
    layers = res_data.get("layers", [])
    packages = res_data.get("packages", [])
    
    print(f"Verified image signed by: {signer}")
    print(f"Verified Layers count: {len(layers)}")
    print(f"Verified Packages count: {len(packages)}")

    # 2. Query OSV.dev for package vulnerabilities
    # TODO: Implement local OSV query logic targeting http://localhost:8082/v1/query
    # For each package in verified packages:
    #   Query OSV.dev mock endpoint using the payload:
    #   {
    #       "version": package_version,
    #       "package": {
    #           "name": package_name,
    #           "ecosystem": package_ecosystem
    #       }
    #   }
    #   Extract all CVE aliases (unique list of CVE IDs) from the vulnerabilities found.
    pkg_cves = {}
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        # ecosystem = pkg.get("ecosystem")
        
        cves = []
        # --- TODO START ---
        # Implement the POST query, extract unique CVE IDs from 'aliases' of each vulnerability
        # --- TODO END ---
        pkg_cves[(name, version)] = cves

    # 3. Generate Graphviz DOT file
    # TODO: Implement the Graphviz DOT output file generation at args.output
    # The graph must link:
    #   Signer node -> Layer nodes
    #   Layer nodes -> Package nodes
    #   Package nodes -> CVE nodes
    # Use format:
    #   Signer node label: "Signer: <email>"
    #   Layer node label: "Layer: <sha256 digest>"
    #   Package node label: "Package: <name> (<version>)"
    #   CVE node label: "<CVE-ID>"
    # Make sure every package is linked to ALL layers verified in the attestation.
    
    # --- TODO START ---
    # Construct and write the Graphviz DOT syntax to args.output
    # --- TODO END ---
    print(f"Successfully generated dependency vulnerability graph at {args.output}")

if __name__ == '__main__':
    main()
