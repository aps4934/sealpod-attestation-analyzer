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
    pkg_cves = {}
    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = pkg.get("ecosystem")
        
        cves = []
        try:
            # Query OSV mock service
            osv_url = "http://localhost:8082/v1/query"
            query_payload = {
                "version": version,
                "package": {
                    "name": name,
                    "ecosystem": ecosystem
                }
            }
            resp = requests.post(osv_url, json=query_payload)
            if resp.status_code == 200:
                vulns = resp.json().get("vulns", [])
                for vuln in vulns:
                    # Extract unique CVE IDs from aliases
                    aliases = vuln.get("aliases", [])
                    for alias in aliases:
                        if alias.startswith("CVE-") and alias not in cves:
                            cves.append(alias)
        except Exception as e:
            print(f"Warning: Failed to query OSV for {name}: {e}")
            
        pkg_cves[(name, version)] = cves

    # 3. Generate Graphviz DOT file
    lines = []
    lines.append("digraph G {")
    lines.append("    node [shape=box, style=filled, fillcolor=lightblue];")
    
    signer_node = f'"Signer: {signer}"'
    
    # Track written nodes and edges to avoid duplication
    written_elements = set()
    
    # Link Signer to all Layers
    for layer in layers:
        layer_node = f'"Layer: {layer}"'
        edge = f"    {signer_node} -> {layer_node};"
        if edge not in written_elements:
            lines.append(edge)
            written_elements.add(edge)
            
        # Link Layers to all Packages
        for pkg in packages:
            pkg_name = pkg.get("name")
            pkg_ver = pkg.get("version")
            pkg_node = f'"Package: {pkg_name} ({pkg_ver})"'
            edge = f"    {layer_node} -> {pkg_node};"
            if edge not in written_elements:
                lines.append(edge)
                written_elements.add(edge)
                
    # Link Packages to their CVEs
    for pkg in packages:
        pkg_name = pkg.get("name")
        pkg_ver = pkg.get("version")
        pkg_node = f'"Package: {pkg_name} ({pkg_ver})"'
        
        cves = pkg_cves.get((pkg_name, pkg_ver), [])
        for cve in cves:
            cve_node = f'"{cve}"'
            edge = f"    {pkg_node} -> {cve_node};"
            if edge not in written_elements:
                lines.append(edge)
                written_elements.add(edge)
                
    lines.append("}")
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        
    print(f"Successfully generated dependency vulnerability graph at {args.output}")

if __name__ == '__main__':
    main()
