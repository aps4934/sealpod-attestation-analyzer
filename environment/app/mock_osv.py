from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded OSV responses for our specific packages
VULN_DB = {
    ("numpy", "PyPI", "1.26.4"): [
        {
            "id": "GHSA-j9vc-ffgh-4573",
            "summary": "Vulnerability in numpy",
            "aliases": ["CVE-2024-37891"]
        }
    ],
    ("lodash", "npm", "4.17.20"): [
        {
            "id": "GHSA-p6mc-m378-538f",
            "summary": "Prototype pollution in lodash",
            "aliases": ["CVE-2020-8203"]
        }
    ],
    ("openssl", "Debian", "3.0.2-0ubuntu1"): [
        {
            "id": "GHSA-739c-v8f6-289c",
            "summary": "Denial of service in openssl",
            "aliases": ["CVE-2022-0778"]
        }
    ]
}

@app.route('/v1/query', methods=['POST'])
def query_vuln():
    data = request.get_json() or {}
    package = data.get("package", {})
    name = package.get("name")
    ecosystem = package.get("ecosystem")
    version = data.get("version")
    
    key = (name, ecosystem, version)
    vulns = VULN_DB.get(key, [])
    
    return jsonify({"vulns": vulns})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082, debug=False)
