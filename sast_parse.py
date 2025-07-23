import json
from collections import defaultdict

# update path to your actual JSON file
def parse_sast_json(path):
    with open(path, "r") as f:
        data = json.load(f)

    vuln_map = defaultdict(lambda: defaultdict(int))

    for vuln in data.get("vulnerabilities", []):
        file_path = vuln["location"]["file"]
        severity = vuln.get("severity", "None").capitalize()

        # Normalize
        if severity not in {"Critical", "High", "Medium", "Low", "None"}:
            severity = "None"

        vuln_map[file_path][severity] += 1

    return dict(vuln_map)
