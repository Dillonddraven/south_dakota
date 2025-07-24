import json
import os 
from utils.repo_utils import extract_repo_from_location


from utils.repo_utils import extract_repo_from_location

def parse_vulns(sast_data):
    """
    Parses SARIF-formatted SAST data and adds 'repo' extracted from location.
    :param sast_data: Parsed JSON from the SARIF file
    :return: List of parsed vulnerabilities, each with a 'repo' field
    """
    vulns = []

    runs = sast_data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for result in results:
            locations = result.get("locations", [])
            if not locations:
                continue

            location_info = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            severity = result.get("properties", {}).get("securitySeverity", "None")
            message = result.get("message", {}).get("text", "")

            repo = extract_repo_from_location(location_info)

            vulns.append({
                "location": location_info,
                "severity": severity,
                "message": message,
                "repo": repo
            })

    return vulns


