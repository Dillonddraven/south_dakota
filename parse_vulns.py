import json
import os 

def parse_vulns(json_data):
    print("parsing vulnerability from the sast json file")

    repo_vulns = {}

    for run in json_data.get("runs", []):
        for result in run.get("results", []):
            props = result.get("properties", {})
            severity = props.get("severity", "None").capitalize()

            # get file location 
            try:
                location = result["location"][0]["physicalLocation"]["artifactLocation"]["uri"]
            except (KeyError, IndexError):
                location = "Unknownfile"

            if location not in repo_vulns:
                repo_vulns[location] = {}

            if severity not in repo_vulns[location]:
                repo_vulns[location][severity] = 0

            repo_vulns[location][severity] += 1

    return repo_vulns


