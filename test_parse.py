from your_module import load_sast_report, parse_vulns  # adjust import if needed
import os
import json

def test_parse_sast():
    sast_data = load_sast_report("path/to/example-sast-report.json")
    results = parse_vulns(sast_data)
    print("Parsed results:")
    for location, severities in results.items():
        print(location, severities)

if __name__ == "__main__":
    test_parse_sast()
