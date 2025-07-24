from collections import defaultdict

def group_by_team(vulns, team_data):
   
    team_vulns = defaultdict(list)

    for vuln in vulns:
        repo = vuln.get("repo")
        if not repo:
            continue  # skip if no repo info

        for team, data in team_data.items():
            team_repos = data.get("repos", [])
            if repo in team_repos:
                team_vulns[team].append(vuln)
                break  # once assigned to one team, skip others

    return dict(team_vulns)

