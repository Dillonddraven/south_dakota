def sast_section(team_repos, sast_vulns,sheet):
    start_col = 33  # column AF
    severity_order = ["critical", "High", "Medium", "Low", "None"]

    row = create_merged_cell(sheet, 1, start_col, start_col + len(severity_order),
                             "Gitlab SAST SCAN RESULTS", "a8d7b2", 14)
    row = create_section_header(sheet, row, start_col, ["Repo"] + severity_order)
    begin_row = row

    for repo in team_repos:
        if repo not in sast_vulns:
            continue

        sheet.cell(row=row, column=start_col, value=repo)
        severity_count = sast_vulns[repo]

        for i, sev in enumerate(severity_order, start=1):
            count = severity_count.get(sev, 0)
            cell = sheet.cell(row=row, column=start_col + i, value=count)
            apply_criticality_formatting(cell, count, sev)

        row += 1

    if begin_row == row:
        return create_merged_cell(sheet, row, start_col, start_col + len(severity_order),
                                 "No Gitlab SAST results were found",
                                 "ffffff", 11, bold=False)
    return row



# call this at the end of the create team sheet function sast_section(team_repos, sast_vulns, sheet)  # <-- pass your processed data
# make sure sast_vulns is passed into create_team_sheet() from main pipeline
