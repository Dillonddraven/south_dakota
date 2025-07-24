def extract_repo_from_location(location: str) -> str:
    """
    Extracts the repo name from a SARIF 'location' field.
    Assumes the path is like 'group/repo-name/...'.
    """
    if not location:
        return None
    parts = location.strip("/").split("/")
    return parts[1] if len(parts) >= 2 else None
