import json
from typing import List, Union


def parse_issues_json_string(issues_json: Union[str, bytes]) -> List[str]:
    """
    Parses a JSON string containing GitHub issues into a list of issue titles.

    Note: The issue data must contain the `title` field.

    :param issue_json: Issue data encoded in JSON format
    :return: A list of titles, e.g. `["Security Alert: poetry package fastapi-0.63.0"]
    """
    issues = []
    issues_data = json.loads(issues_json)
    assert isinstance(issues_data, list)
    for issue_data in issues_data:
        if not isinstance(issue_data, dict):
            raise TypeError(
                f"Issue data entry is not a dict, got: {type(issue_data).__name__}"
            )
        title = issue_data.get("title")
        if title:
            issues.append(title)
    return issues
